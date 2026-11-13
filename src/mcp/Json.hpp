#pragma once
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Minimal JSON value for the MCP server (JSON-RPC 2.0 messages and tool
// payloads). Dependency-free on purpose: the project vendors everything and
// MCP needs only a small, predictable subset.
//
//  - Objects keep insertion order (stable, readable tool output) and are
//    looked up linearly - MCP objects are small.
//  - Numbers are stored as double plus an "integral" flag so ids, offsets and
//    counts round-trip exactly up to 2^53.
//  - dump() always produces valid UTF-8: invalid byte sequences coming from
//    APK content (strings, file names) are replaced by U+FFFD instead of
//    producing a document the client would reject.
//  - parse() is bounded (nesting depth) and never throws.
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Array = std::vector<Json>;
    using Object = std::vector<std::pair<std::string, Json>>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(const Json&) = default;
    Json& operator=(const Json&) = default;
    // A moved-from Json is null. The implicit move would copy type_ but empty
    // arr_ / obj_, leaving an Array or Object with no storage that crashes on
    // any later size() / items() / dump().
    Json(Json&& o) noexcept
        : type_(std::exchange(o.type_, Type::Null)), bool_(o.bool_), num_(o.num_), integral_(o.integral_),
          str_(std::move(o.str_)), arr_(std::move(o.arr_)), obj_(std::move(o.obj_)) {}
    Json& operator=(Json&& o) noexcept {
        if (this != &o) {
            type_ = std::exchange(o.type_, Type::Null);
            bool_ = o.bool_;
            num_ = o.num_;
            integral_ = o.integral_;
            str_ = std::move(o.str_);
            arr_ = std::move(o.arr_);
            obj_ = std::move(o.obj_);
        }
        return *this;
    }
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(int v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(long v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned long v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(long long v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(unsigned long long v) : type_(Type::Number), num_(static_cast<double>(v)), integral_(true) {}
    Json(double v) : type_(Type::Number), num_(v), integral_(false) {}
    Json(const char* s) : type_(Type::String), str_(s ? s : "") {}
    Json(std::string s) : type_(Type::String), str_(std::move(s)) {}
    Json(std::string_view s) : type_(Type::String), str_(s) {}
    Json(Array a) : type_(Type::Array), arr_(std::make_shared<Array>(std::move(a))) {}
    Json(Object o) : type_(Type::Object), obj_(std::make_shared<Object>(std::move(o))) {}

    static Json array() { return Json(Array{}); }
    static Json object() { return Json(Object{}); }
    // {"k": v, ...} shorthand.
    static Json obj(std::initializer_list<std::pair<std::string, Json>> items) {
        return Json(Object(items.begin(), items.end()));
    }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBool() const { return type_ == Type::Bool; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::Array; }
    bool isObject() const { return type_ == Type::Object; }

    bool asBool(bool fallback = false) const { return type_ == Type::Bool ? bool_ : fallback; }
    double asNumber(double fallback = 0) const { return type_ == Type::Number ? num_ : fallback; }
    int64_t asInt(int64_t fallback = 0) const { return type_ == Type::Number ? static_cast<int64_t>(num_) : fallback; }
    const std::string& asString() const;
    std::string asString(const std::string& fallback) const { return isString() ? str_ : fallback; }

    // Arrays.
    size_t size() const;
    const Json& operator[](size_t i) const;
    void push(Json v);
    const Array& items() const;

    // Objects. get() returns a shared null for missing keys / non-objects.
    const Json& get(std::string_view key) const;
    bool has(std::string_view key) const;
    Json& set(std::string key, Json v);  // replaces an existing key
    const Object& members() const;

    std::string dump(bool pretty = false) const;
    static bool parse(std::string_view text, Json& out, std::string* error = nullptr);

    // Equality for ids (number/string) and tests.
    bool operator==(const Json& o) const;
    bool operator!=(const Json& o) const { return !(*this == o); }

private:
    void dumpTo(std::string& out, bool pretty, int indent) const;
    void detach();  // copy-on-write for shared containers

    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    bool integral_ = false;
    std::string str_;
    std::shared_ptr<Array> arr_;
    std::shared_ptr<Object> obj_;
};

namespace json {
// Appends `s` as a quoted JSON string (escaping + UTF-8 sanitizing).
void appendQuoted(std::string& out, std::string_view s);
// Replaces invalid UTF-8 with U+FFFD (used for text coming from APK content).
std::string sanitizeUtf8(std::string_view s);
}  // namespace json
