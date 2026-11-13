#include "mcp/Json.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace {

const Json kNull;
const std::string kEmptyString;
const Json::Array kEmptyArray;
const Json::Object kEmptyObject;

constexpr int kMaxDepth = 128;

// Length of the valid UTF-8 sequence starting at s[i], 0 when invalid.
size_t utf8SeqLen(std::string_view s, size_t i) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) return 1;
    size_t n = 0;
    uint32_t cp = 0;
    if ((c & 0xE0) == 0xC0) n = 2, cp = c & 0x1F;
    else if ((c & 0xF0) == 0xE0) n = 3, cp = c & 0x0F;
    else if ((c & 0xF8) == 0xF0) n = 4, cp = c & 0x07;
    else return 0;
    if (i + n > s.size()) return 0;
    for (size_t k = 1; k < n; ++k) {
        const unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (cc & 0x3F);
    }
    // Reject overlong forms, surrogates and out-of-range code points.
    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000)) return 0;
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return n;
}

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

class Parser {
public:
    explicit Parser(std::string_view t) : t_(t) {}

    bool parseDocument(Json& out, std::string* error) {
        ws();
        if (!value(out, 0)) {
            if (error) *error = err_.empty() ? "invalid JSON" : err_;
            return false;
        }
        ws();
        if (p_ != t_.size()) {
            if (error) *error = "trailing characters after JSON value";
            return false;
        }
        return true;
    }

private:
    bool fail(const char* m) {
        if (err_.empty()) err_ = std::string(m) + " at offset " + std::to_string(p_);
        return false;
    }
    void ws() {
        while (p_ < t_.size() && (t_[p_] == ' ' || t_[p_] == '\t' || t_[p_] == '\n' || t_[p_] == '\r')) ++p_;
    }
    bool lit(const char* word) {
        size_t n = std::char_traits<char>::length(word);
        if (t_.compare(p_, n, word) != 0) return fail("invalid literal");
        p_ += n;
        return true;
    }
    bool value(Json& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        if (p_ >= t_.size()) return fail("unexpected end");
        const char c = t_[p_];
        if (c == '{') return object(out, depth);
        if (c == '[') return array(out, depth);
        if (c == '"') {
            std::string s;
            if (!string(s)) return false;
            out = Json(std::move(s));
            return true;
        }
        if (c == 't') return lit("true") && (out = Json(true), true);
        if (c == 'f') return lit("false") && (out = Json(false), true);
        if (c == 'n') return lit("null") && (out = Json(), true);
        return number(out);
    }
    bool number(Json& out) {
        const size_t start = p_;
        if (p_ < t_.size() && t_[p_] == '-') ++p_;
        if (p_ >= t_.size() || !(t_[p_] >= '0' && t_[p_] <= '9')) return fail("invalid number");
        bool integral = true;
        while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        if (p_ < t_.size() && t_[p_] == '.') {
            integral = false;
            ++p_;
            if (p_ >= t_.size() || !(t_[p_] >= '0' && t_[p_] <= '9')) return fail("invalid number");
            while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        }
        if (p_ < t_.size() && (t_[p_] == 'e' || t_[p_] == 'E')) {
            integral = false;
            ++p_;
            if (p_ < t_.size() && (t_[p_] == '+' || t_[p_] == '-')) ++p_;
            if (p_ >= t_.size() || !(t_[p_] >= '0' && t_[p_] <= '9')) return fail("invalid number");
            while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') ++p_;
        }
        const std::string num(t_.substr(start, p_ - start));
        const double v = std::strtod(num.c_str(), nullptr);
        out = integral ? Json(static_cast<long long>(v)) : Json(v);
        return true;
    }
    bool hex4(uint32_t& v) {
        if (p_ + 4 > t_.size()) return fail("truncated escape");
        v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = t_[p_++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return fail("invalid escape");
        }
        return true;
    }
    bool string(std::string& out) {
        ++p_;  // opening quote
        while (p_ < t_.size()) {
            const char c = t_[p_];
            if (c == '"') {
                ++p_;
                return true;
            }
            if (static_cast<unsigned char>(c) < 0x20) return fail("control character in string");
            if (c != '\\') {
                out.push_back(c);
                ++p_;
                continue;
            }
            if (++p_ >= t_.size()) break;
            const char e = t_[p_++];
            switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                uint32_t cp = 0;
                if (!hex4(cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {  // surrogate pair
                    uint32_t lo = 0;
                    if (p_ + 2 <= t_.size() && t_[p_] == '\\' && t_[p_ + 1] == 'u') {
                        p_ += 2;
                        if (!hex4(lo)) return false;
                        if (lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else cp = 0xFFFD;
                    } else {
                        cp = 0xFFFD;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = 0xFFFD;
                }
                appendUtf8(out, cp);
                break;
            }
            default: return fail("invalid escape");
            }
        }
        return fail("unterminated string");
    }
    bool array(Json& out, int depth) {
        ++p_;
        Json::Array items;
        ws();
        if (p_ < t_.size() && t_[p_] == ']') {
            ++p_;
            out = Json(std::move(items));
            return true;
        }
        for (;;) {
            ws();
            Json v;
            if (!value(v, depth + 1)) return false;
            items.push_back(std::move(v));
            ws();
            if (p_ >= t_.size()) return fail("unterminated array");
            if (t_[p_] == ',') {
                ++p_;
                continue;
            }
            if (t_[p_] == ']') {
                ++p_;
                out = Json(std::move(items));
                return true;
            }
            return fail("expected , or ]");
        }
    }
    bool object(Json& out, int depth) {
        ++p_;
        Json::Object members;
        ws();
        if (p_ < t_.size() && t_[p_] == '}') {
            ++p_;
            out = Json(std::move(members));
            return true;
        }
        for (;;) {
            ws();
            if (p_ >= t_.size() || t_[p_] != '"') return fail("expected key");
            std::string key;
            if (!string(key)) return false;
            ws();
            if (p_ >= t_.size() || t_[p_] != ':') return fail("expected :");
            ++p_;
            ws();
            Json v;
            if (!value(v, depth + 1)) return false;
            members.emplace_back(std::move(key), std::move(v));
            ws();
            if (p_ >= t_.size()) return fail("unterminated object");
            if (t_[p_] == ',') {
                ++p_;
                continue;
            }
            if (t_[p_] == '}') {
                ++p_;
                out = Json(std::move(members));
                return true;
            }
            return fail("expected , or }");
        }
    }

    std::string_view t_;
    size_t p_ = 0;
    std::string err_;
};

}  // namespace

const std::string& Json::asString() const { return type_ == Type::String ? str_ : kEmptyString; }

size_t Json::size() const {
    if (type_ == Type::Array) return arr_->size();
    if (type_ == Type::Object) return obj_->size();
    return 0;
}

const Json& Json::operator[](size_t i) const {
    if (type_ != Type::Array || i >= arr_->size()) return kNull;
    return (*arr_)[i];
}

void Json::detach() {
    if (arr_ && arr_.use_count() > 1) arr_ = std::make_shared<Array>(*arr_);
    if (obj_ && obj_.use_count() > 1) obj_ = std::make_shared<Object>(*obj_);
}

void Json::push(Json v) {
    if (type_ != Type::Array) {
        *this = Json(Array{});
    }
    detach();
    arr_->push_back(std::move(v));
}

const Json::Array& Json::items() const { return type_ == Type::Array ? *arr_ : kEmptyArray; }
const Json::Object& Json::members() const { return type_ == Type::Object ? *obj_ : kEmptyObject; }

const Json& Json::get(std::string_view key) const {
    if (type_ != Type::Object) return kNull;
    for (const auto& kv : *obj_)
        if (kv.first == key) return kv.second;
    return kNull;
}

bool Json::has(std::string_view key) const {
    if (type_ != Type::Object) return false;
    for (const auto& kv : *obj_)
        if (kv.first == key) return true;
    return false;
}

Json& Json::set(std::string key, Json v) {
    if (type_ != Type::Object) *this = Json(Object{});
    detach();
    for (auto& kv : *obj_)
        if (kv.first == key) {
            kv.second = std::move(v);
            return kv.second;
        }
    obj_->emplace_back(std::move(key), std::move(v));
    return obj_->back().second;
}

bool Json::operator==(const Json& o) const {
    if (type_ != o.type_) return false;
    switch (type_) {
    case Type::Null: return true;
    case Type::Bool: return bool_ == o.bool_;
    case Type::Number: return num_ == o.num_;
    case Type::String: return str_ == o.str_;
    case Type::Array: return *arr_ == *o.arr_;
    case Type::Object: return *obj_ == *o.obj_;
    }
    return false;
}

std::string Json::dump(bool pretty) const {
    std::string out;
    dumpTo(out, pretty, 0);
    return out;
}

void Json::dumpTo(std::string& out, bool pretty, int indent) const {
    const auto newline = [&](int level) {
        if (!pretty) return;
        out.push_back('\n');
        out.append(static_cast<size_t>(level) * 2, ' ');
    };
    switch (type_) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += bool_ ? "true" : "false"; break;
    case Type::Number: {
        if (!std::isfinite(num_)) {
            out += "null";  // JSON has no NaN/Inf
        } else if (integral_ && std::fabs(num_) < 9.007199254740992e15) {
            out += std::to_string(static_cast<long long>(num_));
        } else {
            char buf[32];
            std::snprintf(buf, sizeof buf, "%.17g", num_);
            out += buf;
        }
        break;
    }
    case Type::String: json::appendQuoted(out, str_); break;
    case Type::Array: {
        out.push_back('[');
        for (size_t i = 0; i < arr_->size(); ++i) {
            if (i) out.push_back(',');
            newline(indent + 1);
            (*arr_)[i].dumpTo(out, pretty, indent + 1);
        }
        if (!arr_->empty()) newline(indent);
        out.push_back(']');
        break;
    }
    case Type::Object: {
        out.push_back('{');
        for (size_t i = 0; i < obj_->size(); ++i) {
            if (i) out.push_back(',');
            newline(indent + 1);
            json::appendQuoted(out, (*obj_)[i].first);
            out += pretty ? ": " : ":";
            (*obj_)[i].second.dumpTo(out, pretty, indent + 1);
        }
        if (!obj_->empty()) newline(indent);
        out.push_back('}');
        break;
    }
    }
}

bool Json::parse(std::string_view text, Json& out, std::string* error) {
    Parser p(text);
    Json v;
    if (!p.parseDocument(v, error)) return false;
    out = std::move(v);
    return true;
}

namespace json {

void appendQuoted(std::string& out, std::string_view s) {
    out.push_back('"');
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
            }
            ++i;
            continue;
        }
        const size_t n = utf8SeqLen(s, i);
        if (n == 0) {
            out += "\xEF\xBF\xBD";  // U+FFFD for each invalid byte
            ++i;
        } else {
            out.append(s.data() + i, n);
            i += n;
        }
    }
    out.push_back('"');
}

std::string sanitizeUtf8(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        const size_t n = utf8SeqLen(s, i);
        if (n == 0) {
            out += "\xEF\xBF\xBD";
            ++i;
        } else {
            out.append(s.data() + i, n);
            i += n;
        }
    }
    return out;
}

}  // namespace json
