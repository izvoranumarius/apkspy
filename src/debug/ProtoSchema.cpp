#include "debug/ProtoSchema.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"

namespace protoschema {

namespace {

// ---- tokenizer ---------------------------------------------------------------

struct Tok {
    std::string text;
    int line = 0;
    bool str = false;
};

std::vector<Tok> tokenize(const std::string& s) {
    std::vector<Tok> out;
    int line = 1;
    size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (c == '\n') {
            ++line, ++i;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '/') {
            while (i < s.size() && s[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < s.size() && !(s[i] == '*' && s[i + 1] == '/')) line += s[i++] == '\n';
            i += 2;
            continue;
        }
        if (c == '"' || c == '\'') {
            std::string v;
            ++i;
            while (i < s.size() && s[i] != c) {
                if (s[i] == '\\' && i + 1 < s.size()) ++i;
                v += s[i++];
            }
            ++i;
            out.push_back({v, line, true});
            continue;
        }
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' ||
            (c == '-' && i + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1])))) {
            std::string v(1, c);
            ++i;
            while (i < s.size() && (std::isalnum(static_cast<unsigned char>(s[i])) || s[i] == '_' || s[i] == '.')) v += s[i++];
            out.push_back({v, line, false});
            continue;
        }
        out.push_back({std::string(1, c), line, false});
        ++i;
    }
    return out;
}

class Parser {
public:
    Parser(std::vector<Tok> t, std::map<std::string, Message>& msgs, std::map<std::string, Enum>& enums)
        : t_(std::move(t)), msgs_(msgs), enums_(enums) {}

    bool parseFile(std::string& error) {
        while (pos_ < t_.size()) {
            const std::string& w = cur();
            if (w == "syntax" || w == "edition" || w == "import" || w == "option") skipStatement();
            else if (w == "package") {
                ++pos_;
                package_ = cur();
                skipStatement();
            } else if (w == "message") {
                if (!parseMessage(package_)) break;
            } else if (w == "enum") {
                if (!parseEnum(package_)) break;
            } else if (w == "service" || w == "extend") skipBlock();
            else ++pos_;  // ';' and anything unknown
        }
        if (!error_.empty()) error = error_;
        return error_.empty();
    }

private:
    const std::string& cur() const {
        static const std::string kEnd;
        return pos_ < t_.size() ? t_[pos_].text : kEnd;
    }
    bool fail(const std::string& why) {
        if (error_.empty()) error_ = "line " + std::to_string(pos_ < t_.size() ? t_[pos_].line : 0) + ": " + why;
        return false;
    }
    bool expect(const char* s) {
        if (cur() != s) return fail(std::string("expected '") + s + "', found '" + cur() + "'");
        ++pos_;
        return true;
    }
    // Up to and including ';' (aggregate option values in braces are skipped whole).
    void skipStatement() {
        int depth = 0;
        while (pos_ < t_.size()) {
            const std::string& w = t_[pos_++].text;
            if (t_[pos_ - 1].str) continue;
            if (w == "{") ++depth;
            else if (w == "}") --depth;
            else if (w == ";" && depth <= 0) return;
        }
    }
    // A name, then a balanced { ... } block.
    void skipBlock() {
        while (pos_ < t_.size() && cur() != "{") ++pos_;
        int depth = 0;
        while (pos_ < t_.size()) {
            const std::string& w = t_[pos_++].text;
            if (t_[pos_ - 1].str) continue;
            if (w == "{") ++depth;
            else if (w == "}" && --depth == 0) return;
        }
    }
    static std::string join(const std::string& a, const std::string& b) { return a.empty() ? b : a + "." + b; }

    bool parseEnum(const std::string& scope) {
        ++pos_;  // "enum"
        Enum e;
        e.fullName = join(scope, cur());
        ++pos_;
        if (!expect("{")) return false;
        while (pos_ < t_.size() && cur() != "}") {
            if (cur() == "option" || cur() == "reserved") {
                skipStatement();
                continue;
            }
            if (cur() == ";") {
                ++pos_;
                continue;
            }
            const std::string name = cur();
            ++pos_;
            if (!expect("=")) return false;
            const int value = static_cast<int>(std::strtol(cur().c_str(), nullptr, 0));
            ++pos_;
            e.values.emplace(value, name);  // the first name wins for aliases
            skipStatement();
        }
        ++pos_;  // "}"
        enums_[e.fullName] = std::move(e);
        return true;
    }

    bool parseField(Message& m, const std::string& label) {
        Field f;
        f.scope = m.fullName;
        f.repeated = label == "repeated";
        if (cur() == "map") {
            ++pos_;
            if (!expect("<")) return false;
            f.keyType = cur();
            ++pos_;
            if (!expect(",")) return false;
            f.valueType = cur();
            ++pos_;
            if (!expect(">")) return false;
            f.isMap = true;
            f.repeated = true;
            f.type = "map";
        } else {
            f.type = cur();
            ++pos_;
        }
        f.name = cur();
        ++pos_;
        if (!expect("=")) return false;
        f.number = static_cast<int>(std::strtol(cur().c_str(), nullptr, 0));
        ++pos_;
        skipStatement();  // [options] ;
        if (f.number > 0) m.fields[f.number] = std::move(f);
        return true;
    }

    bool parseMessage(const std::string& scope) {
        ++pos_;  // "message"
        Message m;
        m.fullName = join(scope, cur());
        ++pos_;
        if (!expect("{")) return false;
        while (pos_ < t_.size() && cur() != "}") {
            const std::string w = cur();
            if (w == "message") {
                if (!parseMessage(m.fullName)) return false;
            } else if (w == "enum") {
                if (!parseEnum(m.fullName)) return false;
            } else if (w == "oneof") {
                ++pos_;
                ++pos_;  // name
                if (!expect("{")) return false;
                while (pos_ < t_.size() && cur() != "}") {
                    if (cur() == "option") skipStatement();
                    else if (cur() == ";") ++pos_;
                    else if (!parseField(m, "")) return false;
                }
                ++pos_;
            } else if (w == "option" || w == "reserved" || w == "extensions") {
                skipStatement();
            } else if (w == "extend" || w == "group") {
                skipBlock();
            } else if (w == ";") {
                ++pos_;
            } else if (w == "repeated" || w == "optional" || w == "required") {
                ++pos_;
                if (!parseField(m, w)) return false;
            } else if (!parseField(m, "")) {
                return false;
            }
        }
        if (pos_ >= t_.size()) return fail("missing '}' for message " + m.fullName);
        ++pos_;
        msgs_[m.fullName] = std::move(m);
        return true;
    }

    std::vector<Tok> t_;  // owned: the tokens of one file
    std::map<std::string, Message>& msgs_;
    std::map<std::string, Enum>& enums_;
    std::string package_;
    size_t pos_ = 0;
    std::string error_;
};

// ---- wire format ---------------------------------------------------------------

using u8 = unsigned char;

bool readVarint(const u8*& p, const u8* end, uint64_t& v) {
    v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (p >= end) return false;
        const u8 b = *p++;
        v |= static_cast<uint64_t>(b & 0x7f) << shift;
        if (!(b & 0x80)) return true;
    }
    return false;
}

struct Raw {
    uint64_t number = 0;
    int wire = 0;
    uint64_t value = 0;
    std::string bytes;
};

bool parseRaw(const std::string& s, std::vector<Raw>& out) {
    const u8* p = reinterpret_cast<const u8*>(s.data());
    const u8* end = p + s.size();
    while (p < end) {
        uint64_t key;
        if (!readVarint(p, end, key)) return false;
        Raw f;
        f.number = key >> 3;
        f.wire = static_cast<int>(key & 7);
        if (f.number == 0 || f.number > 536870911) return false;
        if (f.wire == 0) {
            if (!readVarint(p, end, f.value)) return false;
        } else if (f.wire == 1 || f.wire == 5) {
            const int n = f.wire == 1 ? 8 : 4;
            if (end - p < n) return false;
            for (int i = n - 1; i >= 0; --i) f.value = f.value << 8 | p[i];
            p += n;
        } else if (f.wire == 2) {
            uint64_t len;
            if (!readVarint(p, end, len) || len > static_cast<uint64_t>(end - p)) return false;
            f.bytes.assign(reinterpret_cast<const char*>(p), static_cast<size_t>(len));
            p += len;
        } else
            return false;
        out.push_back(std::move(f));
    }
    return true;
}

bool printable(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
    return true;
}

std::string quote(const std::string& s) {
    std::string o = "\"";
    for (size_t i = 0; i < s.size() && i < 4096; ++i) {
        const char c = s[i];
        if (c == '"' || c == '\\') o += '\\', o += c;
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o + (s.size() > 4096 ? "...\"" : "\"");
}

std::string hexBytes(const std::string& s) {
    static const char* kHex = "0123456789abcdef";
    std::string o = "<";
    for (size_t i = 0; i < s.size() && i < 64; ++i) {
        if (i) o += ' ';
        o += kHex[static_cast<u8>(s[i]) >> 4];
        o += kHex[static_cast<u8>(s[i]) & 15];
    }
    return o + (s.size() > 64 ? " ...>" : ">");
}

bool isScalar(const std::string& t) {
    static const char* kTypes[] = {"double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64",
                                   "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes"};
    for (const char* k : kTypes)
        if (t == k) return true;
    return false;
}

// A scalar of `type` from a varint / fixed value.
std::string scalar(const std::string& type, uint64_t v, int wire) {
    char buf[64];
    if (type == "bool") return v ? "true" : "false";
    if (type == "sint32" || type == "sint64") return std::to_string(static_cast<int64_t>(v >> 1) ^ -static_cast<int64_t>(v & 1));
    if (type == "int32") return std::to_string(static_cast<int32_t>(v));
    if (type == "int64" || type == "sfixed64") return std::to_string(static_cast<int64_t>(v));
    if (type == "sfixed32") return std::to_string(static_cast<int32_t>(static_cast<uint32_t>(v)));
    if (type == "double" && wire == 1) {
        double d;
        std::memcpy(&d, &v, 8);
        std::snprintf(buf, sizeof buf, "%.17g", d);
        return buf;
    }
    if (type == "float" && wire == 5) {
        float f;
        const uint32_t v32 = static_cast<uint32_t>(v);
        std::memcpy(&f, &v32, 4);
        std::snprintf(buf, sizeof buf, "%.9g", static_cast<double>(f));
        return buf;
    }
    return std::to_string(v);
}

std::string pad(int depth) { return std::string(static_cast<size_t>(depth) * 2, ' '); }

}  // namespace

bool Schema::addSource(const std::string& text, const std::string& fileName, std::string& error) {
    std::map<std::string, Message> msgs;
    std::map<std::string, Enum> enums;
    Parser p(tokenize(text), msgs, enums);
    if (!p.parseFile(error)) {
        error = fileName + ": " + error;
        return false;
    }
    for (auto& [k, v] : msgs) messages_[k] = std::move(v);
    for (auto& [k, v] : enums) enums_[k] = std::move(v);
    return true;
}

size_t Schema::addDirectory(const std::string& dir, std::vector<std::string>& errors) {
    namespace fs = std::filesystem;
    size_t n = 0;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(pathutil::fromUtf8(dir), ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_regular_file(ec) || it->path().extension() != ".proto") continue;
        std::ifstream in(it->path(), std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        std::string error;
        if (addSource(ss.str(), pathutil::toUtf8(it->path().filename()), error)) ++n;
        else errors.push_back(error);
    }
    return n;
}

std::vector<std::string> Schema::messageNames() const {
    std::vector<std::string> out;
    for (const auto& [k, v] : messages_) out.push_back(k);
    return out;
}

const Message* Schema::message(const std::string& fullName) const {
    const auto it = messages_.find(fullName);
    return it == messages_.end() ? nullptr : &it->second;
}

const Message* Schema::resolveMessage(const std::string& type, const std::string& scope) const {
    if (!type.empty() && type[0] == '.') return message(type.substr(1));
    std::string s = scope;
    for (;;) {
        if (const Message* m = message(s.empty() ? type : s + "." + type)) return m;
        if (s.empty()) return nullptr;
        const size_t dot = s.rfind('.');
        s = dot == std::string::npos ? std::string() : s.substr(0, dot);
    }
}

const Enum* Schema::resolveEnum(const std::string& type, const std::string& scope) const {
    const auto find = [&](const std::string& n) -> const Enum* {
        const auto it = enums_.find(n);
        return it == enums_.end() ? nullptr : &it->second;
    };
    if (!type.empty() && type[0] == '.') return find(type.substr(1));
    std::string s = scope;
    for (;;) {
        if (const Enum* e = find(s.empty() ? type : s + "." + type)) return e;
        if (s.empty()) return nullptr;
        const size_t dot = s.rfind('.');
        s = dot == std::string::npos ? std::string() : s.substr(0, dot);
    }
}

bool Schema::decode(const std::string& bytes, const std::string& fullName, std::string& out) const {
    const Message* m = message(fullName);
    if (!m) return false;
    out = "(" + fullName + ")\n";
    return decodeInto(bytes, *m, 0, out);
}

bool Schema::decodeInto(const std::string& bytes, const Message& m, int depth, std::string& out) const {
    std::vector<Raw> raw;
    if (!parseRaw(bytes, raw) || depth > 40) return false;
    // A value of `type` (message, enum or scalar) from one wire field.
    const auto value = [&](const std::string& type, const std::string& scope, const Raw& r, int d, std::string& o) {
        if (r.wire == 2) {
            if (const Message* sub = resolveMessage(type, scope)) {
                std::string inner;
                if (decodeInto(r.bytes, *sub, d + 1, inner)) {
                    o += "{\n" + inner + pad(d) + "}";
                    return;
                }
            }
            if (type == "string" || (type != "bytes" && printable(r.bytes))) o += quote(r.bytes);
            else o += hexBytes(r.bytes) + " (" + std::to_string(r.bytes.size()) + " bytes)";
            return;
        }
        if (const Enum* e = resolveEnum(type, scope)) {
            const auto it = e->values.find(static_cast<int>(r.value));
            o += it == e->values.end() ? std::to_string(static_cast<int32_t>(r.value)) : it->second;
            return;
        }
        o += scalar(type, r.value, r.wire);
    };
    for (const Raw& r : raw) {
        if (out.size() > (512u << 10)) break;
        const auto it = m.fields.find(static_cast<int>(r.number));
        if (it == m.fields.end()) {
            out += pad(depth) + std::to_string(r.number) + ": ";
            if (r.wire == 2) out += printable(r.bytes) ? quote(r.bytes) : hexBytes(r.bytes);
            else out += std::to_string(r.value);
            out += "  (unknown field)\n";
            continue;
        }
        const Field& f = it->second;
        out += pad(depth) + f.name;
        if (f.isMap && r.wire == 2) {
            // An entry message: key = 1, value = 2.
            std::vector<Raw> entry;
            std::string key = "?", val;
            if (parseRaw(r.bytes, entry)) {
                for (const Raw& e : entry) {
                    if (e.number == 1) {
                        key.clear();
                        value(f.keyType, f.scope, e, depth, key);
                    } else if (e.number == 2) {
                        val.clear();
                        value(f.valueType, f.scope, e, depth, val);
                    }
                }
            }
            out += "[" + key + "]: " + val + "\n";
            continue;
        }
        // Packed repeated scalars: one length-delimited field holding them all.
        if (f.repeated && r.wire == 2 && isScalar(f.type) && f.type != "string" && f.type != "bytes") {
            out += ": [";
            const u8* p = reinterpret_cast<const u8*>(r.bytes.data());
            const u8* end = p + r.bytes.size();
            const bool fixed64 = f.type == "fixed64" || f.type == "sfixed64" || f.type == "double";
            const bool fixed32 = f.type == "fixed32" || f.type == "sfixed32" || f.type == "float";
            bool first = true;
            while (p < end) {
                uint64_t v = 0;
                int wire = 0;
                if (fixed64 || fixed32) {
                    const int n = fixed64 ? 8 : 4;
                    if (end - p < n) break;
                    for (int i = n - 1; i >= 0; --i) v = v << 8 | p[i];
                    p += n;
                    wire = fixed64 ? 1 : 5;
                } else if (!readVarint(p, end, v))
                    break;
                out += (first ? "" : ", ") + scalar(f.type, v, wire);
                first = false;
            }
            out += "]\n";
            continue;
        }
        out += ": ";
        value(f.type, f.scope, r, depth, out);
        out += "\n";
    }
    return true;
}

}  // namespace protoschema
