#include "debug/ContentView.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <miniz.h>
#include "core/Codec.hpp"
#include "core/TextUtils.hpp"
#include "debug/ProtoSchema.hpp"
#include "mcp/Json.hpp"

namespace contentview {

namespace {

using u8 = unsigned char;

std::string indent(int depth) { return std::string(static_cast<size_t>(depth) * 2, ' '); }

// Valid UTF-8 without control characters (tabs and line breaks allowed).
bool printableUtf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        const u8 c = static_cast<u8>(s[i]);
        if (c < 0x80) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
            if (c == 0x7f) return false;
            ++i;
            continue;
        }
        int extra = (c & 0xe0) == 0xc0 ? 1 : (c & 0xf0) == 0xe0 ? 2 : (c & 0xf8) == 0xf0 ? 3 : -1;
        if (extra < 0 || i + static_cast<size_t>(extra) >= s.size()) return false;
        for (int k = 1; k <= extra; ++k)
            if ((static_cast<u8>(s[i + static_cast<size_t>(k)]) & 0xc0) != 0x80) return false;
        i += static_cast<size_t>(extra) + 1;
    }
    return true;
}

bool looksBinary(const std::string& body) {
    size_t binary = 0;
    const size_t n = std::min<size_t>(body.size(), 4096);
    for (size_t i = 0; i < n; ++i) {
        const u8 c = static_cast<u8>(body[i]);
        if (c < 9 || (c > 13 && c < 32)) ++binary;
    }
    return binary > std::max<size_t>(2, n / 64);
}

std::string quoted(const std::string& s, size_t cap = 4096) {
    std::string out = "\"";
    for (size_t i = 0; i < s.size() && i < cap; ++i) {
        const char c = s[i];
        if (c == '"' || c == '\\') out += '\\', out += c;
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    if (s.size() > cap) out += "...";
    return out + "\"";
}

std::string shortHex(const std::string& s, size_t cap = 64) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < s.size() && i < cap; ++i) {
        if (i) out += ' ';
        out += kHex[static_cast<u8>(s[i]) >> 4];
        out += kHex[static_cast<u8>(s[i]) & 15];
    }
    if (s.size() > cap) out += " ...";
    return out;
}

// gzip / zlib / raw deflate -> bytes ("" when it does not inflate).
std::string inflateAny(const std::string& in) {
    const auto* d = reinterpret_cast<const u8*>(in.data());
    size_t start = 0;
    int flags = 0;
    if (in.size() > 18 && d[0] == 0x1f && d[1] == 0x8b) {
        const u8 flg = d[3];
        start = 10;
        if (flg & 4) start += 2 + static_cast<size_t>(d[start] | d[start + 1] << 8);
        if (flg & 8) while (start < in.size() && d[start++]) {}
        if (flg & 16) while (start < in.size() && d[start++]) {}
        if (flg & 2) start += 2;
    } else if (in.size() > 2 && (d[0] & 0x0F) == 8 && ((d[0] << 8 | d[1]) % 31) == 0) {
        flags = TINFL_FLAG_PARSE_ZLIB_HEADER;
    }
    if (start >= in.size()) return {};
    size_t outLen = 0;
    void* p = tinfl_decompress_mem_to_heap(d + start, in.size() - start, &outLen, flags);
    if (!p) return {};
    std::string out(static_cast<const char*>(p), std::min<size_t>(outLen, 16u << 20));
    mz_free(p);
    return out;
}

// ---- protobuf --------------------------------------------------------------

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

struct PbField {
    uint64_t number = 0;
    int wire = 0;
    uint64_t value = 0;  // varint / fixed
    std::string bytes;   // length-delimited
};

// Strict: the whole input must parse, with sane field numbers and no groups.
bool parsePb(const std::string& s, std::vector<PbField>& out) {
    const u8* p = reinterpret_cast<const u8*>(s.data());
    const u8* end = p + s.size();
    while (p < end) {
        uint64_t key;
        if (!readVarint(p, end, key)) return false;
        PbField f;
        f.number = key >> 3;
        f.wire = static_cast<int>(key & 7);
        if (f.number == 0 || f.number > 536870911) return false;
        switch (f.wire) {
            case 0:
                if (!readVarint(p, end, f.value)) return false;
                break;
            case 1:
                if (end - p < 8) return false;
                for (int i = 7; i >= 0; --i) f.value = f.value << 8 | p[i];
                p += 8;
                break;
            case 5:
                if (end - p < 4) return false;
                for (int i = 3; i >= 0; --i) f.value = f.value << 8 | p[i];
                p += 4;
                break;
            case 2: {
                uint64_t len;
                if (!readVarint(p, end, len) || len > static_cast<uint64_t>(end - p)) return false;
                f.bytes.assign(reinterpret_cast<const char*>(p), static_cast<size_t>(len));
                p += len;
                break;
            }
            default:
                return false;  // groups (3/4) and reserved types: not decoded
        }
        out.push_back(std::move(f));
    }
    return true;
}

void dumpPb(const std::vector<PbField>& fields, int depth, std::string& out) {
    for (const auto& f : fields) {
        if (out.size() > kMaxOutput) return;
        out += indent(depth) + std::to_string(f.number) + ": ";
        char buf[96];
        switch (f.wire) {
            case 0: {
                out += std::to_string(f.value);
                const int64_t asSigned = static_cast<int64_t>(f.value);
                if (asSigned < 0) out += "  (int64 " + std::to_string(asSigned) + ")";
                else if (f.value > 1 && (f.value & 1)) {
                    const int64_t zz = static_cast<int64_t>(f.value >> 1) ^ -static_cast<int64_t>(f.value & 1);
                    out += "  (sint " + std::to_string(zz) + ")";
                }
                out += '\n';
                break;
            }
            case 1: {
                double d;
                std::memcpy(&d, &f.value, 8);
                std::snprintf(buf, sizeof buf, "0x%016llx", static_cast<unsigned long long>(f.value));
                out += buf;
                if (std::isfinite(d) && std::fabs(d) > 1e-12 && std::fabs(d) < 1e15) {
                    std::snprintf(buf, sizeof buf, "  (double %.10g)", d);
                    out += buf;
                }
                out += "  (fixed64)\n";
                break;
            }
            case 5: {
                float fl;
                const uint32_t v32 = static_cast<uint32_t>(f.value);
                std::memcpy(&fl, &v32, 4);
                out += std::to_string(v32);
                if (std::isfinite(fl) && std::fabs(fl) > 1e-6f && std::fabs(fl) < 1e9f) {
                    std::snprintf(buf, sizeof buf, "  (float %.7g)", static_cast<double>(fl));
                    out += buf;
                }
                out += "  (fixed32)\n";
                break;
            }
            case 2: {
                std::vector<PbField> nested;
                if (f.bytes.empty()) out += "\"\"\n";
                else if (printableUtf8(f.bytes)) out += quoted(f.bytes) + '\n';
                else if (depth < 24 && parsePb(f.bytes, nested) && !nested.empty()) {
                    out += "{\n";
                    dumpPb(nested, depth + 1, out);
                    out += indent(depth) + "}\n";
                } else
                    out += "<" + shortHex(f.bytes) + ">  (" + std::to_string(f.bytes.size()) + " bytes)\n";
                break;
            }
        }
    }
}

// ---- msgpack ---------------------------------------------------------------

struct MpReader {
    const u8* p;
    const u8* end;
    bool need(size_t n) const { return static_cast<size_t>(end - p) >= n; }
    uint64_t be(int n) {
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v = v << 8 | *p++;
        return v;
    }
};

bool mpValue(MpReader& r, int depth, std::string& out);

bool mpString(MpReader& r, size_t len, bool binary, std::string& out) {
    if (!r.need(len)) return false;
    const std::string s(reinterpret_cast<const char*>(r.p), len);
    r.p += len;
    out += binary || !printableUtf8(s) ? "<" + shortHex(s) + "> (" + std::to_string(len) + " bytes)" : quoted(s);
    return true;
}

bool mpArray(MpReader& r, size_t n, int depth, std::string& out) {
    if (n == 0) return out += "[]", true;
    out += "[\n";
    for (size_t i = 0; i < n; ++i) {
        out += indent(depth + 1);
        if (!mpValue(r, depth + 1, out)) return false;
        out += i + 1 < n ? ",\n" : "\n";
        if (out.size() > kMaxOutput) return true;
    }
    out += indent(depth) + "]";
    return true;
}

bool mpMap(MpReader& r, size_t n, int depth, std::string& out) {
    if (n == 0) return out += "{}", true;
    out += "{\n";
    for (size_t i = 0; i < n; ++i) {
        out += indent(depth + 1);
        if (!mpValue(r, depth + 1, out)) return false;
        out += ": ";
        if (!mpValue(r, depth + 1, out)) return false;
        out += i + 1 < n ? ",\n" : "\n";
        if (out.size() > kMaxOutput) return true;
    }
    out += indent(depth) + "}";
    return true;
}

bool mpValue(MpReader& r, int depth, std::string& out) {
    if (depth > 64 || !r.need(1)) return false;
    const u8 t = *r.p++;
    char buf[64];
    if (t <= 0x7f) return out += std::to_string(t), true;
    if (t >= 0xe0) return out += std::to_string(static_cast<int>(static_cast<int8_t>(t))), true;
    if ((t & 0xf0) == 0x80) return mpMap(r, t & 0x0f, depth, out);
    if ((t & 0xf0) == 0x90) return mpArray(r, t & 0x0f, depth, out);
    if ((t & 0xe0) == 0xa0) return mpString(r, t & 0x1f, false, out);
    switch (t) {
        case 0xc0: return out += "null", true;
        case 0xc2: return out += "false", true;
        case 0xc3: return out += "true", true;
        case 0xc4: case 0xc5: case 0xc6: {
            const int n = t == 0xc4 ? 1 : t == 0xc5 ? 2 : 4;
            if (!r.need(static_cast<size_t>(n))) return false;
            return mpString(r, static_cast<size_t>(r.be(n)), true, out);
        }
        case 0xd9: case 0xda: case 0xdb: {
            const int n = t == 0xd9 ? 1 : t == 0xda ? 2 : 4;
            if (!r.need(static_cast<size_t>(n))) return false;
            return mpString(r, static_cast<size_t>(r.be(n)), false, out);
        }
        case 0xca: {
            if (!r.need(4)) return false;
            const uint32_t v = static_cast<uint32_t>(r.be(4));
            float f;
            std::memcpy(&f, &v, 4);
            std::snprintf(buf, sizeof buf, "%.7g", static_cast<double>(f));
            return out += buf, true;
        }
        case 0xcb: {
            if (!r.need(8)) return false;
            const uint64_t v = r.be(8);
            double d;
            std::memcpy(&d, &v, 8);
            std::snprintf(buf, sizeof buf, "%.15g", d);
            return out += buf, true;
        }
        case 0xcc: case 0xcd: case 0xce: case 0xcf: {
            const int n = 1 << (t - 0xcc);
            if (!r.need(static_cast<size_t>(n))) return false;
            return out += std::to_string(r.be(n)), true;
        }
        case 0xd0: case 0xd1: case 0xd2: case 0xd3: {
            const int n = 1 << (t - 0xd0);
            if (!r.need(static_cast<size_t>(n))) return false;
            uint64_t v = r.be(n);
            const int bits = n * 8;
            int64_t s = bits == 64 ? static_cast<int64_t>(v)
                                   : static_cast<int64_t>(v << (64 - bits)) >> (64 - bits);
            return out += std::to_string(s), true;
        }
        case 0xdc: case 0xdd: {
            const int n = t == 0xdc ? 2 : 4;
            if (!r.need(static_cast<size_t>(n))) return false;
            return mpArray(r, static_cast<size_t>(r.be(n)), depth, out);
        }
        case 0xde: case 0xdf: {
            const int n = t == 0xde ? 2 : 4;
            if (!r.need(static_cast<size_t>(n))) return false;
            return mpMap(r, static_cast<size_t>(r.be(n)), depth, out);
        }
        case 0xd4: case 0xd5: case 0xd6: case 0xd7: case 0xd8:
        case 0xc7: case 0xc8: case 0xc9: {
            size_t len;
            if (t >= 0xd4) len = static_cast<size_t>(1) << (t - 0xd4);
            else {
                const int n = t == 0xc7 ? 1 : t == 0xc8 ? 2 : 4;
                if (!r.need(static_cast<size_t>(n))) return false;
                len = static_cast<size_t>(r.be(n));
            }
            if (!r.need(1 + len)) return false;
            const int type = static_cast<int8_t>(*r.p++);
            const std::string data(reinterpret_cast<const char*>(r.p), len);
            r.p += len;
            out += "ext(" + std::to_string(type) + ", <" + shortHex(data) + ">)";
            return true;
        }
        default:
            return false;  // 0xc1: never used
    }
}

// ---- images ------------------------------------------------------------------

uint32_t be32(const u8* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
uint32_t le16(const u8* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8; }
uint32_t le24(const u8* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16; }
uint32_t le32(const u8* p) { return le24(p) | uint32_t(p[3]) << 24; }

std::string headerParam(const std::string& contentType, const char* name) {
    const std::string lower = tex::asciiLower(contentType);
    const std::string key = std::string(name) + "=";
    size_t at = lower.find(key);
    if (at == std::string::npos) return {};
    at += key.size();
    std::string v;
    if (at < contentType.size() && contentType[at] == '"') {
        const size_t close = contentType.find('"', at + 1);
        v = contentType.substr(at + 1, close == std::string::npos ? std::string::npos : close - at - 1);
    } else {
        const size_t endp = contentType.find_first_of("; \t", at);
        v = contentType.substr(at, endp == std::string::npos ? std::string::npos : endp - at);
    }
    return v;
}

std::string capOutput(std::string s, std::string& note) {
    if (s.size() > kMaxOutput) {
        s.resize(kMaxOutput);
        s += "\n...";
        note += (note.empty() ? "" : "; ") + std::string("output cut at 512 KB");
    }
    return s;
}

}  // namespace

const char* viewName(View v) {
    switch (v) {
        case View::Auto: return "Auto";
        case View::Text: return "Text";
        case View::Json: return "JSON";
        case View::Xml: return "XML / HTML";
        case View::Form: return "URL-encoded form";
        case View::Multipart: return "Multipart form";
        case View::Protobuf: return "Protobuf";
        case View::Grpc: return "gRPC";
        case View::MsgPack: return "MessagePack";
        case View::Image: return "Image";
        case View::Hex: return "Hex";
        case View::Jwt: return "JWT";
        case View::GraphQL: return "GraphQL";
        case View::Cbor: return "CBOR";
        case View::Dns: return "DNS";
    }
    return "?";
}

std::string urlDecode(const std::string& s, bool plusIsSpace) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '+' && plusIsSpace) out += ' ';
        else if (c == '%' && i + 2 < s.size() && std::isxdigit(static_cast<u8>(s[i + 1])) &&
                 std::isxdigit(static_cast<u8>(s[i + 2]))) {
            out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else
            out += c;
    }
    return out;
}

std::string hexDump(const std::string& bytes, size_t maxBytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    const size_t n = std::min(bytes.size(), maxBytes);
    out.reserve(n / 16 * 78 + 80);
    for (size_t row = 0; row < n; row += 16) {
        char off[16];
        std::snprintf(off, sizeof off, "%08zx  ", row);
        out += off;
        for (size_t i = 0; i < 16; ++i) {
            if (row + i < n) {
                const u8 c = static_cast<u8>(bytes[row + i]);
                out += kHex[c >> 4];
                out += kHex[c & 15];
                out += ' ';
            } else
                out += "   ";
            if (i == 7) out += ' ';
        }
        out += " |";
        for (size_t i = 0; i < 16 && row + i < n; ++i) {
            const u8 c = static_cast<u8>(bytes[row + i]);
            out += c >= 32 && c < 127 ? static_cast<char>(c) : '.';
        }
        out += "|\n";
    }
    if (bytes.size() > n) out += "... (" + std::to_string(bytes.size() - n) + " more bytes)\n";
    return out;
}

bool prettyJson(const std::string& body, std::string& out) {
    Json j;
    size_t start = 0;
    while (start < body.size() && std::isspace(static_cast<u8>(body[start]))) ++start;
    if (start >= body.size() || (body[start] != '{' && body[start] != '[' && body[start] != '"')) return false;
    if (!Json::parse(body, j)) return false;
    out = j.dump(true);
    return true;
}

std::string prettyXml(const std::string& body) {
    struct Tok {
        bool tag;
        std::string text;
    };
    std::vector<Tok> toks;
    size_t i = 0;
    while (i < body.size()) {
        if (body[i] == '<') {
            size_t end;
            if (body.compare(i, 4, "<!--") == 0) end = body.find("-->", i), end = end == std::string::npos ? body.size() : end + 3;
            else if (body.compare(i, 9, "<![CDATA[") == 0) end = body.find("]]>", i), end = end == std::string::npos ? body.size() : end + 3;
            else {
                // A '>' inside a quoted attribute does not end the tag.
                end = i + 1;
                char q = 0;
                while (end < body.size() && (q || body[end] != '>')) {
                    if (q && body[end] == q) q = 0;
                    else if (!q && (body[end] == '"' || body[end] == '\'')) q = body[end];
                    ++end;
                }
                end = std::min(end + 1, body.size());
            }
            toks.push_back({true, body.substr(i, end - i)});
            i = end;
        } else {
            const size_t end = std::min(body.find('<', i), body.size());
            std::string t = body.substr(i, end - i);
            const size_t a = t.find_first_not_of(" \t\r\n"), b = t.find_last_not_of(" \t\r\n");
            if (a != std::string::npos) toks.push_back({false, t.substr(a, b - a + 1)});
            i = end;
        }
    }
    static const char* kVoid[] = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                                  "link", "meta", "param", "source", "track", "wbr"};
    const auto tagName = [](const std::string& t) {
        size_t s = 1;
        if (s < t.size() && t[s] == '/') ++s;
        size_t e = s;
        while (e < t.size() && !std::isspace(static_cast<u8>(t[e])) && t[e] != '>' && t[e] != '/') ++e;
        return tex::asciiLower(t.substr(s, e - s));
    };
    const auto opens = [&](const std::string& t) {
        if (t.size() < 2 || t[1] == '/' || t[1] == '!' || t[1] == '?') return false;
        if (t.size() >= 2 && t[t.size() - 2] == '/') return false;  // <x/>
        const std::string name = tagName(t);
        for (const char* v : kVoid)
            if (name == v) return false;
        return true;
    };
    std::string out;
    int depth = 0;
    for (size_t k = 0; k < toks.size() && out.size() <= kMaxOutput; ++k) {
        const Tok& t = toks[k];
        if (t.tag && t.text.size() > 1 && t.text[1] == '/') {
            depth = std::max(0, depth - 1);
            out += indent(depth) + t.text + '\n';
        } else if (t.tag && opens(t.text)) {
            // <a>text</a> stays on one line.
            if (k + 2 < toks.size() && !toks[k + 1].tag && toks[k + 2].tag && toks[k + 2].text.size() > 1 &&
                toks[k + 2].text[1] == '/' && tagName(toks[k + 2].text) == tagName(t.text) && toks[k + 1].text.size() < 200) {
                out += indent(depth) + t.text + toks[k + 1].text + toks[k + 2].text + '\n';
                k += 2;
                continue;
            }
            out += indent(depth) + t.text + '\n';
            ++depth;
        } else {
            out += indent(depth) + t.text + '\n';
        }
    }
    return out;
}

bool formFields(const std::string& body, std::string& out) {
    if (body.empty() || body.find('=') == std::string::npos) return false;
    for (char c : body)
        if (static_cast<u8>(c) < 32 && c != '\r' && c != '\n') return false;
    out.clear();
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t amp = body.find('&', pos);
        if (amp == std::string::npos) amp = body.size();
        const std::string pair = body.substr(pos, amp - pos);
        if (!pair.empty()) {
            const size_t eq = pair.find('=');
            const std::string key = urlDecode(pair.substr(0, eq));
            const std::string value = eq == std::string::npos ? std::string() : urlDecode(pair.substr(eq + 1));
            out += key + ": " + (printableUtf8(value) ? value : "<" + shortHex(value) + ">") + '\n';
        }
        pos = amp + 1;
    }
    return !out.empty();
}

bool multipart(const std::string& body, const std::string& contentType, std::string& out) {
    std::string boundary = headerParam(contentType, "boundary");
    if (boundary.empty()) {
        // Sniff it from the first line ("--boundary").
        if (body.rfind("--", 0) != 0) return false;
        const size_t eol = body.find("\r\n");
        if (eol == std::string::npos) return false;
        boundary = body.substr(2, eol - 2);
    }
    const std::string delim = "--" + boundary;
    size_t pos = body.find(delim);
    if (pos == std::string::npos) return false;
    out.clear();
    int n = 0;
    while (pos != std::string::npos) {
        pos += delim.size();
        if (body.compare(pos, 2, "--") == 0) break;  // closing delimiter
        if (body.compare(pos, 2, "\r\n") == 0) pos += 2;
        const size_t next = body.find("\r\n" + delim, pos);
        const std::string part = body.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        const size_t headEnd = part.find("\r\n\r\n");
        const std::string heads = headEnd == std::string::npos ? part : part.substr(0, headEnd);
        const std::string data = headEnd == std::string::npos ? std::string() : part.substr(headEnd + 4);
        out += "--- part " + std::to_string(++n) + " ---\n";
        std::string partType;
        size_t hp = 0;
        while (hp < heads.size()) {
            size_t e = heads.find("\r\n", hp);
            if (e == std::string::npos) e = heads.size();
            const std::string line = heads.substr(hp, e - hp);
            if (tex::asciiLower(line).rfind("content-type:", 0) == 0) partType = line.substr(13);
            out += line + '\n';
            hp = e + 2;
        }
        out += '\n';
        if (data.empty()) out += "(empty)\n";
        else if (!looksBinary(data) && printableUtf8(data.substr(0, 8192)))
            out += data.substr(0, 8192) + (data.size() > 8192 ? "\n...\n" : "\n");
        else {
            std::string info;
            if (imageInfo(data, info)) out += info + '\n';
            out += "(" + std::to_string(data.size()) + " bytes of binary data)\n";
        }
        out += '\n';
        pos = next == std::string::npos ? std::string::npos : next + 2;
        if (out.size() > kMaxOutput) break;
    }
    return n > 0;
}

bool protobuf(const std::string& body, std::string& out) {
    std::vector<PbField> fields;
    if (body.empty() || !parsePb(body, fields) || fields.empty()) return false;
    out.clear();
    dumpPb(fields, 0, out);
    return true;
}

bool grpc(const std::string& body, std::string& out) {
    if (body.size() < 5) return false;
    out.clear();
    size_t pos = 0;
    int n = 0;
    while (pos + 5 <= body.size()) {
        const u8 flag = static_cast<u8>(body[pos]);
        const uint32_t len = be32(reinterpret_cast<const u8*>(body.data()) + pos + 1);
        if (flag > 1 || len > body.size() - pos - 5) return n > 0 && (out += "(trailing bytes are not a gRPC message)\n", true);
        std::string msg = body.substr(pos + 5, len);
        out += "--- message " + std::to_string(++n) + " (" + std::to_string(len) + " bytes" + (flag ? ", compressed" : "") + ") ---\n";
        if (flag) {
            std::string plain = inflateAny(msg);
            if (plain.empty()) {
                out += "(compressed with an encoding ApkSpy does not decode)\n" + hexDump(msg, 1024);
                pos += 5 + len;
                continue;
            }
            msg.swap(plain);
        }
        std::string decoded;
        if (msg.empty()) out += "(empty message)\n";
        else if (protobuf(msg, decoded)) out += decoded;
        else out += hexDump(msg, 4096);
        pos += 5 + len;
        if (out.size() > kMaxOutput) break;
    }
    if (pos < body.size() && out.size() <= kMaxOutput) out += "(" + std::to_string(body.size() - pos) + " trailing bytes)\n";
    return n > 0;
}

bool msgpack(const std::string& body, std::string& out) {
    if (body.empty()) return false;
    MpReader r{reinterpret_cast<const u8*>(body.data()), reinterpret_cast<const u8*>(body.data()) + body.size()};
    out.clear();
    if (!mpValue(r, 0, out)) return false;
    // Several concatenated values (a stream) are fine; garbage after is not.
    while (r.p < r.end) {
        out += "\n";
        if (!mpValue(r, 0, out)) return false;
        if (out.size() > kMaxOutput) break;
    }
    return true;
}

bool imageInfo(const std::string& body, std::string& out) {
    const auto* d = reinterpret_cast<const u8*>(body.data());
    const size_t n = body.size();
    char buf[160];
    if (n >= 24 && std::memcmp(d, "\x89PNG\r\n\x1a\n", 8) == 0) {
        static const char* kColor[] = {"grayscale", "?", "RGB", "palette", "grayscale + alpha", "?", "RGBA"};
        const int ct = d[25 < n ? 25 : 0];
        std::snprintf(buf, sizeof buf, "PNG image, %u x %u, %d-bit %s", be32(d + 16), be32(d + 20), n > 24 ? d[24] : 0,
                      ct >= 0 && ct <= 6 ? kColor[ct] : "?");
        out = buf;
        return true;
    }
    if (n >= 4 && d[0] == 0xff && d[1] == 0xd8) {
        size_t p = 2;
        while (p + 9 < n) {
            if (d[p] != 0xff) { ++p; continue; }
            const u8 m = d[p + 1];
            const size_t len = static_cast<size_t>(d[p + 2] << 8 | d[p + 3]);
            if ((m >= 0xc0 && m <= 0xcf) && m != 0xc4 && m != 0xc8 && m != 0xcc) {
                std::snprintf(buf, sizeof buf, "JPEG image, %u x %u, %d components%s", static_cast<unsigned>(d[p + 7] << 8 | d[p + 8]),
                              static_cast<unsigned>(d[p + 5] << 8 | d[p + 6]), d[p + 9], m == 0xc2 ? ", progressive" : "");
                out = buf;
                return true;
            }
            p += 2 + len;
        }
        out = "JPEG image (dimensions not found)";
        return true;
    }
    if (n >= 10 && (std::memcmp(d, "GIF87a", 6) == 0 || std::memcmp(d, "GIF89a", 6) == 0)) {
        std::snprintf(buf, sizeof buf, "GIF image, %u x %u", le16(d + 6), le16(d + 8));
        out = buf;
        return true;
    }
    if (n >= 30 && std::memcmp(d, "RIFF", 4) == 0 && std::memcmp(d + 8, "WEBP", 4) == 0) {
        unsigned w = 0, h = 0;
        const char* kind = "";
        if (std::memcmp(d + 12, "VP8X", 4) == 0) w = le24(d + 24) + 1, h = le24(d + 27) + 1, kind = " (extended)";
        else if (std::memcmp(d + 12, "VP8L", 4) == 0) {
            const uint32_t b = le32(d + 21);
            w = (b & 0x3fff) + 1, h = ((b >> 14) & 0x3fff) + 1, kind = " (lossless)";
        } else if (std::memcmp(d + 12, "VP8 ", 4) == 0)
            w = le16(d + 26) & 0x3fff, h = le16(d + 28) & 0x3fff, kind = " (lossy)";
        std::snprintf(buf, sizeof buf, "WebP image%s, %u x %u", kind, w, h);
        out = buf;
        return true;
    }
    if (n >= 26 && d[0] == 'B' && d[1] == 'M') {
        std::snprintf(buf, sizeof buf, "BMP image, %u x %u", le32(d + 18), le32(d + 22));
        out = buf;
        return true;
    }
    if (n >= 6 && d[0] == 0 && d[1] == 0 && d[2] == 1 && d[3] == 0) {
        std::snprintf(buf, sizeof buf, "ICO image, %u icon(s)", le16(d + 4));
        out = buf;
        return true;
    }
    const std::string head = tex::asciiLower(body.substr(0, 512));
    if (head.find("<svg") != std::string::npos) {
        out = "SVG image (XML)";
        return true;
    }
    return false;
}

View detect(const std::string& body, const std::string& contentType) {
    const std::string ct = tex::asciiLower(contentType);
    if (body.empty()) return View::Text;
    if (ct.find("grpc") != std::string::npos) return View::Grpc;
    if (ct.find("protobuf") != std::string::npos || ct.find("x-proto") != std::string::npos) return View::Protobuf;
    if (ct.find("msgpack") != std::string::npos || ct.find("messagepack") != std::string::npos) return View::MsgPack;
    if (ct.find("cbor") != std::string::npos) return View::Cbor;
    if (ct.find("dns-message") != std::string::npos) return View::Dns;
    if (ct.find("graphql") != std::string::npos) return View::GraphQL;
    if (ct.find("jwt") != std::string::npos) return View::Jwt;
    {
        std::string tmp2;
        if (ct.find("json") != std::string::npos && body.find("\"query\"") != std::string::npos && graphql(body, tmp2))
            return View::GraphQL;
        const size_t first = body.find_first_not_of(" \t\r\n");
        if (first != std::string::npos && body.compare(first, 3, "eyJ") == 0 && body.size() < 16384 && jwt(body, tmp2))
            return View::Jwt;
    }
    if (ct.find("json") != std::string::npos) return View::Json;
    if (ct.find("x-www-form-urlencoded") != std::string::npos) return View::Form;
    if (ct.find("multipart/") != std::string::npos) return View::Multipart;
    if (ct.find("svg") != std::string::npos) return View::Xml;
    if (ct.rfind("image/", 0) == 0) return View::Image;
    if (ct.find("xml") != std::string::npos || ct.find("html") != std::string::npos) return View::Xml;
    // Sniffing.
    std::string tmp;
    if (prettyJson(body, tmp)) return View::Json;
    if (imageInfo(body, tmp)) return View::Image;
    const size_t first = body.find_first_not_of(" \t\r\n");
    if (first != std::string::npos && body[first] == '<' && !looksBinary(body)) return View::Xml;
    if (looksBinary(body)) {
        std::vector<PbField> f;
        if (parsePb(body, f) && !f.empty()) return View::Protobuf;
        return View::Hex;
    }
    return View::Text;
}

Rendered render(View view, const std::string& body, const std::string& contentType, const protoschema::Schema* schema,
                const std::string& message) {
    Rendered r;
    r.view = view == View::Auto ? detect(body, contentType) : view;
    if (body.empty()) {
        r.view = View::Text;
        return r;
    }
    std::string out;
    bool ok = true;
    switch (r.view) {
        case View::Auto:
        case View::Text:
            if (looksBinary(body)) {
                r.note = "binary data - shown as hex";
                r.view = View::Hex;
                out = hexDump(body);
            } else
                out = json::sanitizeUtf8(body);
            break;
        case View::Json: ok = prettyJson(body, out); break;
        case View::Xml: out = prettyXml(body); break;
        case View::Form: ok = formFields(body, out); break;
        case View::Multipart: ok = multipart(body, contentType, out); break;
        case View::Protobuf:
            if (schema && !message.empty() && schema->decode(body, message, out)) break;
            ok = protobuf(body, out);
            if (ok) r.note = "schema-less protobuf: field numbers, no names (load .proto files for names)";
            break;
        case View::Grpc:
            if (schema && !message.empty()) {
                // Each framed message with the schema.
                out.clear();
                size_t pos = 0;
                int n = 0;
                bool all = body.size() >= 5;
                while (all && pos + 5 <= body.size()) {
                    const uint32_t len = be32(reinterpret_cast<const u8*>(body.data()) + pos + 1);
                    if (body[pos] != 0 || len > body.size() - pos - 5) {
                        all = false;
                        break;
                    }
                    std::string decoded;
                    if (!schema->decode(body.substr(pos + 5, len), message, decoded)) {
                        all = false;
                        break;
                    }
                    out += "--- message " + std::to_string(++n) + " ---\n" + decoded;
                    pos += 5 + len;
                }
                if (all && n > 0) break;
            }
            ok = grpc(body, out);
            break;
        case View::Jwt: ok = jwt(body, out); break;
        case View::GraphQL: ok = graphql(body, out); break;
        case View::Cbor: ok = cbor(body, out); break;
        case View::Dns: ok = dns(body, out); break;
        case View::MsgPack: ok = msgpack(body, out); break;
        case View::Image: ok = imageInfo(body, out); if (ok) out += "\n\n" + hexDump(body, 512); break;
        case View::Hex: out = hexDump(body); break;
    }
    if (!ok) {
        r.note = std::string("not readable as ") + viewName(r.view) + " - shown as hex";
        r.view = View::Hex;
        out = hexDump(body);
    }
    r.text = capOutput(std::move(out), r.note);
    if (r.view != View::Hex && r.view != View::Text) r.text = json::sanitizeUtf8(r.text);
    return r;
}

// ---- JWT ---------------------------------------------------------------------

std::vector<std::string> findJwts(const std::string& text) {
    std::vector<std::string> out;
    size_t pos = 0;
    const auto b64 = [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_'; };
    while ((pos = text.find("eyJ", pos)) != std::string::npos) {
        size_t end = pos;
        int dots = 0;
        while (end < text.size() && (b64(text[end]) || (text[end] == '.' && dots < 2 && (++dots, true)))) ++end;
        const std::string tok = text.substr(pos, end - pos);
        if (dots == 2 && tok.back() != '.' && tok.size() > 20) out.push_back(tok);
        pos = end;
    }
    return out;
}

bool jwt(const std::string& text, std::string& out) {
    const std::vector<std::string> tokens = findJwts(text);
    out.clear();
    for (const auto& tok : tokens) {
        const size_t d1 = tok.find('.'), d2 = tok.find('.', d1 + 1);
        std::string head, claims;
        if (!codec::base64Decode(tok.substr(0, d1), head) || !codec::base64Decode(tok.substr(d1 + 1, d2 - d1 - 1), claims)) continue;
        Json h, c;
        if (!Json::parse(head, h) || !Json::parse(claims, c)) continue;
        out += "--- token " + tok.substr(0, 16) + "... ---\nheader: " + h.dump(true) + "\nclaims: " + c.dump(true) + "\n";
        for (const char* k : {"exp", "iat", "nbf"}) {
            const Json& v = c.get(k);
            if (!v.isNumber()) continue;
            const std::time_t t = static_cast<std::time_t>(v.asNumber());
            std::tm tm{};
#ifdef _WIN32
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            char buf[64];
            std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S UTC", &tm);
            out += std::string(k) + " = " + buf;
            if (std::string(k) == "exp") out += std::time(nullptr) > t ? "  (expired)" : "  (still valid)";
            out += "\n";
        }
        out += "signature: " + std::to_string(tok.size() - d2 - 1) + " base64url characters (not verified)\n\n";
    }
    return !out.empty();
}

// ---- GraphQL -----------------------------------------------------------------

namespace {

std::string indentGraphql(const std::string& q) {
    std::string out;
    int depth = 0;
    int parens = 0;  // inside (arguments): spaces stay spaces
    bool lineStart = true;
    bool inString = false;
    const auto fieldChar = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '$'; };
    for (size_t i = 0; i < q.size(); ++i) {
        const char ch = q[i];
        if (!inString && ch == '(') ++parens;
        if (!inString && ch == ')' && parens > 0) --parens;
        if (inString) {
            out += ch;
            if (ch == '"' && q[i - 1] != '\\') inString = false;
            continue;
        }
        if (ch == '"') {
            if (lineStart) out += indent(depth), lineStart = false;
            out += ch;
            inString = true;
            continue;
        }
        if (ch == '{') {
            if (lineStart) out += indent(depth);
            while (!out.empty() && out.back() == ' ') out.pop_back();
            out += " {\n";
            ++depth;
            lineStart = true;
        } else if (ch == '}') {
            if (!lineStart) out += '\n';
            depth = std::max(0, depth - 1);
            out += indent(depth) + "}\n";
            lineStart = true;
        } else if (ch == '\n' || ch == '\r' || ch == ',') {
            if (!lineStart) out += '\n', lineStart = true;
        } else if (std::isspace(static_cast<unsigned char>(ch))) {
            if (!lineStart && !out.empty() && out.back() != ' ') {
                // Between two fields of a selection set: one field per line.
                size_t next = i + 1;
                while (next < q.size() && std::isspace(static_cast<unsigned char>(q[next]))) ++next;
                const char prev = out.back();
                if (depth > 0 && parens == 0 && next < q.size() && fieldChar(q[next]) && (fieldChar(prev) || prev == ')')) {
                    out += '\n';
                    lineStart = true;
                } else
                    out += ' ';
            }
        } else {
            if (lineStart) out += indent(depth), lineStart = false;
            out += ch;
        }
    }
    return out;
}

bool graphqlOne(const Json& j, std::string& out) {
    const std::string q = j.get("query").asString("");
    if (q.empty() && !j.get("extensions").get("persistedQuery").isObject()) return false;
    if (j.has("operationName") && !j.get("operationName").isNull()) out += "operation: " + j.get("operationName").asString("") + "\n";
    if (!q.empty()) out += indentGraphql(q);
    else out += "(persisted query " + j.get("extensions").get("persistedQuery").get("sha256Hash").asString("") + ")\n";
    if (j.has("variables") && !j.get("variables").isNull()) out += "\nvariables: " + j.get("variables").dump(true) + "\n";
    return true;
}

}  // namespace

bool graphql(const std::string& body, std::string& out) {
    out.clear();
    Json j;
    if (!Json::parse(body, j)) {
        // application/graphql: the query itself.
        const size_t first = body.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || !(body[first] == '{' || body.compare(first, 5, "query") == 0 ||
                                            body.compare(first, 8, "mutation") == 0 || body.compare(first, 12, "subscription") == 0))
            return false;
        out = indentGraphql(body);
        return true;
    }
    if (j.isArray()) {  // a batch
        int n = 0;
        for (const Json& item : j.items()) {
            std::string one;
            if (!graphqlOne(item, one)) return false;
            out += "--- operation " + std::to_string(++n) + " ---\n" + one + "\n";
        }
        return n > 0;
    }
    return j.isObject() && graphqlOne(j, out);
}

// ---- CBOR ----------------------------------------------------------------------

namespace {

struct CborReader {
    const u8* p;
    const u8* end;
};

bool cborValue(CborReader& r, int depth, std::string& out);

bool cborLength(CborReader& r, u8 info, uint64_t& v) {
    if (info < 24) return v = info, true;
    const int n = info == 24 ? 1 : info == 25 ? 2 : info == 26 ? 4 : info == 27 ? 8 : 0;
    if (!n || r.end - r.p < n) return false;
    v = 0;
    for (int i = 0; i < n; ++i) v = v << 8 | *r.p++;
    return true;
}

bool cborValue(CborReader& r, int depth, std::string& out) {
    if (r.p >= r.end || depth > 64 || out.size() > kMaxOutput) return false;
    const u8 ib = *r.p++;
    const int major = ib >> 5;
    const u8 info = ib & 31;
    uint64_t len = 0;
    const bool indefinite = info == 31;
    if (!indefinite && major != 7 && !cborLength(r, info, len)) return false;
    char buf[64];
    switch (major) {
        case 0: out += std::to_string(len); return true;
        case 1: out += "-" + std::to_string(len + 1); return true;
        case 2:
        case 3: {
            std::string s;
            if (indefinite) {  // chunks until the break byte
                while (r.p < r.end && *r.p != 0xff) {
                    const u8 cb = *r.p++;
                    uint64_t cl;
                    if ((cb >> 5) != major || !cborLength(r, cb & 31, cl) || static_cast<uint64_t>(r.end - r.p) < cl) return false;
                    s.append(reinterpret_cast<const char*>(r.p), static_cast<size_t>(cl));
                    r.p += cl;
                }
                if (r.p >= r.end) return false;
                ++r.p;
            } else {
                if (static_cast<uint64_t>(r.end - r.p) < len) return false;
                s.assign(reinterpret_cast<const char*>(r.p), static_cast<size_t>(len));
                r.p += len;
            }
            out += major == 3 && printableUtf8(s) ? quoted(s) : "h'" + shortHex(s, 256) + "'";
            return true;
        }
        case 4:
        case 5: {
            const bool map = major == 5;
            out += map ? "{" : "[";
            bool any = false;
            for (uint64_t i = 0; indefinite || i < len; ++i) {
                if (indefinite && r.p < r.end && *r.p == 0xff) {
                    ++r.p;
                    break;
                }
                out += (any ? ",\n" : "\n") + indent(depth + 1);
                any = true;
                if (!cborValue(r, depth + 1, out)) return false;
                if (map) {
                    out += ": ";
                    if (!cborValue(r, depth + 1, out)) return false;
                }
            }
            out += any ? "\n" + indent(depth) + (map ? "}" : "]") : (map ? "}" : "]");
            return true;
        }
        case 6:
            out += std::to_string(len) + "(";
            if (!cborValue(r, depth, out)) return false;
            out += ")";
            return true;
        default: {  // 7: simple values and floats
            if (info == 20) return out += "false", true;
            if (info == 21) return out += "true", true;
            if (info == 22) return out += "null", true;
            if (info == 23) return out += "undefined", true;
            if (info == 25 && r.end - r.p >= 2) {  // half float
                const uint16_t hbits = static_cast<uint16_t>(r.p[0] << 8 | r.p[1]);
                r.p += 2;
                const int e = (hbits >> 10) & 0x1f, m = hbits & 0x3ff;
                double v = e == 0 ? std::ldexp(m, -24) : e == 31 ? (m ? NAN : INFINITY) : std::ldexp(m + 1024, e - 25);
                if (hbits & 0x8000) v = -v;
                std::snprintf(buf, sizeof buf, "%g", v);
                return out += buf, true;
            }
            if (info == 26 && r.end - r.p >= 4) {
                uint32_t v = 0;
                for (int i = 0; i < 4; ++i) v = v << 8 | *r.p++;
                float f;
                std::memcpy(&f, &v, 4);
                std::snprintf(buf, sizeof buf, "%.7g", static_cast<double>(f));
                return out += buf, true;
            }
            if (info == 27 && r.end - r.p >= 8) {
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) v = v << 8 | *r.p++;
                double d;
                std::memcpy(&d, &v, 8);
                std::snprintf(buf, sizeof buf, "%.15g", d);
                return out += buf, true;
            }
            if (info < 20) return out += "simple(" + std::to_string(info) + ")", true;
            if (info == 24 && r.p < r.end) return out += "simple(" + std::to_string(*r.p++) + ")", true;
            return false;
        }
    }
}

}  // namespace

bool cbor(const std::string& body, std::string& out) {
    if (body.empty()) return false;
    CborReader r{reinterpret_cast<const u8*>(body.data()), reinterpret_cast<const u8*>(body.data()) + body.size()};
    out.clear();
    if (!cborValue(r, 0, out)) return false;
    while (r.p < r.end) {  // a sequence of items
        out += "\n";
        if (!cborValue(r, 0, out)) return false;
    }
    return true;
}

// ---- DNS ---------------------------------------------------------------------------

namespace {

struct DnsRecord {
    std::string name;
    int type = 0, cls = 0;
    uint32_t ttl = 0;
    std::string data;  // rendered
};

struct DnsMessage {
    int id = 0, flags = 0;
    std::vector<DnsRecord> questions, answers, authority, additional;
};

const char* dnsTypeName(int t) {
    switch (t) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 255: return "ANY";
        default: return nullptr;
    }
}

std::string typeText(int t) {
    const char* n = dnsTypeName(t);
    return n ? n : "TYPE" + std::to_string(t);
}

// A (possibly compressed) name at `pos`; advances `pos` past it in place.
bool dnsReadName(const std::string& m, size_t& pos, std::string& name, int depth = 0) {
    if (depth > 16) return false;
    name.clear();
    size_t p = pos;
    bool jumped = false;
    for (int guard = 0; guard < 128; ++guard) {
        if (p >= m.size()) return false;
        const u8 len = static_cast<u8>(m[p]);
        if (len == 0) {
            if (!jumped) pos = p + 1;
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (p + 1 >= m.size()) return false;
            const size_t target = static_cast<size_t>((len & 0x3f) << 8 | static_cast<u8>(m[p + 1]));
            if (!jumped) pos = p + 2;
            jumped = true;
            if (target >= p) return false;  // pointers only go backwards
            p = target;
            continue;
        }
        if (p + 1 + len > m.size()) return false;
        if (!name.empty()) name += '.';
        name.append(m, p + 1, len);
        p += 1 + len;
    }
    return false;
}

bool dnsParse(std::string m, DnsMessage& out) {
    // DNS over TCP carries a 2-byte length first.
    if (m.size() > 14 && static_cast<size_t>(static_cast<u8>(m[0]) << 8 | static_cast<u8>(m[1])) == m.size() - 2) m.erase(0, 2);
    if (m.size() < 12) return false;
    const auto u16 = [&](size_t at) { return static_cast<int>(static_cast<u8>(m[at]) << 8 | static_cast<u8>(m[at + 1])); };
    out.id = u16(0);
    out.flags = u16(2);
    const int counts[4] = {u16(4), u16(6), u16(8), u16(10)};
    if (counts[0] > 64 || counts[1] > 256 || counts[2] > 256 || counts[3] > 256) return false;
    size_t pos = 12;
    for (int i = 0; i < counts[0]; ++i) {
        DnsRecord q;
        if (!dnsReadName(m, pos, q.name) || pos + 4 > m.size()) return false;
        q.type = u16(pos);
        q.cls = u16(pos + 2);
        pos += 4;
        out.questions.push_back(q);
    }
    std::vector<DnsRecord>* sections[3] = {&out.answers, &out.authority, &out.additional};
    for (int s = 0; s < 3; ++s)
        for (int i = 0; i < counts[s + 1]; ++i) {
            DnsRecord r;
            if (!dnsReadName(m, pos, r.name) || pos + 10 > m.size()) return false;
            r.type = u16(pos);
            r.cls = u16(pos + 2);
            r.ttl = static_cast<uint32_t>(u16(pos + 4)) << 16 | static_cast<uint32_t>(u16(pos + 6));
            const size_t rdlen = static_cast<size_t>(u16(pos + 8));
            pos += 10;
            if (pos + rdlen > m.size()) return false;
            const std::string rd = m.substr(pos, rdlen);
            char buf[64];
            if (r.type == 1 && rdlen == 4) {
                std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", static_cast<u8>(rd[0]), static_cast<u8>(rd[1]), static_cast<u8>(rd[2]),
                              static_cast<u8>(rd[3]));
                r.data = buf;
            } else if (r.type == 28 && rdlen == 16) {
                unsigned g[8];
                for (int k = 0; k < 8; ++k) g[k] = static_cast<unsigned>(static_cast<u8>(rd[2 * k]) << 8 | static_cast<u8>(rd[2 * k + 1]));
                int bestAt = -1, bestLen = 1;  // "::" replaces the longest run of 2+ zero groups
                for (int k = 0; k < 8;) {
                    int n = 0;
                    while (k + n < 8 && g[k + n] == 0) ++n;
                    if (n > bestLen) bestAt = k, bestLen = n;
                    k += n ? n : 1;
                }
                for (int k = 0; k < 8; ++k) {
                    if (k == bestAt) {
                        r.data += "::";
                        k += bestLen - 1;
                        continue;
                    }
                    std::snprintf(buf, sizeof buf, "%s%x", (k && !(bestAt >= 0 && k == bestAt + bestLen)) ? ":" : "", g[k]);
                    r.data += buf;
                }
            } else if (r.type == 5 || r.type == 2 || r.type == 12) {
                size_t p2 = pos;
                dnsReadName(m, p2, r.data);
            } else if (r.type == 15 && rdlen > 2) {
                size_t p2 = pos + 2;
                std::string exch;
                dnsReadName(m, p2, exch);
                r.data = std::to_string(u16(pos)) + " " + exch;
            } else if (r.type == 16) {
                size_t k = 0;
                while (k < rd.size()) {
                    const size_t l = static_cast<u8>(rd[k]);
                    r.data += (r.data.empty() ? "" : " ") + quoted(rd.substr(k + 1, l), 256);
                    k += 1 + l;
                }
            } else if (r.type == 41) {
                r.data = "EDNS, UDP size " + std::to_string(r.cls);
            } else {
                r.data = "<" + shortHex(rd, 32) + ">";
            }
            pos += rdlen;
            sections[s]->push_back(r);
        }
    return true;
}

}  // namespace

bool dns(const std::string& msg, std::string& out) {
    DnsMessage d;
    if (!dnsParse(msg, d)) return false;
    static const char* kRcode[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    const bool response = (d.flags & 0x8000) != 0;
    const int rcode = d.flags & 15;
    char buf[160];
    std::snprintf(buf, sizeof buf, "%s id %d%s%s%s, %s\n", response ? "response" : "query", d.id, (d.flags & 0x0400) ? " authoritative" : "",
                  (d.flags & 0x0100) ? " recursion-desired" : "", (d.flags & 0x0200) ? " truncated" : "",
                  rcode < 6 ? kRcode[rcode] : ("rcode " + std::to_string(rcode)).c_str());
    out = buf;
    for (const auto& q : d.questions) out += "question: " + q.name + " " + typeText(q.type) + "\n";
    const auto section = [&](const char* title, const std::vector<DnsRecord>& rs) {
        for (const auto& r : rs) {
            if (r.type == 41) {
                out += std::string(title) + ": " + r.data + "\n";
                continue;
            }
            out += std::string(title) + ": " + r.name + " " + typeText(r.type) + " " + r.data + "  (ttl " + std::to_string(r.ttl) + ")\n";
        }
    };
    section("answer", d.answers);
    section("authority", d.authority);
    section("additional", d.additional);
    return true;
}

std::string dnsSummary(const std::string& msg) {
    DnsMessage d;
    if (!dnsParse(msg, d)) return {};
    if (!(d.flags & 0x8000)) {
        std::string out;
        for (const auto& q : d.questions) out += (out.empty() ? "" : ", ") + typeText(q.type) + "? " + q.name;
        return out;
    }
    std::string out;
    for (const auto& r : d.answers) {
        if (r.type == 41) continue;
        out += (out.empty() ? "" : ", ") + (r.type == 5 ? r.name + " -> " + r.data : typeText(r.type) + " " + r.data);
        if (out.size() > 200) break;
    }
    if (out.empty()) {
        static const char* kRcode[] = {"no answer", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
        const int rcode = d.flags & 15;
        out = (d.questions.empty() ? std::string() : d.questions[0].name + ": ") + (rcode < 6 ? kRcode[rcode] : "error");
    }
    return out;
}

std::string dnsName(const std::string& msg) {
    DnsMessage d;
    return dnsParse(msg, d) && !d.questions.empty() ? d.questions[0].name : std::string();
}

// ---- cookies ---------------------------------------------------------------------

std::vector<Cookie> parseCookieHeader(const std::string& value) {
    std::vector<Cookie> out;
    size_t pos = 0;
    while (pos < value.size()) {
        size_t semi = value.find(';', pos);
        if (semi == std::string::npos) semi = value.size();
        std::string part = value.substr(pos, semi - pos);
        const size_t a = part.find_first_not_of(' ');
        if (a != std::string::npos) {
            part = part.substr(a);
            const size_t eq = part.find('=');
            out.push_back({part.substr(0, eq), eq == std::string::npos ? std::string() : part.substr(eq + 1), {}});
        }
        pos = semi + 1;
    }
    return out;
}

Cookie parseSetCookie(const std::string& value) {
    Cookie c;
    const size_t semi = value.find(';');
    const std::string first = value.substr(0, semi);
    const size_t eq = first.find('=');
    c.name = first.substr(0, eq);
    c.value = eq == std::string::npos ? std::string() : first.substr(eq + 1);
    if (semi != std::string::npos) {
        c.attributes = value.substr(semi + 1);
        const size_t a = c.attributes.find_first_not_of(' ');
        c.attributes = a == std::string::npos ? std::string() : c.attributes.substr(a);
    }
    return c;
}

}  // namespace contentview
