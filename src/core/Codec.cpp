#include "core/Codec.hpp"
#include <miniz.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "core/Sha256.hpp"

namespace codec {

namespace {

constexpr const char* kHexDigits = "0123456789abcdef";

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

// --- UTF-8 ------------------------------------------------------------------

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// Next code point of `s` at `i` (advanced); false on malformed UTF-8.
bool nextUtf8(std::string_view s, size_t& i, uint32_t& cp) {
    const auto b = [&](size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char c = b(i);
    int n = 0;
    if (c < 0x80) cp = c, n = 0;
    else if ((c & 0xE0) == 0xC0) cp = c & 0x1F, n = 1;
    else if ((c & 0xF0) == 0xE0) cp = c & 0x0F, n = 2;
    else if ((c & 0xF8) == 0xF0) cp = c & 0x07, n = 3;
    else return false;
    for (int k = 1; k <= n; ++k) {
        if (i + static_cast<size_t>(k) >= s.size() || (b(i + static_cast<size_t>(k)) & 0xC0) != 0x80) return false;
        cp = (cp << 6) | (b(i + static_cast<size_t>(k)) & 0x3F);
    }
    if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10FFFF))) return false;
    i += static_cast<size_t>(n) + 1;
    return true;
}

bool toCodePoints(std::string_view utf8, std::vector<uint32_t>& cps, std::string& error) {
    for (size_t i = 0; i < utf8.size();) {
        uint32_t cp = 0;
        const size_t at = i;
        if (!nextUtf8(utf8, i, cp)) {
            error = "the input is not valid UTF-8 (byte " + std::to_string(at) + ")";
            return false;
        }
        cps.push_back(cp);
    }
    return true;
}

// Windows-1252: 0x80-0x9F differ from Latin-1 (0 = undefined).
constexpr uint16_t kCp1252[32] = {0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
                                  0x2039, 0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
                                  0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178};

// --- hashes ------------------------------------------------------------------

uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

std::string hexOfBytes(const uint8_t* d, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) s += kHexDigits[d[i] >> 4], s += kHexDigits[d[i] & 15];
    return s;
}

// Message padded for MD5 (little-endian length) or SHA-1 (big-endian length).
std::string padded(std::string_view in, bool bigEndian) {
    std::string m(in);
    const uint64_t bits = static_cast<uint64_t>(in.size()) * 8;
    m += static_cast<char>(0x80);
    while (m.size() % 64 != 56) m += '\0';
    for (int i = 0; i < 8; ++i) m += static_cast<char>((bits >> (bigEndian ? 56 - 8 * i : 8 * i)) & 0xFF);
    return m;
}

// --- compression --------------------------------------------------------------

bool inflateAny(std::string_view in, std::string& out, std::string& error) {
    const auto* d = reinterpret_cast<const uint8_t*>(in.data());
    size_t start = 0;
    int flags = 0;
    if (in.size() > 18 && d[0] == 0x1f && d[1] == 0x8b) {  // gzip
        const uint8_t flg = d[3];
        start = 10;
        if (flg & 4) start += 2 + static_cast<size_t>(d[start] | d[start + 1] << 8);
        if (flg & 8) while (start < in.size() && d[start++]) {}
        if (flg & 16) while (start < in.size() && d[start++]) {}
        if (flg & 2) start += 2;
    } else if (in.size() > 2 && (d[0] & 0x0F) == 8 && ((d[0] << 8 | d[1]) % 31) == 0) {  // zlib
        flags = TINFL_FLAG_PARSE_ZLIB_HEADER;
    }
    if (start >= in.size()) {
        error = "nothing to inflate";
        return false;
    }
    size_t outLen = 0;
    void* p = tinfl_decompress_mem_to_heap(d + start, in.size() - start, &outLen, flags);
    if (!p) {
        error = "not zlib, gzip or deflate data";
        return false;
    }
    out.assign(static_cast<const char*>(p), outLen);
    mz_free(p);
    return true;
}

std::string deflateRaw(std::string_view in, bool zlibHeader) {
    size_t outLen = 0;
    const int flags = 128 | (zlibHeader ? TDEFL_WRITE_ZLIB_HEADER : 0);
    void* p = tdefl_compress_mem_to_heap(in.data(), in.size(), &outLen, flags);
    std::string out;
    if (p) {
        out.assign(static_cast<const char*>(p), outLen);
        mz_free(p);
    }
    return out;
}

// --- escapes --------------------------------------------------------------------

std::string escape(std::string_view in) {
    std::string out;
    for (size_t i = 0; i < in.size();) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        switch (c) {
        case '\n': out += "\\n"; ++i; continue;
        case '\r': out += "\\r"; ++i; continue;
        case '\t': out += "\\t"; ++i; continue;
        case '"': out += "\\\""; ++i; continue;
        case '\\': out += "\\\\"; ++i; continue;
        default: break;
        }
        if (c >= 0x20 && c < 0x7F) {
            out += static_cast<char>(c);
            ++i;
            continue;
        }
        uint32_t cp = 0;
        size_t j = i;
        if (c >= 0x80 && nextUtf8(in, j, cp)) {  // non-ASCII text: \uXXXX (surrogate pairs above the BMP)
            char b[16];
            if (cp >= 0x10000) {
                cp -= 0x10000;
                std::snprintf(b, sizeof b, "\\u%04x\\u%04x", 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
            } else {
                std::snprintf(b, sizeof b, "\\u%04x", cp);
            }
            out += b;
            i = j;
            continue;
        }
        char b[8];
        std::snprintf(b, sizeof b, "\\x%02x", c);
        out += b;
        ++i;
    }
    return out;
}

bool unescape(std::string_view in, std::string& out, std::string& error) {
    uint32_t pendingHigh = 0;  // a \uD8xx waiting for its low surrogate
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\' || i + 1 >= in.size()) {
            out += in[i];
            continue;
        }
        const char e = in[++i];
        const auto hexRun = [&](size_t n, uint32_t& v) {
            v = 0;
            for (size_t k = 1; k <= n; ++k) {
                const int h = i + k < in.size() ? hexValue(in[i + k]) : -1;
                if (h < 0) return false;
                v = v << 4 | static_cast<uint32_t>(h);
            }
            i += n;
            return true;
        };
        uint32_t v = 0;
        switch (e) {
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'v': out += '\v'; break;
        case '0': out += '\0'; break;
        case 'x':
            if (!hexRun(2, v)) return error = "\\x needs two hex digits", false;
            out += static_cast<char>(v);
            break;
        case 'u':
            if (!hexRun(4, v)) return error = "\\u needs four hex digits", false;
            if (v >= 0xD800 && v < 0xDC00) {
                pendingHigh = v;
                break;
            }
            if (v >= 0xDC00 && v < 0xE000 && pendingHigh) {
                v = 0x10000 + ((pendingHigh - 0xD800) << 10) + (v - 0xDC00);
                pendingHigh = 0;
            }
            appendUtf8(out, v);
            break;
        case 'U':
            if (!hexRun(8, v) || v > 0x10FFFF) return error = "\\U needs eight hex digits", false;
            appendUtf8(out, v);
            break;
        default: out += e; break;  // \" \' \\ \/ and unknown escapes: the character itself
        }
    }
    return true;
}

// --- HTML / URL ------------------------------------------------------------------

std::string htmlEncode(std::string_view in) {
    std::string out;
    for (char c : in) {
        switch (c) {
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '&': out += "&amp;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

std::string htmlDecode(std::string_view in) {
    static const std::pair<const char*, uint32_t> kNamed[] = {
        {"lt", '<'}, {"gt", '>'}, {"amp", '&'}, {"quot", '"'}, {"apos", '\''}, {"nbsp", 0xA0}, {"copy", 0xA9}, {"reg", 0xAE},
    };
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        const size_t semi = in[i] == '&' ? in.find(';', i) : std::string_view::npos;
        if (semi == std::string_view::npos || semi - i > 10) {
            out += in[i];
            continue;
        }
        const std::string_view name = in.substr(i + 1, semi - i - 1);
        uint32_t cp = 0;
        bool known = false;
        if (!name.empty() && name[0] == '#') {
            const bool hex = name.size() > 1 && (name[1] == 'x' || name[1] == 'X');
            known = name.size() > (hex ? 2u : 1u);
            for (size_t k = hex ? 2 : 1; k < name.size() && known; ++k) {
                const int h = hex ? hexValue(name[k]) : (name[k] >= '0' && name[k] <= '9' ? name[k] - '0' : -1);
                if (h < 0) known = false;
                else cp = cp * (hex ? 16 : 10) + static_cast<uint32_t>(h);
            }
            known = known && cp <= 0x10FFFF;
        } else {
            for (const auto& [n, c] : kNamed)
                if (name == n) known = true, cp = c;
        }
        if (!known) {
            out += in[i];
            continue;
        }
        appendUtf8(out, cp);
        i = semi;
    }
    return out;
}

std::string urlEncode(std::string_view in) {
    std::string out;
    for (unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += "0123456789ABCDEF"[c >> 4];
            out += "0123456789ABCDEF"[c & 15];
        }
    }
    return out;
}

std::string urlDecode(std::string_view in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size() && hexValue(in[i + 1]) >= 0 && hexValue(in[i + 2]) >= 0) {
            out += static_cast<char>(hexValue(in[i + 1]) << 4 | hexValue(in[i + 2]));
            i += 2;
        } else {
            out += in[i] == '+' ? ' ' : in[i];
        }
    }
    return out;
}

bool looksBase64(std::string_view s) {
    size_t n = 0, pad = 0;
    bool std = false, url = false;
    for (char c : s) {
        if (isSpace(c)) continue;
        if (c == '=') {
            ++pad;
            continue;
        }
        if (pad) return false;  // data after padding
        if (c == '+' || c == '/') std = true;
        else if (c == '-' || c == '_') url = true;
        else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
        ++n;
    }
    return n >= 4 && pad <= 2 && !(std && url) && (n + pad) % 4 != 1;
}

bool looksHex(std::string_view s) {
    std::string tmp;
    return s.size() >= 2 && hexDecode(s, tmp) && !tmp.empty();
}

bool looksUrlEncoded(std::string_view s) {
    for (size_t i = 0; i + 2 < s.size(); ++i)
        if (s[i] == '%' && hexValue(s[i + 1]) >= 0 && hexValue(s[i + 2]) >= 0) return true;
    return false;
}

bool looksJwt(std::string_view s) {
    if (s.substr(0, 3) != "eyJ") return false;
    const size_t a = s.find('.');
    const size_t b = a == std::string_view::npos ? a : s.find('.', a + 1);
    return b != std::string_view::npos && s.find('.', b + 1) == std::string_view::npos;
}

bool compressed(std::string_view s) {
    const auto* d = reinterpret_cast<const unsigned char*>(s.data());
    return s.size() > 2 && ((d[0] == 0x1f && d[1] == 0x8b) || ((d[0] & 0x0F) == 8 && ((d[0] << 8 | d[1]) % 31) == 0 && d[0] == 0x78));
}

}  // namespace

const std::vector<OpInfo>& ops() {
    static const std::vector<OpInfo> kOps = {
        {Op::Base64Decode, "Base64 decode", "Encoding", Arg::None, ""},
        {Op::Base64Encode, "Base64 encode", "Encoding", Arg::None, ""},
        {Op::Base64UrlEncode, "Base64url encode", "Encoding", Arg::None, ""},
        {Op::Base32Decode, "Base32 decode", "Encoding", Arg::None, ""},
        {Op::Base32Encode, "Base32 encode", "Encoding", Arg::None, ""},
        {Op::HexDecode, "Hex decode", "Encoding", Arg::None, ""},
        {Op::HexEncode, "Hex encode", "Encoding", Arg::None, ""},
        {Op::UrlDecode, "URL decode", "Encoding", Arg::None, ""},
        {Op::UrlEncode, "URL encode", "Encoding", Arg::None, ""},
        {Op::HtmlDecode, "HTML entities decode", "Encoding", Arg::None, ""},
        {Op::HtmlEncode, "HTML entities encode", "Encoding", Arg::None, ""},
        {Op::Unescape, "Unescape string (\\n, \\x41, \\u0041)", "Encoding", Arg::None, ""},
        {Op::Escape, "Escape string", "Encoding", Arg::None, ""},
        {Op::DecodeText, "Decode text from charset", "Text", Arg::Charset, "the bytes' charset"},
        {Op::EncodeText, "Encode text to charset", "Text", Arg::Charset, "the charset to write"},
        {Op::Xor, "XOR with key", "Crypto", Arg::Text, "key: text, or bytes as 0x41 0x42"},
        {Op::Rot13, "ROT13", "Crypto", Arg::None, ""},
        {Op::Reverse, "Reverse bytes", "Other", Arg::None, ""},
        {Op::Inflate, "Inflate (gzip / zlib / deflate)", "Compression", Arg::None, ""},
        {Op::ZlibCompress, "Zlib compress", "Compression", Arg::None, ""},
        {Op::GzipCompress, "Gzip compress", "Compression", Arg::None, ""},
        {Op::Md5, "MD5", "Hash", Arg::None, ""},
        {Op::Sha1, "SHA-1", "Hash", Arg::None, ""},
        {Op::Sha256, "SHA-256", "Hash", Arg::None, ""},
        {Op::JwtDecode, "JWT decode", "Other", Arg::None, ""},
    };
    return kOps;
}

const OpInfo& info(Op op) {
    for (const OpInfo& o : ops())
        if (o.op == op) return o;
    return ops().front();
}

const std::vector<const char*>& charsets() {
    static const std::vector<const char*> kCharsets = {"UTF-8",    "UTF-16LE",     "UTF-16BE",     "UTF-32LE", "UTF-32BE",
                                                       "Latin-1",  "Windows-1252", "ASCII",        "Modified UTF-8 (Java / DEX)"};
    return kCharsets;
}

std::string base64Encode(std::string_view in, bool url) {
    const char* a = url ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                        : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    const auto b = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(in[k])); };
    for (; i + 2 < in.size(); i += 3) {
        const uint32_t v = b(i) << 16 | b(i + 1) << 8 | b(i + 2);
        out += a[v >> 18], out += a[(v >> 12) & 63], out += a[(v >> 6) & 63], out += a[v & 63];
    }
    if (i + 1 == in.size()) {
        const uint32_t v = b(i) << 16;
        out += a[v >> 18], out += a[(v >> 12) & 63];
        if (!url) out += "==";
    } else if (i + 2 == in.size()) {
        const uint32_t v = b(i) << 16 | b(i + 1) << 8;
        out += a[v >> 18], out += a[(v >> 12) & 63], out += a[(v >> 6) & 63];
        if (!url) out += '=';
    }
    return out;
}

bool base64Decode(std::string_view in, std::string& out) {
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    bool padding = false;
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=') {
            padding = true;
            continue;
        } else if (isSpace(c)) continue;
        else return false;
        if (padding) return false;
        acc = acc << 6 | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return bits < 6;  // a lone 6-bit group is not valid
}

std::string base32Encode(std::string_view in) {
    const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : in) {
        acc = acc << 8 | c;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += a[(acc >> bits) & 31];
        }
    }
    if (bits) out += a[(acc << (5 - bits)) & 31];
    while (out.size() % 8) out += '=';
    return out;
}

bool base32Decode(std::string_view in, std::string& out) {
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else if (c == '=' || isSpace(c)) continue;
        else return false;
        acc = acc << 5 | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return true;
}

std::string hexEncode(std::string_view in) {
    std::string out;
    out.reserve(in.size() * 2);
    for (unsigned char c : in) out += kHexDigits[c >> 4], out += kHexDigits[c & 15];
    return out;
}

bool hexDecode(std::string_view in, std::string& out) {
    out.clear();
    int high = -1;
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (isSpace(c) || c == ':' || c == ',') {
            if (high >= 0) return false;
            continue;
        }
        if (high < 0 && c == '0' && i + 1 < in.size() && (in[i + 1] == 'x' || in[i + 1] == 'X')) {
            ++i;  // 0x41
            continue;
        }
        if (high < 0 && c == '\\' && i + 1 < in.size() && in[i + 1] == 'x') {
            ++i;  // \x41
            continue;
        }
        const int v = hexValue(c);
        if (v < 0) return false;
        if (high < 0) {
            high = v;
        } else {
            out += static_cast<char>(high << 4 | v);
            high = -1;
        }
    }
    return high < 0;
}

bool decodeText(std::string_view bytes, std::string_view charset, std::string& utf8, std::string& error) {
    utf8.clear();
    const std::string cs = lower(charset);
    const auto u8 = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(bytes[k])); };
    if (cs == "utf-8") {
        if (!isReadableText(bytes)) {
            std::vector<uint32_t> cps;
            if (!toCodePoints(bytes, cps, error)) return false;
        }
        utf8.assign(bytes);
        if (utf8.size() >= 3 && utf8.compare(0, 3, "\xEF\xBB\xBF") == 0) utf8.erase(0, 3);  // byte order mark
        return true;
    }
    if (cs == "utf-16le" || cs == "utf-16be") {
        const bool be = cs == "utf-16be";
        if (bytes.size() % 2) return error = "UTF-16 needs an even number of bytes", false;
        size_t i = 0;
        if (bytes.size() >= 2 && ((be && u8(0) == 0xFE && u8(1) == 0xFF) || (!be && u8(0) == 0xFF && u8(1) == 0xFE))) i = 2;
        for (; i + 1 < bytes.size(); i += 2) {
            uint32_t u = be ? (u8(i) << 8 | u8(i + 1)) : (u8(i + 1) << 8 | u8(i));
            if (u >= 0xD800 && u < 0xDC00 && i + 3 < bytes.size()) {
                const uint32_t lo = be ? (u8(i + 2) << 8 | u8(i + 3)) : (u8(i + 3) << 8 | u8(i + 2));
                if (lo >= 0xDC00 && lo < 0xE000) {
                    u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                    i += 2;
                }
            }
            appendUtf8(utf8, u);
        }
        return true;
    }
    if (cs == "utf-32le" || cs == "utf-32be") {
        const bool be = cs == "utf-32be";
        if (bytes.size() % 4) return error = "UTF-32 needs a multiple of 4 bytes", false;
        for (size_t i = 0; i + 3 < bytes.size(); i += 4) {
            const uint32_t u = be ? (u8(i) << 24 | u8(i + 1) << 16 | u8(i + 2) << 8 | u8(i + 3))
                                  : (u8(i + 3) << 24 | u8(i + 2) << 16 | u8(i + 1) << 8 | u8(i));
            if (u > 0x10FFFF) return error = "code point out of range at byte " + std::to_string(i), false;
            if (u == 0xFEFF && i == 0) continue;
            appendUtf8(utf8, u);
        }
        return true;
    }
    if (cs == "latin-1" || cs == "windows-1252" || cs == "ascii") {
        for (size_t i = 0; i < bytes.size(); ++i) {
            uint32_t c = u8(i);
            if (cs == "ascii" && c >= 0x80) return error = "byte " + std::to_string(i) + " is not ASCII", false;
            if (cs == "windows-1252" && c >= 0x80 && c < 0xA0) c = kCp1252[c - 0x80] ? kCp1252[c - 0x80] : c;
            appendUtf8(utf8, c);
        }
        return true;
    }
    if (cs.rfind("modified utf-8", 0) == 0) {
        // Java's DataInput / DEX strings: NUL as C0 80, supplementary characters as two 3-byte surrogates.
        uint32_t high = 0;
        for (size_t i = 0; i < bytes.size();) {
            const uint32_t c = u8(i);
            uint32_t u;
            if (c < 0x80) {
                u = c, i += 1;
            } else if ((c & 0xE0) == 0xC0 && i + 1 < bytes.size()) {
                u = (c & 0x1F) << 6 | (u8(i + 1) & 0x3F), i += 2;
            } else if ((c & 0xF0) == 0xE0 && i + 2 < bytes.size()) {
                u = (c & 0x0F) << 12 | (u8(i + 1) & 0x3F) << 6 | (u8(i + 2) & 0x3F), i += 3;
            } else {
                return error = "malformed modified UTF-8 at byte " + std::to_string(i), false;
            }
            if (u >= 0xD800 && u < 0xDC00) {
                high = u;
                continue;
            }
            if (u >= 0xDC00 && u < 0xE000 && high) u = 0x10000 + ((high - 0xD800) << 10) + (u - 0xDC00);
            high = 0;
            appendUtf8(utf8, u);
        }
        return true;
    }
    error = "unknown charset '" + std::string(charset) + "'";
    return false;
}

bool encodeText(std::string_view utf8, std::string_view charset, std::string& bytes, std::string& error) {
    bytes.clear();
    std::vector<uint32_t> cps;
    if (!toCodePoints(utf8, cps, error)) return false;
    const std::string cs = lower(charset);
    const auto put16 = [&](uint32_t u, bool be) {
        bytes += static_cast<char>(be ? u >> 8 : u & 0xFF);
        bytes += static_cast<char>(be ? u & 0xFF : u >> 8);
    };
    if (cs == "utf-8") {
        bytes.assign(utf8);
        return true;
    }
    if (cs == "utf-16le" || cs == "utf-16be") {
        const bool be = cs == "utf-16be";
        for (uint32_t u : cps) {
            if (u >= 0x10000) {
                u -= 0x10000;
                put16(0xD800 + (u >> 10), be);
                put16(0xDC00 + (u & 0x3FF), be);
            } else {
                put16(u, be);
            }
        }
        return true;
    }
    if (cs == "utf-32le" || cs == "utf-32be") {
        const bool be = cs == "utf-32be";
        for (uint32_t u : cps)
            for (int k = 0; k < 4; ++k) bytes += static_cast<char>((u >> (be ? 24 - 8 * k : 8 * k)) & 0xFF);
        return true;
    }
    if (cs == "latin-1" || cs == "windows-1252" || cs == "ascii") {
        for (size_t i = 0; i < cps.size(); ++i) {
            uint32_t u = cps[i];
            if (cs == "windows-1252" && u > 0xFF)
                for (int k = 0; k < 32; ++k)
                    if (kCp1252[k] == u) u = static_cast<uint32_t>(0x80 + k);
            const uint32_t limit = cs == "ascii" ? 0x7F : 0xFF;
            if (u > limit) {
                std::string ch;
                appendUtf8(ch, cps[i]);
                return error = "'" + ch + "' has no " + std::string(charset) + " byte", false;
            }
            bytes += static_cast<char>(u);
        }
        return true;
    }
    if (cs.rfind("modified utf-8", 0) == 0) {
        const auto put = [&](uint32_t u) {
            if (u != 0 && u < 0x80) bytes += static_cast<char>(u);
            else if (u < 0x800) bytes += static_cast<char>(0xC0 | (u >> 6)), bytes += static_cast<char>(0x80 | (u & 0x3F));
            else bytes += static_cast<char>(0xE0 | (u >> 12)), bytes += static_cast<char>(0x80 | ((u >> 6) & 0x3F)),
                bytes += static_cast<char>(0x80 | (u & 0x3F));
        };
        for (uint32_t u : cps) {
            if (u >= 0x10000) {
                u -= 0x10000;
                put(0xD800 + (u >> 10));
                put(0xDC00 + (u & 0x3FF));
            } else {
                put(u);
            }
        }
        return true;
    }
    error = "unknown charset '" + std::string(charset) + "'";
    return false;
}

std::string md5Hex(std::string_view in) {
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    static const int R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,
                              14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    const std::string m = padded(in, false);
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i) {
            const auto* p = reinterpret_cast<const unsigned char*>(m.data() + off + 4 * i);
            w[i] = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 |
                   static_cast<uint32_t>(p[3]) << 24;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        for (int i = 0; i < 64; ++i) {
            uint32_t f;
            int g;
            if (i < 16) f = (b & c) | (~b & d), g = i;
            else if (i < 32) f = (d & b) | (~d & c), g = (5 * i + 1) % 16;
            else if (i < 48) f = b ^ c ^ d, g = (3 * i + 5) % 16;
            else f = c ^ (b | ~d), g = (7 * i) % 16;
            const uint32_t t = d;
            d = c;
            c = b;
            b = b + rol(a + f + K[i] + w[g], R[i]);
            a = t;
        }
        h[0] += a, h[1] += b, h[2] += c, h[3] += d;
    }
    uint8_t out[16];
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(h[i / 4] >> (8 * (i % 4)));
    return hexOfBytes(out, 16);
}

std::string sha1Hex(std::string_view in) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    const std::string m = padded(in, true);
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            const auto* p = reinterpret_cast<const unsigned char*>(m.data() + off + 4 * i);
            w[i] = static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
        }
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) f = (b & c) | (~b & d), k = 0x5A827999;
            else if (i < 40) f = b ^ c ^ d, k = 0x6ED9EBA1;
            else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8F1BBCDC;
            else f = b ^ c ^ d, k = 0xCA62C1D6;
            const uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d, d = c, c = rol(b, 30), b = a, a = t;
        }
        h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e;
    }
    uint8_t out[20];
    for (int i = 0; i < 20; ++i) out[i] = static_cast<uint8_t>(h[i / 4] >> (24 - 8 * (i % 4)));
    return hexOfBytes(out, 20);
}

Result apply(Op op, std::string_view in, std::string_view arg) {
    Result r;
    const auto fail = [&](std::string why) {
        r.ok = false;
        r.error = std::move(why);
        r.out.clear();
        return r;
    };
    // Text formats ignore the line break a paste usually ends with.
    std::string_view trimmed = in;
    while (!trimmed.empty() && isSpace(trimmed.back())) trimmed.remove_suffix(1);
    while (!trimmed.empty() && isSpace(trimmed.front())) trimmed.remove_prefix(1);
    switch (op) {
    case Op::Base64Decode:
        if (!base64Decode(trimmed, r.out)) return fail("not Base64 (characters A-Z a-z 0-9 + / or - _, then = padding)");
        return r;
    case Op::Base64Encode: r.out = base64Encode(in); return r;
    case Op::Base64UrlEncode: r.out = base64Encode(in, true); return r;
    case Op::Base32Decode:
        if (!base32Decode(trimmed, r.out)) return fail("not Base32 (characters A-Z and 2-7)");
        return r;
    case Op::Base32Encode: r.out = base32Encode(in); return r;
    case Op::HexDecode:
        if (!hexDecode(trimmed, r.out)) return fail("not hex (pairs of 0-9 a-f; spaces, 0x and \\x are fine)");
        return r;
    case Op::HexEncode: r.out = hexEncode(in); return r;
    case Op::UrlDecode: r.out = urlDecode(in); return r;
    case Op::UrlEncode: r.out = urlEncode(in); return r;
    case Op::HtmlDecode: r.out = htmlDecode(in); return r;
    case Op::HtmlEncode: r.out = htmlEncode(in); return r;
    case Op::Unescape: {
        std::string error;
        if (!unescape(in, r.out, error)) return fail(error);
        return r;
    }
    case Op::Escape: r.out = escape(in); return r;
    case Op::DecodeText: {
        std::string error;
        if (!decodeText(in, arg.empty() ? "UTF-8" : arg, r.out, error)) return fail(error);
        return r;
    }
    case Op::EncodeText: {
        std::string error;
        if (!encodeText(in, arg.empty() ? "UTF-8" : arg, r.out, error)) return fail(error);
        return r;
    }
    case Op::Xor: {
        std::string key(arg);
        std::string bytes;
        if ((arg.substr(0, 2) == "0x" || arg.substr(0, 2) == "0X" || arg.substr(0, 2) == "\\x") && hexDecode(arg, bytes)) key = bytes;
        if (key.empty()) return fail("enter a key");
        r.out.assign(in);
        for (size_t i = 0; i < r.out.size(); ++i) r.out[i] = static_cast<char>(r.out[i] ^ key[i % key.size()]);
        return r;
    }
    case Op::Rot13:
        r.out.assign(in);
        for (char& c : r.out) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') c = static_cast<char>('A' + (c - 'A' + 13) % 26);
        }
        return r;
    case Op::Reverse: r.out.assign(in.rbegin(), in.rend()); return r;
    case Op::Inflate: {
        std::string error;
        if (!inflateAny(in, r.out, error)) return fail(error);
        return r;
    }
    case Op::ZlibCompress: r.out = deflateRaw(in, true); return r;
    case Op::GzipCompress: {
        const std::string raw = deflateRaw(in, false);
        r.out = std::string("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff", 10) + raw;
        const uint32_t crc = static_cast<uint32_t>(mz_crc32(MZ_CRC32_INIT, reinterpret_cast<const unsigned char*>(in.data()), in.size()));
        const uint32_t size = static_cast<uint32_t>(in.size());
        for (int i = 0; i < 4; ++i) r.out += static_cast<char>((crc >> (8 * i)) & 0xFF);
        for (int i = 0; i < 4; ++i) r.out += static_cast<char>((size >> (8 * i)) & 0xFF);
        return r;
    }
    case Op::Md5: r.out = md5Hex(in); return r;
    case Op::Sha1: r.out = sha1Hex(in); return r;
    case Op::Sha256: {
        uint8_t d[32];
        sha256::digest(reinterpret_cast<const uint8_t*>(in.data()), in.size(), d);
        r.out = sha256::hex(d);
        return r;
    }
    case Op::JwtDecode: {
        const size_t a = trimmed.find('.');
        const size_t b = a == std::string_view::npos ? a : trimmed.find('.', a + 1);
        if (b == std::string_view::npos) return fail("a JWT is header.payload.signature");
        std::string header, payload;
        if (!base64Decode(trimmed.substr(0, a), header) || !base64Decode(trimmed.substr(a + 1, b - a - 1), payload))
            return fail("the header or payload is not Base64url");
        r.out = header + "\n" + payload;
        return r;
    }
    }
    return fail("unknown operation");
}

bool isReadableText(std::string_view s) {
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F) return false;
            ++i;
            continue;
        }
        uint32_t cp = 0;
        if (!nextUtf8(s, i, cp)) return false;
        if (cp >= 0x80 && cp < 0xA0) return false;  // C1 controls: binary rather than text
    }
    return true;
}

std::vector<Op> guess(std::string_view in) {
    std::string_view s = in;
    while (!s.empty() && isSpace(s.back())) s.remove_suffix(1);
    while (!s.empty() && isSpace(s.front())) s.remove_prefix(1);
    std::vector<Op> out;
    if (s.empty()) return out;
    if (compressed(in)) out.push_back(Op::Inflate);
    if (looksJwt(s)) out.push_back(Op::JwtDecode);
    if (looksUrlEncoded(s)) out.push_back(Op::UrlDecode);
    if (looksHex(s)) out.push_back(Op::HexDecode);
    if (looksBase64(s)) out.push_back(Op::Base64Decode);
    if (s.find('\\') != std::string_view::npos) out.push_back(Op::Unescape);
    if (s.find('&') != std::string_view::npos && s.find(';') != std::string_view::npos) out.push_back(Op::HtmlDecode);
    // UTF-16LE text: every other byte zero.
    if (in.size() >= 4 && in.size() % 2 == 0) {
        size_t zeros = 0;
        for (size_t i = 1; i < in.size(); i += 2) zeros += in[i] == 0;
        if (zeros * 2 >= in.size() / 2 + 1) out.push_back(Op::DecodeText);
    }
    return out;
}

std::vector<Op> smartDecode(std::string_view in, int maxSteps) {
    std::vector<Op> chain;
    std::string cur(in);
    for (int step = 0; step < maxSteps; ++step) {
        bool advanced = false;
        for (Op op : guess(cur)) {
            const Result r = apply(op, cur, op == Op::DecodeText ? "UTF-16LE" : "");
            if (!r.ok || r.out.empty() || r.out == cur) continue;
            // A step counts when it gives text, or bytes that are themselves compressed.
            if (!isReadableText(r.out) && !compressed(r.out)) continue;
            chain.push_back(op);
            cur = r.out;
            advanced = true;
            break;
        }
        if (!advanced) break;
    }
    return chain;
}

bool decodePreview(std::string_view s, std::string& decoded, std::string& steps) {
    if (s.size() < 8 || s.size() > (1u << 20)) return false;  // short words decode to noise
    const std::vector<Op> chain = smartDecode(s);
    if (std::all_of(chain.begin(), chain.end(), [](Op op) { return op == Op::Unescape || op == Op::HtmlDecode; })) return false;
    std::string cur(s);
    steps.clear();
    for (Op op : chain) {
        const Result r = apply(op, cur, op == Op::DecodeText ? "UTF-16LE" : "");
        if (!r.ok) return false;
        cur = r.out;
        steps += (steps.empty() ? "" : " > ") + std::string(info(op).name);
    }
    if (!isReadableText(cur)) return false;
    decoded = std::move(cur);
    return true;
}

std::vector<Literal> stringLiterals(std::string_view line) {
    std::vector<Literal> out;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/') break;  // a comment
        if (line[i] == '\'' ) {  // a char literal: skip it ('"' would open a string)
            const size_t close = line.find('\'', i + (i + 1 < line.size() && line[i + 1] == '\\' ? 3 : 2));
            if (close != std::string_view::npos && close - i <= 8) i = close;
            continue;
        }
        if (line[i] != '"') continue;
        size_t j = i + 1;
        while (j < line.size() && line[j] != '"') j += line[j] == '\\' ? 2 : 1;
        if (j >= line.size()) break;  // unterminated
        Literal lit;
        lit.begin = i;
        lit.end = j + 1;
        std::string error;
        if (!unescape(line.substr(i + 1, j - i - 1), lit.text, error)) lit.text.assign(line.substr(i + 1, j - i - 1));
        out.push_back(std::move(lit));
        i = j;
    }
    return out;
}

const Literal* literalAt(const std::vector<Literal>& lits, size_t col) {
    for (const Literal& l : lits)
        if (col >= l.begin && col < l.end) return &l;
    return nullptr;
}

std::string hexDump(std::string_view in, size_t maxBytes) {
    std::string out;
    const size_t n = std::min(in.size(), maxBytes);
    char line[128];
    for (size_t off = 0; off < n; off += 16) {
        int len = std::snprintf(line, sizeof line, "%08zx  ", off);
        std::string ascii;
        for (size_t k = 0; k < 16; ++k) {
            if (off + k < n) {
                const unsigned char c = static_cast<unsigned char>(in[off + k]);
                len += std::snprintf(line + len, sizeof line - static_cast<size_t>(len), "%02x ", c);
                ascii += c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.';
            } else {
                len += std::snprintf(line + len, sizeof line - static_cast<size_t>(len), "   ");
            }
            if (k == 7) line[len++] = ' ', line[len] = 0;
        }
        out.append(line, static_cast<size_t>(len));
        out += ' ';
        out += ascii;
        out += '\n';
    }
    if (in.size() > n) out += "... " + std::to_string(in.size() - n) + " more bytes\n";
    return out;
}

}  // namespace codec
