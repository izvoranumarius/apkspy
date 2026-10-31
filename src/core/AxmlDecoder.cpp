#include "core/AxmlDecoder.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>

namespace {

constexpr uint16_t kResXmlType = 0x0003;
constexpr uint16_t kStringPool = 0x0001;
constexpr uint16_t kStartNamespace = 0x0100;
constexpr uint16_t kEndNamespace = 0x0101;
constexpr uint16_t kStartElement = 0x0102;
constexpr uint16_t kEndElement = 0x0103;
constexpr uint16_t kCData = 0x0104;

constexpr uint32_t kNoIndex = 0xFFFFFFFF;

// --- bounds-checked little-endian readers ----------------------------------
struct Cursor {
    const uint8_t* p = nullptr;
    size_t size = 0;
    size_t pos = 0;
    bool ok = true;

    bool avail(size_t n) const { return ok && pos + n <= size; }
    uint16_t u16() {
        if (!avail(2)) { ok = false; return 0; }
        uint16_t v = (uint16_t)(p[pos] | (p[pos + 1] << 8));
        pos += 2;
        return v;
    }
    uint32_t u32() {
        if (!avail(4)) { ok = false; return 0; }
        uint32_t v = (uint32_t)p[pos] | ((uint32_t)p[pos + 1] << 8) |
                     ((uint32_t)p[pos + 2] << 16) | ((uint32_t)p[pos + 3] << 24);
        pos += 4;
        return v;
    }
    uint32_t peek32(size_t at) {
        size_t save = pos;
        pos = at;
        uint32_t v = u32();
        pos = save;
        return v;
    }
};

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back((char)cp);
    } else if (cp < 0x800) {
        out.push_back((char)(0xC0 | (cp >> 6)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back((char)(0xE0 | (cp >> 12)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else {
        out.push_back((char)(0xF0 | (cp >> 18)));
        out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    }
}

bool parseStringPool(const uint8_t* data, size_t size, std::vector<std::string>& out) {
    if (size < 28) return false;
    Cursor c{data, size, 0};
    c.pos = 8;  // stringCount
    uint32_t stringCount = c.u32();
    c.u32();  // styleCount
    uint32_t flags = c.u32();
    uint32_t stringsStart = c.u32();
    c.u32();  // stylesStart - offsets array follows at byte 28
    if (!c.ok || stringCount > 100000 || stringsStart > size) return false;
    bool utf8 = (flags & 0x100) != 0;

    for (uint32_t i = 0; i < stringCount; ++i) {
        if (!c.avail(4)) return false;
        uint32_t offset = c.u32();
        size_t base = (size_t)stringsStart + offset;
        if (base >= size) return false;
        if (utf8) {
            // two varints in a row: char length, then byte length (1-2 bytes each)
            size_t q = base;
            size_t lens[2];
            for (int k = 0; k < 2; ++k) {
                if (q >= size) return false;
                uint8_t b = data[q++];
                if (b & 0x80) {
                    if (q >= size) return false;
                    lens[k] = ((size_t)(b & 0x7F) << 8) | data[q++];
                } else {
                    lens[k] = b;
                }
            }
            size_t byteLen = lens[1];
            if (q + byteLen > size) return false;
            out.emplace_back(reinterpret_cast<const char*>(data + q), byteLen);
        } else {
            size_t p = base;
            if (!c.avail(2)) return false;
            uint32_t len = (uint32_t)data[p] | ((uint32_t)data[p + 1] << 8);
            p += 2;
            if (len & 0x8000) {
                if (p + 2 > size) return false;
                len = ((len & 0x7FFF) << 16) | ((uint32_t)data[p] | ((uint32_t)data[p + 1] << 8));
                p += 2;
            }
            if (p + 2 * (size_t)len > size) return false;
            std::string s;
            s.reserve(len);
            for (uint32_t j = 0; j < len; ++j) {
                uint32_t ch = (uint32_t)data[p + 2 * j] | ((uint32_t)data[p + 2 * j + 1] << 8);
                if (ch >= 0xD800 && ch <= 0xDBFF && j + 1 < len) {
                    uint32_t lo = (uint32_t)data[p + 2 * (j + 1)] | ((uint32_t)data[p + 2 * (j + 1) + 1] << 8);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        appendUtf8(s, 0x10000 + ((ch - 0xD800) << 10) + (lo - 0xDC00));
                        ++j;
                        continue;
                    }
                }
                appendUtf8(s, ch);
            }
            out.push_back(std::move(s));
        }
    }
    return true;
}

std::string poolString(const std::vector<std::string>& pool, uint32_t index) {
    return index < pool.size() ? pool[index] : std::string();
}

void escape(std::string& out, const std::string& s, bool attribute) {
    for (char ch : s) {
        switch (ch) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': if (attribute) out += "&quot;"; else out += '"'; break;
        case '\'': if (attribute) out += "&apos;"; else out += '\''; break;
        default: out += ch;
        }
    }
}

float complexToFloat(uint32_t data) {
    static const float kRadixMults[4] = {0.00390625f, 3.051758E-5f, 1.220703125E-7f, 4.656613E-10f};
    return (float)(data & 0xFFFFFF00u) * kRadixMults[(data >> 4) & 0x3];
}

std::string formatTypedValue(uint8_t type, uint32_t data) {
    char buf[64];
    switch (type) {
    case 0x00: return "";  // NULL
    case 0x01:  // REFERENCE
        if ((data >> 24) == 0x01) std::snprintf(buf, sizeof buf, "@android:0x%08X", data);
        else std::snprintf(buf, sizeof buf, "@ref/0x%08X", data);
        return buf;
    case 0x02:  // ATTRIBUTE
        std::snprintf(buf, sizeof buf, "?attr/0x%08X", data);
        return buf;
    case 0x04:  // FLOAT
        std::snprintf(buf, sizeof buf, "%g", *reinterpret_cast<const float*>(&data));
        return buf;
    case 0x05: {  // DIMENSION
        static const char* kUnits[] = {"px", "dp", "sp", "pt", "in", "mm"};
        uint32_t unit = data & 0xF;
        std::snprintf(buf, sizeof buf, "%g%s", complexToFloat(data),
                      unit < 6 ? kUnits[unit] : "");
        return buf;
    }
    case 0x06: {  // FRACTION
        float v = complexToFloat(data) * 100.f;
        std::snprintf(buf, sizeof buf, "%g%s", v, (data & 0xF) == 1 ? "%p" : "%");
        return buf;
    }
    case 0x10:  // INT_DEC
        std::snprintf(buf, sizeof buf, "%d", (int32_t)data);
        return buf;
    case 0x11:  // INT_HEX
        std::snprintf(buf, sizeof buf, "0x%08X", data);
        return buf;
    case 0x12:  // INT_BOOLEAN
        return data != 0 ? "true" : "false";
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:  // colors
        std::snprintf(buf, sizeof buf, "#%08X", data);
        return buf;
    default:
        std::snprintf(buf, sizeof buf, "0x%08X", data);
        return buf;
    }
}

}  // namespace

bool AxmlDecoder::looksLikeAxml(const std::vector<uint8_t>& bytes) {
    return bytes.size() >= 8 && bytes[0] == 0x03 && bytes[1] == 0x00;
}

bool AxmlDecoder::decode(const std::vector<uint8_t>& bytes, std::string& out, std::string& error) {
    if (!looksLikeAxml(bytes)) {
        error = "not a binary XML chunk";
        return false;
    }
    Cursor c{bytes.data(), bytes.size(), 0};
    uint32_t totalSize = c.peek32(4);
    if (totalSize > bytes.size()) {
        error = "truncated binary XML";
        return false;
    }

    std::vector<std::string> pool;
    // xmlns declarations waiting to be attached to the next start tag
    std::vector<std::pair<std::string, std::string>> pendingNs;   // prefix, uri
    std::vector<std::pair<std::string, std::string>> openNs;      // prefix, uri
    std::vector<std::string> openElements;
    int depth = 0;
    bool pendingOpenTag = false;  // "<name ..." written without ">" yet

    out += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

    size_t pos = 8;  // skip the RES_XML_TYPE wrapper header
    while (pos + 8 <= totalSize) {
        c.pos = pos;
        uint16_t type = c.u16();
        uint16_t headerSize = c.u16();
        uint32_t chunkSize = c.u32();
        if (!c.ok || chunkSize < 8 || pos + chunkSize > totalSize) {
            error = "corrupt chunk header";
            return false;
        }
        const uint8_t* data = bytes.data() + pos;
        size_t size = chunkSize;

        switch (type) {
        case kStringPool:
            if (!parseStringPool(data, size, pool)) {
                error = "corrupt string pool";
                return false;
            }
            break;

        case kStartNamespace: {
            if (size < 24) { error = "short namespace chunk"; return false; }
            c.pos = pos + 16;
            uint32_t prefixIdx = c.u32();
            uint32_t uriIdx = c.u32();
            if (!c.ok) { error = "short namespace chunk"; return false; }
            // Attach xmlns declarations to the element that opens them.
            std::string prefix = poolString(pool, prefixIdx);
            std::string uri = poolString(pool, uriIdx);
            openNs.emplace_back(prefix, uri);
            pendingNs.emplace_back(std::move(prefix), std::move(uri));
            break;
        }

        case kEndNamespace:
            if (!openNs.empty()) openNs.pop_back();
            break;

        case kStartElement: {
            if (size < 36) { error = "short element chunk"; return false; }
            // ResXMLTree_attrExt: ns u32, name u32, attributeStart u16,
            // attributeSize u16, attributeCount u16, id/class/styleIndex u16
            c.pos = pos + 16;
            uint32_t nsElemIdx = c.u32();
            uint32_t nameIdx = c.u32();
            uint16_t attributeStart = c.u16();
            uint16_t attributeSize = c.u16();
            uint16_t attributeCount = c.u16();
            if (!c.ok || attributeSize < 20) { error = "corrupt element"; return false; }
            (void)nsElemIdx;

            if (pendingOpenTag) { out += ">\n"; pendingOpenTag = false; }
            out.append(depth * 4, ' ');
            out += "<" + poolString(pool, nameIdx);
            for (const auto& ns : pendingNs) {
                out += "\n";
                out.append((depth + 1) * 4, ' ');
                out += "xmlns:" + ns.first + "=\"";
                escape(out, ns.second, true);
                out += "\"";
            }
            pendingNs.clear();

            size_t attrBase = pos + attributeStart;
            for (uint16_t i = 0; i < attributeCount; ++i) {
                size_t base = attrBase + (size_t)i * attributeSize;
                if (base + 20 > pos + size) { error = "corrupt attributes"; return false; }
                uint32_t nsIdx = c.peek32(base);
                uint32_t attrNameIdx = c.peek32(base + 4);
                uint32_t rawValue = c.peek32(base + 8);
                // typed value: size u16, res0 u8, dataType u8, data u32
                uint32_t tvHeader = c.peek32(base + 12);
                uint8_t dataType = (uint8_t)(tvHeader >> 24);
                uint32_t typedData = c.peek32(base + 16);

                std::string name = poolString(pool, attrNameIdx);
                if (name.empty()) name = "attr" + std::to_string(i);
                out += "\n";
                out.append((depth + 1) * 4, ' ');
                if (nsIdx != kNoIndex) {
                    std::string uri = poolString(pool, nsIdx);
                    std::string prefix;
                    for (auto it = openNs.rbegin(); it != openNs.rend() && prefix.empty(); ++it)
                        if (it->second == uri) prefix = it->first;
                    if (prefix.empty()) {
                        if (uri == "http://schemas.android.com/apk/res/android") prefix = "android";
                        else if (uri == "http://schemas.android.com/apk/res-auto") prefix = "app";
                        else prefix = "ns";
                    }
                    out += prefix + ":";
                }
                out += name + "=\"";
                if (dataType == 0x03 && typedData != kNoIndex) {
                    escape(out, poolString(pool, typedData), true);
                } else if (rawValue != kNoIndex && dataType == 0x03) {
                    escape(out, poolString(pool, rawValue), true);
                } else {
                    std::string v = formatTypedValue(dataType, dataType == 0x03 ? rawValue : typedData);
                    escape(out, v, true);
                }
                out += "\"";
            }
            // The closing ">" is deferred so an immediately following end
            // element can turn the tag into "<name ... />".
            pendingOpenTag = true;
            openElements.push_back(poolString(pool, nameIdx));
            ++depth;
            break;
        }

        case kEndElement: {
            if (size < 24) { error = "short end-element chunk"; return false; }
            // ResXMLTree_endElementExt: ns u32, name u32
            c.pos = pos + 20;
            uint32_t nameIdx = c.u32();
            if (!c.ok) { error = "short end-element chunk"; return false; }
            if (depth > 0) --depth;
            std::string name = poolString(pool, nameIdx);
            if (pendingOpenTag) {
                out += " />\n";
                pendingOpenTag = false;
                if (!openElements.empty()) openElements.pop_back();
            } else {
                out.append(depth * 4, ' ');
                out += "</" + name + ">\n";
                if (!openElements.empty()) openElements.pop_back();
            }
            break;
        }

        case kCData: {
            if (size < 20) break;
            uint32_t dataIdx = c.peek32(pos + 16);
            if (dataIdx == kNoIndex) break;
            std::string text = poolString(pool, dataIdx);
            // skip whitespace-only text nodes
            bool printable = false;
            for (char ch : text)
                if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') { printable = true; break; }
            if (!printable) break;
            if (pendingOpenTag) { out += ">"; pendingOpenTag = false; }
            escape(out, text, false);
            break;
        }

        default:
            break;  // resource map, unknown chunks - skip
        }
        (void)headerSize;
        pos += chunkSize;
    }

    return true;
}
