#include "core/ResourceTable.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include "core/TextUtils.hpp"

namespace {

constexpr uint16_t kStringPool = 0x0001;
constexpr uint16_t kTable = 0x0002;
constexpr uint16_t kPackage = 0x0200;
constexpr uint16_t kType = 0x0201;
constexpr uint16_t kTypeSpec = 0x0202;
constexpr size_t kMaxStrings = 4u << 20;

struct Reader {
    const std::vector<uint8_t>& d;
    bool in(size_t off, size_t len) const { return off <= d.size() && len <= d.size() - off; }
    uint8_t u8(size_t o) const { return in(o, 1) ? d[o] : 0; }
    uint16_t u16(size_t o) const { return in(o, 2) ? (uint16_t)(d[o] | d[o + 1] << 8) : 0; }
    uint32_t u32(size_t o) const {
        return in(o, 4) ? (uint32_t)d[o] | (uint32_t)d[o + 1] << 8 | (uint32_t)d[o + 2] << 16 | (uint32_t)d[o + 3] << 24 : 0;
    }
};

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out.push_back((char)cp);
    else if (cp < 0x800) {
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

// ResStringPool chunk at `at` -> strings.
std::vector<std::string> readPool(const Reader& r, size_t at) {
    std::vector<std::string> out;
    if (r.u16(at) != kStringPool) return out;
    const uint32_t chunkSize = r.u32(at + 4);
    const uint32_t count = r.u32(at + 8);
    const uint32_t flags = r.u32(at + 16);
    const uint32_t stringsStart = r.u32(at + 20);
    const uint16_t headerSize = r.u16(at + 2);
    if (count > kMaxStrings || !r.in(at, chunkSize) || !r.in(at + headerSize, (size_t)count * 4)) return out;
    const bool utf8 = (flags & (1u << 8)) != 0;
    const size_t end = at + chunkSize;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        size_t p = at + stringsStart + r.u32(at + headerSize + (size_t)i * 4);
        std::string s;
        if (p >= end) {
            out.push_back(s);
            continue;
        }
        if (utf8) {
            // utf16 length (1-2 bytes), utf8 length (1-2 bytes), bytes.
            size_t n = r.u8(p++);
            if (n & 0x80) p++;
            size_t len = r.u8(p++);
            if (len & 0x80) len = ((len & 0x7F) << 8) | r.u8(p++);
            if (p + len <= end) s.assign((const char*)r.d.data() + p, len);
        } else {
            size_t len = r.u16(p);
            p += 2;
            if (len & 0x8000) {
                len = ((len & 0x7FFF) << 16) | r.u16(p);
                p += 2;
            }
            for (size_t k = 0; k < len && p + 2 <= end; ++k, p += 2) {
                uint32_t cp = r.u16(p);
                if (cp >= 0xD800 && cp <= 0xDBFF && p + 4 <= end) {
                    const uint32_t lo = r.u16(p + 2);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        p += 2;
                        ++k;
                    }
                }
                appendUtf8(s, cp);
            }
        }
        out.push_back(std::move(s));
    }
    return out;
}

// UTF-16 fixed-size name (package name field).
std::string utf16Name(const Reader& r, size_t at, size_t chars) {
    std::string s;
    for (size_t i = 0; i < chars; ++i) {
        const uint16_t c = r.u16(at + i * 2);
        if (!c) break;
        appendUtf8(s, c);
    }
    return s;
}

}  // namespace

std::shared_ptr<const ResourceTable> ResourceTable::parse(const std::vector<uint8_t>& data, std::string& error) {
    Reader r{data};
    if (data.size() < 12 || r.u16(0) != kTable) {
        error = "not a resources.arsc table";
        return nullptr;
    }
    auto t = std::make_shared<ResourceTable>();
    const size_t tableEnd = std::min<size_t>(data.size(), r.u32(4));
    size_t pos = r.u16(2);
    while (pos + 8 <= tableEnd) {
        const uint16_t type = r.u16(pos);
        const uint32_t size = r.u32(pos + 4);
        if (size < 8 || !r.in(pos, size)) break;
        if (type == kStringPool && t->strings_.empty()) {
            t->strings_ = readPool(r, pos);
        } else if (type == kPackage) {
            const uint32_t pkgId = r.u32(pos + 8);
            if (t->package_.empty()) t->package_ = utf16Name(r, pos + 12, 128);
            const uint32_t typeStrings = r.u32(pos + 12 + 256);
            const uint32_t keyStrings = r.u32(pos + 12 + 256 + 8);
            const size_t typeBase = t->typeNames_.size();  // several packages: names appended
            const size_t keyBase = t->keys_.size();
            for (auto& s : readPool(r, pos + typeStrings)) t->typeNames_.push_back(std::move(s));
            for (auto& s : readPool(r, pos + keyStrings)) t->keys_.push_back(std::move(s));
            size_t c = pos + r.u16(pos + 2);
            const size_t pkgEnd = pos + size;
            while (c + 8 <= pkgEnd) {
                const uint16_t ctype = r.u16(c);
                const uint16_t cheader = r.u16(c + 2);
                const uint32_t csize = r.u32(c + 4);
                if (csize < 8 || c + csize > pkgEnd) break;
                if (ctype == kType && cheader >= 20) {
                    const uint8_t typeId = r.u8(c + 8);
                    const uint8_t flags = r.u8(c + 9);
                    const uint32_t entryCount = r.u32(c + 12);
                    const uint32_t entriesStart = r.u32(c + 16);
                    // ResTable_config: first u32 is its size; default = all zero.
                    const uint32_t cfgSize = r.u32(c + 20);
                    bool isDefault = true;
                    for (uint32_t k = 4; k < cfgSize && k < 64; ++k)
                        if (r.u8(c + 20 + k)) {
                            isDefault = false;
                            break;
                        }
                    const bool sparse = (flags & 0x01) != 0;
                    const bool offset16 = (flags & 0x02) != 0;
                    const size_t idx = c + cheader;
                    const uint32_t n = std::min<uint32_t>(entryCount, 65536);
                    for (uint32_t e = 0; e < n; ++e) {
                        uint32_t entryIndex = e, off;
                        if (sparse) {
                            entryIndex = r.u16(idx + (size_t)e * 4);
                            off = (uint32_t)r.u16(idx + (size_t)e * 4 + 2) * 4;
                        } else if (offset16) {
                            const uint16_t o = r.u16(idx + (size_t)e * 2);
                            if (o == 0xFFFF) continue;
                            off = (uint32_t)o * 4;
                        } else {
                            off = r.u32(idx + (size_t)e * 4);
                            if (off == 0xFFFFFFFFu) continue;
                        }
                        const size_t ep = c + entriesStart + off;
                        if (!r.in(ep, 8) || ep >= c + csize) continue;
                        Entry entry;
                        const uint16_t esize = r.u16(ep);
                        const uint16_t eflags = r.u16(ep + 2);
                        if (eflags & 0x0008) {  // compact entry: key in size, type in flags
                            entry.key = (uint32_t)(keyBase + esize);
                            entry.dataType = (uint8_t)(eflags >> 8);
                            entry.data = r.u32(ep + 4);
                        } else {
                            entry.key = (uint32_t)(keyBase + r.u32(ep + 4));
                            entry.complex = (eflags & 0x0001) != 0;
                            if (!entry.complex && r.in(ep + esize, 8)) {
                                entry.dataType = r.u8(ep + esize + 3);
                                entry.data = r.u32(ep + esize + 4);
                            }
                        }
                        entry.typeIndex = (uint8_t)std::min<size_t>(255, typeBase + typeId - 1);
                        entry.defaultConfig = isDefault;
                        const uint32_t id = (pkgId << 24) | ((uint32_t)typeId << 16) | entryIndex;
                        auto it = t->entries_.find(id);
                        if (it == t->entries_.end()) {
                            entry.configs = 1;
                            t->entries_.emplace(id, entry);
                        } else {
                            const uint16_t configs = (uint16_t)std::min(65535, it->second.configs + 1);
                            if (isDefault && !it->second.defaultConfig) it->second = entry;  // default config wins
                            it->second.configs = configs;
                        }
                    }
                }
                (void)kTypeSpec;
                c += csize;
            }
        }
        pos += size;
    }
    if (t->entries_.empty() && t->strings_.empty()) {
        error = "resources.arsc contains no entries";
        return nullptr;
    }
    return t;
}

std::string ResourceTable::render(uint8_t type, uint32_t data, int depth) const {
    char buf[64];
    switch (type) {
    case 0x00: return {};
    case 0x01:  // reference
    case 0x07: {  // dynamic reference
        if (depth < 4)
            if (auto it = entries_.find(data); it != entries_.end() && !it->second.complex) {
                const std::string v = render(it->second.dataType, it->second.data, depth + 1);
                if (!v.empty()) return v;
            }
        const std::string ref = reference(data);
        if (!ref.empty()) return ref;
        std::snprintf(buf, sizeof buf, "@0x%08X", data);
        return buf;
    }
    case 0x02: std::snprintf(buf, sizeof buf, "?0x%08X", data); return buf;
    case 0x03: return data < strings_.size() ? strings_[data] : std::string();
    case 0x04: {
        float f;
        std::memcpy(&f, &data, 4);
        std::snprintf(buf, sizeof buf, "%g", f);
        return buf;
    }
    case 0x05:
    case 0x06: {
        static const char* units[] = {"px", "dp", "sp", "pt", "in", "mm", "", ""};
        static const float radix[] = {1.f / (1 << 8), 1.f / (1 << 15), 1.f / (1 << 23), 1.f / ((unsigned)1 << 31)};
        const float v = (float)(int32_t)(data & 0xFFFFFF00u) * radix[(data >> 4) & 3];
        if (type == 0x06) std::snprintf(buf, sizeof buf, "%g%%%s", v * 100.f, (data & 0xF) ? "p" : "");
        else std::snprintf(buf, sizeof buf, "%g%s", v, units[data & 0xF]);
        return buf;
    }
    case 0x10: std::snprintf(buf, sizeof buf, "%d", (int32_t)data); return buf;
    case 0x11: std::snprintf(buf, sizeof buf, "0x%X", data); return buf;
    case 0x12: return data ? "true" : "false";
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:
        std::snprintf(buf, sizeof buf, "#%08X", data);
        return buf;
    default: std::snprintf(buf, sizeof buf, "0x%08X", data); return buf;
    }
}

std::string ResourceTable::reference(uint32_t id) const {
    auto it = entries_.find(id);
    if (it == entries_.end()) return {};
    const Entry& e = it->second;
    const std::string& type = e.typeIndex < typeNames_.size() ? typeNames_[e.typeIndex] : std::string();
    const std::string& key = e.key < keys_.size() ? keys_[e.key] : std::string();
    if (type.empty() || key.empty()) return {};
    return "@" + type + "/" + key;
}

std::string ResourceTable::value(uint32_t id) const {
    auto it = entries_.find(id);
    if (it == entries_.end() || it->second.complex) return {};
    return render(it->second.dataType, it->second.data, 0);
}

bool ResourceTable::lookup(uint32_t id, Item& out) const {
    auto it = entries_.find(id);
    if (it == entries_.end()) return false;
    const Entry& e = it->second;
    out.id = id;
    out.type = e.typeIndex < typeNames_.size() ? typeNames_[e.typeIndex] : std::string();
    out.name = e.key < keys_.size() ? keys_[e.key] : std::string();
    out.complex = e.complex;
    out.configs = e.configs;
    out.value = e.complex ? std::string() : render(e.dataType, e.data, 0);
    return true;
}

std::vector<ResourceTable::Item> ResourceTable::list(const std::string& type, const std::string& filter,
                                                     size_t limit) const {
    std::vector<uint32_t> ids;
    ids.reserve(entries_.size());
    for (const auto& kv : entries_) ids.push_back(kv.first);
    std::sort(ids.begin(), ids.end());
    std::vector<Item> out;
    for (uint32_t id : ids) {
        if (out.size() >= limit) break;
        Item item;
        lookup(id, item);
        if (!type.empty() && item.type != type) continue;
        if (!filter.empty() && tex::ciFind(item.name, filter) == std::string_view::npos &&
            tex::ciFind(item.value, filter) == std::string_view::npos)
            continue;
        out.push_back(std::move(item));
    }
    return out;
}

std::vector<std::string> ResourceTable::types() const {
    std::map<uint32_t, std::string> byId;
    for (const auto& kv : entries_) {
        const uint32_t key = kv.first >> 16;
        if (!byId.count(key) && kv.second.typeIndex < typeNames_.size()) byId[key] = typeNames_[kv.second.typeIndex];
    }
    std::vector<std::string> out;
    for (auto& kv : byId)
        if (std::find(out.begin(), out.end(), kv.second) == out.end()) out.push_back(kv.second);
    return out;
}

uint32_t ResourceTable::find(const std::string& spec) const {
    std::string s = spec;
    if (!s.empty() && s.front() == '@') s.erase(s.begin());
    const size_t slash = s.find('/');
    if (slash == std::string::npos) return 0;
    const std::string type = s.substr(0, slash), name = s.substr(slash + 1);
    for (const auto& kv : entries_) {
        const Entry& e = kv.second;
        if (e.typeIndex < typeNames_.size() && e.key < keys_.size() && typeNames_[e.typeIndex] == type &&
            keys_[e.key] == name)
            return kv.first;
    }
    return 0;
}
