#include "core/ProtoXml.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <set>

namespace protoxml {
namespace {

// Minimal protobuf wire reader.
struct Field {
    uint32_t number = 0;
    int wire = 0;
    uint64_t value = 0;                 // varint / fixed
    const uint8_t* data = nullptr;      // length-delimited payload
    size_t size = 0;
};

bool readFields(const uint8_t* p, size_t n, std::vector<Field>& out) {
    size_t i = 0;
    const auto varint = [&](uint64_t& v) {
        v = 0;
        for (int shift = 0; shift < 64 && i < n; shift += 7) {
            const uint8_t b = p[i++];
            v |= static_cast<uint64_t>(b & 0x7f) << shift;
            if (!(b & 0x80)) return true;
        }
        return false;
    };
    while (i < n) {
        uint64_t key = 0;
        if (!varint(key)) return false;
        Field f;
        f.number = static_cast<uint32_t>(key >> 3);
        f.wire = static_cast<int>(key & 7);
        if (f.wire == 0) {
            if (!varint(f.value)) return false;
        } else if (f.wire == 1) {
            if (i + 8 > n) return false;
            std::memcpy(&f.value, p + i, 8);
            i += 8;
        } else if (f.wire == 5) {
            if (i + 4 > n) return false;
            uint32_t v = 0;
            std::memcpy(&v, p + i, 4);
            f.value = v;
            i += 4;
        } else if (f.wire == 2) {
            uint64_t len = 0;
            if (!varint(len) || len > n - i) return false;
            f.data = p + i;
            f.size = static_cast<size_t>(len);
            i += f.size;
        } else {
            return false;
        }
        out.push_back(f);
    }
    return true;
}

std::string str(const Field& f) { return std::string(reinterpret_cast<const char*>(f.data), f.size); }

struct Attr {
    std::string ns, name, value;
    uint32_t resourceId = 0;
    uint8_t type = 3;       // AXML value type: 3 string, 1 reference, 0x10 / 0x11 int, 0x12 boolean, 4 float
    uint32_t data = 0;
    bool typed = false;
};
struct Element {
    std::vector<std::pair<std::string, std::string>> declarations;  // prefix, uri
    std::string ns, name;
    std::vector<Attr> attrs;
    std::vector<Element> children;
};

bool parseElement(const uint8_t* p, size_t n, Element& e, int depth) {
    if (depth > 64) return false;
    std::vector<Field> fields;
    if (!readFields(p, n, fields)) return false;
    for (const Field& f : fields) {
        if (f.wire != 2) continue;
        if (f.number == 1) {
            std::vector<Field> d;
            if (!readFields(f.data, f.size, d)) return false;
            std::string prefix, uri;
            for (const Field& x : d) {
                if (x.number == 1 && x.wire == 2) prefix = str(x);
                if (x.number == 2 && x.wire == 2) uri = str(x);
            }
            e.declarations.emplace_back(prefix, uri);
        } else if (f.number == 2) {
            e.ns = str(f);
        } else if (f.number == 3) {
            e.name = str(f);
        } else if (f.number == 4) {
            std::vector<Field> a;
            if (!readFields(f.data, f.size, a)) return false;
            Attr at;
            for (const Field& x : a) {
                if (x.number == 1 && x.wire == 2) at.ns = str(x);
                else if (x.number == 2 && x.wire == 2) at.name = str(x);
                else if (x.number == 3 && x.wire == 2) at.value = str(x);
                else if (x.number == 5 && x.wire == 0) at.resourceId = static_cast<uint32_t>(x.value);
                else if (x.number == 6 && x.wire == 2) {  // compiled_item: Item
                    std::vector<Field> item;
                    if (!readFields(x.data, x.size, item)) return false;
                    for (const Field& it : item) {
                        if (it.number == 1 && it.wire == 2) {  // ref
                            std::vector<Field> r;
                            if (!readFields(it.data, it.size, r)) return false;
                            for (const Field& rf : r)
                                if (rf.number == 2 && rf.wire == 0) {
                                    at.type = 1;
                                    at.data = static_cast<uint32_t>(rf.value);
                                    at.typed = true;
                                }
                        } else if (it.number == 7 && it.wire == 2) {  // prim
                            std::vector<Field> pr;
                            if (!readFields(it.data, it.size, pr)) return false;
                            for (const Field& pf : pr) {
                                if (pf.number == 6 && pf.wire == 0) at.type = 0x10, at.data = static_cast<uint32_t>(pf.value), at.typed = true;
                                else if (pf.number == 7 && pf.wire == 0) at.type = 0x11, at.data = static_cast<uint32_t>(pf.value), at.typed = true;
                                else if (pf.number == 8 && pf.wire == 0) at.type = 0x12, at.data = pf.value ? 0xffffffffu : 0u, at.typed = true;
                                else if (pf.number == 3 && pf.wire == 5) at.type = 4, at.data = static_cast<uint32_t>(pf.value), at.typed = true;
                                else if (pf.number == 13 && pf.wire == 0) at.type = 5, at.data = static_cast<uint32_t>(pf.value), at.typed = true;
                                else if (pf.number == 14 && pf.wire == 0) at.type = 6, at.data = static_cast<uint32_t>(pf.value), at.typed = true;
                            }
                        }
                    }
                }
            }
            const auto after = std::find_if(e.attrs.begin(), e.attrs.end(), [&](const Attr& o) {
                return at.resourceId && (!o.resourceId || o.resourceId > at.resourceId);
            });
            e.attrs.insert(after, std::move(at));
        } else if (f.number == 5) {  // child: XmlNode
            std::vector<Field> node;
            if (!readFields(f.data, f.size, node)) return false;
            for (const Field& x : node)
                if (x.number == 1 && x.wire == 2) {  // element
                    Element child;
                    if (!parseElement(x.data, x.size, child, depth + 1)) return false;
                    e.children.push_back(std::move(child));
                }
        }
    }
    return true;
}

// Binary XML writer: a UTF-16 string pool (attribute names that carry a resource id first, as the format requires),
// the resource-id map, then namespace and element chunks.
struct Writer {
    std::vector<uint8_t> out;
    std::vector<std::string> pool;
    std::map<std::string, uint32_t> index;
    std::vector<uint32_t> resIds;  // for the first pool entries

    void u16(uint16_t v) { out.push_back(static_cast<uint8_t>(v)), out.push_back(static_cast<uint8_t>(v >> 8)); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
    void put32(size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) out[at + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
    }
    uint32_t add(const std::string& s) {
        auto it = index.find(s);
        if (it != index.end()) return it->second;
        const uint32_t i = static_cast<uint32_t>(pool.size());
        pool.push_back(s);
        index[s] = i;
        return i;
    }
    uint32_t ref(const std::string& s) { return s.empty() ? 0xffffffffu : add(s); }
};

void collectNames(const Element& e, Writer& w, std::map<std::string, uint32_t>& ids) {
    for (const Attr& a : e.attrs)
        if (a.resourceId && !ids.count(a.name)) ids[a.name] = a.resourceId;
    for (const Element& c : e.children) collectNames(c, w, ids);
}

void collectStrings(const Element& e, Writer& w) {
    for (const auto& d : e.declarations) w.add(d.first), w.add(d.second);
    w.ref(e.ns), w.add(e.name);
    for (const Attr& a : e.attrs) {
        w.ref(a.ns), w.add(a.name);
        if (!a.typed || a.type == 3) w.add(a.value);
    }
    for (const Element& c : e.children) collectStrings(c, w);
}

void writeElement(const Element& e, Writer& w) {
    for (const auto& d : e.declarations) {
        w.u16(0x0100), w.u16(16), w.u32(24), w.u32(1), w.u32(0xffffffffu);
        w.u32(w.add(d.first)), w.u32(w.add(d.second));
    }
    const size_t start = w.out.size();
    w.u16(0x0102), w.u16(16), w.u32(static_cast<uint32_t>(36 + 20 * e.attrs.size())), w.u32(1), w.u32(0xffffffffu);
    w.u32(w.ref(e.ns)), w.u32(w.add(e.name)), w.u16(0x14), w.u16(0x14), w.u16(static_cast<uint16_t>(e.attrs.size())), w.u16(0), w.u16(0), w.u16(0);
    (void)start;
    for (const Attr& a : e.attrs) {
        w.u32(w.ref(a.ns)), w.u32(w.add(a.name));
        const bool asString = !a.typed || a.type == 3;
        w.u32(asString ? w.add(a.value) : 0xffffffffu);
        w.u16(8), w.out.push_back(0), w.out.push_back(asString ? 3 : a.type);
        w.u32(asString ? w.add(a.value) : a.data);
    }
    for (const Element& c : e.children) writeElement(c, w);
    w.u16(0x0103), w.u16(16), w.u32(24), w.u32(1), w.u32(0xffffffffu);
    w.u32(w.ref(e.ns)), w.u32(w.add(e.name));
    for (auto it = e.declarations.rbegin(); it != e.declarations.rend(); ++it) {
        w.u16(0x0101), w.u16(16), w.u32(24), w.u32(1), w.u32(0xffffffffu);
        w.u32(w.add(it->first)), w.u32(w.add(it->second));
    }
}

}  // namespace

bool toBinaryXml(const std::vector<uint8_t>& pb, std::vector<uint8_t>& axml, std::string& error) {
    std::vector<Field> top;
    if (!readFields(pb.data(), pb.size(), top)) {
        error = "not a protobuf XmlNode";
        return false;
    }
    Element root;
    bool found = false;
    for (const Field& f : top)
        if (f.number == 1 && f.wire == 2) {
            if (!parseElement(f.data, f.size, root, 0)) {
                error = "malformed protobuf manifest";
                return false;
            }
            found = true;
        }
    if (!found || root.name.empty()) {
        error = "the protobuf has no root element";
        return false;
    }
    Writer w;
    std::map<std::string, uint32_t> ids;
    collectNames(root, w, ids);
    for (const auto& [name, id] : ids) {  // names with resource ids come first, in the order of the resource map
        w.add(name);
        w.resIds.push_back(id);
    }
    // Attribute names in the pool must line up with the id array: the map iterates by name, and add() assigned the
    // indices in that same order.
    collectStrings(root, w);

    // Body (chunks after the pool) is written first so every string already has its index.
    Writer body;
    body.pool = w.pool;
    body.index = w.index;
    writeElement(root, body);
    if (body.pool.size() != w.pool.size()) {  // writeElement added a string collectStrings missed: rebuild with it
        w.pool = body.pool;
        w.index = body.index;
    }

    // Header, string pool (UTF-16), resource map, body.
    std::vector<uint8_t>& o = w.out;
    o.clear();
    w.u16(0x0003), w.u16(8), w.u32(0);
    const size_t poolStart = o.size();
    w.u16(0x0001), w.u16(28), w.u32(0), w.u32(static_cast<uint32_t>(w.pool.size())), w.u32(0), w.u32(0), w.u32(0), w.u32(0);
    const size_t offsetsAt = o.size();
    for (size_t i = 0; i < w.pool.size(); ++i) w.u32(0);
    const size_t dataStart = o.size();
    for (size_t i = 0; i < w.pool.size(); ++i) {
        w.put32(offsetsAt + 4 * i, static_cast<uint32_t>(o.size() - dataStart));
        // UTF-8 -> UTF-16 (BMP and surrogate pairs).
        std::vector<uint16_t> u;
        const std::string& s = w.pool[i];
        for (size_t k = 0; k < s.size();) {
            const uint8_t c = static_cast<uint8_t>(s[k]);
            uint32_t cp = c;
            size_t len = 1;
            if (c >= 0xF0 && k + 3 < s.size()) cp = (c & 7u) << 18 | (s[k + 1] & 0x3Fu) << 12 | (s[k + 2] & 0x3Fu) << 6 | (s[k + 3] & 0x3Fu), len = 4;
            else if (c >= 0xE0 && k + 2 < s.size()) cp = (c & 15u) << 12 | (s[k + 1] & 0x3Fu) << 6 | (s[k + 2] & 0x3Fu), len = 3;
            else if (c >= 0xC0 && k + 1 < s.size()) cp = (c & 31u) << 6 | (s[k + 1] & 0x3Fu), len = 2;
            if (cp >= 0x10000) cp -= 0x10000, u.push_back(static_cast<uint16_t>(0xD800 + (cp >> 10))), u.push_back(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
            else u.push_back(static_cast<uint16_t>(cp));
            k += len;
        }
        if (u.size() > 0x7FFF) u.resize(0x7FFF);
        w.u16(static_cast<uint16_t>(u.size()));
        for (uint16_t ch : u) w.u16(ch);
        w.u16(0);
    }
    while (o.size() % 4) o.push_back(0);
    w.put32(poolStart + 4, static_cast<uint32_t>(o.size() - poolStart));
    w.put32(poolStart + 20, static_cast<uint32_t>(dataStart - poolStart));  // stringsStart
    if (!w.resIds.empty()) {
        w.u16(0x0180), w.u16(8), w.u32(static_cast<uint32_t>(8 + 4 * w.resIds.size()));
        for (uint32_t id : w.resIds) w.u32(id);
    }
    // The body was generated against `body`'s pool, which equals `w.pool` now: write it again into this buffer.
    Writer rebuilt;
    rebuilt.pool = w.pool;
    rebuilt.index = w.index;
    writeElement(root, rebuilt);
    o.insert(o.end(), rebuilt.out.begin(), rebuilt.out.end());
    w.put32(4, static_cast<uint32_t>(o.size()));
    axml = std::move(o);
    return true;
}

namespace {

// A binary string pool (UTF-16) for resources.arsc.
std::vector<uint8_t> makePool(const std::vector<std::string>& strings) {
    Writer w;
    const size_t start = w.out.size();
    w.u16(0x0001), w.u16(28), w.u32(0), w.u32(static_cast<uint32_t>(strings.size())), w.u32(0), w.u32(0), w.u32(0), w.u32(0);
    const size_t offsetsAt = w.out.size();
    for (size_t i = 0; i < strings.size(); ++i) w.u32(0);
    const size_t dataStart = w.out.size();
    for (size_t i = 0; i < strings.size(); ++i) {
        w.put32(offsetsAt + 4 * i, static_cast<uint32_t>(w.out.size() - dataStart));
        std::vector<uint16_t> u;
        const std::string& s = strings[i];
        for (size_t k = 0; k < s.size();) {
            const uint8_t c = static_cast<uint8_t>(s[k]);
            uint32_t cp = c;
            size_t len = 1;
            if (c >= 0xF0 && k + 3 < s.size()) cp = (c & 7u) << 18 | (s[k + 1] & 0x3Fu) << 12 | (s[k + 2] & 0x3Fu) << 6 | (s[k + 3] & 0x3Fu), len = 4;
            else if (c >= 0xE0 && k + 2 < s.size()) cp = (c & 15u) << 12 | (s[k + 1] & 0x3Fu) << 6 | (s[k + 2] & 0x3Fu), len = 3;
            else if (c >= 0xC0 && k + 1 < s.size()) cp = (c & 31u) << 6 | (s[k + 1] & 0x3Fu), len = 2;
            if (cp >= 0x10000) cp -= 0x10000, u.push_back(static_cast<uint16_t>(0xD800 + (cp >> 10))), u.push_back(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
            else u.push_back(static_cast<uint16_t>(cp));
            k += len;
        }
        if (u.size() > 0x7FFF) u.resize(0x7FFF);
        w.u16(static_cast<uint16_t>(u.size()));
        for (uint16_t ch : u) w.u16(ch);
        w.u16(0);
    }
    while (w.out.size() % 4) w.out.push_back(0);
    w.put32(start + 4, static_cast<uint32_t>(w.out.size() - start));
    w.put32(start + 20, static_cast<uint32_t>(dataStart - start));
    return w.out;
}

// One Res_value: its type and data.
struct ResValue {
    uint8_t type = 0;
    uint32_t data = 0;
};
// What a resource holds in one configuration: a simple value, or a bag (style, array, plurals, attr) with its parent.
struct ResData {
    bool complex = false;
    ResValue value;
    uint32_t parent = 0;
    std::vector<std::pair<uint32_t, ResValue>> bag;
};
using ConfigBytes = std::vector<uint8_t>;  // a 64-byte ResTable_config
struct ResEntry {
    std::string name;
    std::map<ConfigBytes, ResData> values;
};
struct ResType {
    std::string name;
    std::map<uint32_t, ResEntry> entries;
};

using Strings = std::function<uint32_t(const std::string&)>;

// aapt2 `Reference`: the id it points at (field 2).
uint32_t referenceId(const Field& f) {
    std::vector<Field> v;
    readFields(f.data, f.size, v);
    for (const Field& x : v)
        if (x.number == 2 && x.wire == 0) return static_cast<uint32_t>(x.value);
    return 0u;
}

// aapt2 `Item` (a reference, a string, a file or a primitive) as a Res_value.
bool parseItem(const Field& f, const Strings& global, ResValue& out) {
    std::vector<Field> item;
    if (!readFields(f.data, f.size, item)) return false;
    bool have = false;
    for (const Field& it : item) {
        std::vector<Field> inner;
        if (it.wire != 2 || !readFields(it.data, it.size, inner)) continue;
        if (it.number == 1) {  // ref
            out = {0x01, referenceId(it)}, have = true;
        } else if (it.number == 6) {  // id: an @+id/ name, which holds "false"
            out = {0x12, 0}, have = true;
        } else if (it.number >= 2 && it.number <= 5) {  // str, raw_str, styled_str (plain text), file (its path)
            for (const Field& r : inner)
                if (r.number == 1 && r.wire == 2) out = {0x03, global(str(r))}, have = true;
        } else if (it.number == 7) {  // prim
            for (const Field& r : inner) {
                const uint32_t v = static_cast<uint32_t>(r.value);
                if (r.wire == 5 && r.number == 3) out = {0x04, v}, have = true;
                if (r.wire == 2 && r.number == 1) out = {0x00, 0}, have = true;  // @null
                if (r.wire == 2 && r.number == 2) out = {0x00, 1}, have = true;  // @empty
                if (r.wire != 0) continue;
                if (r.number == 6) out = {0x10, v}, have = true;
                else if (r.number == 7) out = {0x11, v}, have = true;
                else if (r.number == 8) out = {0x12, v ? 0xffffffffu : 0u}, have = true;
                else if (r.number >= 9 && r.number <= 12) out = {static_cast<uint8_t>(0x1c + (r.number - 9)), v}, have = true;
                else if (r.number == 13) out = {0x05, v}, have = true;
                else if (r.number == 14) out = {0x06, v}, have = true;
            }
        }
    }
    return have;
}

// aapt2 `CompoundValue`: attr = 1, style = 2, styleable = 3 (not a resource of its own), array = 4, plural = 5.
bool parseCompound(const Field& f, const Strings& global, ResData& out) {
    std::vector<Field> kinds;
    if (!readFields(f.data, f.size, kinds)) return false;
    for (const Field& k : kinds) {
        std::vector<Field> body;
        if (k.wire != 2 || !readFields(k.data, k.size, body)) continue;
        if (k.number == 3) return false;
        out.complex = true;
        uint32_t index = 0;
        for (const Field& e : body) {
            if (k.number == 1) {  // attr: format_flags = 1, symbol = 4 { name = 3, value = 4 }
                if (e.number == 1 && e.wire == 0) out.bag.push_back({0x01000000u, {0x10, static_cast<uint32_t>(e.value)}});
                if (e.number != 4 || e.wire != 2) continue;
                std::vector<Field> sym;
                readFields(e.data, e.size, sym);
                uint32_t name = 0, value = 0;
                for (const Field& s : sym) {
                    if (s.number == 3 && s.wire == 2) name = referenceId(s);
                    if (s.number == 4 && s.wire == 0) value = static_cast<uint32_t>(s.value);
                }
                out.bag.push_back({name, {0x10, value}});
                continue;
            }
            if (k.number == 2 && e.number == 1 && e.wire == 2) {  // style parent
                out.parent = referenceId(e);
                continue;
            }
            const uint32_t entryField = k.number == 2 ? 3u : 1u;
            if (e.number != entryField || e.wire != 2) continue;
            std::vector<Field> en;
            if (!readFields(e.data, e.size, en)) continue;
            uint32_t key = 0, arity = 0;
            ResValue value;
            bool have = false;
            for (const Field& x : en) {
                if (k.number == 2) {  // Style.Entry: key = 3, item = 4
                    if (x.number == 3 && x.wire == 2) key = referenceId(x);
                    if (x.number == 4 && x.wire == 2) have = parseItem(x, global, value);
                } else if (k.number == 4) {  // Array.Element: item = 3
                    if (x.number == 3 && x.wire == 2) have = parseItem(x, global, value);
                } else if (k.number == 5) {  // Plural.Entry: arity = 3, item = 4
                    if (x.number == 3 && x.wire == 0) arity = static_cast<uint32_t>(x.value);
                    if (x.number == 4 && x.wire == 2) have = parseItem(x, global, value);
                }
            }
            if (!have) continue;
            if (k.number == 4) key = 0x02000000u | index++;
            if (k.number == 5) {  // ZERO..OTHER -> ATTR_ZERO..ATTR_MANY, ATTR_OTHER
                static const uint32_t ids[6] = {0x01000005, 0x01000006, 0x01000007, 0x01000008, 0x01000009, 0x01000004};
                key = ids[std::min(arity, 5u)];
            }
            out.bag.push_back({key, value});
        }
        if (k.number == 1 || k.number == 2)
            std::stable_sort(out.bag.begin(), out.bag.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
        return true;
    }
    return false;
}

// aapt2 `Configuration` as the binary ResTable_config.
ConfigBytes parseConfig(const uint8_t* data, size_t size) {
    ConfigBytes c(64, 0);
    c[0] = 64;
    std::vector<Field> fields;
    if (!readFields(data, size, fields)) return c;
    const auto put16 = [&](size_t at, uint32_t v) { c[at] = static_cast<uint8_t>(v), c[at + 1] = static_cast<uint8_t>(v >> 8); };
    for (const Field& f : fields) {
        const uint32_t v = static_cast<uint32_t>(f.value);
        if (f.number == 3 && f.wire == 2) {  // BCP 47 locale: language[-Script][-REGION]
            const std::string tag = str(f);
            size_t start = 0;
            for (int part = 0; start <= tag.size(); ++part) {
                const size_t end = std::min(tag.find('-', start), tag.size());
                const std::string p = tag.substr(start, end - start);
                const auto pack = [&](size_t at, char base) {  // two letters as they are, three packed in two bytes
                    if (p.size() == 2) c[at] = static_cast<uint8_t>(p[0]), c[at + 1] = static_cast<uint8_t>(p[1]);
                    if (p.size() == 3) {
                        const unsigned a = (p[0] - base) & 31, b = (p[1] - base) & 31, d = (p[2] - base) & 31;
                        c[at] = static_cast<uint8_t>(0x80 | (d << 2) | (b >> 3));
                        c[at + 1] = static_cast<uint8_t>((b << 5) | a);
                    }
                };
                if (part == 0) pack(8, 'a');
                else if (p.size() == 4) std::memcpy(&c[36], p.data(), 4);
                else if (p.size() == 2 || p.size() == 3) pack(10, '0');
                start = end + 1;
            }
            continue;
        }
        if (f.wire != 0 || v == 0) continue;
        switch (f.number) {
        case 1: put16(4, v); break;                                    // mcc
        case 2: put16(6, v); break;                                    // mnc
        case 4: c[28] |= static_cast<uint8_t>(v << 6); break;          // layout direction
        case 5: put16(20, v); break;                                   // screen width / height
        case 6: put16(22, v); break;
        case 7: put16(32, v); break;                                   // ... in dp
        case 8: put16(34, v); break;
        case 9: put16(30, v); break;                                   // smallest width dp
        case 10: c[28] |= static_cast<uint8_t>(v & 15); break;         // screen size class
        case 11: c[28] |= v == 1 ? 0x20 : 0x10; break;                 // long / notlong
        case 12: c[48] |= v == 1 ? 2 : 1; break;                       // round / notround
        case 13: c[49] |= v == 1 ? 2 : 1; break;                       // wide colour gamut
        case 14: c[49] |= v == 1 ? 8 : 4; break;                       // hdr
        case 15: c[12] = static_cast<uint8_t>(v); break;               // orientation
        case 16: c[29] |= static_cast<uint8_t>(v & 15); break;         // ui mode type
        case 17: c[29] |= v == 1 ? 0x20 : 0x10; break;                 // night / notnight
        case 18: put16(14, v); break;                                  // density
        case 19: c[13] = static_cast<uint8_t>(v); break;               // touchscreen
        case 20: c[18] |= static_cast<uint8_t>(v & 3); break;          // keys hidden
        case 21: c[16] = static_cast<uint8_t>(v); break;               // keyboard
        case 22: c[18] |= static_cast<uint8_t>((v & 3) << 2); break;   // navigation hidden
        case 23: c[17] = static_cast<uint8_t>(v); break;               // navigation
        case 24: put16(24, v); break;                                  // sdk version
        default: break;
        }
    }
    return c;
}

}  // namespace

bool toArsc(const std::vector<uint8_t>& pb, std::vector<uint8_t>& arsc, std::string& error) {
    std::vector<Field> top;
    if (!readFields(pb.data(), pb.size(), top)) {
        error = "not a protobuf ResourceTable";
        return false;
    }
    std::vector<std::string> globals;  // value strings
    std::map<std::string, uint32_t> globalIdx;
    const Strings global = [&](const std::string& s) {
        auto it = globalIdx.find(s);
        if (it != globalIdx.end()) return it->second;
        const uint32_t i = static_cast<uint32_t>(globals.size());
        globals.push_back(s);
        globalIdx[s] = i;
        return i;
    };
    std::string packageName;
    uint32_t packageId = 0x7f;
    std::map<uint32_t, ResType> types;
    bool sawPackage = false;
    const auto id = [](const Field& f) {  // PackageId / TypeId / EntryId: { uint32 id = 1 }
        std::vector<Field> v;
        readFields(f.data, f.size, v);
        for (const Field& x : v)
            if (x.number == 1 && x.wire == 0) return static_cast<uint32_t>(x.value);
        return 0u;
    };
    for (const Field& f : top) {
        if (f.number != 2 || f.wire != 2) continue;  // package
        std::vector<Field> pkg;
        if (!readFields(f.data, f.size, pkg)) continue;
        if (sawPackage) break;  // the first package (the app's) is enough
        sawPackage = true;
        for (const Field& pf : pkg) {
            if (pf.number == 1 && pf.wire == 2) packageId = id(pf);
            else if (pf.number == 2 && pf.wire == 2) packageName = str(pf);
            else if (pf.number == 3 && pf.wire == 2) {  // type
                std::vector<Field> ty;
                if (!readFields(pf.data, pf.size, ty)) continue;
                uint32_t typeId = 0;
                std::string typeName;
                std::vector<Field> entries;
                for (const Field& tf : ty) {
                    if (tf.number == 1 && tf.wire == 2) typeId = id(tf);
                    else if (tf.number == 2 && tf.wire == 2) typeName = str(tf);
                    else if (tf.number == 3 && tf.wire == 2) entries.push_back(tf);
                }
                if (typeId == 0 || typeId > 255) continue;
                ResType& type = types[typeId];
                type.name = typeName;
                for (const Field& ef : entries) {
                    std::vector<Field> en;
                    if (!readFields(ef.data, ef.size, en)) continue;
                    uint32_t entryId = 0;
                    bool haveId = false;
                    ResEntry re;
                    for (const Field& x : en) {
                        if (x.number == 1 && x.wire == 2) entryId = id(x), haveId = true;
                        else if (x.number == 2 && x.wire == 2) re.name = str(x);
                        else if (x.number == 6 && x.wire == 2) {  // config_value
                            std::vector<Field> cv;
                            if (!readFields(x.data, x.size, cv)) continue;
                            ConfigBytes config = parseConfig(nullptr, 0);
                            const Field* valueField = nullptr;
                            for (const Field& c : cv) {
                                if (c.number == 1 && c.wire == 2) config = parseConfig(c.data, c.size);
                                if (c.number == 2 && c.wire == 2) valueField = &c;
                            }
                            std::vector<Field> val;
                            if (!valueField || !readFields(valueField->data, valueField->size, val)) continue;
                            for (const Field& vf : val) {
                                ResData data;
                                const bool ok = vf.wire != 2          ? false
                                                : vf.number == 4      ? parseItem(vf, global, data.value)
                                                : vf.number == 5      ? parseCompound(vf, global, data)
                                                                      : false;
                                if (ok) re.values[config] = std::move(data);
                            }
                        }
                    }
                    if (haveId && entryId < 0x10000 && !re.name.empty() && !re.values.empty()) type.entries[entryId] = std::move(re);
                }
            }
        }
    }
    if (!sawPackage) {
        error = "the table has no package";
        return false;
    }
    // Type and key pools, then for every type a spec and one chunk per configuration (the default one first).
    uint32_t maxType = 0;
    for (const auto& t : types) maxType = std::max(maxType, t.first);
    std::vector<std::string> typeNames(maxType), keys;
    std::map<std::string, uint32_t> keyIdx;
    for (const auto& t : types) typeNames[t.first - 1] = t.second.name;
    const auto key = [&](const std::string& k) {
        auto it = keyIdx.find(k);
        if (it != keyIdx.end()) return it->second;
        const uint32_t i = static_cast<uint32_t>(keys.size());
        keys.push_back(k);
        keyIdx[k] = i;
        return i;
    };
    const ConfigBytes defaultConfig = parseConfig(nullptr, 0);
    Writer chunks;
    const auto value = [&](const ResValue& v) { chunks.u16(8), chunks.out.push_back(0), chunks.out.push_back(v.type), chunks.u32(v.data); };
    for (const auto& [typeId, t] : types) {
        if (t.entries.empty()) continue;
        const uint32_t count = t.entries.rbegin()->first + 1;
        // TypeSpec
        chunks.u16(0x0202), chunks.u16(16), chunks.u32(16 + 4 * count), chunks.out.push_back(static_cast<uint8_t>(typeId)), chunks.out.push_back(0), chunks.u16(0), chunks.u32(count);
        for (uint32_t i = 0; i < count; ++i) chunks.u32(0);
        std::set<ConfigBytes> others;
        for (const auto& e : t.entries)
            for (const auto& v : e.second.values)
                if (v.first != defaultConfig) others.insert(v.first);
        std::vector<ConfigBytes> configs{defaultConfig};
        configs.insert(configs.end(), others.begin(), others.end());
        for (const ConfigBytes& config : configs) {
            const size_t at = chunks.out.size();
            chunks.u16(0x0201), chunks.u16(84), chunks.u32(0), chunks.out.push_back(static_cast<uint8_t>(typeId)), chunks.out.push_back(0), chunks.u16(0), chunks.u32(count);
            chunks.u32(84 + 4 * count);  // entriesStart
            chunks.out.insert(chunks.out.end(), config.begin(), config.end());
            const size_t offsetsAt = chunks.out.size();
            for (uint32_t i = 0; i < count; ++i) chunks.u32(0xFFFFFFFFu);
            const size_t entriesAt = chunks.out.size();
            for (const auto& [entryId, e] : t.entries) {
                const auto found = e.values.find(config);
                if (found == e.values.end()) continue;
                const ResData& d = found->second;
                chunks.put32(offsetsAt + 4 * entryId, static_cast<uint32_t>(chunks.out.size() - entriesAt));
                if (!d.complex) {
                    chunks.u16(8), chunks.u16(0), chunks.u32(key(e.name));
                    value(d.value);
                    continue;
                }
                chunks.u16(16), chunks.u16(1), chunks.u32(key(e.name)), chunks.u32(d.parent), chunks.u32(static_cast<uint32_t>(d.bag.size()));
                for (const auto& [name, v] : d.bag) {
                    chunks.u32(name);
                    value(v);
                }
            }
            chunks.put32(at + 4, static_cast<uint32_t>(chunks.out.size() - at));
        }
    }
    const std::vector<uint8_t> globalPool = makePool(globals), typePool = makePool(typeNames), keyPool = makePool(keys);
    Writer out;
    out.u16(0x0002), out.u16(12), out.u32(0), out.u32(1);
    out.out.insert(out.out.end(), globalPool.begin(), globalPool.end());
    const size_t pkgAt = out.out.size();
    out.u16(0x0200), out.u16(288), out.u32(0), out.u32(packageId);
    std::vector<uint16_t> name16;
    for (char c : packageName.substr(0, 127)) name16.push_back(static_cast<uint8_t>(c));
    for (size_t i = 0; i < 128; ++i) out.u16(i < name16.size() ? name16[i] : 0);
    out.u32(288), out.u32(0), out.u32(static_cast<uint32_t>(288 + typePool.size())), out.u32(0), out.u32(0);
    out.out.insert(out.out.end(), typePool.begin(), typePool.end());
    out.out.insert(out.out.end(), keyPool.begin(), keyPool.end());
    out.out.insert(out.out.end(), chunks.out.begin(), chunks.out.end());
    out.put32(pkgAt + 4, static_cast<uint32_t>(out.out.size() - pkgAt));
    out.put32(4, static_cast<uint32_t>(out.out.size()));
    arsc = std::move(out.out);
    return true;
}

}  // namespace protoxml
