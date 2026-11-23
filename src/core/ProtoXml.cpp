#include "core/ProtoXml.hpp"
#include <algorithm>
#include <cstring>
#include <map>

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
                            }
                        }
                    }
                }
            }
            e.attrs.push_back(std::move(at));
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

struct ResEntry {
    std::string name;
    uint8_t dataType = 0;
    uint32_t data = 0;
    bool value = false;
};
struct ResType {
    std::string name;
    std::map<uint32_t, ResEntry> entries;
};

}  // namespace

bool toArsc(const std::vector<uint8_t>& pb, std::vector<uint8_t>& arsc, std::string& error) {
    std::vector<Field> top;
    if (!readFields(pb.data(), pb.size(), top)) {
        error = "not a protobuf ResourceTable";
        return false;
    }
    std::vector<std::string> globals;           // value strings
    std::map<std::string, uint32_t> globalIdx;
    const auto global = [&](const std::string& s) {
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
                ResType rt;
                std::vector<Field> entries;
                for (const Field& tf : ty) {
                    if (tf.number == 1 && tf.wire == 2) typeId = id(tf);
                    else if (tf.number == 2 && tf.wire == 2) rt.name = str(tf);
                    else if (tf.number == 3 && tf.wire == 2) entries.push_back(tf);
                }
                if (typeId == 0 || typeId > 255) continue;
                for (const Field& ef : entries) {
                    std::vector<Field> en;
                    if (!readFields(ef.data, ef.size, en)) continue;
                    uint32_t entryId = 0;
                    bool haveId = false;
                    ResEntry re;
                    bool chosenDefault = false;
                    for (const Field& x : en) {
                        if (x.number == 1 && x.wire == 2) entryId = id(x), haveId = true;
                        else if (x.number == 2 && x.wire == 2) re.name = str(x);
                        else if (x.number == 6 && x.wire == 2) {  // config_value
                            std::vector<Field> cv;
                            if (!readFields(x.data, x.size, cv)) continue;
                            bool defaultConfig = true;
                            const Field* valueField = nullptr;
                            for (const Field& c : cv) {
                                if (c.number == 1 && c.wire == 2 && c.size > 0) defaultConfig = false;
                                if (c.number == 2 && c.wire == 2) valueField = &c;
                            }
                            if (!valueField || (re.value && (chosenDefault || !defaultConfig))) continue;
                            std::vector<Field> val;
                            if (!readFields(valueField->data, valueField->size, val)) continue;
                            for (const Field& vf : val) {
                                if (vf.number != 4 || vf.wire != 2) continue;  // item (compound values are skipped)
                                std::vector<Field> item;
                                if (!readFields(vf.data, vf.size, item)) continue;
                                for (const Field& it : item) {
                                    std::vector<Field> inner;
                                    if (it.wire != 2 || !readFields(it.data, it.size, inner)) continue;
                                    if (it.number == 1) {  // ref
                                        for (const Field& r : inner)
                                            if (r.number == 2 && r.wire == 0) re.dataType = 0x01, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                    } else if (it.number == 2 || it.number == 3) {  // str / raw_str
                                        for (const Field& r : inner)
                                            if (r.number == 1 && r.wire == 2) re.dataType = 0x03, re.data = global(str(r)), re.value = true;
                                    } else if (it.number == 4) {  // styled_str: the plain text
                                        for (const Field& r : inner)
                                            if (r.number == 1 && r.wire == 2) re.dataType = 0x03, re.data = global(str(r)), re.value = true;
                                    } else if (it.number == 5) {  // file: its path
                                        for (const Field& r : inner)
                                            if (r.number == 1 && r.wire == 2) re.dataType = 0x03, re.data = global(str(r)), re.value = true;
                                    } else if (it.number == 7) {  // prim
                                        for (const Field& r : inner) {
                                            if (r.number == 6 && r.wire == 0) re.dataType = 0x10, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                            else if (r.number == 7 && r.wire == 0) re.dataType = 0x11, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                            else if (r.number == 8 && r.wire == 0) re.dataType = 0x12, re.data = r.value ? 0xffffffffu : 0u, re.value = true;
                                            else if (r.number == 3 && r.wire == 5) re.dataType = 0x04, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                            else if (r.number == 9 && r.wire == 0) re.dataType = 0x1c, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                            else if (r.number == 10 && r.wire == 0) re.dataType = 0x1d, re.data = static_cast<uint32_t>(r.value), re.value = true;
                                        }
                                    }
                                }
                            }
                            if (re.value) chosenDefault = defaultConfig;
                        }
                    }
                    if (haveId && !re.name.empty()) rt.entries[entryId] = std::move(re);
                }
                ResType& slot = types[typeId];
                slot.name = rt.name;
                for (auto& e : rt.entries) slot.entries[e.first] = std::move(e.second);
            }
        }
    }
    if (!sawPackage) {
        error = "the table has no package";
        return false;
    }
    // Type and key pools, then the type chunks.
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
    Writer chunks;
    for (const auto& [typeId, t] : types) {
        uint32_t maxEntry = 0;
        for (const auto& e : t.entries) maxEntry = std::max(maxEntry, e.first);
        const uint32_t count = maxEntry + 1;
        // TypeSpec
        chunks.u16(0x0202), chunks.u16(16), chunks.u32(16 + 4 * count), chunks.out.push_back(static_cast<uint8_t>(typeId)), chunks.out.push_back(0), chunks.u16(0), chunks.u32(count);
        for (uint32_t i = 0; i < count; ++i) chunks.u32(0);
        // Type (default configuration)
        const size_t at = chunks.out.size();
        chunks.u16(0x0201), chunks.u16(84), chunks.u32(0), chunks.out.push_back(static_cast<uint8_t>(typeId)), chunks.out.push_back(0), chunks.u16(0), chunks.u32(count);
        chunks.u32(84 + 4 * count);  // entriesStart
        chunks.u32(64);              // ResTable_config size, then zeros: the default configuration
        for (int i = 0; i < 60; ++i) chunks.out.push_back(0);
        const size_t offsetsAt = chunks.out.size();
        for (uint32_t i = 0; i < count; ++i) chunks.u32(0xFFFFFFFFu);
        const size_t entriesAt = chunks.out.size();
        for (const auto& [entryId, e] : t.entries) {
            chunks.put32(offsetsAt + 4 * entryId, static_cast<uint32_t>(chunks.out.size() - entriesAt));
            chunks.u16(8), chunks.u16(0), chunks.u32(key(e.name));
            chunks.u16(8), chunks.out.push_back(0), chunks.out.push_back(e.dataType), chunks.u32(e.data);
        }
        chunks.put32(at + 4, static_cast<uint32_t>(chunks.out.size() - at));
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
