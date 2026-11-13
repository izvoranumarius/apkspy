#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

// Minimal, bounds-checked DER walker (M4). Just enough to walk X.509
// certificates found in PKCS#7 blobs (v1/JAR signing) and in the APK signing
// block (v2/v3): read TLV nodes, skip children, compare OIDs and pull the
// Common Name out of a Name. No crypto, no allocation, no recursion.
namespace der {

// A decoded TLV: `content`/`len` describe the value bytes, `total` the whole
// encoding (header included) - fingerprints hash the whole encoding.
struct Node {
    const uint8_t* content = nullptr;
    size_t len = 0;
    size_t total = 0;
    uint8_t tag = 0;

    bool isSequence() const { return tag == 0x30; }
    bool isSet() const { return tag == 0x31; }
    bool isInteger() const { return tag == 0x02; }
    bool isOid() const { return tag == 0x06; }
    bool isContext(uint8_t n) const { return (tag & 0xA0) == 0xA0 && (tag & 0x1F) == n; }
};

// Reads the next TLV at `pos` (advanced past it). Returns false on truncation
// or on lengths that exceed 4 bytes (not expected in certificates).
inline bool read(const uint8_t* data, size_t size, size_t& pos, Node& out) {
    if (!data || pos + 2 > size) return false;
    const uint8_t tag = data[pos++];
    uint8_t first = data[pos++];
    size_t len = 0;
    if (first & 0x80) {
        const int n = first & 0x7F;
        if (n == 0 || n > 4 || pos + static_cast<size_t>(n) > size) return false;
        for (int i = 0; i < n; ++i) len = (len << 8) | data[pos++];
    } else {
        len = first;
    }
    if (pos + len > size) return false;
    const size_t header = len < 128 ? 2 : 2 + static_cast<size_t>(first & 0x7F);
    out.content = data + pos;
    out.len = len;
    out.total = header + len;
    out.tag = tag;
    pos += len;
    return true;
}

// Iterates the children of a constructed node (SEQUENCE/SET/context).
struct Children {
    const uint8_t* data = nullptr;
    size_t size = 0;

    bool next(size_t& pos, Node& out) const { return read(data, size, pos, out); }
};

inline Children of(const Node& n) { return {n.content, n.len}; }

inline bool oidEquals(const Node& n, const uint8_t* oid, size_t len) {
    return n.isOid() && n.len == len && std::memcmp(n.content, oid, len) == 0;
}

// OID 2.5.4.3 (CommonName), DER encoded value.
inline const uint8_t kOidCommonName[] = {0x55, 0x04, 0x03};

// First CommonName inside an X.509 Name (SEQUENCE OF SET OF SEQUENCE).
// PrintableString/UTF8String/IA5String values are returned as-is.
inline std::string commonName(const Node& name) {
    size_t rdnPos = 0;
    Node rdn;
    Children rdns = of(name);
    while (rdns.next(rdnPos, rdn)) {
        size_t atvPos = 0;
        Node atv;
        Children atvs = of(rdn);
        while (atvs.next(atvPos, atv)) {
            Node oid, value;
            size_t innerPos = 0;
            Children inner = of(atv);
            if (!inner.next(innerPos, oid)) continue;
            if (!inner.next(innerPos, value)) continue;
            if (oidEquals(oid, kOidCommonName, sizeof kOidCommonName))
                return std::string(reinterpret_cast<const char*>(value.content), value.len);
        }
    }
    return {};
}

}  // namespace der
