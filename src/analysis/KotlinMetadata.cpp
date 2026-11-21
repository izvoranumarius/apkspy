#include "analysis/KotlinMetadata.hpp"
#include "analysis/DexFile.hpp"

namespace kotlinmeta {
namespace {

// ---- DEX encoded values (dex-format: encoded_value / encoded_annotation) ----

struct Value {
    int type = -1;  // VALUE_* (0x00 byte ... 0x1f boolean)
    uint64_t bits = 0;
    std::vector<Value> array;
};

struct Element {
    std::string name;
    Value value;
};

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : d_(data), n_(size) {}
    bool u32(size_t at, uint32_t& v) const {
        if (at > n_ || n_ - at < 4) return false;
        v = static_cast<uint32_t>(d_[at]) | static_cast<uint32_t>(d_[at + 1]) << 8 | static_cast<uint32_t>(d_[at + 2]) << 16 |
            static_cast<uint32_t>(d_[at + 3]) << 24;
        return true;
    }
    bool uleb(size_t& pos, uint32_t& v) const { return leb::readUleb(d_, n_, pos, v); }
    bool byte(size_t& pos, uint8_t& v) const {
        if (pos >= n_) return false;
        v = d_[pos++];
        return true;
    }

    // One encoded_value; arrays and nested annotations are read (or skipped) whole.
    bool value(size_t& pos, Value& out, int depth = 0) const {
        uint8_t head;
        if (depth > 16 || !byte(pos, head)) return false;
        out.type = head & 0x1F;
        const unsigned arg = head >> 5;
        switch (out.type) {
            case 0x00: case 0x02: case 0x03: case 0x04: case 0x06:  // byte short char int long
            case 0x10: case 0x11:                                   // float double
            case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:  // method type/handle, string, type, field
            case 0x1a: case 0x1b: {                                 // method, enum
                // arg + 1 little-endian bytes (an index for the reference kinds).
                if (arg > 7) return false;
                for (unsigned b = 0; b <= arg; ++b) {
                    uint8_t v;
                    if (!byte(pos, v)) return false;
                    out.bits |= static_cast<uint64_t>(v) << (8 * b);
                }
                return true;
            }
            case 0x1c: {  // array
                uint32_t count;
                if (!uleb(pos, count) || count > 100000) return false;
                out.array.resize(count);
                for (auto& v : out.array)
                    if (!value(pos, v, depth + 1)) return false;
                return true;
            }
            case 0x1d: {  // nested annotation: skipped
                std::vector<Element> ignored;
                std::string type;
                return annotation(pos, type, ignored, depth + 1);
            }
            case 0x1e: return true;              // null
            case 0x1f: out.bits = arg; return true;  // boolean (in the header)
            default: return false;
        }
    }

    bool annotation(size_t& pos, std::string& typeIdxText, std::vector<Element>& out, int depth = 0) const {
        uint32_t typeIdx, count;
        if (!uleb(pos, typeIdx) || !uleb(pos, count) || count > 10000) return false;
        typeIdxText = std::to_string(typeIdx);
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t nameIdx;
            Element e;
            if (!uleb(pos, nameIdx) || !value(pos, e.value, depth)) return false;
            e.name = std::to_string(nameIdx);
            out.push_back(std::move(e));
        }
        return true;
    }

private:
    const uint8_t* d_;
    size_t n_;
};

int64_t signedOf(const Value& v) {
    // Signed kinds are sign-extended from their stored width; @Metadata ints are small and positive.
    return static_cast<int64_t>(static_cast<int32_t>(v.bits));
}

// UTF-8 -> code points; false on malformed input.
bool codePoints(const std::string& s, std::vector<uint32_t>& out) {
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp;
        size_t n;
        if (c < 0x80) cp = c, n = 1;
        else if ((c & 0xE0) == 0xC0) cp = c & 0x1F, n = 2;
        else if ((c & 0xF0) == 0xE0) cp = c & 0x0F, n = 3;
        else if ((c & 0xF8) == 0xF0) cp = c & 0x07, n = 4;
        else return false;
        if (i + n > s.size()) return false;
        for (size_t k = 1; k < n; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = cp << 6 | (cc & 0x3F);
        }
        out.push_back(cp);
        i += n;
    }
    return true;
}

bool varint(const std::string& b, size_t& pos, uint64_t& v) {
    v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (pos >= b.size()) return false;
        const unsigned char c = static_cast<unsigned char>(b[pos++]);
        v |= static_cast<uint64_t>(c & 0x7F) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

}  // namespace

bool classFlagsFromD1(const std::vector<std::string>& d1, uint32_t& flags) {
    // d1 strings concatenated: '\0' marker, then each character is one byte.
    std::vector<uint32_t> cps;
    for (const auto& s : d1)
        if (!codePoints(s, cps)) return false;
    if (cps.empty() || cps[0] != 0) return false;  // the older 8-to-7-bit encoding: not decoded
    std::string bytes;
    for (size_t i = 1; i < cps.size(); ++i) {
        if (cps[i] > 0xFF) return false;
        bytes += static_cast<char>(cps[i]);
    }
    // A length-delimited JvmProtoBuf.StringTableTypes, then ProtoBuf.Class.
    size_t pos = 0;
    uint64_t len;
    if (!varint(bytes, pos, len) || len > bytes.size() - pos) return false;
    pos += static_cast<size_t>(len);
    flags = 6;  // Class.flags default (public final class)
    while (pos < bytes.size()) {
        uint64_t key;
        if (!varint(bytes, pos, key)) return false;
        const unsigned field = static_cast<unsigned>(key >> 3), wire = static_cast<unsigned>(key & 7);
        if (field == 1 && wire == 0) {
            uint64_t v;
            if (!varint(bytes, pos, v)) return false;
            flags = static_cast<uint32_t>(v);
            return true;
        }
        // Skip any other field.
        uint64_t v;
        if (wire == 0) {
            if (!varint(bytes, pos, v)) return false;
        } else if (wire == 1) {
            pos += 8;
        } else if (wire == 2) {
            if (!varint(bytes, pos, v) || v > bytes.size() - pos) return false;
            pos += static_cast<size_t>(v);
        } else if (wire == 5) {
            pos += 4;
        } else {
            return false;
        }
        if (pos > bytes.size()) return false;
    }
    return true;  // flags absent: the default
}

bool has(const DexFile& dex, const std::string& classDescriptor) {
    const uint32_t idx = dex.findClassDef(classDescriptor);
    return idx != DexFile::kNoIndex && dex.classes()[idx].annotationsOff != 0;
}

bool read(const DexFile& dex, const std::string& classDescriptor, Metadata& out) {
    out = Metadata{};
    const uint32_t idx = dex.findClassDef(classDescriptor);
    if (idx == DexFile::kNoIndex) return false;
    const uint32_t dirOff = dex.classes()[idx].annotationsOff;
    if (dirOff == 0) return false;
    const Reader r(dex.data(), dex.sizeBytes());
    // annotations_directory_item: class_annotations_off (uint), then field /
    // method / parameter lists that are not needed here.
    uint32_t setOff, setSize;
    if (!r.u32(dirOff, setOff) || setOff == 0 || !r.u32(setOff, setSize) || setSize > 10000) return false;
    for (uint32_t i = 0; i < setSize; ++i) {
        // annotation_set_item: annotation_off_item[] -> annotation_item:
        // visibility (ubyte) + encoded_annotation.
        uint32_t itemOff;
        if (!r.u32(setOff + 4 + 4 * static_cast<size_t>(i), itemOff)) return false;
        size_t pos = static_cast<size_t>(itemOff) + 1;
        uint32_t typeIdx, count;
        if (!r.uleb(pos, typeIdx) || !r.uleb(pos, count) || count > 10000) continue;
        if (dex.typeDescriptor(typeIdx) != "Lkotlin/Metadata;") continue;
        std::vector<std::string> d1;
        for (uint32_t k = 0; k < count; ++k) {
            uint32_t nameIdx;
            Value v;
            if (!r.uleb(pos, nameIdx) || !r.value(pos, v)) return false;
            const std::string name = dex.string(nameIdx);
            if (name == "k") {
                const int64_t kind = signedOf(v);
                out.kind = kind >= 1 && kind <= 5 ? static_cast<Kind>(kind) : Kind::Unknown;
            } else if (name == "mv") {
                if (v.array.size() > 0) out.versionMajor = static_cast<int>(signedOf(v.array[0]));
                if (v.array.size() > 1) out.versionMinor = static_cast<int>(signedOf(v.array[1]));
                if (v.array.size() > 2) out.versionPatch = static_cast<int>(signedOf(v.array[2]));
            } else if (name == "d2" || name == "d1") {
                for (const Value& s : v.array) {
                    if (s.type != 0x17) continue;  // strings only
                    std::string text = dex.string(static_cast<uint32_t>(s.bits));
                    (name == "d1" ? d1 : out.names).push_back(std::move(text));
                }
            }
        }
        out.present = true;
        if (out.kind == Kind::Class && classFlagsFromD1(d1, out.classFlags)) {
            // Flags layout (kotlin.metadata Flags): hasAnnotations (bit 0),
            // visibility (1-3), modality (4-5), class kind (6-8), then inner,
            // data, external, expect, value.
            out.flagsKnown = true;
            const uint32_t f = out.classFlags;
            const unsigned kind = (f >> 6) & 7;
            out.classKind = kind <= 6 ? static_cast<ClassKind>(kind) : ClassKind::Class;
            out.isSealed = ((f >> 4) & 3) == 3;
            out.isInner = (f >> 9) & 1;
            out.isData = (f >> 10) & 1;
            out.isValue = (f >> 13) & 1;
        }
        return true;
    }
    return false;
}

std::string Metadata::displayKind() const {
    if (!present) return "class";
    switch (kind) {
        case Kind::File: return "file facade";
        case Kind::SyntheticClass: return "synthetic class";
        case Kind::MultiFileClass: return "multi-file class facade";
        case Kind::MultiFilePart: return "multi-file class part";
        case Kind::Unknown: return "class";
        case Kind::Class: break;
    }
    if (!flagsKnown) return "class";
    switch (classKind) {
        case ClassKind::Interface: return isSealed ? "sealed interface" : "interface";
        case ClassKind::EnumClass: return "enum class";
        case ClassKind::EnumEntry: return "enum entry";
        case ClassKind::AnnotationClass: return "annotation class";
        case ClassKind::Object: return isData ? "data object" : "object";
        case ClassKind::CompanionObject: return "companion object";
        case ClassKind::Class: break;
    }
    if (isData) return "data class";
    if (isValue) return "value class";
    if (isSealed) return "sealed class";
    if (isInner) return "inner class";
    return "class";
}

}  // namespace kotlinmeta
