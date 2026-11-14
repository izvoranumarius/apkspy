#include "analysis/DexFile.hpp"
#include <algorithm>
#include <cstring>

namespace leb {

bool readUleb(const uint8_t* data, size_t size, size_t& pos, uint32_t& out) {
    uint32_t result = 0;
    for (int i = 0; i < 5; ++i) {
        if (pos >= size) return false;
        const uint8_t b = data[pos++];
        result |= static_cast<uint32_t>(b & 0x7F) << (7 * i);
        if (!(b & 0x80)) {
            out = result;
            return true;
        }
    }
    return false;  // more than 5 bytes: malformed
}

bool readSleb(const uint8_t* data, size_t size, size_t& pos, int32_t& out) {
    uint32_t result = 0;
    int shift = 0;
    uint8_t b = 0;
    for (int i = 0; i < 5; ++i) {
        if (pos >= size) return false;
        b = data[pos++];
        result |= static_cast<uint32_t>(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            if (shift < 32 && (b & 0x40)) result |= ~0u << shift;  // sign extend
            out = static_cast<int32_t>(result);
            return true;
        }
    }
    return false;
}

}  // namespace leb

namespace {

// Reads UTF-16 code units from MUTF-8 or standard UTF-8 (a 4-byte sequence
// yields a surrogate pair over two calls; C0 80 and a raw 0 both give 0).
class Utf16Reader {
public:
    explicit Utf16Reader(std::string_view s) : s_(s) {}
    bool next(uint32_t& unit) {
        if (pendingLow_) {
            unit = pendingLow_;
            pendingLow_ = 0;
            return true;
        }
        if (i_ >= s_.size()) return false;
        const auto byte = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(s_[i_ + k])); };
        const uint32_t c = byte(0);
        const size_t left = s_.size() - i_;
        if ((c & 0xE0) == 0xC0 && left >= 2) {
            unit = ((c & 0x1F) << 6) | (byte(1) & 0x3F);
            i_ += 2;
        } else if ((c & 0xF0) == 0xE0 && left >= 3) {
            unit = ((c & 0x0F) << 12) | ((byte(1) & 0x3F) << 6) | (byte(2) & 0x3F);
            i_ += 3;
        } else if ((c & 0xF8) == 0xF0 && left >= 4) {
            const uint32_t cp = (((c & 0x07) << 18) | ((byte(1) & 0x3F) << 12) | ((byte(2) & 0x3F) << 6) | (byte(3) & 0x3F)) - 0x10000;
            unit = 0xD800 + (cp >> 10);
            pendingLow_ = 0xDC00 + (cp & 0x3FF);
            i_ += 4;
        } else {
            unit = c;
            i_ += 1;
        }
        return true;
    }

private:
    std::string_view s_;
    size_t i_ = 0;
    uint32_t pendingLow_ = 0;
};

// string_ids are sorted by UTF-16 code units, which byte order does not match
// for C0 80 (encoded NUL) or for 4-byte UTF-8 queries.
int compareUtf16(std::string_view a, std::string_view b) {
    Utf16Reader ra(a), rb(b);
    for (;;) {
        uint32_t x = 0, y = 0;
        const bool hx = ra.next(x), hy = rb.next(y);
        if (!hx || !hy) return hx ? 1 : hy ? -1 : 0;
        if (x != y) return x < y ? -1 : 1;
    }
}

}  // namespace

namespace {

constexpr size_t kHeaderSize = 0x70;
constexpr uint32_t kEndianConstant = 0x12345678;

uint32_t rd32(const uint8_t* p) { return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24; }
uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | p[1] << 8); }

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

const char* primitiveName(char c) {
    switch (c) {
    case 'V': return "void";
    case 'Z': return "boolean";
    case 'B': return "byte";
    case 'S': return "short";
    case 'C': return "char";
    case 'I': return "int";
    case 'J': return "long";
    case 'F': return "float";
    case 'D': return "double";
    default: return nullptr;
    }
}

}  // namespace

std::shared_ptr<DexFile> DexFile::parse(std::shared_ptr<const std::vector<uint8_t>> bytes, std::string name,
                                        std::string& error) {
    if (!bytes || bytes->size() < kHeaderSize) {
        error = "file too small for a DEX header";
        return nullptr;
    }
    const uint8_t* d = bytes->data();
    if (std::memcmp(d, "dex\n", 4) != 0 || d[7] != 0 || d[4] < '0' || d[4] > '9' || d[5] < '0' ||
        d[5] > '9' || d[6] < '0' || d[6] > '9') {
        error = "bad DEX magic";
        return nullptr;
    }
    if (rd32(d + 0x28) != kEndianConstant) {
        error = "unsupported DEX endianness";
        return nullptr;
    }
    std::shared_ptr<DexFile> dex(new DexFile());
    dex->data_ = std::move(bytes);
    dex->name_ = std::move(name);
    dex->version_ = static_cast<uint32_t>((d[4] - '0') * 100 + (d[5] - '0') * 10 + (d[6] - '0'));
    dex->stringIdsSize_ = rd32(d + 0x38);
    dex->stringIdsOff_ = rd32(d + 0x3C);
    dex->typeIdsSize_ = rd32(d + 0x40);
    dex->typeIdsOff_ = rd32(d + 0x44);
    dex->protoIdsSize_ = rd32(d + 0x48);
    dex->protoIdsOff_ = rd32(d + 0x4C);
    dex->fieldIdsSize_ = rd32(d + 0x50);
    dex->fieldIdsOff_ = rd32(d + 0x54);
    dex->methodIdsSize_ = rd32(d + 0x58);
    dex->methodIdsOff_ = rd32(d + 0x5C);
    const uint32_t classDefsSize = rd32(d + 0x60);
    const uint32_t classDefsOff = rd32(d + 0x64);

    // Every id table must lie inside the file; a table that does not is
    // treated as empty (with an error) rather than read out of bounds.
    struct Table {
        uint32_t* size;
        uint32_t off;
        size_t entry;
        const char* what;
    };
    Table tables[] = {{&dex->stringIdsSize_, dex->stringIdsOff_, 4, "string_ids"},
                      {&dex->typeIdsSize_, dex->typeIdsOff_, 4, "type_ids"},
                      {&dex->protoIdsSize_, dex->protoIdsOff_, 12, "proto_ids"},
                      {&dex->fieldIdsSize_, dex->fieldIdsOff_, 8, "field_ids"},
                      {&dex->methodIdsSize_, dex->methodIdsOff_, 8, "method_ids"}};
    for (Table& t : tables) {
        if (*t.size && !dex->inBounds(t.off, static_cast<size_t>(*t.size) * t.entry)) {
            error = std::string(t.what) + " table out of bounds";
            return nullptr;
        }
    }
    // type ids are 32-bit in the table but referenced through u16 fields.
    if (classDefsSize && !dex->inBounds(classDefsOff, static_cast<size_t>(classDefsSize) * 32)) {
        error = "class_defs table out of bounds";
        return nullptr;
    }
    dex->classDefs_.reserve(classDefsSize);
    for (uint32_t i = 0; i < classDefsSize; ++i) {
        const uint8_t* p = d + classDefsOff + static_cast<size_t>(i) * 32;
        ClassDef c;
        c.classIdx = rd32(p);
        c.accessFlags = rd32(p + 4);
        c.superclassIdx = rd32(p + 8);
        c.interfacesOff = rd32(p + 12);
        c.sourceFileIdx = rd32(p + 16);
        c.classDataOff = rd32(p + 24);
        if (c.classIdx >= dex->typeIdsSize_) continue;  // skip junk entries
        dex->classDefs_.push_back(c);
    }
    return dex;
}

bool DexFile::readU32(size_t off, uint32_t& v) const {
    if (!inBounds(off, 4)) return false;
    v = rd32(data_->data() + off);
    return true;
}

bool DexFile::readU16(size_t off, uint16_t& v) const {
    if (!inBounds(off, 2)) return false;
    v = rd16(data_->data() + off);
    return true;
}

std::string_view DexFile::stringView(uint32_t idx) const {
    if (idx >= stringIdsSize_) return {};
    uint32_t off = 0;
    if (!readU32(static_cast<size_t>(stringIdsOff_) + static_cast<size_t>(idx) * 4, off)) return {};
    const uint8_t* d = data_->data();
    const size_t size = data_->size();
    size_t pos = off;
    uint32_t utf16Len = 0;
    if (!leb::readUleb(d, size, pos, utf16Len)) return {};
    size_t end = pos;
    while (end < size && d[end] != 0) ++end;
    if (end >= size) return {};  // unterminated: refuse
    return std::string_view(reinterpret_cast<const char*>(d) + pos, end - pos);
}

std::string DexFile::string(uint32_t idx) const {
    const std::string_view raw = stringView(idx);
    std::string out;
    out.reserve(raw.size());
    const auto* s = reinterpret_cast<const unsigned char*>(raw.data());
    const size_t n = raw.size();
    for (size_t i = 0; i < n;) {
        const unsigned char c = s[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < n) {
            const uint32_t cp = ((c & 0x1Fu) << 6) | (s[i + 1] & 0x3Fu);
            appendUtf8(out, cp);  // C0 80 (MUTF-8 NUL) becomes a real 0
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < n) {
            uint32_t cp = ((c & 0x0Fu) << 12) | ((s[i + 1] & 0x3Fu) << 6) | (s[i + 2] & 0x3Fu);
            i += 3;
            // Surrogate pair encoded as two 3-byte sequences (CESU-8).
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 2 < n && (s[i] & 0xF0) == 0xE0) {
                const uint32_t lo = ((s[i] & 0x0Fu) << 12) | ((s[i + 1] & 0x3Fu) << 6) | (s[i + 2] & 0x3Fu);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    i += 3;
                }
            }
            if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;  // lone surrogate
            appendUtf8(out, cp);
        } else {
            appendUtf8(out, 0xFFFD);
            ++i;
        }
    }
    return out;
}

std::string_view DexFile::typeDescriptor(uint32_t typeIdx) const {
    if (typeIdx >= typeIdsSize_) return {};
    uint32_t strIdx = 0;
    if (!readU32(static_cast<size_t>(typeIdsOff_) + static_cast<size_t>(typeIdx) * 4, strIdx)) return {};
    return stringView(strIdx);
}

uint32_t DexFile::fieldClass(uint32_t fieldIdx) const {
    uint16_t v = 0;
    if (fieldIdx >= fieldIdsSize_ || !readU16(static_cast<size_t>(fieldIdsOff_) + static_cast<size_t>(fieldIdx) * 8, v)) return kNoIndex;
    return v;
}

uint32_t DexFile::fieldType(uint32_t fieldIdx) const {
    uint16_t v = 0;
    if (fieldIdx >= fieldIdsSize_ || !readU16(static_cast<size_t>(fieldIdsOff_) + static_cast<size_t>(fieldIdx) * 8 + 2, v)) return kNoIndex;
    return v;
}

std::string_view DexFile::fieldName(uint32_t fieldIdx) const {
    uint32_t v = 0;
    if (fieldIdx >= fieldIdsSize_ || !readU32(static_cast<size_t>(fieldIdsOff_) + static_cast<size_t>(fieldIdx) * 8 + 4, v)) return {};
    return stringView(v);
}

uint32_t DexFile::methodClass(uint32_t methodIdx) const {
    uint16_t v = 0;
    if (methodIdx >= methodIdsSize_ || !readU16(static_cast<size_t>(methodIdsOff_) + static_cast<size_t>(methodIdx) * 8, v)) return kNoIndex;
    return v;
}

uint32_t DexFile::methodProto(uint32_t methodIdx) const {
    uint16_t v = 0;
    if (methodIdx >= methodIdsSize_ || !readU16(static_cast<size_t>(methodIdsOff_) + static_cast<size_t>(methodIdx) * 8 + 2, v))
        return kNoIndex;
    return v;
}

std::string_view DexFile::methodName(uint32_t methodIdx) const {
    uint32_t v = 0;
    if (methodIdx >= methodIdsSize_ || !readU32(static_cast<size_t>(methodIdsOff_) + static_cast<size_t>(methodIdx) * 8 + 4, v)) return {};
    return stringView(v);
}

uint32_t DexFile::protoReturnType(uint32_t protoIdx) const {
    uint32_t v = 0;
    if (protoIdx >= protoIdsSize_ || !readU32(static_cast<size_t>(protoIdsOff_) + static_cast<size_t>(protoIdx) * 12 + 4, v)) return kNoIndex;
    return v;
}

std::vector<uint32_t> DexFile::protoParameters(uint32_t protoIdx) const {
    std::vector<uint32_t> out;
    uint32_t off = 0, count = 0;
    if (protoIdx >= protoIdsSize_ || !readU32(static_cast<size_t>(protoIdsOff_) + static_cast<size_t>(protoIdx) * 12 + 8, off) || off == 0)
        return out;
    if (!readU32(off, count) || count > 65535 || !inBounds(static_cast<size_t>(off) + 4, static_cast<size_t>(count) * 2)) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) out.push_back(rd16(data_->data() + off + 4 + static_cast<size_t>(i) * 2));
    return out;
}

std::string DexFile::protoDescriptor(uint32_t protoIdx) const {
    std::string out = "(";
    for (uint32_t t : protoParameters(protoIdx)) out += typeDescriptor(t);
    out += ')';
    out += typeDescriptor(protoReturnType(protoIdx));
    return out;
}

std::string DexFile::methodSignature(uint32_t methodIdx) const {
    std::string out(typeDescriptor(methodClass(methodIdx)));
    out += "->";
    out += methodName(methodIdx);
    out += protoDescriptor(methodProto(methodIdx));
    return out;
}

std::string DexFile::fieldSignature(uint32_t fieldIdx) const {
    std::string out(typeDescriptor(fieldClass(fieldIdx)));
    out += "->";
    out += fieldName(fieldIdx);
    out += ':';
    out += typeDescriptor(fieldType(fieldIdx));
    return out;
}

std::vector<uint32_t> DexFile::interfaces(const ClassDef& def) const {
    std::vector<uint32_t> out;
    uint32_t count = 0;
    if (def.interfacesOff == 0 || !readU32(def.interfacesOff, count) || count > 65535 ||
        !inBounds(static_cast<size_t>(def.interfacesOff) + 4, static_cast<size_t>(count) * 2))
        return out;
    for (uint32_t i = 0; i < count; ++i) out.push_back(rd16(data_->data() + def.interfacesOff + 4 + static_cast<size_t>(i) * 2));
    return out;
}

bool DexFile::classData(const ClassDef& def, ClassData& out) const {
    out.fields.clear();
    out.methods.clear();
    if (def.classDataOff == 0) return true;  // marker interface / no members
    const uint8_t* d = data_->data();
    const size_t size = data_->size();
    size_t pos = def.classDataOff;
    if (pos >= size) return false;
    uint32_t staticFields = 0, instanceFields = 0, directMethods = 0, virtualMethods = 0;
    if (!leb::readUleb(d, size, pos, staticFields) || !leb::readUleb(d, size, pos, instanceFields) ||
        !leb::readUleb(d, size, pos, directMethods) || !leb::readUleb(d, size, pos, virtualMethods))
        return false;
    // Each encoded entry takes >= 2 (field) / 3 (method) bytes: counts that
    // cannot fit the rest of the file are bogus - refuse before reserving.
    const size_t remaining = size - pos;
    if ((staticFields + static_cast<uint64_t>(instanceFields)) * 2 +
            (directMethods + static_cast<uint64_t>(virtualMethods)) * 3 >
        remaining)
        return false;
    out.fields.reserve(static_cast<size_t>(staticFields) + instanceFields);
    out.methods.reserve(static_cast<size_t>(directMethods) + virtualMethods);
    const auto readFields = [&](uint32_t count, bool isStatic) {
        uint32_t idx = 0;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t diff = 0, flags = 0;
            if (!leb::readUleb(d, size, pos, diff) || !leb::readUleb(d, size, pos, flags)) return false;
            idx += diff;
            out.fields.push_back({idx, flags, isStatic});
        }
        return true;
    };
    const auto readMethods = [&](uint32_t count, bool direct) {
        uint32_t idx = 0;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t diff = 0, flags = 0, code = 0;
            if (!leb::readUleb(d, size, pos, diff) || !leb::readUleb(d, size, pos, flags) ||
                !leb::readUleb(d, size, pos, code))
                return false;
            idx += diff;
            out.methods.push_back({idx, flags, code, direct});
        }
        return true;
    };
    return readFields(staticFields, true) && readFields(instanceFields, false) &&
           readMethods(directMethods, true) && readMethods(virtualMethods, false);
}

bool DexFile::codeItem(uint32_t codeOff, CodeItem& out) const {
    if (codeOff == 0 || !inBounds(codeOff, 16)) return false;
    const uint8_t* p = data_->data() + codeOff;
    out.registers = rd16(p);
    out.ins = rd16(p + 2);
    out.outs = rd16(p + 4);
    out.tries = rd16(p + 6);
    out.debugInfoOff = rd32(p + 8);
    out.insnsSize = rd32(p + 12);
    out.offset = codeOff;
    if (!inBounds(static_cast<size_t>(codeOff) + 16, static_cast<size_t>(out.insnsSize) * 2)) return false;
    out.insns = p + 16;
    return true;
}

uint32_t DexFile::findString(std::string_view s) const {
    uint32_t lo = 0, hi = stringIdsSize_;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        const int cmp = compareUtf16(stringView(mid), s);
        if (cmp == 0) return mid;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return kNoIndex;
}

uint32_t DexFile::findType(std::string_view descriptor) const {
    const uint32_t strIdx = findString(descriptor);
    if (strIdx == kNoIndex) return kNoIndex;
    uint32_t lo = 0, hi = typeIdsSize_;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        uint32_t v = 0;
        if (!readU32(static_cast<size_t>(typeIdsOff_) + static_cast<size_t>(mid) * 4, v)) return kNoIndex;
        if (v == strIdx) return mid;
        if (v < strIdx) lo = mid + 1;
        else hi = mid;
    }
    return kNoIndex;
}

uint32_t DexFile::findClassDef(std::string_view descriptor) const {
    const uint32_t type = findType(descriptor);
    if (type == kNoIndex) return kNoIndex;
    for (size_t i = 0; i < classDefs_.size(); ++i)
        if (classDefs_[i].classIdx == type) return static_cast<uint32_t>(i);
    return kNoIndex;
}

std::vector<uint32_t> DexFile::findMethods(std::string_view classDescriptor, std::string_view name,
                                           std::string_view protoDesc) const {
    std::vector<uint32_t> out;
    const uint32_t type = findType(classDescriptor);
    if (type == kNoIndex) return out;
    // method_ids are sorted by defining class first: binary search the range.
    uint32_t lo = 0, hi = methodIdsSize_;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (methodClass(mid) < type) lo = mid + 1;
        else hi = mid;
    }
    for (uint32_t m = lo; m < methodIdsSize_ && methodClass(m) == type; ++m) {
        if (!name.empty() && methodName(m) != name) continue;
        if (!protoDesc.empty() && protoDescriptor(methodProto(m)) != protoDesc) continue;
        out.push_back(m);
    }
    return out;
}

std::vector<uint32_t> DexFile::findFields(std::string_view classDescriptor, std::string_view name) const {
    std::vector<uint32_t> out;
    const uint32_t type = findType(classDescriptor);
    if (type == kNoIndex) return out;
    uint32_t lo = 0, hi = fieldIdsSize_;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (fieldClass(mid) < type) lo = mid + 1;
        else hi = mid;
    }
    for (uint32_t f = lo; f < fieldIdsSize_ && fieldClass(f) == type; ++f)
        if (name.empty() || fieldName(f) == name) out.push_back(f);
    return out;
}

int DexFile::lineForPc(const CodeItem& code, uint32_t pc) const {
    if (code.debugInfoOff == 0) return -1;
    const uint8_t* d = data_->data();
    const size_t size = data_->size();
    size_t pos = code.debugInfoOff;
    uint32_t lineStart = 0, paramCount = 0, tmp = 0;
    if (!leb::readUleb(d, size, pos, lineStart) || !leb::readUleb(d, size, pos, paramCount)) return -1;
    if (paramCount > 65535) return -1;
    for (uint32_t i = 0; i < paramCount; ++i)
        if (!leb::readUleb(d, size, pos, tmp)) return -1;
    int64_t line = lineStart;
    uint32_t address = 0;
    int best = -1;
    for (int guard = 0; guard < 1000000 && pos < size; ++guard) {
        const uint8_t op = d[pos++];
        switch (op) {
        case 0x00: return best;  // DBG_END_SEQUENCE
        case 0x01: {             // DBG_ADVANCE_PC
            uint32_t diff = 0;
            if (!leb::readUleb(d, size, pos, diff)) return best;
            address += diff;
            break;
        }
        case 0x02: {  // DBG_ADVANCE_LINE
            int32_t diff = 0;
            if (!leb::readSleb(d, size, pos, diff)) return best;
            line += diff;
            break;
        }
        case 0x03:  // DBG_START_LOCAL: reg, name, type
            if (!leb::readUleb(d, size, pos, tmp) || !leb::readUleb(d, size, pos, tmp) ||
                !leb::readUleb(d, size, pos, tmp))
                return best;
            break;
        case 0x04:  // DBG_START_LOCAL_EXTENDED: reg, name, type, sig
            if (!leb::readUleb(d, size, pos, tmp) || !leb::readUleb(d, size, pos, tmp) ||
                !leb::readUleb(d, size, pos, tmp) || !leb::readUleb(d, size, pos, tmp))
                return best;
            break;
        case 0x05:  // DBG_END_LOCAL
        case 0x06:  // DBG_RESTART_LOCAL
        case 0x09:  // DBG_SET_FILE
            if (!leb::readUleb(d, size, pos, tmp)) return best;
            break;
        case 0x07:  // DBG_SET_PROLOGUE_END
        case 0x08:  // DBG_SET_EPILOGUE_BEGIN
            break;
        default: {  // special opcode: advance both and emit a position
            const int adjusted = op - 0x0A;
            line += -4 + (adjusted % 15);
            address += static_cast<uint32_t>(adjusted / 15);
            if (address > pc) return best;
            best = static_cast<int>(line);
            break;
        }
        }
    }
    return best;
}

std::string DexFile::descriptorToJava(std::string_view desc) {
    int dims = 0;
    while (!desc.empty() && desc.front() == '[') {
        ++dims;
        desc.remove_prefix(1);
    }
    std::string base;
    if (desc.size() == 1 && primitiveName(desc[0])) {
        base = primitiveName(desc[0]);
    } else if (desc.size() >= 2 && desc.front() == 'L' && desc.back() == ';') {
        base.assign(desc.substr(1, desc.size() - 2));
        std::replace(base.begin(), base.end(), '/', '.');
    } else {
        base.assign(desc);
    }
    for (int i = 0; i < dims; ++i) base += "[]";
    return base;
}

std::string DexFile::javaToDescriptor(std::string_view javaName) {
    if (!javaName.empty() && (javaName.front() == 'L' || javaName.front() == '[') && javaName.back() == ';')
        return std::string(javaName);  // already a descriptor
    std::string s = "L";
    s.append(javaName);
    std::replace(s.begin(), s.end(), '.', '/');
    s += ';';
    return s;
}

std::string DexFile::accessFlagsToString(uint32_t f, bool forMethod) {
    std::string out;
    const auto add = [&](uint32_t bit, const char* word) {
        if (f & bit) {
            if (!out.empty()) out += ' ';
            out += word;
        }
    };
    add(0x1, "public");
    add(0x2, "private");
    add(0x4, "protected");
    add(0x8, "static");
    add(0x10, "final");
    if (forMethod) {
        add(0x20, "synchronized");
        add(0x40, "bridge");
        add(0x80, "varargs");
        add(0x100, "native");
    } else {
        add(0x40, "volatile");
        add(0x80, "transient");
    }
    add(0x200, "interface");
    add(0x400, "abstract");
    add(0x1000, "synthetic");
    add(0x2000, "annotation");
    add(0x4000, "enum");
    if (forMethod) add(0x10000, "constructor");
    return out;
}
