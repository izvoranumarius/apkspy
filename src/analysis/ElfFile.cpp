#include "analysis/ElfFile.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace {
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint64_t DT_NULL = 0;
constexpr uint64_t DT_NEEDED = 1;
constexpr uint64_t DT_STRTAB = 5;
constexpr uint64_t DT_STRSZ = 10;
constexpr uint64_t DT_SONAME = 14;
constexpr size_t kMaxSymbols = 2000000;
constexpr size_t kMaxSections = 4096;
}  // namespace

uint16_t ElfFile::u16(uint64_t off) const {
    if (!inBounds(off, 2)) return 0;
    const uint8_t* p = data_->data() + off;
    return little_ ? static_cast<uint16_t>(p[0] | p[1] << 8) : static_cast<uint16_t>(p[1] | p[0] << 8);
}

uint32_t ElfFile::u32(uint64_t off) const {
    if (!inBounds(off, 4)) return 0;
    const uint8_t* p = data_->data() + off;
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[little_ ? i : 3 - i]) << (8 * i);
    return v;
}

uint64_t ElfFile::u64(uint64_t off) const {
    if (!inBounds(off, 8)) return 0;
    const uint8_t* p = data_->data() + off;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[little_ ? i : 7 - i]) << (8 * i);
    return v;
}

std::string ElfFile::cstr(uint64_t off, uint64_t limitEnd) const {
    std::string out;
    limitEnd = std::min<uint64_t>(limitEnd, data_->size());
    for (uint64_t i = off; i < limitEnd && (*data_)[i] != 0 && out.size() < 4096; ++i) out.push_back(static_cast<char>((*data_)[i]));
    return out;
}

std::shared_ptr<ElfFile> ElfFile::parse(std::shared_ptr<const std::vector<uint8_t>> bytes, std::string name,
                                        std::string& error) {
    if (!bytes || bytes->size() < 52 || std::memcmp(bytes->data(), "\x7f" "ELF", 4) != 0) {
        error = "not an ELF file";
        return nullptr;
    }
    std::shared_ptr<ElfFile> e(new ElfFile());
    e->data_ = std::move(bytes);
    e->name_ = std::move(name);
    const uint8_t* d = e->data_->data();
    if (d[4] != 1 && d[4] != 2) {
        error = "bad ELF class";
        return nullptr;
    }
    e->is64_ = d[4] == 2;
    e->little_ = d[5] != 2;
    if (e->is64_ && e->data_->size() < 64) {
        error = "truncated ELF header";
        return nullptr;
    }
    e->type_ = e->u16(16);
    e->machine_ = e->u16(18);
    e->entry_ = e->word(24);
    const uint64_t phoff = e->is64_ ? e->u64(32) : e->u32(28);
    const uint64_t shoff = e->is64_ ? e->u64(40) : e->u32(32);
    const uint16_t phentsize = e->u16(e->is64_ ? 54 : 42);
    const uint16_t phnum = e->u16(e->is64_ ? 56 : 44);
    const uint16_t shentsize = e->u16(e->is64_ ? 58 : 46);
    const uint16_t shnum = e->u16(e->is64_ ? 60 : 48);
    const uint16_t shstrndx = e->u16(e->is64_ ? 62 : 50);

    // Program headers.
    if (phnum && phentsize >= (e->is64_ ? 56 : 32) && e->inBounds(phoff, static_cast<uint64_t>(phnum) * phentsize)) {
        for (uint16_t i = 0; i < phnum; ++i) {
            const uint64_t p = phoff + static_cast<uint64_t>(i) * phentsize;
            Segment s;
            s.type = e->u32(p);
            if (e->is64_) {
                s.flags = e->u32(p + 4);
                s.offset = e->u64(p + 8);
                s.vaddr = e->u64(p + 16);
                s.filesz = e->u64(p + 32);
                s.memsz = e->u64(p + 40);
            } else {
                s.offset = e->u32(p + 4);
                s.vaddr = e->u32(p + 8);
                s.filesz = e->u32(p + 16);
                s.memsz = e->u32(p + 20);
                s.flags = e->u32(p + 24);
            }
            e->segments_.push_back(s);
        }
    } else if (phnum) {
        e->warnings_.push_back("program header table out of bounds");
    }

    // Section headers (optional: stripped/packed libraries may lack them).
    if (shnum && shnum < kMaxSections && shentsize >= (e->is64_ ? 64 : 40) &&
        e->inBounds(shoff, static_cast<uint64_t>(shnum) * shentsize)) {
        std::vector<uint32_t> nameOffs;
        for (uint16_t i = 0; i < shnum; ++i) {
            const uint64_t p = shoff + static_cast<uint64_t>(i) * shentsize;
            Section s;
            nameOffs.push_back(e->u32(p));
            s.type = e->u32(p + 4);
            if (e->is64_) {
                s.flags = e->u64(p + 8);
                s.addr = e->u64(p + 16);
                s.offset = e->u64(p + 24);
                s.size = e->u64(p + 32);
                s.link = e->u32(p + 40);
                s.entsize = e->u64(p + 56);
            } else {
                s.flags = e->u32(p + 8);
                s.addr = e->u32(p + 12);
                s.offset = e->u32(p + 16);
                s.size = e->u32(p + 20);
                s.link = e->u32(p + 24);
                s.entsize = e->u32(p + 36);
            }
            e->sections_.push_back(s);
        }
        if (shstrndx < e->sections_.size()) {
            const Section& strs = e->sections_[shstrndx];
            for (size_t i = 0; i < e->sections_.size(); ++i)
                if (nameOffs[i] < strs.size)
                    e->sections_[i].name = e->cstr(strs.offset + nameOffs[i], strs.offset + strs.size);
        }
        for (const Section& s : e->sections_) {
            if (s.type == SHT_DYNSYM) e->readSymbols(s, true);
            else if (s.type == SHT_SYMTAB) e->readSymbols(s, false);
        }
        for (const Section& s : e->sections_)
            if (s.type == SHT_RELA || s.type == SHT_REL) e->readRelocations(s);
    } else if (shnum) {
        e->warnings_.push_back("section header table out of bounds or too large");
    }
    e->readDynamic();
    return e;
}

void ElfFile::readSymbols(const Section& symtab, bool dynamic) {
    const uint64_t entsize = is64_ ? 24 : 16;
    if (symtab.type == SHT_NOBITS || !inBounds(symtab.offset, symtab.size) || symtab.link >= sections_.size()) {
        warnings_.push_back("symbol table out of bounds");
        return;
    }
    const Section& strtab = sections_[symtab.link];
    if (!inBounds(strtab.offset, strtab.size)) {
        warnings_.push_back("string table out of bounds");
        return;
    }
    const uint64_t count = symtab.size / entsize;
    for (uint64_t i = 1; i < count && symbols_.size() < kMaxSymbols; ++i) {
        const uint64_t p = symtab.offset + i * entsize;
        Symbol s;
        const uint32_t nameOff = u32(p);
        uint8_t info = 0;
        if (is64_) {
            info = inBounds(p + 4, 1) ? (*data_)[p + 4] : 0;
            s.shndx = u16(p + 6);
            s.value = u64(p + 8);
            s.size = u64(p + 16);
        } else {
            s.value = u32(p + 4);
            s.size = u32(p + 8);
            info = inBounds(p + 12, 1) ? (*data_)[p + 12] : 0;
            s.shndx = u16(p + 14);
        }
        s.type = info & 0xF;
        s.binding = info >> 4;
        s.dynamic = dynamic;
        if (nameOff < strtab.size) s.name = cstr(strtab.offset + nameOff, strtab.offset + strtab.size);
        if (s.name.empty()) continue;
        symbols_.push_back(std::move(s));
    }
}

void ElfFile::readRelocations(const Section& rel) {
    const bool rela = rel.type == SHT_RELA;
    const uint64_t entsize = is64_ ? (rela ? 24 : 16) : (rela ? 12 : 8);
    if (!inBounds(rel.offset, rel.size) || rel.link == 0 || rel.link >= sections_.size()) return;
    const Section& symtab = sections_[rel.link];
    if (!inBounds(symtab.offset, symtab.size) || symtab.link >= sections_.size()) return;
    const Section& strtab = sections_[symtab.link];
    if (!inBounds(strtab.offset, strtab.size)) return;
    const uint64_t symEnt = is64_ ? 24 : 16;
    const uint64_t count = rel.size / entsize;
    for (uint64_t i = 0; i < count && relocations_.size() < kMaxSymbols; ++i) {
        const uint64_t p = rel.offset + i * entsize;
        const uint64_t info = word(p + (is64_ ? 8 : 4));
        const uint64_t symIndex = is64_ ? info >> 32 : info >> 8;
        if (symIndex == 0 || (symIndex + 1) * symEnt > symtab.size) continue;
        const uint32_t nameOff = u32(symtab.offset + symIndex * symEnt);
        if (nameOff >= strtab.size) continue;
        Relocation r;
        r.offset = word(p);
        r.type = static_cast<uint32_t>(is64_ ? info & 0xffffffffu : info & 0xffu);
        if (rela) r.addend = is64_ ? static_cast<int64_t>(u64(p + 16)) : static_cast<int64_t>(static_cast<int32_t>(u32(p + 8)));
        r.symbol = cstr(strtab.offset + nameOff, strtab.offset + strtab.size);
        if (!r.symbol.empty()) relocations_.push_back(std::move(r));
    }
}

void ElfFile::readDynamic() {
    const Segment* dyn = nullptr;
    for (const Segment& s : segments_)
        if (s.type == PT_DYNAMIC) dyn = &s;
    if (!dyn || !inBounds(dyn->offset, dyn->filesz)) return;
    const uint64_t entsize = is64_ ? 16 : 8;
    uint64_t strtabAddr = 0, strsz = 0;
    std::vector<uint64_t> neededOffs;
    uint64_t sonameOff = UINT64_MAX;
    for (uint64_t p = dyn->offset; p + entsize <= dyn->offset + dyn->filesz; p += entsize) {
        const uint64_t tag = word(p);
        const uint64_t val = word(p + (is64_ ? 8 : 4));
        if (tag == DT_NULL) break;
        if (tag == DT_NEEDED) neededOffs.push_back(val);
        else if (tag == DT_STRTAB) strtabAddr = val;
        else if (tag == DT_STRSZ) strsz = val;
        else if (tag == DT_SONAME) sonameOff = val;
    }
    uint64_t strOff = 0;
    if (!strtabAddr || !vaddrToOffset(strtabAddr, strOff)) return;
    const uint64_t end = strsz ? strOff + strsz : data_->size();
    for (uint64_t off : neededOffs)
        if (strOff + off < end) needed_.push_back(cstr(strOff + off, end));
    if (sonameOff != UINT64_MAX && strOff + sonameOff < end) soname_ = cstr(strOff + sonameOff, end);
}

bool ElfFile::vaddrToOffset(uint64_t vaddr, uint64_t& offset) const {
    for (const Segment& s : segments_) {
        if (s.type != PT_LOAD) continue;
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.filesz) {
            offset = s.offset + (vaddr - s.vaddr);
            return offset < data_->size();
        }
    }
    return false;
}

std::vector<uint8_t> ElfFile::bytesAt(uint64_t offset, size_t len) const {
    if (offset >= data_->size()) return {};
    const size_t n = static_cast<size_t>(std::min<uint64_t>(len, data_->size() - offset));
    return std::vector<uint8_t>(data_->begin() + static_cast<ptrdiff_t>(offset), data_->begin() + static_cast<ptrdiff_t>(offset + n));
}

std::vector<const ElfFile::Symbol*> ElfFile::exports() const {
    std::vector<const Symbol*> out;
    for (const Symbol& s : symbols_)
        if (s.shndx != 0 && (s.binding == 1 || s.binding == 2) && (s.type == 1 || s.type == 2) && s.dynamic)
            out.push_back(&s);
    return out;
}

std::vector<const ElfFile::Symbol*> ElfFile::imports() const {
    std::vector<const Symbol*> out;
    for (const Symbol& s : symbols_)
        if (s.shndx == 0 && s.dynamic) out.push_back(&s);
    return out;
}

std::vector<const ElfFile::Symbol*> ElfFile::jniSymbols() const {
    std::vector<const Symbol*> out;
    for (const Symbol& s : symbols_)
        if (s.shndx != 0 && (s.name.rfind("Java_", 0) == 0 || s.name == "JNI_OnLoad" || s.name == "JNI_OnUnload"))
            out.push_back(&s);
    return out;
}

std::vector<ElfFile::StringHit> ElfFile::strings(size_t minLen, size_t limit) const {
    std::vector<StringHit> out;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (const Section& s : sections_) {
        if (s.type == SHT_NOBITS) continue;
        if (s.name == ".rodata" || s.name.rfind(".rodata.", 0) == 0 || s.name == ".data.rel.ro" || s.name == ".data")
            ranges.emplace_back(s.offset, s.size);
    }
    if (ranges.empty()) ranges.emplace_back(0, data_->size());
    for (const auto& r : ranges) {
        if (!inBounds(r.first, r.second)) continue;
        std::string cur;
        uint64_t start = r.first;
        for (uint64_t i = r.first; i < r.first + r.second && out.size() < limit; ++i) {
            const unsigned char c = (*data_)[i];
            if (c >= 0x20 && c < 0x7F) {
                if (cur.empty()) start = i;
                if (cur.size() < 2048) cur.push_back(static_cast<char>(c));
            } else {
                if (cur.size() >= minLen) out.push_back({start, cur});
                cur.clear();
            }
        }
        if (cur.size() >= minLen && out.size() < limit) out.push_back({start, cur});
    }
    return out;
}

std::string ElfFile::machineName() const {
    switch (machine_) {
    case 3: return "x86";
    case 8: return "MIPS";
    case 40: return "ARM";
    case 62: return "x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    default: return "machine " + std::to_string(machine_);
    }
}

std::string ElfFile::typeName() const {
    switch (type_) {
    case 1: return "relocatable";
    case 2: return "executable";
    case 3: return "shared object";
    case 4: return "core";
    default: return "type " + std::to_string(type_);
    }
}

namespace {

// Minimal Itanium demangler: nested names, simple builtin parameter types.
bool readSourceName(const std::string& s, size_t& p, std::string& out) {
    if (p >= s.size() || !std::isdigit(static_cast<unsigned char>(s[p]))) return false;
    size_t len = 0;
    while (p < s.size() && std::isdigit(static_cast<unsigned char>(s[p]))) {
        len = len * 10 + static_cast<size_t>(s[p++] - '0');
        if (len > 4096) return false;
    }
    if (p + len > s.size()) return false;
    out = s.substr(p, len);
    p += len;
    return true;
}

const char* builtin(char c) {
    switch (c) {
    case 'v': return "void";
    case 'b': return "bool";
    case 'c': return "char";
    case 'a': return "signed char";
    case 'h': return "unsigned char";
    case 's': return "short";
    case 't': return "unsigned short";
    case 'i': return "int";
    case 'j': return "unsigned int";
    case 'l': return "long";
    case 'm': return "unsigned long";
    case 'x': return "long long";
    case 'y': return "unsigned long long";
    case 'f': return "float";
    case 'd': return "double";
    case 'z': return "...";
    default: return nullptr;
    }
}

}  // namespace

std::string ElfFile::demangle(const std::string& name) {
    if (name.rfind("_Z", 0) != 0) return name;
    size_t p = 2;
    if (p < name.size() && name[p] == 'L') ++p;  // internal linkage (static functions): _ZL14__libc_preinitv
    std::vector<std::string> parts;
    if (p < name.size() && name[p] == 'N') {
        ++p;
        while (p < name.size() && (name[p] == 'K' || name[p] == 'V' || name[p] == 'r')) ++p;  // cv-qualifiers
        while (p < name.size() && name[p] != 'E') {
            std::string part;
            if (name.compare(p, 2, "C1") == 0 || name.compare(p, 2, "C2") == 0) {
                part = parts.empty() ? "ctor" : parts.back();
                p += 2;
            } else if (name.compare(p, 2, "D0") == 0 || name.compare(p, 2, "D1") == 0 ||
                       name.compare(p, 2, "D2") == 0) {
                part = "~" + (parts.empty() ? std::string("dtor") : parts.back());
                p += 2;
            } else if (name.compare(p, 2, "St") == 0) {
                part = "std";
                p += 2;
            } else if (!readSourceName(name, p, part)) {
                return name;
            }
            parts.push_back(part);
        }
        if (p >= name.size()) return name;
        ++p;  // 'E'
    } else {
        std::string part;
        if (!readSourceName(name, p, part)) return name;
        parts.push_back(part);
    }
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) out += (i ? "::" : "") + parts[i];
    out += '(';
    bool firstParam = true;
    while (p < name.size()) {
        std::string prefix, suffix;
        while (p < name.size() && (name[p] == 'P' || name[p] == 'R' || name[p] == 'K')) {
            if (name[p] == 'P') suffix = "*" + suffix;
            else if (name[p] == 'R') suffix = "&" + suffix;
            else prefix += "const ";
            ++p;
        }
        if (p >= name.size()) break;
        std::string type;
        if (const char* b = builtin(name[p])) {
            type = b;
            ++p;
        } else if (std::isdigit(static_cast<unsigned char>(name[p]))) {
            if (!readSourceName(name, p, type)) break;
        } else {
            out += firstParam ? "..." : ", ...";  // unsupported encoding: stop here
            firstParam = false;
            break;
        }
        if (type == "void" && firstParam && suffix.empty() && p >= name.size()) break;  // f(void)
        out += (firstParam ? "" : ", ") + prefix + type + suffix;
        firstParam = false;
    }
    out += ')';
    return out;
}
