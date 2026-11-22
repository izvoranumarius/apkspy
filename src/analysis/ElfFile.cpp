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
constexpr uint32_t SHT_RELR = 19;
constexpr uint32_t PF_X = 1;
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
        for (const Section& s : e->sections_) {
            if (s.type == SHT_RELA || s.type == SHT_REL) e->readRelocations(s);
            if (s.type == SHT_RELA || s.type == SHT_REL || s.type == SHT_RELR) e->readRelative(s);
        }
        std::sort(e->relative_.begin(), e->relative_.end());
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

// RELATIVE relocations (no symbol): the pointer at `offset` becomes load-base + addend.
// Position-independent libraries keep their pointer tables (JNI registrations,
// vtables, string tables) only in this form; RELR packs the same information.
void ElfFile::readRelative(const Section& rel) {
    if (!inBounds(rel.offset, rel.size)) return;
    const size_t ws = is64_ ? 8 : 4;
    constexpr size_t kMaxRelative = 4000000;
    if (rel.type == SHT_RELR) {
        uint64_t where = 0;
        const uint64_t count = rel.size / ws;
        for (uint64_t i = 0; i < count && relative_.size() < kMaxRelative; ++i) {
            const uint64_t entry = word(rel.offset + i * ws);
            if ((entry & 1) == 0) {  // an address
                where = entry;
                uint64_t off = 0, target = 0;
                if (vaddrToOffset(where, off) && inBounds(off, ws)) target = word(off);
                relative_.emplace_back(where, target);
                where += ws;
            } else {  // a bitmap of the next (ws*8 - 1) words
                uint64_t bits = entry >> 1;
                for (uint64_t b = 0; bits; ++b, bits >>= 1)
                    if ((bits & 1) && relative_.size() < kMaxRelative) {
                        const uint64_t at = where + b * ws;
                        uint64_t off = 0, target = 0;
                        if (vaddrToOffset(at, off) && inBounds(off, ws)) target = word(off);
                        relative_.emplace_back(at, target);
                    }
                where += (ws * 8 - 1) * ws;
            }
        }
        return;
    }
    const bool rela = rel.type == SHT_RELA;
    const uint64_t entsize = is64_ ? (rela ? 24 : 16) : (rela ? 12 : 8);
    uint32_t relativeType = 0;
    switch (machine_) {
    case 183: relativeType = 1027; break;  // R_AARCH64_RELATIVE
    case 62: relativeType = 8; break;      // R_X86_64_RELATIVE
    case 3: relativeType = 8; break;       // R_386_RELATIVE
    case 40: relativeType = 23; break;     // R_ARM_RELATIVE
    default: return;
    }
    const uint64_t count = rel.size / entsize;
    for (uint64_t i = 0; i < count && relative_.size() < kMaxRelative; ++i) {
        const uint64_t p = rel.offset + i * entsize;
        const uint64_t info = word(p + ws);
        const uint32_t type = static_cast<uint32_t>(is64_ ? info & 0xffffffffu : info & 0xffu);
        if (type != relativeType) continue;
        const uint64_t where = word(p);
        uint64_t target = 0;
        if (rela) {
            target = is64_ ? u64(p + 16) : static_cast<uint64_t>(u32(p + 8));
        } else {
            uint64_t off = 0;
            if (vaddrToOffset(where, off) && inBounds(off, ws)) target = word(off);
        }
        relative_.emplace_back(where, target);
    }
}

// The pointer stored at `vaddr`: its RELATIVE relocation target, else the raw word.
bool ElfFile::pointerAt(uint64_t vaddr, uint64_t& value) const {
    const auto it = std::lower_bound(relative_.begin(), relative_.end(), std::make_pair(vaddr, uint64_t{0}));
    if (it != relative_.end() && it->first == vaddr) {
        value = it->second;
        return true;
    }
    uint64_t off = 0;
    const size_t ws = is64_ ? 8 : 4;
    if (!vaddrToOffset(vaddr, off) || !inBounds(off, ws)) return false;
    value = word(off);
    return true;
}

bool ElfFile::cstrAtVaddr(uint64_t vaddr, std::string& out) const {
    uint64_t off = 0;
    if (!vaddrToOffset(vaddr, off)) return false;
    out = cstr(off, std::min<uint64_t>(off + 512, data_->size()));
    return !out.empty() && off + out.size() < data_->size();
}

bool ElfFile::executable(uint64_t vaddr) const {
    for (const Segment& s : segments_)
        if (s.type == PT_LOAD && (s.flags & PF_X) && vaddr >= s.vaddr && vaddr < s.vaddr + s.memsz) return true;
    return false;
}

namespace {
bool plausibleJavaName(const std::string& n) {
    if (n.empty() || n.size() > 128) return false;
    if (!(std::isalpha(static_cast<unsigned char>(n[0])) || n[0] == '_' || n[0] == '$' || n[0] == '<')) return false;
    for (char c : n)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '<' || c == '>')) return false;
    return true;
}
// "(ILjava/lang/String;[B)V": parameters and a return type, JNI characters only.
bool plausibleJniSignature(const std::string& s) {
    if (s.size() < 3 || s[0] != '(') return false;
    const size_t close = s.find(')');
    if (close == std::string::npos || close + 1 >= s.size()) return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '(' || c == ')' || c == '[' || c == ';' || c == '/' || c == '$' ||
              c == '_'))
            return false;
    return true;
}
}  // namespace

std::vector<ElfFile::NativeRegistration> ElfFile::jniRegistrations() const {
    std::vector<NativeRegistration> out;
    const size_t ws = is64_ ? 8 : 4, entry = 3 * ws;
    uint64_t scanned = 0;
    constexpr uint64_t kMaxScan = 64ull << 20;
    for (const Section& s : sections_) {
        // Pointer tables live in writable or relro data; skip code and plain strings.
        if (s.type == SHT_NOBITS || s.addr == 0 || s.size < entry) continue;
        const bool data = s.name == ".data" || s.name.rfind(".data.rel", 0) == 0 || s.name == ".init_array" || s.name == ".rodata";
        if (!data) continue;
        for (uint64_t a = (s.addr + ws - 1) & ~(ws - 1); a + entry <= s.addr + s.size && scanned < kMaxScan;) {
            scanned += ws;
            uint64_t pName = 0, pSig = 0, pFn = 0;
            std::string name, sig;
            if (pointerAt(a, pName) && pName && pointerAt(a + ws, pSig) && pSig && pointerAt(a + 2 * ws, pFn) && pFn &&
                executable(pFn & ~uint64_t{1}) && cstrAtVaddr(pName, name) && plausibleJavaName(name) && cstrAtVaddr(pSig, sig) &&
                plausibleJniSignature(sig)) {
                NativeRegistration r;
                r.name = std::move(name);
                r.signature = std::move(sig);
                r.fnAddr = pFn & ~uint64_t{1};  // ARM Thumb marker
                r.tableAddr = a;
                out.push_back(std::move(r));
                a += entry;
            } else {
                a += ws;
            }
        }
    }
    return out;
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

namespace {

// Characters worth reporting in a wide (UTF-16 / UTF-32) string: printable ASCII plus the common scripts.
// Narrow enough that random binary rarely forms a run, wide enough for real text.
bool plausibleWide(uint32_t c) {
    if (c >= 0x20 && c < 0x7F) return true;
    if (c < 0xA0) return false;
    return c <= 0x24F || (c >= 0x370 && c <= 0x52F) || (c >= 0x590 && c <= 0x6FF) || (c >= 0x900 && c <= 0x97F) ||
           (c >= 0xE00 && c <= 0xE7F) || (c >= 0x1E00 && c <= 0x1FFF) || (c >= 0x2010 && c <= 0x205E) ||
           (c >= 0x20A0 && c <= 0x20CF) || (c >= 0x3000 && c <= 0x30FF) || (c >= 0x3400 && c <= 0x4DBF) ||
           (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0xAC00 && c <= 0xD7A3) || (c >= 0xFF01 && c <= 0xFF5E) ||
           (c >= 0x1F300 && c <= 0x1FAFF);
}

void appendUtf8(std::string& s, uint32_t c) {
    if (c < 0x80) s += static_cast<char>(c);
    else if (c < 0x800) s += static_cast<char>(0xC0 | (c >> 6)), s += static_cast<char>(0x80 | (c & 0x3F));
    else if (c < 0x10000)
        s += static_cast<char>(0xE0 | (c >> 12)), s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
    else
        s += static_cast<char>(0xF0 | (c >> 18)), s += static_cast<char>(0x80 | ((c >> 12) & 0x3F)),
            s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
}

// Length of the valid UTF-8 multi-byte sequence at p (2..4), 0 when there is none. Overlong forms, surrogates
// and values past U+10FFFF are rejected.
size_t utf8Sequence(const uint8_t* p, size_t left) {
    const uint8_t b = p[0];
    size_t n = b >= 0xC2 && b <= 0xDF ? 2 : (b >= 0xE0 && b <= 0xEF ? 3 : (b >= 0xF0 && b <= 0xF4 ? 4 : 0));
    if (!n || n > left) return 0;
    uint32_t c = n == 2 ? b & 0x1F : (n == 3 ? b & 0x0F : b & 0x07);
    for (size_t k = 1; k < n; ++k) {
        if ((p[k] & 0xC0) != 0x80) return 0;
        c = (c << 6) | (p[k] & 0x3F);
    }
    if ((n == 3 && c < 0x800) || (n == 4 && (c < 0x10000 || c > 0x10FFFF)) || (c >= 0xD800 && c < 0xE000)) return 0;
    if (c >= 0x80 && c < 0xA0) return 0;  // C1 controls
    return n;
}

}  // namespace

std::vector<ElfFile::StringHit> ElfFile::strings(size_t minLen, size_t limit) const {
    std::vector<StringHit> out;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (const Section& s : sections_) {
        if (s.type == SHT_NOBITS) continue;
        if (s.name == ".rodata" || s.name.rfind(".rodata.", 0) == 0 || s.name == ".data.rel.ro" || s.name == ".data")
            ranges.emplace_back(s.offset, s.size);
    }
    if (ranges.empty()) ranges.emplace_back(0, data_->size());
    const size_t kMaxRun = 2048;
    for (const auto& r : ranges) {
        if (!inBounds(r.first, r.second)) continue;
        const uint8_t* d = data_->data() + r.first;
        const size_t n = static_cast<size_t>(r.second);
        std::vector<StringHit> hits;
        std::vector<uint8_t> taken(n, 0);  // bytes already part of a string
        std::vector<std::pair<size_t, size_t>> wideSpans;  // byte ranges (in this section) of wide hits

        // Narrow text: printable ASCII, with valid UTF-8 sequences allowed inside.
        {
            std::string cur;
            size_t start = 0, chars = 0;
            bool multibyte = false;
            const auto flush = [&] {
                if (chars >= minLen) {
                    hits.push_back({r.first + start, cur, multibyte ? "utf-8" : "ascii"});
                    // A short narrow run could also be (part of) UTF-16 text, e.g. CJK whose bytes are printable;
                    // only a run too long to be that blocks the wide readers.
                    if (cur.size() >= 2 * minLen)
                        for (size_t k = start; k < start + cur.size() && k < n; ++k) taken[k] = 1;
                }
                cur.clear();
                chars = 0;
                multibyte = false;
            };
            for (size_t i = 0; i < n;) {
                const uint8_t c = d[i];
                size_t len = 0;
                if (c >= 0x20 && c < 0x7F) len = 1;
                else if (c >= 0x80) len = utf8Sequence(d + i, n - i);
                if (!len) {
                    flush();
                    ++i;
                    continue;
                }
                if (cur.empty()) start = i;
                if (cur.size() < kMaxRun) cur.append(reinterpret_cast<const char*>(d + i), len);
                multibyte = multibyte || len > 1;
                ++chars;
                i += len;
            }
            flush();
        }

        // Wide text: aligned runs of plausible characters, skipping bytes a narrow string already owns.
        const auto wide = [&](size_t unit, bool bigEndian, const char* name) {
            std::string cur;
            size_t start = 0, chars = 0;
            const auto flush = [&] {
                if (chars >= minLen) {
                    hits.push_back({r.first + start, cur, name});
                    wideSpans.push_back({start, start + chars * unit});
                    for (size_t k = start; k < start + chars * unit && k < n; ++k) taken[k] = 1;
                }
                cur.clear();
                chars = 0;
            };
            for (size_t i = (r.first % unit == 0 ? 0 : unit - r.first % unit); i + unit <= n; i += unit) {
                uint32_t c = 0;
                bool free = true;
                for (size_t k = 0; k < unit; ++k) free = free && !taken[i + k];
                if (unit == 2) c = bigEndian ? (d[i] << 8 | d[i + 1]) : (d[i + 1] << 8 | d[i]);
                else c = static_cast<uint32_t>(d[i]) | static_cast<uint32_t>(d[i + 1]) << 8 | static_cast<uint32_t>(d[i + 2]) << 16 |
                         static_cast<uint32_t>(d[i + 3]) << 24;
                bool ok = free && plausibleWide(c);
                if (ok && unit == 2 && (c & 0xFF) == 0 && (c >> 8) >= 0x20 && (c >> 8) < 0x7F) ok = false;  // ASCII of the other byte order
                if (ok && unit == 2 && c >= 0xD800 && c < 0xE000) ok = false;  // surrogates only matter for emoji; skip
                if (!ok) {
                    flush();
                    continue;
                }
                if (cur.empty()) start = i;
                if (cur.size() < kMaxRun) appendUtf8(cur, c);
                ++chars;
            }
            flush();
        };
        // Wider units go first and claim their bytes, so one text is reported once.
        wide(4, false, "utf-32le");
        wide(2, false, "utf-16le");
        wide(2, true, "utf-16be");

        // Short narrow runs that are only a piece of a wide string are not separate strings.
        hits.erase(std::remove_if(hits.begin(), hits.end(),
                                  [&](const StringHit& h) {
                                      if (h.encoding[0] != 'a' && h.encoding[4] != '8') return false;  // keep wide hits
                                      const size_t at = h.offset - r.first;
                                      for (const auto& w : wideSpans)
                                          if (at >= w.first && at + h.value.size() <= w.second) return true;
                                      return false;
                                  }),
                   hits.end());
        std::sort(hits.begin(), hits.end(), [](const StringHit& a, const StringHit& b) { return a.offset < b.offset; });
        for (StringHit& h : hits) {
            if (out.size() >= limit) break;
            out.push_back(std::move(h));
        }
        if (out.size() >= limit) break;
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
