#include "analysis/NativeCode.hpp"
#include <algorithm>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include "analysis/Abi.hpp"
#include "core/TextUtils.hpp"

namespace {
constexpr uint64_t SHF_EXECINSTR = 4;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t PT_LOAD = 1;
constexpr uint8_t STT_FUNC = 2;
constexpr uint32_t R_AARCH64_GLOB_DAT = 1025;
constexpr uint32_t R_AARCH64_JUMP_SLOT = 1026;
constexpr size_t kMaxRefs = 8000000;
// adrp results are trusted for this many instructions; compilers keep the pair close together.
constexpr size_t kPageWindow = 24;

std::string hex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

// First operand of an ARM instruction as a register number ("r3, [r0]" -> 3, "sp!" -> 13), -1 when it is not one.
int armReg(const std::string& token) {
    std::string t = token;
    while (!t.empty() && (t.back() == '!' || t.back() == ' ')) t.pop_back();
    while (!t.empty() && t.front() == ' ') t.erase(t.begin());
    if (t == "sp") return 13;
    if (t == "lr") return 14;
    if (t == "pc") return 15;
    if (t.size() >= 2 && t[0] == 'r' && std::isdigit(static_cast<unsigned char>(t[1]))) {
        const int n = std::atoi(t.c_str() + 1);
        return n >= 0 && n <= 12 ? n : -1;
    }
    return -1;
}

std::vector<std::string> armTokens(const std::string& ops) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= ops.size(); ++i)
        if (i == ops.size() || ops[i] == ',') {
            out.push_back(ops.substr(start, i - start));
            start = i + 1;
        }
    return out;
}

bool startsWith(const std::string& s, const char* p) { return s.compare(0, std::strlen(p), p) == 0; }

}  // namespace

const char* NativeCode::isaName(Isa isa) {
    switch (isa) {
    case Isa::Arm64: return "AArch64";
    case Isa::Arm32: return "ARM";
    case Isa::X86: return "x86";
    default: return "x86-64";
    }
}

std::string NativeCode::unsupportedReason(const ElfFile& e) {
    const abi::Info info = abi::fromElf(abi::peekElf(e.data().data(), e.data().size()));
    if (info.disassemblable) return {};
    if (!e.littleEndian()) return "big-endian libraries are not supported";
    return "disassembly supports arm64-v8a, armeabi-v7a, x86 and x86_64 libraries; this one is " + abi::machineName(e.machine()) +
           (e.is64() ? " (64-bit)" : " (32-bit)") + ". Open another ABI's copy of the library if the APK ships one.";
}

std::shared_ptr<NativeCode> NativeCode::build(std::shared_ptr<const ElfFile> elf, const std::atomic<bool>* cancel,
                                              std::string& error) {
    if (!elf) {
        error = "no ELF";
        return nullptr;
    }
    if (const std::string why = unsupportedReason(*elf); !why.empty()) {
        error = why;
        return nullptr;
    }
    struct Made : NativeCode {};  // reaches the private constructor for make_shared
    std::shared_ptr<NativeCode> nc = std::make_shared<Made>();
    nc->elf_ = std::move(elf);
    const abi::Info info = abi::fromElf(abi::peekElf(nc->elf_->data().data(), nc->elf_->data().size()));
    nc->isa_ = info.id == abi::Id::Arm64 ? Isa::Arm64 : info.id == abi::Id::Arm32 ? Isa::Arm32 : info.id == abi::Id::X86 ? Isa::X86 : Isa::X86_64;
    const uint64_t align = nc->isa_ == Isa::Arm64 ? 4 : nc->isa_ == Isa::Arm32 ? 2 : 1;
    const uint64_t minSize = nc->isa_ == Isa::Arm64 ? 4 : 2;
    const auto fits = [&](uint64_t off, uint64_t size) { return size >= minSize && off + size <= nc->elf_->data().size(); };
    for (const auto& s : nc->elf_->sections())
        if ((s.flags & SHF_EXECINSTR) && s.type != SHT_NOBITS && fits(s.offset, s.size)) nc->code_.push_back({s.addr, s.size - s.size % align, s.offset});
    if (nc->code_.empty())  // no section table (stripped / packed): fall back to executable segments
        for (const auto& s : nc->elf_->segments())
            if (s.type == PT_LOAD && (s.flags & 1) && fits(s.offset, s.filesz)) nc->code_.push_back({s.vaddr, s.filesz - s.filesz % align, s.offset});
    if (nc->code_.empty()) {
        error = "no executable code found";
        return nullptr;
    }
    std::sort(nc->code_.begin(), nc->code_.end(), [](const Range& a, const Range& b) { return a.vaddr < b.vaddr; });
    // The relocation types of GOT slots that hold an import's address.
    uint32_t relJump = R_AARCH64_JUMP_SLOT, relGlob = R_AARCH64_GLOB_DAT;
    if (nc->isa_ == Isa::Arm32) relJump = 22, relGlob = 21;      // R_ARM_JUMP_SLOT, R_ARM_GLOB_DAT
    else if (nc->isa_ != Isa::Arm64) relJump = 7, relGlob = 6;    // R_386_ / R_X86_64_ JMP_SLOT, GLOB_DAT
    for (const auto& r : nc->elf_->relocations())
        if (r.type == relJump || r.type == relGlob) nc->gotNames_.emplace_back(r.offset, r.symbol);
    std::sort(nc->gotNames_.begin(), nc->gotNames_.end());
    if (nc->isa_ == Isa::X86)
        for (const auto& s : nc->elf_->sections())
            if (s.name == ".got.plt" || (s.name == ".got" && !nc->gotBase_)) nc->gotBase_ = s.addr;
    if (nc->isa_ == Isa::Arm32) {
        // Thumb or ARM: mapping symbols say it exactly; function symbols carry it in their low bit.
        size_t thumbFns = 0, armFns = 0;
        bool mapping = false;
        std::vector<std::pair<uint64_t, char>> fnMarks, mapMarks;
        for (const auto& s : nc->elf_->symbols()) {
            if (s.name.size() >= 2 && s.name[0] == '$' && (s.name[1] == 't' || s.name[1] == 'a' || s.name[1] == 'd') &&
                (s.name.size() == 2 || s.name[2] == '.')) {
                mapMarks.emplace_back(s.value, s.name[1]);
                mapping = true;
            } else if (s.type == STT_FUNC && s.shndx != 0 && s.value) {
                const bool t = (s.value & 1) != 0;
                (t ? thumbFns : armFns)++;
                fnMarks.emplace_back(s.value & ~1ull, t ? 't' : 'a');
            }
        }
        nc->modes_ = std::move(fnMarks);
        nc->modes_.insert(nc->modes_.end(), mapMarks.begin(), mapMarks.end());  // later entries win at the same address
        std::stable_sort(nc->modes_.begin(), nc->modes_.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        nc->defaultThumb_ = thumbFns >= armFns;
        (void)mapping;
    }
    if (nc->isa_ == Isa::Arm64) nc->sweep(cancel);
    else nc->sweepGeneric(cancel);
    if (cancel && cancel->load()) {
        error = "cancelled";
        return nullptr;
    }
    nc->discoverFunctions();
    return nc;
}

bool NativeCode::readWord(uint64_t vaddr, uint32_t& out) const {
    for (const Range& r : code_)
        if (vaddr >= r.vaddr && vaddr + 4 <= r.vaddr + r.size) {
            const uint8_t* p = elf_->data().data() + r.offset + (vaddr - r.vaddr);
            out = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
            return true;
        }
    return false;
}

char NativeCode::modeAtAddr(uint64_t addr) const {
    auto it = std::upper_bound(modes_.begin(), modes_.end(), addr, [](uint64_t a, const std::pair<uint64_t, char>& m) { return a < m.first; });
    if (it == modes_.begin()) return defaultThumb_ ? 't' : 'a';
    return std::prev(it)->second;
}

char NativeCode::modeAt(uint64_t addr, size_t& cursor) const {
    while (cursor < modes_.size() && modes_[cursor].first <= addr) ++cursor;
    return cursor ? modes_[cursor - 1].second : (defaultThumb_ ? 't' : 'a');
}

bool NativeCode::mapped(uint64_t vaddr) const {
    uint64_t off = 0;
    return elf_->vaddrToOffset(vaddr, off);
}

bool NativeCode::readData32(uint64_t vaddr, uint32_t& out) const {
    uint64_t off = 0;
    if (!elf_->vaddrToOffset(vaddr, off) || off + 4 > elf_->data().size()) return false;
    const uint8_t* p = elf_->data().data() + off;
    out = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
    return true;
}

namespace {
native::Insn decodeRaw(NativeCode::Isa isa, const uint8_t* p, size_t avail, uint64_t addr, bool thumb) {
    native::Insn none;
    none.size = 0;
    if (isa == NativeCode::Isa::Arm32) {
        if (avail < (thumb ? 2u : 4u)) return none;
        const arm32::Insn a = arm32::decode(p, avail, addr, thumb);
        native::Insn n;
        n.addr = a.addr;
        n.raw = a.raw;
        n.size = a.size;
        n.mnemonic = a.mnemonic;
        n.operands = a.operands;
        n.flow = static_cast<native::Flow>(a.flow);
        n.hasTarget = a.hasTarget;
        n.target = a.target;
        n.memTarget = a.hasTarget && a.flow == arm32::Flow::Normal;
        n.thumb = a.thumb;
        n.known = a.known;
        return n;
    }
    if (isa == NativeCode::Isa::Arm64) return none;
    return x86::decode(p, avail > 15 ? 15 : avail, addr, isa == NativeCode::Isa::X86_64);
}
}  // namespace

native::Insn NativeCode::decodeAt(uint64_t vaddr, bool thumb) const {
    if (isa_ == Isa::Arm64) {
        uint32_t w = 0;
        if (!readWord(vaddr & ~3ull, w)) {
            native::Insn none;
            none.size = 0;
            return none;
        }
        return arm64::decode(w, vaddr & ~3ull);
    }
    for (const Range& r : code_)
        if (vaddr >= r.vaddr && vaddr < r.vaddr + r.size)
            return decodeRaw(isa_, elf_->data().data() + r.offset + (vaddr - r.vaddr), r.vaddr + r.size - vaddr, vaddr, thumb);
    native::Insn none;
    none.size = 0;
    return none;
}

// ARM: constants held in registers. `ldr rN, [pc, #x]` loads a literal, `movw` / `movt` build one, and an `add` of pc
// turns an offset constant into the address it points at (the position-independent way to name a string or a GOT slot).
bool NativeCode::armDataRef(const native::Insn& in, DataState& st, uint64_t& addr, bool& read) const {
    const std::string& m = in.mnemonic;
    const std::vector<std::string> tok = armTokens(in.operands);
    const int rd = tok.empty() ? -1 : armReg(tok[0]);
    const auto immOf = [&]() -> uint32_t {
        const size_t h = in.operands.find('#');
        return h == std::string::npos ? 0u : static_cast<uint32_t>(std::strtoull(in.operands.c_str() + h + 1, nullptr, 0));
    };
    if (in.flow == native::Flow::Call || in.flow == native::Flow::IndirectCall) {
        for (int r : {0, 1, 2, 3, 12, 14}) st.clear(r);
        return false;
    }
    if (in.hasTarget && in.flow == native::Flow::Normal && startsWith(m, "ldr") && in.operands.find("[pc") != std::string::npos) {
        uint32_t w = 0;
        if (rd >= 0 && readData32(in.target, w)) st.set(rd, w);
        else st.clear(rd);
        return false;
    }
    if (in.hasTarget && in.flow == native::Flow::Normal && startsWith(m, "adr")) {
        addr = in.target;
        read = false;
        st.set(rd, static_cast<uint32_t>(addr));
        return mapped(addr);
    }
    if (startsWith(m, "movw")) {
        st.set(rd, immOf());
        return false;
    }
    if (startsWith(m, "movt")) {
        if (st.has(rd)) st.set(rd, (st.value[rd] & 0xffff) | (immOf() << 16));
        else st.clear(rd);
        return false;
    }
    if (startsWith(m, "add") && !startsWith(m, "adds") && rd >= 0) {
        const uint32_t pcv = static_cast<uint32_t>(in.addr) + (in.thumb ? 4u : 8u);
        int src = -2;
        if (tok.size() == 2 && armReg(tok[1]) == 15) src = rd;
        else if (tok.size() == 3 && armReg(tok[2]) == 15) src = armReg(tok[1]);
        else if (tok.size() == 3 && armReg(tok[1]) == 15) src = armReg(tok[2]);
        if (src >= 0 && st.has(src)) {
            const uint32_t v = st.value[src] + pcv;
            st.set(rd, v);
            addr = v;
            read = false;
            return mapped(addr);
        }
        if (src != -2) {
            st.clear(rd);
            return false;
        }
    }
    // Anything else that writes a tracked register forgets it.
    if (rd >= 0 && !(startsWith(m, "cmp") || startsWith(m, "cmn") || startsWith(m, "tst") || startsWith(m, "teq") ||
                     startsWith(m, "str") || startsWith(m, "push") || startsWith(m, "stm") || m[0] == 'b' || startsWith(m, "cbz") || startsWith(m, "cbnz")))
        st.clear(rd);
    if (!in.operands.empty() && in.operands[0] == '{') st.reset();  // pop / ldm: any of them
    if (startsWith(m, "ldm") || startsWith(m, "pop")) st.reset();
    if (in.flow == native::Flow::Return) st.reset();
    return false;
}

bool NativeCode::dataRef(const native::Insn& in, DataState& st, uint64_t& addr, bool& read) const {
    switch (isa_) {
    case Isa::X86_64:
        if (in.memTarget) {
            addr = in.target;
            read = !in.isAddImm;
            return mapped(addr);
        }
        return false;
    case Isa::X86:
        if ((in.isAddImm || in.isLoad) && in.baseReg == 3 && gotBase_) {  // [ebx + disp]: ebx holds the GOT address
            addr = (gotBase_ + static_cast<uint64_t>(in.offset)) & 0xffffffffull;
            read = !in.isAddImm;
            return mapped(addr);
        }
        return false;
    case Isa::Arm32: return armDataRef(in, st, addr, read);
    default: return false;
    }
}

void NativeCode::annotate(Line& l, uint64_t data, bool dataRead) const {
    l.dataAddr = data;
    // A load reads a value (pointer, constant) from data: only address-forming instructions can point at a string.
    bool wide = false, utf32 = false;
    const std::string str = dataRead ? std::string() : stringAt(data, &wide, &utf32);
    if (!str.empty()) l.comment = (utf32 ? "U\"" : wide ? "u\"" : "\"") + str + "\"";
    else if (std::string sym = symbolize(data); !sym.empty()) l.comment = dataRead ? "[" + sym + "]" : sym;
    else l.comment = dataRead ? "[" + hex(data) + "]" : hex(data);
}

void NativeCode::sweepGeneric(const std::atomic<bool>* cancel) {
    size_t index = 0;
    DataState st;
    const auto& data = elf_->data();
    for (const Range& r : code_) {
        const uint8_t* base = data.data() + r.offset;
        uint64_t off = 0;
        size_t cursor = 0;
        st.reset();
        while (off < r.size) {
            if ((index & 0xffff) == 0 && cancel && cancel->load()) return;
            const uint64_t pc = r.vaddr + off;
            bool thumb = false;
            if (isa_ == Isa::Arm32) {
                const char mode = modeAt(pc, cursor);
                if (mode == 'd') {  // a literal pool: skip to the next marker
                    off = cursor < modes_.size() && modes_[cursor].first > pc ? std::min<uint64_t>(modes_[cursor].first - r.vaddr, r.size) : off + 4;
                    continue;
                }
                thumb = mode == 't';
            }
            const native::Insn in = decodeRaw(isa_, base + off, static_cast<size_t>(r.size - off), pc, thumb);
            if (in.size == 0) break;
            ++index;
            if (refs_.size() < kMaxRefs) {
                if (in.hasTarget && !in.memTarget && in.flow == native::Flow::Call) refs_.push_back({in.target, pc, RefKind::Call});
                else if (in.hasTarget && !in.memTarget && in.flow == native::Flow::Jump) refs_.push_back({in.target, pc, RefKind::Jump});
                uint64_t addr = 0;
                bool read = false;
                if (dataRef(in, st, addr, read)) refs_.push_back({addr, pc, read ? RefKind::Read : RefKind::Data});
            }
            if (isa_ != Isa::Arm32 && (in.flow == native::Flow::Return)) st.reset();
            off += in.size;
        }
    }
    instructions_ = index;
    std::sort(refs_.begin(), refs_.end(), [](const Ref& a, const Ref& b) {
        return a.target != b.target ? a.target < b.target : a.from < b.from;
    });
    refs_.shrink_to_fit();
}

// One pass over every executable word with cheap bit tests (no text formatting):
// records b / bl targets and the addresses formed by adrp + add / ldr pairs.
void NativeCode::sweep(const std::atomic<bool>* cancel) {
    struct Page {
        uint64_t value = 0;
        size_t at = 0;
        bool valid = false;
    } pages[32];
    size_t index = 0;
    const auto& data = elf_->data();
    for (const Range& r : code_) {
        for (auto& p : pages) p.valid = false;
        for (uint64_t off = 0; off + 4 <= r.size; off += 4, ++index) {
            if ((index & 0xffff) == 0 && cancel && cancel->load()) return;
            const uint8_t* b = data.data() + r.offset + off;
            const uint32_t w = static_cast<uint32_t>(b[0]) | static_cast<uint32_t>(b[1]) << 8 | static_cast<uint32_t>(b[2]) << 16 | static_cast<uint32_t>(b[3]) << 24;
            const uint64_t pc = r.vaddr + off;
            if (refs_.size() >= kMaxRefs) continue;
            if ((w & 0x7c000000) == 0x14000000) {  // b / bl
                int64_t imm = static_cast<int64_t>(w & 0x3ffffff);
                if (imm & 0x2000000) imm -= 0x4000000;
                refs_.push_back({pc + static_cast<uint64_t>(imm * 4), pc, (w & 0x80000000) ? RefKind::Call : RefKind::Jump});
                if (w & 0x80000000)  // calls clobber the caller-saved registers
                    for (unsigned k = 0; k < 18; ++k) pages[k].valid = false;
                continue;
            }
            if ((w & 0x9f000000) == 0x90000000) {  // adrp
                int64_t imm = static_cast<int64_t>((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3));
                if (imm & 0x100000) imm -= 0x200000;
                pages[w & 31] = {(pc & ~0xfffull) + static_cast<uint64_t>(imm * 4096), index, true};
                continue;
            }
            if ((w & 0xff800000) == 0x91000000) {  // add xd, xn, #imm (64-bit, no shift)
                const unsigned rn = (w >> 5) & 31, rd = w & 31;
                if (pages[rn].valid && index - pages[rn].at <= kPageWindow) {
                    const uint64_t addr = pages[rn].value + ((w >> 10) & 0xfff);
                    refs_.push_back({addr, pc, RefKind::Data});
                }
                pages[rd].valid = false;
                continue;
            }
            if ((w & 0x3b000000) == 0x39000000 && (w & 0x00400000)) {  // ldr (unsigned offset), any size
                const unsigned rn = (w >> 5) & 31, rt = w & 31, size = w >> 30;
                const bool simd = (w >> 26) & 1;
                const unsigned scale = simd && ((w >> 23) & 1) ? 4 : size;
                if (pages[rn].valid && index - pages[rn].at <= kPageWindow) {
                    const uint64_t addr = pages[rn].value + (static_cast<uint64_t>((w >> 10) & 0xfff) << scale);
                    refs_.push_back({addr, pc, RefKind::Read});
                }
                if (!simd) pages[rt].valid = false;
                continue;
            }
            if ((w & 0xfffffc1f) == 0xd65f0000 || (w & 0xfffffc1f) == 0xd61f0000)  // ret / br: function boundary
                for (auto& p : pages) p.valid = false;
        }
    }
    instructions_ = index;
    std::sort(refs_.begin(), refs_.end(), [](const Ref& a, const Ref& b) {
        return a.target != b.target ? a.target < b.target : a.from < b.from;
    });
    refs_.shrink_to_fit();
}

// PLT stubs named after the import their GOT slot is relocated for ("strlen@plt").
void NativeCode::discoverPlt(std::vector<Function>& fns) const {
    const auto gotName = [&](uint64_t got, std::string& name) {
        auto it = std::lower_bound(gotNames_.begin(), gotNames_.end(), std::make_pair(got, std::string()));
        if (it == gotNames_.end() || it->first != got) return false;
        name = it->second;
        return true;
    };
    for (const auto& sec : elf_->sections()) {
        if (sec.name != ".plt" && sec.name != ".plt.sec" && sec.name != ".plt.got") continue;
        std::string name;
        if (isa_ == Isa::Arm64) {  // adrp x16, page ; ldr x17, [x16, #off]
            for (uint64_t a = sec.addr; a + 8 <= sec.addr + sec.size; a += 4) {
                uint32_t w1 = 0, w2 = 0;
                if (!readWord(a, w1) || !readWord(a + 4, w2)) break;
                if ((w1 & 0x9f00001f) != 0x90000010 || (w2 & 0xffc003ff) != 0xf9400211) continue;
                const arm64::Insn page = arm64::decode(w1, a);
                const uint64_t got = page.target + (((w2 >> 10) & 0xfff) << 3);
                if (!gotName(got, name)) continue;
                Function f;
                f.addr = a;
                f.size = 16;
                f.name = name + "@plt";
                f.kind = FunctionKind::Plt;
                fns.push_back(std::move(f));
                a += 12;
            }
        } else if (isa_ == Isa::Arm32) {  // add ip, pc, #a ; add ip, ip, #b ; ldr pc, [ip, #c]!
            const auto imm = [](uint32_t w) {
                const uint32_t v = w & 0xff, rot = ((w >> 8) & 0xf) * 2;
                return rot ? (v >> rot) | (v << (32 - rot)) : v;
            };
            for (uint64_t a = sec.addr; a + 12 <= sec.addr + sec.size; a += 4) {
                uint32_t w1 = 0, w2 = 0, w3 = 0;
                if (!readWord(a, w1) || !readWord(a + 4, w2) || !readWord(a + 8, w3)) break;
                if ((w1 & 0xfffff000) != 0xe28fc000 || (w2 & 0xfffff000) != 0xe28cc000 || (w3 & 0xfffff000) != 0xe5bcf000) continue;
                const uint64_t got = (a + 8 + imm(w1) + imm(w2) + (w3 & 0xfff)) & 0xffffffffull;
                if (!gotName(got, name)) continue;
                Function f;
                f.addr = a;
                f.size = 12;
                f.name = name + "@plt";
                f.kind = FunctionKind::Plt;
                fns.push_back(std::move(f));
                a += 8;
            }
            // Thumb PLT (lld): movw r12, #lo ; movt r12, #hi ; add r12, pc ; ldr.w pc, [r12]
            for (uint64_t a = sec.addr; a + 12 <= sec.addr + sec.size; a += 2) {
                native::Insn i1 = decodeAt(a, true);
                if (i1.size != 4 || i1.mnemonic != "movw" || i1.operands.compare(0, 4, "r12,") != 0) continue;
                native::Insn i2 = decodeAt(a + 4, true), i3 = decodeAt(a + 8, true);
                if (i2.size != 4 || i2.mnemonic != "movt" || i3.mnemonic != "add" || i3.operands != "r12, pc") continue;
                const auto movImm = [](const native::Insn& i) { return static_cast<uint32_t>(std::strtoul(i.operands.c_str() + i.operands.find('#') + 1, nullptr, 0)); };
                const uint64_t got = (static_cast<uint64_t>(movImm(i1) | (movImm(i2) << 16)) + a + 8 + 4) & 0xffffffffull;
                if (!gotName(got, name)) continue;
                Function f;
                f.addr = a;
                f.size = 16;
                f.thumb = true;
                f.name = name + "@plt";
                f.kind = FunctionKind::Plt;
                fns.push_back(std::move(f));
                a += 14;
            }
        } else {  // x86 / x86-64: an indirect jump through the GOT slot, in a 16-byte entry (8 in .plt.got)
            const uint64_t entry = sec.name == ".plt.got" ? 8 : 16;
            for (uint64_t a = sec.addr; a < sec.addr + sec.size;) {
                const native::Insn in = decodeAt(a, false);
                if (in.size == 0) break;
                uint64_t got = 0;
                bool ok = false;
                if (in.flow == native::Flow::IndirectJump) {
                    if (isa_ == Isa::X86_64 && in.memTarget) got = in.target, ok = true;
                    else if (isa_ == Isa::X86 && in.baseReg == 3 && gotBase_) got = (gotBase_ + static_cast<uint64_t>(in.offset)) & 0xffffffffull, ok = true;
                }
                if (ok && gotName(got, name)) {
                    Function f;
                    f.addr = a - (a - sec.addr) % entry;
                    f.size = entry;
                    f.name = name + "@plt";
                    f.kind = FunctionKind::Plt;
                    fns.push_back(std::move(f));
                }
                a += in.size;
            }
        }
    }
}

void NativeCode::discoverFunctions() {
    const auto inCode = [this](uint64_t a) {
        for (const Range& r : code_)
            if (a >= r.vaddr && a < r.vaddr + r.size) return true;
        return false;
    };
    std::vector<Function> fns;
    for (const auto& s : elf_->symbols()) {
        if (s.type != STT_FUNC || s.shndx == 0 || s.value == 0) continue;
        Function f;
        f.addr = s.value & ~1ull;
        f.thumb = isa_ == Isa::Arm32 && (s.value & 1);
        f.size = s.size;
        f.name = s.name;
        f.exported = s.dynamic && s.binding != 0;
        fns.push_back(std::move(f));
    }
    discoverPlt(fns);
    std::sort(fns.begin(), fns.end(), [](const Function& a, const Function& b) {
        if (a.addr != b.addr) return a.addr < b.addr;
        if (a.exported != b.exported) return a.exported;
        return a.size > b.size;
    });
    fns.erase(std::unique(fns.begin(), fns.end(), [](const Function& a, const Function& b) { return a.addr == b.addr; }),
              fns.end());
    // Call targets without a symbol become sub_<addr>.
    std::vector<uint64_t> known;
    known.reserve(fns.size());
    for (const auto& f : fns) known.push_back(f.addr);
    // A jump leaving a sized symbol is a tail call: its target is a function too.
    const auto inSymbol = [&](uint64_t a) {
        auto it = std::upper_bound(fns.begin(), fns.end(), a, [](uint64_t x, const Function& f) { return x < f.addr; });
        return it != fns.begin() && a < std::prev(it)->addr + std::prev(it)->size;
    };
    std::vector<Function> discovered;
    uint64_t last = UINT64_MAX;
    for (const Ref& r : refs_) {
        if (r.kind == RefKind::Data || r.kind == RefKind::Read || r.target == last) continue;
        if (r.kind == RefKind::Jump && (!inSymbol(r.from) || inSymbol(r.target))) continue;
        last = r.target;
        if (std::binary_search(known.begin(), known.end(), r.target) || !inCode(r.target)) continue;
        Function f;
        f.addr = r.target;
        f.name = "sub_" + hex(r.target).substr(2);
        f.kind = FunctionKind::Discovered;
        f.thumb = isa_ == Isa::Arm32 && modeAtAddr(r.target) == 't';
        discovered.push_back(std::move(f));
    }
    fns.insert(fns.end(), std::make_move_iterator(discovered.begin()), std::make_move_iterator(discovered.end()));
    std::sort(fns.begin(), fns.end(), [](const Function& a, const Function& b) { return a.addr < b.addr; });
    // Unknown sizes run to the next function or the end of the code range.
    for (size_t i = 0; i < fns.size(); ++i) {
        if (fns[i].size) continue;
        uint64_t end = fns[i].addr + 4;
        for (const Range& r : code_)
            if (fns[i].addr >= r.vaddr && fns[i].addr < r.vaddr + r.size) end = r.vaddr + r.size;
        if (i + 1 < fns.size()) end = std::min(end, fns[i + 1].addr);
        fns[i].size = end > fns[i].addr ? end - fns[i].addr : 4;
    }
    functions_ = std::move(fns);
}

const NativeCode::Function* NativeCode::functionAt(uint64_t addr) const {
    auto it = std::upper_bound(functions_.begin(), functions_.end(), addr,
                               [](uint64_t a, const Function& f) { return a < f.addr; });
    if (it == functions_.begin()) return nullptr;
    --it;
    return addr < it->addr + std::max<uint64_t>(it->size, 4) ? &*it : nullptr;
}

std::string NativeCode::displayName(const Function& f) {
    if (f.kind == FunctionKind::Plt) return ElfFile::demangle(f.name.substr(0, f.name.size() - 4)) + "@plt";
    return ElfFile::demangle(f.name);
}

const NativeCode::Function* NativeCode::findFunction(const std::string& query) const {
    if (query.empty()) return nullptr;
    if (query.size() > 2 && query[0] == '0' && (query[1] == 'x' || query[1] == 'X')) {
        char* end = nullptr;
        const unsigned long long a = std::strtoull(query.c_str() + 2, &end, 16);
        if (end && *end == 0) return functionAt(a);
    }
    for (const auto& f : functions_)
        if (f.name == query) return &f;
    for (const auto& f : functions_)
        if (displayName(f) == query) return &f;
    for (const auto& f : functions_)
        if (tex::ciFind(displayName(f), query) != std::string_view::npos) return &f;
    return nullptr;
}

std::string NativeCode::symbolize(uint64_t addr) const {
    auto got = std::lower_bound(gotNames_.begin(), gotNames_.end(), std::make_pair(addr, std::string()));
    if (got != gotNames_.end() && got->first == addr) return ElfFile::demangle(got->second) + "@got";
    if (const Function* f = functionAt(addr)) {
        const std::string n = displayName(*f);
        return addr == f->addr ? n : n + "+" + hex(addr - f->addr);
    }
    for (const auto& s : elf_->symbols())  // data symbols (objects)
        if (s.shndx != 0 && s.value && addr >= s.value && addr < s.value + std::max<uint64_t>(s.size, 1))
            return addr == s.value ? ElfFile::demangle(s.name) : ElfFile::demangle(s.name) + "+" + hex(addr - s.value);
    return {};
}

std::string NativeCode::cStringAt(uint64_t vaddr) const {
    uint64_t off = 0;
    if (!elf_->vaddrToOffset(vaddr, off)) return {};
    const auto& d = elf_->data();
    std::string s;
    for (uint64_t i = off; i < d.size() && s.size() < 240; ++i) {
        const unsigned char c = d[i];
        if (c == 0) break;
        if (c == '\n') s += "\\n";
        else if (c == '\t') s += "\\t";
        else if (c == '\r') s += "\\r";
        else if (c >= 0x20 && c < 0x7f) s.push_back(static_cast<char>(c));
        else if (c >= 0x80) s.push_back(static_cast<char>(c));  // UTF-8 bytes
        else return {};
    }
    if (s.size() < 2) return {};
    return s;
}

std::string NativeCode::wideStringAt(uint64_t vaddr) const {
    uint64_t off = 0;
    if (!elf_->vaddrToOffset(vaddr, off)) return {};
    const auto& d = elf_->data();
    std::string s;
    size_t chars = 0, latin = 0;
    for (uint64_t i = off; i + 1 < d.size() && s.size() < 240; i += 2) {
        uint32_t c = static_cast<uint32_t>(d[i]) | static_cast<uint32_t>(d[i + 1]) << 8;
        if (c == 0) break;
        if (c >= 0xD800 && c < 0xDC00 && i + 3 < d.size()) {  // surrogate pair
            const uint32_t lo = static_cast<uint32_t>(d[i + 2]) | static_cast<uint32_t>(d[i + 3]) << 8;
            if (lo < 0xDC00 || lo >= 0xE000) return {};
            c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
            i += 2;
        } else if (c >= 0xD800 && c < 0xE000) {
            return {};
        }
        if (c == '\n') s += "\\n";
        else if (c == '\t') s += "\\t";
        else if (c == '\r') s += "\\r";
        else if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || c == 0xFFFE || c == 0xFFFF) return {};
        else if (c < 0x80) s.push_back(static_cast<char>(c));
        else if (c < 0x800) s += static_cast<char>(0xC0 | (c >> 6)), s += static_cast<char>(0x80 | (c & 0x3F));
        else if (c < 0x10000)
            s += static_cast<char>(0xE0 | (c >> 12)), s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
        else
            s += static_cast<char>(0xF0 | (c >> 18)), s += static_cast<char>(0x80 | ((c >> 12) & 0x3F)),
                s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
        ++chars;
        if (c < 0x250) ++latin;
    }
    if (chars < 2 || latin * 3 < chars * 2) return {};  // random bytes read as UTF-16 give CJK soup: want mostly Latin text
    return s;
}

std::string NativeCode::wide32StringAt(uint64_t vaddr) const {
    uint64_t off = 0;
    if (!elf_->vaddrToOffset(vaddr, off)) return {};
    const auto& d = elf_->data();
    std::string s;
    size_t chars = 0, latin = 0;
    for (uint64_t i = off; i + 3 < d.size() && s.size() < 240; i += 4) {
        const uint32_t c = static_cast<uint32_t>(d[i]) | static_cast<uint32_t>(d[i + 1]) << 8 | static_cast<uint32_t>(d[i + 2]) << 16 |
                           static_cast<uint32_t>(d[i + 3]) << 24;
        if (c == 0) break;
        if (c == '\n') s += "\\n";
        else if (c == '\t') s += "\\t";
        else if (c == '\r') s += "\\r";
        else if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || (c >= 0xD800 && c < 0xE000) || c > 0x10FFFF) return {};
        else if (c < 0x80) s.push_back(static_cast<char>(c));
        else if (c < 0x800) s += static_cast<char>(0xC0 | (c >> 6)), s += static_cast<char>(0x80 | (c & 0x3F));
        else if (c < 0x10000)
            s += static_cast<char>(0xE0 | (c >> 12)), s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
        else
            s += static_cast<char>(0xF0 | (c >> 18)), s += static_cast<char>(0x80 | ((c >> 12) & 0x3F)),
                s += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), s += static_cast<char>(0x80 | (c & 0x3F));
        ++chars;
        if (c < 0x250) ++latin;
    }
    if (chars < 2 || latin * 3 < chars * 2) return {};
    return s;
}

std::string NativeCode::stringAt(uint64_t vaddr, bool* wide, bool* utf32) const {
    if (wide) *wide = false;
    if (utf32) *utf32 = false;
    for (const Range& r : code_)
        if (vaddr >= r.vaddr && vaddr < r.vaddr + r.size) return {};  // code is not text
    std::string s = cStringAt(vaddr);
    if (!s.empty()) return s;
    s = wideStringAt(vaddr);
    if (!s.empty()) {
        if (wide) *wide = true;
        return s;
    }
    s = wide32StringAt(vaddr);
    if (!s.empty()) {
        if (wide) *wide = true;
        if (utf32) *utf32 = true;
    }
    return s;
}

std::vector<NativeCode::Line> NativeCode::disassemble(uint64_t start, uint64_t end, size_t maxInsns) const {
    return isa_ == Isa::Arm64 ? disassembleArm64(start, end, maxInsns) : disassembleGeneric(start, end, maxInsns);
}

namespace {
size_t boundBefore(const std::vector<NativeCode::Line>& lines, size_t at, std::string* compared = nullptr);
}  // namespace

std::vector<NativeCode::Line> NativeCode::disassembleGeneric(uint64_t start, uint64_t end, size_t maxInsns) const {
    std::vector<Line> out;
    DataState st;
    uint64_t a = isa_ == Isa::Arm32 ? start & ~1ull : start;
    // Words that pc-relative loads read: literal pools, data even where no $d mapping symbol says so (decoding them
    // would knock the Thumb stream out of step).
    std::unordered_set<uint64_t> literals;
    while (a < end && out.size() < maxInsns) {
        char mode = isa_ == Isa::Arm32 ? modeAtAddr(a) : 't';
        if (isa_ == Isa::Arm32 && literals.count(a)) mode = 'd';
        Line l;
        if (mode == 'd') {  // literal pool data between ARM / Thumb code
            uint32_t w = 0;
            if (!readData32(a, w)) break;
            l.insn.addr = a;
            l.insn.raw = w;
            l.insn.size = 4;
            l.insn.mnemonic = ".word";
            l.insn.operands = hex(w);
            l.insn.known = false;
            out.push_back(std::move(l));
            a += 4;
            continue;
        }
        l.insn = decodeAt(a, mode == 't');
        const native::Insn& in = l.insn;
        if (in.size == 0) break;
        uint64_t data = 0;
        bool read = false;
        const bool tracked = dataRef(in, st, data, read);
        if (in.hasTarget && !in.memTarget && in.flow != native::Flow::Normal) {
            l.targetName = symbolize(in.target);
        } else if (tracked) {
            annotate(l, data, read);
        } else if (in.memTarget) {
            uint32_t literal = 0;
            if (isa_ == Isa::Arm32 && startsWith(in.mnemonic, "ldr") && readData32(in.target, literal)) {
                l.dataAddr = in.target;
                l.dataRead = true;
                l.comment = "=" + hex(literal);
                if (in.target > a && in.target < end) {
                    literals.insert(in.target);
                    if (in.mnemonic.rfind("ldrd", 0) == 0) literals.insert(in.target + 4);
                }
            } else {
                if (isa_ == Isa::Arm32 && in.mnemonic.rfind("vldr", 0) == 0 && in.target > a && in.target < end) {  // a double constant
                    literals.insert(in.target);
                    if (in.operands.rfind("d", 0) == 0) literals.insert(in.target + 4);
                }
                annotate(l, in.target, !in.isAddImm);
            }
        }
        l.dataRead = l.dataAddr != 0 && (in.isLoad || in.memTarget) && !in.isAddImm;
        if (in.memTarget) l.insn.hasTarget = false;  // a memory operand, not somewhere to jump
        const uint64_t step = in.size;
        const bool dispatch = isa_ == Isa::Arm32 && (in.mnemonic == "tbb" || in.mnemonic == "tbh") && in.operands.find("[pc") == 0;
        const unsigned entry = in.mnemonic == "tbh" ? 2 : 1;
        out.push_back(std::move(l));
        a += step;
        // The table follows the instruction: show it as data instead of decoding it.
        if (dispatch) {
            const size_t bytes = (boundBefore(out, out.size() - 1) * entry + 1) & ~size_t(1);
            for (size_t at = 0; at < bytes && a < end && out.size() < maxInsns; at += 2, a += 2) {
                uint32_t w = 0;
                if (!readData32(a, w)) break;
                Line entryLine;
                entryLine.insn.addr = a;
                entryLine.insn.raw = w & 0xFFFF;
                entryLine.insn.size = 2;
                entryLine.insn.mnemonic = ".short";
                entryLine.insn.operands = hex(w & 0xFFFF);
                entryLine.insn.known = false;
                entryLine.insn.thumb = true;
                out.push_back(std::move(entryLine));
            }
        }
    }
    std::unordered_set<uint64_t> targets;
    for (const Line& l : out)
        if (l.insn.hasTarget && (l.insn.flow == native::Flow::Jump || l.insn.flow == native::Flow::CondJump)) targets.insert(l.insn.target);
    for (Line& l : out) l.label = targets.count(l.insn.addr) != 0;
    return out;
}

std::vector<NativeCode::Line> NativeCode::disassembleArm64(uint64_t start, uint64_t end, size_t maxInsns) const {
    std::vector<Line> out;
    struct Page {
        uint64_t value = 0;
        size_t at = 0;
        bool valid = false;
    } pages[32];
    for (uint64_t a = start & ~3ull; a < end && out.size() < maxInsns; a += 4) {
        uint32_t w = 0;
        if (!readWord(a, w)) break;
        Line l;
        l.insn = arm64::decode(w, a);
        const arm64::Insn& in = l.insn;
        const size_t idx = out.size();
        uint64_t data = 0;
        if (in.pageReg >= 0) {
            pages[in.pageReg] = {in.target, idx, true};
        } else if ((in.isAddImm || in.isLoad) && in.baseReg >= 0 && pages[in.baseReg].valid &&
                   idx - pages[in.baseReg].at <= kPageWindow) {
            data = pages[in.baseReg].value + static_cast<uint64_t>(in.offset);
        } else if (in.hasTarget && (in.mnemonic == "adr" || in.isLoad)) {
            data = in.target;
        }
        l.dataRead = data && in.isLoad;
        if (in.destReg >= 0 && in.pageReg < 0) pages[in.destReg].valid = false;
        if (in.flow == arm64::Flow::Call)
            for (unsigned k = 0; k < 18; ++k) pages[k].valid = false;
        if (in.hasTarget && in.flow != arm64::Flow::Normal) {
            l.targetName = symbolize(in.target);
        } else if (data) {
            l.dataAddr = data;
            // A load reads a value (pointer, constant) from data: only address-forming instructions can
            // point at a string literal.
            bool wide = false, utf32 = false;
            const std::string str = l.dataRead ? std::string() : stringAt(data, &wide, &utf32);
            if (!str.empty()) l.comment = (utf32 ? "U\"" : wide ? "u\"" : "\"") + str + "\"";  // u"..." UTF-16, U"..." UTF-32
            else if (std::string sym = symbolize(data); !sym.empty()) l.comment = l.dataRead ? "[" + sym + "]" : sym;
            else l.comment = l.dataRead ? "[" + hex(data) + "]" : hex(data);
        }
        out.push_back(std::move(l));
    }
    // Mark local branch targets.
    std::unordered_set<uint64_t> targets;
    for (const Line& l : out)
        if (l.insn.hasTarget && (l.insn.flow == arm64::Flow::Jump || l.insn.flow == arm64::Flow::CondJump))
            targets.insert(l.insn.target);
    for (Line& l : out) l.label = targets.count(l.insn.addr) != 0;
    return out;
}

std::vector<NativeCode::Line> NativeCode::disassembleFunction(const Function& f, size_t maxInsns) const {
    return disassemble(f.addr, f.addr + std::max<uint64_t>(f.size, 4), maxInsns);
}

namespace {

// "[x9, x8, lsl #2]" / "[pc, r6]" / "[ebx+esi*4-0x19484]": the pieces between the brackets.
std::string bracketed(const std::string& operands) {
    const size_t open = operands.find('['), close = operands.rfind(']');
    return open == std::string::npos || close == std::string::npos || close < open ? std::string() : operands.substr(open + 1, close - open - 1);
}

std::vector<std::string> operandList(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    for (char c : s) {
        if (c == '[') ++depth;
        if (c == ']') --depth;
        if (c == ',' && depth == 0) {
            out.push_back(cur);
            cur.clear();
        } else if (c != ' ' || !cur.empty()) {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// "x8" and "w8" are one register, as are "rax" and "eax".
std::string regKey(const std::string& r) {
    if (r.size() > 1 && (r[0] == 'x' || r[0] == 'w') && std::isdigit(static_cast<unsigned char>(r[1]))) return "x" + r.substr(1);
    if (r.size() == 3 && (r[0] == 'e' || r[0] == 'r') && std::isalpha(static_cast<unsigned char>(r[1]))) return r.substr(1);
    return r;
}

// The number of entries the bounds check before line `at` allows ("cmp i, #N; b.hi default"): 0 when there is none.
// `compared` receives the register that was checked.
size_t boundBefore(const std::vector<NativeCode::Line>& lines, size_t at, std::string* compared) {
    for (size_t i = at, steps = 0; i-- > 0 && steps < 40; ++steps) {
        if (lines[i].insn.mnemonic != "cmp" && lines[i].insn.mnemonic != "cmp.w") continue;
        const std::vector<std::string> ops = operandList(lines[i].insn.operands);
        if (ops.size() != 2) return 0;
        std::string imm = ops[1];
        if (!imm.empty() && imm[0] == '#') imm.erase(0, 1);
        if (imm.empty() || !std::isdigit(static_cast<unsigned char>(imm[0]))) return 0;
        const unsigned long long n = std::strtoull(imm.c_str(), nullptr, 0);
        if (n > 1023) return 0;
        if (compared) *compared = ops[0];
        for (size_t k = i + 1; k < at && k < i + 6; ++k) {
            std::string m = lines[k].insn.mnemonic;
            if (m.size() > 2 && m.compare(m.size() - 2, 2, ".w") == 0) m.erase(m.size() - 2);
            if (m == "b.hi" || m == "bhi" || m == "ja") return static_cast<size_t>(n) + 1;
            if (m == "b.hs" || m == "b.cs" || m == "bhs" || m == "bcs" || m == "jae") return static_cast<size_t>(n);
        }
        // A32: the dispatch itself is conditional ("cmp r0, #N; ldrls pc, [pc, r0, lsl #2]").
        const std::string& own = lines[at].insn.mnemonic;
        if (own.size() > 2 && own.compare(own.size() - 2, 2, "ls") == 0) return static_cast<size_t>(n) + 1;
        if (own.size() > 2 && (own.compare(own.size() - 2, 2, "lo") == 0 || own.compare(own.size() - 2, 2, "cc") == 0)) return static_cast<size_t>(n);
        return 0;
    }
    return 0;
}

// The nearest earlier instruction whose first operand is register `reg` (and that is not a compare or a store).
const NativeCode::Line* writerOf(const std::vector<NativeCode::Line>& lines, size_t before, const std::string& reg, size_t& index,
                                 size_t window = 80) {
    const std::string key = regKey(reg);
    for (size_t i = before, steps = 0; i-- > 0 && steps < window; ++steps) {
        const std::string& m = lines[i].insn.mnemonic;
        if (m == "cmp" || m == "test" || m.rfind("st", 0) == 0 || m == "push") continue;
        const std::vector<std::string> ops = operandList(lines[i].insn.operands);
        if (!ops.empty() && regKey(ops[0]) == key) {
            index = i;
            return &lines[i];
        }
    }
    return nullptr;
}

}  // namespace

bool NativeCode::tailJump(const std::vector<Line>& lines, size_t at) const {
    if (at >= lines.size() || lines[at].insn.flow != native::Flow::IndirectJump) return false;
    const native::Insn& jump = lines[at].insn;
    const std::vector<std::string> ops = operandList(jump.operands);
    if (ops.size() != 1) return false;
    if (jump.mnemonic == "bx") return true;  // ARM switches use tbb / ldr pc / mov pc, never bx
    if (jump.mnemonic != "br" && jump.mnemonic != "jmp") return false;
    if (ops[0].find('[') != std::string::npos) return ops[0].find("*4") == std::string::npos && ops[0].find("*8") == std::string::npos;
    // A register that was simply loaded (a vtable slot, a callback) or came in as a parameter; a switch computes it.
    size_t i = 0;
    const Line* writer = writerOf(lines, at, ops[0], i);
    if (!writer) return true;
    const std::string& m = writer->insn.mnemonic;
    const bool load = m == "ldr" || m == "ldur" || m == "ldp" || (m == "mov" && writer->insn.operands.find("*4") == std::string::npos);
    return load;
}

bool NativeCode::jumpTable(const std::vector<Line>& lines, size_t at, std::vector<uint64_t>& targets, std::string& index) const {
    targets.clear();
    if (at >= lines.size()) return false;
    const native::Insn& jump = lines[at].insn;
    const std::vector<std::string> ops = operandList(jump.operands);
    std::string compared;
    size_t count = boundBefore(lines, at, &compared);
    if (ops.empty()) return false;
    // No bounds check (an index from a bit scan, or compared with a register): read entries until one does not land
    // on an instruction of this function.
    const bool probe = count < 2;
    if (probe) count = 64;
    // Every entry must land on an instruction of this listing; when probing, the first that does not ends the table.
    const auto onInstruction = [&](uint64_t target) {
        const auto found = std::lower_bound(lines.begin(), lines.end(), target, [](const Line& l, uint64_t v) { return l.insn.addr < v; });
        return found != lines.end() && found->insn.addr == target;
    };

    uint64_t table = 0, base = 0;
    unsigned size = 4, scale = 1;
    bool sign = false;
    // The value of the register that holds the table's address.
    const auto addressIn = [&](const std::string& reg, size_t before, uint64_t& value) {
        size_t i = 0;
        const Line* l = writerOf(lines, before, reg, i, 3000);  // a table address kept in a register through a loop
        if (!l) return false;
        const std::string& m = l->insn.mnemonic;
        if ((m == "add" || m == "adr" || m == "lea") && l->dataAddr) value = l->dataAddr;
        else if (m == "adr" && l->insn.target) value = l->insn.target;
        else return false;
        return true;
    };

    if (isa_ == Isa::Arm32 && jump.mnemonic == "mov" && ops.size() == 2 && ops[0] == "pc") {
        size_t addAt = 0, adrAt = 0;
        const Line* add = writerOf(lines, at, ops[1], addAt);
        if (!add || add->insn.mnemonic.rfind("add", 0) != 0) return false;
        const std::vector<std::string> a = operandList(add->insn.operands);
        if (a.size() != 4 || a[3] != "lsl #2") return false;
        const Line* adr = writerOf(lines, addAt, a[1], adrAt);
        if (!adr || adr->insn.mnemonic.rfind("adr", 0) != 0) return false;
        const uint64_t start = adr->dataAddr ? adr->dataAddr : adr->insn.target;
        if (probe) return false;  // a branch table of b instructions: only with its bounds check
        index = compared;
        for (size_t i = 0; i < count; ++i) {
            const uint64_t target = start + 4 * i;
            if (!onInstruction(target)) return false;
            targets.push_back(target);
        }
        return true;
    }
    // ldr pc, [pc, rN, lsl #2]: a table of absolute addresses right after the instruction (A32 pc + 8, Thumb aligned + 4).
    if (isa_ == Isa::Arm32 && jump.mnemonic.rfind("ldr", 0) == 0 && ops.size() == 2 && ops[0] == "pc" && !probe) {
        const std::vector<std::string> inner = operandList(bracketed(jump.operands));
        if (inner.size() != 3 || inner[0] != "pc" || inner[2] != "lsl #2") return false;
        const uint64_t start = jump.thumb ? ((jump.addr + 4) & ~uint64_t(3)) : jump.addr + 8;
        for (size_t i = 0; i < count; ++i) {
            uint32_t word = 0;
            if (!readData32(start + 4 * i, word)) return false;
            const uint64_t target = word & ~1u;
            if (!onInstruction(target)) return false;
            targets.push_back(target);
        }
        index = compared.empty() ? inner[1] : compared;
        return true;
    }
    if (isa_ == Isa::Arm32) {
        if (jump.mnemonic != "tbb" && jump.mnemonic != "tbh") return false;
        const std::vector<std::string> inner = operandList(bracketed(jump.operands));
        if (inner.size() < 2 || inner[0] != "pc") return false;
        index = inner[1];
        table = base = jump.addr + 4;
        size = jump.mnemonic == "tbh" ? 2 : 1;
        scale = 2;
    } else {
        if (jump.mnemonic != (isa_ == Isa::Arm64 ? "br" : "jmp") || ops.size() != 1 || ops[0].find('[') != std::string::npos) return false;
        size_t addAt = 0;
        const Line* add = writerOf(lines, at, ops[0], addAt);
        if (!add) return false;
        std::vector<std::string> a = operandList(add->insn.operands);
        // lea rcx, [r11+rcx] adds as well.
        if (add->insn.mnemonic == "lea" && isa_ != Isa::Arm64 && a.size() == 2) {
            const std::string sum = bracketed(a[1]);
            const size_t plus = sum.find('+');
            if (plus == std::string::npos || sum.find_first_of("*-", plus) != std::string::npos) return false;
            a = {sum.substr(0, plus), sum.substr(plus + 1)};
            if (regKey(a[0]) == regKey(ops[0])) std::swap(a[0], a[1]);  // the loaded offset first
            if (regKey(a[0]) != regKey(ops[0])) {
                // lea rcx, [r11+rax]: neither is the destination; the loaded one is whichever a movsxd wrote.
                size_t k = 0;
                const Line* w = writerOf(lines, addAt, a[1], k);
                if (w && w->insn.mnemonic.rfind("mov", 0) == 0) std::swap(a[0], a[1]);
            }
        } else if (add->insn.mnemonic != "add") {
            return false;
        }
        if (isa_ == Isa::Arm64) {
            if (a.size() < 3) return false;
            // add x, loaded, base  |  add x, base, loaded, sxtb #2
            const bool shifted = a.size() == 4;
            const std::string loaded = shifted ? a[2] : a[1], baseReg = shifted ? a[1] : a[2];
            size_t loadAt = 0;
            const Line* load = writerOf(lines, addAt, loaded, loadAt);
            if (!load || load->insn.mnemonic.rfind("ldr", 0) != 0) return false;
            const std::vector<std::string> inner = operandList(bracketed(load->insn.operands));
            if (inner.size() < 2) return false;
            const std::string& m = load->insn.mnemonic;
            size = m == "ldrsw" || m == "ldr" ? 4 : m == "ldrh" || m == "ldrsh" ? 2 : 1;
            sign = m == "ldrsw" || m == "ldrsb" || m == "ldrsh" || (shifted && a[3].rfind("sxt", 0) == 0);
            if (shifted) scale = 4;
            index = inner[1];
            if (!addressIn(inner[0], loadAt, table) || !addressIn(baseReg, addAt, base)) return false;
            if (inner[0] == loaded && !addressIn(baseReg, addAt, table)) return false;
        } else {
            if (a.size() != 2) return false;
            size_t loadAt = 0;
            const Line* load = writerOf(lines, addAt, a[0], loadAt);
            if (!load || load->insn.mnemonic.rfind("mov", 0) != 0) return false;
            const std::string address = bracketed(load->insn.operands);
            const size_t star = address.find("*4");
            if (star == std::string::npos) return false;
            const size_t first = address.find('+');
            if (first == std::string::npos || first >= star) return false;
            const std::string baseReg = address.substr(0, first);
            index = address.substr(first + 1, star - first - 1);
            const std::string rest = address.substr(star + 2);
            const long long disp = rest.empty() ? 0 : std::strtoll(rest.c_str(), nullptr, 0);
            sign = true;
            if (isa_ == Isa::X86_64) {
                if (regKey(a[1]) != regKey(baseReg) || !addressIn(baseReg, loadAt, table)) return false;
                table += static_cast<uint64_t>(disp);
                base = table;
            } else {  // position-independent i386: the table and its entries are relative to the GOT base
                if (regKey(a[1]) != regKey(baseReg) || !gotBase_) return false;
                table = (gotBase_ + static_cast<uint64_t>(disp)) & 0xFFFFFFFFull;
                base = gotBase_;
            }
        }
    }

    for (size_t i = 0; i < count; ++i) {
        const uint64_t entry = table + i * size;
        uint32_t word = 0;
        if (!readData32(entry & ~uint64_t(3), word)) return false;
        uint32_t high = 0;
        if ((entry & 3) + size > 4 && !readData32((entry & ~uint64_t(3)) + 4, high)) return false;
        const uint64_t both = static_cast<uint64_t>(high) << 32 | word;
        uint64_t value = both >> ((entry & 3) * 8);
        value &= size == 4 ? 0xFFFFFFFFull : (1ull << (size * 8)) - 1;
        if (sign && (value >> (size * 8 - 1)) & 1) value |= ~0ull << (size * 8);
        uint64_t target = base + value * scale;
        if (isa_ == Isa::X86 || isa_ == Isa::Arm32) target &= 0xFFFFFFFFull;
        if (!onInstruction(target)) {
            if (probe && targets.size() >= 2) break;
            return false;
        }
        targets.push_back(target);
    }
    if (probe && targets.size() < 2) return false;
    if (!compared.empty()) index = compared;
    return true;
}

NativeCode::ControlFlow NativeCode::controlFlow(const Function& f, size_t maxInsns) const {
    using arm64::Flow;
    ControlFlow cfg;
    cfg.lines = disassembleFunction(f, maxInsns);
    const size_t n = cfg.lines.size();
    if (!n) return cfg;
    const auto lineOf = [&](uint64_t addr) -> int {
        auto it = std::lower_bound(cfg.lines.begin(), cfg.lines.end(), addr, [](const Line& l, uint64_t a) { return l.insn.addr < a; });
        return it != cfg.lines.end() && it->insn.addr == addr ? static_cast<int>(it - cfg.lines.begin()) : -1;
    };
    const auto ends = [](Flow flow) { return flow != Flow::Normal && flow != Flow::Call && flow != Flow::IndirectCall; };
    std::vector<char> leader(n, 0);
    leader[0] = 1;
    std::map<size_t, std::vector<uint64_t>> tables;  // line of the dispatching jump -> targets
    for (size_t i = 0; i < n; ++i) {
        const arm64::Insn& in = cfg.lines[i].insn;
        if (!ends(in.flow)) continue;
        std::vector<uint64_t> targets;
        std::string index;
        if (in.flow == Flow::IndirectJump && jumpTable(cfg.lines, i, targets, index)) {
            for (uint64_t t : targets)
                if (const int line = lineOf(t); line >= 0) leader[static_cast<size_t>(line)] = 1;
            tables[i] = std::move(targets);
        }
        if (i + 1 < n) leader[i + 1] = 1;
        if (in.hasTarget)
            if (const int t = lineOf(in.target); t >= 0) leader[static_cast<size_t>(t)] = 1;
    }
    std::vector<int> blockOf(n, 0);
    for (size_t i = 0; i < n; ++i) {
        if (leader[i]) {
            BasicBlock b;
            b.firstLine = i;
            cfg.blocks.push_back(b);
        }
        blockOf[i] = static_cast<int>(cfg.blocks.size()) - 1;
        ++cfg.blocks.back().lineCount;
    }
    for (size_t b = 0; b < cfg.blocks.size(); ++b) {
        BasicBlock& block = cfg.blocks[b];
        const size_t last = block.firstLine + block.lineCount - 1;
        const arm64::Insn& in = cfg.lines[last].insn;
        const int next = last + 1 < n ? blockOf[last + 1] : -1;
        const int target = in.hasTarget ? lineOf(in.target) : -1;
        switch (in.flow) {
        case Flow::Jump:
            if (target >= 0) block.successors.push_back(blockOf[static_cast<size_t>(target)]);
            else block.exit = true;  // tail call
            break;
        case Flow::CondJump:
            if (target >= 0) block.successors.push_back(blockOf[static_cast<size_t>(target)]);
            if (next >= 0) block.successors.push_back(next);
            block.conditional = block.successors.size() == 2;
            break;
        case Flow::IndirectJump:
            if (const auto table = tables.find(last); table != tables.end()) {
                for (size_t k = 0; k < table->second.size(); ++k) {
                    const int line = lineOf(table->second[k]);
                    if (line < 0) continue;
                    const int to = blockOf[static_cast<size_t>(line)];
                    block.cases.push_back({static_cast<int64_t>(k), to});
                    if (std::find(block.successors.begin(), block.successors.end(), to) == block.successors.end()) block.successors.push_back(to);
                }
                break;
            }
            block.exit = true;
            break;
        case Flow::Return:
        case Flow::Trap: block.exit = true; break;
        default:
            if (next >= 0) block.successors.push_back(next);
            else block.exit = true;
            break;
        }
    }
    return cfg;
}

std::vector<NativeCode::Ref> NativeCode::refsTo(uint64_t addr, size_t limit) const {
    std::vector<Ref> out;
    auto it = std::lower_bound(refs_.begin(), refs_.end(), addr, [](const Ref& r, uint64_t a) { return r.target < a; });
    for (; it != refs_.end() && it->target == addr && out.size() < limit; ++it) out.push_back(*it);
    return out;
}

std::vector<NativeCode::Ref> NativeCode::refsFrom(const Function& f, size_t limit) const {
    std::vector<Ref> out;
    for (const Line& l : disassembleFunction(f, 200000)) {
        if (out.size() >= limit) break;
        if (l.insn.flow == arm64::Flow::Call && l.insn.hasTarget) out.push_back({l.insn.target, l.insn.addr, RefKind::Call});
        else if (l.insn.flow == arm64::Flow::Jump && l.insn.hasTarget &&
                 (l.insn.target < f.addr || l.insn.target >= f.addr + f.size))
            out.push_back({l.insn.target, l.insn.addr, RefKind::Jump});  // tail call
        else if (l.dataAddr) out.push_back({l.dataAddr, l.insn.addr, l.dataRead ? RefKind::Read : RefKind::Data});
    }
    return out;
}

std::vector<NativeCode::StringRef> NativeCode::stringRefs(const std::string& filter, size_t limit) const {
    std::vector<StringRef> out;
    uint64_t last = UINT64_MAX;
    std::string text;
    const char* encoding = "utf-8";
    for (const Ref& r : refs_) {
        if (out.size() >= limit) break;
        if (r.kind != RefKind::Data) continue;
        if (r.target != last) {
            last = r.target;
            bool wide = false, utf32 = false;
            text = stringAt(r.target, &wide, &utf32);
            encoding = utf32 ? "utf-32le" : wide ? "utf-16le" : "utf-8";
        }
        if (text.empty() || (!filter.empty() && tex::ciFind(text, filter) == std::string_view::npos)) continue;
        out.push_back({r.target, r.from, text, encoding});
    }
    return out;
}
