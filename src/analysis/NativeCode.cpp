#include "analysis/NativeCode.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unordered_set>
#include "core/TextUtils.hpp"

namespace {
constexpr uint16_t EM_AARCH64 = 183;
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

std::string machineLabel(uint16_t m) {
    switch (m) {
    case 40: return "32-bit ARM (armeabi-v7a)";
    case 3: return "x86";
    case 62: return "x86-64";
    default: return "machine " + std::to_string(m);
    }
}
}  // namespace

std::shared_ptr<NativeCode> NativeCode::build(std::shared_ptr<const ElfFile> elf, const std::atomic<bool>* cancel,
                                              std::string& error) {
    if (!elf) {
        error = "no ELF";
        return nullptr;
    }
    if (elf->machine() != EM_AARCH64 || !elf->is64() || !elf->littleEndian()) {
        error = "disassembly supports AArch64 (arm64-v8a) libraries; this one is " + machineLabel(elf->machine()) +
                ". Open the arm64-v8a copy of the library if the APK ships one.";
        return nullptr;
    }
    std::shared_ptr<NativeCode> nc(new NativeCode());
    nc->elf_ = std::move(elf);
    for (const auto& s : nc->elf_->sections())
        if ((s.flags & SHF_EXECINSTR) && s.type != SHT_NOBITS && s.size >= 4 && s.offset + s.size <= nc->elf_->data().size())
            nc->code_.push_back({s.addr, s.size & ~3ull, s.offset});
    if (nc->code_.empty())  // no section table (stripped / packed): fall back to executable segments
        for (const auto& s : nc->elf_->segments())
            if (s.type == PT_LOAD && (s.flags & 1) && s.filesz >= 4 && s.offset + s.filesz <= nc->elf_->data().size())
                nc->code_.push_back({s.vaddr, s.filesz & ~3ull, s.offset});
    if (nc->code_.empty()) {
        error = "no executable code found";
        return nullptr;
    }
    std::sort(nc->code_.begin(), nc->code_.end(), [](const Range& a, const Range& b) { return a.vaddr < b.vaddr; });
    for (const auto& r : nc->elf_->relocations())
        if (r.type == R_AARCH64_JUMP_SLOT || r.type == R_AARCH64_GLOB_DAT) nc->gotNames_.emplace_back(r.offset, r.symbol);
    std::sort(nc->gotNames_.begin(), nc->gotNames_.end());
    nc->sweep(cancel);
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
        f.size = s.size;
        f.name = s.name;
        f.exported = s.dynamic && s.binding != 0;
        fns.push_back(std::move(f));
    }
    // PLT stubs: adrp x16, page ; ldr x17, [x16, #off] -> the GOT slot names the import.
    for (const auto& sec : elf_->sections()) {
        if (sec.name != ".plt" && sec.name != ".plt.sec") continue;
        for (uint64_t a = sec.addr; a + 8 <= sec.addr + sec.size; a += 4) {
            uint32_t w1 = 0, w2 = 0;
            if (!readWord(a, w1) || !readWord(a + 4, w2)) break;
            if ((w1 & 0x9f00001f) != 0x90000010 || (w2 & 0xffc003ff) != 0xf9400211) continue;
            const arm64::Insn page = arm64::decode(w1, a);
            const uint64_t got = page.target + (((w2 >> 10) & 0xfff) << 3);
            auto it = std::lower_bound(gotNames_.begin(), gotNames_.end(), std::make_pair(got, std::string()));
            if (it == gotNames_.end() || it->first != got) continue;
            Function f;
            f.addr = a;
            f.size = 16;
            f.name = it->second + "@plt";
            f.kind = FunctionKind::Plt;
            fns.push_back(std::move(f));
            a += 12;
        }
    }
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

std::vector<NativeCode::Line> NativeCode::disassemble(uint64_t start, uint64_t end, size_t maxInsns) const {
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
            const std::string str = l.dataRead ? std::string() : cStringAt(data);
            if (!str.empty()) l.comment = "\"" + str + "\"";
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

NativeCode::ControlFlow NativeCode::controlFlow(const Function& f, size_t maxInsns) const {
    using arm64::Flow;
    ControlFlow cfg;
    cfg.lines = disassembleFunction(f, maxInsns);
    const size_t n = cfg.lines.size();
    if (!n) return cfg;
    const uint64_t first = cfg.lines.front().insn.addr;
    const auto lineOf = [&](uint64_t addr) -> int {
        if (addr < first || (addr - first) % 4) return -1;
        const uint64_t i = (addr - first) / 4;
        return i < n ? static_cast<int>(i) : -1;
    };
    const auto ends = [](Flow flow) { return flow != Flow::Normal && flow != Flow::Call && flow != Flow::IndirectCall; };
    std::vector<char> leader(n, 0);
    leader[0] = 1;
    for (size_t i = 0; i < n; ++i) {
        const arm64::Insn& in = cfg.lines[i].insn;
        if (!ends(in.flow)) continue;
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
        case Flow::Return:
        case Flow::Trap:
        case Flow::IndirectJump: block.exit = true; break;
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
    for (const Ref& r : refs_) {
        if (out.size() >= limit) break;
        if (r.kind != RefKind::Data) continue;
        if (r.target != last) {
            last = r.target;
            text = cStringAt(r.target);
        }
        if (text.empty() || (!filter.empty() && tex::ciFind(text, filter) == std::string_view::npos)) continue;
        out.push_back({r.target, r.from, text});
    }
    return out;
}
