#include "analysis/Arm32.hpp"
#include <cstdio>

namespace arm32 {
namespace {

uint16_t half(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

std::string hex(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%x", v);
    return buf;
}

std::string reg(unsigned r) {
    static const char* names[16] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                                    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
    return names[r & 15];
}

std::string regs(uint32_t list) {
    std::string out;
    for (unsigned i = 0; i < 16; ++i) {
        if (!(list & (1u << i))) continue;
        if (!out.empty()) out += ", ";
        out += reg(i);
    }
    return "{" + out + "}";
}

int32_t signExtend(uint32_t v, unsigned bits) {
    const uint32_t m = 1u << (bits - 1);
    return static_cast<int32_t>((v ^ m) - m);
}

// PC reads as the instruction address + 8 (A32) or + 4 (Thumb).
uint64_t pcValue(uint64_t addr, bool thumb) { return addr + (thumb ? 4 : 8); }

uint64_t relative(uint64_t base, int32_t offset) {
    return static_cast<uint64_t>(static_cast<int64_t>(base) + offset) & 0xFFFFFFFFull;  // 32-bit address space
}

void setBranch(Insn& in, uint64_t target, Flow flow) {
    in.hasTarget = true;
    in.target = target;
    in.operands = hex(static_cast<uint32_t>(target));
    in.flow = flow;
}

Insn unknown16(Insn in, uint16_t h) {
    in.known = false;
    char buf[24];
    std::snprintf(buf, sizeof buf, ".hword 0x%04x", h);
    in.mnemonic = buf;
    return in;
}

Insn thumb16(uint16_t h, uint64_t addr) {
    Insn in;
    in.addr = addr;
    in.raw = h;
    in.size = 2;
    in.thumb = true;
    const uint32_t r = h;
    // 000 op imm5 Rm Rd: lsls / lsrs / asrs (op 11 is add/sub below).
    if ((r & 0xE000) == 0x0000 && ((r >> 11) & 3) != 3) {
        static const char* ops[] = {"lsls", "lsrs", "asrs"};
        const unsigned imm = (r >> 6) & 0x1F;
        if (((r >> 11) & 3) == 0 && imm == 0) {  // lsls #0 is movs rd, rm
            in.mnemonic = "movs";
            in.operands = reg(r & 7) + ", " + reg((r >> 3) & 7);
            return in;
        }
        in.mnemonic = ops[(r >> 11) & 3];
        in.operands = reg(r & 7) + ", " + reg((r >> 3) & 7) + ", #" + std::to_string(imm);
        return in;
    }
    if ((r & 0xF800) == 0x1800) {  // adds / subs (register or 3-bit immediate)
        const bool imm = (r & 0x0400) != 0;
        in.mnemonic = (r & 0x0200) ? "subs" : "adds";
        in.operands = reg(r & 7) + ", " + reg((r >> 3) & 7) + ", " +
                      (imm ? "#" + std::to_string((r >> 6) & 7) : reg((r >> 6) & 7));
        return in;
    }
    if ((r & 0xE000) == 0x2000) {  // movs / cmp / adds / subs with an 8-bit immediate
        static const char* ops[] = {"movs", "cmp", "adds", "subs"};
        in.mnemonic = ops[(r >> 11) & 3];
        in.operands = reg((r >> 8) & 7) + ", #" + std::to_string(r & 0xFF);
        return in;
    }
    if ((r & 0xFF00) == 0x4600) {  // mov (high registers)
        const unsigned rd = (r & 7) | ((r >> 4) & 8);
        const unsigned rm = (r >> 3) & 0xF;
        in.mnemonic = "mov";
        in.operands = reg(rd) + ", " + reg(rm);
        if (rd == 15) in.flow = rm == 14 ? Flow::Return : Flow::IndirectJump;
        return in;
    }
    if ((r & 0xFF07) == 0x4700) {  // bx / blx rm (bit 7 = link)
        const bool link = (r & 0x0080) != 0;
        const unsigned rm = (r >> 3) & 0xF;
        in.mnemonic = link ? "blx" : "bx";
        in.operands = reg(rm);
        in.flow = link ? Flow::IndirectCall : (rm == 14 ? Flow::Return : Flow::IndirectJump);
        return in;
    }
    if ((r & 0xF800) == 0x4800) {  // ldr rt, [pc, #imm8*4]
        const uint32_t imm = (r & 0xFF) * 4;
        in.mnemonic = "ldr";
        in.operands = reg((r >> 8) & 7) + ", [pc, #" + std::to_string(imm) + "]";
        in.hasTarget = true;
        in.target = (pcValue(addr, true) & ~uint64_t(3)) + imm;
        return in;
    }
    if ((r & 0xF000) == 0x6000 || (r & 0xF000) == 0x7000 || (r & 0xF000) == 0x8000) {  // ldr/str[b/h] rt, [rn, #imm5]
        const unsigned group = r >> 12;
        const bool load = (r & 0x0800) != 0;
        const unsigned scale = group == 6 ? 4 : group == 8 ? 2 : 1;
        in.mnemonic = std::string(load ? "ldr" : "str") + (group == 7 ? "b" : group == 8 ? "h" : "");
        in.operands = reg(r & 7) + ", [" + reg((r >> 3) & 7) + ", #" + std::to_string(((r >> 6) & 0x1F) * scale) + "]";
        return in;
    }
    if ((r & 0xF000) == 0x9000) {  // ldr/str rt, [sp, #imm8*4]
        in.mnemonic = (r & 0x0800) ? "ldr" : "str";
        in.operands = reg((r >> 8) & 7) + ", [sp, #" + std::to_string((r & 0xFF) * 4) + "]";
        return in;
    }
    if ((r & 0xF800) == 0xA000) {  // adr rd, pc-relative
        const uint32_t imm = (r & 0xFF) * 4;
        in.mnemonic = "adr";
        in.hasTarget = true;
        in.target = (pcValue(addr, true) & ~uint64_t(3)) + imm;
        in.operands = reg((r >> 8) & 7) + ", " + hex(static_cast<uint32_t>(in.target));
        return in;
    }
    if ((r & 0xFF00) == 0xB000) {  // add / sub sp, sp, #imm7*4
        in.mnemonic = (r & 0x0080) ? "sub" : "add";
        in.operands = "sp, sp, #" + std::to_string((r & 0x7F) * 4);
        return in;
    }
    if ((r & 0xFE00) == 0xB400) {  // push {list[, lr]}
        in.mnemonic = "push";
        in.operands = regs((r & 0xFF) | ((r & 0x0100) ? (1u << 14) : 0));
        return in;
    }
    if ((r & 0xFE00) == 0xBC00) {  // pop {list[, pc]}: with pc it returns
        const bool pc = (r & 0x0100) != 0;
        in.mnemonic = "pop";
        in.operands = regs((r & 0xFF) | (pc ? (1u << 15) : 0));
        if (pc) in.flow = Flow::Return;
        return in;
    }
    if ((r & 0xF500) == 0xB100) {  // cbz / cbnz rn, label (forward only)
        const uint32_t imm = (((r >> 9) & 1) << 6) | (((r >> 3) & 0x1F) << 1);
        in.mnemonic = (r & 0x0800) ? "cbnz" : "cbz";
        setBranch(in, pcValue(addr, true) + imm, Flow::CondJump);
        in.operands = reg(r & 7) + ", " + in.operands;
        return in;
    }
    if ((r & 0xFF00) == 0xBE00) {  // bkpt
        in.mnemonic = "bkpt";
        in.operands = "#" + std::to_string(r & 0xFF);
        in.flow = Flow::Trap;
        return in;
    }
    if (r == 0xBF00) {
        in.mnemonic = "nop";
        return in;
    }
    if ((r & 0xF000) == 0xD000) {  // b<cond> / udf (cond 1110) / svc (cond 1111)
        const unsigned cond = (r >> 8) & 0xF;
        if (cond == 0xE) {
            in.mnemonic = "udf";
            in.operands = "#" + std::to_string(r & 0xFF);
            in.flow = Flow::Trap;
            return in;
        }
        if (cond == 0xF) {
            in.mnemonic = "svc";
            in.operands = "#" + std::to_string(r & 0xFF);
            return in;
        }
        in.mnemonic = std::string("b") + conditionName(cond);
        setBranch(in, relative(pcValue(addr, true), signExtend(r & 0xFF, 8) * 2), Flow::CondJump);
        return in;
    }
    if ((r & 0xF800) == 0xE000) {  // b (11-bit offset)
        in.mnemonic = "b";
        setBranch(in, relative(pcValue(addr, true), signExtend(r & 0x7FF, 11) * 2), Flow::Jump);
        return in;
    }
    return unknown16(in, h);
}

Insn thumb32(uint16_t h1, uint16_t h2, uint64_t addr) {
    Insn in;
    in.addr = addr;
    in.raw = (static_cast<uint32_t>(h1) << 16) | h2;
    in.size = 4;
    in.thumb = true;
    // Branches: 11110 S imm10 | 1 J1 x J2 imm11.
    if ((h1 & 0xF800) == 0xF000 && (h2 & 0x8000) == 0x8000) {
        const uint32_t s = (h1 >> 10) & 1, j1 = (h2 >> 13) & 1, j2 = (h2 >> 11) & 1;
        const unsigned op = (h2 >> 12) & 5;  // bits 14 and 12
        if (op == 5 || op == 4 || op == 1) {  // bl (11x1 -> op 5), blx (op 4), b.w T4 (op 1)
            const uint32_t i1 = ~(j1 ^ s) & 1, i2 = ~(j2 ^ s) & 1;
            const uint32_t imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FFu) << 12) | ((h2 & 0x7FFu) << 1);
            const int32_t off = signExtend(imm, 25);
            if (op == 4) {  // blx: to A32 code, from the word-aligned PC
                in.mnemonic = "blx";
                setBranch(in, relative(pcValue(addr, true) & ~uint64_t(3), off), Flow::Call);
            } else {
                in.mnemonic = op == 5 ? "bl" : "b.w";
                setBranch(in, relative(pcValue(addr, true), off), op == 5 ? Flow::Call : Flow::Jump);
            }
            return in;
        }
        // b<cond>.w T3: S cond imm6 | J1 J2 imm11.
        const unsigned cond = (h1 >> 6) & 0xF;
        if (op == 0 && (cond >> 1) != 7) {
            const uint32_t imm = (s << 20) | (j2 << 19) | (j1 << 18) | ((h1 & 0x3Fu) << 12) | ((h2 & 0x7FFu) << 1);
            in.mnemonic = std::string("b") + conditionName(cond) + ".w";
            setBranch(in, relative(pcValue(addr, true), signExtend(imm, 21)), Flow::CondJump);
            return in;
        }
    }
    if (h1 == 0xE92D) {  // push.w {list}
        in.mnemonic = "push.w";
        in.operands = regs(h2);
        return in;
    }
    if (h1 == 0xE8BD) {  // pop.w {list}: with pc it returns
        in.mnemonic = "pop.w";
        in.operands = regs(h2);
        if (h2 & 0x8000) in.flow = Flow::Return;
        return in;
    }
    if (h1 == 0xF85D && (h2 & 0x0FFF) == 0x0B04) {  // ldr.w rt, [sp], #4 (a single-register pop)
        const unsigned rt = h2 >> 12;
        in.mnemonic = "pop.w";
        in.operands = regs(1u << rt);
        if (rt == 15) in.flow = Flow::Return;
        return in;
    }
    in.known = false;
    char buf[32];
    std::snprintf(buf, sizeof buf, ".hword 0x%04x, 0x%04x", h1, h2);
    in.mnemonic = buf;
    return in;
}

// A32 modified immediate: imm8 rotated right by 2 * rot4.
uint32_t armImmediate(uint32_t w) {
    const uint32_t imm8 = w & 0xFF, rot = ((w >> 8) & 0xF) * 2;
    return rot ? (imm8 >> rot) | (imm8 << (32 - rot)) : imm8;
}

Insn arm32(uint32_t w, uint64_t addr) {
    Insn in;
    in.addr = addr;
    in.raw = w;
    in.size = 4;
    const unsigned cond = w >> 28;
    const std::string c = cond < 0xE ? conditionName(cond) : "";
    if (cond == 0xF) {
        if ((w & 0x0E000000) == 0x0A000000) {  // blx #imm: to Thumb code (H gives the halfword)
            const int32_t off = (signExtend(w & 0xFFFFFF, 24) << 2) | static_cast<int32_t>(((w >> 24) & 1) << 1);
            in.mnemonic = "blx";
            setBranch(in, relative(pcValue(addr, false), off), Flow::Call);
            return in;
        }
    } else {
        if ((w & 0x0FFFFFF0) == 0x012FFF10) {  // bx rm
            in.mnemonic = "bx" + c;
            in.operands = reg(w & 0xF);
            in.flow = (w & 0xF) == 14 ? Flow::Return : Flow::IndirectJump;
            return in;
        }
        if ((w & 0x0FFFFFF0) == 0x012FFF30) {  // blx rm
            in.mnemonic = "blx" + c;
            in.operands = reg(w & 0xF);
            in.flow = Flow::IndirectCall;
            return in;
        }
        if ((w & 0x0E000000) == 0x0A000000) {  // b / bl
            const bool link = (w >> 24) & 1;
            in.mnemonic = std::string(link ? "bl" : "b") + c;
            setBranch(in, relative(pcValue(addr, false), signExtend(w & 0xFFFFFF, 24) << 2),
                      link ? Flow::Call : (cond == 0xE ? Flow::Jump : Flow::CondJump));
            return in;
        }
        if ((w & 0x0FF00000) == 0x03000000 || (w & 0x0FF00000) == 0x03400000) {  // movw / movt
            const uint32_t imm = ((w >> 4) & 0xF000) | (w & 0xFFF);
            in.mnemonic = std::string((w & 0x00400000) ? "movt" : "movw") + c;
            in.operands = reg((w >> 12) & 0xF) + ", #" + hex(imm);
            return in;
        }
        if ((w & 0x0FEF0FF0) == 0x01A00000) {  // mov rd, rm (no shift)
            const unsigned rd = (w >> 12) & 0xF, rm = w & 0xF;
            in.mnemonic = std::string("mov") + ((w >> 20) & 1 ? "s" : "") + c;
            in.operands = reg(rd) + ", " + reg(rm);
            if (rd == 15) in.flow = rm == 14 ? Flow::Return : Flow::IndirectJump;
            return in;
        }
        if ((w & 0x0FE00000) == 0x02800000 || (w & 0x0FE00000) == 0x02400000) {  // add / sub #imm
            const bool sub = (w & 0x0FE00000) == 0x02400000;
            const unsigned rd = (w >> 12) & 0xF, rn = (w >> 16) & 0xF;
            const uint32_t imm = armImmediate(w);
            if (rn == 15 && !((w >> 20) & 1)) {  // adr: a pc-relative address
                in.mnemonic = "adr" + c;
                in.hasTarget = true;
                in.target = relative(pcValue(addr, false), sub ? -static_cast<int32_t>(imm) : static_cast<int32_t>(imm));
                in.operands = reg(rd) + ", " + hex(static_cast<uint32_t>(in.target));
                return in;
            }
            in.mnemonic = std::string(sub ? "sub" : "add") + ((w >> 20) & 1 ? "s" : "") + c;
            in.operands = reg(rd) + ", " + reg(rn) + ", #" + hex(imm);
            return in;
        }
        if ((w & 0x0E000000) == 0x08000000) {  // ldm / stm (push / pop on sp!)
            const bool load = (w >> 20) & 1, wb = (w >> 21) & 1;
            const unsigned rn = (w >> 16) & 0xF;
            const uint32_t list = w & 0xFFFF;
            if (rn == 13 && wb && load && ((w >> 23) & 3) == 1) in.mnemonic = "pop" + c, in.operands = regs(list);
            else if (rn == 13 && wb && !load && ((w >> 23) & 3) == 2) in.mnemonic = "push" + c, in.operands = regs(list);
            else {
                in.mnemonic = std::string(load ? "ldm" : "stm") + c;
                in.operands = reg(rn) + (wb ? "!" : "") + ", " + regs(list);
            }
            if (load && (list & (1u << 15))) in.flow = Flow::Return;
            return in;
        }
        if ((w & 0x0C000000) == 0x04000000 && !((w >> 25) & 1 && (w >> 4) & 1)) {  // ldr / str [b]
            const bool load = (w >> 20) & 1, byte = (w >> 22) & 1, up = (w >> 23) & 1;
            const bool pre = (w >> 24) & 1, wb = (w >> 21) & 1, regOffset = (w >> 25) & 1;
            const unsigned rt = (w >> 12) & 0xF, rn = (w >> 16) & 0xF;
            in.mnemonic = std::string(load ? "ldr" : "str") + (byte ? "b" : "") + c;
            const std::string off = regOffset ? std::string(up ? "" : "-") + reg(w & 0xF)
                                              : "#" + std::string(up ? "" : "-") + std::to_string(w & 0xFFF);
            in.operands = reg(rt) + ", [" + reg(rn) + (pre ? ", " + off + "]" + (wb ? "!" : "") : "], " + off);
            if (!regOffset && rn == 15 && pre) {  // literal
                in.hasTarget = true;
                in.target = relative(pcValue(addr, false), up ? static_cast<int32_t>(w & 0xFFF) : -static_cast<int32_t>(w & 0xFFF));
            }
            if (load && rt == 15) in.flow = rn == 13 ? Flow::Return : Flow::IndirectJump;
            return in;
        }
    }
    in.known = false;
    char buf[16];
    std::snprintf(buf, sizeof buf, ".word 0x%08x", w);
    in.mnemonic = buf;
    return in;
}

Insn tooShort(uint64_t addr, size_t len, bool thumb) {
    Insn in;
    in.addr = addr;
    in.thumb = thumb;
    in.known = false;
    in.size = static_cast<uint8_t>(len);  // the caller advances past what is left
    in.mnemonic = ".byte";
    return in;
}

}  // namespace

Insn decode(const uint8_t* code, size_t len, uint64_t addr, bool thumb) {
    if (!thumb) {
        if (len < 4) return tooShort(addr, len, false);
        const uint32_t w = static_cast<uint32_t>(code[0] | (code[1] << 8) | (code[2] << 16) |
                                                 (static_cast<uint32_t>(code[3]) << 24));
        return arm32(w, addr);
    }
    if (len < 2) return tooShort(addr, len, true);
    const uint16_t h1 = half(code);
    if ((h1 >> 11) >= 0x1D) {  // 11101 / 11110 / 11111: a 32-bit Thumb-2 instruction
        if (len < 4) return tooShort(addr, len, true);
        return thumb32(h1, half(code + 2), addr);
    }
    return thumb16(h1, addr);
}

const char* conditionName(unsigned cond) {
    static const char* names[16] = {"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                                    "hi", "ls", "ge", "lt", "gt", "le", "", ""};
    return names[cond & 15];
}

}  // namespace arm32
