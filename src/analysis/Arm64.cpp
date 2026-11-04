#include "analysis/Arm64.hpp"
#include <cstdio>

namespace arm64 {
namespace {

inline uint32_t bits(uint32_t w, int hi, int lo) { return (w >> lo) & ((1u << (hi - lo + 1)) - 1); }
inline uint32_t bit(uint32_t w, int b) { return (w >> b) & 1u; }
inline int64_t sext(uint64_t v, int width) {
    const uint64_t m = 1ull << (width - 1);
    v &= (width == 64) ? ~0ull : ((1ull << width) - 1);
    return (int64_t)((v ^ m) - m);
}

std::string hex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return b;
}

// "#5", "#0x40", "#-0x10"
std::string imm(int64_t v) {
    char b[40];
    if (v >= 0 && v < 10) std::snprintf(b, sizeof b, "#%lld", (long long)v);
    else if (v < 0 && v > -10) std::snprintf(b, sizeof b, "#%lld", (long long)v);
    else if (v < 0) std::snprintf(b, sizeof b, "#-0x%llx", (unsigned long long)(-(v + 1)) + 1ull);
    else std::snprintf(b, sizeof b, "#0x%llx", (unsigned long long)v);
    return b;
}

std::string uimm(uint64_t v) {
    char b[40];
    if (v < 10) std::snprintf(b, sizeof b, "#%llu", (unsigned long long)v);
    else std::snprintf(b, sizeof b, "#0x%llx", (unsigned long long)v);
    return b;
}

// General-purpose register. n == 31 is sp/wsp when sp is true, else xzr/wzr.
std::string reg(unsigned n, bool x, bool sp = false) {
    if (n == 31) return sp ? (x ? "sp" : "wsp") : (x ? "xzr" : "wzr");
    return (x ? "x" : "w") + std::to_string(n);
}

// FP / SIMD scalar register by size letter.
std::string vreg(unsigned n, char size) { return std::string(1, size) + std::to_string(n); }

const char* const kCond[16] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                               "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
const char* const kShift[4] = {"lsl", "lsr", "asr", "ror"};
const char* const kExtend[8] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};

Insn make(Insn& i, const char* m, std::string ops = {}) {
    i.mnemonic = m;
    i.operands = std::move(ops);
    return i;
}

Insn unknown(Insn& i) {
    i.known = false;
    return make(i, ".inst", hex(i.raw));
}

std::string shifted(unsigned type, unsigned amount) {
    if (amount == 0 && type == 0) return {};
    return std::string(", ") + kShift[type] + " " + uimm(amount);
}

bool decodeBitMask(bool sf, unsigned n, unsigned imms, unsigned immr, uint64_t& out) {
    const unsigned combined = (n << 6) | (~imms & 0x3f);
    int len = -1;
    for (int b = 6; b >= 0; --b)
        if (combined & (1u << b)) {
            len = b;
            break;
        }
    if (len < 1 || (!sf && n)) return false;
    const unsigned size = 1u << len, levels = size - 1;
    const unsigned s = imms & levels, r = immr & levels;
    if (s == levels) return false;
    const uint64_t sizeMask = size == 64 ? ~0ull : ((1ull << size) - 1);
    uint64_t elem = (s + 1 == 64) ? ~0ull : ((1ull << (s + 1)) - 1);
    if (r) elem = ((elem >> r) | (elem << (size - r))) & sizeMask;
    uint64_t v = 0;
    for (unsigned i = 0; i < 64; i += size) v |= elem << i;
    out = sf ? v : (v & 0xffffffffull);
    return true;
}

std::string fpImm(unsigned imm8) {
    const double frac = 1.0 + (double)(imm8 & 0xf) / 16.0;
    const int exp = (int)(((imm8 >> 4) & 7) ^ 4) - 3;
    double v = frac;
    for (int i = 0; i < exp; ++i) v *= 2.0;
    for (int i = 0; i > exp; --i) v /= 2.0;
    if (imm8 & 0x80) v = -v;
    char b[32];
    std::snprintf(b, sizeof b, "#%g", v);
    std::string s = b;
    if (s.find('.') == std::string::npos && s.find('e') == std::string::npos) s += ".0";
    return s;
}

std::string sysRegName(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2) {
    struct Named {
        unsigned op0, op1, crn, crm, op2;
        const char* name;
    };
    static const Named kNames[] = {
        {3, 3, 13, 0, 2, "tpidr_el0"}, {3, 3, 13, 0, 3, "tpidrro_el0"}, {3, 3, 4, 2, 0, "nzcv"},
        {3, 3, 4, 4, 0, "fpcr"},       {3, 3, 4, 4, 1, "fpsr"},         {3, 3, 14, 0, 2, "cntvct_el0"},
        {3, 3, 14, 0, 0, "cntfrq_el0"}, {3, 3, 0, 0, 1, "ctr_el0"},     {3, 3, 0, 0, 7, "dczid_el0"},
        {3, 0, 0, 0, 0, "midr_el1"},   {3, 3, 4, 2, 1, "daif"},          {3, 3, 2, 4, 0, "rndr"},
        {3, 3, 2, 4, 1, "rndrrs"},
    };
    for (const auto& n : kNames)
        if (n.op0 == op0 && n.op1 == op1 && n.crn == crn && n.crm == crm && n.op2 == op2) return n.name;
    char b[48];
    std::snprintf(b, sizeof b, "s%u_%u_c%u_c%u_%u", op0, op1, crn, crm, op2);
    return b;
}

// ---------------------------------------------------------------- data processing (immediate)
Insn dataImm(Insn& i) {
    const uint32_t w = i.raw;
    const bool sf = bit(w, 31);
    const unsigned rd = bits(w, 4, 0), rn = bits(w, 9, 5);
    switch (bits(w, 25, 23)) {
    case 0:
    case 1: {  // ADR / ADRP
        const int64_t off = sext(((uint64_t)bits(w, 23, 5) << 2) | bits(w, 30, 29), 21);
        i.hasTarget = true;
        if (bit(w, 31)) {
            i.target = (i.addr & ~0xfffull) + (uint64_t)(off * 4096);
            i.pageReg = (int8_t)rd;
            return make(i, "adrp", reg(rd, true) + ", " + hex(i.target));
        }
        i.target = i.addr + (uint64_t)off;
        return make(i, "adr", reg(rd, true) + ", " + hex(i.target));
    }
    case 2: {  // ADD/SUB immediate
        const bool sub = bit(w, 30), s = bit(w, 29);
        const uint64_t v = (uint64_t)bits(w, 21, 10) << (bit(w, 22) ? 12 : 0);
        if (!sub && !s) {
            i.isAddImm = true;
            i.baseReg = (int8_t)rn;
            i.destReg = (int8_t)rd;
            i.offset = (int64_t)v;
            if (v == 0 && (rd == 31 || rn == 31)) return make(i, "mov", reg(rd, sf, true) + ", " + reg(rn, sf, true));
        }
        if (s && rd == 31) return make(i, sub ? "cmp" : "cmn", reg(rn, sf, true) + ", " + uimm(v));
        const char* m = sub ? (s ? "subs" : "sub") : (s ? "adds" : "add");
        return make(i, m, reg(rd, sf, !s) + ", " + reg(rn, sf, true) + ", " + uimm(v));
    }
    case 4: {  // logical immediate
        uint64_t v = 0;
        if (!decodeBitMask(sf, bit(w, 22), bits(w, 15, 10), bits(w, 21, 16), v)) return unknown(i);
        const unsigned opc = bits(w, 30, 29);
        if (opc == 3 && rd == 31) return make(i, "tst", reg(rn, sf) + ", " + hex(v).insert(0, "#"));
        if (opc == 1 && rn == 31) return make(i, "mov", reg(rd, sf, true) + ", #" + hex(v));
        static const char* const names[4] = {"and", "orr", "eor", "ands"};
        return make(i, names[opc], reg(rd, sf, opc != 3) + ", " + reg(rn, sf) + ", #" + hex(v));
    }
    case 5: {  // move wide
        const unsigned opc = bits(w, 30, 29), hw = bits(w, 22, 21);
        const uint64_t imm16 = bits(w, 20, 5);
        if (opc == 1 || (!sf && hw >= 2)) return unknown(i);
        if (opc == 3) return make(i, "movk", reg(rd, sf) + ", " + uimm(imm16) + (hw ? ", lsl #" + std::to_string(hw * 16) : ""));
        uint64_t v = imm16 << (hw * 16);
        if (opc == 0) {
            if (imm16 == 0 && hw != 0) return make(i, "movn", reg(rd, sf) + ", " + uimm(imm16) + ", lsl #" + std::to_string(hw * 16));
            v = ~v;
            if (!sf) v &= 0xffffffffull;
            return make(i, "mov", reg(rd, sf) + ", " + (sf ? imm((int64_t)v) : imm((int32_t)(uint32_t)v)));
        }
        if (imm16 == 0 && hw != 0) return make(i, "movz", reg(rd, sf) + ", #0, lsl #" + std::to_string(hw * 16));
        return make(i, "mov", reg(rd, sf) + ", " + uimm(v));
    }
    case 6: {  // bitfield
        const unsigned opc = bits(w, 30, 29), immr = bits(w, 21, 16), imms = bits(w, 15, 10);
        const unsigned size = sf ? 64 : 32;
        if (opc == 3 || bit(w, 22) != (unsigned)sf || immr >= size || imms >= size) return unknown(i);
        const std::string d = reg(rd, sf), n = reg(rn, sf);
        if (opc == 0) {  // SBFM
            if (imms == size - 1) return make(i, "asr", d + ", " + n + ", " + uimm(immr));
            if (immr == 0 && imms == 7) return make(i, "sxtb", d + ", " + reg(rn, false));
            if (immr == 0 && imms == 15) return make(i, "sxth", d + ", " + reg(rn, false));
            if (immr == 0 && imms == 31 && sf) return make(i, "sxtw", d + ", " + reg(rn, false));
            if (imms < immr) return make(i, "sbfiz", d + ", " + n + ", " + uimm(size - immr) + ", " + uimm(imms + 1));
            return make(i, "sbfx", d + ", " + n + ", " + uimm(immr) + ", " + uimm(imms - immr + 1));
        }
        if (opc == 2) {  // UBFM
            if (imms != size - 1 && imms + 1 == immr) return make(i, "lsl", d + ", " + n + ", " + uimm(size - 1 - imms));
            if (imms == size - 1) return make(i, "lsr", d + ", " + n + ", " + uimm(immr));
            if (immr == 0 && imms == 7 && !sf) return make(i, "uxtb", d + ", " + n);
            if (immr == 0 && imms == 15 && !sf) return make(i, "uxth", d + ", " + n);
            if (imms < immr) return make(i, "ubfiz", d + ", " + n + ", " + uimm(size - immr) + ", " + uimm(imms + 1));
            return make(i, "ubfx", d + ", " + n + ", " + uimm(immr) + ", " + uimm(imms - immr + 1));
        }
        if (imms < immr) {
            if (rn == 31) return make(i, "bfc", d + ", " + uimm(size - immr) + ", " + uimm(imms + 1));
            return make(i, "bfi", d + ", " + n + ", " + uimm(size - immr) + ", " + uimm(imms + 1));
        }
        return make(i, "bfxil", d + ", " + n + ", " + uimm(immr) + ", " + uimm(imms - immr + 1));
    }
    case 7: {  // EXTR
        if (bits(w, 30, 29) != 0 || bit(w, 21)) return unknown(i);
        const unsigned rm = bits(w, 20, 16), lsb = bits(w, 15, 10);
        if (rn == rm) return make(i, "ror", reg(rd, sf) + ", " + reg(rn, sf) + ", " + uimm(lsb));
        return make(i, "extr", reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf) + ", " + uimm(lsb));
    }
    default: return unknown(i);
    }
}

// ---------------------------------------------------------------- branches, exceptions, system
Insn branchSys(Insn& i) {
    const uint32_t w = i.raw;
    if (bits(w, 30, 26) == 5) {  // B / BL
        i.hasTarget = true;
        i.target = i.addr + (uint64_t)(sext(bits(w, 25, 0), 26) * 4);
        i.flow = bit(w, 31) ? Flow::Call : Flow::Jump;
        return make(i, bit(w, 31) ? "bl" : "b", hex(i.target));
    }
    if (bits(w, 31, 24) == 0x54) {  // B.cond / BC.cond
        i.hasTarget = true;
        i.target = i.addr + (uint64_t)(sext(bits(w, 23, 5), 19) * 4);
        i.flow = Flow::CondJump;
        const std::string m = std::string(bit(w, 4) ? "bc." : "b.") + kCond[bits(w, 3, 0)];
        i.mnemonic = m;
        i.operands = hex(i.target);
        return i;
    }
    if (bits(w, 30, 25) == 0x1a) {  // CBZ / CBNZ
        i.hasTarget = true;
        i.target = i.addr + (uint64_t)(sext(bits(w, 23, 5), 19) * 4);
        i.flow = Flow::CondJump;
        return make(i, bit(w, 24) ? "cbnz" : "cbz", reg(bits(w, 4, 0), bit(w, 31)) + ", " + hex(i.target));
    }
    if (bits(w, 30, 25) == 0x1b) {  // TBZ / TBNZ
        i.hasTarget = true;
        i.target = i.addr + (uint64_t)(sext(bits(w, 18, 5), 14) * 4);
        i.flow = Flow::CondJump;
        const unsigned b = (bit(w, 31) << 5) | bits(w, 23, 19);
        return make(i, bit(w, 24) ? "tbnz" : "tbz", reg(bits(w, 4, 0), bit(w, 31)) + ", " + uimm(b) + ", " + hex(i.target));
    }
    if (bits(w, 31, 24) == 0xd4) {  // exception generation
        const unsigned opc = bits(w, 23, 21), ll = bits(w, 1, 0);
        const std::string v = uimm(bits(w, 20, 5));
        if (opc == 0 && ll == 1) return make(i, "svc", v);
        if (opc == 0 && ll == 2) return make(i, "hvc", v);
        if (opc == 0 && ll == 3) return make(i, "smc", v);
        if (opc == 1 && ll == 0) {
            i.flow = Flow::Trap;
            return make(i, "brk", v);
        }
        if (opc == 2 && ll == 0) {
            i.flow = Flow::Trap;
            return make(i, "hlt", v);
        }
        return unknown(i);
    }
    if (bits(w, 31, 22) == 0x354) {  // system
        const unsigned l = bit(w, 21), op0 = bits(w, 20, 19), op1 = bits(w, 18, 16), crn = bits(w, 15, 12),
                       crm = bits(w, 11, 8), op2 = bits(w, 7, 5), rt = bits(w, 4, 0);
        if (!l && op0 == 0 && op1 == 3 && crn == 2 && rt == 31) {
            const unsigned h = (crm << 3) | op2;
            switch (h) {
            case 0: return make(i, "nop");
            case 1: return make(i, "yield");
            case 2: return make(i, "wfe");
            case 3: return make(i, "wfi");
            case 4: return make(i, "sev");
            case 5: return make(i, "sevl");
            case 7: return make(i, "xpaclri");
            case 0x08: return make(i, "pacia1716");
            case 0x0a: return make(i, "pacib1716");
            case 0x0c: return make(i, "autia1716");
            case 0x0e: return make(i, "autib1716");
            case 0x18: return make(i, "paciaz");
            case 0x19: return make(i, "paciasp");
            case 0x1a: return make(i, "pacibz");
            case 0x1b: return make(i, "pacibsp");
            case 0x1c: return make(i, "autiaz");
            case 0x1d: return make(i, "autiasp");
            case 0x1e: return make(i, "autibz");
            case 0x1f: return make(i, "autibsp");
            case 0x20: return make(i, "bti");
            case 0x22: return make(i, "bti", "c");
            case 0x24: return make(i, "bti", "j");
            case 0x26: return make(i, "bti", "jc");
            default: return make(i, "hint", uimm(h));
            }
        }
        if (!l && op0 == 0 && op1 == 3 && crn == 3) {
            static const char* const opts[16] = {"#0", "oshld", "oshst", "osh", "#4", "nshld", "nshst", "nsh",
                                                 "#8", "ishld", "ishst", "ish", "#12", "ld", "st", "sy"};
            if (op2 == 2) return make(i, "clrex");
            if (op2 == 4) return make(i, "dsb", opts[crm]);
            if (op2 == 5) return make(i, "dmb", opts[crm]);
            if (op2 == 6) return make(i, "isb");
            return unknown(i);
        }
        if (op0 >= 2) {
            const std::string sr = sysRegName(op0, op1, crn, crm, op2);
            if (l) return make(i, "mrs", reg(rt, true) + ", " + sr);
            return make(i, "msr", sr + ", " + reg(rt, true));
        }
        if (op0 == 1) {
            char b[64];
            std::snprintf(b, sizeof b, "#%u, c%u, c%u, #%u, ", op1, crn, crm, op2);
            return make(i, l ? "sysl" : "sys", b + reg(rt, true));
        }
        if (op0 == 0 && crn == 4) return make(i, "msr", "pstate, " + uimm(crm));
        return unknown(i);
    }
    if (bits(w, 31, 25) == 0x6b) {  // unconditional branch (register)
        const unsigned opc = bits(w, 24, 21), op3 = bits(w, 15, 10), rn = bits(w, 9, 5), op4 = bits(w, 4, 0);
        if (bits(w, 20, 16) != 31) return unknown(i);
        const bool pac = (op3 & 0x3e) == 2;
        const char* key = (op3 & 1) ? "b" : "a";
        switch (opc) {
        case 0:
            i.flow = Flow::IndirectJump;
            if (pac) {
                i.mnemonic = std::string("bra") + key + "z";
                i.operands = reg(rn, true);
                return i;
            }
            return make(i, "br", reg(rn, true));
        case 1:
            i.flow = Flow::IndirectCall;
            if (pac) {
                i.mnemonic = std::string("blra") + key + "z";
                i.operands = reg(rn, true);
                return i;
            }
            return make(i, "blr", reg(rn, true));
        case 2:
            i.flow = Flow::Return;
            if (pac) {
                i.mnemonic = std::string("reta") + key;
                return i;
            }
            return make(i, "ret", rn == 30 ? std::string() : reg(rn, true));
        case 4: i.flow = Flow::Return; return make(i, "eret");
        case 8:
        case 9:
            if (!pac) return unknown(i);
            i.flow = opc == 8 ? Flow::IndirectJump : Flow::IndirectCall;
            i.mnemonic = std::string(opc == 8 ? "bra" : "blra") + key;
            i.operands = reg(rn, true) + ", " + reg(op4, true, true);
            return i;
        default: return unknown(i);
        }
    }
    return unknown(i);
}

// ---------------------------------------------------------------- loads and stores
std::string memOffset(unsigned rn, int64_t off) {
    if (off == 0) return "[" + reg(rn, true, true) + "]";
    return "[" + reg(rn, true, true) + ", " + imm(off) + "]";
}

Insn loadStore(Insn& i) {
    const uint32_t w = i.raw;
    const unsigned rt = bits(w, 4, 0), rn = bits(w, 9, 5);
    const bool v = bit(w, 26);

    // Load register (literal).
    if (bits(w, 29, 27) == 3 && bits(w, 25, 24) == 0) {
        const unsigned opc = bits(w, 31, 30);
        i.hasTarget = true;
        i.target = i.addr + (uint64_t)(sext(bits(w, 23, 5), 19) * 4);
        i.isLoad = true;
        i.destReg = (int8_t)rt;
        if (v) {
            if (opc == 3) return unknown(i);
            return make(i, "ldr", vreg(rt, "sdq"[opc]) + ", " + hex(i.target));
        }
        if (opc == 3) return make(i, "prfm", uimm(rt) + ", " + hex(i.target));
        return make(i, opc == 2 ? "ldrsw" : "ldr", reg(rt, opc != 0) + ", " + hex(i.target));
    }

    // Load/store pair.
    if (bits(w, 29, 27) == 5) {
        const unsigned opc = bits(w, 31, 30), mode = bits(w, 24, 23), rt2 = bits(w, 14, 10);
        const bool l = bit(w, 22);
        int scale;
        std::string r1, r2;
        const char* m;
        if (v) {
            if (opc == 3) return unknown(i);
            const char size = "sdq"[opc];
            scale = 4 << opc;
            r1 = vreg(rt, size);
            r2 = vreg(rt2, size);
            m = mode == 0 ? (l ? "ldnp" : "stnp") : (l ? "ldp" : "stp");
        } else {
            if (opc == 3 || (opc == 1 && !l)) return unknown(i);
            const bool x = opc == 2 || opc == 1;
            scale = opc == 2 ? 8 : 4;
            r1 = reg(rt, x);
            r2 = reg(rt2, x);
            m = opc == 1 ? "ldpsw" : mode == 0 ? (l ? "ldnp" : "stnp") : (l ? "ldp" : "stp");
        }
        const int64_t off = sext(bits(w, 21, 15), 7) * scale;
        std::string addr;
        if (mode == 1) addr = "[" + reg(rn, true, true) + "], " + imm(off);
        else if (mode == 3) addr = "[" + reg(rn, true, true) + ", " + imm(off) + "]!";
        else addr = memOffset(rn, off);
        return make(i, m, r1 + ", " + r2 + ", " + addr);
    }

    // Load/store exclusive / ordered / compare-and-swap.
    if (bits(w, 29, 24) == 8) {
        const unsigned size = bits(w, 31, 30), rs = bits(w, 20, 16), rt2 = bits(w, 14, 10);
        const bool o2 = bit(w, 23), l = bit(w, 22), o1 = bit(w, 21), o0 = bit(w, 15);
        const bool x = size == 3;
        const char* sfx = size == 0 ? "b" : size == 1 ? "h" : "";
        const std::string t = reg(rt, x), addr = "[" + reg(rn, true, true) + "]";
        std::string m;
        std::string ops;
        if (!o2 && !o1) {
            m = std::string(l ? (o0 ? "ldaxr" : "ldxr") : (o0 ? "stlxr" : "stxr")) + sfx;
            ops = l ? t + ", " + addr : reg(rs, false) + ", " + t + ", " + addr;
        } else if (!o2 && o1 && size >= 2) {
            m = l ? (o0 ? "ldaxp" : "ldxp") : (o0 ? "stlxp" : "stxp");
            ops = l ? t + ", " + reg(rt2, x) + ", " + addr : reg(rs, false) + ", " + t + ", " + reg(rt2, x) + ", " + addr;
        } else if (o2 && !o1) {
            m = std::string(l ? (o0 ? "ldar" : "ldlar") : (o0 ? "stlr" : "stllr")) + sfx;
            ops = t + ", " + addr;
        } else {  // CAS
            m = std::string("cas") + (l ? "a" : "") + (o0 ? "l" : "") + sfx;
            ops = reg(rs, x) + ", " + t + ", " + addr;
        }
        i.mnemonic = m;
        i.operands = ops;
        return i;
    }

    // Load/store register (immediate, register offset, atomics).
    if (bits(w, 29, 27) == 7) {
        const unsigned size = bits(w, 31, 30), opc = bits(w, 23, 22);
        std::string t, m;
        int scale = (int)size;
        bool load;
        if (v) {
            static const char kSize[4] = {'b', 'h', 's', 'd'};
            char sz = kSize[size];
            if (opc >= 2) {
                if (size != 0) return unknown(i);
                sz = 'q';
                scale = 4;
            }
            load = opc & 1;
            t = vreg(rt, sz);
            m = load ? "ldr" : "str";
        } else {
            static const char* const kStore[4] = {"strb", "strh", "str", "str"};
            static const char* const kLoad[4] = {"ldrb", "ldrh", "ldr", "ldr"};
            if (opc == 0) {
                m = kStore[size];
                t = reg(rt, size == 3);
                load = false;
            } else if (opc == 1) {
                m = kLoad[size];
                t = reg(rt, size == 3);
                load = true;
            } else if (opc == 2) {
                if (size == 3) {
                    m = "prfm";
                    t = uimm(rt);
                } else {
                    m = size == 0 ? "ldrsb" : size == 1 ? "ldrsh" : "ldrsw";
                    t = reg(rt, true);
                }
                load = true;
            } else {
                if (size >= 2) return unknown(i);
                m = size == 0 ? "ldrsb" : "ldrsh";
                t = reg(rt, false);
                load = true;
            }
        }
        if (bit(w, 24)) {  // unsigned immediate
            const int64_t off = (int64_t)bits(w, 21, 10) << scale;
            if (load) {
                i.isLoad = true;
                i.baseReg = (int8_t)rn;
                i.destReg = (int8_t)rt;
                i.offset = off;
            }
            i.mnemonic = m;
            i.operands = t + ", " + memOffset(rn, off);
            return i;
        }
        if (!bit(w, 21)) {
            const int64_t off = sext(bits(w, 20, 12), 9);
            switch (bits(w, 11, 10)) {
            case 0: {  // unscaled: ldur / stur / prfum
                std::string u = m;
                if (u.rfind("prfm", 0) == 0) u = "prfum";
                else u.insert(2, "u");
                i.mnemonic = u;
                i.operands = t + ", " + memOffset(rn, off);
                return i;
            }
            case 1:
                i.mnemonic = m;
                i.operands = t + ", [" + reg(rn, true, true) + "], " + imm(off);
                return i;
            case 2: {
                std::string u = m;
                u.insert(2, "t");
                i.mnemonic = u;
                i.operands = t + ", " + memOffset(rn, off);
                return i;
            }
            default:
                i.mnemonic = m;
                i.operands = t + ", [" + reg(rn, true, true) + ", " + imm(off) + "]!";
                return i;
            }
        }
        if (bits(w, 11, 10) == 2) {  // register offset
            const unsigned rm = bits(w, 20, 16), option = bits(w, 15, 13);
            const bool s = bit(w, 12);
            std::string ext;
            if (option == 3) ext = s ? ", lsl " + uimm((uint64_t)scale) : "";
            else ext = std::string(", ") + kExtend[option] + (s ? " " + uimm((uint64_t)scale) : "");
            i.mnemonic = m;
            i.operands = t + ", [" + reg(rn, true, true) + ", " + reg(rm, (option & 1) != 0) + ext + "]";
            return i;
        }
        if (bits(w, 11, 10) == 0 && !v) {  // atomic memory operations
            static const char* const kOps[8] = {"ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin"};
            const unsigned rs = bits(w, 20, 16), o3 = bit(w, 15), aop = bits(w, 14, 12);
            const bool a = bit(w, 23), r = bit(w, 22);
            std::string base = o3 ? (aop == 0 ? "swp" : aop == 4 ? "ldapr" : "") : kOps[aop];
            if (base.empty()) return unknown(i);
            base += std::string(a ? "a" : "") + (r ? "l" : "") + (size == 0 ? "b" : size == 1 ? "h" : "");
            i.mnemonic = base;
            const bool x = size == 3;
            i.operands = (base.rfind("ldapr", 0) == 0 ? "" : reg(rs, x) + ", ") + reg(rt, x) + ", [" + reg(rn, true, true) + "]";
            return i;
        }
        return unknown(i);
    }

    // Advanced SIMD load/store multiple structures (ld1/st1 ... ld4/st4), no-offset and post-index forms.
    if (!bit(w, 31) && bits(w, 29, 24) == 0x0c && !bit(w, 21)) {
        const bool l = bit(w, 22), q = bit(w, 30), post = bit(w, 23);
        const unsigned opcode = bits(w, 15, 12), size = bits(w, 11, 10), rm = bits(w, 20, 16);
        int count, structs;
        switch (opcode) {
        case 0: count = 4, structs = 4; break;
        case 2: count = 4, structs = 1; break;
        case 4: count = 3, structs = 3; break;
        case 6: count = 3, structs = 1; break;
        case 7: count = 1, structs = 1; break;
        case 8: count = 2, structs = 2; break;
        case 10: count = 2, structs = 1; break;
        default: return unknown(i);
        }
        static const char* const kArr[4][2] = {{"8b", "16b"}, {"4h", "8h"}, {"2s", "4s"}, {"1d", "2d"}};
        std::string list = "{";
        for (int k = 0; k < count; ++k)
            list += (k ? ", v" : "v") + std::to_string((rt + k) % 32) + "." + kArr[size][q];
        list += "}";
        std::string addr = "[" + reg(rn, true, true) + "]";
        if (post) addr += rm == 31 ? ", " + uimm((uint64_t)(count * (q ? 16 : 8))) : ", " + reg(rm, true);
        i.mnemonic = std::string(l ? "ld" : "st") + std::to_string(structs);
        i.operands = list + ", " + addr;
        return i;
    }
    return unknown(i);
}

// ---------------------------------------------------------------- data processing (register)
Insn dataReg(Insn& i) {
    const uint32_t w = i.raw;
    const bool sf = bit(w, 31);
    const unsigned rd = bits(w, 4, 0), rn = bits(w, 9, 5), rm = bits(w, 20, 16);
    const bool op1 = bit(w, 28);
    const unsigned op2 = bits(w, 24, 21);

    if (!op1 && !(op2 & 8)) {  // logical (shifted register)
        const unsigned opc = bits(w, 30, 29), shift = bits(w, 23, 22), amount = bits(w, 15, 10);
        const bool n = bit(w, 21);
        if (!sf && amount >= 32) return unknown(i);
        const std::string sh = shifted(shift, amount);
        if (opc == 1 && !n && rn == 31 && sh.empty()) return make(i, "mov", reg(rd, sf) + ", " + reg(rm, sf));
        if (opc == 1 && n && rn == 31) return make(i, "mvn", reg(rd, sf) + ", " + reg(rm, sf) + sh);
        if (opc == 3 && !n && rd == 31) return make(i, "tst", reg(rn, sf) + ", " + reg(rm, sf) + sh);
        static const char* const names[8] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};
        return make(i, names[opc * 2 + n], reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf) + sh);
    }
    if (!op1 && (op2 & 9) == 8) {  // add/sub (shifted register)
        const bool sub = bit(w, 30), s = bit(w, 29);
        const unsigned shift = bits(w, 23, 22), amount = bits(w, 15, 10);
        if (shift == 3) return unknown(i);
        const std::string sh = shifted(shift, amount);
        if (s && rd == 31) return make(i, sub ? "cmp" : "cmn", reg(rn, sf) + ", " + reg(rm, sf) + sh);
        if (sub && rn == 31) return make(i, s ? "negs" : "neg", reg(rd, sf) + ", " + reg(rm, sf) + sh);
        const char* m = sub ? (s ? "subs" : "sub") : (s ? "adds" : "add");
        return make(i, m, reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf) + sh);
    }
    if (!op1 && (op2 & 9) == 9) {  // add/sub (extended register)
        const bool sub = bit(w, 30), s = bit(w, 29);
        const unsigned option = bits(w, 15, 13), amount = bits(w, 12, 10);
        if (bits(w, 23, 22) != 0 || amount > 4) return unknown(i);
        std::string ext;
        const bool usesSp = rd == 31 || rn == 31;
        if (usesSp && option == (sf ? 3u : 2u)) ext = amount ? ", lsl " + uimm(amount) : "";
        else ext = std::string(", ") + kExtend[option] + (amount ? " " + uimm(amount) : "");
        const std::string m2 = reg(rm, sf && (option & 3) == 3);
        if (s && rd == 31) return make(i, sub ? "cmp" : "cmn", reg(rn, sf, true) + ", " + m2 + ext);
        const char* m = sub ? (s ? "subs" : "sub") : (s ? "adds" : "add");
        return make(i, m, reg(rd, sf, !s) + ", " + reg(rn, sf, true) + ", " + m2 + ext);
    }
    if (op1 && op2 == 0) {  // add/sub with carry
        const bool sub = bit(w, 30), s = bit(w, 29);
        if (sub && rn == 31) return make(i, s ? "ngcs" : "ngc", reg(rd, sf) + ", " + reg(rm, sf));
        const char* m = sub ? (s ? "sbcs" : "sbc") : (s ? "adcs" : "adc");
        return make(i, m, reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf));
    }
    if (op1 && op2 == 2) {  // conditional compare
        const char* m = bit(w, 30) ? "ccmp" : "ccmn";
        const std::string second = bit(w, 11) ? uimm(rm) : reg(rm, sf);
        return make(i, m, reg(rn, sf) + ", " + second + ", " + uimm(bits(w, 3, 0)) + ", " + kCond[bits(w, 15, 12)]);
    }
    if (op1 && op2 == 4) {  // conditional select
        const bool op = bit(w, 30), o2 = bit(w, 10);
        const unsigned cond = bits(w, 15, 12);
        if (bit(w, 29) || bit(w, 11)) return unknown(i);
        const char* inv = kCond[cond ^ 1];
        const bool notAl = (cond >> 1) != 7;
        if (!op && o2 && notAl) {
            if (rm == 31 && rn == 31) return make(i, "cset", reg(rd, sf) + ", " + inv);
            if (rm == rn) return make(i, "cinc", reg(rd, sf) + ", " + reg(rn, sf) + ", " + inv);
        }
        if (op && !o2 && notAl) {
            if (rm == 31 && rn == 31) return make(i, "csetm", reg(rd, sf) + ", " + inv);
            if (rm == rn) return make(i, "cinv", reg(rd, sf) + ", " + reg(rn, sf) + ", " + inv);
        }
        if (op && o2 && notAl && rm == rn) return make(i, "cneg", reg(rd, sf) + ", " + reg(rn, sf) + ", " + inv);
        static const char* const names[4] = {"csel", "csinc", "csinv", "csneg"};
        return make(i, names[op * 2 + o2], reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf) + ", " + kCond[cond]);
    }
    if (op1 && op2 == 6) {  // data processing 1 / 2 source
        const unsigned opcode = bits(w, 15, 10);
        if (bit(w, 30)) {
            if (rm != 0) return unknown(i);
            switch (opcode) {
            case 0: return make(i, "rbit", reg(rd, sf) + ", " + reg(rn, sf));
            case 1: return make(i, "rev16", reg(rd, sf) + ", " + reg(rn, sf));
            case 2: return make(i, sf ? "rev32" : "rev", reg(rd, sf) + ", " + reg(rn, sf));
            case 3: return sf ? make(i, "rev", reg(rd, sf) + ", " + reg(rn, sf)) : unknown(i);
            case 4: return make(i, "clz", reg(rd, sf) + ", " + reg(rn, sf));
            case 5: return make(i, "cls", reg(rd, sf) + ", " + reg(rn, sf));
            default: return unknown(i);
            }
        }
        const std::string ops = reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf);
        switch (opcode) {
        case 2: return make(i, "udiv", ops);
        case 3: return make(i, "sdiv", ops);
        case 8: return make(i, "lsl", ops);
        case 9: return make(i, "lsr", ops);
        case 10: return make(i, "asr", ops);
        case 11: return make(i, "ror", ops);
        case 12: return make(i, "pacga", reg(rd, true) + ", " + reg(rn, true) + ", " + reg(rm, true, true));
        default:
            if (opcode >= 16 && opcode <= 23) {
                static const char* const crc[8] = {"crc32b", "crc32h", "crc32w", "crc32x",
                                                   "crc32cb", "crc32ch", "crc32cw", "crc32cx"};
                return make(i, crc[opcode - 16], reg(rd, false) + ", " + reg(rn, false) + ", " + reg(rm, (opcode & 3) == 3));
            }
            return unknown(i);
        }
    }
    if (op1 && (op2 & 8)) {  // data processing 3 source
        const unsigned op31 = bits(w, 23, 21), ra = bits(w, 14, 10);
        const bool o0 = bit(w, 15);
        if (bits(w, 30, 29) != 0) return unknown(i);
        if (op31 == 0) {
            if (ra == 31) return make(i, o0 ? "mneg" : "mul", reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf));
            return make(i, o0 ? "msub" : "madd", reg(rd, sf) + ", " + reg(rn, sf) + ", " + reg(rm, sf) + ", " + reg(ra, sf));
        }
        if (!sf) return unknown(i);
        const std::string wn = reg(rn, false), wm = reg(rm, false);
        switch (op31) {
        case 1:
            if (ra == 31) return make(i, o0 ? "smnegl" : "smull", reg(rd, true) + ", " + wn + ", " + wm);
            return make(i, o0 ? "smsubl" : "smaddl", reg(rd, true) + ", " + wn + ", " + wm + ", " + reg(ra, true));
        case 2: return make(i, "smulh", reg(rd, true) + ", " + reg(rn, true) + ", " + reg(rm, true));
        case 5:
            if (ra == 31) return make(i, o0 ? "umnegl" : "umull", reg(rd, true) + ", " + wn + ", " + wm);
            return make(i, o0 ? "umsubl" : "umaddl", reg(rd, true) + ", " + wn + ", " + wm + ", " + reg(ra, true));
        case 6: return make(i, "umulh", reg(rd, true) + ", " + reg(rn, true) + ", " + reg(rm, true));
        default: return unknown(i);
        }
    }
    return unknown(i);
}

// ---------------------------------------------------------------- scalar floating point
Insn fp(Insn& i) {
    const uint32_t w = i.raw;
    const unsigned rd = bits(w, 4, 0), rn = bits(w, 9, 5), rm = bits(w, 20, 16);
    const unsigned ftype = bits(w, 23, 22);
    const char sz = ftype == 0 ? 's' : ftype == 1 ? 'd' : ftype == 3 ? 'h' : '?';

    const auto v = [](unsigned n, const char* arr) { return "v" + std::to_string(n) + "." + arr; };

    // Advanced SIMD three same, floating point (opcode 11xxx).
    if ((w & 0x9f200400) == 0x0e200400 && bits(w, 15, 11) >= 0x18) {
        const bool q = bit(w, 30), u = bit(w, 29), hi = bit(w, 23), dbl = bit(w, 22);
        const unsigned opcode = bits(w, 15, 11) - 0x18;
        static const char* const kFp[2][2][8] = {
            {{"fmaxnm", "fmla", "fadd", "fmulx", "fcmeq", nullptr, "fmax", "frecps"},
             {"fminnm", "fmls", "fsub", nullptr, nullptr, nullptr, "fmin", "frsqrts"}},
            {{"fmaxnmp", nullptr, "faddp", "fmul", "fcmge", "facge", "fmaxp", "fdiv"},
             {"fminnmp", nullptr, "fabd", nullptr, "fcmgt", "facgt", "fminp", nullptr}}};
        const char* m = kFp[u][hi][opcode];
        if (!m || (dbl && !q)) return unknown(i);
        const char* arr = dbl ? "2d" : (q ? "4s" : "2s");
        return make(i, m, v(rd, arr) + ", " + v(rn, arr) + ", " + v(rm, arr));
    }
    // ext vd.T, vn.T, vm.T, #index
    if ((w & 0xbfe08400) == 0x2e000000) {
        const bool q = bit(w, 30);
        const unsigned index = bits(w, 14, 11);
        if (!q && index >= 8) return unknown(i);
        const char* arr = q ? "16b" : "8b";
        return make(i, "ext", v(rd, arr) + ", " + v(rn, arr) + ", " + v(rm, arr) + ", " + uimm(index));
    }
    // Scalar dup (element): mov s0, v1.s[2]
    if ((w & 0xffe0fc00) == 0x5e000400) {
        const unsigned imm5 = bits(w, 20, 16);
        int shift = -1;
        for (int b = 0; b < 4 && shift < 0; ++b)
            if (imm5 & (1u << b)) shift = b;
        if (shift < 0) return unknown(i);
        static const char kElem[4] = {'b', 'h', 's', 'd'};
        return make(i, "mov", vreg(rd, kElem[shift]) + ", v" + std::to_string(rn) + "." + kElem[shift] + "[" +
                                  std::to_string(imm5 >> (shift + 1)) + "]");
    }
    // Advanced SIMD vector x indexed element: 0 Q U 01111 size L M Rm opcode H 0 Rn Rd.
    if ((w & 0x9f000400) == 0x0f000000) {
        const bool q = bit(w, 30), u = bit(w, 29);
        const unsigned size = bits(w, 23, 22), opcode = bits(w, 15, 12);
        const unsigned h = bit(w, 11), l = bit(w, 21), mbit = bit(w, 20);
        const char* m = nullptr;
        bool fpOp = false;
        if (opcode == 1 && !u) m = "fmla", fpOp = true;
        else if (opcode == 5 && !u) m = "fmls", fpOp = true;
        else if (opcode == 9) m = u ? "fmulx" : "fmul", fpOp = true;
        else if (opcode == 8 && !u) m = "mul";
        else if (opcode == 0 && u) m = "mla";
        else if (opcode == 4 && u) m = "mls";
        if (!m) return unknown(i);
        std::string arr, elemReg;
        unsigned index, mreg;
        if (fpOp) {
            if (!(size & 2)) return unknown(i);
            const bool d = size & 1;
            if (d && (l || !q)) return unknown(i);
            arr = d ? "2d" : (q ? "4s" : "2s");
            index = d ? h : (h << 1) | l;
            mreg = (mbit << 4) | rm;
            elemReg = d ? "d" : "s";
        } else {
            if (size == 1) {
                arr = q ? "8h" : "4h";
                index = (h << 2) | (l << 1) | mbit;
                mreg = rm & 15;
                elemReg = "h";
            } else if (size == 2) {
                arr = q ? "4s" : "2s";
                index = (h << 1) | l;
                mreg = (mbit << 4) | rm;
                elemReg = "s";
            } else {
                return unknown(i);
            }
        }
        return make(i, m, v(rd, arr.c_str()) + ", " + v(rn, arr.c_str()) + ", v" + std::to_string(mreg) + "." + elemReg +
                              "[" + std::to_string(index) + "]");
    }
    // Advanced SIMD two-register miscellaneous and across-lanes reductions.
    if ((w & 0x9f3e0c00) == 0x0e200800 || (w & 0x9f3e0c00) == 0x0e300800) {
        const bool q = bit(w, 30), u = bit(w, 29), across = bit(w, 20);
        const unsigned size = bits(w, 23, 22), opcode = bits(w, 16, 12);
        static const char* const kArr[4][2] = {{"8b", "16b"}, {"4h", "8h"}, {"2s", "4s"}, {nullptr, "2d"}};
        if (across) {
            const char* m = nullptr;
            if (opcode == 0x1b && !u) m = "addv";
            else if (opcode == 0x03) m = u ? "uaddlv" : "saddlv";
            else if (opcode == 0x0a) m = u ? "umaxv" : "smaxv";
            else if (opcode == 0x1a) m = u ? "uminv" : "sminv";
            if (!m || size == 3 || !kArr[size][q]) return unknown(i);
            static const char kScalar[4] = {'b', 'h', 's', 'd'};
            const bool widen = opcode == 0x03;
            return make(i, m, vreg(rd, kScalar[size + (widen ? 1 : 0)]) + ", " + v(rn, kArr[size][q]));
        }
        const bool fpSize = size & 2;  // FP ops encode sz in bit 22 with bit 23 selecting the op family
        const char* farr = (size & 1) ? (q ? "2d" : nullptr) : (q ? "4s" : "2s");
        const char* m = nullptr;
        bool fpOp = false;
        switch (opcode) {
        case 0x00: m = u ? "rev32" : "rev64"; break;
        case 0x05: m = u ? (size == 0 ? "mvn" : "rbit") : "cnt"; break;
        case 0x08: m = u ? "cmge" : "cmgt"; break;
        case 0x09: m = u ? "cmle" : "cmeq"; break;
        case 0x0a: m = u ? nullptr : "cmlt"; break;
        case 0x0b: m = u ? "neg" : "abs"; break;
        case 0x0f: if (fpSize) m = u ? "fneg" : "fabs", fpOp = true; break;
        case 0x1f: if (fpSize && u) m = "fsqrt", fpOp = true; break;
        case 0x18:
        case 0x19:
        case 0x1a:
        case 0x1b: {  // rounding / conversion: [U][size<1>][opcode - 0x18]
            static const char* const kRound[2][2][4] = {
                {{"frintn", "frintm", "fcvtns", "fcvtms"}, {"frintp", "frintz", "fcvtps", "fcvtzs"}},
                {{"frinta", "frintx", "fcvtnu", "fcvtmu"}, {nullptr, "frinti", "fcvtpu", "fcvtzu"}}};
            m = kRound[u][fpSize ? 1 : 0][opcode - 0x18];
            fpOp = true;
            break;
        }
        case 0x1c: if (!fpSize) m = u ? "fcvtau" : "fcvtas", fpOp = true; break;
        case 0x1d: if (!fpSize) m = u ? "ucvtf" : "scvtf", fpOp = true; break;
        default: break;
        }
        if (!m) return unknown(i);
        const char* arr = fpOp ? farr : kArr[size][q];
        if (!arr) return unknown(i);
        if (!fpOp && (opcode == 0x05)) arr = q ? "16b" : "8b";
        std::string ops = v(rd, arr) + ", " + v(rn, arr);
        if (opcode >= 0x08 && opcode <= 0x0a) ops += ", #0";
        return make(i, m, ops);
    }
    // Advanced SIMD three same (integer and logical): 0 Q U 01110 size 1 Rm opcode 1 Rn Rd.
    if ((w & 0x9f200400) == 0x0e200400 && bits(w, 15, 11) < 0x18) {
        const bool q = bit(w, 30), u = bit(w, 29);
        const unsigned size = bits(w, 23, 22), opcode = bits(w, 15, 11);
        static const char* const kArr[4][2] = {{"8b", "16b"}, {"4h", "8h"}, {"2s", "4s"}, {"1d", "2d"}};
        if (opcode == 3) {  // logical: arrangement is always bytes
            static const char* const kLogic[2][4] = {{"and", "bic", "orr", "orn"}, {"eor", "bsl", "bit", "bif"}};
            const char* arr = q ? "16b" : "8b";
            if (!u && size == 2 && rn == rm) return make(i, "mov", v(rd, arr) + ", " + v(rn, arr));
            return make(i, kLogic[u][size], v(rd, arr) + ", " + v(rn, arr) + ", " + v(rm, arr));
        }
        static const char* const kOps[2][24] = {
            {"shadd", "sqadd", "srhadd", nullptr, "shsub", "sqsub", "cmgt", "cmge", "sshl", "sqshl", "srshl", "sqrshl",
             "smax", "smin", "sabd", "saba", "add", "cmtst", "mla", "mul", "smaxp", "sminp", "sqdmulh", "addp"},
            {"uhadd", "uqadd", "urhadd", nullptr, "uhsub", "uqsub", "cmhi", "cmhs", "ushl", "uqshl", "urshl", "uqrshl",
             "umax", "umin", "uabd", "uaba", "sub", "cmeq", "mls", "pmul", "umaxp", "uminp", "sqrdmulh", nullptr}};
        const char* m = kOps[u][opcode];
        if (!m || (size == 3 && !q)) return unknown(i);
        const char* arr = kArr[size][q];
        return make(i, m, v(rd, arr) + ", " + v(rn, arr) + ", " + v(rm, arr));
    }
    // Advanced SIMD copy: dup / ins / umov / smov.
    if ((w & 0x9fe08400) == 0x0e000400) {
        const bool q = bit(w, 30), op = bit(w, 29);
        const unsigned imm5 = bits(w, 20, 16), imm4 = bits(w, 14, 11);
        int shift = -1;
        for (int b = 0; b < 4; ++b)
            if (imm5 & (1u << b)) {
                shift = b;
                break;
            }
        if (shift < 0) return unknown(i);
        static const char kElem[4] = {'b', 'h', 's', 'd'};
        const char e = kElem[shift];
        const unsigned idx = imm5 >> (shift + 1);
        const auto elem = [&](unsigned n, unsigned k) {
            return "v" + std::to_string(n) + "." + e + "[" + std::to_string(k) + "]";
        };
        static const char* const kArr[4][2] = {{"8b", "16b"}, {"4h", "8h"}, {"2s", "4s"}, {nullptr, "2d"}};
        if (op) {  // ins (element)
            const unsigned src = bits(w, 14, 11) >> shift;
            return make(i, "mov", elem(rd, idx) + ", " + elem(rn, src));
        }
        switch (imm4) {
        case 0:
            if (!kArr[shift][q]) return unknown(i);
            return make(i, "dup", v(rd, kArr[shift][q]) + ", " + elem(rn, idx));
        case 1:
            if (!kArr[shift][q]) return unknown(i);
            return make(i, "dup", v(rd, kArr[shift][q]) + ", " + reg(rn, shift == 3));
        case 3: return make(i, "mov", elem(rd, idx) + ", " + reg(rn, shift == 3));
        case 5: return make(i, "smov", reg(rd, q) + ", " + elem(rn, idx));
        case 7:
            if (shift >= 2) return make(i, "mov", reg(rd, shift == 3) + ", " + elem(rn, idx));
            return make(i, "umov", reg(rd, false) + ", " + elem(rn, idx));
        default: return unknown(i);
        }
    }
    // Advanced SIMD modified immediate: movi / mvni / orr / bic / fmov (vector).
    if ((w & 0x9ff80400) == 0x0f000400) {
        const bool q = bit(w, 30), op = bit(w, 29);
        const unsigned cmode = bits(w, 15, 12);
        const unsigned imm8 = (bits(w, 18, 16) << 5) | bits(w, 9, 5);
        if (cmode == 0xe && op) {  // 64-bit byte mask
            uint64_t m = 0;
            for (int b = 0; b < 8; ++b)
                if (imm8 & (1u << b)) m |= 0xffull << (b * 8);
            if (!q) return make(i, "movi", vreg(rd, 'd') + ", #" + hex(m));
            return make(i, "movi", v(rd, "2d") + ", #" + hex(m));
        }
        if (cmode == 0xe) return make(i, "movi", v(rd, q ? "16b" : "8b") + ", " + uimm(imm8));
        if (cmode == 0xf && !op) return make(i, "fmov", v(rd, q ? "4s" : "2s") + ", " + fpImm(imm8));
        if (cmode == 0xf && op && q) return make(i, "fmov", v(rd, "2d") + ", " + fpImm(imm8));
        const bool half = (cmode & 0xc) == 0x8;
        const char* arr = half ? (q ? "8h" : "4h") : (q ? "4s" : "2s");
        std::string amount;
        if ((cmode & 0xe) == 0xc) amount = ", msl #" + std::to_string((cmode & 1) ? 16 : 8);
        else if (const unsigned sh = half ? ((cmode >> 1) & 1) * 8 : ((cmode >> 1) & 3) * 8; sh) amount = ", lsl #" + std::to_string(sh);
        const bool logical = (cmode & 1) && (cmode & 0xc) != 0xc;
        const char* m = logical ? (op ? "bic" : "orr") : (op ? "mvni" : "movi");
        return make(i, m, v(rd, arr) + ", " + uimm(imm8) + amount);
    }

    if (bits(w, 31, 24) == 0x1f) {  // fmadd / fmsub / fnmadd / fnmsub
        if (sz == '?') return unknown(i);
        static const char* const names[4] = {"fmadd", "fmsub", "fnmadd", "fnmsub"};
        const unsigned ra = bits(w, 14, 10);
        return make(i, names[(bit(w, 21) << 1) | bit(w, 15)],
                    vreg(rd, sz) + ", " + vreg(rn, sz) + ", " + vreg(rm, sz) + ", " + vreg(ra, sz));
    }
    if ((bits(w, 30, 24) != 0x1e) || !bit(w, 21) || bit(w, 29) || sz == '?') return unknown(i);
    const bool sf = bit(w, 31);

    if (bits(w, 15, 10) == 0) {  // conversion between FP and integer
        const unsigned rmode = bits(w, 20, 19), opcode = bits(w, 18, 16);
        const std::string gd = reg(rd, sf), gn = reg(rn, sf), fd = vreg(rd, sz), fn = vreg(rn, sz);
        if (rmode == 0 && opcode == 2) return make(i, "scvtf", fd + ", " + gn);
        if (rmode == 0 && opcode == 3) return make(i, "ucvtf", fd + ", " + gn);
        if (opcode == 6 && rmode == 0) return make(i, "fmov", gd + ", " + fn);
        if (opcode == 7 && rmode == 0) return make(i, "fmov", fd + ", " + gn);
        if (opcode == 6 && rmode == 1 && sf && ftype == 2) return make(i, "fmov", gd + ", v" + std::to_string(rn) + ".d[1]");
        if (opcode == 7 && rmode == 1 && sf && ftype == 2) return make(i, "fmov", "v" + std::to_string(rd) + ".d[1], " + gn);
        if (opcode == 0 || opcode == 1) {
            static const char* const modes[4] = {"n", "p", "m", "z"};
            i.mnemonic = std::string("fcvt") + modes[rmode] + (opcode ? "u" : "s");
            i.operands = gd + ", " + fn;
            return i;
        }
        if (opcode == 4 || opcode == 5) {
            i.mnemonic = std::string("fcvta") + (opcode == 5 ? "u" : "s");
            i.operands = gd + ", " + fn;
            return i;
        }
        return unknown(i);
    }
    if (bits(w, 14, 10) == 0x10) {  // 1 source
        const unsigned opcode = bits(w, 20, 15);
        const std::string d = vreg(rd, sz), n = vreg(rn, sz);
        switch (opcode) {
        case 0: return make(i, "fmov", d + ", " + n);
        case 1: return make(i, "fabs", d + ", " + n);
        case 2: return make(i, "fneg", d + ", " + n);
        case 3: return make(i, "fsqrt", d + ", " + n);
        case 4: return make(i, "fcvt", vreg(rd, 's') + ", " + n);
        case 5: return make(i, "fcvt", vreg(rd, 'd') + ", " + n);
        case 7: return make(i, "fcvt", vreg(rd, 'h') + ", " + n);
        case 8: return make(i, "frintn", d + ", " + n);
        case 9: return make(i, "frintp", d + ", " + n);
        case 10: return make(i, "frintm", d + ", " + n);
        case 11: return make(i, "frintz", d + ", " + n);
        case 12: return make(i, "frinta", d + ", " + n);
        case 14: return make(i, "frintx", d + ", " + n);
        case 15: return make(i, "frinti", d + ", " + n);
        default: return unknown(i);
        }
    }
    if (bits(w, 13, 10) == 8) {  // compare
        const unsigned opc = bits(w, 4, 3);
        const char* m = (opc & 2) ? "fcmpe" : "fcmp";
        return make(i, m, vreg(rn, sz) + ", " + ((opc & 1) ? std::string("#0.0") : vreg(rm, sz)));
    }
    if (bits(w, 12, 10) == 4) return make(i, "fmov", vreg(rd, sz) + ", " + fpImm(bits(w, 20, 13)));
    if (bits(w, 11, 10) == 2) {  // 2 source
        static const char* const names[9] = {"fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"};
        const unsigned opcode = bits(w, 15, 12);
        if (opcode > 8) return unknown(i);
        return make(i, names[opcode], vreg(rd, sz) + ", " + vreg(rn, sz) + ", " + vreg(rm, sz));
    }
    if (bits(w, 11, 10) == 3)
        return make(i, "fcsel", vreg(rd, sz) + ", " + vreg(rn, sz) + ", " + vreg(rm, sz) + ", " + kCond[bits(w, 15, 12)]);
    if (bits(w, 11, 10) == 1)
        return make(i, bit(w, 4) ? "fccmpe" : "fccmp",
                    vreg(rn, sz) + ", " + vreg(rm, sz) + ", " + uimm(bits(w, 3, 0)) + ", " + kCond[bits(w, 15, 12)]);
    return unknown(i);
}

}  // namespace

const char* conditionName(unsigned cond) { return kCond[cond & 15]; }

Insn decode(uint32_t word, uint64_t pc) {
    Insn i;
    i.addr = pc;
    i.raw = word;
    if (word == 0) {
        i.flow = Flow::Trap;
        return make(i, "udf", "#0");
    }
    const unsigned op0 = bits(word, 28, 25);
    if ((op0 & 0xe) == 0x8) return dataImm(i);
    if ((op0 & 0xe) == 0xa) return branchSys(i);
    if ((op0 & 0x5) == 0x4) return loadStore(i);
    if ((op0 & 0x7) == 0x5) return dataReg(i);
    if ((op0 & 0x7) == 0x7) return fp(i);
    return unknown(i);
}

}  // namespace arm64
