#include "analysis/X86.hpp"
#include <cstdio>
#include <string>

namespace x86 {
namespace {

using native::Flow;
using native::Insn;

const char* const kR64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
const char* const kR32[16] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
const char* const kR16[16] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
const char* const kR8[16] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
const char* const kR8Legacy[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
const char* const kCC[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"};
const char* const kSeg[6] = {"es", "cs", "ss", "ds", "fs", "gs"};
const char* const k16Addr[8] = {"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"};

std::string hexs(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}
std::string imms(int64_t v) {
    if (v < 0) {
        char b[24];
        std::snprintf(b, sizeof b, "-0x%llx", static_cast<unsigned long long>(-(v + 1)) + 1ull);
        return b;
    }
    return hexs(static_cast<uint64_t>(v));
}
const char* sizeName(int bits) {
    switch (bits) {
    case 8: return "byte";
    case 16: return "word";
    case 32: return "dword";
    case 64: return "qword";
    case 80: return "tbyte";
    case 128: return "xmmword";
    case 256: return "ymmword";
    default: return "";
    }
}

// Name of an SSE / SSE2 opcode of the 0F map; pp: 0 none, 1 = 66, 2 = F3, 3 = F2. nullptr when not named here.
std::string sseName(uint8_t op, int pp) {
    static const char* const sfx[4] = {"ps", "pd", "ss", "sd"};
    const auto pick = [&](const char* a, const char* b, const char* c, const char* d) {
        const char* v[4] = {a, b, c, d};
        return std::string(v[pp]);
    };
    switch (op) {
    case 0x10: case 0x11: return pick("movups", "movupd", "movss", "movsd");
    case 0x12: return pick("movlps", "movlpd", "movsldup", "movddup");
    case 0x13: return pick("movlps", "movlpd", "", "");
    case 0x14: return pp < 2 ? std::string("unpcklp") + (pp ? "d" : "s") : "";
    case 0x15: return pp < 2 ? std::string("unpckhp") + (pp ? "d" : "s") : "";
    case 0x16: return pick("movhps", "movhpd", "movshdup", "");
    case 0x17: return pick("movhps", "movhpd", "", "");
    case 0x28: case 0x29: return pp < 2 ? (pp ? "movapd" : "movaps") : "";
    case 0x2A: return pick("cvtpi2ps", "cvtpi2pd", "cvtsi2ss", "cvtsi2sd");
    case 0x2B: return pp < 2 ? (pp ? "movntpd" : "movntps") : "";
    case 0x2C: return pick("cvttps2pi", "cvttpd2pi", "cvttss2si", "cvttsd2si");
    case 0x2D: return pick("cvtps2pi", "cvtpd2pi", "cvtss2si", "cvtsd2si");
    case 0x2E: return pp < 2 ? (pp ? "ucomisd" : "ucomiss") : "";
    case 0x2F: return pp < 2 ? (pp ? "comisd" : "comiss") : "";
    case 0x50: return pp < 2 ? (pp ? "movmskpd" : "movmskps") : "";
    case 0x51: return std::string("sqrt") + sfx[pp];
    case 0x52: return pp == 0 ? "rsqrtps" : pp == 2 ? "rsqrtss" : "";
    case 0x53: return pp == 0 ? "rcpps" : pp == 2 ? "rcpss" : "";
    case 0x54: return pp < 2 ? std::string("andp") + (pp ? "d" : "s") : "";
    case 0x55: return pp < 2 ? std::string("andnp") + (pp ? "d" : "s") : "";
    case 0x56: return pp < 2 ? std::string("orp") + (pp ? "d" : "s") : "";
    case 0x57: return pp < 2 ? std::string("xorp") + (pp ? "d" : "s") : "";
    case 0x58: return std::string("add") + sfx[pp];
    case 0x59: return std::string("mul") + sfx[pp];
    case 0x5A: return pick("cvtps2pd", "cvtpd2ps", "cvtss2sd", "cvtsd2ss");
    case 0x5B: return pick("cvtdq2ps", "cvtps2dq", "cvttps2dq", "");
    case 0x5C: return std::string("sub") + sfx[pp];
    case 0x5D: return std::string("min") + sfx[pp];
    case 0x5E: return std::string("div") + sfx[pp];
    case 0x5F: return std::string("max") + sfx[pp];
    case 0x60: return "punpcklbw";
    case 0x61: return "punpcklwd";
    case 0x62: return "punpckldq";
    case 0x63: return "packsswb";
    case 0x64: return "pcmpgtb";
    case 0x65: return "pcmpgtw";
    case 0x66: return "pcmpgtd";
    case 0x67: return "packuswb";
    case 0x68: return "punpckhbw";
    case 0x69: return "punpckhwd";
    case 0x6A: return "punpckhdq";
    case 0x6B: return "packssdw";
    case 0x6C: return "punpcklqdq";
    case 0x6D: return "punpckhqdq";
    case 0x6E: return "movd";
    case 0x6F: case 0x7F: return pick("movq", "movdqa", "movdqu", "");
    case 0x70: return pick("pshufw", "pshufd", "pshufhw", "pshuflw");
    case 0x74: return "pcmpeqb";
    case 0x75: return "pcmpeqw";
    case 0x76: return "pcmpeqd";
    case 0x7C: return pick("", "haddpd", "", "haddps");
    case 0x7D: return pick("", "hsubpd", "", "hsubps");
    case 0x7E: return pp == 2 ? "movq" : "movd";
    case 0xC2: return std::string("cmp") + sfx[pp];
    case 0xC4: return "pinsrw";
    case 0xC5: return "pextrw";
    case 0xC6: return pp < 2 ? (pp ? "shufpd" : "shufps") : "";
    case 0xD0: return pick("", "addsubpd", "", "addsubps");
    case 0xD1: return "psrlw";
    case 0xD2: return "psrld";
    case 0xD3: return "psrlq";
    case 0xD4: return "paddq";
    case 0xD5: return "pmullw";
    case 0xD6: return "movq";
    case 0xD7: return "pmovmskb";
    case 0xD8: return "psubusb";
    case 0xD9: return "psubusw";
    case 0xDA: return "pminub";
    case 0xDB: return "pand";
    case 0xDC: return "paddusb";
    case 0xDD: return "paddusw";
    case 0xDE: return "pmaxub";
    case 0xDF: return "pandn";
    case 0xE0: return "pavgb";
    case 0xE1: return "psraw";
    case 0xE2: return "psrad";
    case 0xE3: return "pavgw";
    case 0xE4: return "pmulhuw";
    case 0xE5: return "pmulhw";
    case 0xE6: return pick("", "cvttpd2dq", "cvtdq2pd", "cvtpd2dq");
    case 0xE7: return pp == 1 ? "movntdq" : "movntq";
    case 0xE8: return "psubsb";
    case 0xE9: return "psubsw";
    case 0xEA: return "pminsw";
    case 0xEB: return "por";
    case 0xEC: return "paddsb";
    case 0xED: return "paddsw";
    case 0xEE: return "pmaxsw";
    case 0xEF: return "pxor";
    case 0xF0: return pp == 3 ? "lddqu" : "";
    case 0xF1: return "psllw";
    case 0xF2: return "pslld";
    case 0xF3: return "psllq";
    case 0xF4: return "pmuludq";
    case 0xF5: return "pmaddwd";
    case 0xF6: return "psadbw";
    case 0xF8: return "psubb";
    case 0xF9: return "psubw";
    case 0xFA: return "psubd";
    case 0xFB: return "psubq";
    case 0xFC: return "paddb";
    case 0xFD: return "paddw";
    case 0xFE: return "paddd";
    default: return "";
    }
}

struct Decoder {
    const uint8_t* p;
    size_t len;
    uint64_t addr;
    bool is64;
    size_t i = 0;
    bool bad = false;
    // prefixes
    bool opsz = false, adsz = false, rep = false, repne = false, lock = false;
    int segOverride = -1;
    uint8_t rex = 0;
    bool hasRex = false;
    // ModRM
    bool hasModrm = false;
    uint8_t mod = 0, regField = 0, rmField = 0;  // raw 3-bit fields
    std::string mem;                             // "[rax+rcx*4+0x10]" (with segment), empty for register operands
    bool ripRel = false;
    int64_t ripDisp = 0;
    int memBase = -1;      // single base register, no index (extended number), -1 otherwise
    int64_t memDisp = 0;
    bool memPlain = false;  // exactly [base+disp]

    // output
    std::string mn, ops;
    Flow flow = Flow::Normal;
    bool hasTarget = false, memTarget = false, isLoad = false, isLea = false;
    uint64_t target = 0;
    int destReg = -1;

    uint8_t u8() {
        if (i >= len) {
            bad = true;
            return 0;
        }
        return p[i++];
    }
    uint32_t u16() { return u8() | static_cast<uint32_t>(u8()) << 8; }
    uint32_t u32() { return u16() | static_cast<uint32_t>(u16()) << 16; }
    uint64_t u64() { return u32() | static_cast<uint64_t>(u32()) << 32; }
    int64_t s8() { return static_cast<int8_t>(u8()); }
    int64_t s16() { return static_cast<int16_t>(u16()); }
    int64_t s32() { return static_cast<int32_t>(u32()); }

    bool rexW() const { return (rex & 8) != 0; }
    int osz() const { return rexW() ? 64 : opsz ? 16 : 32; }
    int stackSz() const { return is64 ? (opsz ? 16 : 64) : (opsz ? 16 : 32); }
    int rexR() const { return (rex & 4) ? 8 : 0; }
    int rexX() const { return (rex & 2) ? 8 : 0; }
    int rexB() const { return (rex & 1) ? 8 : 0; }

    std::string reg(int n, int bits) const {
        n &= is64 ? 15 : 7;
        switch (bits) {
        case 8: return hasRex || n >= 8 ? kR8[n] : (n < 8 ? kR8Legacy[n] : kR8[n]);
        case 16: return kR16[n];
        case 32: return kR32[n];
        default: return kR64[n];
        }
    }
    std::string xmm(int n, int bits = 128) const { return std::string(bits == 256 ? "ymm" : bits == 512 ? "zmm" : "xmm") + std::to_string(n); }

    // Reads the ModRM byte and everything it implies (SIB, displacement).
    void modrm() {
        const uint8_t m = u8();
        hasModrm = true;
        mod = m >> 6;
        regField = (m >> 3) & 7;
        rmField = m & 7;
        mem.clear();
        ripRel = false;
        memPlain = false;
        memBase = -1;
        memDisp = 0;
        if (mod == 3) return;
        std::string seg = segOverride >= 0 ? std::string(kSeg[segOverride]) + ":" : std::string();
        const bool addr16 = !is64 && adsz;
        if (addr16) {
            std::string body;
            if (mod == 0 && rmField == 6) {
                body = hexs(u16());
            } else {
                body = k16Addr[rmField];
                if (mod == 1) {
                    const int64_t d = s8();
                    body += (d < 0 ? "-" : "+") + hexs(static_cast<uint64_t>(d < 0 ? -d : d));
                } else if (mod == 2) {
                    const int64_t d = s16();
                    body += (d < 0 ? "-" : "+") + hexs(static_cast<uint64_t>(d < 0 ? -d : d));
                }
            }
            mem = seg + "[" + body + "]";
            return;
        }
        const bool a64 = is64 && !adsz;
        const auto aname = [&](int n) { return std::string(a64 ? kR64[n & 15] : kR32[n & 15]); };
        int base = -1, index = -1, scale = 1;
        int64_t disp = 0;
        bool haveDisp = false, noBase = false;
        if (rmField == 4) {
            const uint8_t sib = u8();
            scale = 1 << (sib >> 6);
            index = ((sib >> 3) & 7) | rexX();
            if (index == 4) index = -1;
            base = (sib & 7) | rexB();
            if ((sib & 7) == 5 && mod == 0) {
                noBase = true;
                base = -1;
                disp = s32();
                haveDisp = true;
            }
        } else if (rmField == 5 && mod == 0) {
            if (is64) {
                ripRel = true;
                ripDisp = s32();
                mem = seg + "[" + (a64 ? "rip" : "eip") + (ripDisp < 0 ? "-" : "+") + hexs(static_cast<uint64_t>(ripDisp < 0 ? -ripDisp : ripDisp)) + "]";
                return;
            }
            noBase = true;
            disp = s32();
            haveDisp = true;
        } else {
            base = rmField | rexB();
        }
        if (mod == 1) disp = s8(), haveDisp = true;
        else if (mod == 2) disp = s32(), haveDisp = true;
        std::string body;
        if (base >= 0) body = aname(base);
        if (index >= 0) {
            if (!body.empty()) body += "+";
            body += aname(index);
            if (scale > 1) body += "*" + std::to_string(scale);
        }
        if (noBase && index < 0) {
            body = hexs(static_cast<uint64_t>(disp) & (is64 ? ~0ull : 0xffffffffull));
        } else if (haveDisp && (disp != 0 || mod != 0 || noBase)) {
            if (noBase && body.empty()) body = hexs(static_cast<uint64_t>(disp));
            else body += (disp < 0 ? "-" : "+") + hexs(static_cast<uint64_t>(disp < 0 ? -disp : disp));
        }
        mem = seg + "[" + body + "]";
        if (base >= 0 && index < 0 && !noBase) {
            memPlain = true;
            memBase = base;
            memDisp = haveDisp ? disp : 0;
        } else if (noBase && index < 0) {
            memPlain = false;
        }
    }

    std::string memOp(int bits) const {
        const char* sn = sizeName(bits);
        return (*sn ? std::string(sn) + " ptr " : std::string()) + mem;
    }
    // r/m operand of the given integer size.
    std::string E(int bits) const { return mod == 3 ? reg(rmField | rexB(), bits) : memOp(bits); }
    std::string G(int bits) const { return reg(regField | rexR(), bits); }
    // r/m operand holding an xmm register or memory.
    std::string X(int memBits, int vecBits = 128) const { return mod == 3 ? xmm(rmField | rexB(), vecBits) : memOp(memBits); }
    std::string XG(int vecBits = 128) const { return xmm(regField | rexR(), vecBits); }

    void set(const std::string& m, const std::string& o = std::string()) {
        mn = m;
        ops = o;
    }
    void branch(const std::string& m, int64_t rel, Flow f, uint64_t instrEndIfKnown = 0) {
        (void)instrEndIfKnown;
        mn = m;
        flow = f;
        hasTarget = true;
        // The target needs the final length, known once the displacement was read.
        target = addr + i + static_cast<uint64_t>(rel);
        if (!is64) target &= 0xffffffffull;
        ops = hexs(target);
    }

    std::string aluName(int n) const {
        static const char* const names[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        return names[n & 7];
    }
    std::string imm(int bytes, int opBits) {
        int64_t v = 0;
        if (bytes == 1) v = s8();
        else if (bytes == 2) v = s16();
        else if (bytes == 4) v = s32();
        else v = static_cast<int64_t>(u64());
        if (opBits == 8 && v < 0) v &= 0xff;
        if (opBits == 16 && v < 0) v &= 0xffff;
        if (opBits == 32 && v < 0 && bytes > 1) v &= 0xffffffffll;
        return imms(v);
    }

    void doTwoByte();
    void doVex(bool evex);
    void doX87(uint8_t op);
    void decode();
};

void Decoder::doX87(uint8_t op) {
    modrm();
    static const char* const arith[8] = {"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"};
    if (mod != 3) {
        const int r = regField;
        const char* m = nullptr;
        int bits = 32;
        switch (op) {
        case 0xD8: m = arith[r]; bits = 32; break;
        case 0xDC: m = arith[r]; bits = 64; break;
        case 0xD9: {
            static const char* const t[8] = {"fld", "", "fst", "fstp", "fldenv", "fldcw", "fnstenv", "fnstcw"};
            m = t[r];
            bits = r == 5 || r == 7 ? 16 : r == 4 || r == 6 ? 0 : 32;
            break;
        }
        case 0xDD: {
            static const char* const t[8] = {"fld", "fisttp", "fst", "fstp", "frstor", "", "fnsave", "fnstsw"};
            m = t[r];
            bits = r == 4 || r == 6 ? 0 : r == 7 ? 16 : 64;
            break;
        }
        case 0xDB: {
            static const char* const t[8] = {"fild", "fisttp", "fist", "fistp", "", "fld", "", "fstp"};
            m = t[r];
            bits = r == 5 || r == 7 ? 80 : 32;
            break;
        }
        case 0xDF: {
            static const char* const t[8] = {"fild", "fisttp", "fist", "fistp", "fbld", "fild", "fbstp", "fistp"};
            m = t[r];
            bits = r == 4 || r == 6 ? 80 : r == 5 || r == 7 ? 64 : 16;
            break;
        }
        case 0xDA: {
            static const char* const t[8] = {"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"};
            m = t[r];
            break;
        }
        case 0xDE: {
            static const char* const t[8] = {"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"};
            m = t[r];
            bits = 16;
            break;
        }
        default: break;
        }
        if (!m || !*m) {
            set("(bad)");
            bad = true;
            return;
        }
        set(m, memOp(bits));
        return;
    }
    // Register forms: the common ones by name, the rest generically.
    const int st = rmField;
    const std::string sti = "st(" + std::to_string(st) + ")";
    switch (op) {
    case 0xD8: set(arith[regField], regField == 2 || regField == 3 ? sti : "st, " + sti); return;
    case 0xDC: set(arith[regField == 4 ? 5 : regField == 5 ? 4 : regField == 6 ? 7 : regField == 7 ? 6 : regField], sti + ", st"); return;
    case 0xDE:
        if (regField == 3 && st == 1) set("fcompp");
        else set(std::string(arith[regField == 4 ? 5 : regField == 5 ? 4 : regField == 6 ? 7 : regField == 7 ? 6 : regField]) + "p", sti + ", st");
        return;
    case 0xD9:
        if (regField == 0) set("fld", sti);
        else if (regField == 1) set("fxch", sti);
        else if (regField == 2) set(st == 0 ? "fnop" : "fpu");
        else if (regField == 3) set("fpu");
        else {
            static const char* const d9[4][8] = {{"fchs", "fabs", "", "", "ftst", "fxam", "", ""},
                                                 {"fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", ""},
                                                 {"f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp"},
                                                 {"fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos"}};
            const char* n = d9[regField - 4][st];
            set(*n ? n : "fpu");
        }
        return;
    case 0xDA: {
        static const char* const c[4] = {"fcmovb", "fcmove", "fcmovbe", "fcmovu"};
        if (regField < 4) set(c[regField], "st, " + sti);
        else if (regField == 5 && st == 1) set("fucompp");
        else set("fpu");
        return;
    }
    case 0xDB: {
        static const char* const c[8] = {"fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu", "", "fucomi", "fcomi", ""};
        if (regField == 4 && st == 2) set("fnclex");
        else if (regField == 4 && st == 3) set("fninit");
        else if (c[regField][0]) set(c[regField], "st, " + sti);
        else set("fpu");
        return;
    }
    case 0xDD: {
        static const char* const c[8] = {"ffree", "", "fst", "fstp", "fucom", "fucomp", "", ""};
        if (c[regField][0]) set(c[regField], sti);
        else set("fpu");
        return;
    }
    case 0xDF:
        if (regField == 4 && st == 0) set("fnstsw", "ax");
        else if (regField == 5) set("fucomip", "st, " + sti);
        else if (regField == 6) set("fcomip", "st, " + sti);
        else set("fpu");
        return;
    default: set("fpu"); return;
    }
}

void Decoder::doVex(bool evex) {
    // The prefix byte (C4 / C5 / 62) has been read. VEX payload bytes follow.
    int map = 1, pp = 0, L = 0, vvvv = 0;
    bool w = false;
    uint8_t rx = 0;  // inverted R X B bits as in REX
    if (evex) {
        const uint8_t p0 = u8(), p1 = u8(), p2 = u8();
        map = p0 & 7;
        pp = p1 & 3;
        w = (p1 & 0x80) != 0;
        vvvv = (~p1 >> 3) & 15;
        L = (p2 >> 5) & 3;
        rx = static_cast<uint8_t>(((~p0 >> 5) & 7));
    } else if (p[i - 1] == 0xC5) {
        const uint8_t b = u8();
        rx = static_cast<uint8_t>(((~b >> 7) & 1) << 2);
        vvvv = (~b >> 3) & 15;
        L = (b >> 2) & 1;
        pp = b & 3;
    } else {
        const uint8_t b1 = u8(), b2 = u8();
        rx = static_cast<uint8_t>((~b1 >> 5) & 7);
        map = b1 & 31;
        w = (b2 & 0x80) != 0;
        vvvv = (~b2 >> 3) & 15;
        L = (b2 >> 2) & 1;
        pp = b2 & 3;
    }
    rex = static_cast<uint8_t>(0x40 | (w ? 8 : 0) | (rx & 4) | (rx & 2) | (rx & 1));
    hasRex = true;
    const uint8_t op = u8();
    if (!evex && map == 1 && op == 0x77) {  // vzeroupper / vzeroall: no ModRM byte
        set(L ? "vzeroall" : "vzeroupper");
        return;
    }
    const int vec = evex ? (L == 0 ? 128 : L == 1 ? 256 : 512) : (L ? 256 : 128);
    modrm();
    // Shifts by immediate (the destination is vvvv) and the BMI instructions work on other operands.
    if (map == 1 && (op == 0x71 || op == 0x72 || op == 0x73)) {
        const char* n = nullptr;
        if (op == 0x71) n = regField == 2 ? "vpsrlw" : regField == 4 ? "vpsraw" : regField == 6 ? "vpsllw" : nullptr;
        if (op == 0x72) n = regField == 2 ? "vpsrld" : regField == 4 ? "vpsrad" : regField == 6 ? "vpslld" : nullptr;
        if (op == 0x73) n = regField == 2 ? "vpsrlq" : regField == 3 ? "vpsrldq" : regField == 6 ? "vpsllq" : regField == 7 ? "vpslldq" : nullptr;
        if (n) {
            const int64_t ib = s8();
            set(n, xmm(vvvv, vec) + ", " + X(vec, vec) + ", " + imms(ib & 0xff));
            return;
        }
    }
    if (map == 2 && (op == 0xF7 || op == 0xF5 || op == 0xF2) && !evex) {
        const int gb = w ? 64 : 32;
        const std::string e = E(gb), g = G(gb), v = reg(vvvv, gb);
        if (op == 0xF7) set(pp == 0 ? "bextr" : pp == 1 ? "shlx" : pp == 2 ? "sarx" : "shrx", g + ", " + e + ", " + v);
        else if (op == 0xF5) set(pp == 0 ? "bzhi" : pp == 2 ? "pext" : "pdep", pp == 0 ? g + ", " + e + ", " + v : g + ", " + v + ", " + e);
        else set("andn", g + ", " + v + ", " + e);
        return;
    }
    bool immByte = map == 3 || (map == 1 && (op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 || op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6));
    std::string name = map == 1 ? sseName(op, pp) : std::string();
    if (map == 2 || map == 3) {
        static const struct { int map; uint8_t op; const char* name; } t[] = {
            {2, 0x00, "pshufb"},  {2, 0x17, "ptest"},   {2, 0x18, "broadcastss"}, {2, 0x19, "broadcastsd"}, {2, 0x36, "permd"},
            {2, 0x40, "pmulld"},  {2, 0x58, "pbroadcastd"}, {2, 0x59, "pbroadcastq"}, {2, 0x78, "pbroadcastb"}, {2, 0x79, "pbroadcastw"},
            {2, 0x45, "psrlv"},   {2, 0x46, "psravd"},  {2, 0x47, "psllv"},       {2, 0xDC, "aesenc"},       {2, 0xDD, "aesenclast"},
            {2, 0xDE, "aesdec"},  {2, 0xDF, "aesdeclast"}, {3, 0x00, "permq"},    {3, 0x01, "permpd"},       {3, 0x06, "perm2f128"},
            {3, 0x0E, "pblendw"}, {3, 0x0F, "palignr"}, {3, 0x18, "insertf128"},  {3, 0x19, "extractf128"},  {3, 0x38, "inserti128"},
            {3, 0x39, "extracti128"}, {3, 0x46, "perm2i128"}, {3, 0x44, "pclmulqdq"}, {3, 0xDF, "aeskeygenassist"}};
        for (const auto& e : t)
            if (e.map == map && e.op == op) name = e.name;
    }
    char tmp[40];
    if (name.empty()) {
        std::snprintf(tmp, sizeof tmp, "%s map%d %02x", evex ? "evex" : "vex", map, op);
        mn = tmp;
    } else {
        mn = "v" + name;
    }
    std::string o = XG(vec) + ", ";
    const bool noNds = map == 2 && (op == 0x17 || op == 0x18 || op == 0x19 || op == 0x58 || op == 0x59 || op == 0x78 || op == 0x79 || (op >= 0x20 && op <= 0x35)) ||
                       map == 3 && (op == 0x00 || op == 0x01 || op == 0x39 || op == 0x19 || op == 0xDF);
    const bool nds = !noNds && map != 1 || (op >= 0x54 && op <= 0x5F && op != 0x5A && op != 0x5B) || op == 0x14 || op == 0x15 || op == 0xC6 ||
                     (op >= 0x60 && op <= 0x6D) || (op >= 0x74 && op <= 0x76) || (op >= 0xD1 && op <= 0xFE && op != 0xD6 && op != 0xD7 && op != 0xE6 && op != 0xE7);
    if (nds) o += xmm(vvvv, vec) + ", ";
    o += X(vec, vec);
    if (immByte) o += ", " + imms(s8());
    ops = o;
    if (!name.empty() && (op == 0x11 || op == 0x13 || op == 0x17 || op == 0x29 || op == 0x2B || op == 0x7F || op == 0xD6 || op == 0xE7)) {
        // stores: r/m first
        const size_t comma = ops.find(", ");
        if (comma != std::string::npos) ops = ops.substr(comma + 2) + ", " + ops.substr(0, comma);
    }
}

void Decoder::doTwoByte() {
    const uint8_t op = u8();
    const int pp = rep ? 2 : repne ? 3 : opsz ? 1 : 0;
    const int osz_ = osz();
    char tmp[48];
    if (op >= 0x80 && op <= 0x8F) {
        const int64_t rel = s32();
        branch(std::string("j") + kCC[op & 15], rel, Flow::CondJump);
        return;
    }
    if (op >= 0x90 && op <= 0x9F) {
        modrm();
        set(std::string("set") + kCC[op & 15], E(8));
        return;
    }
    if (op >= 0x40 && op <= 0x4F) {
        modrm();
        set(std::string("cmov") + kCC[op & 15], G(osz_) + ", " + E(osz_));
        isLoad = mod != 3;
        return;
    }
    if (op >= 0xC8 && op <= 0xCF) {
        set("bswap", reg((op & 7) | rexB(), rexW() ? 64 : 32));
        return;
    }
    switch (op) {
    case 0x05: set("syscall"); return;
    case 0x07: set("sysret"); return;
    case 0x0B: set("ud2"); flow = Flow::Trap; return;
    case 0x30: set("wrmsr"); return;
    case 0x31: set("rdtsc"); return;
    case 0x32: set("rdmsr"); return;
    case 0x33: set("rdpmc"); return;
    case 0x34: set("sysenter"); return;
    case 0x35: set("sysexit"); return;
    case 0x77: set("emms"); return;
    case 0xA2: set("cpuid"); return;
    case 0xA0: set("push", "fs"); return;
    case 0xA1: set("pop", "fs"); return;
    case 0xA8: set("push", "gs"); return;
    case 0xA9: set("pop", "gs"); return;
    case 0xAA: set("rsm"); return;
    case 0x0D: case 0x18: modrm(); set(op == 0x0D ? "prefetchw" : (regField == 0 ? "prefetchnta" : regField == 1 ? "prefetcht0" : regField == 2 ? "prefetcht1" : "prefetcht2"), memOp(8)); return;
    case 0x1E:
        if (rep && i < len && p[i] == 0xFA) {
            ++i;
            set("endbr64");
            return;
        }
        if (rep && i < len && p[i] == 0xFB) {
            ++i;
            set("endbr32");
            return;
        }
        modrm();
        set("nop", E(osz_));
        return;
    case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1F: modrm(); set("nop", E(osz_)); return;
    case 0x00: {
        modrm();
        static const char* const n[8] = {"sldt", "str", "lldt", "ltr", "verr", "verw", "(bad)", "(bad)"};
        set(n[regField], E(16));
        return;
    }
    case 0x01: {
        if (i < len) {
            const uint8_t m = p[i];
            if (m == 0xD0) { ++i; set("xgetbv"); return; }
            if (m == 0xD1) { ++i; set("xsetbv"); return; }
            if (m == 0xF9) { ++i; set("rdtscp"); return; }
            if (m == 0xF8) { ++i; set("swapgs"); return; }
            if (m == 0xCA) { ++i; set("clac"); return; }
            if (m == 0xCB) { ++i; set("stac"); return; }
        }
        modrm();
        static const char* const n[8] = {"sgdt", "sidt", "lgdt", "lidt", "smsw", "(bad)", "lmsw", "invlpg"};
        set(n[regField], mod == 3 ? E(32) : memOp(0));
        return;
    }
    case 0x02: case 0x03: modrm(); set(op == 2 ? "lar" : "lsl", G(osz_) + ", " + E(16)); return;
    case 0x06: set("clts"); return;
    case 0x08: set("invd"); return;
    case 0x09: set("wbinvd"); return;
    case 0x20: case 0x22: modrm(); set("mov", op == 0x20 ? reg(rmField | rexB(), is64 ? 64 : 32) + ", cr" + std::to_string(regField | rexR()) : "cr" + std::to_string(regField | rexR()) + ", " + reg(rmField | rexB(), is64 ? 64 : 32)); return;
    case 0x38: {
        const uint8_t op3 = u8();
        modrm();
        if (op3 == 0xF0 || op3 == 0xF1) {
            if (repne) {
                set("crc32", G(rexW() ? 64 : 32) + ", " + E(op3 == 0xF0 ? 8 : osz_));
            } else {
                set("movbe", op3 == 0xF0 ? G(osz_) + ", " + E(osz_) : E(osz_) + ", " + G(osz_));
            }
            return;
        }
        static const struct { uint8_t op; const char* name; } t[] = {
            {0x00, "pshufb"}, {0x01, "phaddw"}, {0x02, "phaddd"}, {0x04, "pmaddubsw"}, {0x08, "psignb"}, {0x0B, "pmulhrsw"},
            {0x17, "ptest"}, {0x1C, "pabsb"}, {0x1D, "pabsw"}, {0x1E, "pabsd"}, {0x20, "pmovsxbw"}, {0x30, "pmovzxbw"},
            {0x38, "pminsb"}, {0x39, "pminsd"}, {0x3A, "pminuw"}, {0x3B, "pminud"}, {0x3C, "pmaxsb"}, {0x3D, "pmaxsd"},
            {0x3E, "pmaxuw"}, {0x3F, "pmaxud"}, {0x40, "pmulld"}, {0xDB, "aesimc"}, {0xDC, "aesenc"}, {0xDD, "aesenclast"},
            {0xDE, "aesdec"}, {0xDF, "aesdeclast"}, {0xC8, "sha1nexte"}, {0xCB, "sha256rnds2"}, {0xCC, "sha256msg1"}, {0xCD, "sha256msg2"}};
        const char* name = nullptr;
        for (const auto& e : t)
            if (e.op == op3) name = e.name;
        if (name) set(name, XG() + ", " + X(128));
        else {
            std::snprintf(tmp, sizeof tmp, "sse 0f 38 %02x", op3);
            set(tmp, XG() + ", " + X(128));
        }
        return;
    }
    case 0x3A: {
        const uint8_t op3 = u8();
        modrm();
        const int64_t ib = s8();
        const char* name = op3 == 0x0F ? "palignr" : op3 == 0x44 ? "pclmulqdq" : op3 == 0xDF ? "aeskeygenassist" : op3 == 0x63 ? "pcmpistri" : op3 == 0x61 ? "pcmpestri" : nullptr;
        if (name) set(name, XG() + ", " + X(128) + ", " + imms(ib & 0xff));
        else {
            std::snprintf(tmp, sizeof tmp, "sse 0f 3a %02x", op3);
            set(tmp, XG() + ", " + X(128) + ", " + imms(ib & 0xff));
        }
        return;
    }
    case 0xA3: case 0xAB: case 0xB3: case 0xBB: {
        modrm();
        set(op == 0xA3 ? "bt" : op == 0xAB ? "bts" : op == 0xB3 ? "btr" : "btc", E(osz_) + ", " + G(osz_));
        return;
    }
    case 0xA4: case 0xAC: {
        modrm();
        const int64_t ib = s8();
        set(op == 0xA4 ? "shld" : "shrd", E(osz_) + ", " + G(osz_) + ", " + imms(ib & 0xff));
        return;
    }
    case 0xA5: case 0xAD: modrm(); set(op == 0xA5 ? "shld" : "shrd", E(osz_) + ", " + G(osz_) + ", cl"); return;
    case 0xAE: {
        modrm();
        if (mod == 3) {
            static const char* const n[8] = {"rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase", "(bad)", "lfence", "mfence", "sfence"};
            set(n[regField], regField < 4 ? E(rexW() ? 64 : 32) : std::string());
        } else {
            static const char* const n[8] = {"fxsave", "fxrstor", "ldmxcsr", "stmxcsr", "xsave", "xrstor", "xsaveopt", "clflush"};
            set(n[regField], memOp(0));
        }
        return;
    }
    case 0xAF: modrm(); set("imul", G(osz_) + ", " + E(osz_)); isLoad = mod != 3; return;
    case 0xB0: case 0xB1: modrm(); set("cmpxchg", op == 0xB0 ? E(8) + ", " + G(8) : E(osz_) + ", " + G(osz_)); return;
    case 0xB2: case 0xB4: case 0xB5: modrm(); set(op == 0xB2 ? "lss" : op == 0xB4 ? "lfs" : "lgs", G(osz_) + ", " + memOp(0)); return;
    case 0xB6: modrm(); set("movzx", G(osz_) + ", " + E(8)); isLoad = mod != 3; return;
    case 0xB7: modrm(); set("movzx", G(osz_) + ", " + E(16)); isLoad = mod != 3; return;
    case 0xBE: modrm(); set("movsx", G(osz_) + ", " + E(8)); isLoad = mod != 3; return;
    case 0xBF: modrm(); set("movsx", G(osz_) + ", " + E(16)); isLoad = mod != 3; return;
    case 0xB8: modrm(); set(rep ? "popcnt" : "jmpe", G(osz_) + ", " + E(osz_)); return;
    case 0xB9: modrm(); set("ud1", G(osz_) + ", " + E(osz_)); flow = Flow::Trap; return;
    case 0xBA: {
        modrm();
        const int64_t ib = s8();
        static const char* const n[8] = {"(bad)", "(bad)", "(bad)", "(bad)", "bt", "bts", "btr", "btc"};
        set(n[regField], E(osz_) + ", " + imms(ib & 0xff));
        if (regField < 4) bad = true;
        return;
    }
    case 0xBC: modrm(); set(rep ? "tzcnt" : "bsf", G(osz_) + ", " + E(osz_)); return;
    case 0xBD: modrm(); set(rep ? "lzcnt" : "bsr", G(osz_) + ", " + E(osz_)); return;
    case 0xC0: case 0xC1: modrm(); set("xadd", op == 0xC0 ? E(8) + ", " + G(8) : E(osz_) + ", " + G(osz_)); return;
    case 0xC3: modrm(); set("movnti", E(rexW() ? 64 : 32) + ", " + G(rexW() ? 64 : 32)); return;
    case 0xC7: {
        modrm();
        if (mod != 3 && regField == 1) set(rexW() ? "cmpxchg16b" : "cmpxchg8b", memOp(rexW() ? 128 : 64));
        else if (mod == 3 && regField == 6) set("rdrand", E(osz_));
        else if (mod == 3 && regField == 7) set("rdseed", E(osz_));
        else {
            set("(bad)");
            bad = true;
        }
        return;
    }
    default: break;
    }
    // SSE / MMX and anything else with a ModRM byte.
    const bool noModrm = false;
    (void)noModrm;
    if (op == 0x71 || op == 0x72 || op == 0x73) {
        modrm();
        const int64_t ib = s8();
        const char* n = nullptr;
        if (op == 0x71) n = regField == 2 ? "psrlw" : regField == 4 ? "psraw" : regField == 6 ? "psllw" : nullptr;
        if (op == 0x72) n = regField == 2 ? "psrld" : regField == 4 ? "psrad" : regField == 6 ? "pslld" : nullptr;
        if (op == 0x73) n = regField == 2 ? "psrlq" : regField == 3 ? "psrldq" : regField == 6 ? "psllq" : regField == 7 ? "pslldq" : nullptr;
        if (!n) {
            set("(bad)");
            bad = true;
            return;
        }
        set(n, xmm(rmField | rexB()) + ", " + imms(ib & 0xff));
        return;
    }
    const bool sseRange = (op >= 0x10 && op <= 0x17) || (op >= 0x28 && op <= 0x2F) || (op >= 0x50 && op <= 0x7F && op != 0x77) || op == 0xC2 ||
                          op == 0xC4 || op == 0xC5 || op == 0xC6 || op >= 0xD0;
    if (!sseRange || op == 0xFF) {
        set("(bad)");
        bad = true;
        return;
    }
    modrm();
    std::string name = sseName(op, pp);
    if (name.empty()) {
        std::snprintf(tmp, sizeof tmp, "sse 0f %02x", op);
        name = tmp;
    }
    const bool store = op == 0x11 || op == 0x13 || op == 0x17 || op == 0x29 || op == 0x2B || op == 0x7F || op == 0xD6 || op == 0xE7 || (op == 0x7E && pp != 2);
    std::string g = XG(), x = X(op == 0x2E || op == 0x2F || op == 0x10 || op == 0x11 || op == 0x51 || (op >= 0x58 && op <= 0x5F) ? (pp == 2 ? 32 : pp == 3 ? 64 : 128) : 128);
    if (op == 0x2A) {
        set(name, g + ", " + E(rexW() ? 64 : 32));
        return;
    }
    if (op == 0x2C || op == 0x2D) {
        set(name, G(rexW() ? 64 : 32) + ", " + x);
        return;
    }
    if (op == 0x50 || op == 0xD7) {
        set(name, G(32) + ", " + (mod == 3 ? xmm(rmField | rexB()) : memOp(128)));
        return;
    }
    if (op == 0x6E) {
        set(rexW() ? "movq" : "movd", g + ", " + E(rexW() ? 64 : 32));
        return;
    }
    if (op == 0x7E && pp != 2) {
        set(rexW() ? "movq" : "movd", E(rexW() ? 64 : 32) + ", " + g);
        return;
    }
    std::string tail;
    if (op == 0x70 || op == 0xC2 || op == 0xC6) tail = ", " + imms(s8() & 0xff);
    if (op == 0xC4) {
        const int64_t ib = s8();
        set(name, g + ", " + E(32) + ", " + imms(ib & 0xff));
        return;
    }
    if (op == 0xC5) {
        const int64_t ib = s8();
        set(name, G(32) + ", " + xmm(rmField | rexB()) + ", " + imms(ib & 0xff));
        return;
    }
    if (store) set(name, x + ", " + g);
    else set(name, g + ", " + x + tail);
}

void Decoder::decode() {
    // Prefixes.
    for (int n = 0; n < 14; ++n) {
        if (i >= len) {
            bad = true;
            return;
        }
        const uint8_t b = p[i];
        if (b == 0x66) opsz = true;
        else if (b == 0x67) adsz = true;
        else if (b == 0xF3) rep = true;
        else if (b == 0xF2) repne = true;
        else if (b == 0xF0) lock = true;
        else if (b == 0x2E) segOverride = 1;
        else if (b == 0x36) segOverride = 2;
        else if (b == 0x3E) segOverride = 3;
        else if (b == 0x26) segOverride = 0;
        else if (b == 0x64) segOverride = 4;
        else if (b == 0x65) segOverride = 5;
        else break;
        ++i;
    }
    if (is64 && i < len && (p[i] & 0xF0) == 0x40) {
        rex = p[i++];
        hasRex = true;
    }
    const uint8_t op = u8();
    if (bad) return;
    char tmp[40];

    if (op == 0x0F) {
        doTwoByte();
        return;
    }
    if (op < 0x40 && (op & 7) < 6) {  // the eight ALU instructions
        const std::string name = aluName(op >> 3);
        switch (op & 7) {
        case 0: modrm(); set(name, E(8) + ", " + G(8)); break;
        case 1: modrm(); set(name, E(osz()) + ", " + G(osz())); break;
        case 2: modrm(); set(name, G(8) + ", " + E(8)); isLoad = mod != 3; break;
        case 3: modrm(); set(name, G(osz()) + ", " + E(osz())); isLoad = mod != 3; break;
        case 4: set(name, std::string("al, ") + imm(1, 8)); break;
        default: set(name, reg(0, osz()) + ", " + imm(osz() == 16 ? 2 : 4, osz())); break;
        }
        return;
    }
    if (!is64 && op >= 0x40 && op <= 0x4F) {
        set(op < 0x48 ? "inc" : "dec", reg(op & 7, osz()));
        return;
    }
    if (op >= 0x50 && op <= 0x57) {
        set("push", reg((op & 7) | rexB(), stackSz()));
        return;
    }
    if (op >= 0x58 && op <= 0x5F) {
        set("pop", reg((op & 7) | rexB(), stackSz()));
        destReg = (op & 7) | rexB();
        return;
    }
    if (op >= 0x70 && op <= 0x7F) {
        branch(std::string("j") + kCC[op & 15], s8(), Flow::CondJump);
        return;
    }
    if (op >= 0x91 && op <= 0x97) {
        set("xchg", reg((op & 7) | rexB(), osz()) + ", " + reg(0, osz()));
        return;
    }
    if (op >= 0xB0 && op <= 0xB7) {
        const int r = (op & 7) | rexB();
        set("mov", reg(r, 8) + ", " + imm(1, 8));
        destReg = r;
        return;
    }
    if (op >= 0xB8 && op <= 0xBF) {
        const int r = (op & 7) | rexB();
        const int bits = osz();
        set("mov", reg(r, bits) + ", " + (bits == 64 ? imm(8, 64) : imm(bits == 16 ? 2 : 4, bits)));
        destReg = r;
        return;
    }
    switch (op) {
    case 0x06: case 0x0E: case 0x16: case 0x1E: case 0x07: case 0x17: case 0x1F:
        if (is64) { set("(bad)"); bad = true; return; }
        set((op & 1) ? "pop" : "push", kSeg[op >> 3]);
        return;
    case 0x27: case 0x2F: case 0x37: case 0x3F: if (is64) { set("(bad)"); bad = true; return; } set(op == 0x27 ? "daa" : op == 0x2F ? "das" : op == 0x37 ? "aaa" : "aas"); return;
    case 0x60: if (is64) { set("(bad)"); bad = true; return; } set(opsz ? "pushaw" : "pushad"); return;
    case 0x61: if (is64) { set("(bad)"); bad = true; return; } set(opsz ? "popaw" : "popad"); return;
    case 0x63:
        modrm();
        if (is64) set("movsxd", G(osz()) + ", " + E(32)), isLoad = mod != 3;
        else set("arpl", E(16) + ", " + G(16));
        return;
    case 0x68: set("push", imm(opsz ? 2 : 4, stackSz())); return;
    case 0x6A: set("push", imm(1, stackSz())); return;
    case 0x69: case 0x6B: {
        modrm();
        const std::string e = E(osz());
        set("imul", G(osz()) + ", " + e + ", " + (op == 0x6B ? imm(1, osz()) : imm(osz() == 16 ? 2 : 4, osz())));
        return;
    }
    case 0x6C: set(rep ? "rep insb" : "insb"); return;
    case 0x6D: set(rep ? "rep ins" : "ins", opsz ? "word" : "dword"); return;
    case 0x6E: set(rep ? "rep outsb" : "outsb"); return;
    case 0x6F: set(rep ? "rep outs" : "outs", opsz ? "word" : "dword"); return;
    case 0x80: case 0x82: {
        modrm();
        const std::string e = E(8);
        set(aluName(regField), e + ", " + imm(1, 8));
        return;
    }
    case 0x81: case 0x83: {
        modrm();
        const std::string e = E(osz());
        set(aluName(regField), e + ", " + (op == 0x83 ? imm(1, osz()) : imm(osz() == 16 ? 2 : 4, osz())));
        return;
    }
    case 0x84: modrm(); set("test", E(8) + ", " + G(8)); return;
    case 0x85: modrm(); set("test", E(osz()) + ", " + G(osz())); return;
    case 0x86: modrm(); set("xchg", E(8) + ", " + G(8)); return;
    case 0x87: modrm(); set("xchg", E(osz()) + ", " + G(osz())); return;
    case 0x88: modrm(); set("mov", E(8) + ", " + G(8)); return;
    case 0x89: modrm(); set("mov", E(osz()) + ", " + G(osz())); return;
    case 0x8A: modrm(); set("mov", G(8) + ", " + E(8)); isLoad = mod != 3; destReg = regField | rexR(); return;
    case 0x8B:
        modrm();
        set("mov", G(osz()) + ", " + E(osz()));
        isLoad = mod != 3;
        destReg = regField | rexR();
        return;
    case 0x8C: modrm(); set("mov", E(mod == 3 ? osz() : 16) + ", " + (regField < 6 ? kSeg[regField] : "(bad)")); return;
    case 0x8D:
        modrm();
        if (mod == 3) {
            set("(bad)");
            bad = true;
            return;
        }
        set("lea", G(osz()) + ", " + mem);
        isLea = true;
        destReg = regField | rexR();
        return;
    case 0x8E: modrm(); set("mov", std::string(regField < 6 ? kSeg[regField] : "(bad)") + ", " + E(mod == 3 ? osz() : 16)); return;
    case 0x8F: modrm(); set("pop", E(stackSz())); return;
    case 0x90:
        if (rep) set("pause");
        else if (rexB() && is64) set("xchg", "r8, rax");
        else set("nop");
        return;
    case 0x98: set(rexW() ? "cdqe" : opsz ? "cbw" : "cwde"); return;
    case 0x99: set(rexW() ? "cqo" : opsz ? "cwd" : "cdq"); return;
    case 0x9A: if (is64) { set("(bad)"); bad = true; return; } { const uint32_t o = opsz ? u16() : u32(); const uint32_t s = u16(); set("call", hexs(s) + ":" + hexs(o)); flow = Flow::IndirectCall; } return;
    case 0x9B: set("fwait"); return;
    case 0x9C: set("pushf"); return;
    case 0x9D: set("popf"); return;
    case 0x9E: set("sahf"); return;
    case 0x9F: set("lahf"); return;
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
        const uint64_t off = is64 && !adsz ? u64() : adsz && !is64 ? u16() : u32();
        const int bits = (op & 1) ? osz() : 8;
        const std::string m = std::string(sizeName(bits)) + " ptr " + (segOverride >= 0 ? std::string(kSeg[segOverride]) + ":" : std::string()) + "[" + hexs(off) + "]";
        if (op < 0xA2) set("mov", reg(0, bits) + ", " + m);
        else set("mov", m + ", " + reg(0, bits));
        return;
    }
    case 0xA4: set(rep || repne ? "rep movsb" : "movsb"); return;
    case 0xA5: set(rep || repne ? "rep movs" : "movs", opsz ? "word" : rexW() ? "qword" : "dword"); return;
    case 0xA6: set(rep ? "repe cmpsb" : repne ? "repne cmpsb" : "cmpsb"); return;
    case 0xA7: set(rep ? "repe cmps" : repne ? "repne cmps" : "cmps", opsz ? "word" : rexW() ? "qword" : "dword"); return;
    case 0xA8: set("test", std::string("al, ") + imm(1, 8)); return;
    case 0xA9: set("test", reg(0, osz()) + ", " + imm(osz() == 16 ? 2 : 4, osz())); return;
    case 0xAA: set(rep || repne ? "rep stosb" : "stosb"); return;
    case 0xAB: set(rep || repne ? "rep stos" : "stos", opsz ? "word" : rexW() ? "qword" : "dword"); return;
    case 0xAC: set(rep || repne ? "rep lodsb" : "lodsb"); return;
    case 0xAD: set(rep || repne ? "rep lods" : "lods", opsz ? "word" : rexW() ? "qword" : "dword"); return;
    case 0xAE: set(rep ? "repe scasb" : repne ? "repne scasb" : "scasb"); return;
    case 0xAF: set(rep ? "repe scas" : repne ? "repne scas" : "scas", opsz ? "word" : rexW() ? "qword" : "dword"); return;
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        static const char* const n[8] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"};
        modrm();
        const int bits = (op & 1) ? osz() : 8;
        const std::string e = E(bits);
        std::string c = op >= 0xD2 ? "cl" : op >= 0xD0 ? "1" : hexs(static_cast<uint64_t>(s8()) & 0xff);
        set(n[regField], e + ", " + c);
        return;
    }
    case 0xC2: set("ret", hexs(u16())); flow = Flow::Return; return;
    case 0xC3: set(rep ? "repz ret" : "ret"); flow = Flow::Return; return;
    case 0xC4: case 0xC5:
        if (is64 || (i < len && (p[i] & 0xC0) == 0xC0)) {
            doVex(false);
            return;
        }
        modrm();
        set(op == 0xC4 ? "les" : "lds", G(osz()) + ", " + memOp(0));
        return;
    case 0x62:
        if (is64 || (i < len && (p[i] & 0xC0) == 0xC0)) {
            doVex(true);
            return;
        }
        modrm();
        set("bound", G(osz()) + ", " + memOp(0));
        return;
    case 0xC6: case 0xC7: {
        modrm();
        const int bits = op == 0xC6 ? 8 : osz();
        if (regField != 0 && !(op == 0xC6 && regField == 7 && mod == 3) && !(op == 0xC7 && regField == 7 && mod == 3)) {
            set("(bad)");
            bad = true;
            return;
        }
        const std::string e = E(bits);
        set("mov", e + ", " + imm(bits == 8 ? 1 : bits == 16 ? 2 : 4, bits));
        return;
    }
    case 0xC8: { const uint32_t a = u16(); const uint32_t b = u8(); set("enter", hexs(a) + ", " + hexs(b)); return; }
    case 0xC9: set("leave"); return;
    case 0xCA: set("retf", hexs(u16())); flow = Flow::Return; return;
    case 0xCB: set("retf"); flow = Flow::Return; return;
    case 0xCC: set("int3"); flow = Flow::Trap; return;
    case 0xCD: set("int", hexs(u8())); return;
    case 0xCE: if (is64) { set("(bad)"); bad = true; return; } set("into"); return;
    case 0xCF: set(rexW() ? "iretq" : "iret"); flow = Flow::Return; return;
    case 0xD4: case 0xD5: if (is64) { set("(bad)"); bad = true; return; } set(op == 0xD4 ? "aam" : "aad", hexs(u8())); return;
    case 0xD6: set("(bad)"); bad = true; return;
    case 0xD7: set("xlat"); return;
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF: doX87(op); return;
    case 0xE0: branch("loopne", s8(), Flow::CondJump); return;
    case 0xE1: branch("loope", s8(), Flow::CondJump); return;
    case 0xE2: branch("loop", s8(), Flow::CondJump); return;
    case 0xE3: branch(is64 ? (adsz ? "jecxz" : "jrcxz") : (adsz ? "jcxz" : "jecxz"), s8(), Flow::CondJump); return;
    case 0xE4: set("in", std::string("al, ") + hexs(u8())); return;
    case 0xE5: set("in", std::string("eax, ") + hexs(u8())); return;
    case 0xE6: { const uint32_t v = u8(); set("out", hexs(v) + ", al"); return; }
    case 0xE7: { const uint32_t v = u8(); set("out", hexs(v) + ", eax"); return; }
    case 0xE8: {
        const int64_t rel = opsz && !is64 ? s16() : s32();
        branch("call", rel, Flow::Call);
        return;
    }
    case 0xE9: {
        const int64_t rel = opsz && !is64 ? s16() : s32();
        branch("jmp", rel, Flow::Jump);
        return;
    }
    case 0xEA: if (is64) { set("(bad)"); bad = true; return; } { const uint32_t o = opsz ? u16() : u32(); const uint32_t s = u16(); set("jmp", hexs(s) + ":" + hexs(o)); flow = Flow::IndirectJump; } return;
    case 0xEB: branch("jmp", s8(), Flow::Jump); return;
    case 0xEC: set("in", "al, dx"); return;
    case 0xED: set("in", "eax, dx"); return;
    case 0xEE: set("out", "dx, al"); return;
    case 0xEF: set("out", "dx, eax"); return;
    case 0xF1: set("int1"); flow = Flow::Trap; return;
    case 0xF4: set("hlt"); flow = Flow::Trap; return;
    case 0xF5: set("cmc"); return;
    case 0xF8: set("clc"); return;
    case 0xF9: set("stc"); return;
    case 0xFA: set("cli"); return;
    case 0xFB: set("sti"); return;
    case 0xFC: set("cld"); return;
    case 0xFD: set("std"); return;
    case 0xF6: case 0xF7: {
        modrm();
        const int bits = op == 0xF6 ? 8 : osz();
        static const char* const n[8] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
        const std::string e = E(bits);
        if (regField < 2) set("test", e + ", " + imm(bits == 8 ? 1 : bits == 16 ? 2 : 4, bits));
        else set(n[regField], e);
        return;
    }
    case 0xFE: {
        modrm();
        if (regField > 1) {
            set("(bad)");
            bad = true;
            return;
        }
        set(regField ? "dec" : "inc", E(8));
        return;
    }
    case 0xFF: {
        modrm();
        switch (regField) {
        case 0: set("inc", E(osz())); return;
        case 1: set("dec", E(osz())); return;
        case 2:
        case 4: {
            const bool call = regField == 2;
            const int bits = is64 ? 64 : osz();
            set(call ? "call" : "jmp", E(bits));
            flow = call ? Flow::IndirectCall : Flow::IndirectJump;
            isLoad = mod != 3;
            return;
        }
        case 3:
        case 5: set(regField == 3 ? "call" : "jmp", mod == 3 ? E(32) : memOp(0)); flow = regField == 3 ? Flow::IndirectCall : Flow::IndirectJump; return;
        case 6: set("push", E(stackSz())); return;
        default: set("(bad)"); bad = true; return;
        }
    }
    default: break;
    }
    std::snprintf(tmp, sizeof tmp, "(bad)");
    set(tmp);
    bad = true;
}

}  // namespace

Insn decode(const uint8_t* code, size_t len, uint64_t addr, bool is64) {
    Insn out;
    out.addr = addr;
    out.size = 1;
    if (len == 0) {
        out.mnemonic = "(bad)";
        out.known = false;
        return out;
    }
    Decoder d{code, len > 15 ? 15 : len, addr, is64};
    d.decode();
    if (d.bad || d.i == 0 || d.i > 15) {
        out.mnemonic = "(bad)";
        out.known = false;
        out.size = 1;
        out.raw = code[0];
        return out;
    }
    out.size = static_cast<uint8_t>(d.i);
    uint32_t raw = 0;
    for (size_t k = 0; k < 4 && k < d.i; ++k) raw |= static_cast<uint32_t>(code[k]) << (8 * k);
    out.raw = raw;
    std::string mn = d.mn;
    if (d.lock) mn = "lock " + mn;
    if (d.rep && (mn == "movsb" || mn == "stosb")) mn = "rep " + mn;
    out.mnemonic = mn;
    out.operands = d.ops;
    out.flow = d.flow;
    if (d.hasTarget) {
        out.hasTarget = true;
        out.target = d.target;
        // A relative branch: the target was computed from the position after the displacement, which is the end of
        // the instruction for every encoding that has one.
        out.target = addr + d.i + (d.target - (addr + d.i));
        if (!is64) out.target &= 0xffffffffull;
        char buf[24];
        std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(out.target));
        out.operands = buf;
    }
    if (d.ripRel) {
        out.hasTarget = true;
        out.memTarget = true;
        out.target = addr + d.i + static_cast<uint64_t>(d.ripDisp);
        if (!is64) out.target &= 0xffffffffull;
    }
    out.isLoad = d.isLoad && !d.isLea;
    out.isAddImm = d.isLea;
    if (d.memPlain && (d.isLea || d.isLoad)) {
        out.baseReg = static_cast<int8_t>(d.memBase);
        out.offset = d.memDisp;
    }
    out.destReg = static_cast<int8_t>(d.destReg);
    return out;
}

}  // namespace x86
