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

uint32_t armImmediate(uint32_t w);

const char* shiftName(unsigned t) {
    static const char* n[4] = {"lsl", "lsr", "asr", "ror"};
    return n[t & 3];
}

// "rm" or "rm, lsl #n" (the immediate-shift forms; a zero shift amount means 32 for lsr / asr, rrx for ror).
std::string shiftedReg(unsigned rm, unsigned type, unsigned imm) {
    if (type == 0 && imm == 0) return reg(rm);
    if (type == 3 && imm == 0) return reg(rm) + ", rrx";
    if ((type == 1 || type == 2) && imm == 0) imm = 32;
    return reg(rm) + ", " + shiftName(type) + " #" + std::to_string(imm);
}

uint32_t ror32(uint32_t v, unsigned n) { return n ? (v >> n) | (v << (32 - n)) : v; }

// Thumb-2 modified immediate (i:imm3:imm8).
uint32_t thumbExpandImm(uint32_t imm12) {
    if ((imm12 >> 10) == 0) {
        const uint32_t b = imm12 & 0xFF;
        switch ((imm12 >> 8) & 3) {
        case 0: return b;
        case 1: return (b << 16) | b;
        case 2: return (b << 24) | (b << 8);
        default: return b * 0x01010101u;
        }
    }
    return ror32(0x80 | (imm12 & 0x7F), (imm12 >> 7) & 31);
}

std::string itName(unsigned firstcond, unsigned mask) {
    unsigned low = 0;
    while (low < 4 && !((mask >> low) & 1)) ++low;
    std::string s = "it";
    for (int b = 3; b > static_cast<int>(low); --b) s += (((mask >> b) & 1) == (firstcond & 1)) ? 't' : 'e';
    return s;
}


// VFP (scalar floating point) in either instruction set: Thumb-2 and A32 share the layout of bits 27..0, so `w` is the
// A32 word or (h1 << 16) | h2. NEON stays unnamed. Returns false for anything that is not VFP.
std::string vfpReg(bool dbl, unsigned v, unsigned hi) {
    return dbl ? "d" + std::to_string((hi << 4) | v) : "s" + std::to_string((v << 1) | hi);
}

bool vfpDecode(Insn& in, uint32_t w, bool thumb, const std::string& c) {
    const unsigned coproc = (w >> 8) & 15;
    if (coproc != 10 && coproc != 11) return false;
    const bool dbl = coproc == 11;
    const unsigned dBit = (w >> 22) & 1, vd = (w >> 12) & 15, nBit = (w >> 7) & 1, vn = (w >> 16) & 15, mBit = (w >> 5) & 1, vm = w & 15;
    const std::string fmt = dbl ? ".f64" : ".f32";
    const unsigned top = (w >> 24) & 15;
    if ((w & 0x0F200000) == 0x0D000000) {  // vldr / vstr
        const bool load = (w >> 20) & 1, up = (w >> 23) & 1;
        const unsigned rn = (w >> 16) & 15;
        const uint32_t imm = (w & 0xFF) * 4;
        in.mnemonic = std::string(load ? "vldr" : "vstr") + c;
        in.operands = vfpReg(dbl, vd, dBit) + ", [" + reg(rn) + (imm ? std::string(up ? ", #" : ", #-") + std::to_string(imm) : std::string()) + "]";
        if (rn == 15) {
            in.hasTarget = true;
            const uint64_t pc = thumb ? ((in.addr + 4) & ~uint64_t(3)) : in.addr + 8;
            in.target = (up ? pc + imm : pc - imm) & 0xFFFFFFFFull;
        }
        return true;
    }
    if ((w & 0x0FBF0E00) == 0x0D2D0A00 || (w & 0x0FBF0E00) == 0x0CBD0A00) {  // vpush / vpop
        const bool push = (w & 0x0FBF0E00) == 0x0D2D0A00;
        const unsigned count = dbl ? (w & 0xFF) / 2 : (w & 0xFF);
        const unsigned first = dbl ? (dBit << 4) | vd : (vd << 1) | dBit;
        in.mnemonic = std::string(push ? "vpush" : "vpop") + c;
        const char* r = dbl ? "d" : "s";
        in.operands = count <= 1 ? std::string("{") + r + std::to_string(first) + "}"
                                 : std::string("{") + r + std::to_string(first) + "-" + r + std::to_string(first + count - 1) + "}";
        return true;
    }
    // vldm / vstm: increment after (with or without write-back), or decrement before with write-back.
    if ((w & 0x0E000000) == 0x0C000000) {
        const bool pre = (w >> 24) & 1, up = (w >> 23) & 1, wb = (w >> 21) & 1, load = (w >> 20) & 1;
        const unsigned rn = (w >> 16) & 15;
        const unsigned count = dbl ? (w & 0xFF) / 2 : (w & 0xFF);
        const unsigned first = dbl ? (dBit << 4) | vd : (vd << 1) | dBit;
        if (((!pre && up) || (pre && !up && wb)) && count > 0 && first + count <= 32) {
            in.mnemonic = std::string(load ? "vldm" : "vstm") + (pre ? "db" : "ia") + c;
            const char* r = dbl ? "d" : "s";
            in.operands = reg(rn) + (wb ? "!" : "") + ", " +
                          (count == 1 ? std::string("{") + r + std::to_string(first) + "}"
                                      : std::string("{") + r + std::to_string(first) + "-" + r + std::to_string(first + count - 1) + "}");
            return true;
        }
    }
    if (top == 0xE && !(w & 0x10)) {  // data processing
        const unsigned opc1 = (w >> 20) & 0xB;
        const bool op = (w >> 6) & 1;
        const std::string d = vfpReg(dbl, vd, dBit), n = vfpReg(dbl, vn, nBit), m = vfpReg(dbl, vm, mBit);
        const char* name = nullptr;
        switch (opc1) {
        case 0x0: name = op ? "vmls" : "vmla"; break;
        case 0x1: name = op ? "vnmla" : "vnmls"; break;
        case 0x2: name = op ? "vnmul" : "vmul"; break;
        case 0x3: name = op ? "vsub" : "vadd"; break;
        case 0x8: name = op ? nullptr : "vdiv"; break;
        case 0x9: name = op ? "vfnma" : "vfnms"; break;
        case 0xA: name = op ? "vfms" : "vfma"; break;
        default: break;
        }
        if (name) {
            in.mnemonic = std::string(name) + c + fmt;
            in.operands = d + ", " + n + ", " + m;
            return true;
        }
        if (opc1 == 0xB) {
            const unsigned opc2 = (w >> 16) & 15;
            if (((w >> 6) & 3) == 0) {  // vmov #imm: eight bits that encode +/- (16..31) / 16 * 2^(-3..4)
                const unsigned imm8 = (vn << 4) | vm;
                const int exponent = (imm8 & 0x40) ? static_cast<int>((imm8 >> 4) & 3) - 3 : static_cast<int>((imm8 >> 4) & 3) + 1;
                double value = (16 + (imm8 & 15)) / 16.0;
                for (int e = 0; e < exponent; ++e) value *= 2;
                for (int e = 0; e > exponent; --e) value /= 2;
                char text[32];
                std::snprintf(text, sizeof text, "%.10g", (imm8 & 0x80) ? -value : value);
                std::string shown = text;
                if (shown.find('.') == std::string::npos) shown += ".0";
                in.mnemonic = "vmov" + c + fmt;
                in.operands = d + ", #" + shown;
                return true;
            }
            if (opc2 == 0 && op) {
                in.mnemonic = std::string((w >> 7) & 1 ? "vabs" : "vmov") + c + fmt;
                in.operands = d + ", " + m;
                return true;
            }
            if (opc2 == 1 && op) {  // bit 7 tells them apart: 01 vneg, 11 vsqrt
                in.mnemonic = std::string((w >> 7) & 1 ? "vsqrt" : "vneg") + c + fmt;
                in.operands = d + ", " + m;
                return true;
            }
            if (opc2 == 4 || opc2 == 5) {
                in.mnemonic = std::string((w >> 7) & 1 ? "vcmpe" : "vcmp") + c + fmt;
                in.operands = opc2 == 5 ? d + ", #0.0" : d + ", " + m;
                return true;
            }
            if (opc2 == 7 && op) {  // vcvt between f64 and f32
                in.mnemonic = "vcvt" + c + (dbl ? ".f32.f64" : ".f64.f32");
                in.operands = (dbl ? vfpReg(false, vd, dBit) + ", " + m : vfpReg(true, vd, dBit) + ", " + vfpReg(false, vm, mBit));
                return true;
            }
            if (opc2 == 8) {  // vcvt int -> float
                in.mnemonic = "vcvt" + c + fmt + ((w >> 7) & 1 ? ".s32" : ".u32");
                in.operands = d + ", " + vfpReg(false, vm, mBit);
                return true;
            }
            if (opc2 == 0xC || opc2 == 0xD) {  // vcvt float -> int
                in.mnemonic = std::string(op ? "vcvt" : "vcvtr") + c + (opc2 == 0xD ? ".s32" : ".u32") + fmt;
                in.operands = vfpReg(false, vd, dBit) + ", " + m;
                return true;
            }
        }
        return false;
    }
    if ((w & 0x0FE00F7F) == 0x0E000A10) {  // vmov between a core register and a single register
        const bool toCore = (w >> 20) & 1;
        const std::string sreg = vfpReg(false, vn, nBit), rt = reg((w >> 12) & 15);
        in.mnemonic = "vmov" + c;
        in.operands = toCore ? rt + ", " + sreg : sreg + ", " + rt;
        return true;
    }
    if ((w & 0x0FFF0FFF) == 0x0EF10A10 || (w & 0x0FFF0FFF) == 0x0EE10A10) {  // vmrs / vmsr fpscr
        const unsigned rt = (w >> 12) & 15;
        const bool read = (w & 0x0FFF0FFF) == 0x0EF10A10;
        in.mnemonic = std::string(read ? "vmrs" : "vmsr") + c;
        in.operands = read ? std::string(rt == 15 ? "APSR_nzcv" : reg(rt).c_str()) + ", fpscr" : "fpscr, " + reg(rt);
        return true;
    }
    if ((w & 0x0FE00ED0) == 0x0C400A10 || (w & 0x0FE00ED0) == 0x0C400B10) {  // vmov two core registers and a d register
        if (!dbl) return false;
        const bool toCore = (w >> 20) & 1;
        const std::string dr = vfpReg(true, vm, mBit), a = reg((w >> 12) & 15), b = reg((w >> 16) & 15);
        in.mnemonic = "vmov" + c;
        in.operands = toCore ? a + ", " + b + ", " + dr : dr + ", " + a + ", " + b;
        return true;
    }
    return false;
}


// NEON (Advanced SIMD): data processing (three registers of the same and of different lengths, by scalar, two-register
// miscellaneous, shifts by immediate, conversions, vext / vtbl / vdup), element and structure loads and stores, and
// immediate moves (the immediate is shown as its raw encoding). `w` is the A32 word (Thumb is converted by the caller).
// Armv8 additions (vrint, vcvta, crypto, ...) stay unnamed.
// A q register with an odd number is an undefined encoding; neonSet() refuses the "?" it prints.
std::string neonReg(bool q, unsigned v, unsigned hi) {
    if (q && (v & 1)) return "?";
    return (q ? "q" : "d") + std::to_string(q ? ((hi << 4) | v) >> 1 : (hi << 4) | v);
}

bool neonSet(Insn& in, const std::string& mnemonic, const std::string& operands) {
    if (operands.find('?') != std::string::npos) return false;
    in.mnemonic = mnemonic;
    in.operands = operands;
    return true;
}

// vld1..4 / vst1..4: whole registers, one lane, or (loads) all lanes.
bool neonElement(Insn& in, uint32_t w) {
    const bool load = (w >> 21) & 1;
    const unsigned rn = (w >> 16) & 15, rm = w & 15, first = (((w >> 22) & 1) << 4) | ((w >> 12) & 15);
    const std::string tail = rm == 13 ? "!" : rm == 15 ? "" : ", " + reg(rm);
    static const char* const sizes[4] = {".8", ".16", ".32", ".64"};
    unsigned n = 1, count = 1, inc = 1, align = 0, size = 0;
    std::string lane;
    if (!((w >> 23) & 1)) {  // multiple structures
        const unsigned type = (w >> 8) & 15, a = (w >> 4) & 3;
        size = (w >> 6) & 3;
        switch (type) {
        case 7: n = 1, count = 1; break;
        case 10: n = 1, count = 2; break;
        case 6: n = 1, count = 3; break;
        case 2: n = 1, count = 4; break;
        case 8: n = 2, count = 2; break;
        case 9: n = 2, count = 2, inc = 2; break;
        case 3: n = 2, count = 4; break;
        case 4: n = 3, count = 3; break;
        case 5: n = 3, count = 3, inc = 2; break;
        case 0: n = 4, count = 4; break;
        case 1: n = 4, count = 4, inc = 2; break;
        default: return false;
        }
        if (n > 1 && size == 3) return false;
        if (((type == 7 || type == 6 || type == 4 || type == 5) && a > 1) || ((type == 10 || type == 8 || type == 9) && a == 3)) return false;
        if (a) align = 32u << a;
    } else {
        n = ((w >> 8) & 3) + 1;
        count = n;
        size = (w >> 10) & 3;
        if (size == 3) {  // one element to all lanes
            if (!load) return false;
            size = (w >> 6) & 3;
            const bool t = (w >> 5) & 1, a = (w >> 4) & 1;
            if (size == 3) {
                if (n != 4 || !a) return false;
                size = 2;
                align = 128;
            } else if (a) {
                if (n == 3 || (n == 1 && size == 0)) return false;
                align = (8u << size) * n;
                if (n == 4 && size == 2) align = 64;
            }
            if (n == 1) count = t ? 2 : 1;
            else inc = t ? 2 : 1;
            lane = "[]";
        } else {  // one element to one lane
            const unsigned ia = (w >> 4) & 15;
            if ((n == 1 && ((size == 0 && (ia & 1)) || (size == 1 && (ia & 2)) || (size == 2 && ((ia & 4) || (ia & 3) == 1 || (ia & 3) == 2)))) ||
                (n == 2 && size == 2 && (ia & 2)) || (n == 3 && ((size < 2 && (ia & 1)) || (size == 2 && (ia & 3)))) ||
                (n == 4 && size == 2 && (ia & 3) == 3))
                return false;
            lane = "[" + std::to_string(ia >> (size + 1)) + "]";
            if (n > 1 && size > 0) inc = ((ia >> size) & 1) ? 2 : 1;
            const unsigned esize = 8u << size;
            if (n == 1) {
                if (size == 1 && (ia & 1)) align = 16;
                if (size == 2 && (ia & 3) == 3) align = 32;
            } else if (n == 2) {
                if (ia & 1) align = esize * 2;
            } else if (n == 4) {
                if (size < 2 && (ia & 1)) align = esize * 4;
                if (size == 2 && (ia & 3)) align = 32u << (ia & 3);
            }
        }
    }
    if (first + (count - 1) * inc > 31) return false;
    std::string list = "{";
    for (unsigned i = 0; i < count; ++i) list += (i ? ", d" : "d") + std::to_string((first + i * inc) & 31) + lane;
    list += "}";
    const std::string mnemonic = std::string(load ? "vld" : "vst") + std::to_string(n) + sizes[size];
    return neonSet(in, mnemonic, list + ", [" + reg(rn) + (align ? " :" + std::to_string(align) : std::string()) + "]" + tail);
}

// Three registers of the same length.
bool neonThreeSame(Insn& in, uint32_t w) {
    const bool u = (w >> 24) & 1, q = (w >> 6) & 1, op = (w >> 4) & 1;
    const unsigned size = (w >> 20) & 3, a = (w >> 8) & 15;
    const std::string d = neonReg(q, (w >> 12) & 15, (w >> 22) & 1), n = neonReg(q, (w >> 16) & 15, (w >> 7) & 1),
                      m = neonReg(q, w & 15, (w >> 5) & 1);
    const std::string all = d + ", " + n + ", " + m;
    const std::string bits = std::to_string(8u << size);
    const std::string sg = (u ? ".u" : ".s") + bits, ig = ".i" + bits;
    const bool high = size & 2;                       // float forms: selects the operation
    const std::string f = ".f32";
    if (a >= 12 && (size & 1)) return false;  // half precision is Armv8.2
    const bool wide64 = (a == 0 && op) || (a == 2 && op) || a == 4 || a == 5 || (a == 8 && !op) || (a == 1 && op);
    if (a < 12 && size == 3 && !wide64) return false;
    const bool pairwise = a == 10 || (a == 11 && op) || (a == 13 && !op && u && !high) || (a == 15 && !op && u);
    if (pairwise && q) return false;
    if (a == 11 && !op && (size == 0 || size == 3)) return false;
    std::string name, suffix = sg;
    switch (a) {
    case 0: name = op ? "vqadd" : "vhadd"; break;
    case 1:
        if (op) {  // logical operations: U and size select which
            static const char* const x[8] = {"vand", "vbic", "vorr", "vorn", "veor", "vbsl", "vbit", "vbif"};
            const unsigned k = (u ? 4 : 0) + size;
            if (k == 2 && n == m) return neonSet(in, "vmov", d + ", " + n);
            return neonSet(in, x[k], all);
        }
        name = "vrhadd";
        break;
    case 2: name = op ? "vqsub" : "vhsub"; break;
    case 3: name = op ? "vcge" : "vcgt"; break;
    case 4:  // shifts by register take the value before the count
        return neonSet(in, (op ? "vqshl" : "vshl") + sg, d + ", " + m + ", " + n);
    case 5: return neonSet(in, (op ? "vqrshl" : "vrshl") + sg, d + ", " + m + ", " + n);
    case 6: name = op ? "vmin" : "vmax"; break;
    case 7: name = op ? "vaba" : "vabd"; break;
    case 8:
        if (op) name = u ? "vceq" : "vtst", suffix = u ? ig : "." + bits;
        else name = u ? "vsub" : "vadd", suffix = ig;
        break;
    case 9:
        if (op && u && size != 0) return false;
        if (op) name = "vmul", suffix = u ? ".p8" : ig;
        else name = u ? "vmls" : "vmla", suffix = ig;
        break;
    case 10: name = op ? "vpmin" : "vpmax"; break;
    case 11:
        if (op && u) return false;
        name = op ? "vpadd" : (u ? "vqrdmulh" : "vqdmulh");
        suffix = op ? ig : ".s" + bits;
        break;
    case 12:
        if (!op || u) return false;
        name = high ? "vfms" : "vfma", suffix = f;
        break;
    case 13:
        suffix = f;
        if (!op) name = u ? (high ? "vabd" : "vpadd") : (high ? "vsub" : "vadd");
        else if (!u) name = high ? "vmls" : "vmla";
        else if (!high) name = "vmul";
        else return false;
        break;
    case 14:
        suffix = f;
        if (!op) {
            if (!u && high) return false;
            name = !u ? "vceq" : high ? "vcgt" : "vcge";
        } else {
            if (!u) return false;
            name = high ? "vacgt" : "vacge";
        }
        break;
    case 15:
        suffix = f;
        if (!op) name = u ? (high ? "vpmin" : "vpmax") : (high ? "vmin" : "vmax");
        else if (!u) name = high ? "vrsqrts" : "vrecps";
        else return false;
        break;
    default: return false;
    }
    return neonSet(in, name + suffix, all);
}

// Three registers of different lengths (long, wide, narrow).
bool neonThreeDifferent(Insn& in, uint32_t w) {
    const bool u = (w >> 24) & 1;
    const unsigned size = (w >> 20) & 3, a = (w >> 8) & 15, vd = (w >> 12) & 15, vn = (w >> 16) & 15, vm = w & 15;
    const unsigned db = (w >> 22) & 1, nb = (w >> 7) & 1, mb = (w >> 5) & 1;
    const std::string bits = std::to_string(8u << size), wide = std::to_string(16u << size);
    const std::string sg = (u ? ".u" : ".s") + bits;
    const std::string longOps = neonReg(true, vd, db) + ", " + neonReg(false, vn, nb) + ", " + neonReg(false, vm, mb);
    switch (a) {
    case 0: return neonSet(in, "vaddl" + sg, longOps);
    case 2: return neonSet(in, "vsubl" + sg, longOps);
    case 1:
    case 3:
        return neonSet(in, (a == 1 ? "vaddw" : "vsubw") + sg,
                       neonReg(true, vd, db) + ", " + neonReg(true, vn, nb) + ", " + neonReg(false, vm, mb));
    case 4:
    case 6:
        return neonSet(in, std::string(u ? "vr" : "v") + (a == 4 ? "addhn" : "subhn") + ".i" + wide,
                       neonReg(false, vd, db) + ", " + neonReg(true, vn, nb) + ", " + neonReg(true, vm, mb));
    case 5: return neonSet(in, "vabal" + sg, longOps);
    case 7: return neonSet(in, "vabdl" + sg, longOps);
    case 8: return neonSet(in, "vmlal" + sg, longOps);
    case 10: return neonSet(in, "vmlsl" + sg, longOps);
    case 12: return neonSet(in, "vmull" + sg, longOps);
    case 9:
    case 11:
    case 13:
        if (u || size == 0) return false;
        return neonSet(in, (a == 9 ? "vqdmlal.s" : a == 11 ? "vqdmlsl.s" : "vqdmull.s") + bits, longOps);
    case 14:
        if (u || size != 0) return false;
        return neonSet(in, "vmull.p8", longOps);
    default: return false;
    }
}

// Two registers and a scalar element.
bool neonByScalar(Insn& in, uint32_t w) {
    const bool u = (w >> 24) & 1;  // Q for the same-length forms, signedness for the long ones
    const unsigned size = (w >> 20) & 3, a = (w >> 8) & 15, vd = (w >> 12) & 15, vn = (w >> 16) & 15;
    const unsigned db = (w >> 22) & 1, nb = (w >> 7) & 1, mb = (w >> 5) & 1;
    if (size == 0) return false;
    const unsigned vm = w & 15;
    const std::string scalar = size == 1 ? "d" + std::to_string(vm & 7) + "[" + std::to_string((mb << 1) | (vm >> 3)) + "]"
                                         : "d" + std::to_string(vm) + "[" + std::to_string(mb) + "]";
    const std::string bits = std::to_string(8u << size);
    const std::string same = neonReg(u, vd, db) + ", " + neonReg(u, vn, nb) + ", " + scalar;
    const std::string longOps = neonReg(true, vd, db) + ", " + neonReg(false, vn, nb) + ", " + scalar;
    const std::string f = ".f32";
    if ((a == 1 || a == 5 || a == 9) && size != 2) return false;
    switch (a) {
    case 0: return neonSet(in, "vmla.i" + bits, same);
    case 1: return neonSet(in, "vmla" + f, same);
    case 4: return neonSet(in, "vmls.i" + bits, same);
    case 5: return neonSet(in, "vmls" + f, same);
    case 8: return neonSet(in, "vmul.i" + bits, same);
    case 9: return neonSet(in, "vmul" + f, same);
    case 12: return neonSet(in, "vqdmulh.s" + bits, same);
    case 13: return neonSet(in, "vqrdmulh.s" + bits, same);
    case 2: return neonSet(in, (u ? "vmlal.u" : "vmlal.s") + bits, longOps);
    case 6: return neonSet(in, (u ? "vmlsl.u" : "vmlsl.s") + bits, longOps);
    case 10: return neonSet(in, (u ? "vmull.u" : "vmull.s") + bits, longOps);
    case 3:
    case 7:
    case 11:
        if (u) return false;
        return neonSet(in, (a == 3 ? "vqdmlal.s" : a == 7 ? "vqdmlsl.s" : "vqdmull.s") + bits, longOps);
    default: return false;
    }
}

// Two registers, miscellaneous.
bool neonMisc(Insn& in, uint32_t w) {
    const unsigned size = (w >> 18) & 3, a = (w >> 16) & 3, b = (w >> 6) & 31, vd = (w >> 12) & 15, vm = w & 15;
    const unsigned db = (w >> 22) & 1, mb = (w >> 5) & 1;
    const bool q = b & 1;
    const std::string d = neonReg(q, vd, db), m = neonReg(q, vm, mb), two = d + ", " + m;
    const unsigned bits = 8u << size;
    const std::string n = std::to_string(bits), nw = std::to_string(bits * 2);
    const bool f = (b >> 4) & 1;  // bit 10: float form of the compares and vabs / vneg
    if (a == 0) {
        const unsigned k = b >> 1;
        if ((k == 0 || k == 4 || k == 5 || k == 8 || k == 9 || k >= 12) && size == 3) return false;
        if ((k == 1 && size > 1) || ((k == 2 || k == 10 || k == 11) && size != 0)) return false;
        switch (b >> 1) {
        case 0: return neonSet(in, "vrev64." + n, two);
        case 1: return neonSet(in, "vrev32." + n, two);
        case 2: return neonSet(in, "vrev16." + n, two);
        case 4: return neonSet(in, "vpaddl.s" + n, two);
        case 5: return neonSet(in, "vpaddl.u" + n, two);
        case 8: return neonSet(in, "vcls.s" + n, two);
        case 9: return neonSet(in, "vclz.i" + n, two);
        case 10: return neonSet(in, "vcnt.8", two);
        case 11: return neonSet(in, "vmvn", two);
        case 12: return neonSet(in, "vpadal.s" + n, two);
        case 13: return neonSet(in, "vpadal.u" + n, two);
        case 14: return neonSet(in, "vqabs.s" + n, two);
        case 15: return neonSet(in, "vqneg.s" + n, two);
        default: return false;
        }
    }
    if (a == 1) {
        static const char* const names[8] = {"vcgt", "vcge", "vceq", "vcle", "vclt", nullptr, "vabs", "vneg"};
        const unsigned k = (b >> 1) & 7;
        if (!names[k] || size == 3 || (f && size != 2)) return false;
        const std::string type = f ? std::string(".f32") : (k == 2 ? ".i" : ".s") + n;
        return neonSet(in, names[k] + type, k < 5 ? two + ", #0" : two);
    }
    if (a == 2) {
        const std::string narrow = neonReg(false, vd, db) + ", " + neonReg(true, vm, mb);
        if ((b >> 1) == 0 && size == 0) return neonSet(in, "vswp", two);
        if ((b >> 1) < 4 && (size == 3 || (b >> 1) == 0 || ((b >> 1) >= 2 && size == 2 && !q))) return false;
        if ((b >> 1) == 1) return neonSet(in, "vtrn." + n, two);
        if ((b >> 1) == 2) return neonSet(in, "vuzp." + n, two);
        if ((b >> 1) == 3) return neonSet(in, "vzip." + n, two);
        if (size == 3) return false;
        if (b == 8) return neonSet(in, "vmovn.i" + nw, narrow);
        if (b == 9) return neonSet(in, "vqmovun.s" + nw, narrow);
        if (b == 10) return neonSet(in, "vqmovn.s" + nw, narrow);
        if (b == 11) return neonSet(in, "vqmovn.u" + nw, narrow);
        if (b == 12) return neonSet(in, "vshll.i" + n, neonReg(true, vd, db) + ", " + neonReg(false, vm, mb) + ", #" + n);
        if (size == 1 && b == 24) return neonSet(in, "vcvt.f16.f32", narrow);
        if (size == 1 && b == 28) return neonSet(in, "vcvt.f32.f16", neonReg(true, vd, db) + ", " + neonReg(false, vm, mb));
        return false;
    }
    if (size != 2) return false;  // reciprocal estimates and int <-> float conversions, single precision
    const std::string ft = "f32", st = "s32", ut = "u32";
    if ((b & 0x18) == 0x10) return neonSet(in, std::string((b & 2) ? "vrsqrte." : "vrecpe.") + ((b & 4) ? ft : ut), two);
    if ((b >> 3) == 3) {
        const unsigned k = (b >> 1) & 3;
        const std::string to = k == 0 || k == 1 ? ft : k == 2 ? st : ut;
        const std::string from = k == 0 ? st : k == 1 ? ut : ft;
        return neonSet(in, "vcvt." + to + "." + from, two);
    }
    return false;
}

// Two registers and a shift amount, and the fixed-point conversions.
bool neonShift(Insn& in, uint32_t w) {
    const bool u = (w >> 24) & 1, q = (w >> 6) & 1;
    const unsigned a = (w >> 8) & 15, imm6 = (w >> 16) & 63, l = (w >> 7) & 1, vd = (w >> 12) & 15, vm = w & 15;
    const unsigned db = (w >> 22) & 1, mb = (w >> 5) & 1;
    unsigned esize = 0;
    if (l) esize = 64;
    else if (imm6 & 32) esize = 32;
    else if (imm6 & 16) esize = 16;
    else if (imm6 & 8) esize = 8;
    else return false;
    const unsigned right = (esize == 64 ? 64 : esize * 2) - imm6, left = imm6 - (esize == 64 ? 0 : esize);
    const std::string n = std::to_string(esize), nw = std::to_string(esize * 2);
    const std::string two = neonReg(q, vd, db) + ", " + neonReg(q, vm, mb);
    const std::string r = ", #" + std::to_string(right), s = ", #" + std::to_string(left);
    const std::string sg = (u ? ".u" : ".s") + n;
    switch (a) {
    case 0: return neonSet(in, "vshr" + sg, two + r);
    case 1: return neonSet(in, "vsra" + sg, two + r);
    case 2: return neonSet(in, "vrshr" + sg, two + r);
    case 3: return neonSet(in, "vrsra" + sg, two + r);
    case 4: return u && neonSet(in, "vsri." + n, two + r);
    case 5: return neonSet(in, (u ? "vsli." : "vshl.i") + n, two + s);
    case 6: return u && neonSet(in, "vqshlu.s" + n, two + s);
    case 7: return neonSet(in, "vqshl" + sg, two + s);
    case 8:
    case 9: {  // narrowing: the source elements are twice the size
        if (l) return false;
        const std::string narrow = neonReg(false, vd, db) + ", " + neonReg(true, vm, mb) + r;
        const bool round = q;
        if (a == 8 && !u) return neonSet(in, std::string(round ? "vrshrn.i" : "vshrn.i") + nw, narrow);
        if (a == 8) return neonSet(in, std::string(round ? "vqrshrun.s" : "vqshrun.s") + nw, narrow);
        return neonSet(in, std::string(round ? "vqrshrn" : "vqshrn") + (u ? ".u" : ".s") + nw, narrow);
    }
    case 10: {
        if (l || q) return false;
        const std::string ops = neonReg(true, vd, db) + ", " + neonReg(false, vm, mb);
        return left == 0 ? neonSet(in, "vmovl" + sg, ops) : neonSet(in, "vshll" + sg, ops + s);
    }
    case 12:
    case 13:
    case 14:
    case 15: {  // vcvt between floating point and fixed point
        if (l || !(imm6 & 32) || !(a & 2)) return false;
        const bool toFixed = a & 1;
        const std::string ft = "f32", it = u ? "u32" : "s32";
        return neonSet(in, "vcvt." + (toFixed ? it : ft) + "." + (toFixed ? ft : it), two + ", #" + std::to_string(64 - imm6));
    }
    default: return false;
    }
}

bool neonDecode(Insn& in, uint32_t w) {
    if ((w & 0xFF100000) == 0xF4000000) return neonElement(in, w);
    if ((w & 0xFE000000) != 0xF2000000) return false;
    if (!(w & 0x00800000)) return neonThreeSame(in, w);
    const bool u = (w >> 24) & 1, q = (w >> 6) & 1;
    const unsigned size = (w >> 20) & 3, vd = (w >> 12) & 15, vn = (w >> 16) & 15, vm = w & 15;
    const unsigned db = (w >> 22) & 1, nb = (w >> 7) & 1, mb = (w >> 5) & 1;
    if (w & 0x10) {
        if (!(w & 0x00380000) && !(w & 0x80)) {
            // One register and a modified immediate (vmov / vmvn / vorr / vbic #imm): shown with the raw imm8.
            const unsigned imm8 = (u ? 0x80 : 0) | (((w >> 16) & 7) << 4) | (w & 15);
            const unsigned cmode = (w >> 8) & 15;
            const bool op = (w >> 5) & 1;
            const bool logical = (cmode & 1) && cmode < 12;
            char b[24];
            std::snprintf(b, sizeof b, ", #0x%02x", imm8);
            return neonSet(in, op ? (logical ? "vbic" : cmode == 14 ? "vmov.i64" : "vmvn") : (logical ? "vorr" : "vmov"),
                           neonReg(q, vd, db) + b);
        }
        return neonShift(in, w);
    }
    if (size != 3) return q ? neonByScalar(in, w) : neonThreeDifferent(in, w);
    if (!u) {  // vext
        const unsigned imm = (w >> 8) & 15;
        if (!q && imm > 7) return false;
        return neonSet(in, "vext.8", neonReg(q, vd, db) + ", " + neonReg(q, vn, nb) + ", " + neonReg(q, vm, mb) + ", #" +
                                         std::to_string(imm));
    }
    if (!(w & 0x800)) return neonMisc(in, w);
    if ((w & 0xC00) == 0x800) {  // vtbl / vtbx
        const unsigned len = (w >> 8) & 3, first = (nb << 4) | vn;
        std::string list = "{";
        if (first + len > 31) return false;
        for (unsigned i = 0; i <= len; ++i) list += (i ? ", d" : "d") + std::to_string((first + i) & 31);
        list += "}";
        return neonSet(in, q ? "vtbx.8" : "vtbl.8", neonReg(false, vd, db) + ", " + list + ", " + neonReg(false, vm, mb));
    }
    if ((w & 0xF80) == 0xC00) {  // vdup from a scalar
        const unsigned imm4 = vn;
        unsigned bits = 0, index = 0;
        if (imm4 & 1) bits = 8, index = imm4 >> 1;
        else if (imm4 & 2) bits = 16, index = imm4 >> 2;
        else if (imm4 & 4) bits = 32, index = imm4 >> 3;
        else return false;
        return neonSet(in, "vdup." + std::to_string(bits),
                       neonReg(q, vd, db) + ", " + neonReg(false, vm, mb) + "[" + std::to_string(index) + "]");
    }
    return false;
}

// vmov between a core register and one element of a d register: vmov.32 d16[0], r1 / vmov.u16 lr, d16[2].
bool neonScalarMove(Insn& in, uint32_t w, const std::string& c) {
    if ((w & 0x0F000F1F) != 0x0E000B10) return false;
    const bool load = (w >> 20) & 1, u = (w >> 23) & 1;  // load: to the core register
    if (!load && u) return false;                       // vdup
    const unsigned opc1 = (w >> 21) & 3, opc2 = (w >> 5) & 3, rt = (w >> 12) & 15;
    const unsigned dreg = ((w >> 7) & 1) << 4 | ((w >> 16) & 15);
    std::string size;
    unsigned index;
    if (opc1 & 2) size = "8", index = (opc1 & 1) << 2 | opc2;
    else if (opc2 & 1) size = "16", index = (opc1 & 1) << 1 | (opc2 >> 1);
    else if (!(opc2 & 2)) size = "32", index = opc1 & 1;
    else return false;
    if (load && size == "32" && u) return false;
    const std::string element = "d" + std::to_string(dreg) + "[" + std::to_string(index) + "]";
    in.mnemonic = "vmov" + c + "." + (load && size != "32" ? (u ? "u" : "s") : "") + size;
    in.operands = load ? reg(rt) + ", " + element : element + ", " + reg(rt);
    return true;
}

bool neonDup(Insn& in, uint32_t w, const std::string& c) {
    if (neonScalarMove(in, w, c)) return true;
    if ((w & 0x0F900F5F) == 0x0E800B10) {  // vdup.<size> Qd, Rt
        const bool q = (w >> 21) & 1;
        const unsigned b = (w >> 22) & 1, e = (w >> 5) & 1;
        in.mnemonic = "vdup" + c + (b ? ".8" : e ? ".16" : ".32");
        in.operands = neonReg(q, (w >> 16) & 15, (w >> 7) & 1) + ", " + reg((w >> 12) & 15);
        return true;
    }
    return false;
}

// The 16-bit Thumb instructions thumb16() does not name itself. Returns false when `r` is not one of them.
bool thumb16Extra(Insn& in, uint32_t r, uint64_t addr) {
    (void)addr;
    if ((r & 0xFC00) == 0x4000) {  // data processing, low registers
        static const char* ops[16] = {"ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
                                      "tst",  "rsbs", "cmp",  "cmn",  "orrs", "muls", "bics", "mvns"};
        const unsigned op = (r >> 6) & 15, rdn = r & 7, rm = (r >> 3) & 7;
        in.mnemonic = ops[op];
        if (op == 9) in.operands = reg(rdn) + ", " + reg(rm) + ", #0";
        else in.operands = reg(rdn) + ", " + reg(rm);
        return true;
    }
    if ((r & 0xFF00) == 0x4400 || (r & 0xFF00) == 0x4500) {  // add / cmp with high registers
        const unsigned rd = (r & 7) | ((r >> 4) & 8), rm = (r >> 3) & 15;
        in.mnemonic = (r & 0x0100) ? "cmp" : "add";
        in.operands = reg(rd) + ", " + reg(rm);
        if (!(r & 0x0100) && rd == 15) in.flow = Flow::IndirectJump;
        return true;
    }
    if ((r & 0xF000) == 0x5000) {  // load / store, register offset
        static const char* ops[8] = {"str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"};
        in.mnemonic = ops[(r >> 9) & 7];
        in.operands = reg(r & 7) + ", [" + reg((r >> 3) & 7) + ", " + reg((r >> 6) & 7) + "]";
        return true;
    }
    if ((r & 0xF800) == 0xA800) {  // add rd, sp, #imm8 * 4
        in.mnemonic = "add";
        in.operands = reg((r >> 8) & 7) + ", sp, #" + std::to_string((r & 0xFF) * 4);
        return true;
    }
    if ((r & 0xFF00) == 0xB200) {
        static const char* ops[4] = {"sxth", "sxtb", "uxth", "uxtb"};
        in.mnemonic = ops[(r >> 6) & 3];
        in.operands = reg(r & 7) + ", " + reg((r >> 3) & 7);
        return true;
    }
    if ((r & 0xFF00) == 0xBA00 && ((r >> 6) & 3) != 2) {
        static const char* ops[4] = {"rev", "rev16", "", "revsh"};
        in.mnemonic = ops[(r >> 6) & 3];
        in.operands = reg(r & 7) + ", " + reg((r >> 3) & 7);
        return true;
    }
    if ((r & 0xFF00) == 0xBF00) {  // hints and IT
        const unsigned mask = r & 15, cond = (r >> 4) & 15;
        if (mask) {
            in.mnemonic = itName(cond, mask);
            in.operands = conditionName(cond);
            return true;
        }
        static const char* hints[8] = {"nop", "yield", "wfe", "wfi", "sev", "sevl", "", ""};
        const unsigned h = (r >> 4) & 15;
        if (h < 6) {
            in.mnemonic = hints[h];
            return true;
        }
        return false;
    }
    if ((r & 0xF000) == 0xC000) {  // stmia / ldmia rn!, {list}
        in.mnemonic = (r & 0x0800) ? "ldmia" : "stmia";
        in.operands = reg((r >> 8) & 7) + "!, " + regs(r & 0xFF);
        return true;
    }
    return false;
}

std::string memImm(unsigned rn, int32_t imm, bool pre, bool wb) {
    const std::string off = "#" + std::to_string(imm);
    if (!pre) return "[" + reg(rn) + "], " + off;
    return "[" + reg(rn) + (imm ? ", " + off : std::string()) + "]" + (wb ? "!" : "");
}

// Thumb-2 32-bit integer instructions beyond the branches thumb32() handles itself.
bool thumb32Extra(Insn& in, uint32_t h1, uint32_t h2, uint64_t addr) {
    // Barriers and clrex.
    if (h1 == 0xF3BF && (h2 & 0xFF00) == 0x8F00) {
        static const char* const options[16] = {"#0", "#1", "oshst", "osh", "#4", "#5", "nshst", "nsh", "#8", "ishld", "ishst", "ish", "#12", "ld", "st", "sy"};
        const unsigned op = (h2 >> 4) & 15;
        if (op == 2 && (h2 & 15) == 15) return in.mnemonic = "clrex", true;
        if (op < 4 || op > 6) return false;
        in.mnemonic = op == 4 ? "dsb" : op == 5 ? "dmb" : "isb";
        in.operands = options[h2 & 15];
        return true;
    }
    // mrc / mcr with a coprocessor other than VFP / NEON (p15: the thread ID registers).
    if ((h1 & 0xFF00) == 0xEE00 && (h2 & 0x10) && ((h2 >> 8) & 0xE) != 0xA) {
        const bool load = (h1 >> 4) & 1;
        in.mnemonic = load ? "mrc" : "mcr";
        in.operands = "p" + std::to_string((h2 >> 8) & 15) + ", #" + std::to_string((h1 >> 5) & 7) + ", " + reg(h2 >> 12) + ", c" +
                      std::to_string(h1 & 15) + ", c" + std::to_string(h2 & 15) + ", #" + std::to_string((h2 >> 5) & 7);
        return true;
    }
    // smmul / smmla / smmls and the halfword multiplies smulxy / smlaxy.
    if ((h1 & 0xFFF0) == 0xFB50 || (h1 & 0xFFF0) == 0xFB60 || (h1 & 0xFFF0) == 0xFB10) {
        const unsigned rn = h1 & 15, ra = (h2 >> 12) & 15, rd = (h2 >> 8) & 15, rm = h2 & 15, op2 = (h2 >> 4) & 15;
        std::string name;
        if ((h1 & 0xFFF0) == 0xFB10) {
            if (op2 > 3) return false;
            const std::string xy = std::string(op2 & 2 ? "t" : "b") + (op2 & 1 ? "t" : "b");
            name = (ra == 15 ? "smul" : "smla") + xy;
        } else {
            if (op2 > 1) return false;
            name = (h1 & 0xFFF0) == 0xFB60 ? "smmls" : ra == 15 ? "smmul" : "smmla";
            if (op2) name += "r";
        }
        in.mnemonic = name;
        in.operands = reg(rd) + ", " + reg(rn) + ", " + reg(rm) + (ra == 15 && name.rfind("smmls", 0) != 0 ? std::string() : ", " + reg(ra));
        return true;
    }
    // ldrexb / ldrexh / ldrexd, strexb / strexh / strexd.
    if (((h1 & 0xFFF0) == 0xE8D0 || (h1 & 0xFFF0) == 0xE8C0) && (((h2 >> 4) & 15) == 4 || ((h2 >> 4) & 15) == 5 || ((h2 >> 4) & 15) == 7)) {
        const bool load = (h1 >> 4) & 1;
        const unsigned op = (h2 >> 4) & 15, rn = h1 & 15, rt = (h2 >> 12) & 15, rt2 = (h2 >> 8) & 15, rd = h2 & 15;
        const char* suffix = op == 4 ? "b" : op == 5 ? "h" : "d";
        if (load && op != 7 && ((h2 & 0x0F0F) != 0x0F0F)) return false;
        if (load && op == 7 && (h2 & 15) != 15) return false;
        if (!load && op != 7 && (h2 & 0x0F00) != 0x0F00) return false;
        in.mnemonic = std::string(load ? "ldrex" : "strex") + suffix;
        const std::string mem = "[" + reg(rn) + "]";
        if (load) in.operands = reg(rt) + (op == 7 ? ", " + reg(rt2) : std::string()) + ", " + mem;
        else in.operands = reg(rd) + ", " + reg(rt) + (op == 7 ? ", " + reg(rt2) : std::string()) + ", " + mem;
        return true;
    }
    if (((h1 & 0xFE00) == 0xEC00 || (h1 & 0xFF00) == 0xEE00) && vfpDecode(in, (h1 << 16) | h2, true, std::string())) return true;
    if ((h1 & 0xFF00) == 0xEE00 && neonDup(in, (h1 << 16) | h2, std::string())) return true;
    if ((h1 & 0xEF00) == 0xEF00 && neonDecode(in, 0xF2000000u | (((h1 >> 12) & 1u) << 24) | ((h1 & 0xFFu) << 16) | h2)) return true;
    if ((h1 & 0xFF10) == 0xF900 && neonDecode(in, 0xF4000000u | ((h1 & 0xFFu) << 16) | h2)) return true;
    // ldrd / strd rt, rt2, [rn, #+/-imm]{!} and the post-indexed form.
    if ((h1 & 0xFE40) == 0xE840 && (h1 & 0x0120) != 0) {
        const bool pre = (h1 >> 8) & 1, up = (h1 >> 7) & 1, wb = (h1 >> 5) & 1, load = (h1 >> 4) & 1;
        const int32_t imm = static_cast<int32_t>((h2 & 0xFF) * 4) * (up ? 1 : -1);
        in.mnemonic = load ? "ldrd" : "strd";
        in.operands = reg(h2 >> 12) + ", " + reg((h2 >> 8) & 15) + ", " + memImm(h1 & 15, imm, pre, wb);
        return true;
    }
    static const char* dp[16] = {"and", "bic", "orr", "orn", "eor", "", "pkh", "", "add", "", "adc", "sbc", "", "sub", "rsb", ""};
    // Data processing, immediate.
    if ((h1 & 0xF800) == 0xF000 && (h2 & 0x8000) == 0) {
        const unsigned rn = h1 & 15, rd = (h2 >> 8) & 15;
        const uint32_t i = (h1 >> 10) & 1, imm3 = (h2 >> 12) & 7, imm8 = h2 & 0xFF;
        if (!(h1 & 0x0200)) {  // modified immediate
            const unsigned op = (h1 >> 5) & 15;
            const bool s = (h1 >> 4) & 1;
            const uint32_t imm = thumbExpandImm((i << 11) | (imm3 << 8) | imm8);
            const std::string immS = "#" + hex(imm);
            std::string name;
            bool compare = false, move = false;
            if (op == 0 && rd == 15 && s) name = "tst", compare = true;
            else if (op == 4 && rd == 15 && s) name = "teq", compare = true;
            else if (op == 8 && rd == 15 && s) name = "cmn", compare = true;
            else if (op == 13 && rd == 15 && s) name = "cmp", compare = true;
            else if (op == 2 && rn == 15) name = "mov", move = true;
            else if (op == 3 && rn == 15) name = "mvn", move = true;
            else if (dp[op][0] && op != 6) name = dp[op];
            else return false;
            in.mnemonic = name + ((s && !compare) ? "s" : "") + ".w";
            if (compare) in.operands = reg(rn) + ", " + immS;
            else if (move) in.operands = reg(rd) + ", " + immS;
            else in.operands = reg(rd) + ", " + reg(rn) + ", " + immS;
            return true;
        }
        const unsigned op = (h1 >> 4) & 0x1F;  // plain binary immediate
        const uint32_t imm12 = (i << 11) | (imm3 << 8) | imm8;
        if (op == 0 || op == 10) {  // addw / subw, adr when the base is pc
            if (rn == 15) {
                const uint64_t base = (addr + 4) & ~uint64_t(3);
                in.mnemonic = "adr.w";
                in.hasTarget = true;
                in.target = (op == 0 ? base + imm12 : base - imm12) & 0xFFFFFFFFull;
                in.operands = reg(rd) + ", " + hex(static_cast<uint32_t>(in.target));
                return true;
            }
            in.mnemonic = op == 0 ? "addw" : "subw";
            in.operands = reg(rd) + ", " + reg(rn) + ", #" + std::to_string(imm12);
            return true;
        }
        if (op == 4 || op == 12) {  // movw / movt
            const uint32_t imm16 = ((h1 & 15) << 12) | (i << 11) | (imm3 << 8) | imm8;
            in.mnemonic = op == 4 ? "movw" : "movt";
            in.operands = reg(rd) + ", #" + hex(imm16);
            return true;
        }
        if (op == 20 || op == 28) {  // sbfx / ubfx
            const unsigned lsb = (imm3 << 2) | ((h2 >> 6) & 3), width = (h2 & 31) + 1;
            in.mnemonic = op == 20 ? "sbfx" : "ubfx";
            in.operands = reg(rd) + ", " + reg(rn) + ", #" + std::to_string(lsb) + ", #" + std::to_string(width);
            return true;
        }
        if (op == 22) {  // bfi / bfc
            const unsigned lsb = (imm3 << 2) | ((h2 >> 6) & 3), msb = h2 & 31;
            if (msb < lsb) return false;
            if (rn == 15) {
                in.mnemonic = "bfc";
                in.operands = reg(rd) + ", #" + std::to_string(lsb) + ", #" + std::to_string(msb - lsb + 1);
            } else {
                in.mnemonic = "bfi";
                in.operands = reg(rd) + ", " + reg(rn) + ", #" + std::to_string(lsb) + ", #" + std::to_string(msb - lsb + 1);
            }
            return true;
        }
        return false;
    }
    // Data processing, shifted register.
    if ((h1 & 0xFE00) == 0xEA00) {
        const unsigned op = (h1 >> 5) & 15, rn = h1 & 15, rd = (h2 >> 8) & 15, rm = h2 & 15;
        const bool s = (h1 >> 4) & 1;
        const unsigned type = (h2 >> 4) & 3, imm5 = ((h2 >> 12) & 7) << 2 | ((h2 >> 6) & 3);
        std::string name;
        bool compare = false, move = false;
        if (op == 0 && rd == 15 && s) name = "tst", compare = true;
        else if (op == 4 && rd == 15 && s) name = "teq", compare = true;
        else if (op == 8 && rd == 15 && s) name = "cmn", compare = true;
        else if (op == 13 && rd == 15 && s) name = "cmp", compare = true;
        else if (op == 2 && rn == 15) name = "mov", move = true;
        else if (op == 3 && rn == 15) name = "mvn", move = true;
        else if (dp[op][0] && op != 6) name = dp[op];
        else return false;
        if (move && name == "mov" && !(type == 0 && imm5 == 0)) {  // a shift written as mov
            if (type == 3 && imm5 == 0) {
                in.mnemonic = std::string("rrx") + (s ? "s" : "") + ".w";
                in.operands = reg(rd) + ", " + reg(rm);
            } else {
                in.mnemonic = std::string(shiftName(type)) + (s ? "s" : "") + ".w";
                in.operands = reg(rd) + ", " + reg(rm) + ", #" + std::to_string((type == 1 || type == 2) && imm5 == 0 ? 32u : imm5);
            }
            return true;
        }
        in.mnemonic = name + ((s && !compare) ? "s" : "") + ".w";
        const std::string op2 = shiftedReg(rm, type, imm5);
        if (compare) in.operands = reg(rn) + ", " + op2;
        else if (move) in.operands = reg(rd) + ", " + op2;
        else in.operands = reg(rd) + ", " + reg(rn) + ", " + op2;
        return true;
    }
    // Register-controlled shifts, extensions, clz / rev.
    if ((h1 & 0xFF00) == 0xFA00) {
        const unsigned rn = h1 & 15, rd = (h2 >> 8) & 15, rm = h2 & 15;
        if ((h1 & 0x0080) == 0 && (h2 & 0xF0F0) == 0xF000) {
            in.mnemonic = std::string(shiftName((h1 >> 5) & 3)) + (((h1 >> 4) & 1) ? "s" : "") + ".w";
            in.operands = reg(rd) + ", " + reg(rn) + ", " + reg(rm);
            return true;
        }
        if ((h1 & 0xFF8F) == 0xFA0F && (h2 & 0xF0C0) == 0xF080) {
            static const char* ops[8] = {"sxth", "uxth", "sxtb16", "uxtb16", "sxtb", "uxtb", "", ""};
            const unsigned op = (h1 >> 4) & 7;
            if (!ops[op][0]) return false;
            const unsigned rot = ((h2 >> 4) & 3) * 8;
            in.mnemonic = std::string(ops[op]) + ".w";
            in.operands = reg(rd) + ", " + reg(rm) + (rot ? ", ror #" + std::to_string(rot) : std::string());
            return true;
        }
        if ((h1 & 0xFFF0) == 0xFAB0 && (h2 & 0xF0F0) == 0xF080) {
            in.mnemonic = "clz";
            in.operands = reg(rd) + ", " + reg(rm);
            return true;
        }
        if ((h1 & 0xFFF0) == 0xFA90 && (h2 & 0xF0C0) == 0xF080) {
            static const char* ops[4] = {"rev.w", "rev16.w", "rbit", "revsh.w"};
            in.mnemonic = ops[(h2 >> 4) & 3];
            in.operands = reg(rd) + ", " + reg(rm);  // Rm is encoded twice (both copies match in valid code)
            return true;
        }
        return false;
    }
    // Multiply, divide.
    if ((h1 & 0xFF80) == 0xFB00) {
        const unsigned op1 = (h1 >> 4) & 7, op2 = (h2 >> 4) & 3, rn = h1 & 15, ra = (h2 >> 12) & 15, rd = (h2 >> 8) & 15, rm = h2 & 15;
        if (op1 == 0 && op2 == 0) {
            in.mnemonic = ra == 15 ? "mul" : "mla";
            in.operands = reg(rd) + ", " + reg(rn) + ", " + reg(rm) + (ra == 15 ? std::string() : ", " + reg(ra));
            return true;
        }
        if (op1 == 0 && op2 == 1) {
            in.mnemonic = "mls";
            in.operands = reg(rd) + ", " + reg(rn) + ", " + reg(rm) + ", " + reg(ra);
            return true;
        }
        return false;
    }
    if ((h1 & 0xFF80) == 0xFB80) {
        const unsigned op1 = (h1 >> 4) & 7, rn = h1 & 15, rdlo = (h2 >> 12) & 15, rdhi = (h2 >> 8) & 15, rm = h2 & 15;
        if ((op1 == 1 || op1 == 3) && (h2 & 0xF0) == 0xF0) {
            in.mnemonic = op1 == 1 ? "sdiv" : "udiv";
            in.operands = reg(rdhi) + ", " + reg(rn) + ", " + reg(rm);
            return true;
        }
        static const char* ops[8] = {"smull", "", "umull", "", "smlal", "", "umlal", ""};
        if (ops[op1][0] && (h2 & 0xF0) == 0) {
            in.mnemonic = ops[op1];
            in.operands = reg(rdlo) + ", " + reg(rdhi) + ", " + reg(rn) + ", " + reg(rm);
            return true;
        }
        return false;
    }
    // Load / store single item.
    if ((h1 & 0xFE00) == 0xF800) {
        const unsigned rn = h1 & 15, rt = (h2 >> 12) & 15;
        const unsigned size = (h1 >> 5) & 3;
        const bool load = (h1 >> 4) & 1, sign = (h1 >> 8) & 1;
        if (size == 3 || (sign && !load) || (sign && size == 2)) return false;
        const char* name = size == 0 ? (sign ? "ldrsb" : load ? "ldrb" : "strb") : size == 1 ? (sign ? "ldrsh" : load ? "ldrh" : "strh") : load ? "ldr" : "str";
        in.mnemonic = std::string(name) + ".w";
        if (load && rn == 15) {  // literal
            const uint32_t imm = h2 & 0xFFF;
            const bool add = (h1 >> 7) & 1;
            in.hasTarget = true;
            in.target = ((addr + 4) & ~uint64_t(3)) + (add ? imm : -static_cast<int64_t>(imm));
            in.target &= 0xFFFFFFFFull;
            in.operands = reg(rt) + ", [pc, #" + (add ? "" : "-") + std::to_string(imm) + "]";
            if (rt == 15) in.flow = Flow::IndirectJump;
            return true;
        }
        if (rn == 15) return false;
        if (h1 & 0x0080) {
            in.operands = reg(rt) + ", " + memImm(rn, static_cast<int32_t>(h2 & 0xFFF), true, false);
        } else if (h2 & 0x0800) {
            const bool pre = (h2 >> 10) & 1, up = (h2 >> 9) & 1, wb = (h2 >> 8) & 1;
            const int32_t imm = up ? static_cast<int32_t>(h2 & 0xFF) : -static_cast<int32_t>(h2 & 0xFF);
            in.operands = reg(rt) + ", " + memImm(rn, imm, pre, wb);
        } else if ((h2 & 0x0FC0) == 0) {
            const unsigned sh = (h2 >> 4) & 3;
            in.operands = reg(rt) + ", [" + reg(rn) + ", " + reg(h2 & 15) + (sh ? ", lsl #" + std::to_string(sh) : std::string()) + "]";
        } else {
            return false;
        }
        if (load && rt == 15 && size == 2) in.flow = Flow::IndirectJump;
        return true;
    }
    // Load / store multiple, dual, exclusive, table branch.
    if ((h1 & 0xFE00) == 0xE800) {
        const unsigned rn = h1 & 15;
        const bool load = (h1 >> 4) & 1, wb = (h1 >> 5) & 1;
        if (!(h1 & 0x0040)) {
            const unsigned op = (h1 >> 7) & 3;
            if (op != 1 && op != 2) return false;
            in.mnemonic = std::string(load ? "ldm" : "stm") + (op == 2 ? "db" : "") + ".w";
            in.operands = reg(rn) + (wb ? "!" : "") + ", " + regs(h2);
            if (load && (h2 & 0x8000)) in.flow = Flow::Return;
            return true;
        }
        if ((h1 & 0xFFF0) == 0xE8D0 && (h2 & 0xFFE0) == 0xF000) {
            const bool half = (h2 >> 4) & 1;
            in.mnemonic = half ? "tbh" : "tbb";
            in.operands = "[" + reg(rn) + ", " + reg(h2 & 15) + (half ? ", lsl #1" : "") + "]";
            in.flow = Flow::IndirectJump;
            return true;
        }
        if ((h1 & 0xFFF0) == 0xE850 || (h1 & 0xFFF0) == 0xE840) {  // ldrex / strex
            const unsigned rt = (h2 >> 12) & 15;
            const int32_t imm = static_cast<int32_t>((h2 & 0xFF) * 4);
            if (h1 & 0x10) {
                in.mnemonic = "ldrex";
                in.operands = reg(rt) + ", " + memImm(rn, imm, true, false);
            } else {
                in.mnemonic = "strex";
                in.operands = reg((h2 >> 8) & 15) + ", " + reg(rt) + ", " + memImm(rn, imm, true, false);
            }
            return true;
        }
        if (h1 & 0x0200) {  // ldrd / strd (P bit set in the E9 half; E8 with W for post-index)
            const bool pre = (h1 >> 8) & 1, up = (h1 >> 7) & 1;
            const int32_t imm = static_cast<int32_t>((h2 & 0xFF) * 4) * (up ? 1 : -1);
            in.mnemonic = load ? "ldrd" : "strd";
            in.operands = reg((h2 >> 12) & 15) + ", " + reg((h2 >> 8) & 15) + ", " + memImm(rn, imm, pre, wb);
            return true;
        }
        return false;
    }
    return false;
}

// A32 instructions beyond the ones arm32() names itself: data processing with register operands, the halfword and
// multiply families, extensions, clz, svc.
bool a32Extra(Insn& in, uint32_t w, const std::string& c) {
    if ((w & 0x0F000000) == 0x0F000000) {
        in.mnemonic = "svc" + c;
        in.operands = "#" + hex(w & 0xFFFFFF);
        return true;
    }
    if ((w & 0x0FFF0FF0) == 0x016F0F10) {
        in.mnemonic = "clz" + c;
        in.operands = reg((w >> 12) & 15) + ", " + reg(w & 15);
        return true;
    }
    if ((w & 0x0F8F03F0) == 0x068F0070 && (w & 0x00700000) != 0 && (w & 0x00700000) <= 0x00700000) {  // sxt / uxt
        static const char* ops[8] = {"", "sxtb16", "", "sxtb", "", "uxtb16", "", "uxtb"};
        const unsigned op = (w >> 20) & 7;
        if (op == 3 || op == 7 || op == 1 || op == 5) {
            in.mnemonic = std::string(ops[op]) + c;
            in.operands = reg((w >> 12) & 15) + ", " + reg(w & 15);
            return true;
        }
    }
    if ((w & 0x0FEF03F0) == 0x06AF0070 || (w & 0x0FEF03F0) == 0x06BF0070) {  // sxtb / sxth / uxtb / uxth
        const bool half = (w & 0x00100000) != 0, uns = (w & 0x00400000) != 0;
        in.mnemonic = std::string(uns ? "uxt" : "sxt") + (half ? "h" : "b") + c;
        in.operands = reg((w >> 12) & 15) + ", " + reg(w & 15);
        return true;
    }
    if ((w & 0x0FC000F0) == 0x00000090) {  // mul / mla
        const bool acc = (w >> 21) & 1;
        in.mnemonic = std::string(acc ? "mla" : "mul") + ((w >> 20) & 1 ? "s" : "") + c;
        in.operands = reg((w >> 16) & 15) + ", " + reg(w & 15) + ", " + reg((w >> 8) & 15) + (acc ? ", " + reg((w >> 12) & 15) : std::string());
        return true;
    }
    if ((w & 0x0F8000F0) == 0x00800090) {  // umull / umlal / smull / smlal
        static const char* ops[4] = {"umull", "umlal", "smull", "smlal"};
        in.mnemonic = std::string(ops[(w >> 21) & 3]) + ((w >> 20) & 1 ? "s" : "") + c;
        in.operands = reg((w >> 12) & 15) + ", " + reg((w >> 16) & 15) + ", " + reg(w & 15) + ", " + reg((w >> 8) & 15);
        return true;
    }
    if ((w & 0x0E000090) == 0x00000090 && (w & 0x60) != 0) {  // ldrh / strh / ldrsb / ldrsh / ldrd / strd
        const bool load = (w >> 20) & 1, pre = (w >> 24) & 1, up = (w >> 23) & 1, imm = (w >> 22) & 1, wb = (w >> 21) & 1;
        const unsigned sh = (w >> 5) & 3, rn = (w >> 16) & 15, rt = (w >> 12) & 15;
        const char* name = nullptr;
        if (load) name = sh == 1 ? "ldrh" : sh == 2 ? "ldrsb" : "ldrsh";
        else name = sh == 1 ? "strh" : sh == 2 ? "ldrd" : "strd";
        in.mnemonic = std::string(name) + c;
        const std::string off = imm ? "#" + std::string(up ? "" : "-") + std::to_string(((w >> 4) & 0xF0) | (w & 0xF))
                                    : std::string(up ? "" : "-") + reg(w & 15);
        in.operands = reg(rt) + ", [" + reg(rn) + (pre ? ", " + off + "]" + (wb ? "!" : "") : "], " + off);
        if (imm && rn == 15 && pre) {
            in.hasTarget = true;
            const int32_t o = static_cast<int32_t>(((w >> 4) & 0xF0) | (w & 0xF));
            in.target = relative(in.addr + 8, up ? o : -o);
        }
        return true;
    }
    if ((w & 0x0C000000) == 0 && (w & 0x01900000) != 0x01000000) {  // data processing
        static const char* ops[16] = {"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"};
        const unsigned op = (w >> 21) & 15, rn = (w >> 16) & 15, rd = (w >> 12) & 15;
        const bool s = (w >> 20) & 1, imm = (w >> 25) & 1;
        if ((w & 0x00000090) == 0x00000090 && !imm) return false;
        std::string op2;
        if (imm) {
            op2 = "#" + hex(armImmediate(w));
        } else {
            const unsigned rm = w & 15, type = (w >> 5) & 3;
            if (w & 0x10) op2 = reg(rm) + ", " + shiftName(type) + " " + reg((w >> 8) & 15);
            else op2 = shiftedReg(rm, type, (w >> 7) & 31);
        }
        const bool compare = op >= 8 && op <= 11, move = op == 13 || op == 15;
        in.mnemonic = std::string(ops[op]) + (s && !compare ? "s" : "") + c;
        if (compare) in.operands = reg(rn) + ", " + op2;
        else if (move) in.operands = reg(rd) + ", " + op2;
        else in.operands = reg(rd) + ", " + reg(rn) + ", " + op2;
        if (!compare && rd == 15) in.flow = (op == 13 && !imm && (w & 15) == 14 && !(w & 0xFF0)) ? Flow::Return : Flow::IndirectJump;
        return true;
    }
    return false;
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
    if (thumb16Extra(in, r, addr)) return in;
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
    if (thumb32Extra(in, h1, h2, addr)) return in;
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
    if (cond != 0xF && (a32Extra(in, w, c) || vfpDecode(in, w, false, c) || neonDup(in, w, c))) return in;
    if (cond == 0xF && neonDecode(in, w)) return in;
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
