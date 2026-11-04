#include "analysis/Dalvik.hpp"
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <set>

namespace dalvik {
namespace {

using F = Format;
using R = RefKind;
using W = Flow;

std::array<OpInfo, 256> buildTable() {
    std::array<OpInfo, 256> t{};
    for (auto& e : t) e = {"unused", F::kUnused, R::None, W::Normal};
    const auto set = [&](int op, const char* name, F f, R r = R::None, W w = W::Normal) { t[op] = {name, f, r, w}; };
    const auto run = [&](int first, std::initializer_list<const char*> names, F f, R r = R::None, W w = W::Normal) {
        int op = first;
        for (const char* n : names) set(op++, n, f, r, w);
    };

    set(0x00, "nop", F::k10x);
    run(0x01, {"move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16", "move-object",
               "move-object/from16", "move-object/16"},
        F::k12x);
    set(0x02, "move/from16", F::k22x);
    set(0x03, "move/16", F::k32x);
    set(0x05, "move-wide/from16", F::k22x);
    set(0x06, "move-wide/16", F::k32x);
    set(0x08, "move-object/from16", F::k22x);
    set(0x09, "move-object/16", F::k32x);
    run(0x0a, {"move-result", "move-result-wide", "move-result-object", "move-exception"}, F::k11x);
    set(0x0e, "return-void", F::k10x, R::None, W::Return);
    run(0x0f, {"return", "return-wide", "return-object"}, F::k11x, R::None, W::Return);
    set(0x12, "const/4", F::k11n);
    set(0x13, "const/16", F::k21s);
    set(0x14, "const", F::k31i);
    set(0x15, "const/high16", F::k21h);
    set(0x16, "const-wide/16", F::k21s);
    set(0x17, "const-wide/32", F::k31i);
    set(0x18, "const-wide", F::k51l);
    set(0x19, "const-wide/high16", F::k21h);
    set(0x1a, "const-string", F::k21c, R::String);
    set(0x1b, "const-string/jumbo", F::k31c, R::String);
    set(0x1c, "const-class", F::k21c, R::Type);
    set(0x1d, "monitor-enter", F::k11x);
    set(0x1e, "monitor-exit", F::k11x);
    set(0x1f, "check-cast", F::k21c, R::Type);
    set(0x20, "instance-of", F::k22c, R::Type);
    set(0x21, "array-length", F::k12x);
    set(0x22, "new-instance", F::k21c, R::Type);
    set(0x23, "new-array", F::k22c, R::Type);
    set(0x24, "filled-new-array", F::k35c, R::Type);
    set(0x25, "filled-new-array/range", F::k3rc, R::Type);
    set(0x26, "fill-array-data", F::k31t);
    set(0x27, "throw", F::k11x, R::None, W::Throw);
    set(0x28, "goto", F::k10t, R::None, W::Goto);
    set(0x29, "goto/16", F::k20t, R::None, W::Goto);
    set(0x2a, "goto/32", F::k30t, R::None, W::Goto);
    set(0x2b, "packed-switch", F::k31t, R::None, W::Switch);
    set(0x2c, "sparse-switch", F::k31t, R::None, W::Switch);
    run(0x2d, {"cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"}, F::k23x);
    run(0x32, {"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"}, F::k22t, R::None, W::Branch);
    run(0x38, {"if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"}, F::k21t, R::None, W::Branch);
    run(0x44, {"aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short", "aput",
               "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short"},
        F::k23x);
    run(0x52, {"iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short", "iput",
               "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short"},
        F::k22c, R::Field);
    run(0x60, {"sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short", "sput",
               "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short"},
        F::k21c, R::Field);
    run(0x6e, {"invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"}, F::k35c,
        R::Method, W::Invoke);
    run(0x74, {"invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range",
               "invoke-interface/range"},
        F::k3rc, R::Method, W::Invoke);
    run(0x7b, {"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double", "int-to-long",
               "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double", "float-to-int",
               "float-to-long", "float-to-double", "double-to-int", "double-to-long", "double-to-float",
               "int-to-byte", "int-to-char", "int-to-short"},
        F::k12x);
    static const char* kBin[] = {"add-int",    "sub-int",    "mul-int",    "div-int",    "rem-int",
                                 "and-int",    "or-int",     "xor-int",    "shl-int",    "shr-int",
                                 "ushr-int",   "add-long",   "sub-long",   "mul-long",   "div-long",
                                 "rem-long",   "and-long",   "or-long",    "xor-long",   "shl-long",
                                 "shr-long",   "ushr-long",  "add-float",  "sub-float",  "mul-float",
                                 "div-float",  "rem-float",  "add-double", "sub-double", "mul-double",
                                 "div-double", "rem-double"};
    static const char* kBin2[] = {
        "add-int/2addr",    "sub-int/2addr",    "mul-int/2addr",    "div-int/2addr",    "rem-int/2addr",
        "and-int/2addr",    "or-int/2addr",     "xor-int/2addr",    "shl-int/2addr",    "shr-int/2addr",
        "ushr-int/2addr",   "add-long/2addr",   "sub-long/2addr",   "mul-long/2addr",   "div-long/2addr",
        "rem-long/2addr",   "and-long/2addr",   "or-long/2addr",    "xor-long/2addr",   "shl-long/2addr",
        "shr-long/2addr",   "ushr-long/2addr",  "add-float/2addr",  "sub-float/2addr",  "mul-float/2addr",
        "div-float/2addr",  "rem-float/2addr",  "add-double/2addr", "sub-double/2addr", "mul-double/2addr",
        "div-double/2addr", "rem-double/2addr"};
    for (int i = 0; i < 32; ++i) {
        set(0x90 + i, kBin[i], F::k23x);
        set(0xb0 + i, kBin2[i], F::k12x);
    }
    run(0xd0, {"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16",
               "or-int/lit16", "xor-int/lit16"},
        F::k22s);
    run(0xd8, {"add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8",
               "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8"},
        F::k22b);
    set(0xfa, "invoke-polymorphic", F::k45cc, R::Method, W::Invoke);
    set(0xfb, "invoke-polymorphic/range", F::k4rcc, R::Method, W::Invoke);
    set(0xfc, "invoke-custom", F::k35c, R::CallSite, W::Invoke);
    set(0xfd, "invoke-custom/range", F::k3rc, R::CallSite, W::Invoke);
    set(0xfe, "const-method-handle", F::k21c, R::MethodHandle);
    set(0xff, "const-method-type", F::k21c, R::Proto);
    return t;
}

const std::array<OpInfo, 256>& table() {
    static const std::array<OpInfo, 256> t = buildTable();
    return t;
}

int32_t s4(uint32_t v) { return (v & 0x8) ? (int32_t)v - 16 : (int32_t)v; }

void appendf(std::string& out, const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) out.append(buf, (size_t)std::min(n, (int)sizeof buf - 1));
}

// Escapes a string constant for the listing (smali style, ASCII-safe).
std::string quote(const std::string& s, size_t max = 400) {
    std::string out = "\"";
    for (size_t i = 0; i < s.size() && i < max; ++i) {
        const unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) appendf(out, "\\u%04x", c);
            else out.push_back((char)c);
        }
    }
    if (s.size() > max) out += "...";
    out += '"';
    return out;
}

}  // namespace

const OpInfo& opInfo(uint8_t opcode) { return table()[opcode]; }

uint32_t formatSize(Format f) {
    switch (f) {
    case F::k10x: case F::k12x: case F::k11n: case F::k11x: case F::k10t: return 1;
    case F::k20t: case F::k20bc: case F::k22x: case F::k21t: case F::k21s: case F::k21h: case F::k21c:
    case F::k23x: case F::k22b: case F::k22t: case F::k22s: case F::k22c: case F::k22cs: return 2;
    case F::k30t: case F::k32x: case F::k31i: case F::k31t: case F::k31c: case F::k35c: case F::k35ms:
    case F::k35mi: case F::k3rc: case F::k3rms: case F::k3rmi: return 3;
    case F::k45cc: case F::k4rcc: return 4;
    case F::k51l: return 5;
    case F::kUnused: return 0;
    }
    return 0;
}

Insn decode(const DexFile::CodeItem& code, uint32_t pc) {
    Insn in;
    in.pc = pc;
    if (pc >= code.insnsSize) return in;
    const uint16_t u0 = code.unit(pc);
    in.opcode = (uint8_t)(u0 & 0xFF);

    // Data payloads live inside the instruction stream, introduced by a nop
    // whose high byte identifies the payload kind.
    if (in.opcode == 0x00 && (u0 >> 8) != 0) {
        const uint16_t ident = u0;
        uint32_t size = 0;
        if (ident == 0x0100 && pc + 2 <= code.insnsSize) {  // packed-switch: size, first_key, targets
            size = 4 + (uint32_t)code.unit(pc + 1) * 2;
        } else if (ident == 0x0200 && pc + 2 <= code.insnsSize) {  // sparse-switch: size, keys, targets
            size = 2 + (uint32_t)code.unit(pc + 1) * 4;
        } else if (ident == 0x0300 && pc + 4 <= code.insnsSize) {  // fill-array-data
            const uint32_t width = code.unit(pc + 1);
            const uint32_t count = code.unit(pc + 2) | ((uint32_t)code.unit(pc + 3) << 16);
            const uint64_t bytes = (uint64_t)width * count;
            size = (uint32_t)std::min<uint64_t>(4 + (bytes + 1) / 2, code.insnsSize);
        }
        if (size > 0 && pc + size <= code.insnsSize) {
            in.payload = true;
            in.payloadIdent = ident;
            in.size = size;
            in.valid = true;
            return in;
        }
    }

    const OpInfo& info = opInfo(in.opcode);
    const uint32_t size = formatSize(info.format);
    if (size == 0 || pc + size > code.insnsSize) return in;  // unused opcode / truncated
    in.size = size;
    in.valid = true;
    const auto u = [&](uint32_t k) -> uint32_t { return code.unit(pc + k); };
    const uint32_t a8 = u0 >> 8;           // AA
    const uint32_t a4 = (u0 >> 8) & 0xF;   // A
    const uint32_t b4 = u0 >> 12;          // B
    switch (info.format) {
    case F::k10x: break;
    case F::k12x: in.regs[0] = a4; in.regs[1] = b4; in.regCount = 2; break;
    case F::k11n: in.regs[0] = a4; in.regCount = 1; in.literal = s4(b4); in.hasLiteral = true; break;
    case F::k11x: in.regs[0] = a8; in.regCount = 1; break;
    case F::k10t: in.branch = (int8_t)a8; in.hasBranch = true; break;
    case F::k20t: in.branch = (int16_t)u(1); in.hasBranch = true; break;
    case F::k22x: in.regs[0] = a8; in.regs[1] = u(1); in.regCount = 2; break;
    case F::k21t: in.regs[0] = a8; in.regCount = 1; in.branch = (int16_t)u(1); in.hasBranch = true; break;
    case F::k21s: in.regs[0] = a8; in.regCount = 1; in.literal = (int16_t)u(1); in.hasLiteral = true; break;
    case F::k21h:
        in.regs[0] = a8;
        in.regCount = 1;
        in.literal = in.opcode == 0x15 ? (int64_t)(int32_t)(u(1) << 16) : (int64_t)((uint64_t)u(1) << 48);
        in.hasLiteral = true;
        break;
    case F::k21c: in.regs[0] = a8; in.regCount = 1; in.index = u(1); break;
    case F::k23x:
        in.regs[0] = a8; in.regs[1] = u(1) & 0xFF; in.regs[2] = u(1) >> 8; in.regCount = 3;
        break;
    case F::k22b:
        in.regs[0] = a8; in.regs[1] = u(1) & 0xFF; in.regCount = 2;
        in.literal = (int8_t)(u(1) >> 8); in.hasLiteral = true;
        break;
    case F::k22t:
        in.regs[0] = a4; in.regs[1] = b4; in.regCount = 2; in.branch = (int16_t)u(1); in.hasBranch = true;
        break;
    case F::k22s:
        in.regs[0] = a4; in.regs[1] = b4; in.regCount = 2; in.literal = (int16_t)u(1); in.hasLiteral = true;
        break;
    case F::k22c: case F::k22cs:
        in.regs[0] = a4; in.regs[1] = b4; in.regCount = 2; in.index = u(1);
        break;
    case F::k30t: in.branch = (int32_t)(u(1) | (u(2) << 16)); in.hasBranch = true; break;
    case F::k32x: in.regs[0] = u(1); in.regs[1] = u(2); in.regCount = 2; break;
    case F::k31i:
        in.regs[0] = a8; in.regCount = 1; in.literal = (int32_t)(u(1) | (u(2) << 16)); in.hasLiteral = true;
        break;
    case F::k31t:
        in.regs[0] = a8; in.regCount = 1; in.branch = (int32_t)(u(1) | (u(2) << 16)); in.hasBranch = true;
        break;
    case F::k31c: in.regs[0] = a8; in.regCount = 1; in.index = u(1) | (u(2) << 16); break;
    case F::k35c: case F::k35ms: case F::k35mi: case F::k45cc: {
        const uint32_t count = std::min<uint32_t>(b4, 5);
        const uint32_t g = a4;
        const uint32_t regsUnit = u(2);
        const uint32_t list[5] = {regsUnit & 0xF, (regsUnit >> 4) & 0xF, (regsUnit >> 8) & 0xF,
                                  (regsUnit >> 12) & 0xF, g};
        for (uint32_t k = 0; k < count; ++k) in.regs[k] = list[k];
        in.regCount = (uint8_t)count;
        in.index = u(1);
        if (info.format == F::k45cc) in.index2 = u(3);
        break;
    }
    case F::k3rc: case F::k3rms: case F::k3rmi: case F::k4rcc:
        in.range = true;
        in.regs[0] = u(2);
        in.regCount = (uint8_t)std::min<uint32_t>(a8, 255);
        in.index = u(1);
        if (info.format == F::k4rcc) in.index2 = u(3);
        break;
    case F::k51l: {
        uint64_t v = 0;
        for (int k = 0; k < 4; ++k) v |= (uint64_t)u((uint32_t)(1 + k)) << (16 * k);
        in.regs[0] = a8; in.regCount = 1; in.literal = (int64_t)v; in.hasLiteral = true;
        break;
    }
    case F::k20bc: in.index = u(1); break;
    case F::kUnused: in.valid = false; break;
    }
    return in;
}

std::vector<uint32_t> switchTargets(const DexFile::CodeItem& code, uint32_t switchPc, uint32_t payloadPc) {
    std::vector<uint32_t> out;
    if (payloadPc + 2 > code.insnsSize) return out;
    const uint16_t ident = code.unit(payloadPc);
    const uint32_t count = code.unit(payloadPc + 1);
    uint32_t targetsAt = 0;
    if (ident == 0x0100) targetsAt = payloadPc + 4;
    else if (ident == 0x0200) targetsAt = payloadPc + 2 + count * 2;
    else return out;
    if ((uint64_t)targetsAt + (uint64_t)count * 2 > code.insnsSize) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const int32_t rel = (int32_t)(code.unit(targetsAt + 2 * i) | ((uint32_t)code.unit(targetsAt + 2 * i + 1) << 16));
        out.push_back((uint32_t)((int64_t)switchPc + rel));
    }
    return out;
}

std::string refToString(const DexFile& dex, RefKind kind, uint32_t index) {
    switch (kind) {
    case R::String: return index < dex.stringCount() ? quote(dex.string(index)) : "string@" + std::to_string(index);
    case R::Type: {
        const auto d = dex.typeDescriptor(index);
        return d.empty() ? "type@" + std::to_string(index) : std::string(d);
    }
    case R::Field:
        return index < dex.fieldCount() ? dex.fieldSignature(index) : "field@" + std::to_string(index);
    case R::Method:
        return index < dex.methodCount() ? dex.methodSignature(index) : "method@" + std::to_string(index);
    case R::Proto:
        return index < dex.protoCount() ? dex.protoDescriptor(index) : "proto@" + std::to_string(index);
    case R::CallSite: return "call_site@" + std::to_string(index);
    case R::MethodHandle: return "method_handle@" + std::to_string(index);
    case R::None: break;
    }
    return {};
}

namespace {

std::string regList(const Insn& in) {
    std::string out = "{";
    if (in.range) {
        if (in.regCount > 0) {
            appendf(out, "v%u", in.regs[0]);
            if (in.regCount > 1) appendf(out, " .. v%u", in.regs[0] + in.regCount - 1);
        }
    } else {
        for (uint32_t k = 0; k < in.regCount; ++k) appendf(out, k ? ", v%u" : "v%u", in.regs[k]);
    }
    out += '}';
    return out;
}

void appendInsn(const DexFile& dex, const Insn& in, std::string& out) {
    const OpInfo& info = opInfo(in.opcode);
    out += info.name;
    const auto target = [&](int32_t rel) {
        char buf[32];
        std::snprintf(buf, sizeof buf, ":L%04x", (unsigned)((int64_t)in.pc + rel));
        return std::string(buf);
    };
    switch (info.format) {
    case F::k35c: case F::k35ms: case F::k35mi: case F::k3rc: case F::k3rms: case F::k3rmi:
        out += ' ';
        out += regList(in);
        out += ", ";
        out += refToString(dex, info.ref, in.index);
        return;
    case F::k45cc: case F::k4rcc:
        out += ' ';
        out += regList(in);
        out += ", ";
        out += refToString(dex, R::Method, in.index);
        out += ", ";
        out += refToString(dex, R::Proto, in.index2);
        return;
    default: break;
    }
    bool first = true;
    const auto sep = [&] {
        out += first ? " " : ", ";
        first = false;
    };
    for (uint32_t k = 0; k < in.regCount; ++k) {
        sep();
        appendf(out, "v%u", in.regs[k]);
    }
    if (in.hasLiteral) {
        sep();
        if (in.literal < 0) appendf(out, "-0x%llx", (unsigned long long)(-(in.literal + 1)) + 1ull);
        else appendf(out, "0x%llx", (unsigned long long)in.literal);
    }
    if (info.ref != R::None && in.index != DexFile::kNoIndex) {
        sep();
        out += refToString(dex, info.ref, in.index);
    }
    if (in.hasBranch) {
        sep();
        out += target(in.branch);
    }
}

}  // namespace

void disassembleMethod(const DexFile& dex, const DexFile::EncodedMethod& m, const ListingOptions& opt,
                       std::string& out, std::vector<int32_t>* linePcs) {
    const auto mark = [&](int32_t pc) {
        if (linePcs) linePcs->push_back(pc);
    };
    std::string flags = DexFile::accessFlagsToString(m.accessFlags, true);
    out += ".method ";
    if (!flags.empty()) out += flags + ' ';
    out += dex.methodName(m.methodIdx);
    out += dex.protoDescriptor(dex.methodProto(m.methodIdx));
    out += '\n';
    mark(-1);
    DexFile::CodeItem code;
    if (m.codeOff == 0 || !dex.codeItem(m.codeOff, code)) {
        out += ".end method\n";
        mark(-1);
        return;
    }
    appendf(out, "    .registers %u\n", code.registers);
    mark(-1);

    // Pass 1: decode + collect branch targets for labels.
    std::vector<Insn> insns;
    std::set<uint32_t> labels;
    for (uint32_t pc = 0; pc < code.insnsSize && insns.size() < opt.maxInstructions;) {
        Insn in = decode(code, pc);
        if (in.valid && !in.payload && in.hasBranch) {
            const int64_t t = (int64_t)pc + in.branch;
            if (t >= 0 && t < code.insnsSize) labels.insert((uint32_t)t);
            if (opInfo(in.opcode).flow == W::Switch)
                for (uint32_t st : switchTargets(code, pc, (uint32_t)t)) labels.insert(st);
        }
        pc += std::max<uint32_t>(in.size, 1);
        insns.push_back(in);
    }

    int lastLine = -1;
    for (const Insn& in : insns) {
        if (labels.count(in.pc)) {
            appendf(out, "    :L%04x\n", in.pc);
            mark((int32_t)in.pc);
        }
        if (opt.showLines && !in.payload) {
            const int line = dex.lineForPc(code, in.pc);
            if (line >= 0 && line != lastLine) {
                appendf(out, "    .line %d\n", line);
                mark((int32_t)in.pc);
                lastLine = line;
            }
        }
        out += "    ";
        if (opt.showOffsets) appendf(out, "/* %04x */ ", in.pc);
        if (opt.showBytes) {
            for (uint32_t k = 0; k < std::min<uint32_t>(in.size, 5) && in.pc + k < code.insnsSize; ++k)
                appendf(out, "%04x ", code.unit(in.pc + k));
        }
        if (!in.valid) {
            appendf(out, ".invalid 0x%04x", code.unit(in.pc));
        } else if (in.payload) {
            const char* kind = in.payloadIdent == 0x0100 ? ".packed-switch-data"
                               : in.payloadIdent == 0x0200 ? ".sparse-switch-data"
                                                           : ".array-data";
            appendf(out, "%s (%u units)", kind, in.size);
        } else {
            appendInsn(dex, in, out);
        }
        out += '\n';
        mark((int32_t)in.pc);
    }
    if (insns.size() >= opt.maxInstructions) {
        out += "    # listing truncated\n";
        mark(-1);
    }
    out += ".end method\n";
    mark(-1);
}

void disassembleClass(const DexFile& dex, const DexFile::ClassDef& def, const ListingOptions& opt, std::string& out) {
    std::string flags = DexFile::accessFlagsToString(def.accessFlags, false);
    out += ".class ";
    if (!flags.empty()) out += flags + ' ';
    out += dex.typeDescriptor(def.classIdx);
    out += '\n';
    if (def.superclassIdx != DexFile::kNoIndex) {
        out += ".super ";
        out += dex.typeDescriptor(def.superclassIdx);
        out += '\n';
    }
    if (def.sourceFileIdx != DexFile::kNoIndex) out += ".source " + quote(dex.string(def.sourceFileIdx)) + '\n';
    for (uint32_t itf : dex.interfaces(def)) {
        out += ".implements ";
        out += dex.typeDescriptor(itf);
        out += '\n';
    }
    DexFile::ClassData data;
    if (!dex.classData(def, data)) {
        out += "\n# class_data_item is malformed\n";
        return;
    }
    if (!data.fields.empty()) out += "\n# fields\n";
    for (const auto& f : data.fields) {
        std::string ff = DexFile::accessFlagsToString(f.accessFlags, false);
        out += ".field ";
        if (!ff.empty()) out += ff + ' ';
        out += dex.fieldName(f.fieldIdx);
        out += ':';
        out += dex.typeDescriptor(dex.fieldType(f.fieldIdx));
        out += '\n';
    }
    bool direct = true;
    bool headerDone = false;
    for (const auto& m : data.methods) {
        if (!headerDone || m.direct != direct) {
            out += m.direct ? "\n# direct methods\n" : "\n# virtual methods\n";
            direct = m.direct;
            headerDone = true;
        }
        disassembleMethod(dex, m, opt, out);
        out += '\n';
    }
}

}  // namespace dalvik
