#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "analysis/DexFile.hpp"

// Dalvik bytecode decoding and smali-style disassembly.
//
// decode() turns one instruction at a code-unit offset into a structured
// Insn (registers, literal, referenced index, branch target), which drives
// both the text listing and the cross-reference / call-graph / CFG analyses.
// Everything is bounds-checked against the code item: a truncated or
// malformed instruction stream is reported as an "invalid" instruction of
// size 1 so linear sweeps always make progress.
namespace dalvik {

enum class Format : uint8_t {
    k10x, k12x, k11n, k11x, k10t, k20t, k20bc, k22x, k21t, k21s, k21h, k21c, k23x, k22b, k22t, k22s, k22c,
    k22cs, k30t, k32x, k31i, k31t, k31c, k35c, k35ms, k35mi, k3rc, k3rms, k3rmi, k45cc, k4rcc, k51l, kUnused
};

// What an instruction's index operand refers to.
enum class RefKind : uint8_t { None, String, Type, Field, Method, Proto, CallSite, MethodHandle };

// Coarse instruction semantics used by the analyses.
enum class Flow : uint8_t {
    Normal,      // falls through
    Goto,        // unconditional branch
    Branch,      // conditional branch (falls through + target)
    Switch,      // packed/sparse switch (falls through + payload targets)
    Return,      // return*
    Throw,       // throw
    Invoke,      // call (falls through)
};

struct OpInfo {
    const char* name;
    Format format;
    RefKind ref;
    Flow flow;
};

const OpInfo& opInfo(uint8_t opcode);
// Size of a format in code units (0 for unused opcodes).
uint32_t formatSize(Format f);

struct Insn {
    uint32_t pc = 0;          // code-unit offset inside the method
    uint32_t size = 1;        // in code units
    uint8_t opcode = 0;
    bool valid = false;
    bool payload = false;     // packed-switch / sparse-switch / fill-array-data data
    uint16_t payloadIdent = 0;
    uint8_t regCount = 0;     // registers in regs[] (range: first + count)
    bool range = false;       // {vC .. vN} form
    uint32_t regs[5] = {0, 0, 0, 0, 0};
    int64_t literal = 0;
    bool hasLiteral = false;
    uint32_t index = DexFile::kNoIndex;   // string/type/field/method/... index
    uint32_t index2 = DexFile::kNoIndex;  // proto index of invoke-polymorphic
    int32_t branch = 0;       // relative target (code units) for branches / payload refs
    bool hasBranch = false;
};

// Decodes the instruction at `pc`. Never reads past code.insnsSize.
Insn decode(const DexFile::CodeItem& code, uint32_t pc);

// Absolute targets of a packed/sparse switch whose payload sits at
// `payloadPc` (relative to the method). Empty for a bad payload.
std::vector<uint32_t> switchTargets(const DexFile::CodeItem& code, uint32_t switchPc, uint32_t payloadPc);

// Human-readable operand text for a reference ("Lfoo;->bar()V", "\"text\"").
std::string refToString(const DexFile& dex, RefKind kind, uint32_t index);

struct ListingOptions {
    bool showOffsets = true;    // "/* 0012 */" prefixes
    bool showLines = true;      // .line directives from debug info
    bool showBytes = false;     // raw code units
    size_t maxInstructions = 200000;
};

// Smali-like listing of one method (header + body). `out` is appended to.
// Also reports, per output line, the pc it belongs to (-1 for directives)
// so the UI can map clicks back to instructions.
void disassembleMethod(const DexFile& dex, const DexFile::EncodedMethod& method, const ListingOptions& opt,
                       std::string& out, std::vector<int32_t>* linePcs = nullptr);

// Whole class: .class/.super/.implements/.source, fields and all methods.
void disassembleClass(const DexFile& dex, const DexFile::ClassDef& def, const ListingOptions& opt,
                      std::string& out);

}  // namespace dalvik
