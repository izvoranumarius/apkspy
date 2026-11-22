#pragma once
#include <cstdint>
#include <string>

// The instruction shape every native-code decoder (AArch64, ARM / Thumb, x86, x86-64) produces, so the analysis and
// the listings do not care which architecture a library is for. A decoder fills what its architecture has and leaves
// the rest at the defaults; `size` is the byte length (fixed for A64, 2 or 4 for Thumb, 1-15 for x86).
namespace native {

enum class Flow : uint8_t {
    Normal,
    Jump,          // unconditional direct jump
    CondJump,      // conditional direct jump
    Call,          // direct call
    Return,
    IndirectJump,  // register / memory jump (switch tables, PLT stubs)
    IndirectCall,
    Trap,          // brk, udf, int3, ud2, hlt
};

struct Insn {
    uint64_t addr = 0;
    uint32_t raw = 0;       // the first (up to four) bytes of the instruction
    uint8_t size = 4;
    std::string mnemonic;
    std::string operands;
    Flow flow = Flow::Normal;
    bool hasTarget = false;
    uint64_t target = 0;    // branch / call target, adr / adrp address, literal or RIP-relative address
    // A target that is a memory address (PC-relative load, RIP-relative operand), not a branch destination.
    bool memTarget = false;
    // Address-forming facts: "adrp x8, page" + "add x8, x8, #off" (A64), "lea r, [ebx+off]" (x86).
    int8_t pageReg = -1;   // ADRP destination
    int8_t baseReg = -1;   // ADD-immediate source / load-store base register
    int8_t destReg = -1;   // ADD-immediate destination / load destination
    int64_t offset = 0;    // ADD immediate, load/store offset, x86 displacement
    bool isAddImm = false; // takes an address (add, lea)
    bool isLoad = false;   // reads memory
    bool known = true;     // false for ".inst" / ".word" / "(bad)"
    bool thumb = false;    // ARM: Thumb encoding
};

}  // namespace native
