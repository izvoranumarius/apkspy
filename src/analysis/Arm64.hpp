#pragma once
#include <cstdint>
#include <string>

// AArch64 (A64) instruction decoder for native-library listings. Covers the
// base integer, load/store, branch and system instructions plus scalar
// floating point; anything else (mostly Advanced SIMD) is rendered as
// ".inst 0x..." so a listing never stops at an unknown word.
namespace arm64 {

enum class Flow : uint8_t {
    Normal,
    Jump,          // b
    CondJump,      // b.cond, cbz, tbz, ...
    Call,          // bl
    Return,        // ret
    IndirectJump,  // br
    IndirectCall,  // blr
    Trap,          // brk, udf
};

struct Insn {
    uint64_t addr = 0;
    uint32_t raw = 0;
    std::string mnemonic;
    std::string operands;
    Flow flow = Flow::Normal;
    bool hasTarget = false;
    uint64_t target = 0;  // branch / call target, adr / adrp address, literal address
    // Address-forming facts used to resolve "adrp x8, page" + "add x8, x8, #off" / "ldr x0, [x8, #off]".
    int8_t pageReg = -1;   // ADRP destination
    int8_t baseReg = -1;   // ADD-immediate source / load-store base register
    int8_t destReg = -1;   // ADD-immediate destination / load destination
    int64_t offset = 0;    // ADD immediate or load/store unsigned offset
    bool isAddImm = false;
    bool isLoad = false;
    bool known = true;     // false for ".inst"
};

Insn decode(uint32_t word, uint64_t pc);

const char* conditionName(unsigned cond);

}  // namespace arm64
