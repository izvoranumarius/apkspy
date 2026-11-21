#pragma once
#include <cstdint>
#include <string>

// ARM32 (A32 + Thumb/Thumb-2) instruction decoder for native-library
// listings, the 32-bit companion of arm64::decode. Like the A64 decoder it
// never stops at an unknown word: anything it does not decode prints as
// ".word 0x..." (A32) or ".hword 0x..." (Thumb).
//
// Thumb has two encodings (16-bit and 32-bit), so decode() takes the
// instruction's first halfword and reports how many bytes it consumed.
namespace arm32 {

enum class Flow : uint8_t {
    Normal,
    Jump,
    CondJump,
    Call,
    Return,
    IndirectJump,
    IndirectCall,
    Trap,
};

struct Insn {
    uint64_t addr = 0;
    uint32_t raw = 0;
    uint8_t size = 4;  // bytes consumed (2 or 4)
    std::string mnemonic;
    std::string operands;
    Flow flow = Flow::Normal;
    bool hasTarget = false;
    uint64_t target = 0;
    bool thumb = false;
    bool known = true;
};

// Decodes one instruction at `addr`. `thumb` selects the Thumb mode (the
// function's low address bit, as the ELF symbols mark it). Never reads
// beyond `size` bytes of `code`.
Insn decode(const uint8_t* code, size_t len, uint64_t addr, bool thumb);

const char* conditionName(unsigned cond);  // ARM condition codes, Thumb suffix

}  // namespace arm32
