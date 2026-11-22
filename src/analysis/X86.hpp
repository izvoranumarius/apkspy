#pragma once
#include <cstddef>
#include <cstdint>
#include "analysis/NativeInsn.hpp"

// x86 (IA-32) and x86-64 instruction decoder for native-library listings, Intel syntax. It always finds the correct
// instruction length for the integer, x87, SSE / AVX and system instruction sets (prefixes, ModRM / SIB, displacement,
// immediates, VEX and EVEX), names the integer instructions and the common SSE ones, and gives everything else a
// generic name ("sse 0f 38 00", "evex 0f 6f"), so a listing never loses its place. Bytes that are not a valid
// instruction decode as "(bad)" with length 1.
//
// For analysis it reports: branch / call targets, RIP-relative addresses (memTarget), and for `lea` / `mov` with a
// plain [base+disp] operand the base register and displacement (the 32-bit PIC pattern [ebx+disp]).
namespace x86 {

// Decodes one instruction at `addr` from at most `len` bytes. Never reads past `len`. `is64` selects 64-bit mode.
native::Insn decode(const uint8_t* code, size_t len, uint64_t addr, bool is64);

}  // namespace x86
