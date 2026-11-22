#pragma once
#include <cstdint>
#include <string>
#include "analysis/NativeInsn.hpp"

// AArch64 (A64) instruction decoder for native-library listings. Covers the
// base integer, load/store, branch and system instructions plus scalar
// floating point; anything else (mostly Advanced SIMD) is rendered as
// ".inst 0x..." so a listing never stops at an unknown word.
namespace arm64 {

using Flow = native::Flow;
using Insn = native::Insn;

Insn decode(uint32_t word, uint64_t pc);

const char* conditionName(unsigned cond);

}  // namespace arm64
