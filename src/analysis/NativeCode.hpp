#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "analysis/Arm32.hpp"
#include "analysis/Arm64.hpp"
#include "analysis/X86.hpp"
#include "analysis/ElfFile.hpp"

// Code analysis of a native library (arm64-v8a, armeabi-v7a, x86 or x86_64): function discovery (symbols,
// PLT stubs named after their imports, call targets), a reference index built by one linear sweep over the
// executable sections (calls, jumps and the data addresses the architecture forms: adrp + add / ldr on AArch64,
// literal pools and movw / movt + add pc on ARM, RIP-relative operands on x86-64, [ebx + disp] on x86) and
// annotated listings. Immutable once built, so it can be shared between the UI and MCP threads.
class NativeCode {
public:
    enum class Isa : uint8_t { Arm64, Arm32, X86, X86_64 };
    static const char* isaName(Isa isa);  // "AArch64", "ARM", "x86", "x86-64"
    enum class FunctionKind : uint8_t { Symbol, Plt, Discovered };
    struct Function {
        uint64_t addr = 0;
        uint64_t size = 0;
        std::string name;  // raw (mangled) symbol name, "puts@plt" or "sub_1234"
        FunctionKind kind = FunctionKind::Symbol;
        bool exported = false;
        bool thumb = false;  // ARM: the function is Thumb code (the symbol's low address bit)
    };
    // Data = address taken (adrp + add, adr); Read = value loaded from the address (adrp + ldr, ldr literal).
    enum class RefKind : uint8_t { Call, Jump, Data, Read };
    struct Ref {
        uint64_t target = 0;
        uint64_t from = 0;
        RefKind kind = RefKind::Call;
    };
    struct Line {
        arm64::Insn insn;
        std::string targetName;  // symbol of a branch / call target ("strlen@plt", "sub_1234", "foo+0x10")
        std::string comment;     // resolved data reference: string literal, GOT slot, symbol
        uint64_t dataAddr = 0;   // address the comment refers to (0 = none)
        bool dataRead = false;   // dataAddr is loaded from, not taken
        bool label = false;      // jumped to from inside the listing
    };
    struct StringRef {
        uint64_t addr = 0;
        uint64_t from = 0;
        std::string text;
        const char* encoding = "utf-8";  // "utf-8" (also plain ASCII), "utf-16le" or "utf-32le"
    };

    // "" when the library can be disassembled; otherwise why not (an architecture without a decoder, big endian, ...).
    static std::string unsupportedReason(const ElfFile& elf);
    // Returns null (with error) for libraries unsupportedReason() rejects or when nothing executable is found.
    static std::shared_ptr<NativeCode> build(std::shared_ptr<const ElfFile> elf, const std::atomic<bool>* cancel,
                                             std::string& error);

    const ElfFile& elf() const { return *elf_; }
    Isa isa() const { return isa_; }
    // The decoded instruction at `vaddr` (size 0 when it is outside the code). `thumb` only matters on ARM.
    native::Insn decodeAt(uint64_t vaddr, bool thumb) const;
    const std::vector<Function>& functions() const { return functions_; }
    size_t instructionCount() const { return instructions_; }

    const Function* functionAt(uint64_t addr) const;  // the function containing addr
    // By exact (raw or demangled) name, "0x1234" address, or case-insensitive substring.
    const Function* findFunction(const std::string& query) const;
    // "name", "name+0x10", "name@got" or "" when nothing is known about addr.
    std::string symbolize(uint64_t addr) const;
    static std::string displayName(const Function& f);  // demangled

    std::vector<Line> disassemble(uint64_t start, uint64_t end, size_t maxInsns) const;
    std::vector<Line> disassembleFunction(const Function& f, size_t maxInsns) const;

    // Basic blocks of a function. Branch tables (br) end a block with no
    // successors: their targets are computed at run time.
    struct BasicBlock {
        size_t firstLine = 0, lineCount = 0;  // into ControlFlow::lines
        std::vector<int> successors;          // block indices
        bool conditional = false;             // successors[0] is taken, [1] falls through
        bool exit = false;                    // return, trap, tail call or indirect jump
    };
    struct ControlFlow {
        std::vector<Line> lines;
        std::vector<BasicBlock> blocks;
    };
    ControlFlow controlFlow(const Function& f, size_t maxInsns) const;

    std::vector<Ref> refsTo(uint64_t addr, size_t limit) const;
    std::vector<Ref> refsFrom(const Function& f, size_t limit) const;  // calls / data refs made by f
    // Printable C string at a virtual address ("" when it does not look like one).
    std::string cStringAt(uint64_t vaddr) const;
    // The same for a UTF-16LE string (Windows / Java style wide text), as UTF-8.
    std::string wideStringAt(uint64_t vaddr) const;
    // The same for UTF-32LE (wchar_t on Linux / Android).
    std::string wide32StringAt(uint64_t vaddr) const;
    // A C string, else a UTF-16LE one (*wide = true), else a UTF-32LE one (*wide and *utf32 = true); "" when none.
    std::string stringAt(uint64_t vaddr, bool* wide = nullptr, bool* utf32 = nullptr) const;
    std::vector<StringRef> stringRefs(const std::string& filter, size_t limit) const;

private:
    NativeCode() = default;
    bool readWord(uint64_t vaddr, uint32_t& out) const;
    void sweep(const std::atomic<bool>* cancel);       // AArch64: bit tests over fixed-width words
    void sweepGeneric(const std::atomic<bool>* cancel);  // ARM, x86, x86-64: a real decode of every instruction
    void discoverFunctions();
    void discoverPlt(std::vector<Function>& fns) const;
    std::vector<Line> disassembleArm64(uint64_t start, uint64_t end, size_t maxInsns) const;
    std::vector<Line> disassembleGeneric(uint64_t start, uint64_t end, size_t maxInsns) const;

    // Per-sweep state of the data-reference trackers (ARM: the constants held in registers).
    struct DataState {
        uint32_t value[16] = {};
        uint16_t known = 0;
        void reset() { known = 0; }
        void set(int r, uint32_t v) { if (r >= 0 && r < 16) value[r] = v, known |= static_cast<uint16_t>(1u << r); }
        void clear(int r) { if (r >= 0 && r < 16) known &= static_cast<uint16_t>(~(1u << r)); }
        bool has(int r) const { return r >= 0 && r < 16 && (known >> r & 1); }
    };
    // The data address an instruction takes (read = false) or loads from (read = true), when the architecture's
    // address-forming pattern is recognised. Updates `st`.
    bool dataRef(const native::Insn& in, DataState& st, uint64_t& addr, bool& read) const;
    bool armDataRef(const native::Insn& in, DataState& st, uint64_t& addr, bool& read) const;
    bool mapped(uint64_t vaddr) const;
    bool readData32(uint64_t vaddr, uint32_t& out) const;
    void annotate(Line& l, uint64_t data, bool dataRead) const;
    char modeAtAddr(uint64_t addr) const;                 // ARM: 't' Thumb, 'a' ARM, 'd' data
    char modeAt(uint64_t addr, size_t& cursor) const;     // the same for increasing addresses

    struct Range {
        uint64_t vaddr = 0, size = 0, offset = 0;
    };
    std::shared_ptr<const ElfFile> elf_;
    Isa isa_ = Isa::Arm64;
    std::vector<std::pair<uint64_t, char>> modes_;  // ARM mode markers ($t / $a / $d and function symbols), by address
    bool defaultThumb_ = true;                      // mode where no marker applies
    uint64_t gotBase_ = 0;                          // x86: the PIC base register's value (.got.plt)
    std::vector<Range> code_;
    std::vector<Function> functions_;            // sorted by address
    std::vector<Ref> refs_;                      // sorted by target
    std::vector<std::pair<uint64_t, std::string>> gotNames_;  // sorted by GOT slot address
    size_t instructions_ = 0;
};
