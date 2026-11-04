#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "analysis/Arm64.hpp"
#include "analysis/ElfFile.hpp"

// Code analysis of an AArch64 native library: function discovery (symbols,
// PLT stubs named after their imports, call targets), a reference index built
// by one linear sweep over the executable sections (calls, jumps and the data
// addresses formed by adrp + add / ldr pairs) and annotated listings.
// Immutable once built, so it can be shared between the UI and MCP threads.
class NativeCode {
public:
    enum class FunctionKind : uint8_t { Symbol, Plt, Discovered };
    struct Function {
        uint64_t addr = 0;
        uint64_t size = 0;
        std::string name;  // raw (mangled) symbol name, "puts@plt" or "sub_1234"
        FunctionKind kind = FunctionKind::Symbol;
        bool exported = false;
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
    };

    // Returns null (with error) for non-AArch64 libraries or when nothing executable is found.
    static std::shared_ptr<NativeCode> build(std::shared_ptr<const ElfFile> elf, const std::atomic<bool>* cancel,
                                             std::string& error);

    const ElfFile& elf() const { return *elf_; }
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
    std::vector<StringRef> stringRefs(const std::string& filter, size_t limit) const;

private:
    NativeCode() = default;
    bool readWord(uint64_t vaddr, uint32_t& out) const;
    void sweep(const std::atomic<bool>* cancel);
    void discoverFunctions();

    struct Range {
        uint64_t vaddr = 0, size = 0, offset = 0;
    };
    std::shared_ptr<const ElfFile> elf_;
    std::vector<Range> code_;
    std::vector<Function> functions_;            // sorted by address
    std::vector<Ref> refs_;                      // sorted by target
    std::vector<std::pair<uint64_t, std::string>> gotNames_;  // sorted by GOT slot address
    size_t instructions_ = 0;
};
