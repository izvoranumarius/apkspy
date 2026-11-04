#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "analysis/DexFile.hpp"

// Whole-APK bytecode analysis over every classesN.dex: class table,
// cross-references (calls, field reads/writes, string and type uses),
// call graph queries, control-flow graphs, class hierarchy and string
// extraction.
//
// Built once per APK on a worker thread (see AnalysisService) and then
// immutable: every query is const and safe from any thread. The DEX bytes
// are shared, not copied; the cross-reference table is one flat sorted
// vector (16 bytes per reference) so even large apps stay compact.
class ApkAnalysis {
public:
    enum class XrefKind : uint8_t { Call, FieldRead, FieldWrite, String, Type };

    // A location inside the bytecode: method `method` of dex `dex`, at `pc`.
    struct CodeRef {
        uint16_t dex = 0;
        uint32_t method = 0;  // method_id index in that dex
        uint32_t pc = 0;
    };

    struct ClassEntry {
        uint16_t dex = 0;
        uint32_t def = 0;  // index into DexFile::classes()
    };

    struct BuildStats {
        size_t classes = 0;
        size_t methods = 0;
        size_t methodsWithCode = 0;
        size_t instructions = 0;
        size_t xrefs = 0;
        size_t codeBytes = 0;
    };

    // Builds the analysis. `stop` aborts early (returns nullptr); `progress`
    // (optional) receives processed/total class counts.
    static std::shared_ptr<ApkAnalysis> build(std::vector<std::shared_ptr<DexFile>> dexes,
                                              const std::atomic<bool>& stop,
                                              std::atomic<size_t>* progressDone = nullptr,
                                              std::atomic<size_t>* progressTotal = nullptr);

    const std::vector<std::shared_ptr<DexFile>>& dexes() const { return dexes_; }
    const std::vector<ClassEntry>& classes() const { return classes_; }  // sorted by descriptor
    const BuildStats& stats() const { return stats_; }

    std::string_view classDescriptor(const ClassEntry& c) const;
    const DexFile::ClassDef& classDef(const ClassEntry& c) const;
    // Class by descriptor ("Lcom/a/B;") or Java name ("com.a.B").
    const ClassEntry* findClass(std::string_view name) const;
    // Classes whose Java name contains `needle` (case-insensitive).
    std::vector<const ClassEntry*> searchClasses(std::string_view needle, size_t limit) const;

    // A resolved method definition (dex + encoded method with code offset).
    struct MethodDef {
        uint16_t dex = 0;
        DexFile::EncodedMethod method;
    };
    std::vector<MethodDef> methodsOf(const ClassEntry& c) const;
    // Finds method definitions by class + name (+ optional proto "(I)V").
    std::vector<MethodDef> findMethodDefs(std::string_view className, std::string_view methodName,
                                          std::string_view proto = {}) const;
    // Parses "Lcom/a/B;->name(I)V" (or "com.a.B.name") into its parts.
    static bool splitMethodRef(std::string_view ref, std::string& cls, std::string& name, std::string& proto);

    // Cross-references -------------------------------------------------------
    struct XrefHit {
        CodeRef from;
        XrefKind kind;
        std::string target;  // rendered target (signature / string)
    };
    // Callers of a method (any overload when `proto` is empty).
    std::vector<XrefHit> callersOf(std::string_view cls, std::string_view name, std::string_view proto,
                                   size_t limit) const;
    // Readers/writers of a field.
    std::vector<XrefHit> fieldAccesses(std::string_view cls, std::string_view name, size_t limit) const;
    // Code using a string constant: exact match, or substring when `substring`.
    std::vector<XrefHit> stringUses(std::string_view text, bool substring, size_t limit) const;
    // Code using string `index` of dex `dex` (the string a StringHit came from).
    std::vector<XrefHit> stringUsesAt(uint16_t dex, uint32_t index, size_t limit) const;
    // Code referencing a type (new-instance, const-class, check-cast, ...).
    std::vector<XrefHit> typeUses(std::string_view cls, size_t limit) const;

    // Calls made by a method (callees), in program order.
    struct Callee {
        uint32_t pc;
        std::string signature;
        std::string opcode;
    };
    std::vector<Callee> calleesOf(const MethodDef& m) const;

    // Constant data flow: for each call in the method, the arguments whose
    // value is a known constant at that point (const-string / const ints),
    // tracked per basic-block-linear sweep. Useful to see e.g. which URLs
    // or keys reach which API.
    struct ConstArgCall {
        uint32_t pc;
        std::string callee;
        std::vector<std::pair<int, std::string>> args;  // (argument position, constant)
    };
    std::vector<ConstArgCall> constantArguments(const MethodDef& m) const;

    // Control-flow graph of one method.
    struct BasicBlock {
        uint32_t startPc = 0;
        uint32_t endPc = 0;  // exclusive
        std::vector<uint32_t> successors;  // block indices
        std::vector<uint32_t> exceptional; // catch handler block indices
        bool exit = false;                 // ends in return/throw
    };
    std::vector<BasicBlock> controlFlowGraph(const MethodDef& m) const;
    // Graphviz DOT for a CFG (instructions rendered inside the nodes).
    std::string cfgToDot(const MethodDef& m, const std::vector<BasicBlock>& blocks) const;

    // Hierarchy -------------------------------------------------------------
    std::vector<std::string> superChain(std::string_view cls) const;  // class, super, super-super...
    std::vector<std::string> subclassesOf(std::string_view cls, size_t limit) const;
    std::vector<std::string> implementersOf(std::string_view iface, size_t limit) const;

    // Strings -----------------------------------------------------------------
    enum class StringCategory : uint8_t { Any, Url, Ip, Path, Secret, Email };
    struct StringHit {
        uint16_t dex;
        uint32_t index;
        std::string value;
        StringCategory category;
    };
    // Scans the string tables. `category` Any + `needle` filters by
    // substring; the specialised categories use heuristics (URLs, IPv4,
    // API paths, key/token-like values, e-mail addresses). For Url the hits
    // are the URL tokens themselves (a log message containing a link yields
    // just the link); dex/index still name the containing string.
    std::vector<StringHit> strings(std::string_view needle, StringCategory category, size_t limit) const;
    static StringCategory classify(std::string_view s);
    // URL tokens ("scheme://...") inside a string.
    static std::vector<std::string> extractUrls(std::string_view s);
    static const char* categoryName(StringCategory c);

    // Rendering helpers.
    std::string methodSignature(const CodeRef& r) const;
    std::string methodSignature(const MethodDef& m) const;
    // Smali-like listing of a method / class.
    std::string disassemble(const MethodDef& m) const;
    std::string disassembleClass(const ClassEntry& c) const;

private:
    struct Xref {
        uint32_t target;  // method/field/string/type index in `dex`
        uint32_t from;    // calling method index in `dex`
        uint32_t pc;
        uint16_t dex;
        XrefKind kind;
    };
    void collect(XrefKind kind, uint16_t dex, uint32_t target, size_t limit, std::vector<XrefHit>& out) const;

    std::vector<std::shared_ptr<DexFile>> dexes_;
    std::vector<ClassEntry> classes_;
    std::vector<Xref> xrefs_;  // sorted by (kind, dex, target)
    BuildStats stats_;
};
