#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "analysis/ApkAnalysis.hpp"

// Mapping between decompiled Java (jadx output) and the bytecode it came
// from, for the Java <-> Smali synchronisation of the Analysis workspace.
//
// The Java file is parsed just enough to know its classes (nested, and
// anonymous ones numbered like javac: Outer$1, Outer$2...) and the line
// range of every method body. Inside a method, lines and instructions are
// matched two ways:
//  - exact, when jadx wrote debug line comments ("/* 42 */", jadx option
//    --add-debug-lines) and the dex has line numbers: Java line -> source
//    line -> instructions;
//  - otherwise by aligning what each side does, in order: calls, object
//    creation, string constants and field accesses on a Java line against
//    the same operations in the bytecode (a longest common subsequence, so
//    a repeated call maps to the right occurrence). Lines with nothing to
//    match (braces, plain arithmetic) map to nothing rather than guessing.
// Lambda bodies map to their synthetic lambda$<method>$N methods.
namespace sourcemap {

struct JavaMethod {
    std::string cls;                  // binary class name: com.a.B, com.a.B$Inner, com.a.B$1
    std::string name;                 // "<init>" for constructors, "<clinit>" for static blocks
    std::vector<std::string> params;  // simple parameter types as written: "String", "int[]", "List"
    int declLine = -1;
    int bodyStart = -1;               // line of the opening brace
    int bodyEnd = -1;                 // line of the closing brace
};

class JavaFile {
public:
    // `lines`: the whole jadx output for one top-level class.
    explicit JavaFile(const std::vector<std::string_view>& lines);

    const std::vector<JavaMethod>& methods() const { return methods_; }
    // Innermost method whose declaration or body contains `line`, or nullptr.
    const JavaMethod* methodAt(int line) const;
    // The declaration line of a method, or -1.
    int findMethod(std::string_view cls, std::string_view name, const std::vector<std::string>& paramSimpleTypes) const;
    const std::string& packageName() const { return package_; }
    bool hasDebugLines() const { return debugLines_; }
    // Debug line comment ("/* 42 */") of a Java line, or -1.
    int debugLine(int line) const;
    size_t lineCount() const { return lines_.size(); }
    std::string_view line(int i) const { return lines_[static_cast<size_t>(i)]; }
    // Line ranges of lambda bodies and of anonymous class bodies inside methods.
    const std::vector<std::pair<int, int>>& lambdaRanges() const { return lambdas_; }
    const std::vector<std::pair<int, int>>& anonymousRanges() const { return anonymous_; }

private:
    std::vector<std::string> lines_;  // own copy: the document may change meanwhile
    std::vector<JavaMethod> methods_;
    std::vector<std::pair<int, int>> lambdas_, anonymous_;
    std::string package_;
    bool debugLines_ = false;
};

// Simple names of a method's parameter types ("(Ljava/lang/String;[I)V" -> String, int[]).
std::vector<std::string> paramSimpleTypes(std::string_view proto);

// The bytecode method a Java method was decompiled from (name + parameters).
bool resolve(const ApkAnalysis& a, const JavaMethod& m, ApkAnalysis::MethodDef& out);

// Where a Java line's code lives: the method (the declared one, or a lambda's
// synthetic method) and its instructions (pcs). False when nothing matches.
struct Target {
    ApkAnalysis::MethodDef method;
    std::vector<uint32_t> pcs;
    bool exact = false;  // from debug line numbers
};
bool javaToBytecode(const ApkAnalysis& a, const JavaFile& file, int line, Target& out);

// The Java line (0-based) an instruction belongs to, or -1. `method` must be
// declared in `file` (or be one of its lambdas).
int bytecodeToJava(const ApkAnalysis& a, const JavaFile& file, const ApkAnalysis::MethodDef& method, uint32_t pc);

}  // namespace sourcemap
