#pragma once
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

class DexFile;

// Static, source-level validation of edited smali.
//
// Checks, per file:
//  - Syntax: the text parses as smali (class / field / method directives,
//    instructions, labels, register lists, type and member references,
//    annotation and payload blocks). Parse problems are errors with a span.
//  - Register bounds: every register an instruction names - including the
//    second half of a wide (long / double) pair and the whole of a
//    {vA .. vB} range - is below the method's register count. With
//    `.registers N` that count is N; with `.locals L` it is L plus the
//    parameter registers (implicit `this` for non-static methods, two for
//    each J / D parameter). Out-of-range registers are errors.
//  - Dangling types: every type used as a class, array element, field owner,
//    method owner, invoke target, new-instance / check-cast / instance-of /
//    const-class / filled-new-array operand, catch type or field / method
//    signature type must resolve. Unresolved is a warning (reflection and
//    dynamically loaded code are legitimate).
//  - Dangling members: once the owner resolves, the referenced method
//    (name + prototype) or field (name + type) must exist on it or a
//    superclass / superinterface. Unresolved is a warning. An unresolved
//    owner yields only the type warning, never a second member warning.
//
// What is NOT checked - this is not a bytecode verifier: no type checking of
// register contents, no branch-target or reachability analysis, no
// try / catch range validation, no stack-map or monitor pairing, no
// opcode-format constraints beyond operand shape (e.g. 4-bit register limits
// of non-range invokes are not enforced), and no check that an invoke's
// register list matches the prototype. .annotation blocks are skipped
// entirely - their type and their values (dalvik Signature strings look like
// type descriptors). Strings and comments - '#' line comments and /* ... */
// blocks, such as the "/* 0000 */" offsets in ApkSpy's own listings - never
// produce type references.
//
// Pure and in-memory: no file system access, no APK input, nothing executed.
namespace smali {

enum class Severity { Error, Warning };

// Which check produced a diagnostic (stable; the edit report keys on it).
enum class Check { Syntax, RegisterBounds, UnresolvedType, UnresolvedMethod, UnresolvedField };
const char* checkName(Check c);  // "syntax", "register-bounds", "unresolved-type", ...

struct Diagnostic {
    std::string file;    // SourceFile::path
    int line = 0;        // 1-based
    int column = 0;      // 1-based, first character of the offending token
    int length = 0;      // token length in characters (0 = to end of line)
    Severity severity = Severity::Error;
    Check check = Check::Syntax;
    std::string message;
};

struct ValidationResult {
    std::vector<Diagnostic> errors;    // ordered by file, line, column
    std::vector<Diagnostic> warnings;  // same order
    bool clean() const { return errors.empty() && warnings.empty(); }
    bool hasErrors() const { return !errors.empty(); }
};

struct SourceFile {
    std::string path;  // workspace-relative, e.g. "smali/com/app/Main.smali"
    std::string text;
};

// What exists outside the files being validated.
class ClassUniverse {
public:
    // Unknown: outside what this universe can answer for (e.g. framework
    // classes when no framework class set is loaded) - never reported.
    enum class Lookup { Found, Missing, Unknown };
    virtual ~ClassUniverse() = default;
    // `descriptor` is a class descriptor ("Lcom/app/Main;"); never an array.
    virtual Lookup findClass(std::string_view descriptor) const = 0;
    // Looks through superclasses and superinterfaces; Unknown when the
    // search leaves the known class set before finding the member.
    virtual Lookup findMethod(std::string_view owner, std::string_view name, std::string_view proto) const = 0;  // proto "(ILjava/lang/String;)V"
    virtual Lookup findField(std::string_view owner, std::string_view name, std::string_view type) const = 0;
};

// The APK's dex classes (ApkAnalysis::dexes()). Classes outside the APK whose
// descriptor starts with one of `platformPrefixes` are Unknown, not Missing:
// ApkSpy holds no framework class set (android.jar), so framework references
// cannot be checked. Everything else outside the APK is Missing.
//
// The one exception is Ljava/lang/Object;, the root of every class chain,
// whose members are fixed by the JLS and are modelled exactly: <init>()V,
// equals(Ljava/lang/Object;)Z, hashCode()I, toString()Ljava/lang/String;,
// getClass()Ljava/lang/Class;, notify()V, notifyAll()V, wait()V, wait(J)V,
// wait(JI)V, clone()Ljava/lang/Object; and finalize()V (and no fields). It is
// Found as a class, and a member search that reaches it without a match is
// Missing. This exception covers Ljava/lang/Object; only and is not to be
// extended to other platform roots: a search that leaves the known set
// through any other framework class (e.g. Landroid/app/Activity;) remains
// Unknown and is never reported.
class DexUniverse final : public ClassUniverse {
public:
    explicit DexUniverse(std::vector<std::shared_ptr<const DexFile>> dexes,
                         std::vector<std::string> platformPrefixes = defaultPlatformPrefixes());
    ~DexUniverse() override;
    Lookup findClass(std::string_view descriptor) const override;
    Lookup findMethod(std::string_view owner, std::string_view name, std::string_view proto) const override;
    Lookup findField(std::string_view owner, std::string_view name, std::string_view type) const override;

    // "Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Lorg/json/", "Lorg/w3c/",
    // "Lorg/xml/", "Lorg/apache/http/", "Lsun/", "Llibcore/", "Lcom/android/internal/".
    static std::vector<std::string> defaultPlatformPrefixes();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Validates a set of edited files together: classes, methods and fields
// declared in any of `files` count as existing (they shadow the universe's
// version of the same class, so members added or removed by the edits are
// taken into account).
ValidationResult validate(std::span<const SourceFile> files, const ClassUniverse& universe);
ValidationResult validate(const SourceFile& file, const ClassUniverse& universe);

}  // namespace smali
