#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/NativeCode.hpp"

// Built-in decompilers for the Decompiler panel (the Ghidra / r2dec pane of
// Cutter): Java-like code for a Dalvik method and C-like code for an AArch64
// function. Both translate instructions to statements over registers, fold
// single-use temporaries into expressions, drop dead definitions, and then
// structure the control-flow graph into if / else, while, switch and break /
// continue, falling back to labelled gotos where the graph is not structured.
//
// Every output line keeps the addresses (Dalvik pc / native vaddr) of the
// instructions it was built from, so the panel can sync with the listing.
namespace decompiler {

struct Line {
    std::string text;              // without indentation
    int indent = 0;
    std::vector<uint64_t> addrs;   // instructions folded into this line (sorted)
    bool contains(uint64_t a) const;
    uint64_t firstAddr() const { return addrs.empty() ? UINT64_MAX : addrs.front(); }
};

// A variable of the function, as IDA lists them: the parameters, then the
// locals declared at the top of the body.
struct Var {
    std::string key;   // original name: v3, arg0, x19, sp_10
    std::string type;  // inferred (String, int, int64_t, uint8_t, char *)
    std::string note;  // when the register holds values of several types ("also int")
    bool param = false;
};

struct Output {
    std::vector<Line> lines;
    std::string error;  // non-empty when nothing could be produced
    std::vector<Var> vars;  // parameters in order, then locals
    // The signature line is headerPrefix + "type name, ..." + headerSuffix and the
    // locals are one "type name;" line each from declLine: both are rebuilt when
    // the user renames or retypes a variable.
    int headerLine = -1;
    std::string headerPrefix, headerSuffix;
    int declLine = -1;
    std::vector<std::pair<std::string, std::string>> renamed;  // applied renames: shown name -> variable key
    std::vector<std::pair<std::string, std::string>> renamedSymbols;  // applied symbol renames: shown -> original
};

Output decompileMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
Output decompileNative(const NativeCode& nc, const NativeCode::Function& f);

// Plain text (4-space indentation), for copying.
std::string toText(const Output& out);

// Variable renaming (IDA's N). Variables are the registers and stack slots the
// output names: v3 / arg0 (Dalvik), x19 / w8 / d0 / t1 / sp_10 / fp_m8 (native).
// The key of a native general register is its x name, so w8 and x8 are one variable.
bool isVariable(std::string_view token, bool native);
std::string variableKey(std::string_view token, bool native);
// Applies the user's names (key -> new name) and types (key -> type, IDA's Y):
// the signature and declarations are rebuilt, the code is renamed outside
// strings and comments.
// `symbols` (original -> new) renames every other identifier: functions, methods,
// fields, classes, labels, globals - wherever they appear, also after a '.'.
void applyUserNames(Output& out, const std::vector<std::pair<std::string, std::string>>& renames,
                    const std::vector<std::pair<std::string, std::string>>& types, bool native,
                    const std::vector<std::pair<std::string, std::string>>& symbols = {});
// A name the user may rename that is not a variable (not a keyword / built-in type).
bool isRenamableSymbol(std::string_view token, bool native);
// The original name of a shown identifier when it is a symbol (renamed or not), else "".
std::string symbolOfShown(const Output& out, std::string_view token, bool native);
// Why `name` cannot replace symbol `original`, or "" when it can ("" name: back to the original).
std::string checkSymbolName(const Output& out, std::string_view name, bool native);
inline void applyRenames(Output& out, const std::vector<std::pair<std::string, std::string>>& renames, bool native) {
    applyUserNames(out, renames, {}, native);
}
// Why `type` cannot be a variable type (empty, too long, odd characters), or "" when it can.
std::string checkTypeName(std::string_view type);
// The variable's current type (user's or inferred), or "" when the function has no such variable.
std::string typeOf(const Output& out, std::string_view key, const std::vector<std::pair<std::string, std::string>>& types);
// Start offsets of the identifiers of a line (outside strings / comments), for a keyboard cursor.
std::vector<size_t> identifierStarts(std::string_view text);
// The variable key of a shown identifier (renamed or not); empty when it is not a variable.
std::string keyOfShown(const Output& out, std::string_view token, bool native);
// Why `name` cannot be used in this function (not an identifier, a keyword, taken), or "" when it can.
std::string checkNewName(const Output& out, std::string_view name, std::string_view key, bool native);
// The identifier containing byte `col` of `text` ("" when none); its start in *begin.
std::string identifierAt(std::string_view text, size_t col, size_t* begin = nullptr);
// Byte offsets of whole-identifier occurrences of `ident` (outside strings / comments).
std::vector<size_t> findIdentifier(std::string_view text, std::string_view ident);

}  // namespace decompiler
