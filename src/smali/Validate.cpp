#include "smali/Validate.hpp"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include "analysis/DexFile.hpp"

namespace smali {

const char* checkName(Check c) {
    switch (c) {
        case Check::Syntax: return "syntax";
        case Check::RegisterBounds: return "register-bounds";
        case Check::UnresolvedType: return "unresolved-type";
        case Check::UnresolvedMethod: return "unresolved-method";
        case Check::UnresolvedField: return "unresolved-field";
    }
    return "?";
}

namespace {

using Lookup = ClassUniverse::Lookup;

// ---------------------------------------------------------------------------
// Opcodes: operand shapes. r register, R wide register (a pair), l register
// list / range, t type, f field ref, m method ref, s string, i literal,
// b label, c opaque (call site, method handle, proto: not checked).
// ---------------------------------------------------------------------------

const std::unordered_map<std::string, std::string>& opcodes() {
    static const std::unordered_map<std::string, std::string> table = [] {
        std::unordered_map<std::string, std::string> t = {
            {"nop", ""},
            {"move", "rr"}, {"move/from16", "rr"}, {"move/16", "rr"},
            {"move-wide", "RR"}, {"move-wide/from16", "RR"}, {"move-wide/16", "RR"},
            {"move-object", "rr"}, {"move-object/from16", "rr"}, {"move-object/16", "rr"},
            {"move-result", "r"}, {"move-result-wide", "R"}, {"move-result-object", "r"}, {"move-exception", "r"},
            {"return-void", ""}, {"return", "r"}, {"return-wide", "R"}, {"return-object", "r"},
            {"const/4", "ri"}, {"const/16", "ri"}, {"const", "ri"}, {"const/high16", "ri"},
            {"const-wide/16", "Ri"}, {"const-wide/32", "Ri"}, {"const-wide", "Ri"}, {"const-wide/high16", "Ri"},
            {"const-string", "rs"}, {"const-string/jumbo", "rs"}, {"const-class", "rt"},
            {"monitor-enter", "r"}, {"monitor-exit", "r"},
            {"check-cast", "rt"}, {"instance-of", "rrt"}, {"array-length", "rr"},
            {"new-instance", "rt"}, {"new-array", "rrt"},
            {"filled-new-array", "lt"}, {"filled-new-array/range", "lt"}, {"fill-array-data", "rb"},
            {"throw", "r"}, {"goto", "b"}, {"goto/16", "b"}, {"goto/32", "b"},
            {"packed-switch", "rb"}, {"sparse-switch", "rb"},
            {"cmpl-float", "rrr"}, {"cmpg-float", "rrr"}, {"cmpl-double", "rRR"}, {"cmpg-double", "rRR"}, {"cmp-long", "rRR"},
            {"invoke-polymorphic", "lmc"}, {"invoke-polymorphic/range", "lmc"},
            {"invoke-custom", "lc"}, {"invoke-custom/range", "lc"},
            {"const-method-handle", "rc"}, {"const-method-type", "rc"},
        };
        for (const char* c : {"eq", "ne", "lt", "ge", "gt", "le"}) {
            t[std::string("if-") + c] = "rrb";
            t[std::string("if-") + c + "z"] = "rb";
        }
        for (const char* s : {"", "-object", "-boolean", "-byte", "-char", "-short"}) {
            for (const char* k : {"aget", "aput"}) t[std::string(k) + s] = "rrr";
            for (const char* k : {"iget", "iput"}) t[std::string(k) + s] = "rrf";
            for (const char* k : {"sget", "sput"}) t[std::string(k) + s] = "rf";
        }
        t["aget-wide"] = t["aput-wide"] = "Rrr";
        t["iget-wide"] = t["iput-wide"] = "Rrf";
        t["sget-wide"] = t["sput-wide"] = "Rf";
        for (const char* k : {"virtual", "super", "direct", "static", "interface"}) {
            t[std::string("invoke-") + k] = "lm";
            t[std::string("invoke-") + k + "/range"] = "lm";
        }
        // Unary and conversions.
        for (const char* k : {"neg-int", "not-int", "neg-float", "int-to-float", "float-to-int", "int-to-byte", "int-to-char",
                              "int-to-short"})
            t[k] = "rr";
        for (const char* k : {"neg-long", "not-long", "neg-double", "long-to-double", "double-to-long"}) t[k] = "RR";
        for (const char* k : {"int-to-long", "int-to-double", "float-to-long", "float-to-double"}) t[k] = "Rr";
        for (const char* k : {"long-to-int", "long-to-float", "double-to-int", "double-to-float"}) t[k] = "rR";
        // Binary operations, three-address and /2addr.
        for (const char* op : {"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"}) {
            const std::string o = op;
            t[o + "-int"] = "rrr";
            t[o + "-int/2addr"] = "rr";
            const bool shift = o == "shl" || o == "shr" || o == "ushr";
            t[o + "-long"] = shift ? "RRr" : "RRR";
            t[o + "-long/2addr"] = shift ? "Rr" : "RR";
            if (o == "add" || o == "sub" || o == "mul" || o == "div" || o == "rem") {
                t[o + "-float"] = "rrr";
                t[o + "-float/2addr"] = "rr";
                t[o + "-double"] = "RRR";
                t[o + "-double/2addr"] = "RR";
            }
        }
        for (const char* k : {"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16",
                              "or-int/lit16", "xor-int/lit16", "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
                              "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8",
                              "ushr-int/lit8"})
            t[k] = "rri";
        return t;
    }();
    return table;
}

// ---------------------------------------------------------------------------
// Collected facts
// ---------------------------------------------------------------------------

struct Pos {
    int line = 0, column = 0, length = 0;
};

struct TypeUse {
    size_t file;
    Pos pos;
    std::string desc;  // a class descriptor (array elements already unwrapped)
};

struct MemberUse {
    size_t file;
    Pos pos;
    std::string owner, name, sig;  // sig: "(I)V" for methods, "I" for fields
    bool method;
};

struct ClassModel {
    std::string super;
    std::vector<std::string> interfaces;
    std::set<std::string> methods;  // name + proto
    std::set<std::string> fields;   // name + ":" + type
};

struct RegUse {
    Pos pos;
    bool param;
    int n;
    bool wide;
};

struct Collected {
    std::vector<Diagnostic> diags;
    std::vector<TypeUse> types;
    std::vector<MemberUse> members;
    std::map<std::string, ClassModel> edited;
};

// One type descriptor at s[i]; class descriptors found inside are reported
// with their offset. False when malformed.
bool parseType(std::string_view s, size_t& i, std::vector<std::pair<size_t, std::string>>* classes, bool allowVoid) {
    size_t dims = 0;
    while (i < s.size() && s[i] == '[') ++i, ++dims;
    if (dims > 255 || i >= s.size()) return false;
    const char c = s[i];
    if (c == 'L') {
        const size_t end = s.find(';', i);
        if (end == std::string_view::npos || end == i + 1) return false;
        for (size_t k = i + 1; k < end; ++k)
            if (s[k] == '(' || s[k] == ')' || s[k] == '[' || s[k] == ':' || s[k] == ' ' || s[k] == '-' && k + 1 < end && s[k + 1] == '>')
                return false;
        if (classes) classes->emplace_back(i, std::string(s.substr(i, end - i + 1)));
        i = end + 1;
        return true;
    }
    if (c == 'V') {
        if (!allowVoid || dims) return false;
        ++i;
        return true;
    }
    if (std::string_view("ZBSCIJFD").find(c) == std::string_view::npos) return false;
    ++i;
    return true;
}

// A whole token as one type.
bool wholeType(std::string_view s, std::vector<std::pair<size_t, std::string>>* classes) {
    size_t i = 0;
    return parseType(s, i, classes, false) && i == s.size();
}

// "(params)ret" -> parameter register count (J / D take two). False when malformed.
bool parseProto(std::string_view s, size_t& i, std::vector<std::pair<size_t, std::string>>* classes, int* paramRegs) {
    if (i >= s.size() || s[i] != '(') return false;
    ++i;
    int regs = 0;
    while (i < s.size() && s[i] != ')') {
        const char first = s[i];
        const size_t before = i;
        if (!parseType(s, i, classes, false)) return false;
        regs += (i - before == 1 && (first == 'J' || first == 'D')) ? 2 : 1;
    }
    if (i >= s.size()) return false;
    ++i;  // ')'
    if (!parseType(s, i, classes, true)) return false;
    if (paramRegs) *paramRegs = regs;
    return true;
}

bool isRegister(std::string_view t, bool& param, int& n) {
    if (t.size() < 2 || (t[0] != 'v' && t[0] != 'p')) return false;
    for (size_t k = 1; k < t.size(); ++k)
        if (!std::isdigit(static_cast<unsigned char>(t[k]))) return false;
    if (t.size() > 7) return false;
    param = t[0] == 'p';
    n = std::stoi(std::string(t.substr(1)));
    return true;
}

std::string_view trim(std::string_view s, size_t& lead) {
    lead = 0;
    while (lead < s.size() && std::isspace(static_cast<unsigned char>(s[lead]))) ++lead;
    size_t end = s.size();
    while (end > lead && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(lead, end - lead);
}

// The line without its comments: '#' to the end of the line, and /* ... */
// blocks (ApkSpy's own listings prefix each instruction with "/* 0000 */",
// its code-unit offset). Block comments become spaces so columns stay exact.
// Both only count outside strings and char literals. `unterminated` reports
// an unclosed string, `openBlock` the column of an unclosed /* (0 = none).
std::string stripComments(std::string_view line, bool& unterminated, int& openBlock) {
    unterminated = false;
    openBlock = 0;
    std::string out(line);
    char quote = 0;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        if (quote) {
            if (c == '\\') ++i;
            else if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '#') {
            out.resize(i);
            break;
        } else if (c == '/' && i + 1 < out.size() && out[i + 1] == '*') {
            const size_t end = out.find("*/", i + 2);
            if (end == std::string::npos) {
                openBlock = static_cast<int>(i) + 1;
                out.resize(i);
                break;
            }
            std::fill(out.begin() + static_cast<std::ptrdiff_t>(i), out.begin() + static_cast<std::ptrdiff_t>(end + 2), ' ');
            i = end + 1;
        }
    }
    unterminated = quote == '"';
    return out;
}

struct Word {
    std::string_view text;
    int column;  // 1-based
};

std::vector<Word> words(std::string_view line) {
    std::vector<Word> out;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        if (i >= line.size()) break;
        const size_t start = i;
        if (line[i] == '"') {  // a string stays one word
            ++i;
            while (i < line.size() && line[i] != '"') i += line[i] == '\\' ? 2 : 1;
            i = std::min(i + 1, line.size());
        } else {
            while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        }
        out.push_back({line.substr(start, i - start), static_cast<int>(start) + 1});
    }
    return out;
}

// Operands: split on commas outside strings, braces and parentheses.
std::vector<Word> operands(std::string_view rest, int baseColumn) {
    std::vector<Word> out;
    int depth = 0;
    char quote = 0;
    size_t start = 0;
    const auto push = [&](size_t end) {
        size_t lead;
        const std::string_view t = trim(rest.substr(start, end - start), lead);
        out.push_back({t, baseColumn + static_cast<int>(start + lead)});
    };
    for (size_t i = 0; i < rest.size(); ++i) {
        const char c = rest[i];
        if (quote) {
            if (c == '\\') ++i;
            else if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') quote = c;
        else if (c == '{' || c == '(') ++depth;
        else if (c == '}' || c == ')') --depth;
        else if (c == ',' && depth == 0) {
            push(i);
            start = i + 1;
        }
    }
    size_t lead;
    if (!trim(rest.substr(start), lead).empty() || !out.empty()) push(rest.size());
    return out;
}

// ---------------------------------------------------------------------------
// Parser: one file
// ---------------------------------------------------------------------------

class FileParser {
public:
    FileParser(size_t index, const SourceFile& file, Collected& out) : index_(index), file_(file), out_(out) {}

    void run() {
        std::string_view text = file_.text;
        int lineNo = 0;
        size_t pos = 0;
        while (pos <= text.size()) {
            size_t eol = text.find('\n', pos);
            if (eol == std::string_view::npos) eol = text.size();
            std::string_view raw = text.substr(pos, eol - pos);
            if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
            ++lineNo;
            line(lineNo, raw);
            if (eol >= text.size()) break;
            pos = eol + 1;
        }
        if (method_.active)
            error(method_.start, "missing .end method for " + method_.name);
        if (skipEnd_.size()) error({skipLine_, 1, 0}, "missing " + skipEnd_);
    }

private:
    struct Method {
        bool active = false;
        std::string name;
        Pos start;
        int ins = 0;
        int registers = -1;  // .registers N
        int locals = -1;     // .locals L
        bool hasInsn = false;
        Pos firstInsn;
        std::vector<RegUse> regs;
    };

    void error(Pos p, std::string msg, Check check = Check::Syntax) {
        out_.diags.push_back({file_.path, p.line, p.column, p.length, Severity::Error, check, std::move(msg)});
    }

    void typeUses(const std::vector<std::pair<size_t, std::string>>& classes, int line, int column) {
        for (const auto& [off, desc] : classes)
            out_.types.push_back({index_, {line, column + static_cast<int>(off), static_cast<int>(desc.size())}, desc});
    }

    ClassModel* model() { return className_.empty() ? nullptr : &out_.edited[className_]; }

    void line(int n, std::string_view raw) {
        bool unterminated = false;
        int openBlock = 0;
        const std::string cleaned = stripComments(raw, unterminated, openBlock);
        if (openBlock && skipEnd_.empty()) error({n, openBlock, 2}, "unterminated /* comment");
        size_t lead;
        const std::string_view code = trim(cleaned, lead);
        if (code.empty()) return;
        const int col0 = static_cast<int>(lead) + 1;
        if (!skipEnd_.empty()) {  // inside an annotation or a payload block
            if (code.rfind(skipEnd_, 0) == 0) skipEnd_.clear();
            return;
        }
        if (unterminated) {
            error({n, col0, 0}, "unterminated string");
            return;
        }
        std::vector<Word> w = words(code);
        for (Word& word : w) word.column += col0 - 1;  // columns of the original line
        const std::string_view head = w[0].text;
        if (!sawClass_ && head != ".class") {
            if (!missingClassReported_) error({n, w[0].column, static_cast<int>(head.size())}, "expected .class first");
            missingClassReported_ = true;
            // Keep parsing the rest so later problems still show.
        }
        if (head[0] == '.') directive(n, w, code, col0);
        else if (head[0] == ':') {
            if (!method_.active) error({n, w[0].column, static_cast<int>(head.size())}, "label outside a method");
        } else instruction(n, w, code, col0);
    }

    void directive(int n, const std::vector<Word>& w, std::string_view code, int col0) {
        const std::string_view d = w[0].text;
        const Pos at{n, w[0].column, static_cast<int>(d.size())};
        // Blocks skipped whole.
        if (d == ".annotation") return skip(n, ".end annotation");
        if (d == ".packed-switch") return skip(n, ".end packed-switch");
        if (d == ".sparse-switch") return skip(n, ".end sparse-switch");
        if (d == ".array-data") return skip(n, ".end array-data");

        if (d == ".class") {
            if (sawClass_) return error(at, "second .class directive");
            sawClass_ = true;
            const Word& name = w.back();
            std::vector<std::pair<size_t, std::string>> cls;
            if (w.size() < 2 || !wholeType(name.text, &cls) || cls.size() != 1 || name.text[0] != 'L')
                return error({n, name.column, static_cast<int>(name.text.size())}, "expected a class descriptor");
            className_ = cls[0].second;
            out_.edited[className_];
            return;
        }
        if (d == ".super" || d == ".implements") {
            std::vector<std::pair<size_t, std::string>> cls;
            if (w.size() != 2 || !wholeType(w[1].text, &cls) || cls.size() != 1 || w[1].text[0] != 'L')
                return error(at, "expected one class descriptor after " + std::string(d));
            typeUses(cls, n, w[1].column);
            if (ClassModel* m = model()) (d == ".super" ? m->super : m->interfaces.emplace_back()) = cls[0].second;
            return;
        }
        if (d == ".source" || d == ".debug") return;
        if (d == ".field") return field(n, w);
        if (d == ".end") {
            if (w.size() < 2) return error(at, ".end without a block name");
            const std::string_view what = w[1].text;
            if (what == "method") {
                if (!method_.active) return error(at, ".end method without .method");
                return endMethod();
            }
            if (what == "field" || what == "param" || what == "local") return;
            return error(at, "unexpected .end " + std::string(what));
        }
        if (d == ".method") return beginMethod(n, w);

        // Method-only directives.
        static const std::set<std::string_view> inMethod = {".registers", ".locals", ".param", ".local", ".restart",
                                                            ".line", ".prologue", ".epilogue", ".catch", ".catchall"};
        if (!inMethod.count(d)) return error(at, "unknown directive " + std::string(d));
        if (!method_.active) return error(at, std::string(d) + " outside a method");
        if (d == ".registers" || d == ".locals") {
            if (method_.registers >= 0 || method_.locals >= 0) return error(at, "register count given twice");
            int v = -1;
            if (w.size() == 2) {
                try {
                    size_t used = 0;
                    v = std::stoi(std::string(w[1].text), &used, 0);
                    if (used != w[1].text.size()) v = -1;
                } catch (...) {
                    v = -1;
                }
            }
            if (v < 0 || v > 65535) return error(at, "expected a register count");
            (d == ".registers" ? method_.registers : method_.locals) = v;
            return;
        }
        if (d == ".catch") {
            std::vector<std::pair<size_t, std::string>> cls;
            if (w.size() < 2 || !wholeType(w[1].text, &cls) || w[1].text[0] != 'L')
                return error(at, "expected an exception class after .catch");
            typeUses(cls, n, w[1].column);
            return;
        }
        (void)code;
        (void)col0;
    }

    void skip(int n, const char* end) {
        skipEnd_ = end;
        skipLine_ = n;
    }

    void field(int n, const std::vector<Word>& w) {
        // .field <flags> name:Type [= value]
        for (size_t k = 1; k < w.size(); ++k) {
            const std::string_view t = w[k].text;
            if (t == "=") break;
            const size_t colon = t.find(':');
            if (colon == std::string_view::npos) continue;
            std::vector<std::pair<size_t, std::string>> cls;
            const std::string_view type = t.substr(colon + 1);
            if (colon == 0 || !wholeType(type, &cls))
                return error({n, w[k].column, static_cast<int>(t.size())}, "malformed field declaration");
            typeUses(cls, n, w[k].column + static_cast<int>(colon) + 1);
            if (ClassModel* m = model()) m->fields.insert(std::string(t));
            return;
        }
        error({n, w[0].column, 6}, "expected name:Type after .field");
    }

    void beginMethod(int n, const std::vector<Word>& w) {
        if (method_.active) {
            error({n, w[0].column, 7}, "missing .end method before the next .method");
            endMethod();
        }
        const Word& sig = w.back();
        const size_t paren = sig.text.find('(');
        bool isStatic = false;
        for (size_t k = 1; k + 1 < w.size(); ++k) isStatic |= w[k].text == "static";
        std::vector<std::pair<size_t, std::string>> cls;
        int regs = 0;
        size_t i = paren;
        if (w.size() < 2 || paren == std::string_view::npos || paren == 0 || !parseProto(sig.text, i, &cls, &regs) ||
            i != sig.text.size()) {
            error({n, sig.column, static_cast<int>(sig.text.size())}, "malformed method declaration");
            method_ = Method{};
            method_.active = true;  // still pair with its .end method
            method_.start = {n, w[0].column, 7};
            method_.ins = -1;
            return;
        }
        typeUses(cls, n, sig.column);
        if (ClassModel* m = model()) m->methods.insert(std::string(sig.text));
        method_ = Method{};
        method_.active = true;
        method_.name = std::string(sig.text);
        method_.start = {n, w[0].column, 7};
        method_.ins = regs + (isStatic ? 0 : 1);
    }

    void endMethod() {
        const Method m = method_;
        method_ = Method{};
        if (m.ins < 0) return;  // malformed declaration: already reported
        if (!m.hasInsn) return;
        if (m.registers < 0 && m.locals < 0) {
            error(m.firstInsn, "method " + m.name + " has instructions but no .registers or .locals");
            return;
        }
        const int total = m.registers >= 0 ? m.registers : m.locals + m.ins;
        for (const RegUse& r : m.regs) {
            const int abs = r.param ? total - m.ins + r.n : r.n;
            const int last = abs + (r.wide ? 1 : 0);
            if (abs < 0 || last >= total || (r.param && r.n + (r.wide ? 1 : 0) >= m.ins)) {
                std::string what = std::string(r.param ? "p" : "v") + std::to_string(r.n);
                if (r.wide && last >= total && abs < total) what += " (with its wide pair)";
                error(r.pos,
                      what + " is out of range: the method has " + std::to_string(total) + " registers" +
                          (r.param ? " (" + std::to_string(m.ins) + " for parameters)" : std::string()),
                      Check::RegisterBounds);
            }
        }
    }

    void reg(Pos p, std::string_view t, bool wide) {
        bool param;
        int num;
        if (!isRegister(t, param, num)) {
            if (!t.empty() && (t[0] == 'v' || t[0] == 'p')) error(p, "malformed register " + std::string(t));
            else error(p, "expected a register, found " + (t.empty() ? std::string("nothing") : std::string(t)));
            return;
        }
        method_.regs.push_back({p, param, num, wide});
    }

    void regList(const Word& op, int line) {
        const std::string_view t = op.text;
        if (t.size() < 2 || t.front() != '{' || t.back() != '}')
            return error({line, op.column, static_cast<int>(t.size())}, "expected a register list {...}");
        const std::string_view inner = t.substr(1, t.size() - 2);
        const int base = op.column + 1;
        const size_t dots = inner.find("..");
        if (dots != std::string_view::npos) {  // {vA .. vB}
            size_t lead;
            const std::string_view a = trim(inner.substr(0, dots), lead);
            const int colA = base + static_cast<int>(lead);
            const std::string_view rest = inner.substr(dots + 2);
            const std::string_view b = trim(rest, lead);
            const int colB = base + static_cast<int>(dots + 2 + lead);
            bool pa, pb;
            int na, nb;
            if (!isRegister(a, pa, na) || !isRegister(b, pb, nb) || pa != pb || nb < na)
                return error({line, op.column, static_cast<int>(t.size())}, "malformed register range");
            reg({line, colA, static_cast<int>(a.size())}, a, false);
            reg({line, colB, static_cast<int>(b.size())}, b, false);  // the end bounds the whole range
            return;
        }
        for (const Word& r : operands(inner, base)) {
            if (r.text.empty()) {
                if (inner.find_first_not_of(" \t") == std::string_view::npos) return;  // {}
                return error({line, r.column, 0}, "empty register in list");
            }
            reg({line, r.column, static_cast<int>(r.text.size())}, r.text, false);
        }
    }

    void memberRef(const Word& op, int line, bool method) {
        const std::string_view t = op.text;
        const Pos whole{line, op.column, static_cast<int>(t.size())};
        const size_t arrow = t.find("->");
        if (arrow == std::string_view::npos || arrow == 0)
            return error(whole, std::string("expected a ") + (method ? "method" : "field") + " reference");
        const std::string_view owner = t.substr(0, arrow);
        std::vector<std::pair<size_t, std::string>> cls;
        if (!wholeType(owner, &cls) || (owner[0] != 'L' && owner[0] != '['))
            return error(whole, "malformed reference owner " + std::string(owner));
        const std::string_view rest = t.substr(arrow + 2);
        const size_t ownerTypes = cls.size();  // 0 for a primitive array owner
        std::string name, sig;
        if (method) {
            const size_t paren = rest.find('(');
            size_t i = paren;
            if (paren == std::string_view::npos || paren == 0 || !parseProto(rest, i, &cls, nullptr) || i != rest.size())
                return error(whole, "malformed method reference " + std::string(t));
            name = std::string(rest.substr(0, paren));
            sig = std::string(rest.substr(paren));
            // Offsets of signature types are relative to `rest`.
            for (size_t k = ownerTypes; k < cls.size(); ++k) cls[k].first += arrow + 2;
        } else {
            const size_t colon = rest.find(':');
            std::vector<std::pair<size_t, std::string>> ftype;
            if (colon == std::string_view::npos || colon == 0 || !wholeType(rest.substr(colon + 1), &ftype))
                return error(whole, "malformed field reference " + std::string(t));
            for (auto& f : ftype) cls.emplace_back(f.first + arrow + 2 + colon + 1, f.second);
            name = std::string(rest.substr(0, colon));
            sig = std::string(rest.substr(colon + 1));
        }
        typeUses(cls, line, op.column);
        if (owner[0] == 'L')  // members of array types (clone, length) are not looked up
            out_.members.push_back({index_, whole, std::string(owner), std::move(name), std::move(sig), method});
    }

    void instruction(int n, const std::vector<Word>& w, std::string_view code, int col0) {
        const std::string_view op = w[0].text;
        const Pos at{n, w[0].column, static_cast<int>(op.size())};
        if (!method_.active) return error(at, "instruction outside a method");
        const auto it = opcodes().find(std::string(op));
        if (it == opcodes().end()) return error(at, "unknown instruction " + std::string(op));
        if (!method_.hasInsn) {
            method_.hasInsn = true;
            method_.firstInsn = at;
        }
        const std::string& spec = it->second;
        const size_t opEnd = static_cast<size_t>(w[0].column - col0) + op.size();
        std::vector<Word> ops = operands(code.substr(opEnd), col0 + static_cast<int>(opEnd));
        if (!spec.empty() && spec.back() == 'c' && ops.size() > spec.size()) ops.resize(spec.size());  // opaque tail
        if (ops.size() != spec.size() || std::any_of(ops.begin(), ops.end(), [](const Word& o) { return o.text.empty(); }))
            return error(at, std::string(op) + " takes " + std::to_string(spec.size()) + " operand(s)");
        for (size_t k = 0; k < spec.size(); ++k) {
            const Word& o = ops[k];
            const Pos p{n, o.column, static_cast<int>(o.text.size())};
            switch (spec[k]) {
                case 'r': reg(p, o.text, false); break;
                case 'R': reg(p, o.text, true); break;
                case 'l': regList(o, n); break;
                case 't': {
                    std::vector<std::pair<size_t, std::string>> cls;
                    if (!wholeType(o.text, &cls) || (o.text[0] != 'L' && o.text[0] != '['))
                        error(p, "expected a type, found " + std::string(o.text));
                    else typeUses(cls, n, o.column);
                    break;
                }
                case 'f': memberRef(o, n, false); break;
                case 'm': memberRef(o, n, true); break;
                case 's':
                    if (o.text.size() < 2 || o.text.front() != '"' || o.text.back() != '"') error(p, "expected a string literal");
                    break;
                case 'b':
                    if (o.text.size() < 2 || o.text[0] != ':') error(p, "expected a label");
                    break;
                case 'i': {
                    const char c = o.text[0];
                    const bool ok = std::isdigit(static_cast<unsigned char>(c)) || c == '-' || c == '+' || c == '\'' ||
                                    o.text.rfind("Infinity", 0) == 0 || o.text.rfind("NaN", 0) == 0 ||
                                    o.text == "true" || o.text == "false";
                    if (!ok || o.text.find_first_of(" \t") != std::string_view::npos) error(p, "expected a literal");
                    break;
                }
                default: break;  // 'c': not checked
            }
        }
    }

    size_t index_;
    const SourceFile& file_;
    Collected& out_;
    bool sawClass_ = false;
    bool missingClassReported_ = false;
    std::string className_;
    Method method_;
    std::string skipEnd_;
    int skipLine_ = 0;
};

// ---------------------------------------------------------------------------
// Resolution: the edited files layered over the universe
// ---------------------------------------------------------------------------

class Combined {
public:
    Combined(const std::map<std::string, ClassModel>& edited, const ClassUniverse& u) : edited_(edited), u_(u) {}

    Lookup cls(const std::string& d) const { return edited_.count(d) ? Lookup::Found : u_.findClass(d); }

    Lookup member(const std::string& owner, const std::string& name, const std::string& sig, bool method, int depth = 0) const {
        if (depth > 32) return Lookup::Unknown;
        const auto it = edited_.find(owner);
        if (it == edited_.end()) return method ? u_.findMethod(owner, name, sig) : u_.findField(owner, name, sig);
        const ClassModel& m = it->second;
        if ((method ? m.methods : m.fields).count(method ? name + sig : name + ":" + sig)) return Lookup::Found;
        Lookup result = Lookup::Missing;
        std::vector<std::string> parents = m.interfaces;
        if (!m.super.empty()) parents.insert(parents.begin(), m.super);
        for (const auto& p : parents) {
            const Lookup r = member(p, name, sig, method, depth + 1);
            if (r == Lookup::Found) return r;
            if (r == Lookup::Unknown) result = Lookup::Unknown;
        }
        return result;
    }

private:
    const std::map<std::string, ClassModel>& edited_;
    const ClassUniverse& u_;
};

}  // namespace

ValidationResult validate(std::span<const SourceFile> files, const ClassUniverse& universe) {
    Collected c;
    for (size_t i = 0; i < files.size(); ++i) FileParser(i, files[i], c).run();

    const Combined world(c.edited, universe);
    for (const TypeUse& t : c.types)
        if (world.cls(t.desc) == Lookup::Missing)
            c.diags.push_back({files[t.file].path, t.pos.line, t.pos.column, t.pos.length, Severity::Warning, Check::UnresolvedType,
                               "unresolved type " + t.desc});
    for (const MemberUse& m : c.members) {
        if (world.cls(m.owner) != Lookup::Found) continue;  // the owner is reported (or unknown) already
        if (world.member(m.owner, m.name, m.sig, m.method) != Lookup::Missing) continue;
        const std::string ref = m.owner + "->" + m.name + (m.method ? m.sig : ":" + m.sig);
        c.diags.push_back({files[m.file].path, m.pos.line, m.pos.column, m.pos.length, Severity::Warning,
                           m.method ? Check::UnresolvedMethod : Check::UnresolvedField,
                           std::string(m.method ? "unresolved method " : "unresolved field ") + ref});
    }

    ValidationResult r;
    for (auto& d : c.diags) (d.severity == Severity::Error ? r.errors : r.warnings).push_back(std::move(d));
    const auto order = [](const Diagnostic& a, const Diagnostic& b) {
        return std::tie(a.file, a.line, a.column) < std::tie(b.file, b.line, b.column);
    };
    std::stable_sort(r.errors.begin(), r.errors.end(), order);
    std::stable_sort(r.warnings.begin(), r.warnings.end(), order);
    return r;
}

ValidationResult validate(const SourceFile& file, const ClassUniverse& universe) {
    return validate(std::span<const SourceFile>(&file, 1), universe);
}

// ---------------------------------------------------------------------------
// DexUniverse
// ---------------------------------------------------------------------------

namespace {

// Ljava/lang/Object; is modelled exactly (see Validate.hpp): its members are
// fixed by the JLS. No other platform class gets this treatment.
constexpr std::string_view kObject = "Ljava/lang/Object;";

bool objectHasMethod(std::string_view name, std::string_view proto) {
    static const std::set<std::string, std::less<>> members = {
        "<init>()V",           "equals(Ljava/lang/Object;)Z",  "hashCode()I", "toString()Ljava/lang/String;",
        "getClass()Ljava/lang/Class;", "notify()V", "notifyAll()V", "wait()V", "wait(J)V", "wait(JI)V",
        "clone()Ljava/lang/Object;",   "finalize()V"};
    return members.count(std::string(name) + std::string(proto)) != 0;
}

}  // namespace

struct DexUniverse::Impl {
    std::vector<std::shared_ptr<const DexFile>> dexes;
    std::vector<std::string> prefixes;

    bool platform(std::string_view d) const {
        return std::any_of(prefixes.begin(), prefixes.end(), [&](const std::string& p) { return d.rfind(p, 0) == 0; });
    }

    const DexFile::ClassDef* find(std::string_view d, const DexFile*& dex) const {
        for (const auto& x : dexes) {
            const uint32_t idx = x->findClassDef(d);
            if (idx != DexFile::kNoIndex) {
                dex = x.get();
                return &x->classes()[idx];
            }
        }
        return nullptr;
    }

    Lookup member(std::string_view owner, std::string_view name, std::string_view sig, bool method, int depth) const {
        if (depth > 32) return Lookup::Unknown;
        const DexFile* dex = nullptr;
        const DexFile::ClassDef* def = find(owner, dex);
        if (!def && owner == kObject)  // the chain's root: decided exactly (Object has no fields)
            return method && objectHasMethod(name, sig) ? Lookup::Found : Lookup::Missing;
        if (!def) return platform(owner) ? Lookup::Unknown : Lookup::Missing;
        DexFile::ClassData data;
        if (dex->classData(*def, data)) {  // the class's own members (method ids also list mere references)
            if (method) {
                for (const auto& m : data.methods)
                    if (dex->methodName(m.methodIdx) == name && dex->protoDescriptor(dex->methodProto(m.methodIdx)) == sig)
                        return Lookup::Found;
            } else {
                for (const auto& f : data.fields)
                    if (dex->fieldName(f.fieldIdx) == name && dex->typeDescriptor(dex->fieldType(f.fieldIdx)) == sig)
                        return Lookup::Found;
            }
        }
        Lookup result = Lookup::Missing;
        std::vector<std::string> parents;
        if (def->superclassIdx != DexFile::kNoIndex) parents.emplace_back(dex->typeDescriptor(def->superclassIdx));
        for (uint32_t t : dex->interfaces(*def)) parents.emplace_back(dex->typeDescriptor(t));
        for (const auto& p : parents) {
            const Lookup r = member(p, name, sig, method, depth + 1);
            if (r == Lookup::Found) return r;
            if (r == Lookup::Unknown) result = Lookup::Unknown;
        }
        return result;
    }
};

DexUniverse::DexUniverse(std::vector<std::shared_ptr<const DexFile>> dexes, std::vector<std::string> platformPrefixes)
    : impl_(std::make_unique<Impl>()) {
    impl_->dexes = std::move(dexes);
    impl_->prefixes = std::move(platformPrefixes);
}

DexUniverse::~DexUniverse() = default;

ClassUniverse::Lookup DexUniverse::findClass(std::string_view descriptor) const {
    const DexFile* dex = nullptr;
    if (impl_->find(descriptor, dex) || descriptor == kObject) return Lookup::Found;
    return impl_->platform(descriptor) ? Lookup::Unknown : Lookup::Missing;
}

ClassUniverse::Lookup DexUniverse::findMethod(std::string_view owner, std::string_view name, std::string_view proto) const {
    return impl_->member(owner, name, proto, true, 0);
}

ClassUniverse::Lookup DexUniverse::findField(std::string_view owner, std::string_view name, std::string_view type) const {
    return impl_->member(owner, name, type, false, 0);
}

std::vector<std::string> DexUniverse::defaultPlatformPrefixes() {
    return {"Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/", "Lorg/apache/http/",
            "Lsun/", "Llibcore/", "Lcom/android/internal/"};
}

}  // namespace smali
