#include "analysis/SourceMap.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include "analysis/Dalvik.hpp"

namespace sourcemap {
namespace {

bool isIdentStart(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '$'; }
bool isIdentChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$'; }

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

// "java.util.List<Foo>" -> "List", "int[]" -> "int[]", "String..." -> "String[]".
std::string simpleType(std::string_view t) {
    t = trim(t);
    std::string out;
    int depth = 0;
    for (char c : t) {
        if (c == '<') ++depth;
        else if (c == '>') --depth;
        else if (depth == 0) out += c;
    }
    std::string dims;
    for (size_t p; (p = out.find("[]")) != std::string::npos;) {
        dims += "[]";
        out.erase(p, 2);
    }
    if (const size_t p = out.find("..."); p != std::string::npos) {
        dims += "[]";
        out.erase(p, 3);
    }
    out = std::string(trim(out));
    const size_t dot = out.find_last_of(".$");
    if (dot != std::string::npos) out = out.substr(dot + 1);
    return out + dims;
}

bool isKeyword(std::string_view w) {
    static constexpr std::string_view kWords[] = {"if", "for", "while", "switch", "catch", "synchronized", "return", "throw",
                                                  "new", "else", "do", "try", "finally", "case", "instanceof", "assert"};
    return std::find(std::begin(kWords), std::end(kWords), w) != std::end(kWords);
}

// Undoes Java string escapes (enough for matching dex constants).
std::string unescape(std::string_view s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) {
            out += s[i];
            continue;
        }
        const char e = s[++i];
        switch (e) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case '0': out += '\0'; break;
        case 'u':
            if (i + 4 < s.size()) {
                const unsigned code = static_cast<unsigned>(std::strtoul(std::string(s.substr(i + 1, 4)).c_str(), nullptr, 16));
                if (code < 0x80) out += static_cast<char>(code);
                else if (code < 0x800) out += static_cast<char>(0xC0 | (code >> 6)), out += static_cast<char>(0x80 | (code & 0x3F));
                else out += static_cast<char>(0xE0 | (code >> 12)), out += static_cast<char>(0x80 | ((code >> 6) & 0x3F)), out += static_cast<char>(0x80 | (code & 0x3F));
                i += 4;
            }
            break;
        default: out += e; break;
        }
    }
    return out;
}

// One line with comments removed and string / char literals blanked out
// (same length, so columns stay valid); the literals are kept apart.
struct LexedLine {
    std::string code;
    std::vector<std::pair<size_t, std::string>> strings;  // column, unescaped contents
};

LexedLine lex(std::string_view line, bool& inComment) {
    LexedLine out;
    out.code.assign(line.size(), ' ');
    for (size_t i = 0; i < line.size(); ++i) {
        if (inComment) {
            if (line[i] == '*' && i + 1 < line.size() && line[i + 1] == '/') inComment = false, ++i;
            continue;
        }
        if (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/') break;
        if (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '*') {
            inComment = true;
            ++i;
            continue;
        }
        if (line[i] == '"' || line[i] == '\'') {
            const char q = line[i];
            const size_t start = i;
            std::string raw;
            for (++i; i < line.size() && line[i] != q; ++i) {
                if (line[i] == '\\' && i + 1 < line.size()) raw += line[i++];
                raw += line[i];
            }
            if (q == '"') out.strings.emplace_back(start, unescape(raw));
            out.code[start] = q;  // keep a marker so `foo("x")` still reads as a call
            continue;
        }
        out.code[i] = line[i];
    }
    return out;
}

// What a line or an instruction does, in order: "M:name" call, "C:Type"
// object creation, "C*" this(...) / super(...), "S:text" string, "F:name" field.
// `fields`: names of the fields the method's bytecode accesses, so an
// unqualified `count` reads as a field access only when it is one.
std::vector<std::string> javaFeatures(const LexedLine& l, const std::vector<std::string>& fields) {
    // Ordered by when they are evaluated: a call completes at its closing
    // parenthesis, after its arguments (`a.equals(new B())`: B() first).
    std::vector<std::pair<size_t, std::string>> out;
    const std::string& c = l.code;
    const auto nextNonSpace = [&](size_t i) {
        while (i < c.size() && c[i] == ' ') ++i;
        return i < c.size() ? c[i] : '\0';
    };
    const auto callEnd = [&](size_t from) {  // matching ')' of the first '(' at or after `from`
        size_t p = c.find('(', from);
        if (p == std::string::npos) return c.size() + from;
        int depth = 0;
        for (; p < c.size(); ++p) {
            if (c[p] == '(') ++depth;
            else if (c[p] == ')' && --depth == 0) return p;
        }
        return c.size() + from;  // continues on the next line
    };
    for (size_t i = 0; i < c.size();) {
        if (!isIdentStart(c[i]) || (i > 0 && isIdentChar(c[i - 1]))) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < c.size() && isIdentChar(c[j])) ++j;
        const std::string word = c.substr(i, j - i);
        size_t k = i;
        while (k > 0 && c[k - 1] == ' ') --k;
        const char prev = k > 0 ? c[k - 1] : '\0';
        const char next = nextNonSpace(j);
        if (word == "new") {
            // new a.b.Type<...>(  -> the last identifier before '(' (arrays: no constructor).
            size_t p = j;
            std::string type;
            while (p < c.size()) {
                while (p < c.size() && c[p] == ' ') ++p;
                if (p >= c.size() || !isIdentStart(c[p])) break;
                size_t q = p;
                while (q < c.size() && isIdentChar(c[q])) ++q;
                type = c.substr(p, q - p);
                p = q;
                if (p < c.size() && c[p] == '<') {  // generics
                    int depth = 0;
                    for (; p < c.size(); ++p) {
                        if (c[p] == '<') ++depth;
                        else if (c[p] == '>' && --depth == 0) {
                            ++p;
                            break;
                        }
                    }
                }
                if (p < c.size() && c[p] == '.') ++p;
                else break;
            }
            while (p < c.size() && c[p] == ' ') ++p;
            if (!type.empty() && p < c.size() && c[p] == '(') out.emplace_back(callEnd(p), "C:" + type);
            i = p;
            continue;
        }
        if (word == "if" || word == "while" || word == "for") {
            out.emplace_back(callEnd(j), "K:if");  // the branch comes after the condition is evaluated
        } else if (word == "return" || word == "throw") {
            out.emplace_back(c.size() + 1, "K:" + word);  // after the returned / thrown expression
        } else if (word == "switch") {
            out.emplace_back(callEnd(j), "K:switch");
        } else if (next == '(' && !isKeyword(word)) {
            if ((word == "super" || word == "this") && prev != '.') out.emplace_back(callEnd(j), "C*");
            else out.emplace_back(callEnd(j), "M:" + word);
        } else if (prev == '.' && next != '.' && next != '(' && word != "class" && word != "length") {
            out.emplace_back(i, "F:" + word);
        } else if (prev != '.' && next != '(' && std::find(fields.begin(), fields.end(), word) != fields.end()) {
            out.emplace_back(i, "F:" + word);  // unqualified field
        }
        i = j;
    }
    for (const auto& [col, s] : l.strings) out.emplace_back(col, "S:" + s);
    std::stable_sort(out.begin(), out.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    std::vector<std::string> features;
    for (auto& f : out) features.push_back(std::move(f.second));
    return features;
}

std::string simpleClass(std::string_view descriptor) {
    if (descriptor.size() >= 2 && descriptor.front() == 'L' && descriptor.back() == ';') descriptor = descriptor.substr(1, descriptor.size() - 2);
    const size_t cut = descriptor.find_last_of("/$");
    return std::string(cut == std::string_view::npos ? descriptor : descriptor.substr(cut + 1));
}

struct Insn {
    uint32_t pc;
    std::string feature;  // "" when the instruction matches nothing on the Java side
};

std::vector<Insn> instructions(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    std::vector<Insn> out;
    const DexFile& dex = *a.dexes()[m.dex];
    DexFile::CodeItem code;
    if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) return out;
    for (uint32_t pc = 0; pc < code.insnsSize;) {
        const dalvik::Insn in = dalvik::decode(code, pc);
        pc += std::max<uint32_t>(in.size, 1);
        if (!in.valid || in.payload) continue;
        const dalvik::OpInfo& info = dalvik::opInfo(in.opcode);
        std::string f;
        if (info.flow == dalvik::Flow::Branch) f = "K:if";
        else if (info.flow == dalvik::Flow::Return) f = "K:return";
        else if (info.flow == dalvik::Flow::Throw) f = "K:throw";
        else if (info.flow == dalvik::Flow::Switch) f = "K:switch";
        else if (in.index != DexFile::kNoIndex) {
            if (info.ref == dalvik::RefKind::Method && info.flow == dalvik::Flow::Invoke) {
                const std::string_view name = dex.methodName(in.index);
                f = name == "<init>" ? "C:" + simpleClass(dex.typeDescriptor(dex.methodClass(in.index))) : "M:" + std::string(name);
            } else if (info.ref == dalvik::RefKind::String) {
                f = "S:" + dex.string(in.index);
            } else if (info.ref == dalvik::RefKind::Field) {
                f = "F:" + std::string(dex.fieldName(in.index));
            }
        }
        out.push_back({in.pc, std::move(f)});
    }
    return out;
}

bool featureEquals(const std::string& java, const std::string& insn) {
    if (java == insn) return true;
    return java == "C*" && insn.rfind("C:", 0) == 0;  // this(...) / super(...): any constructor call
}

// Body lines of a method that belong to it (not to nested classes or lambdas).
std::vector<int> ownLines(const JavaMethod& m, const std::vector<std::pair<int, int>>& nested) {
    std::vector<int> lines;
    for (int l = m.declLine; l <= m.bodyEnd; ++l) {
        const bool inside = std::any_of(nested.begin(), nested.end(), [&](const auto& r) {
            return r.first > m.declLine && l >= r.first && l <= r.second && !(r.first <= m.declLine && r.second >= m.bodyEnd);
        });
        if (!inside) lines.push_back(l);
    }
    return lines;
}

// Java line of each instruction (index-aligned with `insns`), -1 when unknown.
std::vector<int> alignLines(const std::vector<int>& javaLines, const std::vector<std::vector<std::string>>& javaFeatures,
                            const std::vector<Insn>& insns) {
    std::vector<int> owner(insns.size(), -1);
    struct J {
        int line;
        const std::string* f;
    };
    std::vector<J> js;
    for (size_t i = 0; i < javaLines.size(); ++i)
        for (const std::string& f : javaFeatures[i]) js.push_back({javaLines[i], &f});
    std::vector<size_t> is;  // instructions with a feature
    for (size_t i = 0; i < insns.size(); ++i)
        if (!insns[i].feature.empty()) is.push_back(i);
    if (js.empty() || is.empty()) return owner;
    const size_t n = js.size(), m = is.size();
    std::vector<std::pair<size_t, size_t>> matches;  // (j index, insn index)
    if (n * m <= 4'000'000) {
        // Longest common subsequence: repeated calls map to the right occurrence.
        std::vector<std::vector<uint16_t>> dp(n + 1, std::vector<uint16_t>(m + 1, 0));
        for (size_t x = n; x-- > 0;)
            for (size_t y = m; y-- > 0;)
                dp[x][y] = featureEquals(*js[x].f, insns[is[y]].feature) ? static_cast<uint16_t>(dp[x + 1][y + 1] + 1)
                                                                           : std::max(dp[x + 1][y], dp[x][y + 1]);
        for (size_t x = 0, y = 0; x < n && y < m;) {
            if (featureEquals(*js[x].f, insns[is[y]].feature)) matches.emplace_back(x++, is[y++]);
            else if (dp[x + 1][y] >= dp[x][y + 1]) ++x;
            else ++y;
        }
    } else {
        // Too large for the table: greedy in-order matching.
        size_t y = 0;
        for (size_t x = 0; x < n && y < m; ++x)
            for (size_t t = y; t < m; ++t)
                if (featureEquals(*js[x].f, insns[is[t]].feature)) {
                    matches.emplace_back(x, is[t]);
                    y = t + 1;
                    break;
                }
    }
    // A matched instruction belongs to its line; the unmatched ones before it
    // (moves, constants, new-instance) are that statement's setup.
    size_t prev = 0;
    for (const auto& [x, insn] : matches) {
        for (size_t k = prev; k <= insn; ++k) owner[k] = js[x].line;
        prev = insn + 1;
    }
    return owner;
}

std::vector<int> debugAlign(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const JavaFile& file, const std::vector<int>& javaLines,
                            const std::vector<Insn>& insns, bool& any) {
    std::vector<int> owner(insns.size(), -1);
    any = false;
    const DexFile& dex = *a.dexes()[m.dex];
    DexFile::CodeItem code;
    if (!dex.codeItem(m.method.codeOff, code)) return owner;
    std::map<int, int> javaForSource;  // source line -> Java line
    for (int l : javaLines)
        if (const int d = file.debugLine(l); d >= 0 && !javaForSource.count(d)) javaForSource[d] = l;
    if (javaForSource.empty()) return owner;
    for (size_t i = 0; i < insns.size(); ++i) {
        const int src = dex.lineForPc(code, insns[i].pc);
        auto it = javaForSource.find(src);
        if (it != javaForSource.end()) {
            owner[i] = it->second;
            any = true;
        }
    }
    return owner;
}

}  // namespace

// --- JavaFile ----------------------------------------------------------------

namespace {
enum class Scope { Class, Method, Lambda, Other };
struct Frame {
    Scope kind;
    std::string cls;   // Class: binary name
    int method = -1;   // Method: index into methods_
    int start = 0;
    int anonCount = 0; // Class: anonymous classes numbered so far
};
}  // namespace

JavaFile::JavaFile(const std::vector<std::string_view>& lines) : lines_(lines.begin(), lines.end()) {
    const auto inMethodScope = [](const std::vector<Frame>& frames) {
        return std::any_of(frames.begin(), frames.end(), [](const Frame& f) { return f.kind == Scope::Method || f.kind == Scope::Lambda; });
    };
    std::vector<Frame> stack;
    std::string header;
    int headerLine = -1;
    bool inComment = false;
    std::vector<std::pair<int, int>> nestedRanges;  // filled for methods' lambdas / anonymous bodies
    for (int ln = 0; ln < static_cast<int>(lines_.size()); ++ln) {
        const std::string_view raw = lines_[static_cast<size_t>(ln)];
        // jadx --add-debug-lines: "/* 42 */ statement"
        const std::string_view t = trim(raw);
        if (t.size() > 5 && t.substr(0, 3) == "/* " && std::isdigit(static_cast<unsigned char>(t[3]))) debugLines_ = true;
        const LexedLine lexed = lex(raw, inComment);
        const std::string& code = lexed.code;
        if (package_.empty()) {
            const std::string_view c = trim(code);
            if (c.substr(0, 8) == "package ") package_ = std::string(trim(c.substr(8, c.find(';') - 8)));
        }
        for (size_t i = 0; i < code.size(); ++i) {
            const char ch = code[i];
            if (ch == '{') {
                std::string h(trim(header));
                // Leading annotations: @Override, @SuppressLint("x")
                while (!h.empty() && h[0] == '@') {
                    size_t p = 1;
                    while (p < h.size() && (isIdentChar(h[p]) || h[p] == '.')) ++p;
                    if (p < h.size() && h[p] == '(') {
                        int depth = 0;
                        for (; p < h.size(); ++p) {
                            if (h[p] == '(') ++depth;
                            else if (h[p] == ')' && --depth == 0) {
                                ++p;
                                break;
                            }
                        }
                    }
                    h = std::string(trim(std::string_view(h).substr(std::min(p, h.size()))));
                }
                Frame f{Scope::Other, {}, -1, headerLine >= 0 ? headerLine : ln, 0};
                const Frame* cls = nullptr;
                for (auto it = stack.rbegin(); it != stack.rend(); ++it)
                    if (it->kind == Scope::Class) {
                        cls = &*it;
                        break;
                    }
                const bool inMethod = std::any_of(stack.begin(), stack.end(), [](const Frame& x) { return x.kind == Scope::Method || x.kind == Scope::Lambda; });
                // class / interface / enum / record declaration?
                std::string declared;
                for (const char* kw : {"class ", "interface ", "enum ", "record "}) {
                    const size_t p = (" " + h).find(std::string(" ") + kw);
                    if (p == std::string::npos) continue;
                    size_t q = p + std::string(kw).size();
                    while (q < h.size() && h[q] == ' ') ++q;
                    size_t e = q;
                    while (e < h.size() && isIdentChar(h[e])) ++e;
                    declared = h.substr(q, e - q);
                    break;
                }
                const bool endsCall = !h.empty() && h.back() == ')';
                // `new Type<..>(args) {`: the creation must end exactly at the brace
                // (`if (a.equals(new B())) {` is a block, not an anonymous class).
                const auto anonymousCreation = [&]() {
                    const size_t at = h.rfind("new ");
                    if (at == std::string::npos || (at > 0 && isIdentChar(h[at - 1]))) return false;
                    size_t p = at + 4;
                    while (p < h.size() && (isIdentChar(h[p]) || h[p] == '.' || h[p] == ' ' || h[p] == '<' || h[p] == '>' || h[p] == ',' || h[p] == '?'))
                        ++p;
                    if (p >= h.size() || h[p] != '(') return false;
                    int depth = 0;
                    for (size_t q = p; q < h.size(); ++q) {
                        if (h[q] == '(') ++depth;
                        else if (h[q] == ')' && --depth == 0) return q == h.size() - 1;
                    }
                    return false;
                };
                if (!declared.empty() && h.find('(') > h.find(declared)) {
                    f.kind = Scope::Class;
                    f.cls = cls ? cls->cls + "$" + declared : (package_.empty() ? declared : package_ + "." + declared);
                } else if (h.size() >= 2 && h.compare(h.size() - 2, 2, "->") == 0) {
                    f.kind = Scope::Lambda;
                } else if (inMethod && endsCall && cls && anonymousCreation()) {
                    // Anonymous class: numbered per enclosing class, like javac.
                    Frame* owner = nullptr;
                    for (auto it = stack.rbegin(); it != stack.rend(); ++it)
                        if (it->kind == Scope::Class) {
                            owner = &*it;
                            break;
                        }
                    f.kind = Scope::Class;
                    f.cls = owner->cls + "$" + std::to_string(++owner->anonCount);
                } else if (!stack.empty() && stack.back().kind == Scope::Class && (endsCall || h.find(") throws ") != std::string::npos)) {
                    const size_t open = h.find('(');
                    std::string before = std::string(trim(std::string_view(h).substr(0, open)));
                    size_t e = before.size();
                    size_t s = e;
                    while (s > 0 && isIdentChar(before[s - 1])) --s;
                    std::string name = before.substr(s, e - s);
                    if (!name.empty() && open != std::string::npos) {
                        JavaMethod m;
                        m.cls = stack.back().cls;
                        const std::string simple = m.cls.substr(m.cls.find_last_of(".$") == std::string::npos ? 0 : m.cls.find_last_of(".$") + 1);
                        m.name = name == simple ? "<init>" : name;
                        // Parameters between the parentheses (depth 0 commas).
                        int depth = 0;
                        size_t close = open;
                        for (size_t p = open; p < h.size(); ++p) {
                            if (h[p] == '(') ++depth;
                            else if (h[p] == ')' && --depth == 0) {
                                close = p;
                                break;
                            }
                        }
                        const std::string params = h.substr(open + 1, close - open - 1);
                        int angle = 0;
                        size_t from = 0;
                        for (size_t p = 0; p <= params.size(); ++p) {
                            if (p < params.size() && params[p] == '<') ++angle;
                            if (p < params.size() && params[p] == '>') --angle;
                            if (p == params.size() || (params[p] == ',' && angle == 0)) {
                                std::string_view one = trim(std::string_view(params).substr(from, p - from));
                                from = p + 1;
                                while (!one.empty() && one[0] == '@') {  // parameter annotations
                                    const size_t sp = one.find(' ');
                                    one = sp == std::string_view::npos ? std::string_view() : trim(one.substr(sp));
                                }
                                if (one.substr(0, 6) == "final ") one = trim(one.substr(6));
                                if (one.empty()) continue;
                                size_t ns = one.size();
                                while (ns > 0 && isIdentChar(one[ns - 1])) --ns;
                                m.params.push_back(simpleType(one.substr(0, ns)));
                            }
                        }
                        m.declLine = f.start;
                        m.bodyStart = ln;
                        f.kind = Scope::Method;
                        f.method = static_cast<int>(methods_.size());
                        methods_.push_back(std::move(m));
                    }
                } else if (!stack.empty() && stack.back().kind == Scope::Class && trim(h) == "static") {
                    JavaMethod m;
                    m.cls = stack.back().cls;
                    m.name = "<clinit>";
                    m.declLine = f.start;
                    m.bodyStart = ln;
                    f.kind = Scope::Method;
                    f.method = static_cast<int>(methods_.size());
                    methods_.push_back(std::move(m));
                }
                stack.push_back(std::move(f));
                header.clear();
                headerLine = -1;
            } else if (ch == '}') {
                if (!stack.empty()) {
                    const Frame f = stack.back();
                    stack.pop_back();
                    if (f.kind == Scope::Method) methods_[static_cast<size_t>(f.method)].bodyEnd = ln;
                    if (f.kind == Scope::Lambda) lambdas_.push_back({f.start, ln});
                    if (f.kind == Scope::Class && inMethodScope(stack)) anonymous_.push_back({f.start, ln});
                }
                header.clear();
                headerLine = -1;
            } else if (ch == ';') {
                header.clear();
                headerLine = -1;
            } else {
                if (headerLine < 0 && ch != ' ') headerLine = ln;
                header += ch;
            }
        }
        header += ' ';
    }
    for (JavaMethod& m : methods_)
        if (m.bodyEnd < 0) m.bodyEnd = static_cast<int>(lines_.size()) - 1;
}

const JavaMethod* JavaFile::methodAt(int line) const {
    const JavaMethod* best = nullptr;
    for (const JavaMethod& m : methods_)
        if (line >= m.declLine && line <= m.bodyEnd && (!best || m.declLine >= best->declLine)) best = &m;
    return best;
}

int JavaFile::findMethod(std::string_view cls, std::string_view name, const std::vector<std::string>& params) const {
    int best = -1, bestScore = -1;
    for (const JavaMethod& m : methods_) {
        if (m.cls != cls || m.name != name || m.params.size() != params.size()) continue;
        int score = 0;
        for (size_t i = 0; i < params.size(); ++i) score += m.params[i] == params[i] ? 1 : 0;
        if (score > bestScore) best = m.declLine, bestScore = score;
    }
    return best;
}

int JavaFile::debugLine(int line) const {
    if (line < 0 || line >= static_cast<int>(lines_.size())) return -1;
    const std::string_view t = trim(lines_[static_cast<size_t>(line)]);
    if (t.size() < 6 || t.substr(0, 3) != "/* ") return -1;
    size_t p = 3;
    int v = 0;
    while (p < t.size() && std::isdigit(static_cast<unsigned char>(t[p]))) v = v * 10 + (t[p++] - '0');
    return p > 3 && t.substr(p, 3) == " */" ? v : -1;
}

std::vector<std::string> paramSimpleTypes(std::string_view proto) {
    std::vector<std::string> out;
    size_t i = proto.find('(');
    const size_t close = proto.find(')');
    if (i == std::string_view::npos || close == std::string_view::npos) return out;
    for (++i; i < close;) {
        size_t j = i;
        while (j < close && proto[j] == '[') ++j;
        if (j < close && proto[j] == 'L') j = proto.find(';', j);
        if (j == std::string_view::npos || j >= close) break;
        const std::string_view t = proto.substr(i, j - i + 1);
        const size_t dims = t.find_first_not_of('[');
        std::string name;
        switch (t[dims]) {
        case 'Z': name = "boolean"; break;
        case 'B': name = "byte"; break;
        case 'S': name = "short"; break;
        case 'C': name = "char"; break;
        case 'I': name = "int"; break;
        case 'J': name = "long"; break;
        case 'F': name = "float"; break;
        case 'D': name = "double"; break;
        default: name = simpleClass(t.substr(dims)); break;
        }
        for (size_t k = 0; k < dims; ++k) name += "[]";
        out.push_back(std::move(name));
        i = j + 1;
    }
    return out;
}

bool resolve(const ApkAnalysis& a, const JavaMethod& m, ApkAnalysis::MethodDef& out) {
    const auto defs = a.findMethodDefs(m.cls, m.name);
    int bestScore = -1;
    for (const ApkAnalysis::MethodDef& d : defs) {
        const DexFile& dex = *a.dexes()[d.dex];
        const std::vector<std::string> params = paramSimpleTypes(dex.protoDescriptor(dex.methodProto(d.method.methodIdx)));
        if (params.size() != m.params.size()) continue;
        int score = 0;
        for (size_t i = 0; i < params.size(); ++i) {
            // A type variable (T, E) is erased to its bound: it matches anything.
            const bool typeVar = m.params[i].size() == 1 && std::isupper(static_cast<unsigned char>(m.params[i][0]));
            score += params[i] == m.params[i] ? 2 : typeVar ? 1 : 0;
        }
        if (score > bestScore) {
            bestScore = score;
            out = d;
        }
    }
    return bestScore >= 0;
}

namespace {

// Lambda bodies of a method, in source order, and the synthetic methods javac / d8 made of them.
std::vector<ApkAnalysis::MethodDef> lambdaMethods(const ApkAnalysis& a, const JavaMethod& m) {
    std::vector<std::pair<int, ApkAnalysis::MethodDef>> found;
    const std::string prefix = "lambda$" + (m.name == "<init>" ? std::string("new") : m.name == "<clinit>" ? std::string("static") : m.name) + "$";
    if (const ApkAnalysis::ClassEntry* c = a.findClass(m.cls))
        for (const ApkAnalysis::MethodDef& d : a.methodsOf(*c)) {
            const std::string_view name = a.dexes()[d.dex]->methodName(d.method.methodIdx);
            if (name.substr(0, prefix.size()) == prefix) found.emplace_back(std::atoi(std::string(name.substr(prefix.size())).c_str()), d);
        }
    std::sort(found.begin(), found.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    std::vector<ApkAnalysis::MethodDef> out;
    for (auto& f : found) out.push_back(f.second);
    return out;
}

// Java line of each instruction of `def`, using the lines `javaLines`.
std::vector<int> mapLines(const ApkAnalysis& a, const ApkAnalysis::MethodDef& def, const JavaFile& file, const std::vector<int>& javaLines,
                          const std::vector<Insn>& insns, bool& exact) {
    exact = false;
    if (file.hasDebugLines()) {
        bool any = false;
        std::vector<int> owner = debugAlign(a, def, file, javaLines, insns, any);
        if (any) {
            exact = true;
            return owner;
        }
    }
    std::vector<std::string> fields;
    for (const Insn& in : insns)
        if (in.feature.rfind("F:", 0) == 0 && std::find(fields.begin(), fields.end(), in.feature.substr(2)) == fields.end())
            fields.push_back(in.feature.substr(2));
    bool inComment = false;
    std::vector<std::vector<std::string>> features;
    for (int l : javaLines) features.push_back(javaFeatures(lex(file.line(l), inComment), fields));
    return alignLines(javaLines, features, insns);
}

}  // namespace

bool javaToBytecode(const ApkAnalysis& a, const JavaFile& file, int line, Target& out) {
    const JavaMethod* m = file.methodAt(line);
    if (!m) return false;
    std::vector<std::pair<int, int>> nested = file.lambdaRanges();
    for (const auto& r : file.anonymousRanges()) nested.push_back(r);
    // Inside a lambda of this method: its synthetic method, k-th lambda <-> k-th lambda$name$N.
    int lambdaIndex = -1, ordinal = 0;
    std::vector<std::pair<int, int>> lambdas;
    for (const auto& r : file.lambdaRanges())
        if (r.first > m->declLine && r.second <= m->bodyEnd) lambdas.push_back(r);
    std::sort(lambdas.begin(), lambdas.end());
    for (const auto& r : lambdas) {
        if (line >= r.first && line <= r.second) lambdaIndex = ordinal;
        ++ordinal;
    }
    ApkAnalysis::MethodDef def;
    std::vector<int> javaLines;
    if (lambdaIndex >= 0) {
        const auto synth = lambdaMethods(a, *m);
        if (lambdaIndex >= static_cast<int>(synth.size())) return false;
        def = synth[static_cast<size_t>(lambdaIndex)];
        const auto& r = lambdas[static_cast<size_t>(lambdaIndex)];
        for (int l = r.first; l <= r.second; ++l) javaLines.push_back(l);
    } else {
        if (!resolve(a, *m, def)) return false;
        javaLines = ownLines(*m, nested);
    }
    const std::vector<Insn> insns = instructions(a, def);
    const std::vector<int> owner = mapLines(a, def, file, javaLines, insns, out.exact);
    out.method = def;
    out.pcs.clear();
    for (size_t i = 0; i < insns.size(); ++i)
        if (owner[i] == line) out.pcs.push_back(insns[i].pc);
    return true;  // the method resolved even when this line has no instruction of its own
}

int bytecodeToJava(const ApkAnalysis& a, const JavaFile& file, const ApkAnalysis::MethodDef& method, uint32_t pc) {
    const DexFile& dex = *a.dexes()[method.dex];
    const uint32_t idx = method.method.methodIdx;
    const std::string cls = DexFile::descriptorToJava(dex.typeDescriptor(dex.methodClass(idx)));
    const std::string name(dex.methodName(idx));
    std::vector<std::pair<int, int>> nested = file.lambdaRanges();
    for (const auto& r : file.anonymousRanges()) nested.push_back(r);
    std::vector<int> javaLines;
    if (name.rfind("lambda$", 0) == 0) {
        // lambda$<method>$N: find the k-th lambda body of that method.
        const size_t dollar = name.find('$', 7);
        const std::string owner = name.substr(7, dollar - 7);
        for (const JavaMethod& m : file.methods()) {
            if (m.cls != cls || (m.name != owner && !(owner == "new" && m.name == "<init>") && !(owner == "static" && m.name == "<clinit>"))) continue;
            const auto synth = lambdaMethods(a, m);
            const auto it = std::find_if(synth.begin(), synth.end(), [&](const ApkAnalysis::MethodDef& d) { return d.method.methodIdx == idx && d.dex == method.dex; });
            if (it == synth.end()) continue;
            std::vector<std::pair<int, int>> lambdas;
            for (const auto& r : file.lambdaRanges())
                if (r.first > m.declLine && r.second <= m.bodyEnd) lambdas.push_back(r);
            std::sort(lambdas.begin(), lambdas.end());
            const size_t k = static_cast<size_t>(it - synth.begin());
            if (k >= lambdas.size()) return -1;
            for (int l = lambdas[k].first; l <= lambdas[k].second; ++l) javaLines.push_back(l);
            break;
        }
    } else {
        const int decl = file.findMethod(cls, name, paramSimpleTypes(dex.protoDescriptor(dex.methodProto(idx))));
        if (decl < 0) return -1;
        const JavaMethod* m = file.methodAt(decl);
        if (!m) return -1;
        javaLines = ownLines(*m, nested);
    }
    if (javaLines.empty()) return -1;
    const std::vector<Insn> insns = instructions(a, method);
    bool exact = false;
    const std::vector<int> owner = mapLines(a, method, file, javaLines, insns, exact);
    // The instruction's own line, else the statement it leads into, else the one before.
    size_t at = 0;
    while (at < insns.size() && insns[at].pc < pc) ++at;
    for (size_t i = at; i < insns.size(); ++i)
        if (owner[i] >= 0) return owner[i];
    for (size_t i = std::min(at, insns.size()); i-- > 0;)
        if (owner[i] >= 0) return owner[i];
    return javaLines.front();
}

}  // namespace sourcemap
