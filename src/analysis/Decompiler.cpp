#include "analysis/Decompiler.hpp"
#include "analysis/Arm32.hpp"
#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include "analysis/Dalvik.hpp"

namespace decompiler {

bool Line::contains(uint64_t a) const { return std::binary_search(addrs.begin(), addrs.end(), a); }

void declareLocals(Output& out, const std::map<std::string, std::vector<std::string>>& seen, bool native);

std::string toText(const Output& out) {
    std::string s;
    for (const Line& l : out.lines) {
        s.append(static_cast<size_t>(std::max(l.indent, 0)) * 4, ' ');
        s += l.text;
        s += '\n';
    }
    return s;
}

namespace {

// ===========================================================================
// Expressions: text with register placeholders
// ===========================================================================
//
// A register reference inside an expression is "\x01<id>,<hint>,<name>\x02".
// Folding a definition into its use replaces the placeholder with the
// definition's expression; whatever is left at the end is rendered as the
// register name. The hint says what the use expects (L object, Z boolean,
// C char) so a folded literal 0 can read as null / false.

constexpr char kOpen = '\x01';
constexpr char kClose = '\x02';
constexpr char kSep = '\x03';  // condition parts: lhs, operator, rhs
constexpr size_t kMaxInline = 160;
constexpr int kMaxDepth = 120;
constexpr size_t kMaxBlocks = 6000;

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%" PRIx64, v);
    return b;
}

std::string signedHex(int64_t v) {
    if (v < 0) return "-" + hex(static_cast<uint64_t>(-(v + 1)) + 1);
    return hex(static_cast<uint64_t>(v));
}

std::string ph(int id, std::string_view name, char hint = '-') {
    std::string s(1, kOpen);
    s += std::to_string(id);
    s += ',';
    s += hint;
    s += ',';
    s += name;
    s += kClose;
    return s;
}

struct PhRef {
    size_t begin = 0, end = 0;
    int id = -1;
    char hint = '-';
    std::string_view name;
};

bool nextPh(std::string_view s, size_t from, PhRef& r) {
    const size_t open = s.find(kOpen, from);
    if (open == std::string_view::npos) return false;
    const size_t close = s.find(kClose, open);
    if (close == std::string_view::npos) return false;
    const std::string_view body = s.substr(open + 1, close - open - 1);
    const size_t c1 = body.find(',');
    if (c1 == std::string_view::npos || c1 + 3 > body.size()) return false;
    r.begin = open;
    r.end = close + 1;
    r.id = 0;
    for (size_t i = 0; i < c1; ++i) r.id = r.id * 10 + (body[i] - '0');
    r.hint = body[c1 + 1];
    r.name = body.substr(c1 + 3);
    return true;
}

int countUses(std::string_view s, int id) {
    int n = 0;
    PhRef r;
    for (size_t at = 0; nextPh(s, at, r); at = r.end)
        if (r.id == id) ++n;
    return n;
}

template <class F>
void forEachUse(std::string_view s, F f) {
    PhRef r;
    for (size_t at = 0; nextPh(s, at, r); at = r.end) f(r.id);
}

std::string nameOf(std::string_view s, int id) {
    PhRef r;
    for (size_t at = 0; nextPh(s, at, r); at = r.end)
        if (r.id == id) return std::string(r.name);
    return "r" + std::to_string(id);
}

bool intLiteral(std::string_view e, int64_t& v) {
    if (e.empty()) return false;
    size_t i = e[0] == '-' ? 1 : 0;
    if (i >= e.size()) return false;
    int64_t x = 0;
    for (; i < e.size(); ++i) {
        if (e[i] < '0' || e[i] > '9') return false;
        x = x * 10 + (e[i] - '0');
    }
    v = e[0] == '-' ? -x : x;
    return true;
}

std::string withHint(const std::string& e, char hint) {
    if (hint == 'L' && e == "0") return "null";
    if (hint == 'Z') {
        if (e == "0") return "false";
        if (e == "1") return "true";
    }
    int64_t v = 0;
    if (hint == 'C' && intLiteral(e, v) && v >= 32 && v < 127) {
        const char c = static_cast<char>(v);
        if (c == '\'' || c == '\\') return std::string("'\\") + c + "'";
        return std::string("'") + c + "'";
    }
    return e;
}

// Whether an operand standing between `before` and `after` can go without
// parentheses: a whole argument, index, initializer or assigned value.
bool delimited(const std::string& before, std::string_view after) {
    bool open = before.empty();
    if (!open) {
        const char c = before.back();
        const size_t n = before.size();
        open = c == '(' || c == '[' || c == '{' || (n >= 2 && before.compare(n - 2, 2, ", ") == 0) ||
               (n >= 3 && before.compare(n - 2, 2, "= ") == 0 && before[n - 3] == ' ');
    }
    const bool close = after.empty() || after[0] == ')' || after[0] == ']' || after[0] == '}' || after[0] == ',';
    return open && close;
}

std::string substitute(const std::string& s, int id, const std::string& expr, bool atomic) {
    std::string out;
    PhRef r;
    size_t at = 0;
    while (nextPh(s, at, r)) {
        out.append(s, at, r.begin - at);
        if (r.id == id) {
            const std::string e = withHint(expr, r.hint);
            const bool bare = atomic || e != expr || delimited(out, std::string_view(s).substr(r.end));
            out += bare ? e : "(" + e + ")";
        } else {
            out.append(s, r.begin, r.end - r.begin);
        }
        at = r.end;
    }
    out.append(s, at, std::string::npos);
    return out;
}

std::string render(std::string_view s) {
    std::string out;
    PhRef r;
    size_t at = 0;
    while (nextPh(s, at, r)) {
        out.append(s.substr(at, r.begin - at));
        out.append(r.name);
        at = r.end;
    }
    out.append(s.substr(std::min(at, s.size())));
    return out;
}

// True when `e` needs parentheses as an operand: it has a space outside of
// brackets, strings and placeholders.
bool compound(std::string_view e) {
    int depth = 0;
    bool str = false, inPh = false;
    for (size_t i = 0; i < e.size(); ++i) {
        const char c = e[i];
        if (inPh) {
            inPh = c != kClose;
            continue;
        }
        if (str) {
            if (c == '\\') ++i;
            else if (c == '"') str = false;
            continue;
        }
        if (c == kOpen) inPh = true;
        else if (c == '"') str = true;
        else if (c == '(' || c == '[' || c == '{') ++depth;
        else if (c == ')' || c == ']' || c == '}') --depth;
        else if (c == ' ' && depth == 0) return true;
    }
    return false;
}

std::string wrap(const std::string& e) { return compound(e) ? "(" + e + ")" : e; }

// Conditions: "lhs \x03 op \x03 rhs". op "?" means lhs is the condition, "!" its negation.
std::string cond(const std::string& a, std::string_view op, const std::string& b) {
    const bool unary = op == "?" || op == "!";  // "!" wraps when rendered
    return (unary ? a : wrap(a)) + kSep + std::string(op) + kSep + wrap(b);
}

void splitCond(const std::string& c, std::string& a, std::string& op, std::string& b) {
    const size_t s1 = c.find(kSep);
    const size_t s2 = s1 == std::string::npos ? std::string::npos : c.find(kSep, s1 + 1);
    if (s2 == std::string::npos) {
        a = c, op = "?", b.clear();
        return;
    }
    a = c.substr(0, s1);
    op = c.substr(s1 + 1, s2 - s1 - 1);
    b = c.substr(s2 + 1);
}

std::string negateCond(const std::string& c) {
    std::string a, op, b;
    splitCond(c, a, op, b);
    static const std::pair<const char*, const char*> kNeg[] = {{"==", "!="}, {"!=", "=="}, {"<", ">="}, {">=", "<"},
                                                               {">", "<="}, {"<=", ">"},  {"?", "!"},  {"!", "?"}};
    for (const auto& [from, to] : kNeg)
        if (op == from) return a + kSep + to + kSep + b;
    return a + kSep + "!" + kSep;
}

// Condition as an expression (placeholders kept), for csel / ccmp chains.
std::string condExpr(const std::string& c) {
    std::string a, op, b;
    splitCond(c, a, op, b);
    if (op == "?") return a;
    if (op == "!") return "!" + wrap(a);
    return a + " " + op + " " + b;
}

// "Long.compare(x, y)" -> x, y
bool splitCompare(const std::string& a, std::string& x, std::string& y) {
    static const char* const kPrefixes[] = {"Long.compare(", "Float.compare(", "Double.compare("};
    for (const char* p : kPrefixes) {
        const size_t n = std::strlen(p);
        if (a.compare(0, n, p) != 0 || a.back() != ')') continue;
        int depth = 0;
        size_t comma = std::string::npos;
        for (size_t i = n; i + 1 < a.size(); ++i) {
            const char c = a[i];
            if (c == '(' || c == '[') ++depth;
            else if (c == ')' || c == ']') {
                if (--depth < 0) return false;
            } else if (c == ',' && depth == 0 && comma == std::string::npos) {
                comma = i;
            }
        }
        if (depth != 0 || comma == std::string::npos) return false;
        x = a.substr(n, comma - n);
        y = a.substr(comma + 2, a.size() - comma - 3);
        return true;
    }
    return false;
}

std::string renderCond(const std::string& c) {
    std::string a, op, b;
    splitCond(c, a, op, b);
    a = render(a);
    b = render(b);
    std::string x, y;
    if (b == "0" && splitCompare(a, x, y)) a = x, b = y;
    if (op == "?") return a;
    if (op == "!") return "!" + wrap(a);
    return a + " " + op + " " + b;
}

// ===========================================================================
// Intermediate form
// ===========================================================================

struct Stmt {
    std::vector<uint64_t> addrs;
    int def = -1;  // register defined by the value of rhs
    std::string defName;
    std::string rhs;  // the value (def >= 0) or the whole statement
    bool atomic = false;      // rhs needs no parentheses as an operand
    bool constant = false;    // depends on nothing: may move anywhere
    bool readsMem = false;
    bool sideEffect = false;
    bool newInstance = false; // Dalvik new-instance waiting for its <init>
    bool removed = false;
    std::vector<int> kills;   // registers clobbered without a value (calls)
    int moveFrom = -1;        // Dalvik register copy: the source register
    char vkind = 0;           // Dalvik value kind: L object, Z boolean, N number, 0 unknown
    bool smallLiteral = false;  // Dalvik const 0 / 1: may read as null / false / true
    std::string vtype;          // type of the defined value, for the declarations ("" unknown)
};

enum class TermKind : uint8_t { Fall, Cond, Switch, Return, Throw, Stop };

// A branch condition once folding is done: a leaf (cond() text) or && / || of conditions.
struct CondTree {
    char op = 0;  // 0 leaf, '&', '|'
    std::string leaf;
    std::vector<CondTree> kids;
};

CondTree negate(const CondTree& c) {
    if (!c.op) return {0, negateCond(c.leaf), {}};
    CondTree n{c.op == '&' ? '|' : '&', {}, {}};
    for (const CondTree& k : c.kids) n.kids.push_back(negate(k));
    return n;
}

CondTree combine(char op, const CondTree& a, const CondTree& b) {
    CondTree n{op, {}, {}};
    for (const CondTree* x : {&a, &b}) {
        if (x->op == op) n.kids.insert(n.kids.end(), x->kids.begin(), x->kids.end());
        else n.kids.push_back(*x);
    }
    return n;
}

std::string renderTree(const CondTree& c) {
    if (!c.op) return renderCond(c.leaf);
    std::string out;
    for (const CondTree& k : c.kids) {
        if (!out.empty()) out += c.op == '&' ? " && " : " || ";
        const std::string r = renderTree(k);
        // A leaf that is itself a whole expression (ccmp chains, ternaries) keeps its own grouping.
        bool group = k.op != 0;
        if (!group) {
            std::string a, op, b;
            splitCond(k.leaf, a, op, b);
            group = op == "?" && (a.find("||") != std::string::npos || a.find("&&") != std::string::npos || a.find(" ? ") != std::string::npos);
        }
        out += group ? "(" + r + ")" : r;
    }
    return out;
}

struct Term {
    TermKind kind = TermKind::Fall;
    std::vector<uint64_t> addrs;
    std::string text;  // Cond: condition; Switch: value; Return/Throw: value; Stop: statement
    std::vector<std::pair<std::vector<int64_t>, int>> cases;  // Switch: keys -> block
    // Switch over a string: label texts (quoted literals) per case, parallel to `cases` (whose keys are then empty).
    std::vector<std::vector<std::string>> caseLabels;
    CondTree cond;     // Cond, after folding
    bool noDefault = false;  // Switch through a jump table: the bounds check before it handles the other values
};

struct Block {
    uint64_t addr = 0;
    std::vector<Stmt> stmts;
    Term term;
    std::vector<int> succ;  // Fall: [next]; Cond: [taken, not taken]; Switch: [default, cases...]
    std::vector<int> exc;   // exception handlers (liveness only)
    std::vector<std::string> notes;
};

struct Fn {
    std::vector<Block> blocks;
    std::vector<int> roots;     // [0] entry, then exception handler entries
    std::vector<std::string> rootNotes;  // per root (catch clauses)
    int regCount = 0;
    std::string labelPrefix = "label_";
};

void mergeAddrs(std::vector<uint64_t>& into, const std::vector<uint64_t>& from) {
    into.insert(into.end(), from.begin(), from.end());
}

// ===========================================================================
// Data flow: liveness, dead code, folding
// ===========================================================================

class Bits {
public:
    explicit Bits(size_t n = 0) : w_((n + 63) / 64, 0) {}
    bool test(int i) const { return i >= 0 && static_cast<size_t>(i) / 64 < w_.size() && ((w_[static_cast<size_t>(i) / 64] >> (i % 64)) & 1u); }
    void set(int i) {
        if (i >= 0 && static_cast<size_t>(i) / 64 < w_.size()) w_[static_cast<size_t>(i) / 64] |= 1ull << (i % 64);
    }
    void reset(int i) {
        if (i >= 0 && static_cast<size_t>(i) / 64 < w_.size()) w_[static_cast<size_t>(i) / 64] &= ~(1ull << (i % 64));
    }
    bool orWith(const Bits& o) {
        bool changed = false;
        for (size_t k = 0; k < w_.size() && k < o.w_.size(); ++k) {
            const uint64_t v = w_[k] | o.w_[k];
            changed |= v != w_[k];
            w_[k] = v;
        }
        return changed;
    }
    void andNot(const Bits& o) {
        for (size_t k = 0; k < w_.size() && k < o.w_.size(); ++k) w_[k] &= ~o.w_[k];
    }

private:
    std::vector<uint64_t> w_;
};

struct Liveness {
    std::vector<Bits> in, out, always;  // always: live into an exception handler of the block
};

Liveness liveness(const Fn& fn) {
    const size_t n = fn.blocks.size(), regs = static_cast<size_t>(fn.regCount);
    std::vector<Bits> gen(n, Bits(regs)), kill(n, Bits(regs));
    for (size_t b = 0; b < n; ++b) {
        const Block& blk = fn.blocks[b];
        const auto use = [&](int r) {
            if (!kill[b].test(r)) gen[b].set(r);
        };
        for (const Stmt& s : blk.stmts) {
            if (s.removed) continue;
            forEachUse(s.rhs, use);
            if (s.def >= 0) kill[b].set(s.def);
            for (int k : s.kills) kill[b].set(k);
        }
        forEachUse(blk.term.text, use);
    }
    Liveness lv;
    lv.in.assign(n, Bits(regs));
    lv.out.assign(n, Bits(regs));
    lv.always.assign(n, Bits(regs));
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t i = n; i-- > 0;) {
            const Block& blk = fn.blocks[i];
            for (int s : blk.succ) lv.out[i].orWith(lv.in[static_cast<size_t>(s)]);
            for (int h : blk.exc) {
                lv.out[i].orWith(lv.in[static_cast<size_t>(h)]);
                lv.always[i].orWith(lv.in[static_cast<size_t>(h)]);
            }
            Bits in = lv.out[i];
            in.andNot(kill[i]);
            in.orWith(gen[i]);
            in.orWith(lv.always[i]);
            changed |= lv.in[i].orWith(in);
        }
    }
    return lv;
}

void removeDead(Fn& fn, const Liveness& lv) {
    for (size_t b = 0; b < fn.blocks.size(); ++b) {
        Block& blk = fn.blocks[b];
        Bits live = lv.out[b];
        live.orWith(lv.always[b]);
        forEachUse(blk.term.text, [&](int r) { live.set(r); });
        for (size_t i = blk.stmts.size(); i-- > 0;) {
            Stmt& s = blk.stmts[i];
            if (s.removed) continue;
            if (s.def >= 0 && !live.test(s.def)) {
                if (!s.sideEffect) {
                    s.removed = true;
                    continue;
                }
                s.kills.push_back(s.def);  // keep the call, drop the assignment
                s.def = -1;
            }
            if (s.def >= 0) live.reset(s.def);
            for (int k : s.kills) live.reset(k);
            forEachUse(s.rhs, [&](int r) { live.set(r); });
            live.orWith(lv.always[b]);
        }
    }
}

bool clobbers(const Stmt& c, int r) {
    return c.def == r || std::find(c.kills.begin(), c.kills.end(), r) != c.kills.end();
}

// Can `d` be evaluated after `c` instead of before it?
bool movablePast(const Stmt& d, const Stmt& c) {
    bool clash = false;
    forEachUse(d.rhs, [&](int u) { clash |= clobbers(c, u); });
    if (clash) return false;
    if (d.constant) return true;
    if (d.sideEffect) return !c.sideEffect && !c.readsMem;
    if (d.readsMem) return !c.sideEffect;
    return true;
}

void foldTemporaries(Fn& fn, const Liveness& lv) {
    for (size_t b = 0; b < fn.blocks.size(); ++b) {
        Block& blk = fn.blocks[b];
        auto& st = blk.stmts;
        for (size_t i = 0; i < st.size(); ++i) {
            Stmt& d = st[i];
            if (d.removed || d.def < 0 || lv.always[b].test(d.def)) continue;
            if (!d.constant && d.rhs.size() > kMaxInline) continue;
            const int r = d.def;
            // The first later statement reading r; everything in between must let d move past it.
            size_t j = st.size();
            bool ok = true;
            int scanned = 0;
            for (size_t k = i + 1; k < st.size(); ++k) {
                if (st[k].removed) continue;
                if (++scanned > 48) {
                    ok = false;
                    break;
                }
                if (countUses(st[k].rhs, r) > 0) {
                    j = k;
                    break;
                }
                if (clobbers(st[k], r) || !movablePast(d, st[k])) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            std::string* target = nullptr;
            bool liveAfter = false;
            if (j < st.size()) {
                if (countUses(st[j].rhs, r) != 1) continue;
                target = &st[j].rhs;
                if (!clobbers(st[j], r)) {
                    bool decided = false;
                    for (size_t k = j + 1; k < st.size() && !decided; ++k) {
                        if (st[k].removed) continue;
                        if (countUses(st[k].rhs, r) > 0) liveAfter = decided = true;
                        else if (clobbers(st[k], r)) decided = true;
                    }
                    if (!decided) liveAfter = countUses(blk.term.text, r) > 0 || lv.out[b].test(r);
                }
            } else {
                if (countUses(blk.term.text, r) != 1) continue;
                target = &blk.term.text;
                liveAfter = lv.out[b].test(r);
            }
            if (liveAfter) continue;
            *target = substitute(*target, r, d.rhs, d.atomic);
            if (j < st.size()) {
                Stmt& u = st[j];
                mergeAddrs(u.addrs, d.addrs);
                u.readsMem |= d.readsMem;
                u.sideEffect |= d.sideEffect;
                u.constant = u.constant && d.constant;
            } else {
                mergeAddrs(blk.term.addrs, d.addrs);
            }
            d.removed = true;
        }
    }
}

// A branch whose block computes nothing else joins the branch before it:
//   if (a) goto T; if (b) goto T;   ->  if (a || b) goto T;
//   if (a) { if (b) goto T; } F      ->  if (a && b) goto T; F
void mergeConditions(Fn& fn) {
    const int n = static_cast<int>(fn.blocks.size());
    std::vector<char> isRoot(static_cast<size_t>(n), 0);
    for (int r : fn.roots) isRoot[static_cast<size_t>(r)] = 1;
    const auto bare = [&](int b, const std::vector<int>& preds) {
        const Block& blk = fn.blocks[static_cast<size_t>(b)];
        if (blk.term.kind != TermKind::Cond || blk.succ.size() != 2 || !blk.notes.empty() || isRoot[static_cast<size_t>(b)]) return false;
        if (preds[static_cast<size_t>(b)] != 1) return false;
        return std::all_of(blk.stmts.begin(), blk.stmts.end(), [](const Stmt& s) { return s.removed; });
    };
    for (bool changed = true; changed;) {
        changed = false;
        std::vector<int> preds(static_cast<size_t>(n), 0);
        for (const Block& blk : fn.blocks)
            for (int s : blk.succ) ++preds[static_cast<size_t>(s)];
        for (int a = 0; a < n && !changed; ++a) {
            Block& A = fn.blocks[static_cast<size_t>(a)];
            if (A.term.kind != TermKind::Cond || A.succ.size() != 2) continue;
            const int t = A.succ[0], f = A.succ[1];
            int gone = -1;
            if (f != a && bare(f, preds)) {
                const Block& B = fn.blocks[static_cast<size_t>(f)];
                if (B.succ[0] == t) A.term.cond = combine('|', A.term.cond, B.term.cond), A.succ = {t, B.succ[1]}, gone = f;
                else if (B.succ[1] == t) A.term.cond = combine('|', A.term.cond, negate(B.term.cond)), A.succ = {t, B.succ[0]}, gone = f;
            }
            if (gone < 0 && t != a && bare(t, preds)) {
                const Block& B = fn.blocks[static_cast<size_t>(t)];
                if (B.succ[1] == f) A.term.cond = combine('&', A.term.cond, B.term.cond), A.succ = {B.succ[0], f}, gone = t;
                else if (B.succ[0] == f) A.term.cond = combine('&', A.term.cond, negate(B.term.cond)), A.succ = {B.succ[1], f}, gone = t;
            }
            if (gone < 0) continue;
            Block& G = fn.blocks[static_cast<size_t>(gone)];
            mergeAddrs(A.term.addrs, G.term.addrs);
            G.succ.clear();
            G.exc.clear();
            G.term = Term{};
            G.term.kind = TermKind::Stop;
            if (A.succ[0] == A.succ[1]) A.succ.pop_back(), A.term.kind = TermKind::Fall;
            changed = true;
        }
    }
}

// Developer aid: APKSPY_DECOMPILER_DUMP=1 prints the blocks after simplification to stderr.
void dumpFn(const Fn& fn) {
    for (size_t i = 0; i < fn.blocks.size(); ++i) {
        const Block& b = fn.blocks[i];
        std::fprintf(stderr, "B%zu @%llx\n", i, static_cast<unsigned long long>(b.addr));
        for (const Stmt& st : b.stmts) {
            if (st.removed) continue;
            std::fprintf(stderr, "    %s def=%d %s%s\n", st.def >= 0 ? st.defName.c_str() : "-", st.def, render(st.rhs).c_str(),
                         st.constant ? "  [const]" : "");
        }
        const Term& t = b.term;
        const char* kinds[] = {"Fall", "Cond", "Switch", "Return", "Throw", "Stop"};
        std::string text = t.kind == TermKind::Cond ? renderCond(t.text) : render(t.text);
        std::fprintf(stderr, "    -> %s '%s' succ:", kinds[static_cast<int>(t.kind)], text.c_str());
        for (int sc : b.succ) std::fprintf(stderr, " %d", sc);
        if (t.kind == TermKind::Switch)
            for (const auto& [keys, target] : t.cases) {
                std::fprintf(stderr, " [");
                for (int64_t k : keys) std::fprintf(stderr, "%lld,", static_cast<long long>(k));
                std::fprintf(stderr, "]=>%d", target);
            }
        std::fprintf(stderr, "\n");
    }
}

void simplify(Fn& fn) {
    for (int round = 0; round < 2; ++round) {
        removeDead(fn, liveness(fn));
        foldTemporaries(fn, liveness(fn));
    }
    removeDead(fn, liveness(fn));
    for (Block& b : fn.blocks)
        if (b.term.kind == TermKind::Cond) b.term.cond = CondTree{0, b.term.text, {}};
    mergeConditions(fn);
}

// ===========================================================================
// switch (string)
// ===========================================================================
//
// javac, D8 and kotlinc compile a switch over a string into a switch over
// s.hashCode() whose cases test s.equals("a") (a hash collision is a chain of such
// tests). Two shapes follow:
//   indexed: the matching test stores the case's index and a second switch over that
//            index holds the bodies (javac / D8; D8 often reuses the string's own
//            register for the index);
//   direct:  the matching test jumps straight into the body (kotlinc's when).
// Left alone the output is a hash switch, an index variable and gotos to the shared
// "no match" block. When the graph has exactly one of these shapes, this pass
// rebuilds a single switch over the string.

struct StringSwitchPass {
    Fn& fn;
    std::vector<std::vector<int>> preds;

    explicit StringSwitchPass(Fn& f) : fn(f) {}

    static bool endsWith(const std::string& s, const std::string& suffix) {
        return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    static bool numeric(const std::string& t, int64_t& v) {
        if (t.empty()) return false;
        char* end = nullptr;
        const long long x = std::strtoll(t.c_str(), &end, 10);
        if (end != t.c_str() + t.size()) return false;
        v = x;
        return true;
    }
    static bool simpleSubject(const std::string& e) {
        if (e.empty()) return false;
        for (char c : e)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '.')) return false;
        return true;
    }

    // The value of a register that is assigned exactly once in the function, to a number
    // (D8 hoists shared constants into registers: "v6 = v2" then stands for "v6 = 4").
    bool constValue(const std::string& name, int64_t& out) const {
        const Stmt* only = nullptr;
        for (const Block& b : fn.blocks)
            for (const Stmt& st : b.stmts) {
                if (st.removed || st.def < 0 || st.defName != name) continue;
                if (only) return false;
                only = &st;
            }
        return only && numeric(render(only->rhs), out);
    }
    // A number written out, or a register that holds one.
    bool valueOf(const std::string& text, int64_t& out) const { return numeric(text, out) || constValue(text, out); }

    // The number register `reg` holds on entry to block `b`: its last assignment, found by walking back
    // through blocks that have a single predecessor.
    bool reachingConst(int b, int reg, int64_t& out) const {
        for (int steps = 0; steps < 16; ++steps) {
            const Block& bb = fn.blocks[static_cast<size_t>(b)];
            for (size_t i = bb.stmts.size(); i-- > 0;) {
                const Stmt& st = bb.stmts[i];
                if (st.removed || st.def != reg) continue;
                return valueOf(render(st.rhs), out);
            }
            if (preds[static_cast<size_t>(b)].size() != 1) return false;
            b = preds[static_cast<size_t>(b)][0];
        }
        return false;
    }

    int liveStmts(const Block& b) const {
        int n = 0;
        for (const Stmt& st : b.stmts) n += st.removed ? 0 : 1;
        return n;
    }
    // A block that only jumps on (a compiler's goto trampoline).
    bool trampoline(int b) const {
        const Block& bb = fn.blocks[static_cast<size_t>(b)];
        return liveStmts(bb) == 0 && bb.term.kind == TermKind::Fall && bb.succ.size() == 1 && bb.notes.empty() && bb.exc.empty();
    }
    int skipTrampolines(int b, std::vector<int>& visited) const {
        for (int hops = 0; hops < 8 && trampoline(b); ++hops) {
            visited.push_back(b);
            b = fn.blocks[static_cast<size_t>(b)].succ[0];
        }
        return b;
    }

    // "<subject>.equals(\"lit\")", possibly negated, as the condition of a block.
    struct Equals {
        std::string subject, literal;
        int match = -1, noMatch = -1;
    };
    bool parseEquals(int b, Equals& out) const {
        const Block& bb = fn.blocks[static_cast<size_t>(b)];
        if (bb.term.kind != TermKind::Cond || bb.succ.size() != 2 || liveStmts(bb) != 0 || !bb.notes.empty() || !bb.exc.empty()) return false;
        std::string a, op, rhs;
        splitCond(bb.term.text, a, op, rhs);
        if (op != "?" && op != "!") return false;
        const std::string shown = render(a);
        const size_t at = shown.find(".equals(\"");
        if (at == std::string::npos || shown.compare(shown.size() - 1, 1, ")") != 0) return false;
        out.subject = shown.substr(0, at);
        out.literal = shown.substr(at + 8, shown.size() - (at + 8) - 1);  // the quoted literal
        if (out.literal.size() < 2 || out.literal.front() != '"' || out.literal.back() != '"') return false;
        // The literal must be one string: no unescaped quote inside.
        for (size_t i = 1; i + 1 < out.literal.size(); ++i) {
            if (out.literal[i] == '\\') ++i;
            else if (out.literal[i] == '"') return false;
        }
        out.match = op == "?" ? bb.succ[0] : bb.succ[1];
        out.noMatch = op == "?" ? bb.succ[1] : bb.succ[0];
        return true;
    }

    // What the hash switch's cases test.
    struct Collected {
        std::string value;       // "s.hashCode()" as shown
        std::string subjectRaw;  // the subject expression, placeholders kept
        std::set<int> chain;     // the equals tests and the trampolines after them
        std::vector<std::pair<std::string, int>> matches;  // literal -> block the match enters
        std::vector<int> testOf;                           // the equals block of each match
        int noMatch = -1;        // where every failed test, and an unknown hash, ends up
    };

    bool run() {
        bool any = false;
        for (size_t h = 0; h < fn.blocks.size(); ++h) any |= tryBlock(static_cast<int>(h));
        return any;
    }

    void computePreds() {
        preds.assign(fn.blocks.size(), {});
        for (size_t i = 0; i < fn.blocks.size(); ++i)
            for (int sc : fn.blocks[i].succ)
                if (sc >= 0 && static_cast<size_t>(sc) < fn.blocks.size()) preds[static_cast<size_t>(sc)].push_back(static_cast<int>(i));
    }

    bool collect(int h, Collected& c) {
        const Block& H = fn.blocks[static_cast<size_t>(h)];
        if (H.term.kind != TermKind::Switch || H.term.cases.empty() || !H.term.caseLabels.empty()) return false;
        c.value = render(H.term.text);
        const std::string suffix = ".hashCode()";
        if (!endsWith(c.value, suffix) || !endsWith(H.term.text, suffix)) return false;
        const std::string subject = c.value.substr(0, c.value.size() - suffix.size());
        if (!simpleSubject(subject)) return false;
        c.subjectRaw = H.term.text.substr(0, H.term.text.size() - suffix.size());

        for (const auto& [keys, target] : H.term.cases) {
            (void)keys;
            int cur = target;
            for (int step = 0; step < 16; ++step) {
                Equals eq;
                if (!parseEquals(cur, eq) || eq.subject != subject) return false;
                if (step > 0 && preds[static_cast<size_t>(cur)].size() != 1) return false;
                c.chain.insert(cur);
                c.matches.push_back({eq.literal, eq.match});
                c.testOf.push_back(cur);
                std::vector<int> hops;
                const int next = skipTrampolines(eq.noMatch, hops);
                // A further test on the same subject continues a hash-collision chain.
                Equals follow;
                if (parseEquals(next, follow) && follow.subject == subject && preds[static_cast<size_t>(next)].size() == 1) {
                    for (int t : hops) c.chain.insert(t);
                    cur = next;
                    continue;
                }
                if (c.noMatch >= 0 && c.noMatch != next) return false;
                c.noMatch = next;
                for (int t : hops) c.chain.insert(t);
                break;
            }
        }
        if (c.matches.empty() || c.noMatch < 0) return false;
        // An unmatched hash takes the head's default edge: it must end at the same no-match block.
        std::vector<int> hops;
        if (H.succ.empty() || skipTrampolines(H.succ[0], hops) != c.noMatch) return false;
        for (int t : hops) c.chain.insert(t);
        return true;
    }

    bool tryBlock(int h) {
        computePreds();
        Collected c;
        if (!collect(h, c)) return false;
        return tryIndexed(h, c) || tryDirect(h, c);
    }

    struct Group {
        int target;
        int64_t order;
        std::vector<std::string> labels;
    };

    // Installs the rebuilt switch in the head and retires the blocks that carried the old one.
    void install(int h, const Collected& c, std::vector<Group> groups, int defaultTarget, std::set<int> retire) {
        Block& H = fn.blocks[static_cast<size_t>(h)];
        // Source order, equal-bodied labels together.
        std::stable_sort(groups.begin(), groups.end(), [](const Group& a, const Group& b) { return a.order < b.order; });
        Term t;
        t.kind = TermKind::Switch;
        t.addrs = H.term.addrs;
        t.text = c.subjectRaw;
        std::vector<int> succ = {defaultTarget};
        for (const Group& g : groups) {
            t.cases.push_back({{}, g.target});
            t.caseLabels.push_back(g.labels);
            succ.push_back(g.target);
        }
        for (Stmt& st : H.stmts)  // the null-check call kept in front of the switch
            if (!st.removed && st.def < 0 && render(st.rhs) == c.value) st.removed = true;
        H.term = std::move(t);
        H.succ = std::move(succ);
        retire.erase(h);
        for (int b : retire) {
            Block& dead = fn.blocks[static_cast<size_t>(b)];
            dead.stmts.clear();
            dead.succ.clear();
            dead.exc.clear();
            dead.term = Term{};
            dead.term.kind = TermKind::Stop;
        }
    }

    // --- indexed: equals -> "idx = k" -> switch (idx) { bodies } -----------------------------
    bool tryIndexed(int h, const Collected& c) {
        Block& H = fn.blocks[static_cast<size_t>(h)];
        std::set<int> chain = c.chain;
        // Every match block sets the index register to a constant and continues to the index switch.
        int idxReg = -1, s2 = -1;
        std::string idxName;
        std::vector<std::pair<std::string, int64_t>> indexed;  // literal -> index value
        std::vector<std::pair<std::string, int>> straight;  // matches that jump into the index switch itself
        for (const auto& [literal, mb] : c.matches) {
            const Block& M = fn.blocks[static_cast<size_t>(mb)];
            if (M.term.kind == TermKind::Switch) {  // the index already holds this case's value
                straight.push_back({literal, mb});
                continue;
            }
            if (M.term.kind != TermKind::Fall || M.succ.size() != 1 || !M.notes.empty() || !M.exc.empty() || liveStmts(M) != 1) return false;
            const Stmt* set = nullptr;
            for (const Stmt& st : M.stmts)
                if (!st.removed) set = &st;
            int64_t k = 0;
            if (!set || set->def < 0 || !valueOf(render(set->rhs), k)) return false;
            if (idxReg >= 0 && (idxReg != set->def || s2 != M.succ[0])) return false;
            idxReg = set->def;
            idxName = set->defName;
            s2 = M.succ[0];
            indexed.push_back({literal, k});
            chain.insert(mb);
        }
        if (s2 < 0 || chain.count(s2)) return false;
        for (const auto& [literal, mb] : straight) {
            int64_t k = 0;
            if (mb != s2 || !reachingConst(h, idxReg, k)) return false;
            indexed.push_back({literal, k});
        }

        // The no-match path leaves the index at a value no case uses (-1), straight or through one assignment.
        int64_t noMatchValue = 0;
        bool haveNoMatch = false;
        if (c.noMatch == s2) {
            // javac form: the index was initialised in the head, before the hash switch.
            for (const Stmt& st : H.stmts)
                if (!st.removed && st.def == idxReg && valueOf(render(st.rhs), noMatchValue)) haveNoMatch = true;
        } else {
            const Block& D = fn.blocks[static_cast<size_t>(c.noMatch)];
            if (D.term.kind != TermKind::Fall || D.succ.size() != 1 || D.succ[0] != s2 || liveStmts(D) != 1 || !D.notes.empty() || !D.exc.empty())
                return false;
            const Stmt* set = nullptr;
            for (const Stmt& st : D.stmts)
                if (!st.removed) set = &st;
            if (!set || set->def != idxReg) return false;
            haveNoMatch = valueOf(render(set->rhs), noMatchValue);
            chain.insert(c.noMatch);
        }
        if (!haveNoMatch) return false;

        // The index switch: only the switch, nothing else, and nothing but this chain enters it.
        const Block& S2 = fn.blocks[static_cast<size_t>(s2)];
        if (S2.term.kind != TermKind::Switch || liveStmts(S2) != 0 || !S2.notes.empty() || !S2.exc.empty() || !S2.term.caseLabels.empty()) return false;
        if (render(S2.term.text) != idxName) return false;
        for (int p : preds[static_cast<size_t>(s2)])
            if (!chain.count(p)) return false;
        for (int b : chain)  // nothing else may jump into the chain either
            for (int p : preds[static_cast<size_t>(b)])
                if (p != h && !chain.count(p)) return false;
        for (const auto& [keys, t] : S2.term.cases) {
            (void)t;
            for (int64_t k : keys)
                if (k == noMatchValue) return false;  // the "no match" index would hit a case
        }

        // The index value must not be read after the switch (it is about to disappear).
        const Liveness lv = liveness(fn);
        std::vector<int> bodies = {S2.succ.empty() ? -1 : S2.succ[0]};
        for (const auto& [keys, t] : S2.term.cases) {
            (void)keys;
            bodies.push_back(t);
        }
        for (int t : bodies)
            if (t >= 0 && lv.in[static_cast<size_t>(t)].test(idxReg)) return false;

        // Literal -> target: the index switch's case for that index, else its default.
        const int defaultTarget = S2.succ.empty() ? -1 : S2.succ[0];
        if (defaultTarget < 0) return false;
        std::vector<Group> groups;
        for (const auto& [literal, k] : indexed) {
            int target = defaultTarget;
            for (const auto& [keys, t] : S2.term.cases)
                if (std::find(keys.begin(), keys.end(), k) != keys.end()) target = t;
            auto it = std::find_if(groups.begin(), groups.end(), [&](const Group& g) { return g.target == target; });
            if (it == groups.end()) {
                groups.push_back({target, k, {}});
                it = groups.end() - 1;
            }
            it->order = std::min(it->order, k);
            it->labels.push_back(literal);
        }
        for (Group& g : groups) std::sort(g.labels.begin(), g.labels.end());
        chain.insert(s2);
        install(h, c, std::move(groups), defaultTarget, chain);
        return true;
    }

    // --- direct: equals -> body (kotlinc's when over a string) -------------------------------
    bool tryDirect(int h, const Collected& c) {
        // A body may be entered only by its own test, and the tests only from the head's cases.
        for (size_t i = 0; i < c.matches.size(); ++i) {
            const int mb = c.matches[i].second;
            if (c.chain.count(mb) || mb == h || mb == c.noMatch) return false;
            const auto& pr = preds[static_cast<size_t>(mb)];
            for (int p : pr)
                if (!std::count(c.testOf.begin(), c.testOf.end(), p)) return false;
        }
        for (int b : c.chain)
            for (int p : preds[static_cast<size_t>(b)])
                if (p != h && !c.chain.count(p)) return false;
        std::vector<Group> groups;
        int64_t order = 0;
        for (const auto& [literal, mb] : c.matches) {
            auto it = std::find_if(groups.begin(), groups.end(), [&](const Group& g) { return g.target == mb; });
            if (it == groups.end()) {
                groups.push_back({mb, order++, {}});
                it = groups.end() - 1;
            }
            it->labels.push_back(literal);
        }
        // Source order is not recoverable here: keep the bodies in address order.
        std::stable_sort(groups.begin(), groups.end(), [&](const Group& a, const Group& b) {
            return fn.blocks[static_cast<size_t>(a.target)].addr < fn.blocks[static_cast<size_t>(b.target)].addr;
        });
        int64_t n = 0;
        for (Group& g : groups) {
            g.order = n++;
            std::sort(g.labels.begin(), g.labels.end());
        }
        install(h, c, std::move(groups), c.noMatch, c.chain);
        return true;
    }
};

bool recoverStringSwitches(Fn& fn) { return StringSwitchPass(fn).run(); }

// ===========================================================================
// Structuring
// ===========================================================================

class Structurer {
public:
    Structurer(const Fn& fn, std::vector<Line>& out) : fn_(fn), out_(out), n_(static_cast<int>(fn.blocks.size())) {}

    void run(int indent) {
        if (n_ == 0) return;
        analyse();
        emitted_.assign(static_cast<size_t>(n_), 0);
        start_.assign(static_cast<size_t>(n_), -1);
        const size_t bodyStart = out_.size();
        emitSeq(fn_.roots.front(), -1, Ctx{}, indent, 0);
        // Exception handlers and blocks only reached through gotos.
        for (size_t r = 1; r < fn_.roots.size(); ++r) labels_.insert(fn_.roots[r]);
        for (bool more = true; more;) {
            more = false;
            for (int b = 0; b < n_; ++b) {
                if (emitted_[static_cast<size_t>(b)] || rpoIdx_[static_cast<size_t>(b)] < 0) continue;
                labels_.insert(b);
                const int lineAt = static_cast<int>(out_.size());
                for (size_t r = 1; r < fn_.roots.size(); ++r)
                    if (fn_.roots[r] == b && r - 1 < fn_.rootNotes.size()) emit(fn_.rootNotes[r - 1], indent, {fn_.blocks[static_cast<size_t>(b)].addr});
                emitSeq(b, -1, Ctx{}, indent, 0);
                start_[static_cast<size_t>(b)] = lineAt;
                more = true;
                break;  // earlier blocks first, as later ones may now be emitted
            }
        }
        insertLabels(bodyStart);
    }

private:
    struct Ctx {
        int header = -1, follow = -1;
        const std::vector<char>* body = nullptr;
        bool inSwitch = false;
        int switchFollow = -1;
    };

    const Block& blk(int b) const { return fn_.blocks[static_cast<size_t>(b)]; }

    void emit(std::string text, int indent, std::vector<uint64_t> addrs) {
        // A call through a resolved GOT slot: (*&memcpy)(a, b) -> memcpy(a, b)
        for (size_t at = text.find("(*&"); at != std::string::npos; at = text.find("(*&", at + 1)) {
            size_t e = at + 3;
            while (e < text.size() && (std::isalnum(static_cast<unsigned char>(text[e])) || text[e] == '_' || text[e] == '$' || text[e] == ':'))
                ++e;
            if (e > at + 3 && text.compare(e, 2, ")(") == 0) text = text.substr(0, at) + text.substr(at + 3, e - at - 3) + text.substr(e + 1);
        }
        std::sort(addrs.begin(), addrs.end());
        addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
        out_.push_back({std::move(text), indent, std::move(addrs)});
    }

    std::string label(int b) const {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%04" PRIx64, blk(b).addr);
        return fn_.labelPrefix + buf;
    }

    void emitGoto(int b, int indent, const std::vector<uint64_t>& addrs) {
        labels_.insert(b);
        emit("goto " + label(b) + ";", indent, addrs);
    }

    // ---- graph analysis
    void analyse() {
        const size_t n = static_cast<size_t>(n_);
        preds_.assign(n, {});
        for (int b = 0; b < n_; ++b)
            for (int s : blk(b).succ) preds_[static_cast<size_t>(s)].push_back(b);

        // Dominators (Cooper, Harvey, Kennedy) from a virtual root above all roots.
        const int root = n_;
        std::vector<int> order = postorder(fn_.roots, [&](int b) -> const std::vector<int>& { return blk(b).succ; });
        std::reverse(order.begin(), order.end());
        rpoIdx_.assign(n + 1, -1);
        rpoIdx_[n] = 0;
        for (size_t i = 0; i < order.size(); ++i) rpoIdx_[static_cast<size_t>(order[i])] = static_cast<int>(i) + 1;
        std::vector<char> isRoot(n, 0);
        for (int r : fn_.roots) isRoot[static_cast<size_t>(r)] = 1;
        idom_ = dominators(order, root, rpoIdx_, [&](int b, const auto& f) {
            if (isRoot[static_cast<size_t>(b)]) f(root);
            for (int p : preds_[static_cast<size_t>(b)]) f(p);
        });

        // Post-dominators over the reversed graph, from a virtual exit.
        const int exitNode = n_;
        std::vector<int> exits;
        std::vector<char> isExit(n, 0);
        for (int b = 0; b < n_; ++b)
            if (blk(b).succ.empty()) exits.push_back(b), isExit[static_cast<size_t>(b)] = 1;
        std::vector<int> rorder = postorder(exits, [&](int b) -> const std::vector<int>& { return preds_[static_cast<size_t>(b)]; });
        std::reverse(rorder.begin(), rorder.end());
        prpoIdx_.assign(n + 1, -1);
        prpoIdx_[n] = 0;
        for (size_t i = 0; i < rorder.size(); ++i) prpoIdx_[static_cast<size_t>(rorder[i])] = static_cast<int>(i) + 1;
        ipdom_ = dominators(rorder, exitNode, prpoIdx_, [&](int b, const auto& f) {
            if (isExit[static_cast<size_t>(b)]) f(exitNode);
            for (int s : blk(b).succ) f(s);
        });

        // Natural loops.
        header_.assign(n, 0);
        loopFollow_.assign(n, -1);
        for (int b = 0; b < n_; ++b) {
            if (rpoIdx_[static_cast<size_t>(b)] < 0) continue;
            for (int h : blk(b).succ) {
                if (!dominates(h, b)) continue;
                header_[static_cast<size_t>(h)] = 1;
                auto& body = bodies_[h];
                if (body.empty()) body.assign(n, 0);
                body[static_cast<size_t>(h)] = 1;
                std::vector<int> work{b};
                while (!work.empty()) {
                    const int x = work.back();
                    work.pop_back();
                    if (body[static_cast<size_t>(x)]) continue;
                    body[static_cast<size_t>(x)] = 1;
                    for (int p : preds_[static_cast<size_t>(x)])
                        if (rpoIdx_[static_cast<size_t>(p)] >= 0) work.push_back(p);
                }
            }
        }
        for (auto& [h, body] : bodies_) {
            int best = -1;
            const Block& hb = blk(h);
            if (hb.term.kind == TermKind::Cond) {
                int outside = 0, cand = -1;
                for (int s : hb.succ)
                    if (!body[static_cast<size_t>(s)]) ++outside, cand = s;
                if (outside == 1) best = cand;
            }
            if (best < 0)
                for (int b = 0; b < n_; ++b) {
                    if (!body[static_cast<size_t>(b)]) continue;
                    for (int s : blk(b).succ)
                        if (!body[static_cast<size_t>(s)] && (best < 0 || rpoIdx_[static_cast<size_t>(s)] < rpoIdx_[static_cast<size_t>(best)]))
                            best = s;
                }
            loopFollow_[static_cast<size_t>(h)] = best;
        }
    }

    template <class Next>
    std::vector<int> postorder(const std::vector<int>& starts, Next next) const {
        std::vector<int> order;
        std::vector<char> seen(static_cast<size_t>(n_), 0);
        std::vector<std::pair<int, size_t>> stack;
        for (int s0 : starts) {
            if (seen[static_cast<size_t>(s0)]) continue;
            seen[static_cast<size_t>(s0)] = 1;
            stack.push_back({s0, 0});
            while (!stack.empty()) {
                auto& [b, i] = stack.back();
                const std::vector<int>& succ = next(b);
                if (i < succ.size()) {
                    const int s = succ[i++];
                    if (!seen[static_cast<size_t>(s)]) {
                        seen[static_cast<size_t>(s)] = 1;
                        stack.push_back({s, 0});
                    }
                } else {
                    order.push_back(b);
                    stack.pop_back();
                }
            }
        }
        return order;
    }

    template <class Preds>
    std::vector<int> dominators(const std::vector<int>& rpo, int root, const std::vector<int>& idx, Preds preds) const {
        std::vector<int> dom(static_cast<size_t>(n_) + 1, -1);
        dom[static_cast<size_t>(root)] = root;
        const auto intersect = [&](int a, int b) {
            while (a != b) {
                while (idx[static_cast<size_t>(a)] > idx[static_cast<size_t>(b)]) a = dom[static_cast<size_t>(a)];
                while (idx[static_cast<size_t>(b)] > idx[static_cast<size_t>(a)]) b = dom[static_cast<size_t>(b)];
            }
            return a;
        };
        for (bool changed = true; changed;) {
            changed = false;
            for (int b : rpo) {
                int nd = -1;
                preds(b, [&](int p) {
                    if (idx[static_cast<size_t>(p)] < 0 || dom[static_cast<size_t>(p)] < 0) return;
                    nd = nd < 0 ? p : intersect(p, nd);
                });
                if (nd >= 0 && dom[static_cast<size_t>(b)] != nd) {
                    dom[static_cast<size_t>(b)] = nd;
                    changed = true;
                }
            }
        }
        return dom;
    }

    bool dominates(int a, int b) const {
        for (int x = b, guard = 0; x >= 0 && guard <= n_; x = idom_[static_cast<size_t>(x)], ++guard) {
            if (x == a) return true;
            if (x == n_) return false;
        }
        return false;
    }

    bool postDominates(int a, int b) const {
        for (int x = b, guard = 0; x >= 0 && guard <= n_; x = ipdom_[static_cast<size_t>(x)], ++guard) {
            if (x == a) return true;
            if (x == n_) return false;
        }
        return false;
    }

    int ipdom(int b) const {
        const int p = ipdom_[static_cast<size_t>(b)];
        return p == n_ ? -1 : p;
    }

    bool inBody(const Ctx& c, int b) const { return c.body && (*c.body)[static_cast<size_t>(b)]; }

    // ---- emission
    // A jump that leaves the current construct: continue / break / goto.
    bool jumpEdge(int s, const Ctx& c, int indent, const std::vector<uint64_t>& addrs) {
        if (c.header >= 0 && s == c.header) {
            emit("continue;", indent, addrs);
            return true;
        }
        if (c.inSwitch && s == c.switchFollow) {
            emit("break;", indent, addrs);
            return true;
        }
        if (c.header >= 0 && s == c.follow) {
            if (c.inSwitch) emitGoto(s, indent, addrs);
            else emit("break;", indent, addrs);
            return true;
        }
        return false;
    }

    // The follow of a branch, kept inside the current construct.
    int branchFollow(int b, int stop, const Ctx& c) const {
        int f = ipdom(b);
        if (c.header >= 0 && f >= 0 && (f == c.header || !inBody(c, f))) f = -1;
        if (stop >= 0 && (f < 0 || (f != stop && postDominates(f, stop)))) f = stop;
        return f;
    }

    // Emits the region starting at b up to (not including) stop. Returns true
    // when control reaches stop, false when the region ended with a jump.
    bool emitSeq(int b, int stop, const Ctx& c, int indent, int depth) {
        while (b >= 0 && b != stop) {
            const Block& bb = blk(b);
            if (emitted_[static_cast<size_t>(b)] || depth > kMaxDepth) {
                // A short exit (return x0; / throw e;) reads better repeated than jumped to.
                if (smallExit(b)) emitExit(b, indent);
                else emitGoto(b, indent, {});
                return false;
            }
            if (header_[static_cast<size_t>(b)] && c.header != b) {
                emitLoop(b, c, indent, depth);
                const int f = loopFollow_[static_cast<size_t>(b)];
                if (f < 0) return false;
                if (f == stop) return true;
                if (jumpEdge(f, c, indent, {})) return false;
                b = f;
                continue;
            }
            markStart(b);
            for (const std::string& note : bb.notes) emit(note, indent, {bb.addr});
            for (const Stmt& s : bb.stmts) {
                if (s.removed) continue;
                emit(s.def >= 0 ? s.defName + " = " + render(s.rhs) + ";" : render(s.rhs) + ";", indent, s.addrs);
            }
            const Term& t = bb.term;
            switch (t.kind) {
            case TermKind::Return:
                emit(t.text.empty() ? "return;" : "return " + render(t.text) + ";", indent, t.addrs);
                return false;
            case TermKind::Throw:
                emit("throw " + render(t.text) + ";", indent, t.addrs);
                return false;
            case TermKind::Stop:
                if (!t.text.empty()) emit(render(t.text) + ";", indent, t.addrs);
                return false;
            case TermKind::Fall: {
                if (bb.succ.empty()) return false;
                const int s = bb.succ[0];
                if (s == stop) return true;
                if (jumpEdge(s, c, indent, t.addrs)) return false;
                b = s;
                break;
            }
            case TermKind::Cond: {
                const int follow = branchFollow(b, stop, c);
                emitIf(b, follow, c, indent, depth);
                if (follow < 0) return false;
                if (follow == stop) return true;
                if (jumpEdge(follow, c, indent, {})) return false;
                b = follow;
                break;
            }
            case TermKind::Switch: {
                const int follow = branchFollow(b, stop, c);
                emitSwitch(b, follow, c, indent, depth);
                if (follow < 0) return false;
                if (follow == stop) return true;
                if (jumpEdge(follow, c, indent, {})) return false;
                b = follow;
                break;
            }
            }
        }
        return true;
    }

    bool smallExit(int b) const {
        const Block& bb = blk(b);
        if (!bb.succ.empty() || !bb.notes.empty()) return false;
        if (bb.term.kind != TermKind::Return && bb.term.kind != TermKind::Throw) return false;
        int live = 0;
        for (const Stmt& s : bb.stmts) live += s.removed ? 0 : 1;
        return live <= 2;
    }

    void emitExit(int b, int indent) {
        const Block& bb = blk(b);
        for (const Stmt& s : bb.stmts)
            if (!s.removed) emit(s.def >= 0 ? s.defName + " = " + render(s.rhs) + ";" : render(s.rhs) + ";", indent, s.addrs);
        const Term& t = bb.term;
        if (t.kind == TermKind::Throw) emit("throw " + render(t.text) + ";", indent, t.addrs);
        else emit(t.text.empty() ? "return;" : "return " + render(t.text) + ";", indent, t.addrs);
    }

    void markStart(int b) {
        emitted_[static_cast<size_t>(b)] = 1;
        start_[static_cast<size_t>(b)] = static_cast<int>(out_.size());
    }

    // An arm of an if: nothing (reaches the follow), a jump, or a nested region.
    bool armEmpty(int s, int follow) const { return s == follow; }

    void emitArm(int s, int follow, const Ctx& c, int indent, int depth, const std::vector<uint64_t>& addrs) {
        if (jumpEdge(s, c, indent, addrs)) return;
        emitSeq(s, follow, c, indent, depth + 1);
    }

    void emitIf(int b, int follow, const Ctx& c, int indent, int depth) {
        const Block& bb = blk(b);
        const int taken = bb.succ[0], fall = bb.succ.size() > 1 ? bb.succ[1] : bb.succ[0];
        const CondTree& cnd = bb.term.cond;
        const bool tEmpty = armEmpty(taken, follow), fEmpty = armEmpty(fall, follow);
        if (tEmpty && fEmpty) return;
        // The fall-through arm first (address order), as "if (!cond)".
        const int first = fEmpty ? taken : fall, second = fEmpty || tEmpty ? -1 : taken;
        const size_t ifLine = out_.size();
        emit("if (" + renderTree(fEmpty ? cnd : negate(cnd)) + ") {", indent, bb.term.addrs);
        emitArm(first, follow, c, indent + 1, depth, {});
        const bool firstEmpty = out_.size() == ifLine + 1;  // its code was all dead
        if (second < 0) {
            if (firstEmpty) out_.pop_back();
            else emit("}", indent, {});
            return;
        }
        if (firstEmpty) {  // if (cond) { taken }
            out_[ifLine].text = "if (" + renderTree(cnd) + ") {";
        } else {
            emit("} else {", indent, {});
        }
        const size_t before = out_.size();
        emitArm(second, follow, c, indent + 1, depth, {});
        if (firstEmpty && out_.size() == before) {
            out_.pop_back();  // both arms empty: the "if" line goes too
            return;
        }
        if (!firstEmpty && out_.size() == before) out_.pop_back();  // drop "} else {"
        emit("}", indent, {});
    }

    void emitSwitch(int b, int follow, const Ctx& c, int indent, int depth) {
        const Block& bb = blk(b);
        emit("switch (" + render(bb.term.text) + ") {", indent, bb.term.addrs);
        Ctx sc = c;
        sc.inSwitch = true;
        sc.switchFollow = follow;
        const auto body = [&](int target) {
            if (target == follow) {
                emit("break;", indent + 2, {});
                return;
            }
            if (jumpEdge(target, sc, indent + 2, {})) return;
            if (emitSeq(target, follow, sc, indent + 2, depth + 1)) emit("break;", indent + 2, {});
        };
        for (size_t i = 0; i < bb.term.cases.size(); ++i) {
            const auto& [keys, target] = bb.term.cases[i];
            if (i < bb.term.caseLabels.size() && !bb.term.caseLabels[i].empty())
                for (const std::string& label : bb.term.caseLabels[i]) emit("case " + label + ":", indent + 1, {});
            else
                for (int64_t k : keys) emit("case " + std::to_string(k) + ":", indent + 1, {});
            body(target);
        }
        if (!bb.term.noDefault && !bb.succ.empty() && bb.succ[0] != follow) {
            emit("default:", indent + 1, {});
            body(bb.succ[0]);
        }
        emit("}", indent, {});
    }

    void emitLoop(int h, const Ctx& outer, int indent, int depth) {
        Ctx c;
        c.header = h;
        c.follow = loopFollow_[static_cast<size_t>(h)];
        c.body = &bodies_.at(h);
        (void)outer;
        const Block& hb = blk(h);
        bool bare = true;
        for (const Stmt& s : hb.stmts) bare = bare && s.removed;
        if (bare && hb.notes.empty() && hb.term.kind == TermKind::Cond && hb.succ.size() == 2 &&
            (hb.succ[0] == c.follow) != (hb.succ[1] == c.follow)) {
            // while (cond) { body }
            markStart(h);
            const bool exitTaken = hb.succ[0] == c.follow;
            const int bodyStart = exitTaken ? hb.succ[1] : hb.succ[0];
            emit("while (" + renderTree(exitTaken ? negate(hb.term.cond) : hb.term.cond) + ") {", indent, hb.term.addrs);
            if (bodyStart != h) emitSeq(bodyStart, -1, c, indent + 1, depth + 1);
        } else {
            emit("while (true) {", indent, {});
            emitSeq(h, -1, c, indent + 1, depth + 1);
        }
        // "if (c) { X } else { continue; }" closing the body: the else is implied.
        const size_t n = out_.size();
        if (n >= 3 && out_[n - 3].text == "} else {" && out_[n - 3].indent == indent + 1 && out_[n - 2].text == "continue;" &&
            out_[n - 2].indent == indent + 2 && out_[n - 1].text == "}" && out_[n - 1].indent == indent + 1)
            out_.erase(out_.begin() + static_cast<std::ptrdiff_t>(n - 3), out_.begin() + static_cast<std::ptrdiff_t>(n - 1));
        if (!out_.empty() && out_.back().text == "continue;" && out_.back().indent == indent + 1) out_.pop_back();
        emit("}", indent, {});
    }

    void insertLabels(size_t bodyStart) {
        if (labels_.empty()) return;
        std::multimap<int, int> at;  // line index -> block
        for (int b : labels_)
            if (start_[static_cast<size_t>(b)] >= 0) at.insert({start_[static_cast<size_t>(b)], b});
        std::vector<Line> merged;
        merged.reserve(out_.size() + at.size());
        for (size_t i = 0; i < bodyStart; ++i) merged.push_back(std::move(out_[i]));
        auto it = at.begin();
        for (size_t i = bodyStart; i <= out_.size(); ++i) {
            for (; it != at.end() && static_cast<size_t>(it->first) <= i; ++it) {
                const int indent = i < out_.size() ? std::max(out_[i].indent - 1, 0) : 0;
                merged.push_back({label(it->second) + ":", indent, {blk(it->second).addr}});
            }
            if (i < out_.size()) merged.push_back(std::move(out_[i]));
        }
        out_ = std::move(merged);
    }

    const Fn& fn_;
    std::vector<Line>& out_;
    int n_;
    std::vector<std::vector<int>> preds_;
    std::vector<int> rpoIdx_, prpoIdx_, idom_, ipdom_;
    std::vector<char> header_;
    std::unordered_map<int, std::vector<char>> bodies_;
    std::vector<int> loopFollow_;
    std::vector<char> emitted_;
    std::vector<int> start_;
    std::set<int> labels_;
};

// The "return;" that ends a void function's body says nothing.
void dropTrailingReturn(std::vector<Line>& lines) {
    if (lines.size() < 2) return;
    const Line& last = lines.back();
    const Line& prev = lines[lines.size() - 2];
    const bool labelled = !prev.text.empty() && prev.text.back() == ':';
    if (last.text == "return;" && last.indent == 1 && !labelled) lines.pop_back();
}

}  // namespace

// ===========================================================================
// Nesting cleanup (on the finished lines)
// ===========================================================================

namespace {

bool opensIf(const std::string& t) { return t.rfind("if (", 0) == 0 && t.size() > 7 && t.compare(t.size() - 3, 3, ") {") == 0; }

bool leaves(const std::string& t) {
    return t == "break;" || t == "continue;" || t == "return;" || t.rfind("return ", 0) == 0 || t.rfind("throw ", 0) == 0 ||
           t.rfind("goto ", 0) == 0;
}

// The "}" that closes the block opened at line `open`, and the "} else ..." in between (npos: none). False when the
// lines do not nest as expected.
bool blockEnd(const std::vector<Line>& lines, size_t open, size_t& elseAt, size_t& close) {
    const int indent = lines[open].indent;
    elseAt = std::string::npos;
    for (size_t i = open + 1; i < lines.size(); ++i) {
        const Line& l = lines[i];
        if (l.indent > indent) continue;
        if (!l.text.empty() && l.text.back() == ':') continue;  // a goto label sits one level out
        if (l.indent < indent) return false;
        if (l.text == "}") {
            close = i;
            return true;
        }
        if (l.text.rfind("} else", 0) != 0) return false;
        if (elseAt == std::string::npos) elseAt = i;
    }
    return false;
}

void mergeInto(Line& to, const Line& from) {
    to.addrs.insert(to.addrs.end(), from.addrs.begin(), from.addrs.end());
    std::sort(to.addrs.begin(), to.addrs.end());
    to.addrs.erase(std::unique(to.addrs.begin(), to.addrs.end()), to.addrs.end());
}

void dedent(std::vector<Line>& lines, size_t from, size_t to) {
    for (size_t i = from; i < to; ++i) lines[i].indent = std::max(lines[i].indent - 1, 0);
}

// The condition of "if (c) {", parenthesized when it binds looser than && (a disjunction or a ternary).
std::string conditionOf(const std::string& t) {
    std::string c = t.substr(4, t.size() - 7);
    return c.find(" || ") != std::string::npos || c.find(" ? ") != std::string::npos ? "(" + c + ")" : c;
}

bool flattenOnce(std::vector<Line>& lines, size_t i) {
    const std::string t = lines[i].text;
    if (!opensIf(t)) return false;
    size_t elseAt = 0, close = 0;
    if (!blockEnd(lines, i, elseAt, close)) return false;
    const int indent = lines[i].indent;
    const auto at = [&](size_t k) { return lines.begin() + static_cast<std::ptrdiff_t>(k); };
    if (elseAt != std::string::npos && lines[elseAt].text == "} else {") {
        // if (c) { ...; return; } else { rest }  ->  if (c) { ...; return; } rest
        if (elseAt > i + 1 && lines[elseAt - 1].indent == indent + 1 && leaves(lines[elseAt - 1].text)) {
            dedent(lines, elseAt + 1, close);
            mergeInto(lines[elseAt - 1], lines[close]);
            lines.erase(at(close));
            lines[elseAt].text = "}";
            return true;
        }
        // else { if (d) {...} [else ...] }  ->  else if (d) {...} [else ...]
        const size_t inner = elseAt + 1;
        size_t innerElse = 0, innerClose = 0;
        if (inner < close && lines[inner].indent == indent + 1 && opensIf(lines[inner].text) &&
            blockEnd(lines, inner, innerElse, innerClose) && innerClose + 1 == close) {
            lines[elseAt].text = "} else " + lines[inner].text;
            mergeInto(lines[elseAt], lines[inner]);
            mergeInto(lines[innerClose], lines[close]);
            dedent(lines, inner + 1, close);
            lines.erase(at(close));
            lines.erase(at(inner));
            return true;
        }
        return false;
    }
    if (elseAt != std::string::npos) return false;
    // if (a) { if (b) { body } }  ->  if (a && b) { body }
    const size_t inner = i + 1;
    size_t innerElse = 0, innerClose = 0;
    if (inner < close && lines[inner].indent == indent + 1 && opensIf(lines[inner].text) && blockEnd(lines, inner, innerElse, innerClose) &&
        innerElse == std::string::npos && innerClose + 1 == close) {
        lines[i].text = "if (" + conditionOf(t) + " && " + conditionOf(lines[inner].text) + ") {";
        mergeInto(lines[i], lines[inner]);
        mergeInto(lines[close], lines[innerClose]);
        dedent(lines, inner + 1, innerClose);
        lines.erase(at(innerClose));
        lines.erase(at(inner));
        return true;
    }
    return false;
}

}  // namespace

void flattenNesting(std::vector<Line>& lines) {
    // Inner blocks first (from the bottom), repeated while something changes.
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t i = lines.size(); i-- > 0;)
            if (i < lines.size() && flattenOnce(lines, i)) changed = true;
    }
}

namespace {

// ===========================================================================
// Dalvik
// ===========================================================================

std::string javaType(std::string_view d) {
    int dims = 0;
    while (!d.empty() && d[0] == '[') ++dims, d.remove_prefix(1);
    std::string base;
    switch (d.empty() ? '?' : d[0]) {
    case 'V': base = "void"; break;
    case 'Z': base = "boolean"; break;
    case 'B': base = "byte"; break;
    case 'S': base = "short"; break;
    case 'C': base = "char"; break;
    case 'I': base = "int"; break;
    case 'J': base = "long"; break;
    case 'F': base = "float"; break;
    case 'D': base = "double"; break;
    case 'L': {
        std::string_view n = d.substr(1, d.size() >= 2 ? d.size() - 2 : 0);
        const size_t slash = n.rfind('/');
        base = std::string(slash == std::string_view::npos ? n : n.substr(slash + 1));
        break;
    }
    default: base = std::string(d);
    }
    for (int i = 0; i < dims; ++i) base += "[]";
    return base;
}

char hintOf(std::string_view d) {
    if (d.empty()) return '-';
    if (d[0] == 'L' || d[0] == '[') return 'L';
    if (d[0] == 'Z') return 'Z';
    if (d[0] == 'C') return 'C';
    return '-';
}

char kindOf(std::string_view d) {
    if (d.empty()) return 0;
    if (d[0] == 'L' || d[0] == '[') return 'L';
    if (d[0] == 'Z') return 'Z';
    return 'N';
}

bool wideType(std::string_view d) { return !d.empty() && (d[0] == 'J' || d[0] == 'D'); }

std::string intText(int64_t v, bool wide) {
    std::string s = (v >= 0x10000 || v <= -0x10000) ? signedHex(v) : std::to_string(v);
    if (wide) s += 'L';
    return s;
}

std::string floatText(double v, bool isDouble) {
    char b[48];
    std::snprintf(b, sizeof b, "%.9g", v);
    std::string s = b;
    if (s.find_first_of(".eEn") == std::string::npos) s += ".0";
    if (!isDouble) s += 'f';
    return s;
}

struct TryInfo {
    uint32_t start = 0, end = 0;
    std::vector<std::pair<std::string, uint32_t>> handlers;  // type (empty: any), handler pc
};

std::vector<TryInfo> parseTries(const DexFile& dex, const DexFile::CodeItem& code,
                                const std::function<std::string(std::string_view)>& typeName) {
    std::vector<TryInfo> out;
    if (!code.tries) return out;
    const uint8_t* d = dex.data();
    const size_t size = dex.sizeBytes();
    size_t pos = static_cast<size_t>(code.offset) + 16 + static_cast<size_t>(code.insnsSize) * 2;
    if (code.insnsSize & 1) pos += 2;
    const size_t triesAt = pos;
    const size_t handlersAt = triesAt + static_cast<size_t>(code.tries) * 8;
    if (handlersAt > size) return out;
    for (uint32_t t = 0; t < code.tries; ++t) {
        const uint8_t* p = d + triesAt + static_cast<size_t>(t) * 8;
        TryInfo r;
        r.start = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 |
                  static_cast<uint32_t>(p[3]) << 24;
        r.end = r.start + static_cast<uint32_t>(p[4] | p[5] << 8);
        size_t hp = handlersAt + static_cast<uint32_t>(p[6] | p[7] << 8);
        int32_t n = 0;
        if (hp < size && leb::readSleb(d, size, hp, n)) {
            const int32_t pairs = n < 0 ? -n : n;
            for (int32_t k = 0; k < pairs && k < 4096; ++k) {
                uint32_t type = 0, addr = 0;
                if (!leb::readUleb(d, size, hp, type) || !leb::readUleb(d, size, hp, addr)) break;
                r.handlers.push_back({typeName(dex.typeDescriptor(type)), addr});
            }
            if (n <= 0) {
                uint32_t addr = 0;
                if (leb::readUleb(d, size, hp, addr)) r.handlers.push_back({std::string(), addr});
            }
        }
        out.push_back(std::move(r));
    }
    return out;
}

class DalvikDecompiler {
public:
    DalvikDecompiler(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const Naming& naming)
        : a_(a), m_(m), dex_(*a.dexes()[m.dex]), naming_(naming) {}

    Output run() {
        Output out;
        const uint32_t mi = m_.method.methodIdx;
        clsDesc_ = std::string(dex_.typeDescriptor(dex_.methodClass(mi)));
        isStatic_ = (m_.method.accessFlags & 0x8) != 0;
        const std::string name(dex_.methodName(mi));
        const std::string shownName = methodName(mi);
        const uint32_t proto = dex_.methodProto(mi);
        retDesc_ = std::string(dex_.typeDescriptor(dex_.protoReturnType(proto)));
        const std::vector<uint32_t> params = dex_.protoParameters(proto);
        isCtor_ = name == "<init>";

        const bool hasCode = m_.method.codeOff && dex_.codeItem(m_.method.codeOff, code_) && code_.insnsSize > 0;
        const int regs = hasCode ? code_.registers : 0;
        names_.resize(static_cast<size_t>(regs));
        kinds_.assign(static_cast<size_t>(regs), 0);
        for (int r = 0; r < regs; ++r) names_[static_cast<size_t>(r)] = "v" + std::to_string(r);

        // Parameters occupy the last `ins` registers.
        int reg = hasCode ? code_.registers - code_.ins : 0;
        if (!isStatic_) {
            if (hasCode && reg >= 0 && reg < regs) names_[static_cast<size_t>(reg)] = "this", kinds_[static_cast<size_t>(reg)] = 'L';
            thisReg_ = reg++;
        }
        for (size_t k = 0; k < params.size(); ++k) {
            const std::string_view pd = dex_.typeDescriptor(params[k]);
            const std::string pn = "arg" + std::to_string(k);
            if (hasCode && reg >= 0 && reg < regs) names_[static_cast<size_t>(reg)] = pn, kinds_[static_cast<size_t>(reg)] = kindOf(pd);
            out.vars.push_back(Var{pn, typeName(pd), std::string(), true});
            reg += wideType(pd) ? 2 : 1;
        }

        std::string flags = DexFile::accessFlagsToString(m_.method.accessFlags, true);
        for (const char* drop : {"constructor", "bridge", "varargs", "synthetic"}) {
            const size_t at = flags.find(drop);
            if (at == std::string::npos) continue;
            flags.erase(at, std::strlen(drop));
            if (at < flags.size() && flags[at] == ' ') flags.erase(at, 1);
            else if (at > 0 && flags[at - 1] == ' ') flags.erase(at - 1, 1);
        }
        // The signature: prefix + "type name, ..." + suffix, rebuilt with the user's names and types.
        if (name == "<clinit>") {
            out.headerPrefix = "static";
        } else {
            out.headerPrefix = flags.empty() ? "" : flags + " ";
            if (!isCtor_) out.returnAt = out.headerPrefix.size(), out.returnType = typeName(retDesc_);
            out.headerPrefix += isCtor_ ? typeName(clsDesc_) : typeName(retDesc_) + " " + shownName;
            out.headerPrefix += "(";
            out.headerSuffix = ")";
        }
        const std::string javaName = DexFile::descriptorToJava(clsDesc_);
        const std::string originalName = naming_.mapping ? naming_.mapping->originalClass(javaName) : javaName;
        out.lines.push_back({"// " + (originalName == javaName ? javaName : originalName + "  (" + javaName + " in the app)"), 0, {}});
        out.headerLine = static_cast<int>(out.lines.size());
        if (!hasCode) {
            out.headerSuffix += ";";
            out.lines.push_back({std::string(), 0, {}});
            out.lines.push_back({"// no code: abstract or native", 0, {}});
            applyUserNames(out, {}, {}, false);
            return out;
        }
        out.headerSuffix += " {";
        out.lines.push_back({std::string(), 0, {0}});

        if (!build(out.error)) return out;
        simplify(fn_);
        if (recoverStringSwitches(fn_)) {  // the index variable is gone: let single-use values fold again
            removeDead(fn_, liveness(fn_));
            foldTemporaries(fn_, liveness(fn_));
            removeDead(fn_, liveness(fn_));
        }
        if (std::getenv("APKSPY_DECOMPILER_DUMP")) dumpFn(fn_);
        Structurer(fn_, out.lines).run(1);
        flattenNesting(out.lines);
        if (retDesc_ == "V") dropTrailingReturn(out.lines);
        out.lines.push_back({"}", 0, {}});
        declareLocals(out, valueTypes(), false);
        applyUserNames(out, {}, {}, false);
        return out;
    }

    // Types of the values each register is given (by its shown name), for the declarations.
    std::map<std::string, std::vector<std::string>> valueTypes() const {
        // The assignments still shown decide; folded or dead ones only when nothing else says.
        std::map<std::string, std::vector<std::string>> shown, all;
        for (const Block& b : fn_.blocks)
            for (const Stmt& s : b.stmts) {
                if (s.def < 0 || s.vtype.empty()) continue;
                all[s.defName].push_back(s.vtype);
                if (!s.removed) shown[s.defName].push_back(s.vtype);
            }
        for (auto& [name, types] : all)
            if (!shown.count(name)) shown[name] = std::move(types);
        return shown;
    }

private:
    std::string R(uint32_t r, char hint = '-') const {
        return ph(static_cast<int>(r), r < names_.size() ? names_[r] : "v" + std::to_string(r), hint);
    }

    void note(uint32_t r, char k) {
        if (!k || r >= kinds_.size()) return;
        char& cur = kinds_[r];
        if (!cur) cur = k;
        else if (cur != k) cur = '?';
    }

    void inferKinds() {
        char lastRet = 0;
        for (uint32_t pc = 0; pc < code_.insnsSize;) {
            const dalvik::Insn in = dalvik::decode(code_, pc);
            pc += std::max<uint32_t>(in.size, 1);
            if (!in.valid || in.payload) continue;
            const uint8_t op = in.opcode;
            const uint32_t A = in.regs[0];
            const auto& info = dalvik::opInfo(op);
            if (info.flow == dalvik::Flow::Invoke && info.ref == dalvik::RefKind::Method && in.index < dex_.methodCount())
                lastRet = kindOf(dex_.typeDescriptor(dex_.protoReturnType(dex_.methodProto(in.index))));
            else if (op == 0x24 || op == 0x25) lastRet = 'L';
            if ((op >= 0x07 && op <= 0x09) || op == 0x0c || op == 0x0d || op == 0x1a || op == 0x1b || op == 0x1c ||
                op == 0x1f || op == 0x22 || op == 0x23 || op == 0x46)
                note(A, 'L');
            else if (op == 0x0a || op == 0x0b) note(A, lastRet == 'Z' ? 'Z' : 'N');
            else if (op == 0x20 || op == 0x47) note(A, 'Z');
            else if (op == 0x21 || (op >= 0x2d && op <= 0x31) || op == 0x44 || op == 0x45 || (op >= 0x48 && op <= 0x4a) ||
                     (op >= 0x7b && op <= 0xe2))
                note(A, 'N');
            else if ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66))
                if (in.index < dex_.fieldCount()) note(A, kindOf(dex_.typeDescriptor(dex_.fieldType(in.index))));
        }
    }

    std::string owner(uint32_t typeIdx) const {
        const std::string_view d = dex_.typeDescriptor(typeIdx);
        return d == clsDesc_ ? std::string() : typeName(d) + ".";
    }

    // javaType(), with the mapping's original class name.
    std::string typeName(std::string_view d) const {
        if (!naming_.mapping) return javaType(d);
        size_t dims = 0;
        while (dims < d.size() && d[dims] == '[') ++dims;
        const std::string_view base = d.substr(dims);
        if (base.size() < 3 || base[0] != 'L') return javaType(d);
        const std::string java = DexFile::descriptorToJava(base);
        std::string original = naming_.mapping->originalClass(java);
        if (original == java) return javaType(d);
        original.erase(0, original.find_last_of('.') + 1);
        for (size_t i = 0; i < dims; ++i) original += "[]";
        return original;
    }

    // A type as mapping.txt writes it in member signatures: "int", "com.example.Name[]".
    std::string mappingType(std::string_view d) const {
        size_t dims = 0;
        while (dims < d.size() && d[dims] == '[') ++dims;
        const std::string_view base = d.substr(dims);
        std::string out = !base.empty() && base[0] == 'L' ? naming_.mapping->originalClass(DexFile::descriptorToJava(base)) : javaType(base);
        for (size_t i = 0; i < dims; ++i) out += "[]";
        return out;
    }

    // The original name of member `obf` of class `cls` (a descriptor) or of a class it inherits from, "" when unmapped.
    // `signature` is the mapping-file form the entry must match: "type " for fields, "(arguments)" for methods.
    std::string mappedMember(std::string_view cls, const std::string& obf, const std::string& signature, bool method) const {
        std::vector<std::string> chain = a_.superChain(cls);
        if (chain.empty()) chain.push_back(std::string(cls));
        for (const std::string& step : chain) {
            const std::string java = !step.empty() && step[0] == 'L' ? DexFile::descriptorToJava(step) : step;
            const std::string original = naming_.mapping->originalMember(java, obf, signature, method);
            if (!original.empty()) return original;
        }
        return {};
    }

    std::string methodName(uint32_t mi) const {
        const std::string obf(dex_.methodName(mi));
        if (!naming_.mapping || obf.empty() || obf[0] == '<') return obf;
        std::string args;
        for (uint32_t p : dex_.protoParameters(dex_.methodProto(mi)))
            args += (args.empty() ? "" : ",") + mappingType(dex_.typeDescriptor(p));
        const std::string original = mappedMember(dex_.typeDescriptor(dex_.methodClass(mi)), obf, "(" + args + ")", true);
        return original.empty() ? obf : original;
    }

    std::string fieldName(uint32_t fi) const {
        const std::string obf(dex_.fieldName(fi));
        if (!naming_.mapping) return obf;
        const std::string original =
            mappedMember(dex_.typeDescriptor(dex_.fieldClass(fi)), obf, mappingType(dex_.typeDescriptor(dex_.fieldType(fi))) + " ", false);
        return original.empty() ? obf : original;
    }

    // "R.string.app_name" for a constant that is one of the app's resource ids, else "".
    std::string resourceName(int64_t value) const {
        if (!naming_.resources || value < 0x7f000000 || value > 0x7fffffff) return {};
        ResourceTable::Item item;
        if (!naming_.resources->lookup(static_cast<uint32_t>(value), item) || item.type.empty() || item.name.empty()) return {};
        std::string name = item.name;
        std::replace(name.begin(), name.end(), '.', '_');
        return "R." + item.type + "." + name;
    }

    bool build(std::string& error) {
        const std::vector<ApkAnalysis::BasicBlock> cfg = a_.controlFlowGraph(m_);
        if (cfg.empty()) {
            error = "no control-flow graph for this method";
            return false;
        }
        if (cfg.size() > kMaxBlocks) {
            error = "method too large to decompile (" + std::to_string(cfg.size()) + " blocks)";
            return false;
        }
        inferKinds();
        fn_.regCount = code_.registers;
        fn_.labelPrefix = "L_";
        std::map<uint32_t, int> blockAt;
        for (size_t i = 0; i < cfg.size(); ++i) blockAt[cfg[i].startPc] = static_cast<int>(i);
        fn_.blocks.resize(cfg.size());
        for (size_t i = 0; i < cfg.size(); ++i) {
            Block& blk = fn_.blocks[i];
            blk.addr = cfg[i].startPc;
            for (uint32_t s : cfg[i].successors) blk.succ.push_back(static_cast<int>(s));
            for (uint32_t h : cfg[i].exceptional) blk.exc.push_back(static_cast<int>(h));
            translateBlock(cfg[i], blk, blockAt);
        }
        literalsFromUses();
        // Roots: the entry, then the catch handlers.
        fn_.roots.push_back(0);
        std::map<int, std::vector<std::string>> catches;
        for (const TryInfo& t : parseTries(dex_, code_, [this](std::string_view d) { return typeName(d); })) {
            std::string what;
            for (const auto& [type, pc] : t.handlers) {
                auto it = blockAt.find(pc);
                if (it == blockAt.end()) continue;
                auto& list = catches[it->second];
                const std::string tn = type.empty() ? "any" : type;
                if (std::find(list.begin(), list.end(), tn) == list.end()) list.push_back(tn);
                char buf[64];
                std::snprintf(buf, sizeof buf, "%s -> %s%04x", tn.c_str(), fn_.labelPrefix.c_str(), pc);
                if (!what.empty()) what += ", ";
                what += buf;
            }
            auto it = blockAt.find(t.start);
            if (it != blockAt.end() && !what.empty()) {
                char range[48];
                std::snprintf(range, sizeof range, "// try %04x-%04x: catch ", t.start, t.end);
                fn_.blocks[static_cast<size_t>(it->second)].notes.push_back(range + what);
            }
        }
        for (const auto& [b, types] : catches) {
            if (b == 0) continue;
            std::string joined;
            for (const std::string& t : types) joined += (joined.empty() ? "" : " | ") + t;
            fn_.roots.push_back(b);
            fn_.rootNotes.push_back("// catch (" + joined + ")");
        }
        return true;
    }

    void translateBlock(const ApkAnalysis::BasicBlock& cb, Block& blk, const std::map<uint32_t, int>& blockAt) {
        std::vector<dalvik::Insn> insns;
        for (uint32_t pc = cb.startPc; pc < cb.endPc && pc < code_.insnsSize;) {
            dalvik::Insn in = dalvik::decode(code_, pc);
            pc += std::max<uint32_t>(in.size, 1);
            if (in.payload) continue;
            insns.push_back(in);
        }
        if (insns.empty()) return;
        const dalvik::Insn& last = insns.back();
        const dalvik::Flow lastFlow = last.valid ? dalvik::opInfo(last.opcode).flow : dalvik::Flow::Normal;
        const bool lastIsTerm = lastFlow == dalvik::Flow::Goto || lastFlow == dalvik::Flow::Branch ||
                                lastFlow == dalvik::Flow::Switch || lastFlow == dalvik::Flow::Return ||
                                lastFlow == dalvik::Flow::Throw;
        const size_t body = lastIsTerm ? insns.size() - 1 : insns.size();
        for (size_t i = 0; i < body; ++i) {
            const dalvik::Insn* next = i + 1 < body ? &insns[i + 1] : nullptr;
            if (translate(insns[i], next, blk)) ++i;  // the move-result was folded in
        }
        Term& t = blk.term;
        t.addrs = {last.pc};
        if (!lastIsTerm) {
            t.kind = TermKind::Fall;
            t.addrs.clear();
            if (blk.succ.empty()) t.kind = TermKind::Stop;
            return;
        }
        const uint8_t op = last.opcode;
        const uint32_t A = last.regs[0], B = last.regs[1];
        switch (lastFlow) {
        case dalvik::Flow::Return:
            t.kind = TermKind::Return;
            if (op != 0x0e) t.text = R(A, hintOf(retDesc_));
            break;
        case dalvik::Flow::Throw:
            t.kind = TermKind::Throw;
            t.text = R(A, 'L');
            break;
        case dalvik::Flow::Goto:
            t.kind = TermKind::Fall;
            break;
        case dalvik::Flow::Branch: {
            if (blk.succ.size() < 2) {
                t.kind = TermKind::Fall;
                break;
            }
            static const char* const kOps[] = {"==", "!=", "<", ">=", ">", "<="};
            t.kind = TermKind::Cond;
            if (op >= 0x32 && op <= 0x37) {
                const char k = valueKind(blk, A) == 'L' || valueKind(blk, B) == 'L' ? 'L' : '-';
                t.text = cond(R(A, k), kOps[op - 0x32], R(B, k));
            } else {
                const char kind = valueKind(blk, A);
                const char* o = kOps[op - 0x38];
                if (kind == 'L') t.text = cond(R(A, 'L'), o, "null");
                else if (kind == 'Z' && op == 0x38) t.text = cond(R(A, 'Z'), "!", "");
                else if (kind == 'Z' && op == 0x39) t.text = cond(R(A, 'Z'), "?", "");
                else t.text = cond(R(A), o, "0");
            }
            break;
        }
        case dalvik::Flow::Switch: {
            t.kind = TermKind::Switch;
            t.text = R(A);
            const uint32_t p = static_cast<uint32_t>(static_cast<int64_t>(last.pc) + last.branch);
            if (p + 2 > code_.insnsSize) break;
            const uint16_t ident = code_.unit(p);
            const uint32_t count = code_.unit(p + 1);
            const auto u32 = [&](uint32_t at) { return static_cast<uint32_t>(code_.unit(at)) | static_cast<uint32_t>(code_.unit(at + 1)) << 16; };
            std::map<int, std::vector<int64_t>> byTarget;
            std::vector<int> order;
            for (uint32_t i = 0; i < count; ++i) {
                int64_t key = 0;
                uint32_t relAt = 0;
                if (ident == 0x0100) {
                    if (p + 4 + 2 * count > code_.insnsSize) break;
                    key = static_cast<int32_t>(u32(p + 2)) + static_cast<int64_t>(i);
                    relAt = p + 4 + 2 * i;
                } else if (ident == 0x0200) {
                    if (p + 2 + 4 * count > code_.insnsSize) break;
                    key = static_cast<int32_t>(u32(p + 2 + 2 * i));
                    relAt = p + 2 + 2 * count + 2 * i;
                } else {
                    break;
                }
                const uint32_t target = static_cast<uint32_t>(static_cast<int64_t>(last.pc) + static_cast<int32_t>(u32(relAt)));
                auto it = blockAt.find(target);
                if (it == blockAt.end()) continue;
                if (!byTarget.count(it->second)) order.push_back(it->second);
                byTarget[it->second].push_back(key);
            }
            for (int target : order) t.cases.push_back({byTarget[target], target});
            break;
        }
        default: break;
        }
    }

    std::string literal(const dalvik::Insn& in) const {
        const uint8_t op = in.opcode;
        if (op == 0x14 || op == 0x15)  // a full 32-bit value (or its high half), which is how resource ids are loaded
            if (const std::string res = resourceName(in.literal); !res.empty()) return res;
        if (op == 0x15) {  // const/high16: almost always a float
            float f;
            const uint32_t bits = static_cast<uint32_t>(in.literal);
            std::memcpy(&f, &bits, sizeof f);
            // 0x7f01xxxx..0x7f3fxxxx is where an app's resource ids live; as a float it would be a number near 1.7e38.
            const bool resourceRange = bits >> 24 == 0x7f && (bits >> 16 & 0xff) >= 1 && (bits >> 16 & 0xff) <= 0x3f;
            if (in.literal != 0 && !resourceRange) return floatText(f, false);
        }
        if (op == 0x19 && in.literal != 0) {
            double d;
            const uint64_t bits = static_cast<uint64_t>(in.literal);
            std::memcpy(&d, &bits, sizeof d);
            return floatText(d, true);
        }
        return intText(in.literal, op >= 0x16 && op <= 0x19);
    }

    // Returns true when `next` (a move-result) was consumed.
    bool translate(const dalvik::Insn& in, const dalvik::Insn* next, Block& blk) {
        Stmt s;
        s.addrs = {in.pc};
        if (!in.valid) {
            s.rhs = "/* invalid instruction */";
            s.sideEffect = true;
            blk.stmts.push_back(std::move(s));
            return false;
        }
        const uint8_t op = in.opcode;
        const auto& info = dalvik::opInfo(op);
        const uint32_t A = in.regs[0], B = in.regs[1], C = in.regs[2];
        const auto def = [&](uint32_t r, std::string rhs, bool atomic) {
            s.def = static_cast<int>(r);
            s.defName = r < names_.size() ? names_[r] : "v" + std::to_string(r);
            s.rhs = std::move(rhs);
            s.atomic = atomic;
        };
        const auto stmt = [&](std::string text) {
            s.rhs = std::move(text);
            s.sideEffect = true;
        };
        const auto moveResultOf = [&](std::string call) {
            if (next && next->valid && next->opcode >= 0x0a && next->opcode <= 0x0c) {
                def(next->regs[0], std::move(call), true);
                s.addrs.push_back(next->pc);
                return true;
            }
            s.rhs = std::move(call);
            return false;
        };
        bool consumed = false;

        if (op == 0x00) return false;
        if (op >= 0x01 && op <= 0x09) {
            def(A, R(B), true);
            s.moveFrom = static_cast<int>(B);
            s.vkind = op >= 0x07 ? 'L' : valueKind(blk, B);
        } else if (op >= 0x0a && op <= 0x0c) {
            def(A, "result", true);
        } else if (op == 0x0d) {
            def(A, "exception", true);
            s.vkind = 'L';
        } else if (op >= 0x12 && op <= 0x19) {
            def(A, literal(in), true);
            s.constant = true;
            s.smallLiteral = op <= 0x14 && (in.literal == 0 || in.literal == 1);
            if (op >= 0x16) s.vkind = 'N';
        } else if (op == 0x1a || op == 0x1b) {
            def(A, dalvik::refToString(dex_, dalvik::RefKind::String, in.index), true);
            s.constant = true;
        } else if (op == 0x1c) {
            def(A, typeName(dex_.typeDescriptor(in.index)) + ".class", true);
            s.constant = true;
        } else if (op == 0x1d || op == 0x1e) {
            stmt(std::string(op == 0x1d ? "monitorEnter(" : "monitorExit(") + R(A, 'L') + ")");
        } else if (op == 0x1f) {
            def(A, "(" + typeName(dex_.typeDescriptor(in.index)) + ") " + R(A, 'L'), false);
        } else if (op == 0x20) {
            def(A, R(B, 'L') + " instanceof " + typeName(dex_.typeDescriptor(in.index)), false);
        } else if (op == 0x21) {
            def(A, R(B, 'L') + ".length", true);
            s.readsMem = true;
        } else if (op == 0x22) {
            def(A, "new " + typeName(dex_.typeDescriptor(in.index)), true);
            s.sideEffect = s.newInstance = true;
        } else if (op == 0x23) {
            const std::string t = typeName(dex_.typeDescriptor(in.index));  // "int[]"
            const size_t br = t.find('[');
            def(A, "new " + (br == std::string::npos ? t : t.substr(0, br)) + "[" + R(B) + "]" +
                       (br == std::string::npos ? "" : t.substr(br + 2)),
                true);
            s.sideEffect = true;
        } else if (op == 0x24 || op == 0x25) {
            const std::string t = typeName(dex_.typeDescriptor(in.index));
            std::string args;
            for (uint32_t k = 0; k < in.regCount; ++k) args += (k ? ", " : "") + R(in.range ? in.regs[0] + k : in.regs[k]);
            s.sideEffect = true;
            consumed = moveResultOf("new " + t + "{" + args + "}");
        } else if (op == 0x26) {
            stmt("fillArray(" + R(A, 'L') + ", " + arrayData(in) + ")");
        } else if (op >= 0x2d && op <= 0x31) {
            static const char* const kCmp[] = {"Float.compare(", "Float.compare(", "Double.compare(", "Double.compare(", "Long.compare("};
            def(A, kCmp[op - 0x2d] + R(B) + ", " + R(C) + ")", true);
        } else if (op >= 0x44 && op <= 0x4a) {
            def(A, R(B, 'L') + "[" + R(C) + "]", true);
            s.readsMem = true;
        } else if (op >= 0x4b && op <= 0x51) {
            const char h = op == 0x4d ? 'L' : op == 0x4e ? 'Z' : op == 0x50 ? 'C' : '-';
            stmt(R(B, 'L') + "[" + R(C) + "] = " + R(A, h));
        } else if (op >= 0x52 && op <= 0x5f) {
            const std::string f = in.index < dex_.fieldCount() ? fieldName(in.index) : "field" + std::to_string(in.index);
            if (op <= 0x58) {
                def(A, R(B, 'L') + "." + f, true);
                s.readsMem = true;
            } else {
                const char h = in.index < dex_.fieldCount() ? hintOf(dex_.typeDescriptor(dex_.fieldType(in.index))) : '-';
                stmt(R(B, 'L') + "." + f + " = " + R(A, h));
            }
        } else if (op >= 0x60 && op <= 0x6d) {
            std::string f = "field" + std::to_string(in.index);
            char h = '-';
            if (in.index < dex_.fieldCount()) {
                f = owner(dex_.fieldClass(in.index)) + fieldName(in.index);
                h = hintOf(dex_.typeDescriptor(dex_.fieldType(in.index)));
            }
            if (op <= 0x66) {
                def(A, f, true);
                s.readsMem = true;
            } else {
                stmt(f + " = " + R(A, h));
            }
        } else if (info.flow == dalvik::Flow::Invoke) {
            consumed = invoke(in, next, blk, s);
            if (s.removed) return consumed;  // folded into a new-instance: already pushed
        } else if (op >= 0x7b && op <= 0x8f) {
            static const char* const kUnary[] = {"-", "~", "-", "~", "-", "-", "(long) ", "(float) ", "(double) ", "(int) ",
                                                 "(float) ", "(double) ", "(int) ", "(long) ", "(double) ", "(int) ",
                                                 "(long) ", "(float) ", "(byte) ", "(char) ", "(short) "};
            def(A, kUnary[op - 0x7b] + R(B), false);
        } else if (op >= 0x90 && op <= 0xcf) {
            static const char* const kBin[] = {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>",
                                               "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>",
                                               "+", "-", "*", "/", "%", "+", "-", "*", "/", "%"};
            if (op < 0xb0) def(A, R(B) + " " + kBin[op - 0x90] + " " + R(C), false);
            else def(A, R(A) + " " + kBin[op - 0xb0] + " " + R(B), false);
        } else if (op >= 0xd0 && op <= 0xe2) {
            static const char* const kLit[] = {"+", "-", "*", "/", "%", "&", "|", "^", "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"};
            const char* o = kLit[op - 0xd0];
            const bool rsub = op == 0xd1 || op == 0xd9;
            if (rsub) {
                def(A, intText(in.literal, false) + " - " + R(B), false);
            } else if (std::strcmp(o, "+") == 0 && in.literal < 0) {
                def(A, R(B) + " - " + intText(-in.literal, false), false);
            } else {
                def(A, R(B) + " " + o + " " + intText(in.literal, false), false);
            }
        } else if (op == 0xfe || op == 0xff) {
            def(A, std::string(op == 0xfe ? "methodHandle#" : "methodType#") + std::to_string(in.index), true);
            s.constant = true;
        } else {
            stmt(std::string("/* ") + info.name + " */");
        }
        if (!s.vkind && s.def >= 0) s.vkind = defKind(in, next, consumed);
        if (s.def >= 0 && s.vtype.empty()) s.vtype = defType(in, consumed, blk);
        blk.stmts.push_back(std::move(s));
        return consumed;
    }

    // Java type of an instruction's result, for the declarations ("" when unknown).
    std::string defType(const dalvik::Insn& in, bool consumedNext, const Block& blk) const {
        const uint8_t op = in.opcode;
        const auto type = [&](uint32_t idx) { return idx < dex_.typeCount() ? typeName(dex_.typeDescriptor(idx)) : std::string(); };
        const auto field = [&](uint32_t idx) {
            return idx < dex_.fieldCount() ? typeName(dex_.typeDescriptor(dex_.fieldType(idx))) : std::string();
        };
        if (op >= 0x01 && op <= 0x09) {  // a copy: the type of what was copied
            for (size_t k = blk.stmts.size(); k-- > 0;)
                if (!blk.stmts[k].removed && blk.stmts[k].def == static_cast<int>(in.regs[1])) return blk.stmts[k].vtype;
            return std::string();
        }
        if (op == 0x0d) return "Throwable";
        if (op >= 0x12 && op <= 0x14) return "int";
        if (op == 0x15) return in.literal ? "float" : "int";
        if (op >= 0x16 && op <= 0x18) return "long";
        if (op == 0x19) return in.literal ? "double" : "long";
        if (op == 0x1a || op == 0x1b) return "String";
        if (op == 0x1c) return "Class";
        if (op == 0x1f || op == 0x22 || op == 0x23 || op == 0x24 || op == 0x25) return type(in.index);
        if (op == 0x20) return "boolean";
        if (op == 0x21 || (op >= 0x2d && op <= 0x31)) return "int";
        if (op >= 0x44 && op <= 0x4a) {
            static const char* const kElem[] = {"int", "long", "Object", "boolean", "byte", "char", "short"};
            return kElem[op - 0x44];
        }
        if ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66)) return field(in.index);
        if (consumedNext && dalvik::opInfo(op).flow == dalvik::Flow::Invoke && dalvik::opInfo(op).ref == dalvik::RefKind::Method &&
            in.index < dex_.methodCount())
            return type(dex_.protoReturnType(dex_.methodProto(in.index)));
        if (op >= 0x7b && op <= 0x8f) {
            static const char* const kUnary[] = {"int", "int", "long", "long", "float", "double", "long", "float", "double", "int", "float",
                                                 "double", "int", "long", "double", "int", "long", "float", "byte", "char", "short"};
            return kUnary[op - 0x7b];
        }
        if (op >= 0x90 && op <= 0xcf) {
            const int k = (op - 0x90) % 32;
            return k < 11 ? "int" : k < 22 ? "long" : k < 27 ? "float" : "double";
        }
        if (op >= 0xd0 && op <= 0xe2) return "int";
        if (op == 0xfe) return "MethodHandle";
        if (op == 0xff) return "MethodType";
        return std::string();
    }

    // What an instruction's result is (for null / boolean rendering).
    char defKind(const dalvik::Insn& in, const dalvik::Insn* next, bool consumedNext) const {
        const uint8_t op = in.opcode;
        if (op == 0x1a || op == 0x1b || op == 0x1c || op == 0x1f || op == 0x22 || op == 0x23 || op == 0x24 || op == 0x25 || op == 0x46)
            return 'L';
        if (op == 0x20 || op == 0x47) return 'Z';
        if ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66))
            return in.index < dex_.fieldCount() ? kindOf(dex_.typeDescriptor(dex_.fieldType(in.index))) : 0;
        if (consumedNext && next && dalvik::opInfo(op).flow == dalvik::Flow::Invoke && in.index < dex_.methodCount() &&
            dalvik::opInfo(op).ref == dalvik::RefKind::Method)
            return kindOf(dex_.typeDescriptor(dex_.protoReturnType(dex_.methodProto(in.index))));
        if (op == 0x21 || (op >= 0x2d && op <= 0x31) || op == 0x44 || op == 0x45 || (op >= 0x48 && op <= 0x4a) || (op >= 0x7b && op <= 0xe2))
            return 'N';
        return 0;
    }

    // Kind of the value register r holds at the end of blk (its last definition there), else the method-wide guess.
    char valueKind(const Block& blk, uint32_t r) const {
        for (size_t k = blk.stmts.size(); k-- > 0;) {
            const Stmt& s = blk.stmts[k];
            if (s.removed || s.def != static_cast<int>(r)) continue;
            if (s.vkind) return s.vkind;
            break;
        }
        const char k = r < kinds_.size() ? kinds_[r] : 0;
        return k == '?' ? 0 : k;
    }

    // const 0 / 1 read as null / false / true when every use in the block expects that.
    void literalsFromUses() {
        for (Block& blk : fn_.blocks) {
            for (size_t i = 0; i < blk.stmts.size(); ++i) {
                Stmt& d = blk.stmts[i];
                if (!d.smallLiteral || d.removed) continue;
                char want = 0;
                bool mixed = false, open = true;
                const auto look = [&](const std::string& text) {
                    PhRef r;
                    for (size_t at = 0; nextPh(text, at, r); at = r.end) {
                        if (r.id != d.def) continue;
                        const char h = r.hint == 'L' || r.hint == 'Z' ? r.hint : 'N';
                        if (!want) want = h;
                        else if (want != h) mixed = true;
                    }
                };
                for (size_t k = i + 1; k < blk.stmts.size() && open; ++k) {
                    look(blk.stmts[k].rhs);
                    if (clobbers(blk.stmts[k], d.def)) open = false;
                }
                if (open) look(blk.term.text);
                if (mixed || !want || want == 'N') continue;
                if (want == 'L' && d.rhs == "0") d.rhs = "null", d.vkind = 'L', d.vtype.clear();
                if (want == 'Z') d.rhs = d.rhs == "0" ? "false" : "true", d.vkind = 'Z', d.vtype = "boolean";
            }
        }
    }

    bool invoke(const dalvik::Insn& in, const dalvik::Insn* next, Block& blk, Stmt& s) {
        const uint8_t op = in.opcode;
        const auto regAt = [&](uint32_t k) { return in.range ? in.regs[0] + k : in.regs[k]; };
        s.sideEffect = s.readsMem = true;
        const auto finish = [&](std::string call, bool returnsValue) {
            if (returnsValue && next && next->valid && next->opcode >= 0x0a && next->opcode <= 0x0c) {
                s.def = static_cast<int>(next->regs[0]);
                s.defName = next->regs[0] < names_.size() ? names_[next->regs[0]] : "v" + std::to_string(next->regs[0]);
                s.rhs = std::move(call);
                s.atomic = true;
                s.addrs.push_back(next->pc);
                return true;
            }
            s.rhs = std::move(call);
            return false;
        };
        if (op == 0xfc || op == 0xfd) {
            std::string args;
            for (uint32_t k = 0; k < in.regCount; ++k) args += (k ? ", " : "") + R(regAt(k));
            return finish("invokeCustom#" + std::to_string(in.index) + "(" + args + ")", true);
        }
        if (in.index >= dex_.methodCount()) return finish("method#" + std::to_string(in.index) + "()", true);
        const uint32_t mi = in.index;
        const std::string name = methodName(mi);
        const std::string ownerDesc(dex_.typeDescriptor(dex_.methodClass(mi)));
        const uint32_t proto = dex_.methodProto(mi);
        const std::string ret(dex_.typeDescriptor(dex_.protoReturnType(proto)));
        const bool isStaticCall = op == 0x71 || op == 0x77;
        const bool isSuper = op == 0x6f || op == 0x75;
        const bool isDirect = op == 0x70 || op == 0x76;
        uint32_t pos = isStaticCall ? 0 : 1;
        std::string args;
        for (uint32_t p : dex_.protoParameters(proto)) {
            if (pos >= in.regCount) break;
            const std::string_view pd = dex_.typeDescriptor(p);
            args += (args.empty() ? "" : ", ") + R(regAt(pos), hintOf(pd));
            pos += wideType(pd) ? 2 : 1;
        }
        const uint32_t recv = in.regCount ? regAt(0) : 0;
        if (name == "<init>" && isDirect && in.regCount) {
            if (static_cast<int>(recv) == thisReg_ && isCtor_) {
                s.rhs = (ownerDesc == clsDesc_ ? "this(" : "super(") + args + ")";
                return false;
            }
            // new-instance vX [+ move vR, vX] + invoke-direct {vR, ...} <init>  ->  vX = new T(...)
            const std::string created = "new " + typeName(ownerDesc) + "(" + args + ")";
            const auto lastDef = [&](int reg, size_t before) {
                for (size_t k = before; k-- > 0;)
                    if (!blk.stmts[k].removed && blk.stmts[k].def == reg) return k;
                return std::string::npos;
            };
            const int rv = static_cast<int>(recv);
            size_t k = lastDef(rv, blk.stmts.size()), mv = std::string::npos;
            int obj = rv;
            if (k != std::string::npos && !blk.stmts[k].newInstance && blk.stmts[k].moveFrom >= 0) {
                mv = k;
                obj = blk.stmts[k].moveFrom;
                k = lastDef(obj, mv);
            }
            if (k != std::string::npos && blk.stmts[k].newInstance) {
                bool usedBetween = false;
                for (size_t q = k + 1; q < blk.stmts.size(); ++q) {
                    if (q == mv || blk.stmts[q].removed) continue;
                    if (countUses(blk.stmts[q].rhs, obj) || (mv != std::string::npos && q > mv && countUses(blk.stmts[q].rhs, rv)))
                        usedBetween = true;
                }
                if (!usedBetween) {
                    Stmt& ns = blk.stmts[k];
                    ns.removed = true;
                    Stmt made = s;
                    mergeAddrs(made.addrs, ns.addrs);
                    made.def = obj;
                    made.defName = ns.defName;
                    made.rhs = created;
                    made.atomic = true;
                    made.vkind = 'L';
                    made.vtype = typeName(ownerDesc);
                    if (mv != std::string::npos) {
                        mergeAddrs(made.addrs, blk.stmts[mv].addrs);
                        blk.stmts[mv].removed = true;
                    }
                    blk.stmts.push_back(std::move(made));
                    if (mv != std::string::npos) {  // the copy, dropped later when nothing reads it
                        Stmt copy;
                        copy.addrs = {in.pc};
                        copy.def = rv;
                        copy.defName = recv < names_.size() ? names_[recv] : "v" + std::to_string(recv);
                        copy.rhs = R(static_cast<uint32_t>(obj));
                        copy.atomic = true;
                        copy.moveFrom = obj;
                        copy.vkind = 'L';
                        copy.vtype = typeName(ownerDesc);
                        blk.stmts.push_back(std::move(copy));
                    }
                    s.removed = true;
                    return false;
                }
            }
            s.rhs = R(recv, 'L') + ".<init>(" + args + ")";
            return false;
        }
        std::string call;
        if (isStaticCall) call = owner(dex_.methodClass(mi)) + name + "(" + args + ")";
        else if (isSuper) call = "super." + name + "(" + args + ")";
        else call = R(recv, 'L') + "." + name + "(" + args + ")";
        return finish(std::move(call), ret != "V");
    }

    std::string arrayData(const dalvik::Insn& in) const {
        const uint32_t p = static_cast<uint32_t>(static_cast<int64_t>(in.pc) + in.branch);
        if (p + 4 > code_.insnsSize || code_.unit(p) != 0x0300) return "{...}";
        const uint32_t width = code_.unit(p + 1);
        const uint32_t count = code_.unit(p + 2) | static_cast<uint32_t>(code_.unit(p + 3)) << 16;
        const uint64_t bytes = static_cast<uint64_t>(width) * count;
        if (width == 0 || width > 8 || p + 4 + (bytes + 1) / 2 > code_.insnsSize) return "{...}";
        const uint8_t* data = code_.insns + 2 * (static_cast<size_t>(p) + 4);
        std::string out = "{";
        for (uint32_t i = 0; i < count && i < 16; ++i) {
            int64_t v = 0;
            for (uint32_t b = 0; b < width; ++b) v |= static_cast<int64_t>(data[i * width + b]) << (8 * b);
            if (width < 8 && (v >> (8 * width - 1)) & 1) v -= static_cast<int64_t>(1) << (8 * width);  // sign extend
            out += (i ? ", " : "") + intText(v, width == 8);
        }
        if (count > 16) out += ", ...";
        return out + "}";
    }

    const ApkAnalysis& a_;
    const ApkAnalysis::MethodDef& m_;
    const DexFile& dex_;
    const Naming naming_;
    DexFile::CodeItem code_;
    std::string clsDesc_, retDesc_;
    bool isStatic_ = false, isCtor_ = false;
    int thisReg_ = -1;
    std::vector<std::string> names_;
    std::vector<char> kinds_;  // per register: L object, Z boolean, N number, ? mixed, 0 unknown
    Fn fn_;
};

// ===========================================================================
// AArch64
// ===========================================================================

struct Reg {
    int id = -1;        // 0-30 general, 31 sp, 32-63 FP/SIMD
    bool zero = false;  // xzr / wzr
    char cls = 0;       // x w s d q h b v
    std::string name;
};

bool parseReg(std::string_view t, Reg& r) {
    r = Reg{};
    if (t == "sp" || t == "wsp") {
        r.id = 31, r.cls = t[0] == 'w' ? 'w' : 'x', r.name = std::string(t);
        return true;
    }
    if (t == "xzr" || t == "wzr") {
        r.zero = true, r.cls = t[0], r.name = "0";
        return true;
    }
    if (t.size() < 2) return false;
    const char c = t[0];
    if (std::strchr("xwbhsdqv", c) == nullptr) return false;
    size_t i = 1;
    int n = 0;
    while (i < t.size() && t[i] >= '0' && t[i] <= '9') n = n * 10 + (t[i++] - '0');
    if (i == 1) return false;
    if (i < t.size() && !(c == 'v' && t[i] == '.')) return false;
    if (c == 'x' || c == 'w') {
        if (n > 30) return false;
        r.id = n;
    } else {
        if (n > 31) return false;
        r.id = 32 + n;
    }
    r.cls = c;
    r.name = std::string(t);
    return true;
}

bool parseImm(std::string_view t, int64_t& v) {
    if (t.empty() || t[0] != '#') return false;
    t.remove_prefix(1);
    bool neg = false;
    if (!t.empty() && t[0] == '-') neg = true, t.remove_prefix(1);
    uint64_t x = 0;
    if (t.size() > 2 && t[0] == '0' && t[1] == 'x') {
        for (size_t i = 2; i < t.size(); ++i) {
            const char c = t[i];
            const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
            if (d < 0) return false;
            x = x * 16 + static_cast<uint64_t>(d);
        }
    } else {
        if (t.empty()) return false;
        for (char c : t) {
            if (c < '0' || c > '9') return false;
            x = x * 10 + static_cast<uint64_t>(c - '0');
        }
    }
    v = neg ? -static_cast<int64_t>(x) : static_cast<int64_t>(x);
    return true;
}

bool parseHex(std::string_view t, uint64_t& v) {
    if (t.size() < 3 || t[0] != '0' || t[1] != 'x') return false;
    v = std::strtoull(std::string(t.substr(2)).c_str(), nullptr, 16);
    return true;
}

std::vector<std::string> splitOps(std::string_view s) {
    std::vector<std::string> out;
    int depth = 0;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i < s.size()) {
            if (s[i] == '[' || s[i] == '{') ++depth;
            else if (s[i] == ']' || s[i] == '}') --depth;
            if (!(s[i] == ',' && depth == 0)) continue;
        }
        std::string_view part = s.substr(start, i - start);
        while (!part.empty() && part.front() == ' ') part.remove_prefix(1);
        while (!part.empty() && part.back() == ' ') part.remove_suffix(1);
        if (!part.empty()) out.emplace_back(part);
        start = i + 1;
    }
    return out;
}

// --- documented intrinsic names for vector instructions without a C operator ---------------------------------
// An AArch64 vector operand's shape: "v4.4s" (32-bit lanes, 128 bits), "v3.s[1]" (an element), "{v0.16b, v1.16b}".
struct VecShape {
    int bits = 0;        // lane width
    bool q = false;      // 128 bits
    bool element = false;
    int regs = 1;        // registers in a {list}
};

VecShape vecShape(const std::string& op) {
    VecShape s;
    std::string t = op;
    if (!t.empty() && t[0] == '{') {
        s.regs = static_cast<int>(std::count(t.begin(), t.end(), ',')) + 1;
        s.element = t.find("}[") != std::string::npos;
        t = t.substr(1, t.find_first_of(",}") - 1);
    }
    const size_t dot = t.find('.');
    if (t.empty() || t[0] != 'v' || dot == std::string::npos) return s;
    std::string arr = t.substr(dot + 1);
    const size_t bracket = arr.find('[');
    if (bracket != std::string::npos) s.element = true, arr.resize(bracket);
    if (arr.empty()) return s;
    const char c = arr.back();
    s.bits = c == 'b' ? 8 : c == 'h' ? 16 : c == 's' ? 32 : c == 'd' ? 64 : 0;
    const int lanes = arr.size() > 1 ? std::atoi(arr.c_str()) : 1;
    s.q = lanes * s.bits == 128;
    return s;
}

// The arm_neon.h name of an AArch64 Advanced SIMD instruction: "zip1 v4.4s, ..." is vzip1q_u32, "umull2 v12.8h,
// v7.16b, v0.16b" vmull_high_u8, "ushr v17.4s, v1.4s, #24" vshrq_n_u32, "ld1r {v26.4s}, [x8]" vld1q_dup_u32. Empty
// when the instruction is not one of them.
std::string neonA64Name(const std::string& mnemonic, const std::vector<std::string>& ops) {
    if (ops.empty()) return {};
    static const std::map<std::string, std::string> plain = {
        {"add", "vadd"},     {"sub", "vsub"},     {"mul", "vmul"},     {"mla", "vmla"},     {"mls", "vmls"},     {"shl", "vshl_n"},
        {"rev64", "vrev64"}, {"rev32", "vrev32"}, {"rev16", "vrev16"}, {"zip1", "vzip1"},   {"zip2", "vzip2"},   {"uzp1", "vuzp1"},
        {"uzp2", "vuzp2"},   {"trn1", "vtrn1"},   {"trn2", "vtrn2"},   {"cnt", "vcnt"},     {"abs", "vabs"},     {"neg", "vneg"},
        {"ext", "vext"},     {"addv", "vaddv"},   {"addp", "vpadd"},   {"bsl", "vbsl"},     {"sli", "vsli_n"},   {"sri", "vsri_n"},
        {"shrn", "vshrn_n"}, {"rshrn", "vrshrn_n"}, {"xtn", "vmovn"},  {"cmeq", "vceq"},    {"cmtst", "vtst"},   {"and", "vand"},
        {"orr", "vorr"},     {"eor", "veor"},     {"bic", "vbic"},     {"orn", "vorn"},     {"mvn", "vmvn"},     {"not", "vmvn"},
        {"clz", "vclz"},     {"cls", "vcls"},     {"rbit", "vrbit"},   {"ld1", "vld1"},     {"ld2", "vld2"},     {"ld3", "vld3"},
        {"ld4", "vld4"},     {"st1", "vst1"},     {"st2", "vst2"},     {"st3", "vst3"},     {"st4", "vst4"},     {"ld1r", "vld1_dup"},
        {"ld2r", "vld2_dup"}, {"ld3r", "vld3_dup"}, {"ld4r", "vld4_dup"}, {"dup", "vdup"},  {"movi", "vdup_n"},  {"pmul", "vmul"},
        {"bit", "vbsl"},     {"bif", "vbsl"},
        {"cmhi", "vcgt"},    {"cmhs", "vcge"},    {"cmgt", "vcgt"},    {"cmge", "vcge"},    {"cmle", "vcle"},    {"cmlt", "vclt"}};
    static const std::map<std::string, std::string> sign = {  // after the u / s prefix
        {"qadd", "vqadd"},   {"qsub", "vqsub"},     {"hadd", "vhadd"},     {"hsub", "vhsub"},       {"rhadd", "vrhadd"},     {"shl", "vshl"},
        {"rshl", "vrshl"},   {"qshl", "vqshl"},     {"qrshl", "vqrshl"},   {"max", "vmax"},         {"min", "vmin"},         {"maxp", "vpmax"},
        {"minp", "vpmin"},   {"abd", "vabd"},       {"aba", "vaba"},       {"mull", "vmull"},       {"mlal", "vmlal"},       {"mlsl", "vmlsl"},
        {"addl", "vaddl"},   {"addw", "vaddw"},     {"subl", "vsubl"},     {"subw", "vsubw"},       {"abal", "vabal"},       {"abdl", "vabdl"},
        {"shr", "vshr_n"},   {"sra", "vsra_n"},     {"rshr", "vrshr_n"},   {"rsra", "vrsra_n"},     {"shll", "vshll_n"},     {"qshrn", "vqshrn_n"},
        {"qrshrn", "vqrshrn_n"}, {"qshrun", "vqshrun_n"}, {"qrshrun", "vqrshrun_n"}, {"qxtn", "vqmovn"}, {"qxtun", "vqmovun"}, {"addlv", "vaddlv"},
        {"maxv", "vmaxv"},   {"minv", "vminv"},     {"addlp", "vpaddl"},   {"qdmulh", "vqdmulh"},   {"qrdmulh", "vqrdmulh"}, {"qneg", "vqneg"},
        {"qabs", "vqabs"},   {"qdmull", "vqdmull"}, {"qdmlal", "vqdmlal"}, {"qdmlsl", "vqdmlsl"}};
    static const std::set<std::string> longOrNarrow = {"mull", "mlal", "mlsl", "addl", "addw", "subl", "subw", "abal", "abdl", "shll", "shrn",
                                                       "rshrn", "qshrn", "qrshrn", "qshrun", "qrshrun", "xtn", "qxtn", "qxtun", "qdmull",
                                                       "qdmlal", "qdmlsl"};
    std::string m = mnemonic;
    bool high = false;
    char sgn = 'u';
    std::string base;
    const auto find = [&](const std::string& name) {  // sets m to the name without its sign prefix
        if (const auto p = plain.find(name); p != plain.end()) return m = name, base = p->second, true;
        if ((name[0] == 'u' || name[0] == 's') && name.size() > 2)
            if (const auto s = sign.find(name.substr(1)); s != sign.end()) return sgn = name[0], m = name.substr(1), base = s->second, true;
        return false;
    };
    if (!find(mnemonic)) {  // the "2" forms work on the upper halves
        if (mnemonic.size() < 3 || mnemonic.back() != '2' || !find(mnemonic.substr(0, mnemonic.size() - 1)) || !longOrNarrow.count(m)) return {};
        high = true;
    }
    if (m == "cmgt" || m == "cmge" || m == "cmle" || m == "cmlt" || m == "abs" || m == "neg" || m == "cls") sgn = 's';
    const bool shapeChange = longOrNarrow.count(m) > 0;
    // Which operand carries the element type: the narrow source of long ops, the wide source of narrowing ones.
    size_t typed = 0;
    if (shapeChange || m == "addv" || m == "addlv" || m == "maxv" || m == "minv") typed = ops.size() > 1 ? 1 : 0;
    if (m == "addw" || m == "subw") typed = ops.size() - 1;
    const VecShape shape = vecShape(ops[typed]), first = vecShape(ops[0]);
    if (!shape.bits) return {};
    if (m == "shll" && ops.back() == "#0") base = "vmovl";  // ushll #0: widen
    const size_t under = base.find('_');
    std::string stem = base.substr(0, under), suffix = under == std::string::npos ? std::string() : base.substr(under);
    const bool memory = m.size() >= 3 && (m.compare(0, 2, "ld") == 0 || m.compare(0, 2, "st") == 0) && std::isdigit(static_cast<unsigned char>(m[2]));
    if (memory && first.element) suffix = "_lane" + suffix;
    else if (!memory && ops.back().find('[') != std::string::npos && ops.back()[0] == 'v') suffix = "_lane" + suffix;
    const bool q = !shapeChange && (memory && first.element ? true : first.q);
    std::string name = stem + (q ? "q" : "") + (high ? "_high" : "") + suffix + "_" + sgn + std::to_string(shape.bits);
    if (memory && !first.element && m.size() == 3 && m[2] == '1' && first.regs > 1) name += "_x" + std::to_string(first.regs);
    return name;
}

// The arm_neon.h name of an A32 / Thumb NEON instruction: "vrshrn.i16 d0, q1, #8" is vrshrn_n_u16, "vqadd.s32 q0,
// q1, q2" vqaddq_s32, "vmlal.u16 q0, d1, d2" vmlal_u16. Empty when the mnemonic is not one.
std::string neonA32Name(const std::string& mnemonic, const std::vector<std::string>& ops) {
    const size_t dot = mnemonic.find('.');
    if (dot == std::string::npos || mnemonic[0] != 'v' || ops.empty()) return {};
    const std::string op = mnemonic.substr(0, dot);
    std::string type = mnemonic.substr(dot + 1);
    if (type.empty()) return {};
    if (std::isdigit(static_cast<unsigned char>(type[0]))) type = "u" + type;
    else if (type[0] == 'i') type[0] = 'u';
    if (type[0] != 'u' && type[0] != 's' && type[0] != 'f' && type[0] != 'p') return {};
    static const std::set<std::string> known = {
        "vadd", "vsub", "vmul", "vmla", "vmls", "vqadd", "vqsub", "vhadd", "vhsub", "vrhadd", "vshl", "vrshl", "vqshl", "vqrshl", "vmax",
        "vmin", "vpmax", "vpmin", "vabd", "vaba", "vmull", "vmlal", "vmlsl", "vaddl", "vaddw", "vsubl", "vsubw", "vabal", "vabdl", "vshr",
        "vsra", "vrshr", "vrsra", "vshll", "vmovl", "vshrn", "vrshrn", "vqshrn", "vqrshrn", "vqshrun", "vqrshrun", "vmovn", "vqmovn",
        "vqmovun", "vzip", "vuzp", "vtrn", "vrev64", "vrev32", "vrev16", "vext", "vtst", "vceq", "vcgt", "vcge", "vclt", "vcle", "vabs",
        "vneg", "vqabs", "vqneg", "vcnt", "vclz", "vcls", "vpadd", "vpaddl", "vpadal", "vqdmulh", "vqrdmulh", "vqdmull", "vqdmlal",
        "vqdmlsl", "vld1", "vld2", "vld3", "vld4", "vst1", "vst2", "vst3", "vst4", "vbsl", "vdup", "vsli", "vsri", "vrecpe", "vrsqrte",
        "vrecps", "vrsqrts", "vcvt", "vswp", "vtbl", "vtbx", "vbif", "vbit"};
    if (!known.count(op)) return {};
    static const std::set<std::string> shapeChange = {"vmull", "vmlal", "vmlsl", "vaddl", "vaddw", "vsubl", "vsubw", "vabal", "vabdl", "vshll",
                                                      "vmovl", "vshrn", "vrshrn", "vqshrn", "vqrshrn", "vqshrun", "vqrshrun", "vmovn",
                                                      "vqmovn", "vqmovun", "vqdmull", "vqdmlal", "vqdmlsl"};
    static const std::set<std::string> shifts = {"vshr", "vsra", "vrshr", "vrsra", "vshl", "vqshl", "vsli", "vsri", "vshrn", "vrshrn",
                                                 "vqshrn", "vqrshrn", "vqshrun", "vqrshrun", "vshll", "vqshlu"};
    const bool memory = op.rfind("vld", 0) == 0 || op.rfind("vst", 0) == 0;
    std::string name = op;
    if (memory) {
        const std::string& list = ops[0];
        const int regs = list[0] == '{' ? static_cast<int>(std::count(list.begin(), list.end(), ',')) + 1 : 1;
        const bool lane = list.find('[') != std::string::npos;
        const bool quad = list.find('q') != std::string::npos || regs == 2 || regs == 4;
        name += std::string(quad && !lane ? "q" : "") + (lane ? "_lane" : "");
        name += "_" + type;
        if (op == "vld1" || op == "vst1")
            if (!lane && regs > 2) name += "_x" + std::to_string(regs / 2);
        return name;
    }
    const bool quad = ops[0][0] == 'q' && !shapeChange.count(op);
    const bool immediate = !ops.empty() && ops.back()[0] == '#' && shifts.count(op);
    if (op == "vshll" && ops.back() == "#0") name = "vmovl";
    return name + (quad ? "q" : "") + (immediate && name != "vmovl" ? "_n" : "") + "_" + type;
}

// The Intel intrinsic for an SSE instruction the translation leaves as a call. `readsDest`: the destination is also
// the first source (two-operand forms); `dropLast`: the immediate is part of the name (cmpss xmm0, xmm1, 1 is
// _mm_cmplt_ss).
std::string sseIntrinsic(const std::string& m, const std::vector<std::string>& ops, bool& readsDest, bool& dropLast) {
    readsDest = true;
    dropLast = false;
    static const std::map<std::string, std::pair<const char*, bool>> table = {  // name, reads the destination
        {"pmovmskb", {"_mm_movemask_epi8", false}}, {"movmskps", {"_mm_movemask_ps", false}}, {"movmskpd", {"_mm_movemask_pd", false}},
        {"pextrw", {"_mm_extract_epi16", false}},  {"pextrb", {"_mm_extract_epi8", false}},   {"pextrd", {"_mm_extract_epi32", false}},
        {"pinsrw", {"_mm_insert_epi16", true}},    {"pinsrb", {"_mm_insert_epi8", true}},     {"pinsrd", {"_mm_insert_epi32", true}},
        {"pmaddwd", {"_mm_madd_epi16", true}},     {"pmaddubsw", {"_mm_maddubs_epi16", true}}, {"pshuflw", {"_mm_shufflelo_epi16", false}},
        {"pshufhw", {"_mm_shufflehi_epi16", false}}, {"pshufd", {"_mm_shuffle_epi32", false}}, {"pshufb", {"_mm_shuffle_epi8", true}},
        {"pslldq", {"_mm_slli_si128", true}},      {"psrldq", {"_mm_srli_si128", true}},      {"pmovzxbw", {"_mm_cvtepu8_epi16", false}},
        {"pmovzxbd", {"_mm_cvtepu8_epi32", false}}, {"pmovzxwd", {"_mm_cvtepu16_epi32", false}}, {"pmovzxdq", {"_mm_cvtepu32_epi64", false}},
        {"pmovsxbw", {"_mm_cvtepi8_epi16", false}}, {"pmovsxwd", {"_mm_cvtepi16_epi32", false}}, {"pmovsxdq", {"_mm_cvtepi32_epi64", false}},
        {"punpcklbw", {"_mm_unpacklo_epi8", true}}, {"punpckhbw", {"_mm_unpackhi_epi8", true}}, {"punpcklwd", {"_mm_unpacklo_epi16", true}},
        {"punpckhwd", {"_mm_unpackhi_epi16", true}}, {"punpckldq", {"_mm_unpacklo_epi32", true}}, {"punpckhdq", {"_mm_unpackhi_epi32", true}},
        {"punpcklqdq", {"_mm_unpacklo_epi64", true}}, {"punpckhqdq", {"_mm_unpackhi_epi64", true}}, {"packuswb", {"_mm_packus_epi16", true}},
        {"packsswb", {"_mm_packs_epi16", true}},   {"packssdw", {"_mm_packs_epi32", true}},   {"packusdw", {"_mm_packus_epi32", true}},
        {"pavgb", {"_mm_avg_epu8", true}},         {"pavgw", {"_mm_avg_epu16", true}},        {"psadbw", {"_mm_sad_epu8", true}},
        {"pmulhw", {"_mm_mulhi_epi16", true}},     {"pmulhuw", {"_mm_mulhi_epu16", true}},    {"pmuludq", {"_mm_mul_epu32", true}},
        {"pmulld", {"_mm_mullo_epi32", true}},     {"pminub", {"_mm_min_epu8", true}},        {"pmaxub", {"_mm_max_epu8", true}},
        {"pminsw", {"_mm_min_epi16", true}},       {"pmaxsw", {"_mm_max_epi16", true}},       {"pcmpeqb", {"_mm_cmpeq_epi8", true}},
        {"pcmpeqw", {"_mm_cmpeq_epi16", true}},    {"pcmpeqd", {"_mm_cmpeq_epi32", true}},    {"pcmpgtb", {"_mm_cmpgt_epi8", true}},
        {"pcmpgtw", {"_mm_cmpgt_epi16", true}},    {"pcmpgtd", {"_mm_cmpgt_epi32", true}},    {"paddusb", {"_mm_adds_epu8", true}},
        {"paddusw", {"_mm_adds_epu16", true}},     {"psubusb", {"_mm_subs_epu8", true}},      {"psubusw", {"_mm_subs_epu16", true}},
        {"paddsw", {"_mm_adds_epi16", true}},      {"psubsw", {"_mm_subs_epi16", true}},      {"shufps", {"_mm_shuffle_ps", true}},
        {"shufpd", {"_mm_shuffle_pd", true}},      {"unpcklps", {"_mm_unpacklo_ps", true}},   {"unpckhps", {"_mm_unpackhi_ps", true}},
        {"unpcklpd", {"_mm_unpacklo_pd", true}},   {"unpckhpd", {"_mm_unpackhi_pd", true}},   {"rcpps", {"_mm_rcp_ps", false}},
        {"rsqrtps", {"_mm_rsqrt_ps", false}},      {"sqrtps", {"_mm_sqrt_ps", false}},        {"sqrtpd", {"_mm_sqrt_pd", false}},
        {"palignr", {"_mm_alignr_epi8", true}},    {"pblendw", {"_mm_blend_epi16", true}},    {"blendps", {"_mm_blend_ps", true}},
        {"pabsb", {"_mm_abs_epi8", false}},        {"pabsw", {"_mm_abs_epi16", false}},       {"pabsd", {"_mm_abs_epi32", false}},
        {"pclmulqdq", {"_mm_clmulepi64_si128", true}}, {"aesenc", {"_mm_aesenc_si128", true}}, {"aesdec", {"_mm_aesdec_si128", true}},
        {"aesenclast", {"_mm_aesenclast_si128", true}}, {"aesdeclast", {"_mm_aesdeclast_si128", true}}};
    const std::string base = m.size() > 1 && m[0] == 'v' && table.count(m.substr(1)) ? m.substr(1) : m;  // VEX forms take three operands
    if (const auto it = table.find(base); it != table.end()) {
        readsDest = it->second.second && base == m;
        return it->second.first;
    }
    // cmpss / cmpsd / cmpps / cmppd with the predicate as the immediate.
    if ((base == "cmpss" || base == "cmpsd" || base == "cmpps" || base == "cmppd") && ops.size() == 3) {
        static const char* const predicate[8] = {"eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord"};
        const int p = std::atoi(ops[2].c_str());
        if (p < 0 || p > 7) return {};
        dropLast = true;
        return std::string("_mm_cmp") + predicate[p] + "_" + base.substr(3);
    }
    return {};
}

const char* memType(char cls) {
    switch (cls) {
    case 'x': return "uint64_t";
    case 'w': return "uint32_t";
    case 's': return "float";
    case 'd': return "double";
    case 'q': return "uint128_t";
    case 'h': return "uint16_t";
    case 'b': return "uint8_t";
    default: return "uint64_t";
    }
}

int memSize(char cls) {
    switch (cls) {
    case 'x': case 'd': return 8;
    case 'q': return 16;
    case 'h': return 2;
    case 'b': return 1;
    default: return 4;
    }
}

bool calleeSaved(const Reg& r) { return (r.id >= 19 && r.id <= 30) || (r.id >= 32 + 8 && r.id <= 32 + 15); }

// C string literal; bytes >= 0x80 kept (UTF-8 text).
std::string cQuote(std::string_view s) {
    std::string out = "\"";
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\') out += '\\', out += ch;
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else if (c == '\r') out += "\\r";
        else if (c < 0x20 || c == 0x7f) {
            char b[8];
            std::snprintf(b, sizeof b, "\\x%02x", c);
            out += b;
        } else {
            out += ch;
        }
    }
    return out + "\"";
}

// Mostly printable ASCII: text, not a pointer table that happens to be NUL-terminated.
bool looksLikeText(std::string_view s) {
    if (s.size() < 2) return false;
    size_t printable = 0;
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        printable += (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\t' || c == '\r';
    }
    return printable * 4 >= s.size() * 3;
}

bool evalCond(std::string_view cc, unsigned nzcv) {
    const bool N = nzcv & 8, Z = nzcv & 4, C = nzcv & 2, V = nzcv & 1;
    if (cc == "eq") return Z;
    if (cc == "ne") return !Z;
    if (cc == "hs" || cc == "cs") return C;
    if (cc == "lo" || cc == "cc") return !C;
    if (cc == "mi") return N;
    if (cc == "pl") return !N;
    if (cc == "vs") return V;
    if (cc == "vc") return !V;
    if (cc == "hi") return C && !Z;
    if (cc == "ls") return !(C && !Z);
    if (cc == "ge") return N == V;
    if (cc == "lt") return N != V;
    if (cc == "gt") return !Z && N == V;
    if (cc == "le") return !(!Z && N == V);
    return cc == "al";
}

// Reverse post-order from block 0: a block comes after its predecessors, back edges aside.
std::vector<int> predecessorsFirst(size_t blocks, const std::function<const std::vector<int>&(size_t)>& successors) {
    std::vector<int> order;
    std::vector<char> seen(blocks, 0);
    std::vector<std::pair<int, size_t>> stack;
    if (blocks) stack.push_back({0, 0}), seen[0] = 1;
    while (!stack.empty()) {
        const int b = stack.back().first;
        const std::vector<int>& next = successors(static_cast<size_t>(b));
        if (stack.back().second < next.size()) {
            const int s = next[stack.back().second++];
            if (s >= 0 && static_cast<size_t>(s) < blocks && !seen[static_cast<size_t>(s)]) seen[static_cast<size_t>(s)] = 1, stack.push_back({s, 0});
        } else {
            order.push_back(b);
            stack.pop_back();
        }
    }
    std::reverse(order.begin(), order.end());
    return order;
}

// A switch over a jump table's index: values that go to the same block share a case body.
void tableSwitch(Term& t, const std::vector<std::pair<int64_t, int>>& entries, std::string value) {
    t.kind = TermKind::Switch;
    t.noDefault = true;
    t.text = std::move(value);
    t.cases.clear();
    for (const auto& [key, block] : entries) {
        auto it = std::find_if(t.cases.begin(), t.cases.end(), [&](const auto& c) { return c.second == block; });
        if (it == t.cases.end()) t.cases.push_back({{key}, block});
        else it->first.push_back(key);
    }
}

// Common vector instructions as expressions over whole registers. `a` holds the source operands in order (for the
// two-operand x86 forms the destination comes first). Returns "" for instructions that stay __intrinsics.
std::string vectorInfix(const std::string& x, const char* op, const std::string& y) { return wrap(x) + " " + op + " " + wrap(y); }

std::string vectorCall(const char* name, const std::vector<std::string>& a) {
    std::string out = std::string(name) + "(";
    for (size_t i = 0; i < a.size(); ++i) out += (i ? ", " : "") + a[i];
    return out + ")";
}

// SSE / AVX, mnemonic without the VEX "v". `type` receives the element type of the result.
std::string sseExpression(const std::string& m, const std::vector<std::string>& a, std::string& type) {
    const auto ends = [&](const char* s) {
        const size_t n = std::strlen(s);
        return m.size() > n && m.compare(m.size() - n, n, s) == 0;
    };
    type = ends("ps") || ends("ss") ? "float4" : ends("pd") || ends("sd") ? "double2" : "int4";
    const std::string stem = m.size() > 2 && (ends("ps") || ends("pd") || ends("ss") || ends("sd")) ? m.substr(0, m.size() - 2) : m;
    const bool two = a.size() == 2;
    if (a.size() == 1) {
        if (stem == "sqrt") return vectorCall("sqrt", a);
        if (stem == "rcp") return "1.0 / " + wrap(a[0]);
        if (stem == "rsqrt") return "1.0 / " + vectorCall("sqrt", a);
        if (m == "movddup") return type = "double2", vectorCall("duplicate_low", a);
        if (m == "movshdup") return type = "float4", vectorCall("duplicate_odd", a);
        if (m == "movsldup") return type = "float4", vectorCall("duplicate_even", a);
        if (m == "cvtdq2ps") return type = "float4", "(float4)" + wrap(a[0]);
        if (m == "cvtps2dq" || m == "cvttps2dq") return type = "int4", "(int4)" + wrap(a[0]);
        if (m == "cvtps2pd") return type = "double2", "(double2)" + wrap(a[0]);
        if (m == "cvtpd2ps") return type = "float4", "(float4)" + wrap(a[0]);
        if (m == "cvtdq2pd") return type = "double2", "(double2)" + wrap(a[0]);
        if (m == "pabsb" || m == "pabsw" || m == "pabsd") return vectorCall("abs", a);
        if (m == "broadcastss" || m == "broadcastsd" || m.rfind("pbroadcast", 0) == 0) return vectorCall("splat", a);
        return {};
    }
    if (two) {
        const std::string &x = a[0], &y = a[1];
        if (stem == "add") return vectorInfix(x, "+", y);
        if (stem == "sub") return vectorInfix(x, "-", y);
        if (stem == "mul") return vectorInfix(x, "*", y);
        if (stem == "div") return vectorInfix(x, "/", y);
        if (stem == "min") return vectorCall("min", a);
        if (stem == "max") return vectorCall("max", a);
        if (stem == "and" || m == "pand") return vectorInfix(x, "&", y);
        if (stem == "or" || m == "por") return vectorInfix(x, "|", y);
        if (stem == "xor" || m == "pxor") return vectorInfix(x, "^", y);
        if (stem == "andn" || m == "pandn") return "~" + wrap(x) + " & " + wrap(y);
        if (m == "paddb" || m == "paddw" || m == "paddd" || m == "paddq") return vectorInfix(x, "+", y);
        if (m == "psubb" || m == "psubw" || m == "psubd" || m == "psubq") return vectorInfix(x, "-", y);
        if (m == "pmullw" || m == "pmulld" || m == "pmuludq" || m == "pmuldq") return vectorInfix(x, "*", y);
        if (m == "psllw" || m == "pslld" || m == "psllq") return vectorInfix(x, "<<", y);
        if (m == "psrlw" || m == "psrld" || m == "psrlq") return "(unsigned)" + wrap(x) + " >> " + wrap(y);
        if (m == "psraw" || m == "psrad") return vectorInfix(x, ">>", y);
        if (m.rfind("pcmpeq", 0) == 0) return vectorInfix(x, "==", y);
        if (m.rfind("pcmpgt", 0) == 0) return vectorInfix(x, ">", y);
        if (m == "pminsb" || m == "pminsw" || m == "pminsd" || m == "pminub" || m == "pminuw" || m == "pminud") return vectorCall("min", a);
        if (m == "pmaxsb" || m == "pmaxsw" || m == "pmaxsd" || m == "pmaxub" || m == "pmaxuw" || m == "pmaxud") return vectorCall("max", a);
        if (m == "pshufd" || m == "pshuflw" || m == "pshufhw") return {};
        if (m == "pshufb") return vectorCall("shuffle_bytes", a);
        if (stem == "unpckl" || m.rfind("punpckl", 0) == 0) return vectorCall("interleave_low", a);
        if (stem == "unpckh" || m.rfind("punpckh", 0) == 0) return vectorCall("interleave_high", a);
        if (stem == "addsub") return vectorCall("addsub", a);
        if (stem == "hadd" || m == "phaddd" || m == "phaddw") return vectorCall("pairwise_add", a);
        if (stem == "hsub") return vectorCall("pairwise_sub", a);
        if (m == "movlhps") return type = "float4", "concat(low_half(" + x + "), low_half(" + y + "))";
        if (m == "movhlps") return type = "float4", "concat(high_half(" + y + "), high_half(" + x + "))";
        if (m == "packsswb" || m == "packssdw" || m == "packuswb" || m == "packusdw") return vectorCall("narrow_saturate", a);
    }
    if (a.size() == 3) {
        if (stem == "shuf") return vectorCall("shuffle", a);
        if (m == "palignr") return vectorCall("align_right", a);
        if (m == "pblendw" || stem == "blend") return vectorCall("blend", a);
    }
    return {};
}

class NativeDecompiler {
public:
    NativeDecompiler(const NativeCode& nc, const NativeCode::Function& f) : nc_(nc), f_(f) {}

    Output run() {
        Output out;
        cfg_ = nc_.controlFlow(f_, 20000);
        if (cfg_.blocks.empty()) {
            out.error = "no code decoded for this function";
            return out;
        }
        if (cfg_.blocks.size() > kMaxBlocks) {
            out.error = "function too large to decompile (" + std::to_string(cfg_.blocks.size()) + " blocks)";
            return out;
        }
        fn_.labelPrefix = "loc_";
        fn_.roots.push_back(0);
        fn_.blocks.resize(cfg_.blocks.size());
        // Only code reachable from the entry: a symbol's size often spans what follows the last ret.
        std::vector<char> reach(cfg_.blocks.size(), 0);
        std::vector<int> work{0};
        while (!work.empty()) {
            const int b = work.back();
            work.pop_back();
            if (b < 0 || static_cast<size_t>(b) >= reach.size() || reach[static_cast<size_t>(b)]) continue;
            reach[static_cast<size_t>(b)] = 1;
            for (int s : cfg_.blocks[static_cast<size_t>(b)].successors) work.push_back(s);
        }
        for (size_t i = 0; i < cfg_.blocks.size(); ++i) {
            if (reach[i]) {
                translateBlock(i);
            } else {
                fn_.blocks[i].addr = cfg_.blocks[i].lineCount ? cfg_.lines[cfg_.blocks[i].firstLine].insn.addr : 0;
                fn_.blocks[i].term.kind = TermKind::Stop;
            }
        }
        decideReturns();
        fn_.regCount = nextSynth_;
        simplify(fn_);

        // Parameters: argument registers read before being written.
        const Liveness lv = liveness(fn_);
        int maxX = -1, maxD = -1;
        for (int r = 0; r < 8; ++r) {
            if (lv.in[0].test(r)) maxX = r;
            if (lv.in[0].test(32 + r)) maxD = r;
        }
        for (int r = 0; r <= maxX; ++r) out.vars.push_back(Var{"x" + std::to_string(r), "int64_t", std::string(), true});
        for (int r = 0; r <= maxD; ++r) out.vars.push_back(Var{"d" + std::to_string(r), "double", std::string(), true});
        out.lines.push_back({"// " + hex(f_.addr) + " (" + std::to_string(f_.size) + " bytes)", 0, {}});
        out.headerLine = static_cast<int>(out.lines.size());
        out.returnType = returnsValue_ ? "int64_t" : "void";
        out.returnAt = 0;
        out.headerPrefix = out.returnType + " " + NativeCode::displayName(f_) + "(";
        out.headerSuffix = ") {";
        out.lines.push_back({std::string(), 0, {f_.addr}});
        Structurer(fn_, out.lines).run(1);
        flattenNesting(out.lines);
        if (!returnsValue_) dropTrailingReturn(out.lines);
        out.lines.push_back({"}", 0, {}});
        declareLocals(out, types_, true);
        applyUserNames(out, {}, {}, true);
        return out;
    }

private:
    struct Flags {
        enum Kind { None, Cmp, Cmn, Tst, FCmp } kind = None;
        std::string a, b, res;  // res: result of subs / adds / ands (compared with 0)
        std::string guard;      // ccmp: condition under which a / b were compared
        unsigned nzcv = 0;      // ccmp: flags when the guard is false
        char width = 'x';
        bool operator==(const Flags& o) const {
            return kind == o.kind && a == o.a && b == o.b && res == o.res && guard == o.guard && nzcv == o.nzcv && width == o.width;
        }
    };

    struct State {
        std::map<int, uint64_t> consts;
        std::map<int, uint64_t> addrs;  // registers holding an address formed by adrp / adr
        Flags flags;
        unsigned argMask = 0;  // x0-x7 written since the last call
        unsigned fpArgMask = 0;
        bool callSeen = false;
        bool epilogue = false;  // the return address was restored: a br now is a tail call
    };

    std::string R(const Reg& r) const { return r.zero ? "0" : ph(r.id, r.name); }

    std::string operand(const std::string& t, const std::string& shift = {}) const {
        Reg r;
        int64_t v = 0;
        std::string e;
        const bool isReg = parseReg(t, r);
        if (isReg) e = R(r);
        else if (parseImm(t, v)) e = v < 10 && v > -10 ? std::to_string(v) : signedHex(v);
        else if (t.size() > 1 && t[0] == '#') e = t.substr(1);
        else e = t;
        if (!shift.empty()) e = applyShift(e, shift, isReg ? r.cls : 'x');
        return e;
    }

    // "lsl #2", "sxtw", "uxtw #2", "asr #3"
    static std::string applyShift(const std::string& e, const std::string& sh, char cls = 'x') {
        const size_t sp = sh.find(' ');
        const std::string kind = sh.substr(0, sp);
        int64_t amount = 0;
        if (sp != std::string::npos) parseImm(sh.substr(sp + 1), amount);
        std::string x = e;
        static const std::pair<const char*, const char*> kExt[] = {{"uxtb", "(uint8_t)"}, {"uxth", "(uint16_t)"}, {"uxtw", "(uint32_t)"},
                                                                    {"uxtx", ""},          {"sxtb", "(int8_t)"},   {"sxth", "(int16_t)"},
                                                                    {"sxtw", "(int32_t)"}, {"sxtx", ""}};
        for (const auto& [name, cast] : kExt)
            if (kind == name) {
                x = std::string(cast) + wrap(x);
                if (amount) x = wrap(x) + " << " + std::to_string(amount);
                return x;
            }
        if (!amount) return x;
        if (kind == "lsl") return wrap(x) + " << " + std::to_string(amount);
        if (kind == "lsr") return std::string(cls == 'w' ? "(uint32_t)" : "(uint64_t)") + wrap(x) + " >> " + std::to_string(amount);
        if (kind == "asr") return wrap(x) + " >> " + std::to_string(amount);
        if (kind == "ror") return "ror(" + x + ", " + std::to_string(amount) + ")";
        return x;
    }

    struct Mem {
        bool ok = false;
        Reg base;
        std::string index;  // scaled index expression
        int64_t off = 0;
        bool pre = false, post = false;
        int64_t wb = 0;
    };

    static bool parseMem(const std::string& tok, const std::string* after, Mem& m) {
        m = Mem{};
        std::string_view t = tok;
        if (t.empty() || t[0] != '[') return false;
        if (t.back() == '!') m.pre = true, t.remove_suffix(1);
        if (t.empty() || t.back() != ']') return false;
        const std::vector<std::string> inner = splitOps(t.substr(1, t.size() - 2));
        if (inner.empty() || !parseReg(inner[0], m.base)) return false;
        if (inner.size() >= 2) {
            int64_t v = 0;
            Reg idx;
            if (parseImm(inner[1], v)) {
                m.off = v;
            } else if (parseReg(inner[1], idx)) {
                m.index = applyShift(idx.zero ? "0" : ph(idx.id, idx.name), inner.size() >= 3 ? inner[2] : std::string());
            }
        }
        if (m.pre) m.wb = m.off;
        if (after && !after->empty()) {
            int64_t v = 0;
            if (parseImm(*after, v)) m.post = true, m.wb = v;
        }
        m.ok = true;
        return true;
    }

    // Value at [m + extra] of type `cls`, as an lvalue.
    std::string deref(const Mem& m, int extra, char cls, const State& st) const {
        const int64_t off = (m.pre || m.post ? 0 : m.off) + extra;
        const std::string type = memType(cls);
        if (m.index.empty()) {
            if (m.base.id == 31 && !m.pre && !m.post) return "sp_" + hex(static_cast<uint64_t>(off)).substr(2);
            if (m.base.id == 29 && !m.pre && !m.post)
                return off < 0 ? "fp_m" + hex(static_cast<uint64_t>(-off)).substr(2) : "fp_" + hex(static_cast<uint64_t>(off)).substr(2);
            auto c = st.addrs.find(m.base.id);
            if (c != st.addrs.end()) {
                const uint64_t addr = c->second + static_cast<uint64_t>(off);
                const std::string sym = nc_.symbolize(addr);
                if (!sym.empty() && sym.find_first_of("+@") == std::string::npos) return sym;
                return "*(" + type + " *)" + hex(addr);
            }
        }
        std::string addr = R(m.base);
        if (!m.index.empty()) addr += " + " + wrap(m.index);
        if (off > 0) addr += " + " + signedHex(off);
        else if (off < 0) addr += " - " + signedHex(-off);
        return "*(" + type + " *)" + wrap(addr);
    }

    void push(Block& blk, Stmt s) { blk.stmts.push_back(std::move(s)); }

    // A definition of register d. Saves a copy of d for pending flags that still need the old value.
    static const char* regType(char cls) {
        switch (cls) {
        case 'w': return "int32_t";
        case 's': return "float";
        case 'd': return "double";
        case 'q': case 'v': return "uint128_t";
        case 'h': return "uint16_t";
        case 'b': return "uint8_t";
        default: return "int64_t";
        }
    }

    // vtype: what the value is when the register class does not say it (a byte load, a string pointer).
    void define(Block& blk, State& st, const Reg& d, std::string rhs, bool atomic, uint64_t addr, bool readsMem = false,
                bool sideEffect = false, bool constant = false, const std::string& vtype = std::string()) {
        if (d.zero) {
            if (sideEffect) {
                Stmt s;
                s.addrs = {addr};
                s.rhs = std::move(rhs);
                s.sideEffect = true;
                s.readsMem = readsMem;
                push(blk, std::move(s));
            }
            return;
        }
        preserveFlags(blk, st, d.id, addr);
        types_[variableKey(d.name, true)].push_back(vtype.empty() ? regType(d.cls) : vtype);
        Stmt s;
        s.addrs = {addr};
        s.def = d.id;
        s.defName = d.name;
        s.rhs = std::move(rhs);
        s.atomic = atomic;
        s.readsMem = readsMem;
        s.sideEffect = sideEffect;
        s.constant = constant;
        push(blk, std::move(s));
        st.consts.erase(d.id);
        st.addrs.erase(d.id);
        if (d.id < 8) st.argMask |= 1u << d.id;
        if (d.id >= 32 && d.id < 40) st.fpArgMask |= 1u << (d.id - 32);
    }

    // A temporary holding `rhs` now (a struct of vectors that several registers then take apart).
    std::string snapshot(Block& blk, const std::string& rhs, uint64_t addr, const std::string& type) {
        const int t = nextSynth_++;
        const std::string tn = "t" + std::to_string(t - 64);
        Stmt s;
        s.addrs = {addr};
        s.def = t;
        s.defName = tn;
        types_[tn].push_back(type);
        s.rhs = rhs;
        s.atomic = true;
        s.readsMem = s.sideEffect = true;
        push(blk, std::move(s));
        return ph(t, tn);
    }

    void preserveFlags(Block& blk, State& st, int id, uint64_t addr) {
        Flags& f = st.flags;
        if (f.kind == Flags::None) return;
        if (!countUses(f.a, id) && !countUses(f.b, id) && !countUses(f.res, id) && !countUses(f.guard, id)) return;
        const std::string old = nameOf(f.a + f.b + f.res + f.guard, id);
        const int t = nextSynth_++;
        const std::string tn = "t" + std::to_string(t - 64);
        Stmt s;
        s.addrs = {addr};
        s.def = t;
        s.defName = tn;
        types_[tn].push_back("int64_t");
        s.rhs = ph(id, old);
        s.atomic = true;
        push(blk, std::move(s));
        const std::string rep = ph(t, tn);
        f.a = substitute(f.a, id, rep, true);
        f.b = substitute(f.b, id, rep, true);
        f.res = substitute(f.res, id, rep, true);
        f.guard = substitute(f.guard, id, rep, true);
    }

    std::string baseCond(const Flags& f, std::string_view cc) const {
        if (cc == "al") return cond("1", "?", "");
        if (cc == "nv") return cond("0", "?", "");
        const std::string ut = f.width == 'w' ? "(uint32_t)" : "(uint64_t)";
        switch (f.kind) {
        case Flags::Cmp:
        case Flags::Cmn: {
            const std::string a = f.a;
            const std::string b = f.kind == Flags::Cmn ? "-" + wrap(f.b) : f.b;
            if (!f.res.empty() && (cc == "eq" || cc == "ne" || cc == "mi" || cc == "pl"))
                return cond(f.res, cc == "eq" ? "==" : cc == "ne" ? "!=" : cc == "mi" ? "<" : ">=", "0");
            if (cc == "eq") return cond(a, "==", b);
            if (cc == "ne") return cond(a, "!=", b);
            if (cc == "ge") return cond(a, ">=", b);
            if (cc == "lt") return cond(a, "<", b);
            if (cc == "gt") return cond(a, ">", b);
            if (cc == "le") return cond(a, "<=", b);
            if (cc == "hs" || cc == "cs") return cond(ut + wrap(a), ">=", ut + wrap(b));
            if (cc == "lo" || cc == "cc") return cond(ut + wrap(a), "<", ut + wrap(b));
            if (cc == "hi") return cond(ut + wrap(a), ">", ut + wrap(b));
            if (cc == "ls") return cond(ut + wrap(a), "<=", ut + wrap(b));
            if (cc == "mi") return cond(a + " - " + wrap(b), "<", "0");
            if (cc == "pl") return cond(a + " - " + wrap(b), ">=", "0");
            if (cc == "vs") return cond("overflow(" + a + " - " + wrap(b) + ")", "?", "");
            if (cc == "vc") return cond("overflow(" + a + " - " + wrap(b) + ")", "!", "");
            break;
        }
        case Flags::Tst: {
            const std::string e = f.a == f.b ? f.a : wrap(f.a) + " & " + wrap(f.b);
            if (cc == "eq") return cond(e, "==", "0");
            if (cc == "ne") return cond(e, "!=", "0");
            if (cc == "mi" || cc == "lt") return cond(e, "<", "0");
            if (cc == "pl" || cc == "ge") return cond(e, ">=", "0");
            if (cc == "gt") return cond(e, ">", "0");
            if (cc == "le") return cond(e, "<=", "0");
            if (cc == "hi" || cc == "hs" || cc == "cs" || cc == "vs") return cond("0", "?", "");
            return cond("1", "?", "");
        }
        case Flags::FCmp: {
            if (cc == "eq") return cond(f.a, "==", f.b);
            if (cc == "ne") return cond(f.a, "!=", f.b);
            if (cc == "mi" || cc == "lo" || cc == "cc" || cc == "lt") return cond(f.a, "<", f.b);
            if (cc == "ge" || cc == "pl" || cc == "hs" || cc == "cs") return cond(f.a, ">=", f.b);
            if (cc == "gt" || cc == "hi") return cond(f.a, ">", f.b);
            if (cc == "le" || cc == "ls") return cond(f.a, "<=", f.b);
            if (cc == "vs") return cond("isunordered(" + f.a + ", " + f.b + ")", "?", "");
            if (cc == "vc") return cond("isunordered(" + f.a + ", " + f.b + ")", "!", "");
            break;
        }
        case Flags::None: break;
        }
        return cond("flags_" + std::string(cc), "?", "");
    }

    std::string flagCond(const Flags& f, std::string_view cc) const {
        const std::string c = baseCond(f, cc);
        if (f.guard.empty()) return c;
        const std::string e = condExpr(c);
        if (evalCond(cc, f.nzcv)) return cond("!" + wrap(f.guard) + " || " + wrap(e), "?", "");
        return cond(wrap(f.guard) + " && " + wrap(e), "?", "");
    }

    std::string calleeName(const arm64::Insn& in, const NativeCode::Line& l) const {
        std::string name;
        if (const NativeCode::Function* t = nc_.functionAt(in.target); t && t->addr == in.target) name = NativeCode::displayName(*t);
        if (name.empty()) name = l.targetName;
        if (name.empty()) name = "sub_" + hex(in.target).substr(2);
        const size_t at = name.find("@plt");
        if (at != std::string::npos) name.erase(at);
        return name;
    }

    static bool noReturn(const std::string& callee) {
        static const char* const kNames[] = {"__stack_chk_fail", "abort", "exit", "_exit", "__cxa_throw", "__cxa_rethrow",
                                             "_Unwind_Resume", "__assert2", "__fortify_fail", "std::terminate()",
                                             "__cxa_bad_cast", "__cxa_bad_typeid", "__cxa_pure_virtual"};
        for (const char* n : kNames)
            if (callee == n) return true;
        return false;
    }

    std::string callArgs(State& st) const {
        unsigned mask = st.argMask;
        if (!mask && !st.callSeen) mask = 1;
        int maxX = -1, maxD = -1;
        for (int r = 0; r < 8; ++r) {
            if (mask & (1u << r)) maxX = r;
            if (st.fpArgMask & (1u << r)) maxD = r;
        }
        std::string args;
        for (int r = 0; r <= maxX; ++r) args += (args.empty() ? "" : ", ") + ph(r, "x" + std::to_string(r));
        for (int r = 0; r <= maxD; ++r) args += (args.empty() ? "" : ", ") + ph(32 + r, "d" + std::to_string(r));
        return args;
    }

    void call(Block& blk, State& st, std::string callee, uint64_t addr) {
        Stmt s;
        s.addrs = {addr};
        s.def = 0;
        s.defName = "x0";
        types_["x0"].push_back("int64_t");
        // Calls that never return or take no arguments do not read x0 - x7.
        const bool noArgs = callee == "__stack_chk_fail" || callee == "abort" || callee == "__cxa_rethrow";
        s.rhs = callee + "(" + (noArgs ? std::string() : callArgs(st)) + ")";
        s.atomic = true;
        s.sideEffect = s.readsMem = true;
        for (int k = 1; k <= 18; ++k) s.kills.push_back(k);
        for (int k = 32; k < 40; ++k) s.kills.push_back(k);
        for (int k = 48; k < 64; ++k) s.kills.push_back(k);
        push(blk, std::move(s));
        st.flags = Flags{};
        for (int k = 0; k <= 18; ++k) st.consts.erase(k), st.addrs.erase(k);
        st.argMask = st.fpArgMask = 0;
        st.callSeen = true;
    }

    void stmt(Block& blk, std::string text, uint64_t addr, bool readsMem = true) {
        Stmt s;
        s.addrs = {addr};
        s.rhs = std::move(text);
        s.sideEffect = true;
        s.readsMem = readsMem;
        push(blk, std::move(s));
    }

    bool frameNoise(const std::string& m, const std::vector<std::string>& ops) const {
        static const char* const kDrop[] = {"nop", "paciasp", "autiasp", "pacibsp", "autibsp", "bti", "hint", "xpaclri",
                                            "dmb", "dsb", "isb", "prfm", "prfum", "clrex", "yield", "pacia", "autia", "pacib", "autib"};
        for (const char* d : kDrop)
            if (m == d) return true;
        if ((m == "sub" || m == "add") && ops.size() >= 2 && ops[0] == "sp" && ops[1] == "sp") return true;
        if ((m == "mov" || m == "add") && ops.size() >= 2 && ops[0] == "x29" && ops[1] == "sp") return true;
        if (m == "stp" || m == "ldp" || m == "str" || m == "ldr" || m == "stur" || m == "ldur") {
            const size_t nregs = (m == "stp" || m == "ldp") ? 2 : 1;
            if (ops.size() < nregs + 1) return false;
            Mem mem;
            if (!parseMem(ops[nregs], ops.size() > nregs + 1 ? &ops[nregs + 1] : nullptr, mem)) return false;
            if (mem.base.id != 31 && mem.base.id != 29) return false;
            for (size_t k = 0; k < nregs; ++k) {
                Reg r;
                if (!parseReg(ops[k], r) || !calleeSaved(r)) return false;
            }
            return true;
        }
        return false;
    }

    void translateBlock(size_t bi) {
        const NativeCode::BasicBlock& cb = cfg_.blocks[bi];
        Block& blk = fn_.blocks[bi];
        blk.addr = cb.lineCount ? cfg_.lines[cb.firstLine].insn.addr : 0;
        for (int s : cb.successors) blk.succ.push_back(s);
        State st;
        // A block starts with the flags its predecessors leave, when they all leave the same: "cmp; b.gt ...; b.ne ..."
        // compares once.
        const Flags* inherited = nullptr;
        bool agree = true;
        for (size_t p = 0; p < cfg_.blocks.size() && agree; ++p) {
            const std::vector<int>& next = cfg_.blocks[p].successors;
            if (std::find(next.begin(), next.end(), static_cast<int>(bi)) == next.end()) continue;
            const auto before = endFlags_.find(static_cast<int>(p));
            if (before == endFlags_.end() || (inherited && !(*inherited == before->second))) agree = false;
            else inherited = &before->second;
        }
        if (agree && inherited) st.flags = *inherited;
        const size_t end = cb.firstLine + cb.lineCount;
        std::string selected;  // jump table: the switched value, copied before the dispatch sequence reuses its register
        if (!cb.cases.empty()) {
            std::vector<uint64_t> targets;
            std::string index;
            Reg selector;
            if (nc_.jumpTable(cfg_.lines, end - 1, targets, index) && parseReg(index, selector)) {
                const int t = nextSynth_++;
                const std::string name = "t" + std::to_string(t - 64);
                Stmt s;
                s.addrs = {cfg_.lines[end - 1].insn.addr};
                s.def = t;
                s.defName = name;
                s.rhs = R(selector);
                s.atomic = true;
                types_[name].push_back("int64_t");
                blk.stmts.push_back(std::move(s));
                selected = ph(t, name);
            }
        }
        for (size_t li = cb.firstLine; li < end; ++li) {
            const NativeCode::Line& l = cfg_.lines[li];
            const bool last = li + 1 == end;
            const arm64::Flow flow = l.insn.flow;
            if (last && flow != arm64::Flow::Normal && flow != arm64::Flow::Call && flow != arm64::Flow::IndirectCall) {
                terminator(blk, st, l, cb);
                if (blk.term.kind == TermKind::Switch && !selected.empty()) blk.term.text = selected;
                endFlags_[static_cast<int>(bi)] = st.flags;
                return;
            }
            if (flow == arm64::Flow::CondJump) {  // conditional tail call inside a block
                stmt(blk, "if (" + condExpr(branchCond(st, l)) + ") return " + calleeName(l.insn, l) + "(" + callArgs(st) + ")", l.insn.addr);
                continue;
            }
            insn(blk, st, l);
            if (flow == arm64::Flow::Call && noReturn(calleeName(l.insn, l))) {
                // What follows is a landing pad or the next function, not this path.
                blk.succ.clear();
                blk.term.kind = TermKind::Stop;
                return;
            }
        }
        // Fell off the block: no terminating instruction.
        blk.term.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall;
        endFlags_[static_cast<int>(bi)] = st.flags;
    }

    std::string branchCond(const State& st, const NativeCode::Line& l) const {
        const arm64::Insn& in = l.insn;
        const std::vector<std::string> ops = splitOps(in.operands);
        if (in.mnemonic.rfind("b.", 0) == 0 || in.mnemonic.rfind("bc.", 0) == 0)
            return flagCond(st.flags, std::string_view(in.mnemonic).substr(in.mnemonic.find('.') + 1));
        Reg r;
        if (ops.empty() || !parseReg(ops[0], r)) return cond("flags", "?", "");
        if (in.mnemonic == "cbz") return cond(R(r), "==", "0");
        if (in.mnemonic == "cbnz") return cond(R(r), "!=", "0");
        int64_t bit = 0;
        if (ops.size() >= 2) parseImm(ops[1], bit);
        const std::string e = wrap(R(r)) + " & " + hex(1ull << (bit & 63));
        return cond(e, in.mnemonic == "tbz" ? "==" : "!=", "0");
    }

    void terminator(Block& blk, State& st, const NativeCode::Line& l, const NativeCode::BasicBlock& cb) {
        const arm64::Insn& in = l.insn;
        Term& t = blk.term;
        t.addrs = {in.addr};
        const std::vector<std::string> ops = splitOps(in.operands);
        switch (in.flow) {
        case arm64::Flow::Return:
            t.kind = TermKind::Return;  // value decided once all blocks are known
            break;
        case arm64::Flow::Trap:
            t.kind = TermKind::Stop;
            t.text = "__builtin_trap()";
            break;
        case arm64::Flow::IndirectJump: {
            if (!cb.cases.empty()) {  // switch: the value the bounds check compared
                tableSwitch(t, cb.cases, "selector");
                break;
            }
            Reg r;
            const std::string target = ops.empty() || !parseReg(ops[0], r) ? std::string("?") : R(r);
            if (st.epilogue || f_.kind == NativeCode::FunctionKind::Plt || nc_.tailJump(cfg_.lines, cb.firstLine + cb.lineCount - 1)) {  // indirect tail call
                t.kind = TermKind::Return;
                t.text = "(*" + target + ")(" + callArgs(st) + ")";
                tailCall_ = true;
            } else {  // jump table or computed goto
                t.kind = TermKind::Stop;
                t.text = "goto *" + target;
            }
            break;
        }
        case arm64::Flow::Jump:
            if (cb.exit || blk.succ.empty()) {  // tail call
                t.kind = TermKind::Return;
                t.text = calleeName(in, l) + "(" + callArgs(st) + ")";
                tailCall_ = true;
            } else {
                t.kind = TermKind::Fall;
            }
            break;
        case arm64::Flow::CondJump:
            if (blk.succ.size() >= 2) {
                t.kind = TermKind::Cond;
                t.text = branchCond(st, l);
            } else if (blk.succ.size() == 1 && blk.succ[0] >= 0 && in.hasTarget &&
                       fn_.blocks.size() > static_cast<size_t>(blk.succ[0]) && !targetInside(in.target)) {
                // Conditional tail call: if (cond) return f(...);
                stmt(blk, "if (" + condExpr(branchCond(st, l)) + ") return " + calleeName(in, l) + "(" + callArgs(st) + ")", in.addr);
                t.kind = TermKind::Fall;
            } else {
                t.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall;
            }
            break;
        default:
            t.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall;
            break;
        }
    }

    bool targetInside(uint64_t a) const { return a >= f_.addr && a < f_.addr + f_.size; }

    void decideReturns() {
        // A function returns a value when x0 is set right before some ret.
        std::string name = "x0";
        for (const Block& b : fn_.blocks) {
            if (b.term.kind != TermKind::Return || !b.term.text.empty()) continue;
            for (const Stmt& s : b.stmts)
                if (s.def == 0) returnsValue_ = true, name = s.defName;
        }
        returnsValue_ = returnsValue_ || tailCall_;
        if (!returnsValue_) return;
        for (Block& b : fn_.blocks)
            if (b.term.kind == TermKind::Return && b.term.text.empty()) b.term.text = ph(0, name == "w0" ? "w0" : "x0");
    }

    void insn(Block& blk, State& st, const NativeCode::Line& l) {
        const arm64::Insn& in = l.insn;
        const uint64_t addr = in.addr;
        std::string m = in.mnemonic;
        const std::vector<std::string> ops = splitOps(in.operands);
        if (!in.known) {
            stmt(blk, "__asm(\"" + m + " " + in.operands + "\")", addr);
            return;
        }
        if (frameNoise(m, ops)) {
            if ((m == "ldp" || m == "ldr") && in.operands.find("x30") != std::string::npos) st.epilogue = true;
            return;
        }
        if (in.flow == arm64::Flow::Call) {
            call(blk, st, calleeName(in, l), addr);
            return;
        }
        if (in.flow == arm64::Flow::IndirectCall) {
            Reg r;
            call(blk, st, "(*" + (ops.empty() || !parseReg(ops[0], r) ? std::string("?") : R(r)) + ")", addr);
            return;
        }
        Reg d, a, b;
        const bool hasD = !ops.empty() && parseReg(ops[0], d);
        const std::string op1 = ops.size() > 1 ? ops[1] : std::string();
        const std::string op2 = ops.size() > 2 ? ops[2] : std::string();
        const std::string op3 = ops.size() > 3 ? ops[3] : std::string();

        // Address formation resolved by NativeCode (adrp + add / ldr, adr, literal loads).
        if (m == "adrp" && hasD && in.hasTarget) {
            define(blk, st, d, hex(in.target), true, addr, false, false, true);
            st.consts[d.id] = st.addrs[d.id] = in.target;
            return;
        }
        if (l.dataAddr && hasD && !l.dataRead && (m == "add" || m == "adr")) {
            std::string e = l.comment.empty() ? hex(l.dataAddr) : l.comment;
            const bool wideLit = e.rfind("u\"", 0) == 0, wide32Lit = e.rfind("U\"", 0) == 0;
            if (!e.empty() && e[0] == '"') e = cQuote(nc_.cStringAt(l.dataAddr));
            else if (wideLit || wide32Lit) e = std::string(wide32Lit ? "U" : "u") + cQuote(nc_.stringAt(l.dataAddr));
            else if (!e.empty() && e.rfind("0x", 0) != 0) e = "&" + e;
            define(blk, st, d, e, true, addr, false, false, true, e[0] == '"' ? "char *" : wideLit ? "char16_t *" : wide32Lit ? "char32_t *" : "void *");
            st.consts[d.id] = st.addrs[d.id] = l.dataAddr;
            return;
        }
        if (l.dataAddr && hasD && l.dataRead && m.rfind("ld", 0) == 0 && ops.size() == 2) {
            std::string e;
            const std::string& c = l.comment;
            if (c.size() > 2 && c.front() == '[' && c.back() == ']') {
                std::string sym = c.substr(1, c.size() - 2);
                const size_t got = sym.find("@got");
                if (got != std::string::npos) e = "&" + sym.substr(0, got);
                else if (sym.find('+') == std::string::npos && sym.rfind("0x", 0) != 0) e = sym;
            }
            if (e.empty()) e = "*(" + std::string(memType(d.cls)) + " *)" + hex(l.dataAddr);
            define(blk, st, d, e, true, addr, true, false, false, e[0] == '&' ? "void *" : std::string());
            return;
        }

        // Loads and stores.
        if (m.rfind("ld", 0) == 0 || m.rfind("st", 0) == 0) {
            if (loadStore(blk, st, m, ops, addr)) return;
        }

        if (m == "mov" || m == "movz" || m == "fmov") {
            if (!hasD || ops.size() < 2) return fallback(blk, st, l, ops);
            int64_t v = 0;
            if (parseImm(op1, v)) {
                if (ops.size() > 2) {
                    int64_t sh = 0;
                    const std::string& s2 = op2;
                    if (s2.rfind("lsl ", 0) == 0) parseImm(s2.substr(4), sh);
                    v = static_cast<int64_t>(static_cast<uint64_t>(v) << sh);
                }
                define(blk, st, d, v < 10 && v > -10 ? std::to_string(v) : signedHex(v), true, addr, false, false, true);
                st.consts[d.id] = static_cast<uint64_t>(v);
                return;
            }
            if (Reg s; parseReg(op1, s)) {
                const auto c = st.consts.find(s.id);
                const bool known = c != st.consts.end();
                const uint64_t value = known ? c->second : 0;
                define(blk, st, d, R(s), true, addr, false, false, s.zero);
                if (known) st.consts[d.id] = value;
                return;
            }
            define(blk, st, d, op1.size() > 1 && op1[0] == '#' ? op1.substr(1) : op1, true, addr, false, false, true);
            return;
        }
        if (m == "movk" && hasD) {
            int64_t v = 0, sh = 0;
            parseImm(op1, v);
            if (op2.rfind("lsl ", 0) == 0) parseImm(op2.substr(4), sh);
            const uint64_t mask = 0xffffull << sh;
            auto c = st.consts.find(d.id);
            if (c != st.consts.end()) {
                const uint64_t nv = (c->second & ~mask) | (static_cast<uint64_t>(v) << sh);
                define(blk, st, d, hex(nv), true, addr, false, false, true);
                st.consts[d.id] = nv;
            } else {
                define(blk, st, d, wrap(R(d)) + " & ~" + hex(mask) + " | " + hex(static_cast<uint64_t>(v) << sh), false, addr);
            }
            return;
        }
        if (m == "movn" && hasD) {
            int64_t v = 0;
            parseImm(op1, v);
            define(blk, st, d, signedHex(~v), true, addr, false, false, true);
            return;
        }

        // Compares.
        if ((m == "cmp" || m == "cmn" || m == "tst" || m == "fcmp" || m == "fcmpe") && ops.size() >= 2) {
            Flags f;
            f.kind = m == "cmp" ? Flags::Cmp : m == "cmn" ? Flags::Cmn : m == "tst" ? Flags::Tst : Flags::FCmp;
            f.a = operand(ops[0]);
            f.b = operand(op1, ops.size() > 2 ? op2 : std::string());
            f.width = hasD ? d.cls : 'x';
            if (f.kind == Flags::FCmp && (op1 == "#0.0" || op1 == "#0")) f.b = "0.0";
            st.flags = f;
            return;
        }
        if ((m == "ccmp" || m == "ccmn" || m == "fccmp" || m == "fccmpe") && ops.size() >= 4) {
            Flags f;
            f.kind = m == "ccmp" ? Flags::Cmp : m == "ccmn" ? Flags::Cmn : Flags::FCmp;
            f.a = operand(ops[0]);
            f.b = operand(op1);
            f.width = hasD ? d.cls : 'x';
            int64_t nzcv = 0;
            parseImm(op2, nzcv);
            f.nzcv = static_cast<unsigned>(nzcv);
            f.guard = condExpr(flagCond(st.flags, op3));
            st.flags = f;
            return;
        }

        if (m == "svc") {
            Reg x0;
            parseReg("x0", x0);
            define(blk, st, x0, "syscall(" + ph(8, "x8") + ", " + ph(0, "x0") + ", " + ph(1, "x1") + ", " + ph(2, "x2") + ", " + ph(3, "x3") + ", " +
                                    ph(4, "x4") + ", " + ph(5, "x5") + ")",
                   true, addr, true, true);
            return;
        }
        if (m == "msr" && ops.size() == 2) {
            stmt(blk, "__builtin_arm_wsr64(\"" + ops[0] + "\", " + operand(op1) + ")", addr);
            return;
        }
        // Exclusive and acquire / release exclusive accesses: the clang builtins.
        if ((m.rfind("ldxr", 0) == 0 || m.rfind("ldaxr", 0) == 0 || m.rfind("stxr", 0) == 0 || m.rfind("stlxr", 0) == 0) && m.find('p') == std::string::npos) {
            const bool load = m[0] == 'l', ordered = m[2] == 'a' || m[2] == 'l';
            const char size = m.back() == 'b' ? 'b' : m.back() == 'h' ? 'h' : 0;
            Reg status, value;
            const size_t valueAt = load ? 0 : 1;
            Mem mem;
            if (ops.size() < valueAt + 2 || !parseReg(ops[valueAt], value) || !parseMem(ops[valueAt + 1], nullptr, mem)) return fallback(blk, st, l, ops);
            const std::string type = size == 'b' ? "uint8_t" : size == 'h' ? "uint16_t" : memType(value.cls);
            const std::string ptr = "(" + type + " *)" + wrap(R(mem.base) + (mem.off ? " + " + signedHex(mem.off) : ""));
            if (load) {
                define(blk, st, value, std::string(ordered ? "__builtin_arm_ldaex(" : "__builtin_arm_ldrex(") + ptr + ")", true, addr, true, true);
            } else {
                if (!parseReg(ops[0], status)) return fallback(blk, st, l, ops);
                define(blk, st, status, std::string(ordered ? "__builtin_arm_stlex(" : "__builtin_arm_strex(") + R(value) + ", " + ptr + ")", true, addr, true, true);
            }
            return;
        }

        if (!hasD) return fallback(blk, st, l, ops);

        // Bit-field inserts and extracts between registers.
        if ((m == "bfi" || m == "bfxil") && ops.size() == 4) {
            int64_t lsb = 0, width = 0;
            parseImm(op2, lsb);
            parseImm(op3, width);
            const uint64_t field = width >= 64 ? ~0ull : (1ull << width) - 1;
            const uint64_t all = d.cls == 'w' ? 0xFFFFFFFFull : ~0ull;
            if (m == "bfi")
                define(blk, st, d, wrap(R(d)) + " & " + hex(~(field << lsb) & all) + " | (" + wrap(operand(op1)) + " & " + hex(field) + ") << " + std::to_string(lsb),
                       false, addr);
            else
                define(blk, st, d, wrap(R(d)) + " & " + hex(~field & all) + " | " + wrap(operand(op1)) + " >> " + std::to_string(lsb) + " & " + hex(field), false, addr);
            return;
        }
        if (m == "extr" && ops.size() == 4) {
            int64_t lsb = 0;
            parseImm(op3, lsb);
            const int width = d.cls == 'w' ? 32 : 64;
            const std::string cast = d.cls == 'w' ? "(uint32_t)" : "(uint64_t)";
            if (lsb == 0) define(blk, st, d, operand(op2), true, addr);
            else
                define(blk, st, d, cast + wrap(operand(op2)) + " >> " + std::to_string(lsb) + " | " + wrap(operand(op1)) + " << " + std::to_string(width - lsb), false,
                       addr);
            return;
        }

        // Conditional selects.
        if ((m == "csel" || m == "csinc" || m == "csinv" || m == "csneg" || m == "fcsel") && ops.size() >= 4) {
            const std::string c = condExpr(flagCond(st.flags, op3));
            std::string other = operand(op2);
            if (m == "csinc") other = wrap(other) + " + 1";
            else if (m == "csinv") other = "~" + wrap(other);
            else if (m == "csneg") other = "-" + wrap(other);
            define(blk, st, d, c + " ? " + operand(op1) + " : " + other, false, addr);
            return;
        }
        if ((m == "cset" || m == "csetm") && ops.size() >= 2) {
            const std::string c = condExpr(flagCond(st.flags, op1));
            define(blk, st, d, m == "cset" ? c : wrap(c) + " ? -1 : 0", false, addr);
            return;
        }
        if ((m == "cinc" || m == "cinv" || m == "cneg") && ops.size() >= 3) {
            const std::string c = condExpr(flagCond(st.flags, op2));
            const std::string x = operand(op1);
            const std::string alt = m == "cinc" ? wrap(x) + " + 1" : m == "cinv" ? "~" + wrap(x) : "-" + wrap(x);
            define(blk, st, d, c + " ? " + alt + " : " + x, false, addr);
            return;
        }

        // Arithmetic and logic.
        static const std::pair<const char*, const char*> kBin[] = {
            {"add", "+"},  {"adds", "+"}, {"sub", "-"},  {"subs", "-"}, {"and", "&"},  {"ands", "&"},  {"orr", "|"},
            {"eor", "^"},  {"mul", "*"},  {"sdiv", "/"}, {"udiv", "/"}, {"lsl", "<<"}, {"lsr", ">>"},  {"asr", ">>"},
            {"lslv", "<<"}, {"lsrv", ">>"}, {"asrv", ">>"}, {"bic", "& ~"}, {"bics", "& ~"}, {"orn", "| ~"}, {"eon", "^ ~"},
            {"fadd", "+"}, {"fsub", "-"}, {"fmul", "*"}, {"fdiv", "/"}};
        // Address arithmetic on a known constant (adrp page + offsets, vtable + 0x10): fold it.
        if ((m == "add" || m == "sub") && ops.size() == 3) {
            Reg src;
            int64_t imm = 0;
            if (parseReg(op1, src) && parseImm(op2, imm)) {
                const auto c = st.addrs.find(src.id);
                if (c != st.addrs.end()) {
                    const uint64_t v = m == "add" ? c->second + static_cast<uint64_t>(imm) : c->second - static_cast<uint64_t>(imm);
                    bool wide = false, utf32 = false;
                    const std::string str = nc_.stringAt(v, &wide, &utf32);
                    std::string e;
                    if (looksLikeText(str)) e = (utf32 ? "U" : wide ? "u" : "") + cQuote(str);
                    else if (const std::string sym = nc_.symbolize(v); !sym.empty()) e = "&" + sym;
                    else e = hex(v);
                    define(blk, st, d, e, true, addr, false, false, true, e[0] == '"' ? "char *" : wide && e[0] == 'U' ? "char32_t *" : wide && e[0] == 'u' ? "char16_t *" : "void *");
                    st.consts[d.id] = st.addrs[d.id] = v;
                    return;
                }
            }
        }
        for (const auto& [name, sym] : kBin) {
            if (m != name || ops.size() < 3) continue;
            std::string lhs = operand(op1);
            std::string rhs = operand(op2, ops.size() > 3 ? op3 : std::string());
            if (m == "lsr" || m == "lsrv" || m == "udiv") lhs = std::string(d.cls == 'w' ? "(uint32_t)" : "(uint64_t)") + wrap(lhs);
            std::string o = sym;
            int64_t v = 0;
            if ((o == "+" || o == "-") && parseImm(op2, v) && v < 0 && ops.size() == 3) {
                o = o == "+" ? "-" : "+";
                rhs = signedHex(-v);
            }
            const std::string e = o.back() == '~' ? wrap(lhs) + " " + o + wrap(rhs) : wrap(lhs) + " " + o + " " + wrap(rhs);
            // Flags of adds / subs / ands.
            if (m == "subs" || m == "adds" || m == "ands" || m == "bics") {
                Flags f;
                f.kind = m == "subs" ? Flags::Cmp : m == "adds" ? Flags::Cmn : Flags::Tst;
                f.a = lhs;
                f.b = m == "bics" ? "~" + wrap(rhs) : rhs;
                f.width = d.cls;
                define(blk, st, d, e, false, addr);
                if (!d.zero) f.res = R(d);
                st.flags = f;
                return;
            }
            define(blk, st, d, e, false, addr);
            return;
        }
        if ((m == "neg" || m == "negs" || m == "mvn" || m == "fneg") && ops.size() >= 2) {
            define(blk, st, d, std::string(m == "mvn" ? "~" : "-") + wrap(operand(op1, ops.size() > 2 ? op2 : std::string())), false, addr);
            return;
        }
        if ((m == "madd" || m == "msub" || m == "fmadd" || m == "fmsub") && ops.size() >= 4) {
            const std::string prod = wrap(operand(op1)) + " * " + wrap(operand(op2));
            define(blk, st, d, operand(op3) + (m == "madd" || m == "fmadd" ? " + " : " - ") + prod, false, addr);
            return;
        }
        if (m == "mneg" && ops.size() >= 3) {
            define(blk, st, d, "-(" + wrap(operand(op1)) + " * " + wrap(operand(op2)) + ")", false, addr);
            return;
        }
        if ((m == "smull" || m == "umull" || m == "smaddl" || m == "umaddl") && ops.size() >= 3 && d.id < 32) {  // vector umull is vmull
            const std::string cast = m[0] == 's' ? "(int64_t)" : "(uint64_t)";
            std::string e = cast + wrap(operand(op1)) + " * " + wrap(operand(op2));
            if (ops.size() >= 4) e = operand(op3) + " + " + e;
            define(blk, st, d, e, false, addr);
            return;
        }
        if ((m == "smulh" || m == "umulh") && ops.size() >= 3) {
            define(blk, st, d, m + "(" + operand(op1) + ", " + operand(op2) + ")", true, addr);
            return;
        }
        if ((m == "ubfx" || m == "sbfx") && ops.size() >= 4) {
            int64_t lsb = 0, width = 0;
            parseImm(op2, lsb);
            parseImm(op3, width);
            const uint64_t mask = width >= 64 ? ~0ull : (1ull << width) - 1;
            std::string e = wrap(operand(op1)) + " >> " + std::to_string(lsb);
            e = (lsb ? "(" + e + ")" : operand(op1)) + " & " + hex(mask);
            if (m == "sbfx") e = "sext(" + e + ", " + std::to_string(width) + ")";
            define(blk, st, d, e, false, addr);
            return;
        }
        if ((m == "ubfiz" || m == "sbfiz") && ops.size() >= 4) {
            int64_t lsb = 0, width = 0;
            parseImm(op2, lsb);
            parseImm(op3, width);
            const uint64_t mask = width >= 64 ? ~0ull : (1ull << width) - 1;
            define(blk, st, d, "(" + wrap(operand(op1)) + " & " + hex(mask) + ") << " + std::to_string(lsb), false, addr);
            return;
        }
        static const std::pair<const char*, const char*> kCast[] = {
            {"sxtb", "(int8_t)"}, {"sxth", "(int16_t)"}, {"sxtw", "(int32_t)"}, {"uxtb", "(uint8_t)"}, {"uxth", "(uint16_t)"}};
        for (const auto& [name, cast] : kCast)
            if (m == name && ops.size() >= 2) {
                define(blk, st, d, std::string(cast) + wrap(operand(op1)), false, addr);
                return;
            }
        if ((m == "scvtf" || m == "ucvtf") && ops.size() >= 2) {
            define(blk, st, d, std::string(d.cls == 's' ? "(float)" : "(double)") + wrap(operand(op1)), false, addr);
            return;
        }
        if ((m.rfind("fcvtz", 0) == 0 || m.rfind("fcvta", 0) == 0 || m.rfind("fcvtm", 0) == 0 || m.rfind("fcvtn", 0) == 0 ||
             m.rfind("fcvtp", 0) == 0) &&
            ops.size() >= 2) {
            const bool u = m.size() > 5 && m[5] == 'u';
            const std::string cast = d.cls == 'w' ? (u ? "(uint32_t)" : "(int32_t)") : (u ? "(uint64_t)" : "(int64_t)");
            define(blk, st, d, cast + wrap(operand(op1)), false, addr);
            return;
        }
        if (m == "fcvt" && ops.size() >= 2) {
            define(blk, st, d, std::string(d.cls == 's' ? "(float)" : d.cls == 'd' ? "(double)" : "(half)") + wrap(operand(op1)), false, addr);
            return;
        }
        static const char* const kFunc[] = {"fabs", "fsqrt", "fmax", "fmin", "fmaxnm", "fminnm", "frintm", "frintp", "frintz",
                                            "frinta", "frintn", "frintx", "frinti", "clz", "cls", "rbit", "rev", "rev16", "rev32",
                                            "ror", "rorv", "fnmul", "fnmadd", "fnmsub", "abs", "cnt"};
        for (const char* fnName : kFunc)
            if (m == fnName && ops.size() >= 2) {
                std::string args;
                for (size_t k = 1; k < ops.size(); ++k) args += (k > 1 ? ", " : "") + operand(ops[k]);
                define(blk, st, d, m + "(" + args + ")", true, addr);
                return;
            }
        if (m == "mrs" && ops.size() >= 2) {
            define(blk, st, d, op1 == "tpidr_el0" ? "__builtin_thread_pointer()" : "__builtin_arm_rsr64(\"" + op1 + "\")", true, addr, true, true);
            return;
        }
        fallback(blk, st, l, ops);
    }

    bool loadStore(Block& blk, State& st, const std::string& mIn, const std::vector<std::string>& ops, uint64_t addr) {
        // Normalise: ldur -> ldr, ldurb -> ldrb, ...; acquire / release forms are plain accesses here.
        std::string m = mIn;
        if (m.rfind("ldur", 0) == 0) m = "ldr" + m.substr(4);
        else if (m.rfind("stur", 0) == 0) m = "str" + m.substr(4);
        else if (m == "ldar" || m == "ldarb" || m == "ldarh") m = "ldr" + m.substr(4);
        else if (m == "ldapr") m = "ldr";
        else if (m == "stlr" || m == "stlrb" || m == "stlrh") m = "str" + m.substr(4);
        const bool pair = m == "ldp" || m == "stp" || m == "ldpsw" || m == "ldnp" || m == "stnp";
        const bool load = m[0] == 'l';
        static const char* const kPlain[] = {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "str", "strb", "strh",
                                             "ldp", "stp", "ldpsw", "ldnp", "stnp"};
        if (std::find_if(std::begin(kPlain), std::end(kPlain), [&](const char* p) { return m == p; }) == std::end(kPlain)) return false;
        const size_t nregs = pair ? 2 : 1;
        if (ops.size() < nregs + 1) return false;
        Reg r[2];
        for (size_t k = 0; k < nregs; ++k)
            if (!parseReg(ops[k], r[k])) return false;
        Mem mem;
        if (!parseMem(ops[nregs], ops.size() > nregs + 1 ? &ops[nregs + 1] : nullptr, mem)) return false;
        // Access type from the mnemonic suffix, else from the register.
        char cls = r[0].cls;
        std::string type = memType(cls);
        if (m == "ldrb" || m == "strb") type = "uint8_t", cls = 'b';
        else if (m == "ldrh" || m == "strh") type = "uint16_t", cls = 'h';
        else if (m == "ldrsb") type = "int8_t", cls = 'b';
        else if (m == "ldrsh") type = "int16_t", cls = 'h';
        else if (m == "ldrsw" || m == "ldpsw") type = "int32_t", cls = 'w';
        const int size = memSize(cls);
        const bool spWriteback = (mem.pre || mem.post) && mem.base.id == 31;
        const auto writeback = [&]() {
            if (!(mem.pre || mem.post) || spWriteback || mem.wb == 0) return;
            define(blk, st, mem.base, wrap(R(mem.base)) + (mem.wb < 0 ? " - " + signedHex(-mem.wb) : " + " + signedHex(mem.wb)), false, addr);
        };
        if (mem.pre) writeback();
        for (size_t k = 0; k < nregs; ++k) {
            std::string lv = deref(mem, static_cast<int>(k) * size, cls, st);
            if (type != memType(cls) && lv.rfind("*(", 0) == 0) lv = "*(" + type + lv.substr(lv.find(" *)"));
            if (lv.rfind("sp_", 0) == 0 || lv.rfind("fp_", 0) == 0) types_[lv].push_back(type);  // a stack slot
            if (load) {
                // A narrower or signed access says more than the register class (ldrb -> uint8_t).
                define(blk, st, r[k], lv, true, addr, true, false, false, type != memType(r[k].cls) ? type : std::string());
            } else {
                Stmt s;
                s.addrs = {addr};
                s.rhs = lv + " = " + R(r[k]);
                s.sideEffect = true;
                push(blk, std::move(s));
            }
        }
        if (mem.post) writeback();
        return true;
    }

    // An Advanced SIMD instruction as its arm_neon.h call `name`: vector registers as values, a load defining the
    // register it fills (vld1q_u32(p)), a store taking the pointer first, lanes as an index, accumulating forms taking
    // the destination first, and the post-index write-back. False: not a shape this handles.
    bool neonCall(Block& blk, State& st, const NativeCode::Line& l, const std::vector<std::string>& ops, std::string name) {
        const arm64::Insn& in = l.insn;
        const std::string& m = in.mnemonic;
        const uint64_t addr = in.addr;
        Reg d;
        if (name.rfind("vld", 0) == 0 || name.rfind("vst", 0) == 0) {
            if (ops.size() < 2 || ops[0].size() < 3 || ops[0][0] != '{') return false;
            const size_t close = ops[0].find('}');
            const std::vector<std::string> items = splitOps(std::string_view(ops[0]).substr(1, close - 1));
            std::vector<Reg> regs(items.size());
            for (size_t k = 0; k < items.size(); ++k)
                if (!parseReg(items[k], regs[k])) return false;
            if (regs.empty()) return false;
            d = regs[0];
            const std::string lane = close + 1 < ops[0].size() && ops[0][close + 1] == '[' ? ops[0].substr(close + 2, ops[0].size() - close - 3) : std::string();
            Mem mem;
            if (!parseMem(ops[1], ops.size() > 2 ? &ops[2] : nullptr, mem) || !mem.index.empty()) return false;
            const std::string ptr = R(mem.base) + (mem.off && !mem.post ? " + " + signedHex(mem.off) : "");
            const bool load = name.rfind("vld", 0) == 0;
            if (regs.size() > 1) {
                // Several registers travel as one arm_neon.h struct: uint32x4x4_t, its .val[k] the registers.
                if (!lane.empty()) return false;
                const VecShape s = vecShape(items[0]);
                if (!s.bits) return false;
                const std::string type = std::string(name.find("_s") != std::string::npos ? "int" : "uint") + std::to_string(s.bits) + "x" +
                                         std::to_string((s.q ? 128 : 64) / s.bits) + "x" + std::to_string(regs.size()) + "_t";
                if (load) {
                    const std::string all = snapshot(blk, name + "(" + ptr + ")", addr, type);
                    for (size_t k = 0; k < regs.size(); ++k) define(blk, st, regs[k], all + ".val[" + std::to_string(k) + "]", true, addr);
                } else {
                    std::string list;
                    for (const Reg& r : regs) list += (list.empty() ? "" : ", ") + R(r);
                    stmt(blk, name + "(" + ptr + ", (" + type + "){{" + list + "}})", addr);
                }
            } else if (load) {
                define(blk, st, d, name + "(" + ptr + (lane.empty() ? "" : ", " + R(d) + ", " + lane) + ")", true, addr, true, true);
            } else {
                stmt(blk, name + "(" + ptr + ", " + R(d) + (lane.empty() ? "" : ", " + lane) + ")", addr);
            }
            // Post-index: by the immediate, or by a register.
            Reg by;
            if (mem.post && mem.wb) define(blk, st, mem.base, wrap(R(mem.base)) + " + " + signedHex(mem.wb), false, addr);
            else if (ops.size() > 2 && parseReg(ops[2], by)) define(blk, st, mem.base, wrap(R(mem.base)) + " + " + R(by), false, addr);
            return true;
        }
        if (!parseReg(ops[0], d) || d.id < 32) {
            // umov / smov into a general register: a lane read.
            if ((m == "umov" || m == "smov" || m == "mov") && ops.size() == 2 && parseReg(ops[0], d)) {
                const size_t bracket = ops[1].find('[');
                Reg v;
                if (bracket == std::string::npos || !parseReg(ops[1], v)) return false;
                v.name = ops[1].substr(0, ops[1].find('.'));
                const VecShape s = vecShape(ops[1]);
                const std::string type = std::string(m == "smov" ? "s" : "u") + std::to_string(s.bits);
                define(blk, st, d, "vgetq_lane_" + type + "(" + R(v) + ", " + ops[1].substr(bracket + 1, ops[1].size() - bracket - 2) + ")", true, addr);
                return true;
            }
            return false;
        }
        // bsl / bit / bif all select bits; arm_neon.h has only vbsl(mask, if set, if clear).
        if ((m == "bsl" || m == "bit" || m == "bif") && ops.size() == 3) {
            Reg n, k;
            if (!parseReg(ops[1], n) || !parseReg(ops[2], k)) return false;
            const std::string q = vecShape(ops[0]).q ? "q" : "";
            const std::string e = m == "bsl" ? R(d) + ", " + R(n) + ", " + R(k) : m == "bit" ? R(k) + ", " + R(n) + ", " + R(d) : R(k) + ", " + R(d) + ", " + R(n);
            define(blk, st, d, "vbsl" + q + "_u8(" + e + ")", true, addr);
            return true;
        }
        static const std::set<std::string> accumulate = {"mla", "mls", "umlal", "smlal", "umlal2", "smlal2", "umlsl", "smlsl", "umlsl2", "smlsl2",
                                                         "usra", "ssra", "ursra", "srsra", "uaba", "saba", "uabal", "sabal", "uabal2", "sabal2",
                                                         "sli", "sri", "sqdmlal", "sqdmlal2", "sqdmlsl", "sqdmlsl2", "uadalp", "sadalp"};
        // The "2" narrowing forms keep the low half of the destination: arm_neon.h takes it first.
        const bool keepsLow = m.size() > 2 && m.back() == '2' && name.find("_high") != std::string::npos && (name.find("vmovn") == 0 || name.find("vqmovn") == 0 ||
                              name.find("vqmovun") == 0 || name.find("shrn") != std::string::npos);
        std::string args;
        for (size_t k = accumulate.count(m) || keepsLow ? 0 : 1; k < ops.size(); ++k) {
            const std::string& t = ops[k];
            std::string e;
            Reg r;
            int64_t imm = 0;
            const size_t bracket = t.find('[');
            if (bracket != std::string::npos && parseReg(t, r)) {  // an element: the register, then the index
                r.name = t.substr(0, t.find('.'));
                e = R(r) + ", " + t.substr(bracket + 1, t.size() - bracket - 2);
            }
            else if (parseReg(t, r)) e = R(r);
            else if (parseImm(t, imm)) e = std::to_string(imm);
            else return false;
            if (name.rfind("vmovl", 0) == 0 && k == ops.size() - 1 && imm == 0 && t[0] == '#') continue;  // ushll #0
            args += (args.empty() ? "" : ", ") + e;
        }
        define(blk, st, d, name + "(" + args + ")", true, addr);
        return true;
    }

    void fallback(Block& blk, State& st, const NativeCode::Line& l, const std::vector<std::string>& ops) {
        const arm64::Insn& in = l.insn;
        const std::string& m = in.mnemonic;
        Reg v;
        if (ops.size() >= 2 && parseReg(ops[0], v) && v.id >= 32) {
            std::vector<std::string> a;
            for (size_t k = 1; k < ops.size(); ++k) a.push_back(operand(ops[k]));
            std::string e;
            if ((m == "fmla" || m == "mla") && a.size() == 2) e = R(v) + " + " + wrap(a[0]) + " * " + wrap(a[1]);
            else if ((m == "fmls" || m == "mls") && a.size() == 2) e = R(v) + " - " + wrap(a[0]) + " * " + wrap(a[1]);
            else if ((m == "faddp" || m == "addp") && !a.empty()) e = vectorCall("pairwise_add", a);
            else if (m == "dup" && a.size() == 1) e = vectorCall("splat", a);
            else if (m == "movi" && a.size() == 1) e = vectorCall("splat", a);
            else if (m == "zip1" && a.size() == 2) e = vectorCall("interleave_low", a);
            else if (m == "zip2" && a.size() == 2) e = vectorCall("interleave_high", a);
            else if (m == "uzp1" && a.size() == 2) e = vectorCall("even_lanes", a);
            else if (m == "uzp2" && a.size() == 2) e = vectorCall("odd_lanes", a);
            else if (m == "ext" && a.size() == 3) e = vectorCall("ext", a);
            else if (m == "addv" && a.size() == 1) e = vectorCall("sum", a);
            else if (m == "umov" && a.size() == 1) e = a[0];
            else if (m == "xtn" && a.size() == 1) e = vectorCall("narrow", a);
            else if ((m == "sshll" || m == "ushll") && a.size() == 2) e = "widening(" + wrap(a[0]) + " << " + a[1] + ")";
            else if ((m == "sshr" || m == "ushr") && a.size() == 2) e = wrap(a[0]) + " >> " + a[1];
            else if (m == "shl" && a.size() == 2) e = wrap(a[0]) + " << " + a[1];
            else if ((m == "smin" || m == "umin") && a.size() == 2) e = vectorCall("min", a);
            else if ((m == "smax" || m == "umax") && a.size() == 2) e = vectorCall("max", a);
            else if ((m == "cmeq" || m == "fcmeq") && a.size() == 2) e = wrap(a[0]) + " == " + wrap(a[1]);
            else if ((m == "cmgt" || m == "fcmgt") && a.size() == 2) e = wrap(a[0]) + " > " + wrap(a[1]);
            if (!e.empty()) {
                define(blk, st, v, e, false, in.addr);
                return;
            }
        }
        if ((m == "umov" || m == "smov") && neonCall(blk, st, l, ops, "vgetq_lane")) return;
        if (const std::string named = neonA64Name(m, ops); !named.empty() && neonCall(blk, st, l, ops, named)) return;
        std::string args;
        size_t first = 0;
        Reg d;
        const bool defines = !ops.empty() && parseReg(ops[0], d) && m.rfind("st", 0) != 0 && m.rfind("cmp", 0) != 0 &&
                             m.rfind("tst", 0) != 0 && m.rfind("msr", 0) != 0;
        if (defines) first = 1;
        for (size_t k = first; k < ops.size(); ++k) {
            std::string e;
            Mem mem;
            if (!ops[k].empty() && ops[k][0] == '[' && parseMem(ops[k], nullptr, mem)) {
                e = "[" + R(mem.base) + (mem.index.empty() ? "" : " + " + wrap(mem.index)) +
                    (mem.off ? " + " + signedHex(mem.off) : "") + "]";
            } else {
                e = operand(ops[k]);
            }
            args += (k > first ? ", " : "") + e;
        }
        const std::string call = "__" + m + "(" + args + ")";
        // Only these write NZCV; everything else (vector arithmetic, say) leaves a pending compare in place.
        static const char* const setsFlags[] = {"adds", "subs", "ands", "bics", "adcs", "sbcs", "negs", "ngcs", "cmp",   "cmn",   "tst",
                                                "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe", "msr", "cfinv", "rmif", "setf8", "setf16"};
        if (std::find_if(std::begin(setsFlags), std::end(setsFlags), [&](const char* x) { return m == x; }) != std::end(setsFlags)) st.flags = Flags{};
        if (defines) define(blk, st, d, call, true, in.addr, true, true);
        else stmt(blk, call, in.addr);
    }

    const NativeCode& nc_;
    const NativeCode::Function& f_;
    NativeCode::ControlFlow cfg_;
    Fn fn_;
    int nextSynth_ = 64;
    std::map<int, Flags> endFlags_;  // block -> the flags it leaves
    std::map<std::string, std::vector<std::string>> types_;  // variable key -> types of the values it is given
    bool returnsValue_ = false;
    bool tailCall_ = false;
};

// ===========================================================================
// x86, x86-64 and ARM (A32 / Thumb)
// ===========================================================================

// The same intermediate form as AArch64, filled from the x86 and ARM listings. Registers are one variable each under
// their full name (rax, eax, r0); narrower reads and writes show as casts. Calls take the registers (x86-64: rdi, rsi,
// rdx, rcx, r8, r9; ARM: r0-r3) written since the previous call, or on x86 the values pushed for it; stack
// parameters of x86 functions with a frame pointer are fp_8, fp_c, ... Instructions without a translation show as
// __mnemonic(operands).
class OtherDecompiler {
public:
    OtherDecompiler(const NativeCode& nc, const NativeCode::Function& f)
        : nc_(nc), f_(f), arm_(nc.isa() == NativeCode::Isa::Arm32), x64_(nc.isa() == NativeCode::Isa::X86_64) {}

    Output run() {
        Output out;
        lines_ = nc_.disassembleFunction(f_, 20000);
        if (lines_.empty()) {
            out.error = "no code decoded for this function";
            return out;
        }
        conditions();
        if (arm_) frameLayout();
        if (!blocks()) {
            out.error = "function too large to decompile";
            return out;
        }
        fn_.labelPrefix = "loc_";
        fn_.roots.push_back(0);
        std::vector<char> reach(fn_.blocks.size(), 0);
        std::vector<int> work{0};
        while (!work.empty()) {
            const int b = work.back();
            work.pop_back();
            if (b < 0 || static_cast<size_t>(b) >= reach.size() || reach[static_cast<size_t>(b)]) continue;
            reach[static_cast<size_t>(b)] = 1;
            for (int s : fn_.blocks[static_cast<size_t>(b)].succ) work.push_back(s);
        }
        for (size_t i = 0; i < fn_.blocks.size(); ++i)
            if (!reach[i]) fn_.blocks[i].term.kind = TermKind::Stop;
        for (const int b : predecessorsFirst(fn_.blocks.size(), [this](size_t i) -> const std::vector<int>& { return fn_.blocks[i].succ; }))
            translateBlock(static_cast<size_t>(b));
        decideReturns();
        fn_.regCount = nextSynth_;
        simplify(fn_);

        const Liveness lv = liveness(fn_);
        std::vector<int> argRegs = argumentRegisters();
        int last = -1;
        for (size_t i = 0; i < argRegs.size(); ++i)
            if (lv.in[0].test(argRegs[i])) last = static_cast<int>(i);
        if (arm_ && maxStackArg_ >= 0) last = 3;  // stack arguments come after all of r0-r3
        for (int i = 0; i <= last; ++i) out.vars.push_back(Var{regName(argRegs[static_cast<size_t>(i)]), wordType(), std::string(), true});
        for (int off = 0; arm_ && off <= maxStackArg_; off += 4)
            out.vars.push_back(Var{"stk_" + hex(static_cast<uint64_t>(off)).substr(2), "int32_t", std::string(), true});
        for (int off = 8; !arm_ && off <= maxStackArg_; off += 4) out.vars.push_back(Var{"fp_" + hex(static_cast<uint64_t>(off)).substr(2), "int32_t", std::string(), true});
        out.lines.push_back({"// " + hex(f_.addr) + " (" + std::to_string(f_.size) + " bytes, " + NativeCode::isaName(nc_.isa()) + ")", 0, {}});
        out.headerLine = static_cast<int>(out.lines.size());
        out.returnType = fpuReturns_ ? "double" : returnsValue_ ? wordType() : "void";
        out.returnAt = 0;
        out.headerPrefix = out.returnType + " " + NativeCode::displayName(f_) + "(";
        out.headerSuffix = ") {";
        out.lines.push_back({std::string(), 0, {f_.addr}});
        Structurer(fn_, out.lines).run(1);
        flattenNesting(out.lines);
        if (!returnsValue_) dropTrailingReturn(out.lines);
        out.lines.push_back({"}", 0, {}});
        declareLocals(out, types_, true);
        applyUserNames(out, {}, {}, true);
        return out;
    }

private:
    struct Flags {
        enum Kind { None, Cmp, Cmn, Tst, FCmp, Bit, Over, Vtest } kind = None;  // Bit: x86 "bt"; Over: mul / imul; Vtest: ptest a, b
        std::string a, b, res;
        bool operator==(const Flags& o) const { return kind == o.kind && a == o.a && b == o.b && res == o.res; }
    };
    struct State {
        Flags flags;
        std::map<int, uint64_t> consts;     // registers holding a known constant or address
        std::vector<std::string> pushed;    // x86: values pushed for the next call
        std::set<int> written;              // registers written since the last call
        std::set<int> outgoing;             // ARM: stack offsets stored since the last call
        bool callSeen = false;
        // x87: the values this block pushed (back = st(0)), above what the block started with (st0, st1, ... from
        // the variables of those names); fpuUnder of those have been pulled into fpu.
        std::vector<std::string> fpu;
        int fpuUnder = 0;
        // i386: the call just made, whose float or double result (in st(0)) the next x87 read takes.
        Block* fpuCallBlock = nullptr;
        int fpuCall = -1;
    };

    // --- registers -----------------------------------------------------------
    // 0..15 general (x86 numbering, or r0..r15), 32..95 FP / SIMD.
    static constexpr int kFp = 32;
    static constexpr int kFirstTemp = 96;
    static constexpr int kX87 = kFp + 56;  // x86: the x87 stack positions st0..st7 as variables, between blocks

    std::string regName(int id) const {
        static const char* const x64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        static const char* const x86[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        if (arm_) {
            if (id >= kFp + 64) return "q" + std::to_string(id - kFp - 64);
            if (id >= kFp) return (id - kFp >= 32 ? "s" + std::to_string(id - kFp - 32) : "d" + std::to_string(id - kFp));
            return "r" + std::to_string(id);
        }
        if (id >= kX87 && id < kX87 + 8) return "st" + std::to_string(id - kX87);
        if (id >= kFp) return "xmm" + std::to_string(id - kFp);
        return x64_ ? x64[id & 15] : x86[id & 7];
    }

    // A register operand: its id and width in bits.
    bool parseRegister(const std::string& t, int& id, int& bits) const {
        if (t.size() < 2) return false;
        const auto number = [&](size_t from, size_t to, int& n) {
            if (from >= to) return false;
            n = 0;
            for (size_t i = from; i < to; ++i) {
                if (t[i] < '0' || t[i] > '9') return false;
                n = n * 10 + (t[i] - '0');
            }
            return true;
        };
        int n = 0;
        if (arm_) {
            static const std::pair<const char*, int> named[] = {{"sp", 13}, {"lr", 14}, {"pc", 15}, {"ip", 12}, {"fp", 11}, {"sl", 10}, {"sb", 9}};
            for (const auto& [name, r] : named)
                if (t == name) return id = r, bits = 32, true;
            if (t[0] == 'r' && number(1, t.size(), n) && n < 16) return id = n, bits = 32, true;
            if (t[0] == 'd' && number(1, t.size(), n) && n < 32) return id = kFp + n, bits = 64, true;
            if (t[0] == 's' && number(1, t.size(), n) && n < 32) return id = kFp + 32 + n, bits = 32, true;
            if (t[0] == 'q' && number(1, t.size(), n) && n < 16) return id = kFp + 64 + n, bits = 128, true;
            return false;
        }
        static const char* const r64[8] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
        static const char* const r32[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        static const char* const r16[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
        static const char* const r8[8] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
        static const char* const high[4] = {"ah", "ch", "dh", "bh"};
        for (int i = 0; i < 8; ++i) {
            if (t == r64[i]) return id = i, bits = 64, true;
            if (t == r32[i]) return id = i, bits = 32, true;
            if (t == r16[i]) return id = i, bits = 16, true;
            if (t == r8[i]) return id = i, bits = 8, true;
        }
        for (int i = 0; i < 4; ++i)
            if (t == high[i]) return id = i, bits = 8, true;
        if (t[0] == 'r' && t.size() >= 2) {
            size_t end = t.size();
            int width = 64;
            if (t.back() == 'd') width = 32, --end;
            else if (t.back() == 'w') width = 16, --end;
            else if (t.back() == 'b') width = 8, --end;
            if (number(1, end, n) && n >= 8 && n < 16) return id = n, bits = width, true;
        }
        if (t.rfind("xmm", 0) == 0 && number(3, t.size(), n) && n < 32) return id = kFp + n, bits = 128, true;
        return false;
    }

    std::string read(int id) const { return ph(id, regName(id)); }
    std::string wordType() const { return x64_ ? "int64_t" : "int32_t"; }
    static std::string castFor(int bits, bool isSigned) { return std::string("(") + (isSigned ? "int" : "uint") + std::to_string(bits) + "_t)"; }

    static std::string number(int64_t v) { return v < 10 && v > -10 ? std::to_string(v) : signedHex(v); }
    static bool parseNumber(std::string_view t, int64_t& v) {
        if (!t.empty() && t[0] == '#') t.remove_prefix(1);
        bool neg = false;
        if (!t.empty() && (t[0] == '-' || t[0] == '+')) neg = t[0] == '-', t.remove_prefix(1);
        if (t.empty() || t[0] < '0' || t[0] > '9') return false;
        char* end = nullptr;
        const std::string s(t);
        const uint64_t u = std::strtoull(s.c_str(), &end, 0);
        if (!end || *end) return false;
        v = static_cast<int64_t>(neg ? 0 - u : u);
        return true;
    }

    // --- conditions and blocks -------------------------------------------------
    // The condition an instruction executes under: ARM IT blocks and A32 condition fields. "" = always.
    void conditions() {
        cc_.assign(lines_.size(), std::string());
        mnemonic_.clear();
        for (const NativeCode::Line& l : lines_) mnemonic_.push_back(l.insn.mnemonic);
        if (!arm_) return;
        static const char* const names[15] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", ""};
        for (size_t i = 0; i < lines_.size(); ++i) {
            const arm64::Insn& in = lines_[i].insn;
            std::string& m = mnemonic_[i];
            if (m.size() > 2 && m.compare(m.size() - 2, 2, ".w") == 0) m.erase(m.size() - 2);
            if (in.thumb) {
                if (m.size() >= 2 && m.size() <= 5 && m.compare(0, 2, "it") == 0 && m.find_first_not_of("te", 2) == std::string::npos) {
                    const std::string first = in.operands == "cs" ? "hs" : in.operands == "cc" ? "lo" : in.operands;
                    for (size_t k = 0; k + 1 < m.size() && i + 1 + k < lines_.size(); ++k)
                        cc_[i + 1 + k] = k == 0 || m[1 + k] == 't' ? first : inverse(first);
                }
            } else if (const unsigned cond = in.raw >> 28; cond < 14) {
                const std::string suffix = arm32::conditionName(cond);
                const size_t at = m.rfind(suffix);
                if (!suffix.empty() && at != std::string::npos && at > 0) {
                    m.erase(at, suffix.size());
                    if (m != "b") cc_[i] = names[cond];
                    else m = in.mnemonic;  // a conditional branch keeps its suffix
                }
            }
        }
    }

    static std::string inverse(const std::string& cc) {
        static const std::pair<const char*, const char*> pairs[] = {{"eq", "ne"}, {"hs", "lo"}, {"mi", "pl"}, {"vs", "vc"}, {"hi", "ls"}, {"ge", "lt"}, {"gt", "le"}};
        for (const auto& [a, b] : pairs) {
            if (cc == a) return b;
            if (cc == b) return a;
        }
        return cc;
    }

    // "call next; pop reg": how 32-bit x86 reads its own address.
    bool callNext(size_t i) const {
        const arm64::Insn& in = lines_[i].insn;
        return !arm_ && in.flow == arm64::Flow::Call && in.hasTarget && in.target == in.addr + in.size;
    }

    arm64::Flow flowOf(size_t i) const {
        const arm64::Flow f = lines_[i].insn.flow;
        // "ldrls pc, [pc, r0, lsl #2]": a jump table under its bounds check, falling through to the default.
        if (f == arm64::Flow::IndirectJump && conditionalTables_.count(i)) return f;
        // A conditional return or indirect jump falls through when the condition fails: it is a statement, not an end.
        if (!cc_[i].empty() && (f == arm64::Flow::Return || f == arm64::Flow::IndirectJump || f == arm64::Flow::Jump)) return arm64::Flow::Normal;
        return f;
    }

    bool blocks() {
        const size_t n = lines_.size();
        const auto lineOf = [&](uint64_t addr) -> int {
            for (size_t lo = 0, hi = n; lo < hi;) {
                const size_t mid = (lo + hi) / 2;
                if (lines_[mid].insn.addr == addr) return static_cast<int>(mid);
                if (lines_[mid].insn.addr < addr) lo = mid + 1;
                else hi = mid;
            }
            return -1;
        };
        const auto ends = [](arm64::Flow f) { return f != arm64::Flow::Normal && f != arm64::Flow::Call && f != arm64::Flow::IndirectCall; };
        std::vector<char> leader(n, 0);
        leader[0] = 1;
        for (size_t i = 0; i < n; ++i) {
            std::vector<uint64_t> targets;
            std::string index;
            if (!cc_[i].empty() && lines_[i].insn.flow == arm64::Flow::IndirectJump && nc_.jumpTable(lines_, i, targets, index)) conditionalTables_.insert(i);
        }
        for (size_t i = 0; i < n; ++i) {
            const arm64::Insn& in = lines_[i].insn;
            const bool stops = flowOf(i) == arm64::Flow::Call && in.hasTarget && noReturn(calleeName(i));
            if (!ends(flowOf(i)) && !stops) continue;
            std::vector<uint64_t> targets;
            std::string index;
            if (flowOf(i) == arm64::Flow::IndirectJump && nc_.jumpTable(lines_, i, targets, index)) {
                for (uint64_t t : targets)
                    if (const int line = lineOf(t); line >= 0) leader[static_cast<size_t>(line)] = 1;
                tables_[i] = {std::move(targets), index};
            }
            if (i + 1 < n) leader[i + 1] = 1;
            if (in.hasTarget && !stops)
                if (const int t = lineOf(in.target); t >= 0) leader[static_cast<size_t>(t)] = 1;
        }
        std::vector<int> blockOf(n, 0);
        for (size_t i = 0; i < n; ++i) {
            if (leader[i]) {
                first_.push_back(i);
                count_.push_back(0);
            }
            blockOf[i] = static_cast<int>(first_.size()) - 1;
            ++count_.back();
        }
        if (first_.size() > kMaxBlocks) return false;
        fn_.blocks.resize(first_.size());
        for (size_t b = 0; b < first_.size(); ++b) {
            Block& blk = fn_.blocks[b];
            blk.addr = lines_[first_[b]].insn.addr;
            const size_t last = first_[b] + count_[b] - 1;
            const arm64::Insn& in = lines_[last].insn;
            const int next = last + 1 < n ? blockOf[last + 1] : -1;
            const int target = in.hasTarget ? lineOf(in.target) : -1;
            switch (flowOf(last)) {
            case arm64::Flow::Jump:
                if (target >= 0) blk.succ.push_back(blockOf[static_cast<size_t>(target)]);
                break;
            case arm64::Flow::CondJump:
                if (target >= 0) blk.succ.push_back(blockOf[static_cast<size_t>(target)]);
                if (next >= 0) blk.succ.push_back(next);
                break;
            case arm64::Flow::IndirectJump:
                if (const auto table = tables_.find(last); table != tables_.end()) {
                    if (conditionalTables_.count(last) && next >= 0) blk.succ.push_back(next);  // the default: first
                    for (size_t k = 0; k < table->second.first.size(); ++k) {
                        const int line = lineOf(table->second.first[k]);
                        if (line < 0) continue;
                        const int to = blockOf[static_cast<size_t>(line)];
                        cases_[static_cast<int>(b)].push_back({static_cast<int64_t>(k), to});
                        if (std::find(blk.succ.begin(), blk.succ.end(), to) == blk.succ.end()) blk.succ.push_back(to);
                    }
                }
                break;
            case arm64::Flow::Return:
            case arm64::Flow::Trap: break;
            case arm64::Flow::Call:
                if (in.hasTarget && noReturn(calleeName(last))) break;
                [[fallthrough]];
            default:
                if (next >= 0) blk.succ.push_back(next);
                break;
            }
        }
        return true;
    }

    // --- calls -------------------------------------------------------------------
    std::string calleeName(size_t i) const {
        const arm64::Insn& in = lines_[i].insn;
        std::string name;
        if (const NativeCode::Function* t = nc_.functionAt(in.target); t && t->addr == in.target) name = NativeCode::displayName(*t);
        if (name.empty()) name = lines_[i].targetName;
        if (name.empty()) name = "sub_" + hex(in.target).substr(2);
        const size_t at = name.find("@plt");
        if (at != std::string::npos) name.erase(at);
        return name;
    }

    static bool noReturn(const std::string& callee) {
        static const char* const kNames[] = {"__stack_chk_fail", "abort", "exit", "_exit", "__cxa_throw", "__cxa_rethrow", "_Unwind_Resume",
                                             "__assert2", "__fortify_fail", "std::terminate()", "__cxa_bad_cast", "__cxa_bad_typeid"};
        for (const char* n : kNames)
            if (callee == n) return true;
        return false;
    }

    std::vector<int> argumentRegisters() const {
        if (arm_) return {0, 1, 2, 3};
        if (x64_) return {7, 6, 2, 1, 8, 9};
        return {};
    }

    std::string callArgs(State& st, bool consume) const {
        std::string args;
        const auto add = [&](const std::string& a) { args += (args.empty() ? "" : ", ") + a; };
        if (!arm_ && !x64_) {  // cdecl: the pushed values, last pushed first
            for (size_t i = st.pushed.size(); i-- > 0;) add(st.pushed[i]);
            if (consume) st.pushed.clear();
            return args;
        }
        const std::vector<int> regs = argumentRegisters();
        int last = -1;
        for (size_t i = 0; i < regs.size(); ++i)
            if (st.written.count(regs[i])) last = static_cast<int>(i);
        if (last < 0 && !st.callSeen) last = 0;
        for (int i = 0; i <= last; ++i) add(read(regs[static_cast<size_t>(i)]));
        if (arm_ && last == 3 && st.written.count(0) && st.written.count(1) && st.written.count(2) && st.written.count(3))
            for (int off = 0; off < 64 && st.outgoing.count(off); off += 4) add("sp_" + hex(static_cast<uint64_t>(off)).substr(2));
        return args;
    }

    void call(Block& blk, State& st, const std::string& callee, uint64_t addr) {
        Stmt s;
        s.addrs = {addr};
        s.def = 0;
        s.defName = regName(0);
        types_[s.defName].push_back(wordType());
        s.rhs = callee + "(" + (callee == "__stack_chk_fail" || callee == "abort" ? std::string() : callArgs(st, true)) + ")";
        s.atomic = true;
        s.sideEffect = s.readsMem = true;
        const std::vector<int> lost = arm_ ? std::vector<int>{1, 2, 3, 12, 14} : x64_ ? std::vector<int>{1, 2, 6, 7, 8, 9, 10, 11} : std::vector<int>{1, 2};
        for (int r : lost) s.kills.push_back(r), st.consts.erase(r);
        st.consts.erase(0);
        blk.stmts.push_back(std::move(s));
        if (!arm_ && !x64_) {  // the x87 stack is empty at a call; a float result comes back in st(0)
            st.fpu.clear();
            st.fpuUnder = 0;
            st.fpuCallBlock = &blk;
            st.fpuCall = static_cast<int>(blk.stmts.size()) - 1;
        }
        st.flags = Flags{};
        st.written.clear();
        st.pushed.clear();
        st.outgoing.clear();
        st.callSeen = true;
    }

    // --- statements ------------------------------------------------------------
    void stmt(Block& blk, std::string text, uint64_t addr, bool readsMem = true) {
        Stmt s;
        s.addrs = {addr};
        s.rhs = std::move(text);
        s.sideEffect = true;
        s.readsMem = readsMem;
        blk.stmts.push_back(std::move(s));
    }

    // Keeps a copy of register `id` for pending flags and pushed values that still need its old value.
    void preserve(Block& blk, State& st, int id, uint64_t addr) {
        bool used = countUses(st.flags.a, id) || countUses(st.flags.b, id) || countUses(st.flags.res, id);
        for (const std::string& p : st.pushed) used = used || countUses(p, id);
        if (!used) return;
        const int t = nextSynth_++;
        const std::string name = "t" + std::to_string(t - kFirstTemp);
        Stmt s;
        s.addrs = {addr};
        s.def = t;
        s.defName = name;
        types_[name].push_back(id >= kFp ? "float" : wordType());
        s.rhs = read(id);
        s.atomic = true;
        blk.stmts.push_back(std::move(s));
        const std::string rep = ph(t, name);
        st.flags.a = substitute(st.flags.a, id, rep, true);
        st.flags.b = substitute(st.flags.b, id, rep, true);
        st.flags.res = substitute(st.flags.res, id, rep, true);
        for (std::string& p : st.pushed) p = substitute(p, id, rep, true);
    }

    // A temporary holding `rhs` now: for instructions with two results that both read the old values.
    std::string snapshot(Block& blk, const std::string& rhs, uint64_t addr, const std::string& type) {
        const int t = nextSynth_++;
        const std::string name = "t" + std::to_string(t - kFirstTemp);
        Stmt s;
        s.addrs = {addr};
        s.def = t;
        s.defName = name;
        types_[name].push_back(type);
        s.rhs = rhs;
        s.atomic = rhs.find(' ') == std::string::npos;
        blk.stmts.push_back(std::move(s));
        return ph(t, name);
    }

    void define(Block& blk, State& st, int id, std::string rhs, bool atomic, uint64_t addr, bool readsMem = false, bool sideEffect = false,
                bool constant = false, const std::string& type = std::string()) {
        preserve(blk, st, id, addr);
        const std::string name = regName(id);
        types_[name].push_back(!type.empty() ? type : id >= kFp ? (name[0] == 's' ? "float" : "double") : wordType());
        Stmt s;
        s.addrs = {addr};
        s.def = id;
        s.defName = name;
        s.rhs = std::move(rhs);
        s.atomic = atomic;
        s.readsMem = readsMem;
        s.sideEffect = sideEffect;
        s.constant = constant;
        blk.stmts.push_back(std::move(s));
        st.consts.erase(id);
        st.written.insert(id);
    }

    // The condition for ARM / x86 condition code `cc` ("eq", "ne", "lt", ...) against the pending flags.
    std::string flagCond(const Flags& f, const std::string& cc) const {
        const std::string ut = x64_ ? "(uint64_t)" : "(uint32_t)";
        switch (f.kind) {
        case Flags::Cmp:
        case Flags::Cmn: {
            const std::string a = f.a, b = f.kind == Flags::Cmn ? "-" + wrap(f.b) : f.b;
            if (!f.res.empty() && (cc == "eq" || cc == "ne" || cc == "mi" || cc == "pl"))
                return cond(f.res, cc == "eq" ? "==" : cc == "ne" ? "!=" : cc == "mi" ? "<" : ">=", "0");
            if (cc == "eq") return cond(a, "==", b);
            if (cc == "ne") return cond(a, "!=", b);
            if (cc == "ge") return cond(a, ">=", b);
            if (cc == "lt") return cond(a, "<", b);
            if (cc == "gt") return cond(a, ">", b);
            if (cc == "le") return cond(a, "<=", b);
            if (cc == "hs") return cond(ut + wrap(a), ">=", ut + wrap(b));
            if (cc == "lo") return cond(ut + wrap(a), "<", ut + wrap(b));
            if (cc == "hi") return cond(ut + wrap(a), ">", ut + wrap(b));
            if (cc == "ls") return cond(ut + wrap(a), "<=", ut + wrap(b));
            if (cc == "mi") return cond(a + " - " + wrap(b), "<", "0");
            if (cc == "pl") return cond(a + " - " + wrap(b), ">=", "0");
            if (cc == "vs" || cc == "vc") return cond("overflow(" + a + " - " + wrap(b) + ")", cc == "vs" ? "?" : "!", "");
            break;
        }
        case Flags::Vtest:  // ZF: no bit set in both; CF: no bit of b outside a
            if (cc == "eq" || cc == "ne") return cond(wrap(f.a) + " & " + wrap(f.b), cc == "eq" ? "==" : "!=", "0");
            if (cc == "lo" || cc == "hs") return cond("~" + wrap(f.a) + " & " + wrap(f.b), cc == "lo" ? "==" : "!=", "0");
            break;
        case Flags::Over:  // only carry and overflow mean anything after a multiplication
            if (cc == "vs" || cc == "lo") return cond("overflow(" + f.a + ")", "?", "");
            if (cc == "vc" || cc == "hs") return cond("overflow(" + f.a + ")", "!", "");
            break;
        case Flags::Bit:
            if (cc == "lo") return cond(f.a, "!=", "0");
            if (cc == "hs") return cond(f.a, "==", "0");
            break;
        case Flags::Tst: {
            const std::string e = f.b.empty() || f.a == f.b ? f.a : wrap(f.a) + " & " + wrap(f.b);
            if (cc == "vs" || cc == "vc") return cond("overflow(" + e + ")", cc == "vs" ? "?" : "!", "");
            if (cc == "eq") return cond(e, "==", "0");
            if (cc == "ne") return cond(e, "!=", "0");
            if (cc == "mi" || cc == "lt") return cond(e, "<", "0");
            if (cc == "pl" || cc == "ge") return cond(e, ">=", "0");
            if (cc == "gt") return cond(e, ">", "0");
            if (cc == "le") return cond(e, "<=", "0");
            break;
        }
        case Flags::FCmp:
            if (cc == "eq") return cond(f.a, "==", f.b);
            if (cc == "ne") return cond(f.a, "!=", f.b);
            if (cc == "mi" || cc == "lo" || cc == "lt") return cond(f.a, "<", f.b);
            if (cc == "ge" || cc == "pl" || cc == "hs") return cond(f.a, ">=", f.b);
            if (cc == "gt" || cc == "hi") return cond(f.a, ">", f.b);
            if (cc == "le" || cc == "ls") return cond(f.a, "<=", f.b);
            // x86 "jp" / "jnp" after comiss, ARM "bvs" / "bvc" after vcmp: one side is a NaN, or neither.
            if (cc == "vs" || cc == "vc") return cond("isunordered(" + f.a + ", " + f.b + ")", cc == "vs" ? "?" : "!", "");
            break;
        case Flags::None: break;
        }
        return cond("flags_" + cc, "?", "");
    }

    static std::string x86Condition(const std::string& cc) {
        static const std::pair<const char*, const char*> map[] = {
            {"e", "eq"},  {"z", "eq"},  {"ne", "ne"}, {"nz", "ne"}, {"l", "lt"},  {"ge", "ge"}, {"le", "le"}, {"g", "gt"},  {"b", "lo"},
            {"c", "lo"},  {"ae", "hs"}, {"nc", "hs"}, {"be", "ls"}, {"a", "hi"},  {"s", "mi"},  {"ns", "pl"}, {"o", "vs"},  {"no", "vc"},
            {"p", "vs"},  {"np", "vc"}};
        for (const auto& [x, a] : map)
            if (cc == x) return a;
        return cc;
    }

    // --- memory ----------------------------------------------------------------
    // The text of an address, and what it names: a stack slot, a known global, or an expression.
    struct Address {
        std::string slot;     // "sp_10" / "fp_m8": the memory is a local
        std::string expr;     // otherwise the address expression
        uint64_t global = 0;  // a known address
    };

    std::string slotName(bool frame, int64_t off) {
        if (!frame) return "sp_" + hex(static_cast<uint64_t>(off < 0 ? -off : off)).substr(2);
        if (!arm_ && !x64_ && off >= 8 && off < 0x80) maxStackArg_ = std::max(maxStackArg_, static_cast<int>(off & ~3));
        return off < 0 ? "fp_m" + hex(static_cast<uint64_t>(-off)).substr(2) : "fp_" + hex(static_cast<uint64_t>(off)).substr(2);
    }

    // Combines base + index * scale + displacement.
    Address address(const State& st, int base, int index, int scale, int64_t disp, const std::string& shiftedIndex = {}) {
        Address a;
        const int sp = arm_ ? 13 : 4, fp = arm_ ? frameReg_ : 5;
        if (index < 0 && shiftedIndex.empty() && base >= 0) {
            if (arm_ && (base == sp || (base == fp && frame_))) {
                const int64_t fromEntry = disp - (base == sp ? frameSize_ : fpDepth_);
                if (fromEntry >= 0 && fromEntry < 256 && fromEntry % 4 == 0) {
                    maxStackArg_ = std::max(maxStackArg_, static_cast<int>(fromEntry));
                    a.slot = "stk_" + hex(static_cast<uint64_t>(fromEntry)).substr(2);
                    return a;
                }
            }
            if (base == sp && disp >= 0) {
                a.slot = slotName(false, disp);
                return a;
            }
            if (base == fp && frame_) {
                a.slot = slotName(true, disp);
                return a;
            }
            const auto known = st.consts.find(base);
            if (known != st.consts.end()) {
                a.global = known->second + static_cast<uint64_t>(disp);
                return a;
            }
            if (base == pic_) {
                a.global = picValue_ + static_cast<uint64_t>(disp);
                return a;
            }
        }
        std::string e;
        const auto add = [&](const std::string& term) { e += (e.empty() ? "" : " + ") + term; };
        if (base >= 0) add(base == sp ? std::string("sp") : read(base));
        if (!shiftedIndex.empty()) add(shiftedIndex);
        else if (index >= 0) add(scale > 1 ? read(index) + " * " + std::to_string(scale) : read(index));
        if (e.empty()) {
            a.global = static_cast<uint64_t>(disp);
            return a;
        }
        if (disp > 0) e += " + " + signedHex(disp);
        else if (disp < 0) e += " - " + signedHex(-disp);
        a.expr = e;
        return a;
    }

    // The value at an address, as an lvalue of `type`.
    std::string deref(const Address& a, const std::string& type) {
        if (!a.slot.empty()) {
            types_[a.slot].push_back(type);
            return a.slot;
        }
        if (a.expr.empty()) {
            const std::string sym = nc_.symbolize(a.global);
            const size_t got = sym.find("@got");
            if (got != std::string::npos) return "&" + sym.substr(0, got);
            if (!sym.empty() && sym.find_first_of("+@") == std::string::npos) return sym;
            return "*(" + type + " *)" + hex(a.global);
        }
        return "*(" + type + " *)" + wrap(a.expr);
    }

    // What taking the address gives (lea, add reg, sp, #n).
    std::string addressOf(const Address& a, std::string& type) {
        if (!a.slot.empty()) return type = "void *", "&" + a.slot;
        if (!a.expr.empty()) return a.expr;
        bool wide = false, utf32 = false;
        const std::string text = nc_.stringAt(a.global, &wide, &utf32);
        if (looksLikeText(text)) return type = "char *", (utf32 ? "U" : wide ? "u" : "") + cQuote(text);
        const std::string sym = nc_.symbolize(a.global);
        type = "void *";
        return sym.empty() ? hex(a.global) : "&" + sym;
    }

    // "dword ptr fs:[rax+rcx*4-0x8]"
    bool parseX86Memory(const State& st, const std::string& t, uint64_t ripTarget, Address& out, std::string& type) {
        const size_t open = t.find('[');
        if (open == std::string::npos || t.back() != ']') return false;
        const std::string head = t.substr(0, open);
        type = head.rfind("byte", 0) == 0    ? "uint8_t"
               : head.rfind("word", 0) == 0  ? "uint16_t"
               : head.rfind("dword", 0) == 0 ? "uint32_t"
               : head.rfind("qword", 0) == 0 ? "uint64_t"
               : head.rfind("xmmword", 0) == 0 ? "uint128_t"
                                             : std::string();
        const std::string body = t.substr(open + 1, t.size() - open - 2);
        if (body.rfind("rip", 0) == 0 || body.rfind("eip", 0) == 0) {
            out = Address{};
            out.global = ripTarget;
            return true;
        }
        int base = -1, index = -1, scale = 1, bits = 0, sign = 1;
        int64_t disp = 0;
        for (size_t i = 0; i < body.size();) {
            if (body[i] == '+') {
                sign = 1, ++i;
                continue;
            }
            if (body[i] == '-') {
                sign = -1, ++i;
                continue;
            }
            size_t j = i;
            while (j < body.size() && body[j] != '+' && body[j] != '-') ++j;
            std::string term = body.substr(i, j - i);
            i = j;
            const size_t star = term.find('*');
            int64_t v = 0;
            int id = 0;
            if (star != std::string::npos) {
                if (!parseRegister(term.substr(0, star), id, bits)) return false;
                index = id;
                scale = std::atoi(term.c_str() + star + 1);
            } else if (parseRegister(term, id, bits)) {
                if (base < 0) base = id;
                else index = id;
            } else if (parseNumber(term, v)) {
                disp = sign * v;
            } else {
                return false;
            }
        }
        const size_t colon = head.find(':');
        if (colon != std::string::npos && colon >= 2) {  // fs: / gs: thread data
            const std::string seg = head.substr(colon - 2, 2);
            out = Address{};
            std::string e = seg + "_base";
            if (base >= 0) e += " + " + read(base);
            if (disp) e += " + " + signedHex(disp);
            out.expr = e;
            return true;
        }
        out = address(st, base, index, scale, disp);
        return true;
    }

    // An x86 source operand as an expression. `bits` receives its width (0 when unknown).
    std::string x86Value(const State& st, const std::string& t, uint64_t ripTarget, bool& readsMem, int* bits = nullptr) {
        int id = 0, width = 0;
        if (parseRegister(t, id, width)) {
            if (bits) *bits = width;
            if (id < kFp && width < 32) return castFor(width, false) + read(id);
            return read(id);
        }
        int64_t v = 0;
        if (parseNumber(t, v)) return number(v);
        Address a;
        std::string type;
        if (parseX86Memory(st, t, ripTarget, a, type)) {
            if (bits) *bits = type == "uint8_t" ? 8 : type == "uint16_t" ? 16 : type == "uint32_t" ? 32 : type == "uint64_t" ? 64 : 0;
            readsMem = true;
            return deref(a, type.empty() ? "uint64_t" : type);
        }
        return t;
    }

    // Writes `value` to an x86 destination operand.
    void x86Store(Block& blk, State& st, const std::string& t, uint64_t ripTarget, const std::string& value, bool atomic, uint64_t addr,
                  bool readsMem = false, bool constant = false, const std::string& type = std::string()) {
        int id = 0, width = 0;
        if (parseRegister(t, id, width)) {
            if (id < kFp && width < 32) define(blk, st, id, castFor(width, false) + wrap(value), false, addr, readsMem, false, false, type);
            else define(blk, st, id, value, atomic, addr, readsMem, false, constant, !type.empty() ? type : width == 32 && x64_ ? "int32_t" : "");
            return;
        }
        Address a;
        std::string mtype;
        if (parseX86Memory(st, t, ripTarget, a, mtype)) {
            const std::string lv = deref(a, mtype.empty() ? "uint64_t" : mtype);
            stmt(blk, lv + " = " + value, addr);
            return;
        }
        stmt(blk, t + " = " + value, addr);
    }

    void fallback(Block& blk, State& st, size_t i, const std::vector<std::string>& ops, bool defines) {
        const arm64::Insn& in = lines_[i].insn;
        std::string args;
        int id = 0, bits = 0;
        bool writesFirst = defines && !ops.empty() && parseRegister(ops[0], id, bits);
        bool readsMem = false;
        // A documented intrinsic when there is one (arm_neon.h, the Intel intrinsics), else the mnemonic.
        bool readsDest = true, dropLast = false;
        const std::string named = arm_ ? neonA32Name(mnemonic_[i], ops) : sseIntrinsic(mnemonic_[i], ops, readsDest, dropLast);
        if (!named.empty() && arm_) {
            if (armIntrinsic(blk, st, i, ops, named)) return;
        }
        size_t first = 0, last = ops.size();
        if (!named.empty() && !arm_) {
            if (!readsDest && writesFirst) first = 1;
            if (dropLast && last) --last;
        }
        for (size_t k = first; k < last; ++k) {
            std::string e;
            int r = 0, w = 0;
            if (parseRegister(ops[k], r, w)) e = read(r);
            else if (!arm_) e = x86Value(st, ops[k], in.target, readsMem);
            else e = ops[k][0] == '#' ? ops[k].substr(1) : ops[k];
            args += (k > first ? ", " : "") + e;
        }
        if (!named.empty() && !arm_ && !writesFirst && !ops.empty()) {  // a result stored to memory
            x86Store(blk, st, ops[0], in.target, named + "(" + args + ")", true, in.addr, readsMem);
            return;
        }
        const std::string text = (named.empty() ? "__" + mnemonic_[i] : named) + "(" + args + ")";
        // Most instructions leave the flags alone (vector, x87, prefetch). These x86 ones write them; on ARM only the "s"
        // forms (translated above) do.
        static const char* const x86Writes[] = {"adc",  "sbb",  "add",    "sub",    "and",     "or",      "xor",    "shl",     "shr",    "sar",
                                                "rol",  "ror",  "rcl",    "rcr",    "shld",    "shrd",    "bsf",    "bsr",     "bts",    "btr",
                                                "btc",  "bt",   "popcnt", "lzcnt",  "tzcnt",   "popf",    "sahf",   "cmpxchg", "xadd",   "fcomi",
                                                "stc",  "clc",  "cmc",    "fcomip", "fucomi",  "fucomip", "comiss", "ucomiss", "comisd", "ucomisd",
                                                "ptest", "imul", "mul",   "div",    "idiv",    "cmp",     "test",   "inc",     "dec",    "neg"};
        if (!arm_) {
            std::string base = mnemonic_[i];
            if (base.rfind("lock ", 0) == 0) base.erase(0, 5);
            const bool strings = base.find("cmps") != std::string::npos || base.find("scas") != std::string::npos;  // "repe cmpsb"
            if (strings || std::find_if(std::begin(x86Writes), std::end(x86Writes), [&](const char* x) { return base == x; }) != std::end(x86Writes))
                st.flags = Flags{};
        }
        if (writesFirst) define(blk, st, id, text, true, in.addr, true, true);
        else stmt(blk, text, in.addr);
    }

    // --- x86 -----------------------------------------------------------------
    static bool calleeSavedX86(const std::string& r) {
        return r == "ebp" || r == "ebx" || r == "esi" || r == "edi" || r == "rbp" || r == "rbx" || r == "r12" || r == "r13" || r == "r14" || r == "r15";
    }

    // SSE / AVX arithmetic, shuffles and half-register moves; false when the instruction has no translation.
    bool sse(Block& blk, State& st, size_t i, const std::vector<std::string>& ops) {
        std::string m = mnemonic_[i];
        const uint64_t addr = lines_[i].insn.addr, target = lines_[i].insn.target;
        const bool vex = m.size() > 1 && m[0] == 'v';
        if (vex) m.erase(0, 1);
        int d = 0, bits = 0;
        const bool destRegister = !ops.empty() && parseRegister(ops[0], d, bits) && d >= kFp;
        bool readsMem = false;
        const auto value = [&](const std::string& op) { return x86Value(st, op, target, readsMem); };
        // movlps / movhps / movlpd / movhpd: eight bytes into or out of one half of a register.
        if ((m == "movlps" || m == "movlpd" || m == "movhps" || m == "movhpd") && ops.size() >= 2) {
            const bool high = m[3] == 'h';
            const std::string type = m.back() == 's' ? "float4" : "double2";
            if (destRegister) {
                const std::string kept = value(ops.size() == 3 ? ops[1] : ops[0]);
                const std::string loaded = value(ops.back());
                define(blk, st, d, (high ? "set_high(" : "set_low(") + kept + ", " + loaded + ")", true, addr, readsMem, false, false, type);
            } else {
                x86Store(blk, st, ops[0], target, (high ? "high_half(" : "low_half(") + value(ops[1]) + ")", true, addr);
            }
            return true;
        }
        if (!destRegister) return false;
        // vfmadd231ps d, a, b: d = a * b + d (the digits give the order of the three operands).
        if (vex && ops.size() == 3 && (m.rfind("fmadd", 0) == 0 || m.rfind("fmsub", 0) == 0 || m.rfind("fnmadd", 0) == 0)) {
            const size_t digits = m.find_first_of("123");
            if (digits == std::string::npos || digits + 3 > m.size()) return false;
            const std::string order = m.substr(digits, 3);
            const std::string v[3] = {value(ops[0]), value(ops[1]), value(ops[2])};
            const std::string product = wrap(v[order[0] - '1']) + " * " + wrap(v[order[1] - '1']), rest = v[order[2] - '1'];
            const std::string e = m.rfind("fnmadd", 0) == 0 ? wrap(rest) + " - " + product : product + (m.rfind("fmsub", 0) == 0 ? " - " : " + ") + wrap(rest);
            define(blk, st, d, e, false, addr, readsMem, false, false, m.back() == 's' ? "float4" : "double2");
            return true;
        }
        std::vector<std::string> sources;
        const bool unary = m.rfind("sqrt", 0) == 0 || m.rfind("rcp", 0) == 0 || m.rfind("rsqrt", 0) == 0 || m.rfind("cvt", 0) == 0 ||
                           m.rfind("pabs", 0) == 0 || m == "movddup" || m == "movshdup" || m == "movsldup" || m.rfind("broadcast", 0) == 0 ||
                           m.rfind("pbroadcast", 0) == 0;
        if (m == "pshufd" && ops.size() == 3) {
            define(blk, st, d, "shuffle(" + value(ops[1]) + ", " + value(ops[2]) + ")", true, addr, readsMem, false, false, "int4");
            return true;
        }
        for (size_t k = vex || unary ? 1 : 0; k < ops.size(); ++k) sources.push_back(value(ops[k]));
        std::string type;
        const std::string e = sseExpression(m, sources, type);
        if (e.empty()) return false;
        const bool call = e.back() == ')' && e.find(' ') > e.find('(');
        define(blk, st, d, e, call, addr, readsMem, false, false, type);
        return true;
    }

    // Scalar A32 / Thumb instructions with a C spelling: carries, long and high multiplies, bit fields, rotates,
    // exclusive accesses, system calls, the thread pointer and moves between core and NEON registers.
    bool armScalar(Block& blk, State& st, size_t i, const std::vector<std::string>& ops, const std::string& guard, bool hasD, int d) {
        const std::string& m = mnemonic_[i];
        const arm64::Insn& in = lines_[i].insn;
        const uint64_t addr = in.addr;
        const bool shift = ops.size() > 2 && ops.back().find(' ') != std::string::npos;
        const size_t n = shift ? ops.size() - 1 : ops.size();
        const auto val = [&](size_t k) { return armOperand(ops[k], shift && k + 1 == n ? ops.back() : std::string()); };
        const auto set = [&](int reg, const std::string& e, bool readsMem = false) {
            if (guard.empty()) define(blk, st, reg, e, false, addr, readsMem);
            else define(blk, st, reg, guard + " ? " + wrap(e) + " : " + read(reg), false, addr, readsMem);
        };
        const auto immediate = [&](size_t k) {
            int64_t v = 0;
            parseNumber(k < ops.size() ? ops[k] : std::string(), v);
            return v;
        };
        std::string stem = m;
        const bool flagsOut = stem == "adcs" || stem == "sbcs" || stem == "rscs";
        if (flagsOut) stem.pop_back();
        if ((stem == "adc" || stem == "sbc" || stem == "rsc") && hasD && n >= 2) {
            const std::string c = carryExpr(st, true);
            const std::string x = val(n >= 3 ? 1 : 0), y = val(n - 1);
            const std::string e = stem == "adc"   ? wrap(x) + " + " + wrap(y) + " + " + wrap(c)
                                  : stem == "sbc" ? wrap(x) + " - " + wrap(y) + " - !" + wrap(c)
                                                  : wrap(y) + " - " + wrap(x) + " - !" + wrap(c);
            set(d, e);
            if (flagsOut) st.flags = Flags{};
            return true;
        }
        // umull lo, hi, a, b (and the accumulating / signed forms): a 64-bit product in two registers.
        if ((m == "umull" || m == "smull" || m == "umlal" || m == "smlal") && ops.size() == 4 && guard.empty()) {
            int lo = 0, hi = 0, bits = 0;
            if (!parseRegister(ops[0], lo, bits) || !parseRegister(ops[1], hi, bits)) return false;
            const bool s = m[0] == 's';
            const std::string wide = s ? "(int64_t)" : "(uint64_t)", narrow = s ? "(int32_t)" : "(uint32_t)";
            std::string product = wide + narrow + wrap(val(2)) + " * " + narrow + wrap(val(3));
            if (m[2] == 'l') product = "(" + wide + read(hi) + " << 32 | (uint32_t)" + read(lo) + ") + " + wrap(product);
            const std::string all = snapshot(blk, product, addr, s ? "int64_t" : "uint64_t");
            define(blk, st, lo, "(uint32_t)" + all, false, addr);
            define(blk, st, hi, "(uint32_t)(" + all + " >> 32)", false, addr);
            return true;
        }
        if ((m == "smmul" || m == "smmulr" || m == "smmla" || m == "smmls") && hasD && ops.size() >= 3) {
            std::string e = "(int32_t)(((int64_t)" + wrap(val(1)) + " * " + wrap(val(2)) + (m == "smmulr" ? " + 0x80000000" : "") + ") >> 32)";
            if (m == "smmla") e = val(3) + " + " + e;
            if (m == "smmls") e = val(3) + " - " + e;
            set(d, e);
            return true;
        }
        if ((m.rfind("smul", 0) == 0 || m.rfind("smla", 0) == 0) && m.size() == 6 && (m[4] == 'b' || m[4] == 't') && hasD && ops.size() >= 3) {
            const auto half = [&](size_t k, char which) { return std::string("(int16_t)") + (which == 't' ? "(" + wrap(val(k)) + " >> 16)" : wrap(val(k))); };
            std::string e = half(1, m[4]) + " * " + half(2, m[5]);
            if (m[1] == 'm' && m[2] == 'l') e = val(3) + " + " + e;
            set(d, e);
            return true;
        }
        if (m == "ror" && hasD && n >= 2) {
            set(d, "__builtin_rotateright32(" + val(n >= 3 ? 1 : 0) + ", " + val(n - 1) + ")");
            return true;
        }
        if ((m == "ubfx" || m == "sbfx") && hasD && ops.size() == 4) {
            const int64_t lsb = immediate(2), width = immediate(3);
            const std::string mask = hex(width >= 32 ? 0xFFFFFFFFull : (1ull << width) - 1);
            if (m == "ubfx") set(d, "(uint32_t)" + wrap(val(1)) + " >> " + std::to_string(lsb) + " & " + mask);
            else set(d, "(int32_t)" + wrap(val(1)) + " << " + std::to_string(32 - lsb - width) + " >> " + std::to_string(32 - width));
            return true;
        }
        if ((m == "bfc" || m == "bfi") && hasD && ops.size() == (m == "bfc" ? 3u : 4u)) {
            const int64_t lsb = immediate(ops.size() - 2), width = immediate(ops.size() - 1);
            const uint64_t field = (width >= 32 ? 0xFFFFFFFFull : (1ull << width) - 1);
            const std::string keep = wrap(read(d)) + " & " + hex(~(field << lsb) & 0xFFFFFFFFull);
            if (m == "bfc") set(d, keep);
            else set(d, keep + " | (" + wrap(val(1)) + " & " + hex(field) + ") << " + std::to_string(lsb));
            return true;
        }
        if (m == "adr" && hasD && ops.size() == 2) {
            int64_t at = 0;
            const uint64_t target = in.hasTarget ? in.target : parseNumber(ops[1], at) ? static_cast<uint64_t>(at) : 0;
            if (!target) return false;
            set(d, hex(target));
            st.consts[d] = target;
            return true;
        }
        // vldmia r0!, {d8-d15} / vstmdb r1, {s0-s3}: consecutive FP registers to or from memory.
        if ((m.rfind("vldm", 0) == 0 || m.rfind("vstm", 0) == 0) && ops.size() == 2 && guard.empty() && ops[1].size() > 3 && ops[1][0] == '{') {
            std::string baseName = ops[0];
            const bool writeBack = !baseName.empty() && baseName.back() == '!';
            if (writeBack) baseName.pop_back();
            int base = 0, bits = 0;
            if (!parseRegister(baseName, base, bits)) return false;
            if (base == 13) return true;  // saving and restoring callee-saved registers
            const char cls = ops[1][1];
            const int first = std::atoi(ops[1].c_str() + 2);
            const size_t dash = ops[1].find('-');
            const int last = dash == std::string::npos ? first : std::atoi(ops[1].c_str() + dash + 2);
            if ((cls != 'd' && cls != 's') || last < first || last - first > 31) return false;
            const bool load = m[1] == 'l', down = m.find("db") != std::string::npos;
            const int size = cls == 'd' ? 8 : 4, count = last - first + 1;
            const std::string type = cls == 'd' ? "double" : "float";
            for (int k = 0; k < count; ++k) {
                int r = 0;
                if (!parseRegister(std::string(1, cls) + std::to_string(first + k), r, bits)) return false;
                const int offset = down ? -(count - k) * size : k * size;
                const std::string at = "*(" + type + " *)" + (offset ? "(" + read(base) + (offset < 0 ? " - " : " + ") + std::to_string(offset < 0 ? -offset : offset) + ")" : read(base));
                if (load) define(blk, st, r, at, true, addr, true);
                else stmt(blk, at + " = " + read(r), addr);
            }
            if (writeBack) define(blk, st, base, read(base) + (down ? " - " : " + ") + std::to_string(count * size), false, addr);
            return true;
        }
        // Exclusive accesses: the clang builtins (ldrex / strex loops are an atomic read-modify-write).
        if (m.rfind("ldrex", 0) == 0 || m.rfind("strex", 0) == 0) {
            const bool load = m[0] == 'l';
            const char size = m.size() > 5 ? m[5] : 'w';
            const std::string type = size == 'b' ? "uint8_t" : size == 'h' ? "uint16_t" : size == 'd' ? "uint64_t" : "uint32_t";
            std::string mem = ops.empty() ? std::string() : ops.back();
            if (mem.size() < 3 || mem.front() != '[' || mem.back() != ']') return false;
            const std::vector<std::string> parts = splitOps(std::string_view(mem).substr(1, mem.size() - 2));
            int base = 0, bits = 0;
            if (parts.empty() || !parseRegister(parts[0], base, bits)) return false;
            std::string ptr = read(base);
            if (int64_t off = 0; parts.size() > 1 && parseNumber(parts[1], off) && off) ptr = wrap(ptr) + " + " + std::to_string(off);
            ptr = "(" + type + " *)" + wrap(ptr);
            int r = 0;
            if (load && ops.size() >= 2 && parseRegister(ops[0], r, bits)) {
                if (size == 'd') return false;
                set(r, "__builtin_arm_ldrex(" + ptr + ")", true);
                return true;
            }
            int status = 0, value = 0;
            if (!load && ops.size() >= 3 && parseRegister(ops[0], status, bits) && parseRegister(ops[1], value, bits) && size != 'd') {
                define(blk, st, status, "__builtin_arm_strex(" + read(value) + ", " + ptr + ")", true, addr, true, true);
                return true;
            }
            return false;
        }
        if (m == "clrex") {
            stmt(blk, "__builtin_arm_clrex()", addr);
            return true;
        }
        if (m == "svc" && guard.empty()) {  // r7: the number, r0-r5 the arguments (EABI)
            define(blk, st, 0, "syscall(" + read(7) + ", " + read(0) + ", " + read(1) + ", " + read(2) + ", " + read(3) + ", " + read(4) + ", " + read(5) + ")",
                   true, addr, true, true);
            return true;
        }
        // mrc p15, 0, rN, c13, c0, 3: the thread ID register, i.e. the thread pointer.
        if (m == "mrc" && ops.size() == 6 && ops[0] == "p15" && ops[3] == "c13" && ops[4] == "c0") {
            int r = 0, bits = 0;
            if (!parseRegister(ops[2], r, bits)) return false;
            set(r, ops[5] == "#3" ? "__builtin_thread_pointer()" : "__builtin_arm_mrc(15, 0, 13, 0, " + ops[5].substr(1) + ")", true);
            return true;
        }
        // vmov.32 d16[0], r1 / vmov.u16 lr, d16[2]: one lane.
        if (m.rfind("vmov.", 0) == 0 && ops.size() == 2) {
            const std::string type = m.substr(5);
            const std::string t = std::isdigit(static_cast<unsigned char>(type[0])) ? "u" + type : type;
            const size_t lane0 = ops[0].find('['), lane1 = ops[1].find('[');
            int r = 0, v = 0, bits = 0;
            if (lane0 != std::string::npos && parseRegister(ops[0].substr(0, lane0), v, bits) && parseRegister(ops[1], r, bits)) {
                const std::string index = ops[0].substr(lane0 + 1, ops[0].size() - lane0 - 2);
                set(v, "vset_lane_" + t + "(" + read(r) + ", " + read(v) + ", " + index + ")");
                return true;
            }
            if (lane1 != std::string::npos && parseRegister(ops[1].substr(0, lane1), v, bits) && parseRegister(ops[0], r, bits)) {
                const std::string index = ops[1].substr(lane1 + 1, ops[1].size() - lane1 - 2);
                set(r, "vget_lane_" + t + "(" + read(v) + ", " + index + ")");
                return true;
            }
        }
        // vmov r0, r1, d16 / vmov d16, r0, r1: a d register as two words.
        if (m == "vmov" && ops.size() == 3 && guard.empty()) {
            int a = 0, b = 0, c = 0, bits = 0;
            if (!parseRegister(ops[0], a, bits) || !parseRegister(ops[1], b, bits) || !parseRegister(ops[2], c, bits)) return false;
            if (a < kFp && b < kFp && c >= kFp) {
                const std::string whole = snapshot(blk, read(c), addr, "uint64_t");
                define(blk, st, a, "(uint32_t)" + whole, false, addr);
                define(blk, st, b, "(uint32_t)(" + whole + " >> 32)", false, addr);
                return true;
            }
            if (a >= kFp && b < kFp && c < kFp) {
                define(blk, st, a, "(uint64_t)" + read(c) + " << 32 | " + read(b), false, addr);
                return true;
            }
        }
        return false;
    }

    // An A32 NEON instruction as its arm_neon.h call `name`: d / q registers as values, [rN] as the pointer, a load
    // defining the register it fills, a store taking the pointer first, and the post-increment. False: leave it to the
    // generic form.
    bool armIntrinsic(Block& blk, State& st, size_t i, const std::vector<std::string>& ops, std::string name) {
        const uint64_t addr = lines_[i].insn.addr;
        const std::string& m = mnemonic_[i];
        const std::string op = m.substr(0, m.find('.'));
        int bits = 0;
        // "{d16, d17}" is q8, "{d16}" d16; lanes and longer lists are not one register.
        const auto single = [&](const std::string& t, int& reg, int& count) {
            reg = -1;
            count = 0;
            if (t.size() < 3 || t.front() != '{' || t.back() != '}') return;
            const std::vector<std::string> items = splitOps(std::string_view(t).substr(1, t.size() - 2));
            count = static_cast<int>(items.size());
            int a = 0, b = 0;
            if (items.size() == 1 && parseRegister(items[0], a, bits)) reg = a;
            else if (items.size() == 2 && items[0].size() > 1 && items[0][0] == 'd' && parseRegister(items[0], a, bits) && parseRegister(items[1], b, bits)) {
                const int n = std::atoi(items[0].c_str() + 1);
                int q = 0;
                if (n % 2 == 0 && std::atoi(items[1].c_str() + 1) == n + 1 && parseRegister("q" + std::to_string(n / 2), q, bits)) reg = q;
            }
        };
        if (op.rfind("vld", 0) == 0 || op.rfind("vst", 0) == 0) {
            if (ops.size() < 2) return false;
            int reg = -1, count = 0;
            std::string lane;
            if (name.find("_lane") != std::string::npos) {  // {d16[0]}: one lane of one register
                const std::string& t = ops[0];
                const size_t open = t.find('['), close = t.find(']');
                if (t.size() < 6 || t.front() != '{' || t.back() != '}' || t.find(',') != std::string::npos || open == std::string::npos || close == std::string::npos ||
                    !parseRegister(t.substr(1, open - 1), reg, bits))
                    return false;
                lane = t.substr(open + 1, close - open - 1);
                count = 1;
            } else {
                single(ops[0], reg, count);
            }
            std::string mem = ops[1];
            const bool writeBack = !mem.empty() && mem.back() == '!';
            if (writeBack) mem.pop_back();
            if (mem.size() < 3 || mem.front() != '[' || mem.back() != ']') return false;
            mem = mem.substr(1, mem.size() - 2);
            if (const size_t colon = mem.find(':'); colon != std::string::npos) mem.resize(colon);  // alignment
            while (!mem.empty() && mem.back() == ' ') mem.pop_back();
            int base = 0;
            if (!parseRegister(mem, base, bits) || reg < 0) return false;
            const std::string ptr = read(base);
            const std::string at = lane.empty() ? std::string() : ", " + lane;
            if (op[1] == 'l') define(blk, st, reg, name + "(" + ptr + (lane.empty() ? "" : ", " + read(reg)) + at + ")", true, addr, true, true);
            else stmt(blk, name + "(" + ptr + ", " + read(reg) + at + ")", addr);
            int by = 0;
            const int bytes = lane.empty() ? 8 * count : std::max(1, std::atoi(m.c_str() + m.find('.') + 1) / 8);
            if (ops.size() > 2 && parseRegister(ops[2], by, bits)) define(blk, st, base, read(base) + " + " + read(by), false, addr);
            else if (writeBack) define(blk, st, base, read(base) + " + " + std::to_string(bytes), false, addr);
            return true;
        }
        int d = 0;
        if (!parseRegister(ops[0], d, bits)) return false;
        if (op == "vzip" || op == "vuzp" || op == "vtrn" || op == "vswp") return false;  // two results
        // Accumulating forms read the destination, which arm_neon.h takes first.
        static const std::set<std::string> accumulate = {"vmla", "vmls", "vmlal", "vmlsl", "vsra", "vrsra", "vaba", "vabal", "vbsl",
                                                         "vsli", "vsri", "vqdmlal", "vqdmlsl", "vpadal", "vbif", "vbit"};
        std::string args;
        for (size_t k = accumulate.count(op) ? 0 : 1; k < ops.size(); ++k) {
            std::string t = ops[k], e;
            int r = 0;
            const size_t bracket = t.find('[');
            if (bracket != std::string::npos && parseRegister(t.substr(0, bracket), r, bits)) {  // a scalar: d2[1]
                e = read(r) + ", " + t.substr(bracket + 1, t.size() - bracket - 2);
                const size_t type = name.rfind('_');
                if (name.find("_lane") == std::string::npos) name = name.substr(0, type) + "_lane" + name.substr(type);
            } else if (parseRegister(t, r, bits)) {
                e = read(r);
            } else if (!t.empty() && t[0] == '#') {
                e = t.substr(1);
            } else {
                return false;
            }
            args += (args.empty() ? "" : ", ") + e;
        }
        define(blk, st, d, name + "(" + args + ")", true, addr);
        return true;
    }

    void x86(Block& blk, State& st, size_t i) {
        const NativeCode::Line& l = lines_[i];
        const arm64::Insn& in = l.insn;
        const std::string& m = mnemonic_[i];
        const uint64_t addr = in.addr, target = in.target;
        const std::vector<std::string> ops = splitOps(in.operands);
        const std::string op0 = ops.empty() ? std::string() : ops[0], op1 = ops.size() > 1 ? ops[1] : std::string(),
                          op2 = ops.size() > 2 ? ops[2] : std::string();
        if (!in.known) {
            stmt(blk, "__asm(\"" + m + " " + in.operands + "\")", addr);
            return;
        }
        if (callNext(i)) {  // the pop that follows takes this address
            nextAddress_ = in.addr + in.size;
            return;
        }
        if (in.flow == arm64::Flow::Call) {
            const std::string name = calleeName(i);
            // __x86.get_pc_thunk.bx and friends: a register gets the return address.
            if (!x64_ && ops.size() == 1 && isThunk(target)) {
                pic_ = thunkRegister(target);
                picValue_ = addr + in.size;
                return;
            }
            call(blk, st, name, addr);
            return;
        }
        if (in.flow == arm64::Flow::IndirectCall) {
            bool mem = false;
            call(blk, st, "(*" + wrap(x86Value(st, op0, target, mem)) + ")", addr);
            return;
        }
        if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "leave" || m == "pause" || m == "mfence" || m == "lfence" || m == "sfence" ||
            m.rfind("prefetch", 0) == 0)  // a cache hint: nothing the code computes
            return;
        if (m == "push") {
            if (calleeSavedX86(op0) && prologue_) return;
            if (!x64_) {
                bool mem = false;
                st.pushed.push_back(x86Value(st, op0, target, mem));
            }
            return;
        }
        if (m == "pop") {
            int id = 0, bits = 0;
            if (nextAddress_ && parseRegister(op0, id, bits)) {
                pic_ = id;
                picValue_ = nextAddress_;
                nextAddress_ = 0;
            }
            if (!st.pushed.empty()) st.pushed.pop_back();
            return;  // restoring saved registers
        }
        if (m == "mov" && (op0 == "ebp" && op1 == "esp" || op0 == "rbp" && op1 == "rsp")) {
            frame_ = true;
            return;
        }
        if (op0 == "esp" || op0 == "rsp") return;  // frame arithmetic
        prologue_ = false;

        if (x87(blk, st, i, ops)) return;
        bool readsMem = false;
        int id = 0, bits = 0;
        const bool destReg = parseRegister(op0, id, bits);
        if (m.size() > 4 && m[0] == 'v' && (m.rfind("vmov", 0) == 0) && ops.size() == 2) {  // VEX moves are moves
            x86Store(blk, st, op0, target, x86Value(st, op1, target, readsMem), !readsMem, addr, readsMem);
            return;
        }
        if (sse(blk, st, i, ops)) return;
        if (pic_ >= 0 && destReg && id == pic_) {
            int64_t v = 0;
            if (m == "add" && parseNumber(op1, v)) {  // ebx += GOT offset
                picValue_ += static_cast<uint64_t>(v);
                return;
            }
            pic_ = -1;
        }
        if (m == "mov" || m == "movabs" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movss" || m == "movsd" || m == "movaps" ||
            m == "movups" || m == "movapd" || m == "movupd" || m == "movdqa" || m == "movdqu" || m == "movd" || m == "movq") {
            if (ops.size() != 2) return fallback(blk, st, i, ops, true);
            int srcBits = 0;
            std::string v = x86Value(st, op1, target, readsMem, &srcBits);
            if ((m == "movsx" || m == "movsxd") && srcBits) v = castFor(srcBits, true) + wrap(v);
            if (m == "movzx" && srcBits && v.rfind("(uint", 0) != 0) v = castFor(srcBits, false) + wrap(v);
            int64_t imm = 0;
            const bool isImm = parseNumber(op1, imm);
            int sid = 0, sbits = 0;
            const bool known = parseRegister(op1, sid, sbits) && st.consts.count(sid);
            const uint64_t value = isImm ? static_cast<uint64_t>(imm) : known ? st.consts[sid] : 0;
            x86Store(blk, st, op0, target, v, !readsMem, addr, readsMem, isImm);
            if ((isImm || known) && destReg) st.consts[id] = value;
            return;
        }
        if (m == "lea" && destReg) {
            Address a;
            std::string type;
            if (!parseX86Memory(st, op1, target, a, type)) return fallback(blk, st, i, ops, true);
            std::string vtype;
            const std::string v = addressOf(a, vtype);
            const bool constant = a.expr.empty() && a.slot.empty();
            define(blk, st, id, v, a.expr.empty(), addr, false, false, constant, vtype);
            if (constant) st.consts[id] = a.global;
            return;
        }
        static const std::pair<const char*, const char*> binary[] = {
            {"add", "+"},   {"sub", "-"},   {"and", "&"},   {"or", "|"},    {"xor", "^"},   {"shl", "<<"},  {"sal", "<<"},  {"shr", ">>"},
            {"sar", ">>"},  {"addss", "+"}, {"subss", "-"}, {"mulss", "*"}, {"divss", "/"}, {"addsd", "+"}, {"subsd", "-"}, {"mulsd", "*"},
            {"divsd", "/"}};
        for (const auto& [name, symbol] : binary) {
            if (m != name || ops.size() < 2) continue;
            if ((m == "xor") && op0 == op1 && destReg) {
                define(blk, st, id, "0", true, addr, false, false, true);
                st.consts[id] = 0;
                st.flags = Flags{Flags::Tst, "0", "", ""};
                return;
            }
            std::string lhs = x86Value(st, op0, target, readsMem), rhs = x86Value(st, op1, target, readsMem);
            if (m == "shr") lhs = std::string(bits == 64 ? "(uint64_t)" : "(uint32_t)") + wrap(lhs);
            std::string o = symbol;
            int64_t v = 0;
            if ((o == "+" || o == "-") && parseNumber(op1, v) && v < 0) o = o == "+" ? "-" : "+", rhs = number(-v);
            const std::string e = wrap(lhs) + " " + o + " " + wrap(rhs);
            const bool floating = m.size() == 5 && (m.compare(3, 2, "ss") == 0 || m.compare(3, 2, "sd") == 0);
            if (!floating && destReg) preserve(blk, st, id, addr);
            x86Store(blk, st, op0, target, e, false, addr, readsMem);
            if (!floating) {
                const std::string now = destReg ? read(id) : x86Value(st, op0, target, readsMem);
                if (m == "sub") st.flags = Flags{Flags::Cmp, now + " + " + wrap(rhs), rhs, now};
                else if (m == "add") st.flags = Flags{Flags::Cmn, now + " - " + wrap(rhs), rhs, now};
                else st.flags = Flags{Flags::Tst, now, "", ""};
            }
            return;
        }
        if ((m == "inc" || m == "dec" || m == "neg" || m == "not") && !ops.empty()) {
            const std::string x = x86Value(st, op0, target, readsMem);
            const std::string e = m == "inc" ? wrap(x) + " + 1" : m == "dec" ? wrap(x) + " - 1" : (m == "neg" ? "-" : "~") + wrap(x);
            x86Store(blk, st, op0, target, e, false, addr, readsMem);
            if (m != "not") st.flags = Flags{Flags::Tst, destReg ? read(id) : x86Value(st, op0, target, readsMem), "", ""};
            return;
        }
        if (m == "imul" && ops.size() >= 2 && destReg) {
            const std::string a = x86Value(st, ops.size() == 3 ? op1 : op0, target, readsMem);
            const std::string b = x86Value(st, ops.size() == 3 ? op2 : op1, target, readsMem);
            st.flags = Flags{Flags::Over, wrap(a) + " * " + wrap(b), "", ""};  // before the write: it keeps the old values
            define(blk, st, id, wrap(a) + " * " + wrap(b), false, addr, readsMem);
            return;
        }
        if ((m == "mul" || m == "imul" || m == "div" || m == "idiv") && ops.size() == 1) {
            const std::string x = x86Value(st, op0, target, readsMem);
            st.flags = m[m.size() - 1] == 'v' ? Flags{} : Flags{Flags::Over, read(0) + " * " + wrap(x), "", ""};
            if (m[m.size() - 1] == 'v') {
                define(blk, st, 2, read(0) + " % " + wrap(x), false, addr, readsMem);
                define(blk, st, 0, read(0) + " / " + wrap(x), false, addr, readsMem);
            } else {
                define(blk, st, 2, "mulhi(" + read(0) + ", " + x + ")", true, addr, readsMem);
                define(blk, st, 0, read(0) + " * " + wrap(x), false, addr, readsMem);
            }
            return;
        }
        if (m == "cdq" || m == "cqo") {
            define(blk, st, 2, read(0) + (m == "cqo" ? " >> 63" : " >> 31"), false, addr);
            return;
        }
        if (m == "cdqe" || m == "cwde") {
            define(blk, st, 0, std::string(m == "cdqe" ? "(int32_t)" : "(int16_t)") + read(0), false, addr);
            return;
        }
        if ((m == "ptest" || m == "vptest") && ops.size() == 2) {
            const std::string a = x86Value(st, op0, target, readsMem), b = x86Value(st, op1, target, readsMem);
            st.flags = Flags{Flags::Vtest, a, b, ""};
            return;
        }
        if (m == "bt" && ops.size() == 2) {
            const std::string x = x86Value(st, op0, target, readsMem), n = x86Value(st, op1, target, readsMem);
            st.flags = Flags{Flags::Bit, "(" + wrap(x) + " >> " + wrap(n) + " & 1)", "", ""};
            return;
        }
        if ((m == "cmp" || m == "test" || m == "comiss" || m == "comisd" || m == "ucomiss" || m == "ucomisd") && ops.size() == 2) {
            const std::string a = x86Value(st, op0, target, readsMem), b = x86Value(st, op1, target, readsMem);
            st.flags = Flags{m == "cmp" ? Flags::Cmp : m == "test" ? Flags::Tst : Flags::FCmp, a, b, ""};
            return;
        }
        if (m.rfind("set", 0) == 0 && ops.size() == 1) {
            x86Store(blk, st, op0, target, condExpr(flagCond(st.flags, x86Condition(m.substr(3)))), false, addr);
            return;
        }
        if (m.rfind("cmov", 0) == 0 && ops.size() == 2 && destReg) {
            const std::string c = condExpr(flagCond(st.flags, x86Condition(m.substr(4))));
            define(blk, st, id, c + " ? " + x86Value(st, op1, target, readsMem) + " : " + read(id), false, addr, readsMem);
            return;
        }
        if ((m == "xorps" || m == "xorpd" || m == "pxor") && op0 == op1 && destReg) {
            define(blk, st, id, "0", true, addr, false, false, true);
            return;
        }
        if (m.rfind("cvt", 0) == 0 && ops.size() == 2 && destReg) {
            const size_t two = m.find('2');
            const std::string to = two == std::string::npos ? std::string() : m.substr(two + 1);
            const std::string cast = to == "ss" ? "(float)" : to == "sd" ? "(double)" : to == "si" ? "(int)" : std::string();
            if (!cast.empty()) {
                define(blk, st, id, cast + wrap(x86Value(st, op1, target, readsMem)), false, addr, readsMem);
                return;
            }
        }
        if (x86Scalar(blk, st, i, ops)) return;
        if (m.rfind("rep", 0) == 0 || m.rfind("stos", 0) == 0 || m.rfind("lock", 0) == 0) return fallback(blk, st, i, ops, false);
        fallback(blk, st, i, ops, true);
    }

    // --- x87 -----------------------------------------------------------------
    // st(i) now, pulling the values the block started with into the local stack as needed.
    std::string fpuAt(State& st, size_t i) {
        while (st.fpu.size() <= i) {
            if (st.fpuCall >= 0 && st.fpuCallBlock && static_cast<size_t>(st.fpuCall) < st.fpuCallBlock->stmts.size()) {
                // st(0) right after a call is what the callee returned: the call defines a double, not eax.
                Stmt& s = st.fpuCallBlock->stmts[static_cast<size_t>(st.fpuCall)];
                const int t = nextSynth_++;
                const std::string name = "t" + std::to_string(t - kFirstTemp);
                s.def = t;
                s.defName = name;
                s.kills.push_back(0);
                types_[name].push_back("double");
                st.fpu.insert(st.fpu.begin(), ph(t, name));
                st.fpuCall = -1;
                continue;
            }
            st.fpu.insert(st.fpu.begin(), read(kX87 + st.fpuUnder));
            ++st.fpuUnder;
        }
        return st.fpu[st.fpu.size() - 1 - i];
    }
    void fpuSet(State& st, size_t i, const std::string& v) {
        fpuAt(st, i);
        st.fpu[st.fpu.size() - 1 - i] = v;
    }
    void fpuPush(Block& blk, State& st, const std::string& e, uint64_t addr) { st.fpu.push_back(snapshot(blk, e, addr, "double")); }
    void fpuPop(State& st) {
        fpuAt(st, 0);
        st.fpu.pop_back();
    }
    // The stack as the next block sees it: st0.. hold what this block leaves.
    void fpuFlush(Block& blk, State& st, uint64_t addr) {
        if (st.fpu.empty() && st.fpuUnder == 0) return;
        const size_t n = st.fpu.size();
        std::vector<std::string> values;
        for (size_t k = 0; k < n; ++k) values.push_back(snapshot(blk, st.fpu[n - 1 - k], addr, "double"));  // read everything first
        std::vector<std::string> below;
        if (st.fpuUnder > 0 && static_cast<size_t>(st.fpuUnder) != n)
            for (int j = 0; j < 2 && st.fpuUnder + j < 8 && n + static_cast<size_t>(j) < 8; ++j)
                below.push_back(snapshot(blk, read(kX87 + st.fpuUnder + j), addr, "double"));
        for (size_t k = 0; k < n && k < 8; ++k) define(blk, st, kX87 + static_cast<int>(k), values[k], true, addr, false, false, false, "double");
        for (size_t j = 0; j < below.size(); ++j) define(blk, st, kX87 + static_cast<int>(n + j), below[j], true, addr, false, false, false, "double");
        st.fpu.clear();
        st.fpuUnder = 0;
        st.fpuCall = -1;
    }

    bool x87(Block& blk, State& st, size_t i, const std::vector<std::string>& ops) {
        const std::string& m = mnemonic_[i];
        if (x64_ ? m.rfind("f", 0) != 0 : m.empty() || m[0] != 'f') return false;
        const arm64::Insn& in = lines_[i].insn;
        const uint64_t addr = in.addr, target = in.target;
        bool readsMem = false;
        // "st(3)" -> 3, "st" -> 0.
        const auto position = [](const std::string& t, size_t& k) {
            if (t == "st") return k = 0, true;
            if (t.size() == 5 && t.compare(0, 3, "st(") == 0 && t[4] == ')' && t[3] >= '0' && t[3] <= '7') return k = static_cast<size_t>(t[3] - '0'), true;
            return false;
        };
        // A memory operand as a value of the given type.
        const auto memory = [&](const std::string& t, const std::string& type, std::string& out) {
            Address a;
            std::string sized;
            if (!parseX86Memory(st, t, target, a, sized)) return false;
            readsMem = true;
            out = deref(a, type);
            return true;
        };
        const auto realType = [&](const std::string& t) {
            return t.rfind("dword", 0) == 0 ? "float" : t.rfind("qword", 0) == 0 ? "double" : "long double";
        };
        const auto intType = [&](const std::string& t) {
            return t.rfind("word", 0) == 0 ? "int16_t" : t.rfind("qword", 0) == 0 ? "int64_t" : "int32_t";
        };
        size_t k = 0;
        std::string v;
        // Loads.
        static const std::pair<const char*, const char*> constants[] = {{"fldz", "0.0"},
                                                                       {"fld1", "1.0"},
                                                                       {"fldpi", "3.14159265358979323846"},
                                                                       {"fldl2e", "1.4426950408889634074"},
                                                                       {"fldl2t", "3.3219280948873623479"},
                                                                       {"fldln2", "0.69314718055994530942"},
                                                                       {"fldlg2", "0.30102999566398119521"}};
        for (const auto& [name, value] : constants)
            if (m == name) return fpuPush(blk, st, value, addr), true;
        if (m == "fld" && ops.size() == 1) {
            if (position(ops[0], k)) return fpuPush(blk, st, fpuAt(st, k), addr), true;
            if (!memory(ops[0], realType(ops[0]), v)) return false;
            return fpuPush(blk, st, v, addr), true;
        }
        if (m == "fild" && ops.size() == 1) {
            if (!memory(ops[0], intType(ops[0]), v)) return false;
            return fpuPush(blk, st, "(double)" + wrap(v), addr), true;
        }
        // Stores.
        if ((m == "fst" || m == "fstp") && ops.size() == 1) {
            const std::string top = fpuAt(st, 0);
            if (position(ops[0], k)) {
                if (k) fpuSet(st, k, top);
            } else {
                Address a;
                std::string sized;
                if (!parseX86Memory(st, ops[0], target, a, sized)) return false;
                stmt(blk, deref(a, realType(ops[0])) + " = " + top, addr);
            }
            if (m == "fstp") fpuPop(st);
            return true;
        }
        if ((m == "fist" || m == "fistp" || m == "fisttp") && ops.size() == 1) {
            Address a;
            std::string sized;
            if (!parseX86Memory(st, ops[0], target, a, sized)) return false;
            const std::string type = intType(ops[0]);
            const std::string top = fpuAt(st, 0);
            stmt(blk, deref(a, type) + " = (" + type + ")" + (m == "fisttp" ? wrap(top) : "llrint(" + top + ")"), addr);
            if (m != "fist") fpuPop(st);
            return true;
        }
        // Arithmetic: fadd m / fadd st, st(i) / fadd st(i), st / faddp st(i), st / fiadd m.
        static const std::pair<const char*, const char*> arith[] = {{"add", "+"}, {"sub", "-"}, {"subr", "-"}, {"mul", "*"}, {"div", "/"}, {"divr", "/"}};
        for (const auto& [name, symbol] : arith) {
            const std::string base = std::string("f") + name;
            const bool pop = m == base + "p", integer = m == std::string("fi") + name;
            if (m != base && !pop && !integer) continue;
            const bool reversed = std::string(name).back() == 'r';
            const auto combine = [&](const std::string& x, const std::string& y) {
                return reversed ? wrap(y) + " " + symbol + " " + wrap(x) : wrap(x) + " " + symbol + " " + wrap(y);
            };
            size_t a = 0, b = 0;
            if (ops.size() == 1 && !pop) {  // with memory: st0 = st0 op m
                if (!memory(ops[0], integer ? intType(ops[0]) : realType(ops[0]), v)) return false;
                if (integer) v = "(double)" + wrap(v);
                fpuSet(st, 0, snapshot(blk, combine(fpuAt(st, 0), v), addr, "double"));
                return true;
            }
            if (ops.empty() && pop) a = 1, b = 0;  // faddp: st(1) op= st0
            else if (ops.size() == 2 && position(ops[0], a) && position(ops[1], b)) {
            } else {
                return false;
            }
            const std::string x = fpuAt(st, a), y = fpuAt(st, b);
            fpuSet(st, a, snapshot(blk, combine(x, y), addr, "double"));
            if (pop) fpuPop(st);
            return true;
        }
        if (m == "fxch") {
            if (!ops.empty() && !position(ops[0], k)) return false;
            if (ops.empty()) k = 1;
            const std::string top = fpuAt(st, 0), other = fpuAt(st, k);
            fpuSet(st, 0, other);
            fpuSet(st, k, top);
            return true;
        }
        static const std::pair<const char*, const char*> unary[] = {
            {"fchs", "-"}, {"fabs", "fabs"}, {"fsqrt", "sqrt"}, {"frndint", "nearbyint"}, {"fsin", "sin"}, {"fcos", "cos"}};
        for (const auto& [name, fn] : unary)
            if (m == name) {
                const std::string x = fpuAt(st, 0);
                fpuSet(st, 0, snapshot(blk, std::string(fn) == "-" ? "-" + wrap(x) : std::string(fn) + "(" + x + ")", addr, "double"));
                return true;
            }
        // Compares: the flags read like comiss (fnstsw ax; sahf copies them to the CPU flags).
        if (m == "fcomi" || m == "fucomi" || m == "fcomip" || m == "fucomip" || m == "fcom" || m == "fcomp" || m == "fucom" || m == "fucomp" ||
            m == "fcompp" || m == "fucompp" || m == "ftst") {
            std::string other;
            if (m == "ftst") other = "0.0";
            else if (ops.empty()) other = fpuAt(st, 1);
            else if (position(ops.back(), k)) other = fpuAt(st, k);
            else if (!memory(ops.back(), realType(ops.back()), other)) return false;
            const std::string top = fpuAt(st, 0);
            st.flags = Flags{Flags::FCmp, top, other, ""};
            const int pops = m == "fcompp" || m == "fucompp" ? 2 : m.back() == 'p' ? 1 : 0;
            for (int p = 0; p < pops; ++p) fpuPop(st);
            return true;
        }
        if (m == "fnstsw" || m == "fwait" || m == "fnclex" || m == "fninit" || m == "fnop" || m == "ffree" || m == "fincstp" || m == "fdecstp") return true;
        if (m == "fldcw" && ops.size() == 1) {  // the rounding mode / precision control word
            bool mem = false;
            stmt(blk, "_FPU_SETCW(" + x86Value(st, ops[0], target, mem) + ")", addr);
            return true;
        }
        if (m == "fnstcw" && ops.size() == 1) {
            x86Store(blk, st, ops[0], target, "_FPU_GETCW()", true, addr);
            return true;
        }
        if (m.rfind("fcmov", 0) == 0 && ops.size() == 2 && position(ops[1], k)) {
            static const std::pair<const char*, const char*> cc[] = {{"b", "b"}, {"e", "e"}, {"be", "be"}, {"u", "p"},
                                                                    {"nb", "ae"}, {"ne", "ne"}, {"nbe", "a"}, {"nu", "np"}};
            for (const auto& [suffix, x86cc] : cc)
                if (m.substr(5) == suffix) {
                    const std::string c = condExpr(flagCond(st.flags, x86Condition(x86cc)));
                    const std::string chosen = fpuAt(st, k), kept = fpuAt(st, 0);
                    fpuSet(st, 0, snapshot(blk, c + " ? " + chosen + " : " + kept, addr, "double"));
                    return true;
                }
        }
        (void)readsMem;
        return false;
    }

    // The carry flag as an expression: after an addition it is the carry out, after a subtraction or compare the borrow.
    std::string carryExpr(const State& st, bool armCarry) const {
        if (st.flags.kind == Flags::None) return "carry";
        if (armCarry || st.flags.kind == Flags::Cmn) return condExpr(flagCond(st.flags, "hs"));
        return condExpr(flagCond(st.flags, "lo"));
    }

    // Scalar x86 instructions with a C spelling: carries, rotates, bit scans, byte swaps, double shifts, exchanges,
    // system calls, non-temporal stores and the SSE control register.
    bool x86Scalar(Block& blk, State& st, size_t i, const std::vector<std::string>& ops) {
        const std::string& m = mnemonic_[i];
        const arm64::Insn& in = lines_[i].insn;
        const uint64_t addr = in.addr, target = in.target;
        bool readsMem = false;
        int id = 0, bits = 0;
        const bool destReg = !ops.empty() && parseRegister(ops[0], id, bits);
        const std::string w = std::to_string(bits ? bits : x64_ ? 64 : 32);
        const auto value = [&](size_t k) { return x86Value(st, ops[k], target, readsMem); };
        if ((m == "adc" || m == "sbb") && ops.size() == 2) {
            const std::string carry = carryExpr(st, false);
            std::string e;
            if (m == "sbb" && ops[0] == ops[1]) e = "-" + wrap(carry);  // sbb eax, eax: all ones when the borrow is set
            else e = wrap(value(0)) + (m == "adc" ? " + " : " - ") + wrap(value(1)) + (m == "adc" ? " + " : " - ") + wrap(carry);
            x86Store(blk, st, ops[0], target, e, false, addr, readsMem);
            st.flags = Flags{};
            return true;
        }
        if ((m == "rol" || m == "ror") && ops.size() == 2 && bits >= 8) {
            const std::string fn = std::string("__builtin_rotate") + (m == "rol" ? "left" : "right") + w;
            x86Store(blk, st, ops[0], target, fn + "(" + value(0) + ", " + value(1) + ")", false, addr, readsMem);
            st.flags = Flags{};
            return true;
        }
        if ((m == "bsf" || m == "bsr" || m == "tzcnt" || m == "lzcnt" || m == "popcnt") && ops.size() == 2 && destReg) {
            const bool wide = bits == 64;
            const std::string x = value(1), ll = wide ? "ll" : "";
            std::string e = m == "bsf" || m == "tzcnt" ? "__builtin_ctz" + ll + "(" + x + ")"
                            : m == "bsr"            ? std::string(wide ? "63" : "31") + " - __builtin_clz" + ll + "(" + x + ")"
                            : m == "lzcnt"          ? "__builtin_clz" + ll + "(" + x + ")"
                                                    : "__builtin_popcount" + ll + "(" + x + ")";
            define(blk, st, id, e, false, addr, readsMem);
            st.flags = Flags{Flags::Tst, x, "", ""};  // ZF: the source was zero
            return true;
        }
        if (m == "bswap" && ops.size() == 1 && destReg && bits >= 32) {
            define(blk, st, id, "__builtin_bswap" + w + "(" + read(id) + ")", true, addr);
            return true;
        }
        if ((m == "shld" || m == "shrd") && ops.size() == 3 && bits >= 16) {
            const std::string d = value(0), s = value(1), n = value(2), ut = "(uint" + w + "_t)";
            const std::string e = m == "shld" ? wrap(d) + " << " + wrap(n) + " | " + ut + wrap(s) + " >> " + w + " - " + wrap(n)
                                              : ut + wrap(d) + " >> " + wrap(n) + " | " + wrap(s) + " << " + w + " - " + wrap(n);
            x86Store(blk, st, ops[0], target, e, false, addr, readsMem);
            st.flags = Flags{};
            return true;
        }
        if (m == "xchg" && ops.size() == 2) {
            int other = 0, otherBits = 0;
            const bool regs = destReg && parseRegister(ops[1], other, otherBits);
            if (regs && id == other) return true;  // xchg ax, ax: a nop
            if (regs) {
                const std::string old = snapshot(blk, read(id), addr, wordType());
                define(blk, st, id, read(other), true, addr);
                define(blk, st, other, old, true, addr);
                return true;
            }
            // With memory it is an atomic exchange.
            const size_t memAt = ops[0][0] == '[' || ops[0].find("ptr") != std::string::npos ? 0 : 1;
            int r = 0, rbits = 0;
            if (!parseRegister(ops[1 - memAt], r, rbits)) return false;
            Address a;
            std::string type;
            if (!parseX86Memory(st, ops[memAt], target, a, type)) return false;
            std::string vtype;
            define(blk, st, r, "__atomic_exchange_n((" + (type.empty() ? std::string("uint32_t") : type) + " *)" + wrap(addressOf(a, vtype)) + ", " + read(r) + ", __ATOMIC_SEQ_CST)",
                   true, addr, true, true);
            return true;
        }
        if (m == "syscall" && x64_) {  // rax: number, then rdi, rsi, rdx, r10, r8, r9
            define(blk, st, 0, "syscall(" + read(0) + ", " + read(7) + ", " + read(6) + ", " + read(2) + ", " + read(10) + ", " + read(8) + ", " + read(9) + ")",
                   true, addr, true, true);
            return true;
        }
        if (m == "int" && ops.size() == 1 && ops[0] == "0x80" && !x64_) {  // eax: number, then ebx, ecx, edx, esi, edi, ebp
            define(blk, st, 0, "syscall(" + read(0) + ", " + read(3) + ", " + read(1) + ", " + read(2) + ", " + read(6) + ", " + read(7) + ", " + read(5) + ")",
                   true, addr, true, true);
            return true;
        }
        if ((m == "movntdq" || m == "movnti" || m == "movntps" || m == "movntpd" || m == "movntq" || m == "vmovntdq") && ops.size() == 2) {
            x86Store(blk, st, ops[0], target, value(1), true, addr, readsMem);  // a store that bypasses the cache
            return true;
        }
        if ((m == "stmxcsr" || m == "ldmxcsr") && ops.size() == 1) {
            if (m == "stmxcsr") x86Store(blk, st, ops[0], target, "_mm_getcsr()", true, addr, readsMem);
            else stmt(blk, "_mm_setcsr(" + value(0) + ")", addr);
            return true;
        }
        return false;
    }

    bool isThunk(uint64_t target) const {
        const native::Insn a = nc_.decodeAt(target, false);
        if (a.mnemonic != "mov" || a.operands.find("[esp]") == std::string::npos) return false;
        return nc_.decodeAt(target + a.size, false).flow == native::Flow::Return;
    }
    int thunkRegister(uint64_t target) const {
        const std::string ops = nc_.decodeAt(target, false).operands;
        int id = 0, bits = 0;
        return parseRegister(ops.substr(0, ops.find(',')), id, bits) ? id : -1;
    }

    // --- ARM -----------------------------------------------------------------
    // How far the prologue moves sp (pushes, sub sp) and where the frame pointer lands: slots beyond that are the
    // caller's, which is where arguments after r0-r3 are.
    void frameLayout() {
        frameReg_ = !lines_.empty() && lines_.front().insn.thumb ? 7 : 11;
        const auto listSize = [](const std::string& operands, int each) {
            int registers = 0;
            size_t at = operands.find('{');
            while (at != std::string::npos && at < operands.size() && operands[at] != '}') {
                const size_t end = std::min(operands.find(',', at + 1), operands.find('}', at + 1));
                const std::string item = operands.substr(at + 1, end - at - 1);
                const size_t dash = item.find('-');
                if (dash == std::string::npos) ++registers;
                else registers += std::atoi(item.c_str() + item.find_first_of("0123456789", dash)) - std::atoi(item.c_str() + item.find_first_of("0123456789")) + 1;
                if (end == std::string::npos || operands[end] == '}') break;
                at = end + 1;
            }
            return registers * each;
        };
        for (size_t i = 0; i < lines_.size() && i < 24; ++i) {
            const arm64::Insn& in = lines_[i].insn;
            if (in.flow != arm64::Flow::Normal) break;  // the prologue is straight-line code
            const std::string& m = mnemonic_[i];
            const std::vector<std::string> ops = splitOps(in.operands);
            int64_t imm = 0;
            if (m == "push" || m == "stmdb" && !ops.empty() && ops[0] == "sp!") frameSize_ += listSize(in.operands, 4);
            else if (m == "vpush") frameSize_ += listSize(in.operands, in.operands.find('d') != std::string::npos ? 8 : 4);
            else if ((m == "sub" || m == "subw") && ops.size() >= 2 && ops[0] == "sp" && parseNumber(ops.back(), imm)) frameSize_ += static_cast<int>(imm);
            else if (m == "str" && in.operands.find("[sp, #-4]!") != std::string::npos) frameSize_ += 4;
            else if ((m == "add" || m == "mov") && ops.size() >= 2 && ops[0] == "r" + std::to_string(frameReg_) && ops[1] == "sp") {
                imm = 0;
                if (ops.size() >= 3) parseNumber(ops[2], imm);
                fpDepth_ = frameSize_ - static_cast<int>(imm);  // how far below the entry sp the frame pointer points
            }
        }
    }

    std::string armOperand(const std::string& t, const std::string& shift = {}) const {
        int id = 0, bits = 0;
        int64_t v = 0;
        std::string e;
        if (parseRegister(t, id, bits)) e = id == 13 ? "sp" : read(id);
        else if (parseNumber(t, v)) e = number(v);
        else e = !t.empty() && t[0] == '#' ? t.substr(1) : t;
        if (!shift.empty()) {
            const size_t space = shift.find(' ');
            const std::string kind = shift.substr(0, space);
            int64_t amount = 0;
            if (space != std::string::npos) parseNumber(shift.substr(space + 1), amount);
            if (kind == "lsl" && amount) e = wrap(e) + " << " + std::to_string(amount);
            else if (kind == "lsr" && amount) e = "(uint32_t)" + wrap(e) + " >> " + std::to_string(amount);
            else if (kind == "asr" && amount) e = wrap(e) + " >> " + std::to_string(amount);
            else if (kind == "ror" && amount) e = "ror(" + e + ", " + std::to_string(amount) + ")";
        }
        return e;
    }

    // "[r1, #4]", "[r1, r2, lsl #2]", "[r1], #4", "[sp, #8]!"
    bool armMemory(Block& blk, State& st, const std::vector<std::string>& ops, size_t at, uint64_t addr, Address& out) {
        if (at >= ops.size() || ops[at].empty() || ops[at][0] != '[') return false;
        std::string t = ops[at];
        const bool pre = t.back() == '!';
        if (pre) t.pop_back();
        if (t.back() != ']') return false;
        const std::vector<std::string> inner = splitOps(t.substr(1, t.size() - 2));
        int base = 0, bits = 0, index = 0;
        if (inner.empty() || !parseRegister(inner[0], base, bits)) return false;
        int64_t disp = 0;
        std::string shifted;
        if (inner.size() >= 2 && !parseNumber(inner[1], disp)) {
            if (!parseRegister(inner[1], index, bits)) return false;
            shifted = armOperand(inner[1], inner.size() >= 3 ? inner[2] : std::string());
        }
        if (base == 15 && shifted.empty()) {  // PC-relative: the literal's own address
            out = Address{};
            const uint64_t pc = nc_.isa() == NativeCode::Isa::Arm32 && currentThumb_ ? (addr + 4) & ~uint64_t(3) : addr + 8;
            out.global = (pc + static_cast<uint64_t>(disp)) & 0xFFFFFFFFull;
            return true;
        }
        out = address(st, base, -1, 1, disp, shifted);
        int64_t post = 0;
        if (base != 13 && at + 1 < ops.size() && parseNumber(ops[at + 1], post)) {
            out = address(st, base, -1, 1, 0);
            postUpdate_ = {base, post};
        } else if (base != 13 && pre && disp) {
            postUpdate_ = {base, disp};
            out = address(st, base, -1, 1, disp);
        }
        (void)blk;
        return true;
    }

    void arm(Block& blk, State& st, size_t i) {
        const NativeCode::Line& l = lines_[i];
        const arm64::Insn& in = l.insn;
        std::string m = mnemonic_[i];
        const uint64_t addr = in.addr;
        currentThumb_ = in.thumb;
        const std::vector<std::string> ops = splitOps(in.operands);
        const std::string guard = cc_[i].empty() ? std::string() : condExpr(flagCond(st.flags, cc_[i]));
        if (!in.known) {
            if (m == ".word" || m == ".short") return;  // a literal pool or a branch table: data, never executed
            stmt(blk, "__asm(\"" + m + " " + in.operands + "\")", addr);
            return;
        }
        if (m == "nop" || m.compare(0, 2, "it") == 0 && m.find_first_not_of("te", 2) == std::string::npos || m == "dmb" || m == "dsb" || m == "isb" ||
            m == "push" || m == "vpush" || m == "vpop")
            return;
        if (in.flow == arm64::Flow::Return || (in.flow == arm64::Flow::IndirectJump && !guard.empty())) {  // conditional return
            if (!guard.empty()) stmt(blk, "if (" + guard + ") return " + read(0), addr);
            return;
        }
        if (m == "pop") return;
        if (in.flow == arm64::Flow::Jump && !guard.empty()) {
            stmt(blk, "if (" + guard + ") return " + calleeName(i) + "(" + callArgs(st, false) + ")", addr);
            return;
        }
        if (in.flow == arm64::Flow::Call || in.flow == arm64::Flow::IndirectCall) {
            int id = 0, bits = 0;
            std::string callee = in.flow == arm64::Flow::Call ? calleeName(i)
                                 : "(*" + (ops.empty() || !parseRegister(ops[0], id, bits) ? std::string("?") : read(id)) + ")";
            if (!guard.empty()) stmt(blk, "if (" + guard + ") " + callee + "(" + callArgs(st, false) + ")", addr);
            else call(blk, st, callee, addr);
            return;
        }
        int d = 0, dbits = 0;
        const bool hasD = !ops.empty() && parseRegister(ops[0], d, dbits);
        if (hasD && d == 13) return;  // frame arithmetic
        if ((m == "mov" || m == "add") && hasD && d == frameReg_ && ops.size() >= 2 && ops[1] == "sp") {
            frame_ = true;
            return;
        }
        // Sets register d, under the instruction's condition when it has one.
        const auto set = [&](int reg, const std::string& e, bool atomic, bool readsMem, bool constant, const std::string& type) {
            if (guard.empty()) define(blk, st, reg, e, atomic, addr, readsMem, false, constant, type);
            else define(blk, st, reg, guard + " ? " + wrap(e) + " : " + read(reg), false, addr, readsMem, false, false, type);
        };
        // Resolved data addresses (literal pools, add rd, pc).
        if (l.dataAddr && hasD && !l.dataRead && (m == "add" || m == "adr" || m == "movt" || m == "ldr")) {
            Address a;
            a.global = l.dataAddr;
            std::string type;
            std::string e = addressOf(a, type);
            const std::string& c = l.comment;
            if (c.size() > 2 && c.front() == '[' && c.back() == ']') e = "&" + c.substr(1, c.find("@got") == std::string::npos ? c.size() - 2 : c.find("@got") - 1);
            set(d, e, true, false, true, type);
            st.consts[d] = l.dataAddr;
            return;
        }
        if (m.rfind("ldr", 0) == 0 || m.rfind("str", 0) == 0 || m == "vldr" || m == "vstr") {
            const bool load = m[0] == 'l' || m == "vldr";
            const bool pair = m == "ldrd" || m == "strd";
            const size_t memAt = pair ? 2 : 1;
            if (m.find("ex") != std::string::npos && armScalar(blk, st, i, ops, guard, hasD, d)) return;  // ldrex / strex
            if (!hasD || ops.size() <= memAt || m.find("ex") != std::string::npos) return fallback(blk, st, i, ops, load);
            if (load && l.comment.size() > 1 && l.comment[0] == '=') {  // literal pool value
                int64_t v = 0;
                if (parseNumber(l.comment.substr(1, l.comment.find_first_of(" ;") - 1), v)) {
                    set(d, number(v), true, false, true, "");
                    st.consts[d] = static_cast<uint64_t>(v);
                    return;
                }
            }
            const std::string type = m == "ldrb" || m == "strb" ? "uint8_t" : m == "ldrh" || m == "strh" ? "uint16_t" : m == "ldrsb" ? "int8_t"
                                     : m == "ldrsh" ? "int16_t" : m[0] == 'v' ? (dbits == 64 ? "double" : "float") : "uint32_t";
            postUpdate_ = {-1, 0};
            Address a;
            if (!armMemory(blk, st, ops, memAt, addr, a)) return fallback(blk, st, i, ops, load);
            for (size_t k = 0; k < (pair ? 2u : 1u); ++k) {
                int r = 0, bits = 0;
                if (!parseRegister(ops[k], r, bits)) return fallback(blk, st, i, ops, load);
                Address at = a;
                if (k) {  // the second word of ldrd / strd
                    if (!at.slot.empty() && at.slot.rfind("sp_", 0) == 0) at.slot = slotName(false, std::strtoll(at.slot.c_str() + 3, nullptr, 16) + 4);
                    else if (!at.slot.empty() && at.slot.rfind("stk_", 0) == 0) {  // a parameter in the caller's frame
                        const int off = static_cast<int>(std::strtol(at.slot.c_str() + 4, nullptr, 16)) + 4;
                        maxStackArg_ = std::max(maxStackArg_, off);
                        at.slot = "stk_" + hex(static_cast<uint64_t>(off)).substr(2);
                    } else if (!at.slot.empty() && at.slot.rfind("fp_m", 0) == 0) {
                        const int64_t off = -std::strtoll(at.slot.c_str() + 4, nullptr, 16) + 4;
                        at.slot = slotName(true, off);
                    } else if (!at.slot.empty() && at.slot.rfind("fp_", 0) == 0) {
                        at.slot = slotName(true, std::strtoll(at.slot.c_str() + 3, nullptr, 16) + 4);
                    } else if (!at.expr.empty()) {
                        at.expr += " + 4";
                    } else {
                        at.global += 4;
                    }
                }
                const std::string lv = deref(at, type);
                if (load) set(r, lv, true, true, false, m == "ldr" || m == "ldrd" ? "" : type);
                else stmt(blk, (guard.empty() ? "" : "if (" + guard + ") ") + lv + " = " + (r == 13 ? "sp" : read(r)), addr);
                if (!load && at.slot.rfind("sp_", 0) == 0) st.outgoing.insert(static_cast<int>(std::strtol(at.slot.c_str() + 3, nullptr, 16)));
            }
            if (postUpdate_.first >= 0) {
                const int base = postUpdate_.first;
                const int64_t by = postUpdate_.second;
                set(base, read(base) + (by < 0 ? " - " + number(-by) : " + " + number(by)), false, false, false, "");
            }
            return;
        }
        if (m == "pld" || m == "pldw") return;  // cache hints
        // ldm / stm: consecutive words at the base register.
        if ((m == "ldm" || m == "ldmia" || m == "stm" || m == "stmia") && ops.size() == 2 && !ops[1].empty() && ops[1].front() == '{') {
            std::string baseName = ops[0];
            const bool writeBack = !baseName.empty() && baseName.back() == '!';
            if (writeBack) baseName.pop_back();
            int base = 0, bits = 0;
            const std::vector<std::string> list = splitOps(std::string_view(ops[1]).substr(1, ops[1].size() - 2));
            if (parseRegister(baseName, base, bits) && base != 13 && guard.empty()) {
                const bool load = m[0] == 'l';
                int own = -1;  // loading the base itself happens last
                for (size_t k = 0; k < list.size(); ++k) {
                    int r = 0;
                    if (!parseRegister(list[k], r, bits)) return fallback(blk, st, i, ops, false);
                    const std::string at = "*(uint32_t *)" + (k ? "(" + read(base) + " + " + std::to_string(4 * k) + ")" : read(base));
                    if (!load) stmt(blk, at + " = " + read(r), addr);
                    else if (r == base) own = static_cast<int>(k);
                    else define(blk, st, r, at, true, addr, true);
                }
                if (own >= 0) define(blk, st, base, "*(uint32_t *)" + (own ? "(" + read(base) + " + " + std::to_string(4 * own) + ")" : read(base)), true, addr, true);
                else if (writeBack) define(blk, st, base, read(base) + " + " + std::to_string(4 * list.size()), false, addr);
                return;
            }
        }
        if (m == "cbz" || m == "cbnz") return;  // a terminator
        if ((m == "cmp" || m == "cmn" || m == "tst" || m == "teq") && ops.size() >= 2) {
            const std::string a = armOperand(ops[0]), b = armOperand(ops[1], ops.size() > 2 ? ops[2] : std::string());
            if (m == "teq") st.flags = Flags{Flags::Tst, wrap(a) + " ^ " + wrap(b), "", ""};
            else st.flags = Flags{m == "cmp" ? Flags::Cmp : m == "cmn" ? Flags::Cmn : Flags::Tst, a, b, ""};
            return;
        }
        if ((m == "vcmp.f32" || m == "vcmp.f64" || m == "vcmpe.f32" || m == "vcmpe.f64") && ops.size() >= 2) {
            st.flags = Flags{Flags::FCmp, armOperand(ops[0]), armOperand(ops[1]), ""};
            return;
        }
        if (m == "vmrs") return;
        if (armScalar(blk, st, i, ops, guard, hasD, d)) return;
        if (neon(blk, st, i, ops, guard)) return;
        if (!hasD) return fallback(blk, st, i, ops, false);
        if (m.size() > 4 && (m.rfind("vmla.f", 0) == 0 || m.rfind("vmls.f", 0) == 0 || m.rfind("vnmla.f", 0) == 0 || m.rfind("vnmls.f", 0) == 0) &&
            ops.size() == 3) {
            const std::string product = wrap(armOperand(ops[1])) + " * " + wrap(armOperand(ops[2]));
            const std::string e = m.rfind("vmla", 0) == 0   ? read(d) + " + " + product
                                  : m.rfind("vmls", 0) == 0 ? read(d) + " - " + product
                                  : m.rfind("vnmla", 0) == 0 ? "-" + read(d) + " - " + product
                                                             : "-" + read(d) + " + " + product;
            if (guard.empty()) define(blk, st, d, e, false, addr);
            else define(blk, st, d, guard + " ? " + e + " : " + read(d), false, addr);
            return;
        }
        if ((m.rfind("vsqrt.", 0) == 0 || m.rfind("vabs.", 0) == 0 || m.rfind("vneg.", 0) == 0) && ops.size() == 2) {
            const std::string x = armOperand(ops[1]);
            const std::string e = m[1] == 's' ? "sqrt(" + x + ")" : m[1] == 'a' ? "fabs(" + x + ")" : "-" + wrap(x);
            if (guard.empty()) define(blk, st, d, e, false, addr);
            else define(blk, st, d, guard + " ? " + e + " : " + read(d), false, addr);
            return;
        }

        // "adds r0, #1" is "adds r0, r0, #1".
        const bool shiftToken = ops.size() > 2 && ops.back().find(' ') != std::string::npos;
        std::vector<std::string> a = ops;
        // In an IT block the 16-bit forms do not set flags.
        bool setsFlags = false;
        static const char* const bases[] = {"mov", "mvn", "add", "sub", "rsb", "and", "orr", "eor", "bic", "orn", "lsl", "lsr", "asr", "ror", "mul", "neg"};
        for (const char* b : bases)
            if (m == std::string(b) + "s") setsFlags = cc_[i].empty(), m = b;
        const auto op = [&](size_t k) { return armOperand(a[k], shiftToken && k + 2 == a.size() ? a.back() : std::string()); };
        if (shiftToken) {
            // handled by op(): the shift belongs to the operand before it
        }
        const size_t count = shiftToken ? a.size() - 1 : a.size();
        const auto finish = [&](const std::string& e, bool atomic, bool constant, const std::string& lhs, const std::string& rhs) {
            if (setsFlags) preserve(blk, st, d, addr);
            set(d, e, atomic, false, constant, "");
            if (!setsFlags) return;
            if (m == "sub") st.flags = Flags{Flags::Cmp, read(d) + " + " + wrap(rhs), rhs, read(d)};
            else if (m == "add") st.flags = Flags{Flags::Cmn, read(d) + " - " + wrap(rhs), rhs, read(d)};
            else st.flags = Flags{Flags::Tst, read(d), "", ""};
            (void)lhs;
        };
        if ((m == "mov" || m == "movw") && count >= 2) {
            int64_t v = 0;
            const bool imm = parseNumber(a[1], v);
            const std::string e = a[1] == "sp" ? "&" + slotName(false, 0) : op(1);
            finish(e, true, imm, e, e);
            if (imm && guard.empty()) st.consts[d] = static_cast<uint64_t>(v);
            return;
        }
        if (m == "movt" && count >= 2) {
            int64_t v = 0;
            parseNumber(a[1], v);
            const auto known = st.consts.find(d);
            if (known != st.consts.end()) {
                const uint64_t value = (known->second & 0xFFFF) | static_cast<uint64_t>(v) << 16;
                set(d, hex(value), true, false, true, "");
                st.consts[d] = value;
            } else {
                set(d, "(" + read(d) + " & 0xffff) | " + hex(static_cast<uint64_t>(v) << 16), false, false, false, "");
            }
            return;
        }
        if (m == "mvn" && count >= 2) return finish("~" + wrap(op(1)), false, false, "", "");
        if (m == "neg" && count >= 2) return finish("-" + wrap(op(1)), false, false, "", "");
        static const std::pair<const char*, const char*> binary[] = {{"add", "+"},  {"addw", "+"}, {"sub", "-"},  {"subw", "-"}, {"and", "&"},
                                                                    {"orr", "|"},  {"eor", "^"},  {"bic", "& ~"}, {"orn", "| ~"}, {"lsl", "<<"},
                                                                    {"lsr", ">>"}, {"asr", ">>"}, {"mul", "*"},  {"sdiv", "/"}, {"udiv", "/"},
                                                                    {"vadd.f32", "+"}, {"vsub.f32", "-"}, {"vmul.f32", "*"}, {"vdiv.f32", "/"},
                                                                    {"vadd.f64", "+"}, {"vsub.f64", "-"}, {"vmul.f64", "*"}, {"vdiv.f64", "/"}};
        for (const auto& [name, symbol] : binary) {
            if (m != name || count < 2) continue;
            const size_t li = count >= 3 ? 1 : 0, ri = count >= 3 ? 2 : 1;
            int base = 0, bits = 0;
            int64_t imm = 0;
            // add rd, sp, #n takes the address of a stack slot.
            if ((m == "add" || m == "addw") && count == 3 && parseRegister(a[1], base, bits) && base == 13 && parseNumber(a[2], imm)) {
                const Address at = address(st, 13, -1, 1, imm);
                set(d, "&" + (at.slot.empty() ? slotName(false, imm) : at.slot), true, false, false, "void *");
                return;
            }
            std::string lhs = op(li), rhs = op(ri);
            if (m == "lsr" || m == "udiv") lhs = "(uint32_t)" + wrap(lhs);
            const std::string o = symbol;
            const std::string e = o.back() == '~' ? wrap(lhs) + " " + o + wrap(rhs) : wrap(lhs) + " " + o + " " + wrap(rhs);
            return finish(e, false, false, lhs, rhs);
        }
        if (m == "rsb" && count >= 2) {
            const std::string lhs = op(count >= 3 ? 2 : 1), rhs = op(count >= 3 ? 1 : 0);
            return finish(wrap(lhs) + " - " + wrap(rhs), false, false, lhs, rhs);
        }
        if ((m == "mla" || m == "mls") && count >= 4)
            return finish(op(3) + (m == "mla" ? " + " : " - ") + wrap(op(1)) + " * " + wrap(op(2)), false, false, "", "");
        static const std::pair<const char*, const char*> casts[] = {{"uxtb", "(uint8_t)"}, {"uxth", "(uint16_t)"}, {"sxtb", "(int8_t)"}, {"sxth", "(int16_t)"}};
        for (const auto& [name, cast] : casts)
            if (m == name && count >= 2) return finish(std::string(cast) + wrap(op(1)), false, false, "", "");
        if ((m == "vmov" || m == "vmov.f32" || m == "vmov.f64") && count == 2) return finish(op(1), true, false, "", "");
        if (m.rfind("vcvt", 0) == 0 && count == 2) return finish(m + "(" + op(1) + ")", true, false, "", "");
        if ((m == "clz" || m == "rev" || m == "rev16" || m == "rbit") && count >= 2) return finish(m + "(" + op(1) + ")", true, false, "", "");
        fallback(blk, st, i, ops, m.rfind("st", 0) != 0 && m.rfind("v", 0) != 0);
    }

    // Common NEON operations on d / q registers, vld1 / vst1 of whole registers, vdup.
    bool neon(Block& blk, State& st, size_t i, const std::vector<std::string>& ops, const std::string& guard) {
        const std::string& m = mnemonic_[i];
        const uint64_t addr = lines_[i].insn.addr;
        if (m.size() < 3 || m[0] != 'v' || ops.empty() || !guard.empty()) return false;
        const size_t dot = m.find('.');
        const std::string op = m.substr(0, dot), kind = dot == std::string::npos ? std::string() : m.substr(dot + 1);
        const std::string type = kind.find('f') != std::string::npos ? "float4" : "int4";
        if ((op == "vld1" || op == "vst1") && ops.size() >= 2 && ops[0].size() > 2 && ops[0].front() == '{') {
            std::vector<std::string> list = splitOps(std::string_view(ops[0]).substr(1, ops[0].size() - 2));
            std::string base = ops[1];
            const bool writeBack = !base.empty() && base.back() == '!';
            if (writeBack) base.pop_back();
            const size_t colon = base.find(" :");
            if (colon != std::string::npos) base.erase(colon, base.find(']') - colon);
            int b = 0, bits = 0;
            if (base.size() < 3 || !parseRegister(base.substr(1, base.size() - 2), b, bits)) return false;
            for (size_t k = 0; k < list.size(); ++k) {
                int r = 0;
                if (!parseRegister(list[k], r, bits)) return false;
                const std::string at = "*(uint64_t *)" + (k ? "(" + read(b) + " + " + std::to_string(8 * k) + ")" : read(b));
                if (op == "vld1") define(blk, st, r, at, true, addr, true);
                else stmt(blk, at + " = " + read(r), addr);
            }
            int offset = 0;
            if (writeBack) define(blk, st, b, read(b) + " + " + std::to_string(8 * list.size()), false, addr);
            else if (ops.size() > 2 && parseRegister(ops[2], offset, bits)) define(blk, st, b, read(b) + " + " + read(offset), false, addr);
            return true;
        }
        int d = 0, bits = 0;
        if (!parseRegister(ops[0], d, bits) || d < kFp) return false;
        std::vector<std::string> a;
        for (size_t k = 1; k < ops.size(); ++k) {
            const size_t lane = ops[k].find('[');
            int r = 0, w = 0;
            int64_t v = 0;
            if (parseRegister(lane == std::string::npos ? ops[k] : ops[k].substr(0, lane), r, w))
                a.push_back(lane == std::string::npos ? read(r) : "lane(" + read(r) + ", " + ops[k].substr(lane + 1, ops[k].size() - lane - 2) + ")");
            else if (parseNumber(ops[k], v)) a.push_back(number(v));
            else if (!ops[k].empty() && ops[k][0] == '#') a.push_back(ops[k].substr(1));
            else return false;
        }
        std::string e;
        if (a.size() == 2) {
            if (op == "vadd") e = vectorInfix(a[0], "+", a[1]);
            else if (op == "vsub") e = vectorInfix(a[0], "-", a[1]);
            else if (op == "vmul") e = vectorInfix(a[0], "*", a[1]);
            else if (op == "vdiv") e = vectorInfix(a[0], "/", a[1]);
            else if (op == "vand") e = vectorInfix(a[0], "&", a[1]);
            else if (op == "vorr") e = vectorInfix(a[0], "|", a[1]);
            else if (op == "veor") e = vectorInfix(a[0], "^", a[1]);
            else if (op == "vbic") e = wrap(a[0]) + " & ~" + wrap(a[1]);
            else if (op == "vmla") e = read(d) + " + " + wrap(a[0]) + " * " + wrap(a[1]);
            else if (op == "vmls") e = read(d) + " - " + wrap(a[0]) + " * " + wrap(a[1]);
            else if (op == "vfma") e = read(d) + " + " + wrap(a[0]) + " * " + wrap(a[1]);
            else if (op == "vmin") e = vectorCall("min", a);
            else if (op == "vmax") e = vectorCall("max", a);
            else if (op == "vshl") e = vectorInfix(a[0], "<<", a[1]);
            else if (op == "vshr") e = vectorInfix(a[0], ">>", a[1]);
            else if (op == "vceq") e = vectorInfix(a[0], "==", a[1]);
            else if (op == "vcgt") e = vectorInfix(a[0], ">", a[1]);
            else if (op == "vcge") e = vectorInfix(a[0], ">=", a[1]);
            else if (op == "vpadd") e = vectorCall("pairwise_add", a);
            else if (op == "vmull") e = "widening(" + wrap(a[0]) + " * " + wrap(a[1]) + ")";
            else if (op == "vaddl" || op == "vaddw") e = "widening(" + vectorInfix(a[0], "+", a[1]) + ")";
        } else if (a.size() == 1) {
            if (op == "vabs") e = vectorCall("abs", a);
            else if (op == "vneg") e = "-" + wrap(a[0]);
            else if (op == "vsqrt") e = vectorCall("sqrt", a);
            else if (op == "vdup") e = vectorCall("splat", a);
            else if (op == "vmov" && bits >= 64) e = a[0];
            else if (op == "vmvn") e = "~" + wrap(a[0]);
            else if (op == "vmovl") e = vectorCall("widen", a);
            else if (op == "vmovn") e = vectorCall("narrow", a);
            else if (op == "vrecpe") e = "1.0 / " + wrap(a[0]);
        } else if (a.size() == 3 && op == "vext") {
            e = vectorCall("ext", a);
        }
        if (e.empty()) return false;
        define(blk, st, d, e, false, addr, false, false, false, bits == 128 ? type : bits == 64 ? "double" : "float");
        return true;
    }

    // --- blocks ------------------------------------------------------------------
    std::string branchCond(const State& st, size_t i) const {
        const arm64::Insn& in = lines_[i].insn;
        std::string m = mnemonic_[i];
        const std::vector<std::string> ops = splitOps(in.operands);
        if (arm_) {
            if ((m == "cbz" || m == "cbnz") && !ops.empty()) {
                int id = 0, bits = 0;
                if (parseRegister(ops[0], id, bits)) return cond(read(id), m == "cbz" ? "==" : "!=", "0");
            }
            std::string cc = m.size() >= 3 ? m.substr(1, 2) : std::string();
            if (cc == "cs") cc = "hs";
            if (cc == "cc") cc = "lo";
            return flagCond(st.flags, cc);
        }
        if ((m == "jecxz" || m == "jrcxz")) return cond(read(1), "==", "0");
        return flagCond(st.flags, x86Condition(m.substr(1)));
    }

    void translateBlock(size_t b) {
        Block& blk = fn_.blocks[b];
        State st;
        prologue_ = b == 0;
        // A block starts with the flags its predecessors leave, when they all leave the same: "cmp; jg ...; jne ..."
        // compares once.
        const Flags* inherited = nullptr;
        bool agree = true;
        for (size_t p = 0; p < fn_.blocks.size() && agree; ++p) {
            if (std::find(fn_.blocks[p].succ.begin(), fn_.blocks[p].succ.end(), static_cast<int>(b)) == fn_.blocks[p].succ.end()) continue;
            const auto before = endFlags_.find(static_cast<int>(p));
            if (before == endFlags_.end() || (inherited && !(*inherited == before->second))) agree = false;
            else inherited = &before->second;
        }
        if (agree && inherited) st.flags = *inherited;
        // Arguments are often set up before the block that calls: what every predecessor has set since its last call.
        bool first = true, all = true;
        for (size_t p = 0; p < fn_.blocks.size() && all; ++p) {
            if (std::find(fn_.blocks[p].succ.begin(), fn_.blocks[p].succ.end(), static_cast<int>(b)) == fn_.blocks[p].succ.end()) continue;
            const auto before = endArgs_.find(static_cast<int>(p));
            if (before == endArgs_.end()) {
                all = false;
                break;
            }
            const auto keep = [&](std::set<int>& to, const std::set<int>& from) {
                if (first) to = from;
                else
                    for (auto it = to.begin(); it != to.end();) it = from.count(*it) ? std::next(it) : to.erase(it);
            };
            keep(st.written, before->second.first);
            keep(st.outgoing, before->second.second);
            first = false;
        }
        if (!all) st.written.clear(), st.outgoing.clear();
        const size_t end = first_[b] + count_[b];
        std::string selected;  // jump table: the switched value, copied before the dispatch sequence reuses its register
        if (const auto table = tables_.find(end - 1); table != tables_.end()) {
            int selector = 0, width = 0;
            if (parseRegister(table->second.second, selector, width)) {
                const int t = nextSynth_++;
                const std::string name = "t" + std::to_string(t - kFirstTemp);
                Stmt s;
                s.addrs = {lines_[end - 1].insn.addr};
                s.def = t;
                s.defName = name;
                s.rhs = read(selector);
                s.atomic = true;
                types_[name].push_back(wordType());
                blk.stmts.push_back(std::move(s));
                selected = ph(t, name);
            }
        }
        for (size_t i = first_[b]; i < end; ++i) {
            const arm64::Insn& in = lines_[i].insn;
            const arm64::Flow flow = flowOf(i);
            if (i + 1 == end && flow != arm64::Flow::Normal && flow != arm64::Flow::Call && flow != arm64::Flow::IndirectCall) {
                // i386 returns float and double in st(0).
                const bool fpuResult = !arm_ && !x64_ && flow == arm64::Flow::Return && !st.fpu.empty();
                const std::string fpuTop = fpuResult ? st.fpu.back() : std::string();
                if (!arm_ && !fpuResult) fpuFlush(blk, st, in.addr);
                terminator(blk, st, i);
                if (fpuResult && blk.term.kind == TermKind::Return && blk.term.text.empty()) blk.term.text = fpuTop, fpuReturns_ = true;
                if (blk.term.kind == TermKind::Switch && !selected.empty()) blk.term.text = selected;
                endFlags_[static_cast<int>(b)] = st.flags;
                endArgs_[static_cast<int>(b)] = {st.written, st.outgoing};
                return;
            }
            if (arm_) arm(blk, st, i);
            else x86(blk, st, i);
            if (flow == arm64::Flow::Call && in.hasTarget && noReturn(calleeName(i))) {
                blk.term.kind = TermKind::Stop;
                return;
            }
        }
        if (!arm_ && !lines_.empty() && end > first_[b]) fpuFlush(blk, st, lines_[end - 1].insn.addr);
        blk.term.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall;
        endFlags_[static_cast<int>(b)] = st.flags;
        endArgs_[static_cast<int>(b)] = {st.written, st.outgoing};
    }

    void terminator(Block& blk, State& st, size_t i) {
        const arm64::Insn& in = lines_[i].insn;
        Term& t = blk.term;
        t.addrs = {in.addr};
        switch (flowOf(i)) {
        case arm64::Flow::Return: t.kind = TermKind::Return; break;
        case arm64::Flow::Trap:
            t.kind = TermKind::Stop;
            t.text = "__builtin_trap()";
            break;
        case arm64::Flow::IndirectJump: {
            if (const auto table = tables_.find(i); table != tables_.end()) {
                for (const auto& [block, entries] : cases_)
                    if (&fn_.blocks[static_cast<size_t>(block)] == &blk) tableSwitch(t, entries, table->second.second);
                if (conditionalTables_.count(i)) t.noDefault = false;  // out of range: the instruction after
                break;
            }
            const std::vector<std::string> ops = splitOps(in.operands);
            bool mem = false;
            int id = 0, bits = 0;
            std::string target = ops.empty() ? std::string("?")
                                 : parseRegister(ops.back(), id, bits) ? read(id)
                                 : arm_ ? std::string("table")
                                        : x86Value(st, ops[0], in.target, mem);
            // add pc, r12, pc after ldr r12, =offset: a hand-made PLT entry the listing already names ("puts@plt").
            const std::string& note = lines_[i].comment;
            if (const size_t plt = note.find("@plt"); plt != std::string::npos && note.find_first_of(" ;") > plt) {
                t.kind = TermKind::Return;
                t.text = note.substr(0, plt) + "(" + callArgs(st, true) + ")";
                tailCall_ = true;
            } else if (f_.kind == NativeCode::FunctionKind::Plt || nc_.tailJump(lines_, i)) {
                t.kind = TermKind::Return;
                t.text = "(*" + wrap(target) + ")(" + callArgs(st, true) + ")";
                tailCall_ = true;
            } else {
                t.kind = TermKind::Stop;
                t.text = "goto *" + wrap(target);
            }
            break;
        }
        case arm64::Flow::Jump:
            if (blk.succ.empty()) {  // tail call
                t.kind = TermKind::Return;
                t.text = calleeName(i) + "(" + callArgs(st, true) + ")";
                tailCall_ = true;
            } else {
                t.kind = TermKind::Fall;
            }
            break;
        case arm64::Flow::CondJump:
            if (blk.succ.size() >= 2) {
                t.kind = TermKind::Cond;
                t.text = branchCond(st, i);
            } else if (blk.succ.size() == 1 && in.hasTarget && (in.target < f_.addr || in.target >= f_.addr + f_.size)) {
                stmt(blk, "if (" + condExpr(branchCond(st, i)) + ") return " + calleeName(i) + "(" + callArgs(st, false) + ")", in.addr);
                t.kind = TermKind::Fall;
            } else {
                t.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall;
            }
            break;
        default: t.kind = blk.succ.empty() ? TermKind::Stop : TermKind::Fall; break;
        }
    }

    void decideReturns() {
        for (size_t i = 0; i < fn_.blocks.size(); ++i) {
            const Block& b = fn_.blocks[i];
            if (b.term.kind != TermKind::Return || !b.term.text.empty()) continue;
            for (const Stmt& s : b.stmts)
                if (s.def == 0) returnsValue_ = true;
            // Set earlier (before a stack-protector check, say): a computed value, not a call's leftover.
            std::vector<char> seen(fn_.blocks.size(), 0);
            std::vector<size_t> work{i};
            while (!work.empty() && !returnsValue_) {
                const size_t at = work.back();
                work.pop_back();
                for (size_t p = 0; p < fn_.blocks.size(); ++p) {
                    if (seen[p] || std::find(fn_.blocks[p].succ.begin(), fn_.blocks[p].succ.end(), static_cast<int>(at)) == fn_.blocks[p].succ.end())
                        continue;
                    seen[p] = 1;
                    const Stmt* last = nullptr;
                    for (const Stmt& s : fn_.blocks[p].stmts)
                        if (s.def == 0) last = &s;
                    if (!last) work.push_back(p);
                    else if (!last->sideEffect) returnsValue_ = true;
                }
            }
        }
        // ARM conditional returns ("it eq; bxeq lr") are statements: they count when the function computes r0.
        const std::string conditional = ") return " + read(0);
        bool anyConditional = false, computed = false;
        for (const Block& b : fn_.blocks)
            for (const Stmt& s : b.stmts) {
                anyConditional = anyConditional || (s.def < 0 && s.rhs.find(conditional) != std::string::npos);
                computed = computed || (s.def == 0 && !s.sideEffect);
            }
        returnsValue_ = returnsValue_ || tailCall_ || (anyConditional && computed) || fpuReturns_;
        if (!returnsValue_) {
            for (Block& b : fn_.blocks)
                for (Stmt& s : b.stmts)
                    if (const size_t at = s.def < 0 ? s.rhs.find(conditional) : std::string::npos; at != std::string::npos)
                        s.rhs.erase(at + 8);
            return;
        }
        for (Block& b : fn_.blocks)
            if (b.term.kind == TermKind::Return && b.term.text.empty()) b.term.text = read(0);
    }

    const NativeCode& nc_;
    const NativeCode::Function& f_;
    const bool arm_, x64_;
    std::vector<NativeCode::Line> lines_;
    std::vector<std::string> cc_, mnemonic_;
    std::vector<size_t> first_, count_;
    Fn fn_;
    int nextSynth_ = kFirstTemp;
    std::map<std::string, std::vector<std::string>> types_;
    bool returnsValue_ = false, tailCall_ = false;
    bool fpuReturns_ = false;  // i386: a float or double comes back in st(0)
    std::set<size_t> conditionalTables_;  // lines of conditional table dispatches (ldrls pc, ...)
    bool frame_ = false;      // a frame pointer was set up
    bool prologue_ = true;    // x86: still saving registers
    int pic_ = -1;            // x86: the register holding the position-independent base
    uint64_t picValue_ = 0, nextAddress_ = 0;
    std::pair<int, int64_t> postUpdate_{-1, 0};
    std::map<int, Flags> endFlags_;  // block -> the flags it leaves
    std::map<int, std::pair<std::set<int>, std::set<int>>> endArgs_;  // block -> registers and stack slots set since a call
    std::map<size_t, std::pair<std::vector<uint64_t>, std::string>> tables_;  // dispatching line -> targets, index register
    std::map<int, std::vector<std::pair<int64_t, int>>> cases_;              // block -> index value, target block
    bool currentThumb_ = true;       // ARM: the mode of the instruction being translated
    int maxStackArg_ = -1;  // highest stack-argument offset seen (-1: none)
    int frameSize_ = 0, fpDepth_ = 0, frameReg_ = 7;  // ARM: sp moved by the prologue; the frame pointer's depth
};

}  // namespace

// ---------------------------------------------------------------------------
// Renaming

namespace {

bool identStart(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '$'; }
bool identChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$'; }

// Calls f(begin, length, afterDot) for each identifier outside string / char literals and // comments.
template <class F>
void forEachIdent(std::string_view s, F f) {
    for (size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (c == '"' || c == '\'') {
            for (++i; i < s.size() && s[i] != c; ++i)
                if (s[i] == '\\') ++i;
            ++i;
        } else if (c == '/' && i + 1 < s.size() && s[i + 1] == '/') {
            return;
        } else if (identStart(c)) {
            size_t j = i + 1;
            while (j < s.size() && identChar(s[j])) ++j;
            f(i, j - i, i > 0 && s[i - 1] == '.');
            i = j;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            while (i < s.size() && (identChar(s[i]) || s[i] == '.')) ++i;
        } else {
            ++i;
        }
    }
}

bool digitsFrom(std::string_view s, size_t at, bool hexDigits = false) {
    if (at >= s.size()) return false;
    for (size_t i = at; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (!(hexDigits ? std::isxdigit(c) : std::isdigit(c))) return false;
    }
    return true;
}

}  // namespace

bool isVariable(std::string_view t, bool native) {
    if (t.empty()) return false;
    if (!native) return (t[0] == 'v' && digitsFrom(t, 1)) || (t.rfind("arg", 0) == 0 && digitsFrom(t, 3));
    for (const char* r : {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp"})
        if (t == r) return true;
    if (t[0] == 'r' && digitsFrom(t, 1)) return t.size() <= 3 && std::atoi(std::string(t.substr(1)).c_str()) <= 15;
    if (t.rfind("xmm", 0) == 0 && digitsFrom(t, 3)) return t.size() <= 5;
    if (std::strchr("xwsdqhbt", t[0]) && digitsFrom(t, 1)) {
        if (t.size() > 4) return false;
        const int n = std::atoi(std::string(t.substr(1)).c_str());
        return t[0] == 't' || ((t[0] == 'x' || t[0] == 'w') ? n <= 30 : n <= 31);
    }
    if (t.rfind("sp_", 0) == 0) return digitsFrom(t, 3, true);
    if (t.rfind("stk_", 0) == 0) return digitsFrom(t, 4, true);
    if (t.rfind("fp_m", 0) == 0) return digitsFrom(t, 4, true);
    if (t.rfind("fp_", 0) == 0) return digitsFrom(t, 3, true);
    return false;
}

std::string variableKey(std::string_view t, bool native) {
    if (native && !t.empty() && t[0] == 'w' && digitsFrom(t, 1)) return "x" + std::string(t.substr(1));
    return std::string(t);
}

void applyUserNames(Output& out, const std::vector<std::pair<std::string, std::string>>& renames,
                    const std::vector<std::pair<std::string, std::string>>& types, bool native,
                    const std::vector<std::pair<std::string, std::string>>& symbols) {
    out.renamed.clear();
    out.renamedSymbols.clear();
    std::map<std::string, std::string> byKey, typeByKey;
    for (const auto& [key, name] : renames) byKey[variableKey(key, native)] = name;
    for (const auto& [key, type] : types) typeByKey[variableKey(key, native)] = type;
    for (const auto& [key, name] : byKey) out.renamed.emplace_back(name, key);
    const auto nameOf = [&](const std::string& key) {
        auto it = byKey.find(key);
        return it == byKey.end() ? key : it->second;
    };
    // "char *p", "int n"
    const auto declare = [](const std::string& type, const std::string& name) {
        return type + (!type.empty() && type.back() == '*' ? "" : " ") + name;
    };
    // Signature and declarations: rebuilt from the variables.
    size_t locals = 0;
    std::string params;
    for (const Var& v : out.vars) {
        auto t = typeByKey.find(v.key);
        const std::string type = t == typeByKey.end() ? v.type : t->second;
        if (v.param) {
            params += (params.empty() ? "" : ", ") + declare(type, nameOf(v.key));
            continue;
        }
        const size_t at = static_cast<size_t>(out.declLine) + locals++;
        if (out.declLine < 0 || at >= out.lines.size()) continue;
        out.lines[at].text = declare(type, nameOf(v.key)) + ";" + (v.note.empty() || t != typeByKey.end() ? "" : "  // " + v.note);
    }
    std::string prefix = out.headerPrefix;
    if (auto r = typeByKey.find(std::string(kReturnKey)); r != typeByKey.end() && out.returnAt != std::string::npos &&
                                                          out.returnAt + out.returnType.size() <= prefix.size()) {
        const bool pointer = !r->second.empty() && r->second.back() == '*';
        size_t len = out.returnType.size();
        if (pointer && out.returnAt + len < prefix.size() && prefix[out.returnAt + len] == ' ') ++len;  // "char *name"
        prefix.replace(out.returnAt, len, r->second);
    }
    if (out.headerLine >= 0 && static_cast<size_t>(out.headerLine) < out.lines.size())
        out.lines[static_cast<size_t>(out.headerLine)].text = prefix + params + out.headerSuffix;
    // Other names (functions, methods, fields, classes, labels, globals): everywhere, even after a '.'.
    std::map<std::string, std::string> symbolMap(symbols.begin(), symbols.end());
    for (const auto& [original, name] : symbolMap) out.renamedSymbols.emplace_back(name, original);
    if (!symbolMap.empty())
        for (Line& l : out.lines) {
            std::string text;
            size_t at = 0;
            forEachIdent(l.text, [&](size_t b, size_t n, bool afterDot) {
                const std::string_view tok = std::string_view(l.text).substr(b, n);
                if (!afterDot && isVariable(tok, native)) return;
                auto it = symbolMap.find(std::string(tok));
                if (it == symbolMap.end()) return;
                text.append(l.text, at, b - at);
                text += it->second;
                at = b + n;
            });
            if (at == 0) continue;
            text.append(l.text, at, std::string::npos);
            l.text = std::move(text);
        }
    if (byKey.empty()) return;
    for (size_t li = 0; li < out.lines.size(); ++li) {
        if (static_cast<int>(li) == out.headerLine) continue;
        if (out.declLine >= 0 && li >= static_cast<size_t>(out.declLine) && li < static_cast<size_t>(out.declLine) + locals) continue;
        Line& l = out.lines[li];
        std::string text;
        size_t at = 0;
        forEachIdent(l.text, [&](size_t b, size_t n, bool afterDot) {
            const std::string_view tok = std::string_view(l.text).substr(b, n);
            if (afterDot || !isVariable(tok, native)) return;
            auto it = byKey.find(variableKey(tok, native));
            if (it == byKey.end()) return;
            text.append(l.text, at, b - at);
            text += it->second;
            at = b + n;
        });
        if (at == 0) continue;
        text.append(l.text, at, std::string::npos);
        l.text = std::move(text);
    }
}

// Pseudocode: any text is a type (struct foo *, unsigned int, void (*)(int), int[4]), on one line.
std::string checkTypeName(std::string_view type) {
    if (type.empty()) return "";  // back to the inferred type
    if (type.size() > 200) return "at most 200 characters";
    for (const char c : type)
        if (c == '\n' || c == '\r' || c == '\0') return "a type is one line";
    return "";
}

std::string typeOf(const Output& out, std::string_view key, const std::vector<std::pair<std::string, std::string>>& types) {
    for (const auto& [k, t] : types)
        if (k == key) return t;
    if (key == kReturnKey) return out.returnType;
    for (const Var& v : out.vars)
        if (v.key == key) return v.type;
    return "";
}

std::vector<size_t> identifierStarts(std::string_view text) {
    std::vector<size_t> out;
    forEachIdent(text, [&](size_t b, size_t, bool) { out.push_back(b); });
    return out;
}

namespace {

bool javaPrimitive(const std::string& t) {
    static const char* const kPrim[] = {"boolean", "byte", "char", "short", "int", "long", "float", "double"};
    return std::any_of(std::begin(kPrim), std::end(kPrim), [&](const char* p) { return t == p; });
}

}  // namespace

// The locals: every variable the body names, declared after the signature with its inferred type.
void declareLocals(Output& out, const std::map<std::string, std::vector<std::string>>& seen, bool native) {
    if (out.headerLine < 0) return;
    std::set<std::string> known;
    for (const Var& v : out.vars) known.insert(v.key);
    std::vector<Var> locals;
    for (size_t li = static_cast<size_t>(out.headerLine) + 1; li < out.lines.size(); ++li)
        forEachIdent(out.lines[li].text, [&](size_t b, size_t n, bool afterDot) {
            const std::string_view tok = std::string_view(out.lines[li].text).substr(b, n);
            if (afterDot || !isVariable(tok, native)) return;
            const std::string key = variableKey(tok, native);
            if (!known.insert(key).second) return;
            Var v;
            v.key = key;
            // One type for the register: the only one seen, else a common one with the others noted.
            std::vector<std::string> types;
            if (auto it = seen.find(key); it != seen.end())
                for (const std::string& t : it->second)
                    if (!t.empty() && std::find(types.begin(), types.end(), t) == types.end()) types.push_back(t);
            if (types.empty()) {
                v.type = native ? "int64_t" : "var";
            } else if (types.size() == 1) {
                v.type = types[0];
            } else {
                if (native) {
                    v.type = std::find(types.begin(), types.end(), "int64_t") != types.end() ? "int64_t" : types[0];
                } else {
                    const bool objects = std::none_of(types.begin(), types.end(), javaPrimitive);
                    v.type = objects ? "Object" : "var";
                }
                // The register is reused: say what it holds (a few, then a count).
                size_t listed = 0, others = 0;
                for (const std::string& t : types) {
                    if (t == v.type) continue;
                    if (listed == 3) {
                        ++others;
                        continue;
                    }
                    v.note += (v.note.empty() ? "holds " : ", ") + t;
                    ++listed;
                }
                if (others) v.note += " and " + std::to_string(others) + " more";
            }
            locals.push_back(std::move(v));
        });
    if (locals.empty()) return;
    out.declLine = out.headerLine + 1;
    std::vector<Line> decl(locals.size(), Line{std::string(), 1, {}});
    decl.push_back(Line{std::string(), 0, {}});  // blank line after the declarations
    out.lines.insert(out.lines.begin() + out.declLine, decl.begin(), decl.end());
    for (Var& v : locals) out.vars.push_back(std::move(v));
}

std::string keyOfShown(const Output& out, std::string_view token, bool native) {
    for (const auto& [shown, key] : out.renamed)
        if (shown == token) return key;
    return isVariable(token, native) ? variableKey(token, native) : std::string();
}

namespace {

// Keywords and built-in types of the Java-like and C-like output: never renamed, never a new name.
bool reservedWord(std::string_view name) {
    static const char* const kReserved[] = {
        "abstract", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do",
        "double", "else", "enum", "extends", "false", "final", "finally", "float", "for", "goto", "if", "implements",
        "import", "instanceof", "int", "interface", "long", "native", "new", "null", "package", "private", "protected",
        "public", "return", "short", "static", "super", "switch", "synchronized", "this", "throw", "throws", "true", "try",
        "void", "volatile", "while", "struct", "union", "unsigned", "signed", "sizeof", "typedef", "extern", "auto",
        "register", "sp", "fp", "exception", "result", "var", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t",
        "uint16_t", "uint32_t", "uint64_t", "uint128_t", "size_t", "half"};
    return std::any_of(std::begin(kReserved), std::end(kReserved), [&](const char* r) { return name == r; });
}

std::string identifierProblem(std::string_view name) {
    if (name.size() > 64) return "at most 64 characters";
    if (!identStart(name[0]) || !std::all_of(name.begin(), name.end(), identChar)) return "not an identifier (letters, digits, _ and $)";
    if (reservedWord(name)) return "'" + std::string(name) + "' is reserved";
    return "";
}

}  // namespace

bool isRenamableSymbol(std::string_view token, bool native) {
    return !token.empty() && identStart(token[0]) && !isVariable(token, native) && !reservedWord(token);
}

std::string symbolOfShown(const Output& out, std::string_view token, bool native) {
    for (const auto& [shown, original] : out.renamedSymbols)
        if (shown == token) return original;
    return isRenamableSymbol(token, native) ? std::string(token) : std::string();
}

std::string checkSymbolName(const Output& out, std::string_view name, bool native) {
    if (name.empty()) return "";  // back to the original name
    if (std::string why = identifierProblem(name); !why.empty()) return why;
    if (isVariable(name, native)) return "looks like a register / variable name";
    // A variable of this function shown under that name would become ambiguous.
    for (const auto& [shown, key] : out.renamed)
        if (shown == name) return "'" + std::string(name) + "' is a variable of this function";
    return "";
}

std::string checkNewName(const Output& out, std::string_view name, std::string_view key, bool native) {
    if (name.empty()) return "";  // back to the original name
    if (std::string why = identifierProblem(name); !why.empty()) return why;
    if (isVariable(name, native) && variableKey(name, native) != key) return "looks like another register's name";
    bool taken = false;
    for (const Line& l : out.lines)
        forEachIdent(l.text, [&](size_t b, size_t n, bool afterDot) {
            const std::string_view tok = std::string_view(l.text).substr(b, n);
            if (!afterDot && tok == name && keyOfShown(out, tok, native) != key) taken = true;
        });
    return taken ? "'" + std::string(name) + "' is already used in this function" : "";
}

std::string identifierAt(std::string_view text, size_t col, size_t* begin) {
    std::string found;
    forEachIdent(text, [&](size_t b, size_t n, bool) {
        if (col >= b && col < b + n && found.empty()) {
            found = std::string(text.substr(b, n));
            if (begin) *begin = b;
        }
    });
    return found;
}

std::vector<size_t> findIdentifier(std::string_view text, std::string_view ident) {
    std::vector<size_t> out;
    forEachIdent(text, [&](size_t b, size_t n, bool) {
        if (text.substr(b, n) == ident) out.push_back(b);
    });
    return out;
}

// A decompiler bug must not take the UI frame or an MCP call down with it.
Output decompileMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const Naming& naming) {
    if (m.dex >= a.dexes().size()) return {{}, "bad method"};
    try {
        return DalvikDecompiler(a, m, naming).run();
    } catch (const std::exception& e) {
        return {{}, std::string("decompiler error: ") + e.what()};
    }
}

Output decompileNative(const NativeCode& nc, const NativeCode::Function& f) {
    try {
        if (nc.isa() != NativeCode::Isa::Arm64) return OtherDecompiler(nc, f).run();
        return NativeDecompiler(nc, f).run();
    } catch (const std::exception& e) {
        return {{}, std::string("decompiler error: ") + e.what()};
    }
}

}  // namespace decompiler
