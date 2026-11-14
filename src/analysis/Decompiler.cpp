#include "analysis/Decompiler.hpp"
#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    CondTree cond;     // Cond, after folding
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
        for (const auto& [keys, target] : bb.term.cases) {
            for (int64_t k : keys) emit("case " + std::to_string(k) + ":", indent + 1, {});
            body(target);
        }
        if (!bb.succ.empty() && bb.succ[0] != follow) {
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

std::vector<TryInfo> parseTries(const DexFile& dex, const DexFile::CodeItem& code) {
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
                r.handlers.push_back({javaType(dex.typeDescriptor(type)), addr});
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
    DalvikDecompiler(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m)
        : a_(a), m_(m), dex_(*a.dexes()[m.dex]) {}

    Output run() {
        Output out;
        const uint32_t mi = m_.method.methodIdx;
        clsDesc_ = std::string(dex_.typeDescriptor(dex_.methodClass(mi)));
        isStatic_ = (m_.method.accessFlags & 0x8) != 0;
        const std::string name(dex_.methodName(mi));
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
            out.vars.push_back(Var{pn, javaType(pd), std::string(), true});
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
            out.headerPrefix += isCtor_ ? javaType(clsDesc_) : javaType(retDesc_) + " " + name;
            out.headerPrefix += "(";
            out.headerSuffix = ")";
        }
        out.lines.push_back({"// " + DexFile::descriptorToJava(clsDesc_), 0, {}});
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
        Structurer(fn_, out.lines).run(1);
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
        return d == clsDesc_ ? std::string() : javaType(d) + ".";
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
        for (const TryInfo& t : parseTries(dex_, code_)) {
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
        if (op == 0x15) {  // const/high16: almost always a float
            float f;
            const uint32_t bits = static_cast<uint32_t>(in.literal);
            std::memcpy(&f, &bits, sizeof f);
            if (in.literal != 0) return floatText(f, false);
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
            def(A, javaType(dex_.typeDescriptor(in.index)) + ".class", true);
            s.constant = true;
        } else if (op == 0x1d || op == 0x1e) {
            stmt(std::string(op == 0x1d ? "monitorEnter(" : "monitorExit(") + R(A, 'L') + ")");
        } else if (op == 0x1f) {
            def(A, "(" + javaType(dex_.typeDescriptor(in.index)) + ") " + R(A, 'L'), false);
        } else if (op == 0x20) {
            def(A, R(B, 'L') + " instanceof " + javaType(dex_.typeDescriptor(in.index)), false);
        } else if (op == 0x21) {
            def(A, R(B, 'L') + ".length", true);
            s.readsMem = true;
        } else if (op == 0x22) {
            def(A, "new " + javaType(dex_.typeDescriptor(in.index)), true);
            s.sideEffect = s.newInstance = true;
        } else if (op == 0x23) {
            const std::string t = javaType(dex_.typeDescriptor(in.index));  // "int[]"
            const size_t br = t.find('[');
            def(A, "new " + (br == std::string::npos ? t : t.substr(0, br)) + "[" + R(B) + "]" +
                       (br == std::string::npos ? "" : t.substr(br + 2)),
                true);
            s.sideEffect = true;
        } else if (op == 0x24 || op == 0x25) {
            const std::string t = javaType(dex_.typeDescriptor(in.index));
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
            const std::string f = in.index < dex_.fieldCount() ? std::string(dex_.fieldName(in.index)) : "field" + std::to_string(in.index);
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
                f = owner(dex_.fieldClass(in.index)) + std::string(dex_.fieldName(in.index));
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
        const auto type = [&](uint32_t idx) { return idx < dex_.typeCount() ? javaType(dex_.typeDescriptor(idx)) : std::string(); };
        const auto field = [&](uint32_t idx) {
            return idx < dex_.fieldCount() ? javaType(dex_.typeDescriptor(dex_.fieldType(idx))) : std::string();
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
        const std::string name(dex_.methodName(mi));
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
            const std::string created = "new " + javaType(ownerDesc) + "(" + args + ")";
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
                    made.vtype = javaType(ownerDesc);
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
                        copy.vtype = javaType(ownerDesc);
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
        out.headerPrefix = std::string(returnsValue_ ? "int64_t " : "void ") + NativeCode::displayName(f_) + "(";
        out.headerSuffix = ") {";
        out.lines.push_back({std::string(), 0, {f_.addr}});
        Structurer(fn_, out.lines).run(1);
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
        const size_t end = cb.firstLine + cb.lineCount;
        for (size_t li = cb.firstLine; li < end; ++li) {
            const NativeCode::Line& l = cfg_.lines[li];
            const bool last = li + 1 == end;
            const arm64::Flow flow = l.insn.flow;
            if (last && flow != arm64::Flow::Normal && flow != arm64::Flow::Call && flow != arm64::Flow::IndirectCall) {
                terminator(blk, st, l, cb);
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
            Reg r;
            const std::string target = ops.empty() || !parseReg(ops[0], r) ? std::string("?") : R(r);
            if (st.epilogue || f_.kind == NativeCode::FunctionKind::Plt) {  // indirect tail call (or an import stub)
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
            if (!e.empty() && e[0] == '"') e = cQuote(nc_.cStringAt(l.dataAddr));
            else if (!e.empty() && e.rfind("0x", 0) != 0) e = "&" + e;
            define(blk, st, d, e, true, addr, false, false, true, e[0] == '"' ? "char *" : "void *");
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

        if (!hasD) return fallback(blk, st, l, ops);

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
                    const std::string str = nc_.cStringAt(v);
                    std::string e;
                    if (looksLikeText(str)) e = cQuote(str);
                    else if (const std::string sym = nc_.symbolize(v); !sym.empty()) e = "&" + sym;
                    else e = hex(v);
                    define(blk, st, d, e, true, addr, false, false, true, e[0] == '"' ? "char *" : "void *");
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
        if ((m == "smull" || m == "umull" || m == "smaddl" || m == "umaddl") && ops.size() >= 3) {
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
            define(blk, st, d, op1 == "tpidr_el0" ? "__builtin_thread_pointer()" : "__mrs(" + op1 + ")", true, addr, true, true);
            return;
        }
        if (m == "svc") {
            Reg x0;
            parseReg("x0", x0);
            define(blk, st, x0, "syscall(" + ph(8, "x8") + ", " + ph(0, "x0") + ", " + ph(1, "x1") + ", " + ph(2, "x2") + ")", true, addr, true, true);
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

    void fallback(Block& blk, State& st, const NativeCode::Line& l, const std::vector<std::string>& ops) {
        const arm64::Insn& in = l.insn;
        const std::string& m = in.mnemonic;
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
        st.flags = Flags{};
        if (defines) define(blk, st, d, call, true, in.addr, true, true);
        else stmt(blk, call, in.addr);
    }

    const NativeCode& nc_;
    const NativeCode::Function& f_;
    NativeCode::ControlFlow cfg_;
    Fn fn_;
    int nextSynth_ = 64;
    std::map<std::string, std::vector<std::string>> types_;  // variable key -> types of the values it is given
    bool returnsValue_ = false;
    bool tailCall_ = false;
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
    if (std::strchr("xwsdqhbt", t[0]) && digitsFrom(t, 1)) {
        if (t.size() > 4) return false;
        const int n = std::atoi(std::string(t.substr(1)).c_str());
        return t[0] == 't' || ((t[0] == 'x' || t[0] == 'w') ? n <= 30 : n <= 31);
    }
    if (t.rfind("sp_", 0) == 0) return digitsFrom(t, 3, true);
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
    if (out.headerLine >= 0 && static_cast<size_t>(out.headerLine) < out.lines.size())
        out.lines[static_cast<size_t>(out.headerLine)].text = out.headerPrefix + params + out.headerSuffix;
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

std::string checkTypeName(std::string_view type) {
    if (type.empty()) return "";  // back to the inferred type
    if (type.size() > 80) return "at most 80 characters";
    if (!identStart(type[0])) return "a type starts with a letter or _";
    for (const char c : type)
        if (!identChar(c) && !std::strchr(" .*&<>[],:", c)) return std::string("'") + c + "' cannot appear in a type";
    return "";
}

std::string typeOf(const Output& out, std::string_view key, const std::vector<std::pair<std::string, std::string>>& types) {
    for (const auto& [k, t] : types)
        if (k == key) return t;
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
Output decompileMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    if (m.dex >= a.dexes().size()) return {{}, "bad method"};
    try {
        return DalvikDecompiler(a, m).run();
    } catch (const std::exception& e) {
        return {{}, std::string("decompiler error: ") + e.what()};
    }
}

Output decompileNative(const NativeCode& nc, const NativeCode::Function& f) {
    try {
        return NativeDecompiler(nc, f).run();
    } catch (const std::exception& e) {
        return {{}, std::string("decompiler error: ") + e.what()};
    }
}

}  // namespace decompiler
