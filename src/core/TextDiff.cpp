#include "core/TextDiff.hpp"
#include <algorithm>
#include <cstdint>
#include <functional>

namespace textdiff {

namespace {

enum class Op { Equal, Delete, Insert };

struct Edit {
    Op op;
    int a = -1, b = -1;  // element indices
};

// Myers' greedy O(ND) diff of a[0..n) and b[0..m); false when more than maxD
// edits would be needed (the caller then falls back to a coarse answer).
bool myers(int n, int m, const std::function<bool(int, int)>& eq, int maxD, std::vector<Edit>& out) {
    const int limit = std::min(maxD, n + m);
    const int offset = limit + 1;
    std::vector<int> v(static_cast<size_t>(2 * limit + 3), 0);
    std::vector<std::vector<int>> trace;  // v[-d..d] before step d
    for (int d = 0; d <= limit; ++d) {
        trace.emplace_back(v.begin() + (offset - d), v.begin() + (offset + d + 1));
        for (int k = -d; k <= d; k += 2) {
            int x = (k == -d || (k != d && v[static_cast<size_t>(offset + k - 1)] < v[static_cast<size_t>(offset + k + 1)]))
                        ? v[static_cast<size_t>(offset + k + 1)]
                        : v[static_cast<size_t>(offset + k - 1)] + 1;
            int y = x - k;
            while (x < n && y < m && eq(x, y)) ++x, ++y;
            v[static_cast<size_t>(offset + k)] = x;
            if (x >= n && y >= m) {
                // Walk back through the trace.
                std::vector<Edit> rev;
                int cx = n, cy = m;
                for (int dd = d; dd >= 0; --dd) {
                    const std::vector<int>& t = trace[static_cast<size_t>(dd)];
                    const auto at = [&](int kk) { return t[static_cast<size_t>(kk + dd)]; };
                    const int ck = cx - cy;
                    int prevK, prevX, prevY;
                    if (dd == 0) {
                        prevX = prevY = 0;
                    } else {
                        prevK = (ck == -dd || (ck != dd && at(ck - 1) < at(ck + 1))) ? ck + 1 : ck - 1;
                        prevX = at(prevK);
                        prevY = prevX - prevK;
                    }
                    while (cx > prevX && cy > prevY) rev.push_back({Op::Equal, --cx, --cy});
                    if (dd > 0) {
                        if (cx == prevX) rev.push_back({Op::Insert, -1, --cy});
                        else rev.push_back({Op::Delete, --cx, -1});
                    }
                }
                out.assign(rev.rbegin(), rev.rend());
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string_view> splitLines(std::string_view s) {
    std::vector<std::string_view> out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        if (e == std::string_view::npos) e = s.size();
        std::string_view line = s.substr(pos, e - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        out.push_back(line);
        pos = e + 1;
    }
    return out;
}

uint64_t hashOf(std::string_view s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) h = (h ^ c) * 1099511628211ull;
    return h;
}

// Words, runs of spaces and single punctuation marks, as [begin, end) ranges.
std::vector<Span> tokens(std::string_view s) {
    std::vector<Span> out;
    const auto word = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || (static_cast<unsigned char>(c) & 0x80);
    };
    for (size_t i = 0; i < s.size();) {
        size_t j = i + 1;
        if (word(s[i])) while (j < s.size() && word(s[j])) ++j;
        else if (s[i] == ' ' || s[i] == '\t') while (j < s.size() && (s[j] == ' ' || s[j] == '\t')) ++j;
        out.push_back({i, j});
        i = j;
    }
    return out;
}

void addSpan(std::vector<Span>& spans, Span s) {
    if (!spans.empty() && spans.back().end == s.begin) spans.back().end = s.end;
    else spans.push_back(s);
}

}  // namespace

void wordDiff(std::string_view a, std::string_view b, std::vector<Span>& aSpans, std::vector<Span>& bSpans) {
    aSpans.clear();
    bSpans.clear();
    const std::vector<Span> ta = tokens(a), tb = tokens(b);
    const auto text = [](std::string_view s, Span sp) { return s.substr(sp.begin, sp.end - sp.begin); };
    std::vector<Edit> edits;
    if (!myers(static_cast<int>(ta.size()), static_cast<int>(tb.size()),
               [&](int i, int j) { return text(a, ta[static_cast<size_t>(i)]) == text(b, tb[static_cast<size_t>(j)]); }, 300, edits)) {
        if (!a.empty()) aSpans.push_back({0, a.size()});
        if (!b.empty()) bSpans.push_back({0, b.size()});
        return;
    }
    for (const Edit& e : edits) {
        if (e.op == Op::Delete) addSpan(aSpans, ta[static_cast<size_t>(e.a)]);
        if (e.op == Op::Insert) addSpan(bSpans, tb[static_cast<size_t>(e.b)]);
    }
}

Result diff(std::string_view a, std::string_view b, int maxEdits) {
    Result r;
    r.a = splitLines(a);
    r.b = splitLines(b);
    const int n = static_cast<int>(r.a.size()), m = static_cast<int>(r.b.size());
    // Common head and tail first: most comparisons differ in a few places.
    int head = 0;
    while (head < n && head < m && r.a[static_cast<size_t>(head)] == r.b[static_cast<size_t>(head)]) ++head;
    int tail = 0;
    while (tail < n - head && tail < m - head && r.a[static_cast<size_t>(n - 1 - tail)] == r.b[static_cast<size_t>(m - 1 - tail)]) ++tail;
    const int an = n - head - tail, bm = m - head - tail;
    std::vector<uint64_t> ha, hb;
    for (int i = 0; i < an; ++i) ha.push_back(hashOf(r.a[static_cast<size_t>(head + i)]));
    for (int j = 0; j < bm; ++j) hb.push_back(hashOf(r.b[static_cast<size_t>(head + j)]));
    std::vector<Edit> mid;
    if (!myers(an, bm,
               [&](int i, int j) {
                   return ha[static_cast<size_t>(i)] == hb[static_cast<size_t>(j)] &&
                          r.a[static_cast<size_t>(head + i)] == r.b[static_cast<size_t>(head + j)];
               },
               maxEdits, mid)) {
        r.approximate = true;  // the whole middle as one replaced block
        mid.clear();
        for (int i = 0; i < an; ++i) mid.push_back({Op::Delete, i, -1});
        for (int j = 0; j < bm; ++j) mid.push_back({Op::Insert, -1, j});
    }
    std::vector<Edit> all;
    for (int i = 0; i < head; ++i) all.push_back({Op::Equal, i, i});
    for (const Edit& e : mid) all.push_back({e.op, e.a < 0 ? -1 : e.a + head, e.b < 0 ? -1 : e.b + head});
    for (int i = 0; i < tail; ++i) all.push_back({Op::Equal, n - tail + i, m - tail + i});

    // Rows: removed and added lines between two equal ones face each other as changed pairs.
    for (size_t i = 0; i < all.size();) {
        if (all[i].op == Op::Equal) {
            r.rows.push_back({Kind::Same, all[i].a, all[i].b, {}, {}});
            ++i;
            continue;
        }
        std::vector<int> dels, ins;
        while (i < all.size() && all[i].op != Op::Equal) {
            if (all[i].op == Op::Delete) dels.push_back(all[i].a);
            else ins.push_back(all[i].b);
            ++i;
        }
        const size_t pairs = r.approximate ? 0 : std::min(dels.size(), ins.size());
        for (size_t k = 0; k < pairs; ++k) {
            Row row{Kind::Changed, dels[k], ins[k], {}, {}};
            wordDiff(r.a[static_cast<size_t>(dels[k])], r.b[static_cast<size_t>(ins[k])], row.leftSpans, row.rightSpans);
            r.rows.push_back(std::move(row));
            ++r.changed;
        }
        for (size_t k = pairs; k < dels.size(); ++k) r.rows.push_back({Kind::Removed, dels[k], -1, {}, {}}), ++r.removed;
        for (size_t k = pairs; k < ins.size(); ++k) r.rows.push_back({Kind::Added, -1, ins[k], {}, {}}), ++r.added;
    }
    return r;
}

}  // namespace textdiff
