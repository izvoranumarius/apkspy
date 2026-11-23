#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Line diff (Myers' O((N+M)D) algorithm) for side-by-side views and change
// summaries. Common prefix and suffix are trimmed first; past `maxEdits`
// differences the middle is reported as one delete + insert block, so huge
// rewrites stay cheap instead of exhausting memory.
namespace linediff {

enum class Op : uint8_t { Equal, Delete, Insert };

struct Edit {
    Op op;
    int a = -1;  // line in the old text (Equal / Delete)
    int b = -1;  // line in the new text (Equal / Insert)
};

inline std::vector<Edit> diff(const std::vector<std::string_view>& a, const std::vector<std::string_view>& b, int maxEdits = 2000) {
    std::vector<Edit> out;
    const int n = static_cast<int>(a.size()), m = static_cast<int>(b.size());
    int pre = 0;
    while (pre < n && pre < m && a[static_cast<size_t>(pre)] == b[static_cast<size_t>(pre)]) ++pre;
    int suf = 0;
    while (suf < n - pre && suf < m - pre && a[static_cast<size_t>(n - 1 - suf)] == b[static_cast<size_t>(m - 1 - suf)]) ++suf;
    for (int i = 0; i < pre; ++i) out.push_back({Op::Equal, i, i});
    const int an = n - pre - suf, bn = m - pre - suf;
    const auto A = [&](int i) { return a[static_cast<size_t>(pre + i)]; };
    const auto B = [&](int j) { return b[static_cast<size_t>(pre + j)]; };

    // Myers forward pass, keeping each round's V for the backtrack.
    const int max = an + bn;
    const int limit = std::min(max, maxEdits);
    const int offset = max + 1;
    std::vector<int> v(static_cast<size_t>(2 * max + 3), 0);
    // trace[d] holds V before round d for diagonals -(d+1)..d+1 only: O(D^2) memory.
    std::vector<std::vector<int>> trace;
    int found = -1;
    for (int d = 0; d <= limit && found < 0; ++d) {
        trace.emplace_back(v.begin() + (offset - d - 1), v.begin() + (offset + d + 2));
        for (int k = -d; k <= d; k += 2) {
            int x;
            if (k == -d || (k != d && v[static_cast<size_t>(offset + k - 1)] < v[static_cast<size_t>(offset + k + 1)]))
                x = v[static_cast<size_t>(offset + k + 1)];  // down: insert
            else
                x = v[static_cast<size_t>(offset + k - 1)] + 1;  // right: delete
            int y = x - k;
            while (x < an && y < bn && A(x) == B(y)) ++x, ++y;
            v[static_cast<size_t>(offset + k)] = x;
            if (x >= an && y >= bn) {
                found = d;
                break;
            }
        }
    }
    std::vector<Edit> middle;
    if (found < 0) {
        // Too different: the whole middle is replaced.
        for (int i = 0; i < an; ++i) middle.push_back({Op::Delete, pre + i, -1});
        for (int j = 0; j < bn; ++j) middle.push_back({Op::Insert, -1, pre + j});
    } else {
        int x = an, y = bn;
        for (int d = found; d > 0; --d) {
            const std::vector<int>& pv = trace[static_cast<size_t>(d)];
            const auto at = [&](int diag) { return pv[static_cast<size_t>(diag + d + 1)]; };
            const int k = x - y;
            const bool down = k == -d || (k != d && at(k - 1) < at(k + 1));
            const int pk = down ? k + 1 : k - 1;
            const int px = at(pk);
            const int py = px - pk;
            while (x > px + (down ? 0 : 1) && y > py + (down ? 1 : 0)) {
                --x, --y;
                middle.push_back({Op::Equal, pre + x, pre + y});
            }
            if (down) middle.push_back({Op::Insert, -1, pre + (--y)});
            else middle.push_back({Op::Delete, pre + (--x), -1});
        }
        while (x > 0 && y > 0) {
            --x, --y;
            middle.push_back({Op::Equal, pre + x, pre + y});
        }
        std::reverse(middle.begin(), middle.end());
    }
    out.insert(out.end(), middle.begin(), middle.end());
    for (int i = 0; i < suf; ++i) out.push_back({Op::Equal, n - suf + i, m - suf + i});
    return out;
}

// One row of a side-by-side view: a deleted line next to the inserted line
// that replaced it, unchanged lines on both sides, -1 for an empty cell.
struct Row {
    int a = -1, b = -1;
    Op kind = Op::Equal;  // Equal, Delete (a only / changed), Insert (b only)
    bool changed = false;  // both cells set and different
};

inline std::vector<Row> sideBySide(const std::vector<Edit>& edits) {
    std::vector<Row> rows;
    for (size_t i = 0; i < edits.size();) {
        if (edits[i].op == Op::Equal) {
            rows.push_back({edits[i].a, edits[i].b, Op::Equal, false});
            ++i;
            continue;
        }
        // A run of deletes and inserts: pair them up line by line.
        std::vector<int> dels, ins;
        while (i < edits.size() && edits[i].op != Op::Equal) {
            if (edits[i].op == Op::Delete) dels.push_back(edits[i].a);
            else ins.push_back(edits[i].b);
            ++i;
        }
        const size_t pairs = std::max(dels.size(), ins.size());
        for (size_t k = 0; k < pairs; ++k) {
            Row r;
            r.a = k < dels.size() ? dels[k] : -1;
            r.b = k < ins.size() ? ins[k] : -1;
            r.kind = r.a >= 0 ? Op::Delete : Op::Insert;
            r.changed = r.a >= 0 && r.b >= 0;
            rows.push_back(r);
        }
    }
    return rows;
}

inline std::vector<std::string_view> splitLines(std::string_view text) {
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string_view::npos) end = text.size();
        std::string_view line = text.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (end == text.size() && line.empty() && start == text.size()) break;  // no phantom last line
        lines.push_back(line);
        start = end + 1;
    }
    return lines;
}

}  // namespace linediff
