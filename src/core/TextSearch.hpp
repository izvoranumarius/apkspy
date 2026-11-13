#pragma once
#include <string>
#include <string_view>
#include <vector>
#include "core/TextUtils.hpp"

// In-file text search shared by the editor's find bar (M1). Pure logic: no
// ImGui, no Document - takes any line container (size() + operator[] yielding
// something convertible to std::string_view) so it stays unit-testable.
//
// Conventions (single source of truth):
//  - Match::line is 0-based (same convention as Document::goTo/highlight and
//    SearchHit::line; the UI adds 1 only when displaying).
//  - Match::col / Match::len are BYTE offsets into the line's UTF-8 text.
//  - Case-insensitive matching folds ASCII only (tex::asciiLower); bytes
//    >= 0x80 are never touched, so UTF-8 text stays byte-identical.
namespace textsearch {

struct Options {
    bool matchCase = false;
    bool wholeWord = false;
};

struct Match {
    int line;  // 0-based
    int col;   // byte offset of the match inside the line
    int len;   // byte length of the match (never across line boundaries)
};

// Result cap: a huge file must not flood the UI with millions of hits.
constexpr size_t kDefaultMaxMatches = 10000;

// Byte-wise equality of needle at line[at..] with word-boundary handling.
// Both `view` and `needle` must already be folded when !opt.matchCase.
inline bool matchesAt(std::string_view view, size_t at, std::string_view needle, bool wholeWord) {
    for (size_t k = 0; k < needle.size(); ++k)
        if (view[at + k] != needle[k]) return false;
    if (wholeWord) {
        // Word chars are the shared identifier definition (alnum, '_', '$').
        if (at > 0 && tex::isIdentChar(view[at - 1])) return false;
        if (at + needle.size() < view.size() && tex::isIdentChar(view[at + needle.size()])) return false;
    }
    return true;
}

// Finds all matches across `lines` in order (line by line, left to right).
// Stops after `maxMatches` hits and sets `truncated` when the list was cut
// short. An empty query yields an empty result; matches never span lines.
// Overlapping matches are reported ("aa" in "aaaa" = 3 hits): the scan
// advances one byte per hit so users can step through every occurrence.
template <typename Lines>
inline std::vector<Match> findAll(const Lines& lines, const std::string& query,
                                  const Options& opt, size_t maxMatches, bool& truncated) {
    truncated = false;
    std::vector<Match> out;
    if (query.empty()) return out;
    const std::string needle = opt.matchCase ? query : tex::asciiLower(query);
    std::string folded;  // reused fold buffer: one allocation for the whole scan
    for (size_t li = 0; li < lines.size(); ++li) {
        const std::string_view raw = lines[li];
        if (needle.size() > raw.size()) continue;
        std::string_view view;
        if (opt.matchCase) {
            view = raw;
        } else {
            folded.assign(raw);  // keeps capacity across lines - no per-line heap churn
            for (char& c : folded) c = tex::asciiLowerCh(c);
            view = folded;
        }
        const size_t n = view.size();
        for (size_t p = 0; p + needle.size() <= n; ++p) {
            if (view[p] != needle[0]) continue;  // cheap first-char reject
            if (matchesAt(view, p, needle, opt.wholeWord)) {
                out.push_back({static_cast<int>(li), static_cast<int>(p), static_cast<int>(needle.size())});
                if (out.size() >= maxMatches) {
                    truncated = true;
                    return out;
                }
            }
        }
    }
    return out;
}

template <typename Lines>
inline std::vector<Match> findAll(const Lines& lines, const std::string& query,
                                  const Options& opt, bool& truncated) {
    return findAll(lines, query, opt, kDefaultMaxMatches, truncated);
}

// Index of the first match at/after (line, col), wrapping around to the
// beginning; -1 when there are no matches. Relies on findAll's ordering.
inline int nextIndex(const std::vector<Match>& ms, int line, int col) {
    if (ms.empty()) return -1;
    for (size_t i = 0; i < ms.size(); ++i) {
        const Match& m = ms[i];
        if (m.line > line || (m.line == line && m.col >= col)) return static_cast<int>(i);
    }
    return 0;  // wrap: everything is before (line, col)
}

// Index of the last match strictly before (line, col), wrapping around to
// the end; -1 when there are no matches.
inline int prevIndex(const std::vector<Match>& ms, int line, int col) {
    if (ms.empty()) return -1;
    for (size_t i = ms.size(); i-- > 0;) {
        const Match& m = ms[i];
        if (m.line < line || (m.line == line && m.col < col)) return static_cast<int>(i);
    }
    return static_cast<int>(ms.size()) - 1;  // wrap: everything is at/after (line, col)
}

}  // namespace textsearch
