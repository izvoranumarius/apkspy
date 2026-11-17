#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

// Line diff for the Comparer (Myers' O(ND) algorithm), shaped for a side-by-side
// view: equal lines face each other, a run of removed lines next to a run of
// added lines becomes "changed" pairs, and each changed pair carries the word
// ranges that differ.
namespace textdiff {

enum class Kind { Same, Removed, Added, Changed };

struct Span {  // [begin, end) bytes of a line
    size_t begin = 0, end = 0;
};

struct Row {
    Kind kind = Kind::Same;
    int left = -1;   // line index in A (-1: none on this side)
    int right = -1;  // line index in B
    std::vector<Span> leftSpans, rightSpans;  // Changed rows: the parts that differ
};

struct Result {
    std::vector<std::string_view> a, b;  // the lines (views into the inputs)
    std::vector<Row> rows;
    int removed = 0, added = 0, changed = 0;
    bool approximate = false;  // too many differences for an exact diff: a coarse one
    bool identical() const { return removed == 0 && added == 0 && changed == 0; }
};

// `a` and `b` must outlive the result (rows refer into them).
Result diff(std::string_view a, std::string_view b, int maxEdits = 4000);
// The parts of two lines that differ, word by word.
void wordDiff(std::string_view a, std::string_view b, std::vector<Span>& aSpans, std::vector<Span>& bSpans);

}  // namespace textdiff
