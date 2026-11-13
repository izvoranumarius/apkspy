#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

// Small ASCII-only text helpers shared across the code base. ASCII only on
// purpose: file names and code identifiers are matched byte-wise, never
// locale-aware.
namespace tex {

inline std::string asciiLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

inline char asciiLowerCh(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

inline bool asciiIEqual(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (asciiLowerCh(a[i]) != asciiLowerCh(b[i])) return false;
    return true;
}

// Case-insensitive substring search without allocating lower-case copies.
// Returns the offset of the first match or npos.
inline size_t ciFind(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return 0;
    if (haystack.size() < needle.size()) return std::string_view::npos;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        size_t k = 0;
        while (k < needle.size() && asciiLowerCh(haystack[i + k]) == asciiLowerCh(needle[k])) ++k;
        if (k == needle.size()) return i;
    }
    return std::string_view::npos;
}

// Shared identifier-character definition: letters, digits, '_' and '$'
// (jadx emits '$' for nested classes, so it is part of identifiers here).
inline bool isIdentChar(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_' || c == '$';
}

// True when `needle` occurs in `haystack` as a standalone identifier
// (not glued to letters/digits/_/$ on either side).
inline bool ciContainsWord(std::string_view haystack, std::string_view needle) {
    size_t pos = 0;
    while (pos < haystack.size()) {
        size_t rel = ciFind(haystack.substr(pos), needle);
        if (rel == std::string_view::npos) return false;
        size_t at = pos + rel;
        bool leftOk = at == 0 || !isIdentChar(haystack[at - 1]);
        size_t end = at + needle.size();
        bool rightOk = end >= haystack.size() || !isIdentChar(haystack[end]);
        if (leftOk && rightOk) return true;
        pos = at + needle.size();
    }
    return false;
}

}  // namespace tex
