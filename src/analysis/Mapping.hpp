#pragma once
#include <map>
#include <string>
#include <string_view>
#include <vector>

// ProGuard / R8 mapping files (mapping.txt): parse them and retrace
// obfuscated stack traces back to the original names.
//
//   com.example.Original -> a.b:
//       int field -> a
//       1:5:void method(int):12:16 -> b
//
// Text in, text out: nothing is executed or modified.
namespace mapping {

struct Member {
    std::string original;    // "method" / "field"
    std::string signature;   // "void method(int)" / "int field"
    bool method = false;
    int obfStart = 0, obfEnd = 0;     // obfuscated line range (0 = none)
    int origStart = 0, origEnd = 0;   // original line range (0 = none)
};

struct Class {
    std::string original;    // "com.example.Original"
    std::string obfuscated;  // "a.b"
    std::multimap<std::string, Member> members;  // by obfuscated name
};

struct Mapping {
    std::map<std::string, Class> byObfuscated;  // "a.b" -> class
    std::map<std::string, std::string> originalToObfuscated;
    int errors = 0;  // lines that could not be parsed (skipped)

    // Original class name, or `obf` itself when unknown.
    std::string originalClass(std::string_view obf) const;
    // Original method name for `obf` in class `obfClass` at obfuscated line
    // `line` (0 = any); several candidates are joined with '|'.
    std::string originalMethod(std::string_view obfClass, std::string_view obf, int line) const;
    // Original line for an obfuscated line inside a method's range (or `line`).
    int originalLine(std::string_view obfClass, std::string_view obf, int line) const;
};

Mapping parse(std::string_view text);

// Rewrites "at a.b.c(SourceFile:12)" frames and bare class names in
// "Caused by: a.b: msg" lines; other text is kept as is.
std::string retrace(const Mapping& m, std::string_view trace);

}  // namespace mapping
