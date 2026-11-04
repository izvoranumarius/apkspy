#pragma once
#include <string>
#include <string_view>
#include <vector>
#include "imgui.h"

enum class Language { Plain, Java, Kotlin, Groovy, JavaScript, Css, Xml, Json, Smali, Yaml, Python };

struct Span {
    size_t begin;
    size_t end;
    ImU32 color;
};

class SyntaxHighlighter {
public:
    static void tokenize(std::string_view line, Language lang, bool& inBlock, std::vector<Span>& out);

private:
    static void tokenizeCLike(std::string_view line, bool& inBlock, std::vector<Span>& out, int keywordSet);
    static void tokenizeXml(std::string_view line, bool& inBlock, std::vector<Span>& out);
    static void tokenizeJson(std::string_view line, std::vector<Span>& out);
    static void tokenizeSmali(std::string_view line, std::vector<Span>& out);
    static void tokenizeYaml(std::string_view line, std::vector<Span>& out);
    static void tokenizeCss(std::string_view line, bool& inBlock, std::vector<Span>& out);
    static void tokenizePython(std::string_view line, bool& inBlock, std::vector<Span>& out);
};
