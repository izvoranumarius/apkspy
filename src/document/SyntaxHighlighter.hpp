#pragma once
#include <string>
#include <vector>
#include "imgui.h"

enum class Language { Plain, Java, Kotlin, Groovy, JavaScript, Css, Xml, Json, Smali, Yaml };

struct Span {
    size_t begin;
    size_t end;
    ImU32 color;
};

class SyntaxHighlighter {
public:
    static void tokenize(const std::string& line, Language lang, bool& inBlock, std::vector<Span>& out);

private:
    static void tokenizeCLike(const std::string& line, bool& inBlock, std::vector<Span>& out, int keywordSet);
    static void tokenizeXml(const std::string& line, bool& inBlock, std::vector<Span>& out);
    static void tokenizeJson(const std::string& line, std::vector<Span>& out);
    static void tokenizeSmali(const std::string& line, std::vector<Span>& out);
    static void tokenizeYaml(const std::string& line, std::vector<Span>& out);
    static void tokenizeCss(const std::string& line, bool& inBlock, std::vector<Span>& out);
};
