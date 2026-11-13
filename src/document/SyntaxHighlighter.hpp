#pragma once
#include <string>
#include <string_view>
#include <cstddef>
#include <cstdint>
#include <vector>

enum class Language { Plain, Java, Kotlin, Groovy, JavaScript, Css, Xml, Json, Smali, Yaml, Python };

// What a span of source is. The UI maps it to a colour of the active theme
// (theme::syntax), so the document model does not depend on the UI.
enum class SyntaxToken : uint8_t { Default, Keyword, String, Comment, Number, Type, Punctuation, Attribute, Directive };

struct Span {
    size_t begin;
    size_t end;
    SyntaxToken token;
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
