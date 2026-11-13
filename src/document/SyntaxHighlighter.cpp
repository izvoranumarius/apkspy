#include "document/SyntaxHighlighter.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_set>

namespace {
constexpr SyntaxToken kDefault = SyntaxToken::Default;
constexpr SyntaxToken kKeyword = SyntaxToken::Keyword;
constexpr SyntaxToken kString = SyntaxToken::String;
constexpr SyntaxToken kComment = SyntaxToken::Comment;
constexpr SyntaxToken kNumber = SyntaxToken::Number;
constexpr SyntaxToken kType = SyntaxToken::Type;
constexpr SyntaxToken kPunct = SyntaxToken::Punctuation;
constexpr SyntaxToken kAttr = SyntaxToken::Attribute;
constexpr SyntaxToken kDirective = SyntaxToken::Directive;

enum KeywordSet { KwJava, KwKotlin, KwGroovy, KwJs };

const std::unordered_set<std::string_view>& keywordSet(int set) {
    static const std::unordered_set<std::string_view> java = {
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
        "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
        "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
        "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp",
        "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void",
        "volatile", "while", "true", "false", "null", "var", "record", "sealed", "permits", "yield"};
    static const std::unordered_set<std::string_view> kotlin = {
        "package", "import", "class", "object", "interface", "fun", "val", "var", "if", "else", "when",
        "for", "while", "do", "return", "try", "catch", "finally", "throw", "throws", "null", "true",
        "false", "this", "super", "is", "in", "as", "open", "override", "abstract", "final", "sealed",
        "data", "enum", "companion", "lateinit", "lazy", "by", "suspend", "internal", "public", "private",
        "protected", "inline", "reified", "crossinline", "noinline", "operator", "infix", "typealias",
        "init", "constructor", "field", "get", "set", "where", "out", "vararg", "dynamic", "const",
        "external", "infix", "tailrec", "expect", "actual"};
    static const std::unordered_set<std::string_view> groovy = {
        "def", "package", "import", "class", "interface", "trait", "enum", "if", "else", "for", "while",
        "switch", "case", "break", "continue", "return", "try", "catch", "finally", "throw", "throws",
        "new", "this", "super", "null", "true", "false", "extends", "implements", "static", "final",
        "abstract", "public", "private", "protected", "synchronized", "volatile", "transient", "native",
        "assert", "in", "as", "it", "use", "with", "closure"};
    static const std::unordered_set<std::string_view> js = {
        "function", "var", "let", "const", "class", "extends", "if", "else", "return", "new", "this",
        "typeof", "instanceof", "null", "undefined", "true", "false", "async", "await", "import", "export",
        "default", "try", "catch", "finally", "throw", "for", "while", "do", "switch", "case", "break",
        "continue", "of", "in", "delete", "yield", "static", "get", "set", "super"};
    switch (set) {
    case KwKotlin: return kotlin;
    case KwGroovy: return groovy;
    case KwJs: return js;
    default: return java;
    }
}

void push(std::vector<Span>& out, size_t b, size_t e, SyntaxToken c) {
    if (e <= b) return;
    if (!out.empty() && out.back().token == c && out.back().end == b)
        out.back().end = e;
    else
        out.push_back({b, e, c});
}

bool isIdentStart(unsigned char c) { return std::isalpha(c) || c == '_' || c == '$'; }
bool isIdentPart(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$'; }
}

void SyntaxHighlighter::tokenize(std::string_view line, Language lang, bool& inBlock, std::vector<Span>& out) {
    out.clear();
    switch (lang) {
    case Language::Java: tokenizeCLike(line, inBlock, out, KwJava); break;
    case Language::Kotlin: tokenizeCLike(line, inBlock, out, KwKotlin); break;
    case Language::Groovy: tokenizeCLike(line, inBlock, out, KwGroovy); break;
    case Language::JavaScript: tokenizeCLike(line, inBlock, out, KwJs); break;
    case Language::Xml: tokenizeXml(line, inBlock, out); break;
    case Language::Json: tokenizeJson(line, out); break;
    case Language::Smali: tokenizeSmali(line, out); break;
    case Language::Yaml: tokenizeYaml(line, out); break;
    case Language::Css: tokenizeCss(line, inBlock, out); break;
    case Language::Python: tokenizePython(line, inBlock, out); break;
    default: push(out, 0, line.size(), kDefault); break;
    }
}

// Shared tokenizer for Java, Kotlin, Groovy and JavaScript.
void SyntaxHighlighter::tokenizeCLike(std::string_view line, bool& inBlock, std::vector<Span>& out, int set) {
    size_t i = 0;
    const size_t n = line.size();
    const std::unordered_set<std::string_view>& words = keywordSet(set);
    while (i < n) {
        if (inBlock) {
            size_t e = line.find("*/", i);
            if (e == std::string::npos) {
                push(out, i, n, kComment);
                i = n;
            } else {
                push(out, i, e + 2, kComment);
                i = e + 2;
                inBlock = false;
            }
            continue;
        }
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (c == '/' && i + 1 < n && line[i + 1] == '/') {
            push(out, i, n, kComment);
            break;
        }
        if (c == '/' && i + 1 < n && line[i + 1] == '*') {
            inBlock = true;
            push(out, i, i + 2, kComment);
            i += 2;
            continue;
        }
        if (c == '"' || c == '\'') {
            size_t j = i + 1;
            while (j < n && line[j] != static_cast<char>(c)) {
                if (line[j] == '\\') ++j;
                ++j;
            }
            j = std::min(j + 1, n);
            push(out, i, j, kString);
            i = j;
            continue;
        }
        if (std::isdigit(c)) {
            size_t j = i;
            while (j < n && (std::isalnum(static_cast<unsigned char>(line[j])) || line[j] == '.' || line[j] == '_')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && isIdentPart(static_cast<unsigned char>(line[j]))) ++j;
            std::string_view word = line.substr(i, j - i);
            SyntaxToken col = kDefault;
            if (words.count(word)) col = kKeyword;
            else if (std::isupper(c)) col = kType;
            push(out, i, j, col);
            i = j;
            continue;
        }
        push(out, i, i + 1, std::isspace(c) ? kDefault : kPunct);
        ++i;
    }
}

// inBlock means "inside a triple-quoted string". It cannot say which quote
// opened the string, so either closing delimiter ends it.
void SyntaxHighlighter::tokenizePython(std::string_view line, bool& inBlock, std::vector<Span>& out) {
    static const std::unordered_set<std::string_view> keywords = {
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
        "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in",
        "is", "lambda", "match", "case", "nonlocal", "not", "or", "pass", "raise", "return", "try",
        "while", "with", "yield"};
    static const std::unordered_set<std::string_view> builtins = {
        "abs", "all", "any", "bool", "bytes", "chr", "dict", "dir", "enumerate", "filter", "float",
        "format", "getattr", "hasattr", "hex", "int", "isinstance", "iter", "len", "list", "map", "max",
        "min", "next", "open", "ord", "print", "range", "repr", "reversed", "set", "setattr", "sorted",
        "str", "sum", "super", "tuple", "type", "zip", "self", "cls"};
    const auto closeTriple = [&](size_t from) {
        const size_t a = line.find("\"\"\"", from), b = line.find("'''", from);
        return std::min(a, b);
    };
    size_t i = 0;
    const size_t n = line.size();
    bool nameFollows = false;  // the word after def / class
    while (i < n) {
        if (inBlock) {
            const size_t e = closeTriple(i);
            if (e == std::string_view::npos) {
                push(out, i, n, kString);
                return;
            }
            push(out, i, e + 3, kString);
            i = e + 3;
            inBlock = false;
            continue;
        }
        const unsigned char c = static_cast<unsigned char>(line[i]);
        if (c == '#') {
            push(out, i, n, kComment);
            return;
        }
        if (c == '@') {  // decorator
            size_t j = i + 1;
            while (j < n && (isIdentPart(static_cast<unsigned char>(line[j])) || line[j] == '.')) ++j;
            push(out, i, j, j > i + 1 ? kDirective : kPunct);
            i = j;
            continue;
        }
        // A string, with any r / b / f / u prefix counted as part of it.
        size_t quote = i;
        while (quote < n && quote - i < 2 && std::strchr("rRbBfFuU", line[quote]) != nullptr && line[quote] != 0) ++quote;
        if (quote < n && (line[quote] == '"' || line[quote] == '\'')) {
            const char q = line[quote];
            if (line.substr(quote, 3) == std::string_view(q == '"' ? "\"\"\"" : "'''")) {
                const size_t e = closeTriple(quote + 3);
                if (e == std::string_view::npos) {
                    push(out, i, n, kString);
                    inBlock = true;
                    return;
                }
                push(out, i, e + 3, kString);
                i = e + 3;
                continue;
            }
            size_t j = quote + 1;
            while (j < n && line[j] != q) {
                if (line[j] == '\\') ++j;
                ++j;
            }
            j = std::min(j + 1, n);
            push(out, i, j, kString);
            i = j;
            continue;
        }
        if (std::isdigit(c)) {
            size_t j = i;
            while (j < n && (std::isalnum(static_cast<unsigned char>(line[j])) || line[j] == '.' || line[j] == '_')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && isIdentPart(static_cast<unsigned char>(line[j]))) ++j;
            const std::string_view word = line.substr(i, j - i);
            SyntaxToken color = kDefault;
            if (nameFollows) color = kType;
            else if (keywords.count(word)) color = kKeyword;
            else if (builtins.count(word)) color = kAttr;
            else if (std::isupper(c)) color = kType;
            nameFollows = word == "def" || word == "class";
            push(out, i, j, color);
            i = j;
            continue;
        }
        push(out, i, i + 1, std::isspace(c) ? kDefault : kPunct);
        ++i;
    }
}

void SyntaxHighlighter::tokenizeJson(std::string_view line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (std::isspace(c)) {
            push(out, i, i + 1, kDefault);
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            size_t j = i + 1;
            while (j < n && line[j] != static_cast<char>(c)) {
                if (line[j] == '\\') ++j;
                ++j;
            }
            j = std::min(j + 1, n);
            size_t k = j;
            while (k < n && std::isspace(static_cast<unsigned char>(line[k]))) ++k;
            push(out, i, j, k < n && line[k] == ':' ? kAttr : kString);
            i = j;
            continue;
        }
        if (std::isdigit(c) || (c == '-' && i + 1 < n && std::isdigit(static_cast<unsigned char>(line[i + 1])))) {
            size_t j = i + 1;
            while (j < n && (std::isdigit(static_cast<unsigned char>(line[j])) || line[j] == '.' || line[j] == 'e' ||
                             line[j] == 'E' || line[j] == '+' || line[j] == '-'))
                ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && isIdentPart(static_cast<unsigned char>(line[j]))) ++j;
            std::string_view word = line.substr(i, j - i);
            push(out, i, j, word == "true" || word == "false" || word == "null" ? kKeyword : kDefault);
            i = j;
            continue;
        }
        push(out, i, i + 1, kPunct);
        ++i;
    }
}

void SyntaxHighlighter::tokenizeSmali(std::string_view line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (std::isspace(c)) {
            push(out, i, i + 1, kDefault);
            ++i;
            continue;
        }
        if (c == '#') {
            push(out, i, n, kComment);
            break;
        }
        if (c == '"') {
            size_t j = i + 1;
            while (j < n && line[j] != '"') {
                if (line[j] == '\\') ++j;
                ++j;
            }
            j = std::min(j + 1, n);
            push(out, i, j, kString);
            i = j;
            continue;
        }
        if (c == '.') {
            size_t j = i;
            while (j < n && !std::isspace(static_cast<unsigned char>(line[j]))) ++j;
            push(out, i, j, kDirective);
            i = j;
            continue;
        }
        if (c == ':') {
            size_t j = i;
            while (j < n && !std::isspace(static_cast<unsigned char>(line[j]))) ++j;
            push(out, i, j, kAttr);
            i = j;
            continue;
        }
        if (c == 'v' || c == 'p') {
            size_t j = i + 1;
            if (j < n && std::isdigit(static_cast<unsigned char>(line[j]))) {
                while (j < n && std::isdigit(static_cast<unsigned char>(line[j]))) ++j;
                push(out, i, j, kNumber);
                i = j;
                continue;
            }
        }
        if (std::isdigit(c) || c == '-') {
            // smali literals: -42, 0x1F, wide register pairs
            size_t j = i + 1;
            while (j < n && (std::isalnum(static_cast<unsigned char>(line[j])) || line[j] == '-')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && (isIdentPart(static_cast<unsigned char>(line[j])) || line[j] == '/' || line[j] == '-' ||
                             line[j] == '>' || line[j] == ';'))
                ++j;
            push(out, i, j, kDefault);
            i = j;
            continue;
        }
        push(out, i, i + 1, kPunct);
        ++i;
    }
}

void SyntaxHighlighter::tokenizeYaml(std::string_view line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n && (line[i] == ' ' || line[i] == '-')) {
        push(out, i, i + 1, kPunct);
        ++i;
    }
    // A '#' before the key starts a full-line comment.
    if (i < n && line[i] == '#') {
        push(out, i, n, kComment);
        return;
    }
    size_t colon = line.find(':', i);
    size_t comment = line.find('#', i);
    if (comment != std::string::npos && (colon == std::string::npos || comment < colon)) colon = comment;
    if (colon != std::string::npos) {
        push(out, i, colon, kAttr);          // key
        push(out, colon, colon + 1, kPunct); // ':'
        i = colon + 1;
    }
    if (comment != std::string::npos && comment >= i) {
        if (comment > i) push(out, i, comment, kDefault);
        push(out, comment, n, kComment);
        return;
    }
    if (i < n) push(out, i, n, kDefault);
}

void SyntaxHighlighter::tokenizeCss(std::string_view line, bool& inBlock, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (c == '/' && i + 1 < n && line[i + 1] == '*') {
            size_t e = line.find("*/", i + 2);
            if (e == std::string::npos) {
                inBlock = true;
                push(out, i, n, kComment);
                i = n;
            } else {
                push(out, i, e + 2, kComment);
                i = e + 2;
            }
            continue;
        }
        if (inBlock) {
            size_t e = line.find("*/", i);
            if (e == std::string::npos) {
                push(out, i, n, kComment);
                i = n;
            } else {
                push(out, i, e + 2, kComment);
                i = e + 2;
                inBlock = false;
            }
            continue;
        }
        if (c == '"' || c == '\'') {
            size_t j = i + 1;
            while (j < n && line[j] != static_cast<char>(c)) ++j;
            j = std::min(j + 1, n);
            push(out, i, j, kString);
            i = j;
            continue;
        }
        if (c == '{' || c == '}' || c == ';' || c == ':') {
            push(out, i, i + 1, kPunct);
            ++i;
            continue;
        }
        if (c == '#') {  // hex color or id selector
            size_t j = i + 1;
            while (j < n && (std::isxdigit(static_cast<unsigned char>(line[j])) || line[j] == '#' || line[j] == '-')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        size_t j = i;
        while (j < n && line[j] != '{' && line[j] != '}' && line[j] != ';' && line[j] != ':' && line[j] != '#') ++j;
        bool beforeBrace = j < n && line[j] == '{';
        push(out, i, j, beforeBrace ? kKeyword : kAttr);  // selector vs property
        i = j;
    }
}

void SyntaxHighlighter::tokenizeXml(std::string_view line, bool& inBlock, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        if (inBlock) {
            size_t e = line.find("-->", i);
            if (e == std::string::npos) {
                push(out, i, n, kComment);
                i = n;
            } else {
                push(out, i, e + 3, kComment);
                i = e + 3;
                inBlock = false;
            }
            continue;
        }
        if (line.compare(i, 4, "<!--") == 0) {
            inBlock = true;
            push(out, i, i + 4, kComment);
            i += 4;
            continue;
        }
        if (line[i] == '<') {
            push(out, i, i + 1, kPunct);
            ++i;
            if (i < n && (line[i] == '/' || line[i] == '?')) {
                push(out, i, i + 1, kPunct);
                ++i;
            }
            size_t j = i;
            while (j < n && !std::isspace(static_cast<unsigned char>(line[j])) && line[j] != '>' && line[j] != '/') ++j;
            push(out, i, j, kKeyword);
            i = j;
            while (i < n && line[i] != '>') {
                char c = line[i];
                if (c == '"' || c == '\'') {
                    j = i + 1;
                    while (j < n && line[j] != c) ++j;
                    j = std::min(j + 1, n);
                    push(out, i, j, kString);
                    i = j;
                } else if (std::isspace(static_cast<unsigned char>(c)) || c == '=' || c == '/' || c == '?') {
                    push(out, i, i + 1, kPunct);
                    ++i;
                } else {
                    j = i;
                    while (j < n && !std::isspace(static_cast<unsigned char>(line[j])) && line[j] != '=' && line[j] != '>' && line[j] != '/') ++j;
                    push(out, i, j, kAttr);
                    i = j;
                }
            }
            if (i < n) {
                push(out, i, i + 1, kPunct);
                ++i;
            }
            continue;
        }
        size_t j = i;
        while (j < n && line[j] != '<') ++j;
        push(out, i, j, kDefault);
        i = j;
    }
}
