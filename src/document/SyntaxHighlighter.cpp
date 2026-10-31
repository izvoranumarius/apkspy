#include "document/SyntaxHighlighter.hpp"
#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace {
const ImU32 kDefault = IM_COL32(220, 220, 220, 255);
const ImU32 kKeyword = IM_COL32(86, 156, 214, 255);
const ImU32 kString = IM_COL32(214, 157, 133, 255);
const ImU32 kComment = IM_COL32(87, 166, 74, 255);
const ImU32 kNumber = IM_COL32(181, 206, 168, 255);
const ImU32 kType = IM_COL32(78, 201, 176, 255);
const ImU32 kPunct = IM_COL32(180, 180, 180, 255);
const ImU32 kAttr = IM_COL32(156, 220, 254, 255);
const ImU32 kDirective = IM_COL32(197, 134, 192, 255);

enum KeywordSet { KwJava, KwKotlin, KwGroovy, KwJs };

const std::unordered_set<std::string>& keywordSet(int set) {
    static const std::unordered_set<std::string> java = {
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
        "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
        "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native",
        "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp",
        "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void",
        "volatile", "while", "true", "false", "null", "var", "record", "sealed", "permits", "yield"};
    static const std::unordered_set<std::string> kotlin = {
        "package", "import", "class", "object", "interface", "fun", "val", "var", "if", "else", "when",
        "for", "while", "do", "return", "try", "catch", "finally", "throw", "throws", "null", "true",
        "false", "this", "super", "is", "in", "as", "open", "override", "abstract", "final", "sealed",
        "data", "enum", "companion", "lateinit", "lazy", "by", "suspend", "internal", "public", "private",
        "protected", "inline", "reified", "crossinline", "noinline", "operator", "infix", "typealias",
        "init", "constructor", "field", "get", "set", "where", "out", "vararg", "dynamic", "const",
        "external", "infix", "tailrec", "expect", "actual"};
    static const std::unordered_set<std::string> groovy = {
        "def", "package", "import", "class", "interface", "trait", "enum", "if", "else", "for", "while",
        "switch", "case", "break", "continue", "return", "try", "catch", "finally", "throw", "throws",
        "new", "this", "super", "null", "true", "false", "extends", "implements", "static", "final",
        "abstract", "public", "private", "protected", "synchronized", "volatile", "transient", "native",
        "assert", "in", "as", "it", "use", "with", "closure"};
    static const std::unordered_set<std::string> js = {
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

void push(std::vector<Span>& out, size_t b, size_t e, ImU32 c) {
    if (e <= b) return;
    if (!out.empty() && out.back().color == c && out.back().end == b)
        out.back().end = e;
    else
        out.push_back({b, e, c});
}

bool isIdentStart(unsigned char c) { return std::isalpha(c) || c == '_' || c == '$'; }
bool isIdentPart(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$'; }
}

void SyntaxHighlighter::tokenize(const std::string& line, Language lang, bool& inBlock, std::vector<Span>& out) {
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
    default: push(out, 0, line.size(), kDefault); break;
    }
}

// Shared tokenizer for Java, Kotlin, Groovy and JavaScript.
void SyntaxHighlighter::tokenizeCLike(const std::string& line, bool& inBlock, std::vector<Span>& out, int set) {
    size_t i = 0;
    const size_t n = line.size();
    const std::unordered_set<std::string>& words = keywordSet(set);
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
        unsigned char c = (unsigned char)line[i];
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
            while (j < n && line[j] != (char)c) {
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
            while (j < n && (std::isalnum((unsigned char)line[j]) || line[j] == '.' || line[j] == '_')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && isIdentPart((unsigned char)line[j])) ++j;
            std::string word = line.substr(i, j - i);
            ImU32 col = kDefault;
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

void SyntaxHighlighter::tokenizeJson(const std::string& line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = (unsigned char)line[i];
        if (std::isspace(c)) {
            push(out, i, i + 1, kDefault);
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            size_t j = i + 1;
            while (j < n && line[j] != (char)c) {
                if (line[j] == '\\') ++j;
                ++j;
            }
            j = std::min(j + 1, n);
            size_t k = j;
            while (k < n && std::isspace((unsigned char)line[k])) ++k;
            push(out, i, j, k < n && line[k] == ':' ? kAttr : kString);
            i = j;
            continue;
        }
        if (std::isdigit(c) || (c == '-' && i + 1 < n && std::isdigit((unsigned char)line[i + 1]))) {
            size_t j = i + 1;
            while (j < n && (std::isdigit((unsigned char)line[j]) || line[j] == '.' || line[j] == 'e' ||
                             line[j] == 'E' || line[j] == '+' || line[j] == '-'))
                ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && isIdentPart((unsigned char)line[j])) ++j;
            std::string word = line.substr(i, j - i);
            push(out, i, j, word == "true" || word == "false" || word == "null" ? kKeyword : kDefault);
            i = j;
            continue;
        }
        push(out, i, i + 1, kPunct);
        ++i;
    }
}

void SyntaxHighlighter::tokenizeSmali(const std::string& line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = (unsigned char)line[i];
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
            while (j < n && !std::isspace((unsigned char)line[j])) ++j;
            push(out, i, j, kDirective);
            i = j;
            continue;
        }
        if (c == ':') {
            size_t j = i;
            while (j < n && !std::isspace((unsigned char)line[j])) ++j;
            push(out, i, j, kAttr);
            i = j;
            continue;
        }
        if (c == 'v' || c == 'p') {
            size_t j = i + 1;
            if (j < n && std::isdigit((unsigned char)line[j])) {
                while (j < n && std::isdigit((unsigned char)line[j])) ++j;
                push(out, i, j, kNumber);
                i = j;
                continue;
            }
        }
        if (std::isdigit(c) || c == '-') {
            size_t j = i + 1;
            while (j < n && (std::isdigit((unsigned char)line[j]) || line[j] == 'x' ||
                             (std::isxdigit((unsigned char)line[j]) && line[j - 1] == 'x' && false) ||
                             std::isalnum((unsigned char)line[j])))
                ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        if (isIdentStart(c)) {
            size_t j = i;
            while (j < n && (isIdentPart((unsigned char)line[j]) || line[j] == '/' || line[j] == '-' ||
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

void SyntaxHighlighter::tokenizeYaml(const std::string& line, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n && (line[i] == ' ' || line[i] == '-')) {
        push(out, i, i + 1, kPunct);
        ++i;
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

void SyntaxHighlighter::tokenizeCss(const std::string& line, bool& inBlock, std::vector<Span>& out) {
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        unsigned char c = (unsigned char)line[i];
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
            while (j < n && line[j] != (char)c) ++j;
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
            while (j < n && (std::isxdigit((unsigned char)line[j]) || line[j] == '#' || line[j] == '-')) ++j;
            push(out, i, j, kNumber);
            i = j;
            continue;
        }
        size_t j = i;
        while (j < n && line[j] != '{' && line[j] != '}' && line[j] != ';' && line[j] != ':' && line[j] != '#') ++j;
        size_t end = j;
        while (end > i && std::isspace((unsigned char)line[end - 1])) --end;
        bool beforeBrace = j < n && line[j] == '{';
        push(out, i, j, beforeBrace ? kKeyword : kAttr);  // selector vs property
        i = j;
    }
}

void SyntaxHighlighter::tokenizeXml(const std::string& line, bool& inBlock, std::vector<Span>& out) {
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
            while (j < n && !std::isspace((unsigned char)line[j]) && line[j] != '>' && line[j] != '/') ++j;
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
                } else if (std::isspace((unsigned char)c) || c == '=' || c == '/' || c == '?') {
                    push(out, i, i + 1, kPunct);
                    ++i;
                } else {
                    j = i;
                    while (j < n && !std::isspace((unsigned char)line[j]) && line[j] != '=' && line[j] != '>' && line[j] != '/') ++j;
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
