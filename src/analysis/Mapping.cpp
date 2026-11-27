#include "analysis/Mapping.hpp"
#include <cctype>
#include <set>

namespace mapping {

namespace {

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// Reads "<digits>" at the start of `s`; advances.
bool number(std::string_view& s, int& out) {
    size_t n = 0;
    int v = 0;
    while (n < s.size() && std::isdigit(static_cast<unsigned char>(s[n]))) v = v * 10 + (s[n++] - '0');
    if (n == 0) return false;
    out = v;
    s.remove_prefix(n);
    return true;
}

bool parseMember(std::string_view left, std::string_view obf, Class& cls) {
    Member m;
    // Optional "a:b:" obfuscated line range.
    {
        std::string_view t = left;
        int a = 0, b = 0;
        if (number(t, a) && !t.empty() && t[0] == ':') {
            t.remove_prefix(1);
            if (number(t, b) && !t.empty() && t[0] == ':') {
                t.remove_prefix(1);
                m.obfStart = a;
                m.obfEnd = b;
                left = t;
            }
        }
    }
    const size_t paren = left.find('(');
    m.method = paren != std::string_view::npos;
    std::string_view sig = left;
    if (m.method) {
        const size_t close = left.find(')', paren);
        if (close == std::string_view::npos) return false;
        sig = left.substr(0, close + 1);
        std::string_view rest = left.substr(close + 1);
        // Optional ":c" or ":c:d" original line range.
        if (!rest.empty() && rest[0] == ':') {
            rest.remove_prefix(1);
            int c = 0, d = 0;
            if (number(rest, c)) {
                m.origStart = c;
                m.origEnd = c;
                if (!rest.empty() && rest[0] == ':') {
                    rest.remove_prefix(1);
                    if (number(rest, d)) m.origEnd = d;
                }
            }
        }
    }
    const size_t space = sig.find(' ');
    if (space == std::string_view::npos) return false;
    const std::string_view nameAndArgs = trim(sig.substr(space + 1));
    m.original = std::string(m.method ? nameAndArgs.substr(0, nameAndArgs.find('(')) : nameAndArgs);
    m.signature = std::string(sig);
    if (m.original.empty() || obf.empty()) return false;
    cls.members.emplace(std::string(obf), std::move(m));
    return true;
}

bool isNameChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '.'; }

std::string outerSimpleName(const std::string& cls) {
    std::string s = cls.substr(cls.find_last_of('.') + 1);
    return s.substr(0, s.find('$'));
}

}  // namespace

Mapping parse(std::string_view text) {
    Mapping m;
    Class* current = nullptr;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        if (e == std::string_view::npos) e = text.size();
        const std::string_view raw = text.substr(pos, e - pos);
        pos = e + 1;
        const std::string_view line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        const size_t arrow = line.find(" -> ");
        if (arrow == std::string_view::npos) {
            ++m.errors;
            continue;
        }
        const bool member = raw[0] == ' ' || raw[0] == '\t';
        const std::string_view left = trim(line.substr(0, arrow));
        std::string_view right = trim(line.substr(arrow + 4));
        if (!member) {
            if (right.empty() || right.back() != ':') {
                ++m.errors;
                current = nullptr;
                continue;
            }
            right.remove_suffix(1);
            Class c;
            c.original = std::string(left);
            c.obfuscated = std::string(right);
            m.originalToObfuscated[c.original] = c.obfuscated;
            current = &(m.byObfuscated[c.obfuscated] = std::move(c));
        } else if (!current || !parseMember(left, right, *current)) {
            ++m.errors;
        }
    }
    return m;
}

std::string Mapping::originalClass(std::string_view obf) const {
    const auto it = byObfuscated.find(std::string(obf));
    if (it != byObfuscated.end()) return it->second.original;
    // Inner class of a mapped outer class: "a.b$c" with only "a.b" mapped.
    const size_t dollar = obf.find('$');
    if (dollar != std::string_view::npos) {
        const auto outer = byObfuscated.find(std::string(obf.substr(0, dollar)));
        if (outer != byObfuscated.end()) return outer->second.original + std::string(obf.substr(dollar));
    }
    return std::string(obf);
}

std::string Mapping::originalMethod(std::string_view obfClass, std::string_view obf, int line) const {
    const auto it = byObfuscated.find(std::string(obfClass));
    if (it == byObfuscated.end()) return std::string(obf);
    const auto [b, e] = it->second.members.equal_range(std::string(obf));
    std::vector<std::string> names;
    std::set<std::string> seen;
    bool ranged = false;
    for (auto i = b; i != e; ++i)
        if (i->second.method && line > 0 && i->second.obfStart > 0 && line >= i->second.obfStart && line <= i->second.obfEnd) ranged = true;
    for (auto i = b; i != e; ++i) {
        const Member& mb = i->second;
        if (!mb.method) continue;
        if (ranged && !(line >= mb.obfStart && line <= mb.obfEnd)) continue;
        if (seen.insert(mb.original).second) names.push_back(mb.original);
    }
    if (names.empty()) return std::string(obf);
    std::string out = names[0];
    for (size_t i = 1; i < names.size(); ++i) out += "|" + names[i];
    return out;
}

std::string Mapping::originalMember(std::string_view javaClass, const std::string& obf, const std::string& signature, bool method) const {
    const auto found = byObfuscated.find(std::string(javaClass));
    if (found == byObfuscated.end()) return {};
    const auto [begin, end] = found->second.members.equal_range(obf);
    for (auto it = begin; it != end; ++it) {
        const Member& m = it->second;
        if (m.method != method || m.original.find('.') != std::string::npos) continue;  // inlined from elsewhere
        if (method ? m.signature.size() >= signature.size() &&
                         m.signature.compare(m.signature.size() - signature.size(), signature.size(), signature) == 0
                   : m.signature.rfind(signature, 0) == 0)
            return m.original;
    }
    return {};
}

int Mapping::originalLine(std::string_view obfClass, std::string_view obf, int line) const {
    const auto it = byObfuscated.find(std::string(obfClass));
    if (it == byObfuscated.end() || line <= 0) return line;
    const auto [b, e] = it->second.members.equal_range(std::string(obf));
    for (auto i = b; i != e; ++i) {
        const Member& mb = i->second;
        if (!mb.method || mb.obfStart <= 0 || line < mb.obfStart || line > mb.obfEnd) continue;
        if (mb.origStart <= 0) return line;
        if (mb.origEnd - mb.origStart == mb.obfEnd - mb.obfStart) return mb.origStart + (line - mb.obfStart);
        return mb.origStart;
    }
    return line;
}

std::string retrace(const Mapping& m, std::string_view trace) {
    std::string out;
    size_t pos = 0;
    while (pos < trace.size()) {
        size_t e = trace.find('\n', pos);
        const bool hasNl = e != std::string_view::npos;
        if (!hasNl) e = trace.size();
        const std::string_view line = trace.substr(pos, e - pos);
        pos = e + 1;

        const size_t at = line.find("at ");
        const size_t open = line.find('(', at == std::string_view::npos ? 0 : at);
        const size_t close = line.find(')', open == std::string_view::npos ? 0 : open);
        bool done = false;
        if (at != std::string_view::npos && open != std::string_view::npos && close != std::string_view::npos &&
            line.substr(0, at).find_first_not_of(" \t") == std::string_view::npos) {
            const std::string_view frame = line.substr(at + 3, open - at - 3);
            const size_t dot = frame.find_last_of('.');
            if (dot != std::string_view::npos) {
                const std::string obfCls(frame.substr(0, dot));
                const std::string obfMethod(frame.substr(dot + 1));
                std::string_view src = line.substr(open + 1, close - open - 1);
                int lineNo = 0;
                const size_t colon = src.find_last_of(':');
                if (colon != std::string_view::npos) {
                    std::string_view n = src.substr(colon + 1);
                    if (!number(n, lineNo)) lineNo = 0;
                }
                const std::string cls = m.originalClass(obfCls);
                const std::string method = m.originalMethod(obfCls, obfMethod, lineNo);
                const int origLine = m.originalLine(obfCls, obfMethod, lineNo);
                std::string file(colon != std::string_view::npos ? src.substr(0, colon) : src);
                if (file == "SourceFile" || file == "Unknown Source" || file.empty())
                    file = cls != obfCls ? outerSimpleName(cls) + ".java" : file;
                out += line.substr(0, at + 3);
                out += cls + "." + method + "(" + file;
                if (lineNo > 0) out += ":" + std::to_string(origLine);
                out += ")";
                out += line.substr(close + 1);
                done = true;
            }
        }
        if (!done) {
            // Replace dotted class-name tokens ("Caused by: a.b.c: message").
            size_t i = 0;
            while (i < line.size()) {
                if (!isNameChar(line[i])) {
                    out += line[i++];
                    continue;
                }
                size_t j = i;
                while (j < line.size() && isNameChar(line[j])) ++j;
                std::string_view tok = line.substr(i, j - i);
                while (!tok.empty() && tok.back() == '.') tok.remove_suffix(1);
                const std::string mapped = tok.find('.') != std::string_view::npos ? m.originalClass(tok) : std::string(tok);
                out += mapped;
                out += line.substr(i + tok.size(), j - i - tok.size());
                i = j;
            }
        }
        if (hasNl) out += '\n';
    }
    return out;
}

}  // namespace mapping
