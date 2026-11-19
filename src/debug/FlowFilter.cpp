#include "debug/FlowFilter.hpp"
#include <cctype>
#include <cstdlib>
#include <regex>
#include <vector>
#include "core/TextUtils.hpp"

namespace flowfilter {

namespace {

constexpr size_t kMaxSearch = 4u << 20;  // body text searched per message

const Help kHelp[] = {
    {"~u regex", "URL"},
    {"~d regex", "domain (host or TLS server name)"},
    {"~m regex", "method"},
    {"~c code", "response status code"},
    {"~t regex", "content type (request or response)"},
    {"~tq / ~ts regex", "request / response content type"},
    {"~h regex", "header line \"Name: value\" (request or response)"},
    {"~hq / ~hs regex", "request / response header"},
    {"~b regex", "body (request or response, decoded)"},
    {"~bq / ~bs regex", "request / response body"},
    {"~q", "request without a response yet"},
    {"~s", "has a response"},
    {"~e", "error (failed flow, refused TLS)"},
    {"~a", "static asset (script, style, image, font)"},
    {"~http", "HTTP flow (not a tunnel)"},
    {"~tcp", "tunnel or raw TCP stream"},
    {"~udp / ~dns", "UDP datagrams / DNS (SOCKS5 UDP)"},
    {"~websocket", "WebSocket connection"},
    {"~modified", "changed by match & replace, a script or the intercept"},
    {"~marked", "highlighted or commented"},
    {"~comment regex", "comment text"},
    {"~all", "every flow"},
    {"!  &  |  ( )", "not, and (or a space), or, grouping"},
    {"word", "a bare word matches the URL"},
};

bool isAssetPath(const std::string& path) {
    const std::string p = tex::asciiLower(path.substr(0, path.find('?')));
    static const char* kExt[] = {".js",  ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
                                 ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm", ".mp3"};
    for (const char* e : kExt) {
        const size_t n = std::char_traits<char>::length(e);
        if (p.size() >= n && p.compare(p.size() - n, n, e) == 0) return true;
    }
    return false;
}

}  // namespace

struct Filter::Node {
    enum class Op { And, Or, Not, Leaf } op = Op::Leaf;
    std::unique_ptr<Node> a, b;
    std::string kind;     // "u", "d", "bq", ... for leaves
    std::string value;    // as typed
    bool plain = true;    // no regex metacharacters: substring search
    std::regex re;
    int code = 0;

    bool test(const std::string& hay) const {
        if (plain) return tex::ciFind(hay, value) != std::string_view::npos;
        try {
            return std::regex_search(hay, re);
        } catch (const std::exception&) {
            return false;  // (MSVC's regex can give up on huge inputs)
        }
    }
};

namespace {

using Node = Filter::Node;

struct Lexer {
    const std::string& s;
    size_t pos = 0;
    std::string error;

    void skip() {
        while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) ++pos;
    }
    bool atEnd() {
        skip();
        return pos >= s.size();
    }
    char peek() {
        skip();
        return pos < s.size() ? s[pos] : '\0';
    }
    // A value: quoted (with \" escapes) or a run up to whitespace / ( ) / operator.
    bool value(std::string& out) {
        skip();
        out.clear();
        if (pos >= s.size()) return false;
        const char q = s[pos];
        if (q == '"' || q == '\'') {
            ++pos;
            while (pos < s.size() && s[pos] != q) {
                if (s[pos] == '\\' && pos + 1 < s.size() && s[pos + 1] == q) ++pos;
                out += s[pos++];
            }
            if (pos >= s.size()) return error = "unterminated quote", false;
            ++pos;
            return true;
        }
        while (pos < s.size() && !std::isspace(static_cast<unsigned char>(s[pos])) && s[pos] != '(' && s[pos] != ')' &&
               s[pos] != '&' && s[pos] != '|')
            out += s[pos++];
        return !out.empty();
    }
};

struct FilterSpec {
    const char* name;
    bool takesValue;
    bool content;  // needs headers / bodies a summary row lacks
};
const FilterSpec kSpecs[] = {
    {"u", true, false},   {"d", true, false},  {"m", true, false},   {"c", true, false},
    {"t", true, true},    {"tq", true, true},  {"ts", true, false},  {"h", true, true},
    {"hq", true, true},   {"hs", true, false}, {"b", true, true},    {"bq", true, true},
    {"bs", true, true},   {"q", false, false}, {"s", false, false},  {"e", false, false},
    {"a", false, false},  {"http", false, false}, {"tcp", false, false}, {"websocket", false, false},
    {"udp", false, false}, {"dns", false, false},
    {"modified", false, false}, {"marked", false, false}, {"comment", true, false}, {"all", false, false},
};

class Parser {
public:
    explicit Parser(const std::string& s) : lx_{s} {}
    std::unique_ptr<Node> parseAll(bool& content, std::string& error) {
        auto n = orExpr();
        if (n && !lx_.atEnd()) {
            lx_.error = std::string("unexpected '") + lx_.peek() + "'";
            n.reset();
        }
        if (!n && lx_.error.empty()) lx_.error = "empty expression";
        error = lx_.error;
        content = content_;
        return n;
    }

private:
    std::unique_ptr<Node> orExpr() {
        auto left = andExpr();
        while (left && lx_.peek() == '|') {
            ++lx_.pos;
            auto right = andExpr();
            if (!right) return fail("expected a filter after '|'");
            left = binary(Node::Op::Or, std::move(left), std::move(right));
        }
        return left;
    }
    std::unique_ptr<Node> andExpr() {
        auto left = unary();
        for (;;) {
            if (!left) return nullptr;
            const char c = lx_.peek();
            if (c == '&') {
                ++lx_.pos;
                auto right = unary();
                if (!right) return fail("expected a filter after '&'");
                left = binary(Node::Op::And, std::move(left), std::move(right));
            } else if (c != '\0' && c != '|' && c != ')') {
                auto right = unary();  // juxtaposition = and
                if (!right) return nullptr;
                left = binary(Node::Op::And, std::move(left), std::move(right));
            } else
                return left;
        }
    }
    std::unique_ptr<Node> unary() {
        const char c = lx_.peek();
        if (c == '!') {
            ++lx_.pos;
            auto inner = unary();
            if (!inner) return fail("expected a filter after '!'");
            auto n = std::make_unique<Node>();
            n->op = Node::Op::Not;
            n->a = std::move(inner);
            return n;
        }
        if (c == '(') {
            ++lx_.pos;
            auto inner = orExpr();
            if (!inner) return nullptr;
            if (lx_.peek() != ')') return fail("missing ')'");
            ++lx_.pos;
            return inner;
        }
        if (c == '~') {
            ++lx_.pos;
            std::string name;
            while (lx_.pos < lx_.s.size() && std::isalpha(static_cast<unsigned char>(lx_.s[lx_.pos]))) name += lx_.s[lx_.pos++];
            const FilterSpec* spec = nullptr;
            for (const auto& sp : kSpecs)
                if (name == sp.name) spec = &sp;
            if (!spec) return fail("unknown filter ~" + name);
            auto n = std::make_unique<Node>();
            n->kind = name;
            content_ |= spec->content;
            if (spec->takesValue) {
                if (!lx_.value(n->value)) return fail(lx_.error.empty() ? "~" + name + " needs a value" : lx_.error);
                if (!compile(*n)) return nullptr;
            }
            return n;
        }
        if (c == '\0' || c == ')' || c == '&' || c == '|') return nullptr;
        auto n = std::make_unique<Node>();  // a bare word: ~u
        n->kind = "u";
        if (!lx_.value(n->value)) return fail(lx_.error.empty() ? "expected a filter" : lx_.error);
        if (!compile(*n)) return nullptr;
        return n;
    }
    bool compile(Node& n) {
        if (n.kind == "c") {
            char* end = nullptr;
            n.code = static_cast<int>(std::strtol(n.value.c_str(), &end, 10));
            if (!end || *end) return fail("~c needs a status code"), false;
            return true;
        }
        n.plain = n.value.find_first_of("\\^$.|?*+()[]{}") == std::string::npos;
        if (!n.plain) {
            try {
                n.re = std::regex(n.value, std::regex::ECMAScript | std::regex::icase);
            } catch (const std::regex_error&) {
                return fail("invalid regex: " + n.value), false;
            }
        }
        return true;
    }
    static std::unique_ptr<Node> binary(Node::Op op, std::unique_ptr<Node> a, std::unique_ptr<Node> b) {
        auto n = std::make_unique<Node>();
        n->op = op;
        n->a = std::move(a);
        n->b = std::move(b);
        return n;
    }
    std::unique_ptr<Node> fail(const std::string& why) {
        if (lx_.error.empty()) lx_.error = why;
        return nullptr;
    }

    Lexer lx_;
    bool content_ = false;
};

bool headerMatch(const Node& n, const TrafficProxy::Message& m) {
    for (const auto& [name, value] : m.headers)
        if (n.test(name + ": " + value)) return true;
    return false;
}

bool bodyMatch(const Node& n, const TrafficProxy::Message& m) {
    if (m.body.empty()) return false;
    std::string body = TrafficProxy::decodeBody(m, nullptr);
    if (body.size() > kMaxSearch) body.resize(kMaxSearch);
    return n.test(body);
}

bool eval(const Node& n, const TrafficProxy::Flow& f, const Context* ctx) {
    switch (n.op) {
        case Node::Op::And: return eval(*n.a, f, ctx) && eval(*n.b, f, ctx);
        case Node::Op::Or: return eval(*n.a, f, ctx) || eval(*n.b, f, ctx);
        case Node::Op::Not: return !eval(*n.a, f, ctx);
        case Node::Op::Leaf: break;
    }
    const std::string& k = n.kind;
    if (k == "all") return true;
    if (k == "u") return n.test(f.url());
    if (k == "d") return n.test(f.host) || (!f.sni.empty() && n.test(f.sni));
    if (k == "m") return n.test(f.method);
    if (k == "c") return f.status == n.code;
    if (k == "q") return f.status == 0 && !f.tunnel;
    if (k == "s") return f.status != 0;
    if (k == "e") return !f.error.empty() || !f.tlsError.empty();
    if (k == "http") return !f.tunnel && f.transport.empty();
    if (k == "tcp") return f.tunnel || f.transport == "tcp";
    if (k == "udp") return f.transport == "udp";
    if (k == "dns") return f.method == "DNS" || (f.transport == "udp" && f.port == 53);
    if (k == "websocket") return f.websocket;
    if (k == "modified") return f.edited;
    if (k == "marked") return ctx && ctx->marked && ctx->marked(f.id);
    if (k == "comment") return ctx && ctx->comment && n.test(ctx->comment(f.id));
    if (k == "a") {
        const std::string ct = tex::asciiLower(f.response.header("content-type"));
        return isAssetPath(f.path) || ct.find("javascript") != std::string::npos || ct.find("text/css") != std::string::npos ||
               ct.rfind("image/", 0) == 0 || ct.rfind("font/", 0) == 0 || ct.find("font-") != std::string::npos;
    }
    if (k == "t") return n.test(f.request.header("content-type")) || n.test(f.response.header("content-type"));
    if (k == "tq") return n.test(f.request.header("content-type"));
    if (k == "ts") return n.test(f.response.header("content-type"));
    if (k == "h") return headerMatch(n, f.request) || headerMatch(n, f.response);
    if (k == "hq") return headerMatch(n, f.request);
    if (k == "hs") return headerMatch(n, f.response);
    if (k == "b") return bodyMatch(n, f.request) || bodyMatch(n, f.response);
    if (k == "bq") return bodyMatch(n, f.request);
    if (k == "bs") return bodyMatch(n, f.response);
    return false;
}

}  // namespace

Filter::~Filter() = default;

std::shared_ptr<const Filter> Filter::parse(const std::string& expr, std::string& error) {
    Parser p(expr);
    bool content = false;
    std::unique_ptr<Node> root = p.parseAll(content, error);
    if (!root) return nullptr;
    std::shared_ptr<Filter> f(new Filter());
    f->root_ = std::move(root);
    f->needsContent_ = content;
    f->text_ = expr;
    return f;
}

bool Filter::match(const TrafficProxy::Flow& f, const Context* ctx) const { return root_ && eval(*root_, f, ctx); }

bool looksLikeExpression(const std::string& text) {
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '~') continue;
        if (i + 1 < text.size() && std::isalpha(static_cast<unsigned char>(text[i + 1])) &&
            (i == 0 || std::isspace(static_cast<unsigned char>(text[i - 1])) || text[i - 1] == '!' || text[i - 1] == '(' ||
             text[i - 1] == '&' || text[i - 1] == '|'))
            return true;
    }
    return false;
}

const Help* helpItems(size_t& count) {
    count = sizeof kHelp / sizeof kHelp[0];
    return kHelp;
}

}  // namespace flowfilter
