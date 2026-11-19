#pragma once
#include <functional>
#include <memory>
#include <string>
#include "debug/TrafficProxy.hpp"

// Filter expressions for captured flows, in mitmproxy's syntax:
//
//   ~d api.example.com & ~m POST        host and method
//   ~c 500 | ~e                         server errors or failed flows
//   !~a & ~t json                       JSON that is not a static asset
//   ~b "access_token" & !~websocket     a body containing the text
//   login                               a bare word matches the URL (~u)
//
// Operators: `!` not, `&` and (also implied between two terms), `|` or, and
// parentheses. Values are regular expressions (ECMAScript, case-insensitive)
// and may be quoted; a value without regex metacharacters is a plain
// case-insensitive substring search.
//
// Some filters look inside headers or bodies (needsContent()); the summary
// rows of TrafficProxy::flows() do not carry those, so such a filter must be
// evaluated against full flows (TrafficProxy::selectFlows).
namespace flowfilter {

// What only the UI knows about a flow (highlights and comments).
struct Context {
    std::function<bool(uint64_t)> marked;
    std::function<std::string(uint64_t)> comment;
};

class Filter {
public:
    struct Node;
    // Null (with `error`) when the expression does not parse.
    static std::shared_ptr<const Filter> parse(const std::string& expr, std::string& error);
    bool match(const TrafficProxy::Flow& f, const Context* ctx = nullptr) const;
    bool needsContent() const { return needsContent_; }
    const std::string& text() const { return text_; }
    ~Filter();
    Filter(const Filter&) = delete;
    Filter& operator=(const Filter&) = delete;

private:
    Filter() = default;
    std::unique_ptr<Node> root_;
    bool needsContent_ = false;
    std::string text_;
};

// True when `text` is meant as an expression (uses a ~filter or an operator
// before one) rather than a plain search string.
bool looksLikeExpression(const std::string& text);

// One line per filter, for the UI's help popup.
struct Help {
    const char* syntax;
    const char* meaning;
};
const Help* helpItems(size_t& count);

}  // namespace flowfilter
