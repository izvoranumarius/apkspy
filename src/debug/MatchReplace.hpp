#pragma once
#include <memory>
#include <regex>
#include <string>
#include <vector>

// Match & replace rules for the traffic proxy (as in Burp): every plain-HTTP
// request and response that passes through is rewritten by the enabled rules.
//
//  - First line / header rules work line by line: a header rule with an empty
//    match adds its replacement as a new header; one with an empty replacement
//    removes the matching header lines.
//  - Body rules work on the decoded body: chunked framing and gzip / deflate are
//    undone first when a rule matches, and Content-Length is set to the result.
//  - Literal rules replace every occurrence; regex rules use ECMAScript syntax
//    and $1-style groups in the replacement.
namespace matchreplace {

enum class Where { RequestLine, RequestHeader, RequestBody, ResponseLine, ResponseHeader, ResponseBody };
const char* whereName(Where w);
constexpr int kWhereCount = 6;

struct Rule {
    bool enabled = true;
    Where where = Where::RequestHeader;
    std::string match;
    std::string replace;
    bool regex = false;
    std::string comment;
};

// Rules made ready to apply (regexes compiled once).
class RuleSet {
public:
    RuleSet() = default;
    explicit RuleSet(std::vector<Rule> rules);
    const std::vector<Rule>& rules() const { return rules_; }
    // Why rule `i` cannot be used ("" when it can): a regex that does not compile.
    const std::string& error(size_t i) const { return errors_[i]; }
    bool appliesTo(bool response) const;  // any enabled, valid rule for requests / responses
    // Rewrites a raw message (start line, CRLF headers, blank line, body). Returns
    // how many replacements were made; `hits[i]` counts those of rule i.
    int apply(bool response, std::string& raw, std::vector<int>* hits = nullptr) const;

private:
    std::vector<Rule> rules_;
    std::vector<std::shared_ptr<std::regex>> compiled_;
    std::vector<std::string> errors_;
};

// Saved form (a JSON array) for the settings file.
std::string toJson(const std::vector<Rule>& rules);
std::vector<Rule> fromJson(const std::string& text);
// Common rules to start from, as in Burp's defaults (all disabled).
std::vector<Rule> presets();

}  // namespace matchreplace
