#include "debug/MatchReplace.hpp"
#include "core/TextUtils.hpp"
#include "debug/TrafficProxy.hpp"
#include "mcp/Json.hpp"

namespace matchreplace {

namespace {

bool isRequest(Where w) { return w == Where::RequestLine || w == Where::RequestHeader || w == Where::RequestBody; }

// Replaces every match in `s`; returns how many there were.
int replaceIn(std::string& s, const Rule& r, const std::regex* re) {
    if (r.match.empty()) return 0;
    if (re) {
        int n = 0;
        for (auto it = std::sregex_iterator(s.begin(), s.end(), *re); it != std::sregex_iterator(); ++it) ++n;
        if (n) s = std::regex_replace(s, *re, r.replace);
        return n;
    }
    int n = 0;
    for (size_t pos = s.find(r.match); pos != std::string::npos; pos = s.find(r.match, pos + r.replace.size())) {
        s.replace(pos, r.match.size(), r.replace);
        ++n;
    }
    return n;
}

bool matches(const std::string& s, const Rule& r, const std::regex* re) {
    return re ? std::regex_search(s, *re) : s.find(r.match) != std::string::npos;
}

std::string headerName(const std::string& line) { return tex::asciiLower(line.substr(0, line.find(':'))); }

}  // namespace

const char* whereName(Where w) {
    switch (w) {
    case Where::RequestLine: return "Request first line";
    case Where::RequestHeader: return "Request header";
    case Where::RequestBody: return "Request body";
    case Where::ResponseLine: return "Response first line";
    case Where::ResponseHeader: return "Response header";
    case Where::ResponseBody: return "Response body";
    }
    return "?";
}

RuleSet::RuleSet(std::vector<Rule> rules) : rules_(std::move(rules)) {
    for (const Rule& r : rules_) {
        std::shared_ptr<std::regex> re;
        std::string error;
        if (r.regex && !r.match.empty()) {
            try {
                re = std::make_shared<std::regex>(r.match, std::regex::ECMAScript);
            } catch (const std::regex_error& e) {
                error = std::string("invalid regex: ") + e.what();
            }
        }
        compiled_.push_back(std::move(re));
        errors_.push_back(std::move(error));
    }
}

bool RuleSet::appliesTo(bool response) const {
    for (size_t i = 0; i < rules_.size(); ++i)
        if (rules_[i].enabled && errors_[i].empty() && isRequest(rules_[i].where) != response) return true;
    return false;
}

int RuleSet::apply(bool response, std::string& raw, std::vector<int>* hits) const {
    if (!appliesTo(response)) return 0;
    if (hits) hits->resize(rules_.size(), 0);
    const size_t headEnd = raw.find("\r\n\r\n");
    const std::string head = headEnd == std::string::npos ? raw : raw.substr(0, headEnd);
    std::string body = headEnd == std::string::npos ? std::string() : raw.substr(headEnd + 4);
    std::vector<std::string> lines;
    for (size_t pos = 0; pos <= head.size();) {
        size_t e = head.find("\r\n", pos);
        if (e == std::string::npos) e = head.size();
        lines.push_back(head.substr(pos, e - pos));
        pos = e + 2;
    }
    if (lines.empty()) return 0;
    int total = 0;
    bool bodyDecoded = false, bodyChanged = false;
    for (size_t i = 0; i < rules_.size(); ++i) {
        const Rule& r = rules_[i];
        if (!r.enabled || !errors_[i].empty() || isRequest(r.where) == response) continue;
        const std::regex* re = compiled_[i].get();
        int n = 0;
        switch (r.where) {
        case Where::RequestLine:
        case Where::ResponseLine: n = replaceIn(lines[0], r, re); break;
        case Where::RequestHeader:
        case Where::ResponseHeader:
            if (r.match.empty()) {  // add a header
                if (!r.replace.empty()) lines.push_back(r.replace), n = 1;
                break;
            }
            for (size_t k = 1; k < lines.size();) {
                if (!matches(lines[k], r, re)) {
                    ++k;
                    continue;
                }
                ++n;
                if (r.replace.empty() && !re) {  // literal match, empty replacement: remove the header
                    lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(k));
                    continue;
                }
                std::string line = lines[k];
                replaceIn(line, r, re);
                if (line.empty()) {  // a regex that consumed the whole line: remove it
                    lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(k));
                    continue;
                }
                lines[k] = line;
                ++k;
            }
            break;
        case Where::RequestBody:
        case Where::ResponseBody: {
            if (r.match.empty()) break;
            if (!bodyDecoded) {
                // Undo chunked framing and compression so the rule sees the real body.
                TrafficProxy::Message m;
                for (size_t k = 1; k < lines.size(); ++k) {
                    const size_t colon = lines[k].find(':');
                    if (colon == std::string::npos) continue;
                    std::string value = lines[k].substr(colon + 1);
                    while (!value.empty() && value.front() == ' ') value.erase(value.begin());
                    m.headers.emplace_back(lines[k].substr(0, colon), value);
                }
                m.body = body;
                std::string decoded = TrafficProxy::decodeBody(m, nullptr);
                std::string probe = decoded;
                if (replaceIn(probe, r, re) == 0) break;  // nothing to change: keep the original bytes
                body = std::move(decoded);
                bodyDecoded = true;
            }
            n = replaceIn(body, r, re);
            bodyChanged = bodyChanged || n > 0;
            break;
        }
        }
        if (hits) (*hits)[i] += n;
        total += n;
    }
    if (total == 0) return 0;
    if (bodyChanged) {
        // The body is now plain: no chunking, no compression, its real length.
        for (size_t k = 1; k < lines.size();) {
            const std::string name = headerName(lines[k]);
            if (name == "transfer-encoding" || name == "content-encoding" || name == "content-length")
                lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(k));
            else
                ++k;
        }
        lines.push_back("Content-Length: " + std::to_string(body.size()));
    }
    std::string out;
    for (const std::string& l : lines) out += l + "\r\n";
    out += "\r\n";
    out += body;
    raw = std::move(out);
    return total;
}

std::string toJson(const std::vector<Rule>& rules) {
    Json arr = Json::array();
    for (const Rule& r : rules)
        arr.push(Json::obj({{"enabled", r.enabled},
                            {"where", static_cast<int>(r.where)},
                            {"match", r.match},
                            {"replace", r.replace},
                            {"regex", r.regex},
                            {"comment", r.comment}}));
    return arr.dump();
}

std::vector<Rule> fromJson(const std::string& text) {
    std::vector<Rule> out;
    Json j;
    if (text.empty() || !Json::parse(text, j) || !j.isArray()) return out;
    for (const Json& e : j.items()) {
        Rule r;
        r.enabled = e.get("enabled").asBool(true);
        const int64_t w = e.get("where").asInt(1);
        r.where = static_cast<Where>(w >= 0 && w < kWhereCount ? w : 1);
        r.match = e.get("match").asString(std::string());
        r.replace = e.get("replace").asString(std::string());
        r.regex = e.get("regex").asBool(false);
        r.comment = e.get("comment").asString(std::string());
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<Rule> presets() {
    return {
        {false, Where::RequestHeader, "^User-Agent:.*$", "User-Agent: ApkSpy", true, "Replace the User-Agent"},
        {false, Where::RequestHeader, "", "X-Debug: 1", false, "Add a request header"},
        {false, Where::RequestHeader, "^If-None-Match:.*$", "", true, "Remove If-None-Match (no cached 304 answers)"},
        {false, Where::RequestHeader, "^If-Modified-Since:.*$", "", true, "Remove If-Modified-Since (no cached 304 answers)"},
        {false, Where::RequestHeader, "^Accept-Encoding:.*$", "", true, "Ask for uncompressed responses"},
        {false, Where::ResponseHeader, "", "Access-Control-Allow-Origin: *", false, "Add a CORS header"},
        {false, Where::ResponseHeader, "^Cache-Control:.*$", "Cache-Control: no-store", true, "Stop the app caching responses"},
        {false, Where::ResponseBody, "\"isPremium\":false", "\"isPremium\":true", false, "Example: flip a JSON flag"},
    };
}

}  // namespace matchreplace
