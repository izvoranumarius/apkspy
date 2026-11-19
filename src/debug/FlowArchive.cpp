#include "debug/FlowArchive.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include "core/Codec.hpp"
#include "core/TextUtils.hpp"
#include "debug/ContentView.hpp"
#include "mcp/Json.hpp"

namespace flowarchive {

namespace {

bool printableUtf8(const std::string& s) { return json::sanitizeUtf8(s) == s; }

Json headersJson(const TrafficProxy::Headers& headers) {
    Json arr = Json::array();
    for (const auto& [name, value] : headers) arr.push(Json::obj({{"name", name}, {"value", value}}));
    return arr;
}

TrafficProxy::Headers headersFrom(const Json& arr, bool dropEncodings) {
    TrafficProxy::Headers out;
    for (const Json& h : arr.items()) {
        const std::string name = h.get("name").asString("");
        if (name.empty()) continue;
        if (dropEncodings && (tex::asciiIEqual(name, "content-encoding") || tex::asciiIEqual(name, "transfer-encoding")))
            continue;
        if (!name.empty() && name[0] == ':') continue;  // HTTP/2 pseudo-headers (some tools export them)
        out.emplace_back(name, h.get("value").asString(""));
    }
    return out;
}

// The text form HAR wants: decoded, base64 when it is not text.
void putText(Json& obj, const std::string& decoded) {
    if (printableUtf8(decoded)) obj.set("text", decoded);
    else {
        obj.set("text", codec::base64Encode(decoded));
        obj.set("encoding", "base64");
    }
}

std::string httpVersion(const std::string& startLine, bool response) {
    if (response) {
        const size_t sp = startLine.find(' ');
        return sp == std::string::npos ? "HTTP/1.1" : startLine.substr(0, sp);
    }
    const size_t sp = startLine.rfind(' ');
    return sp == std::string::npos ? "HTTP/1.1" : startLine.substr(sp + 1);
}

Json queryString(const std::string& path) {
    Json arr = Json::array();
    const size_t q = path.find('?');
    if (q == std::string::npos) return arr;
    const std::string query = path.substr(q + 1);
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        const std::string pair = query.substr(pos, amp - pos);
        if (!pair.empty()) {
            const size_t eq = pair.find('=');
            arr.push(Json::obj({{"name", contentview::urlDecode(pair.substr(0, eq))},
                                {"value", eq == std::string::npos ? std::string() : contentview::urlDecode(pair.substr(eq + 1))}}));
        }
        pos = amp + 1;
    }
    return arr;
}

}  // namespace

std::string isoTime(double unix) {
    const std::time_t t = static_cast<std::time_t>(std::floor(unix));
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    const int ms = static_cast<int>((unix - std::floor(unix)) * 1000.0 + 0.5) % 1000;
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    return buf;
}

double parseIsoTime(const std::string& s) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0;
    double sec = 0;
    if (std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%lf", &y, &mo, &d, &h, &mi, &sec) < 5) return 0;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = 0;
#ifdef _WIN32
    double t = static_cast<double>(_mkgmtime(&tm));
#else
    double t = static_cast<double>(timegm(&tm));
#endif
    t += sec;
    // A zone offset after the seconds ("+02:00"): HAR allows any.
    size_t tpos = s.find('T');
    if (tpos != std::string::npos) {
        const size_t z = s.find_first_of("+-", tpos);
        if (z != std::string::npos) {
            int oh = 0, om = 0;
            if (std::sscanf(s.c_str() + z + 1, "%d:%d", &oh, &om) >= 1) t -= (s[z] == '-' ? -1 : 1) * (oh * 3600.0 + om * 60.0);
        }
    }
    return t;
}

std::string toHar(const std::vector<TrafficProxy::Flow>& flows, const Marks* marks) {
    Json entries = Json::array();
    for (const auto& f : flows) {
        Json req = Json::object();
        req.set("method", f.method.empty() ? "GET" : f.method);
        req.set("url", f.url());
        req.set("httpVersion", httpVersion(f.request.startLine, false));
        req.set("cookies", Json::array());
        req.set("headers", headersJson(f.request.headers));
        req.set("queryString", queryString(f.path));
        req.set("headersSize", -1);
        req.set("bodySize", static_cast<long long>(f.request.bodySize));
        if (!f.request.body.empty()) {
            Json post = Json::object();
            post.set("mimeType", f.request.header("content-type"));
            putText(post, TrafficProxy::decodeBody(f.request, nullptr));
            req.set("postData", post);
        }

        Json resp = Json::object();
        resp.set("status", f.status);
        const std::string& sl = f.response.startLine;
        const size_t sp2 = sl.find(' ', std::min<size_t>(sl.find(' ') + 1, sl.size()));
        resp.set("statusText", sp2 == std::string::npos ? std::string() : sl.substr(sp2 + 1));
        resp.set("httpVersion", httpVersion(sl, true));
        resp.set("cookies", Json::array());
        resp.set("headers", headersJson(f.response.headers));
        Json content = Json::object();
        const std::string decoded = TrafficProxy::decodeBody(f.response, nullptr);
        content.set("size", static_cast<long long>(decoded.size()));
        content.set("mimeType", f.response.header("content-type"));
        if (!decoded.empty()) putText(content, decoded);
        resp.set("content", content);
        resp.set("redirectURL", f.response.header("location"));
        resp.set("headersSize", -1);
        resp.set("bodySize", static_cast<long long>(f.response.bodySize));

        Json extra = Json::object();
        extra.set("id", static_cast<unsigned long long>(f.id));
        extra.set("host", f.host);
        extra.set("port", f.port);
        extra.set("path", f.path);
        extra.set("requestLine", f.request.startLine);
        extra.set("responseLine", f.response.startLine);
        if (!f.request.body.empty()) extra.set("rawRequestBody", codec::base64Encode(f.request.body));
        if (!f.response.body.empty()) extra.set("rawResponseBody", codec::base64Encode(f.response.body));
        extra.set("requestTruncated", f.request.truncated);
        extra.set("responseTruncated", f.response.truncated);
        extra.set("tunnel", f.tunnel);
        extra.set("https", f.https);
        extra.set("complete", f.complete);
        extra.set("websocket", f.websocket);
        extra.set("edited", f.edited);
        extra.set("bytesUp", static_cast<unsigned long long>(f.bytesUp));
        extra.set("bytesDown", static_cast<unsigned long long>(f.bytesDown));
        if (!f.sni.empty()) extra.set("sni", f.sni);
        if (!f.tlsVersion.empty()) extra.set("tlsVersion", f.tlsVersion);
        if (!f.tlsCipher.empty()) extra.set("tlsCipher", f.tlsCipher);
        if (!f.alpn.empty()) extra.set("alpn", f.alpn);
        if (!f.tlsError.empty()) extra.set("tlsError", f.tlsError);
        if (!f.error.empty()) extra.set("error", f.error);
        if (!f.note.empty()) extra.set("note", f.note);
        if (!f.transport.empty()) extra.set("transport", f.transport);

        Json entry = Json::object();
        entry.set("startedDateTime", isoTime(f.startedAt));
        entry.set("time", f.durationMs);
        entry.set("request", req);
        entry.set("response", resp);
        entry.set("cache", Json::object());
        entry.set("timings", Json::obj({{"send", 0}, {"wait", f.durationMs}, {"receive", 0}}));
        if (marks) {
            const auto it = marks->find(f.id);
            if (it != marks->end()) {
                if (it->second.color) extra.set("highlight", it->second.color);
                if (!it->second.comment.empty()) {
                    extra.set("comment", it->second.comment);
                    entry.set("comment", it->second.comment);  // HAR's own comment field
                }
            }
        }
        entry.set("_apkspy", extra);
        if (!f.wsFrames.empty()) {
            Json ws = Json::array();
            for (const auto& w : f.wsFrames) {
                Json m = Json::object();
                m.set("type", w.fromClient ? "send" : "receive");
                m.set("time", w.at);
                m.set("opcode", w.opcode);
                m.set("size", static_cast<unsigned long long>(w.size));
                if (printableUtf8(w.preview)) m.set("data", w.preview);
                else {
                    m.set("data", codec::base64Encode(w.preview));
                    m.set("_encoding", "base64");
                }
                ws.push(m);
            }
            entry.set("_webSocketMessages", ws);
        }
        entries.push(entry);
    }
    Json log = Json::object();
    log.set("version", "1.2");
    log.set("creator", Json::obj({{"name", "ApkSpy"}, {"version", "0.4"}}));
    log.set("pages", Json::array());
    log.set("entries", entries);
    return Json::obj({{"log", log}}).dump(true);
}

bool fromHar(const std::string& text, std::vector<TrafficProxy::Flow>& out, std::string& error, std::vector<Mark>* marks) {
    Json root;
    if (!Json::parse(text, root, &error)) {
        error = "not JSON: " + error;
        return false;
    }
    const Json& entries = root.get("log").get("entries");
    if (!entries.isArray()) {
        error = "not a HAR file (no log.entries)";
        return false;
    }
    for (const Json& e : entries.items()) {
        TrafficProxy::Flow f;
        const Json& req = e.get("request");
        const Json& resp = e.get("response");
        const Json& x = e.get("_apkspy");
        const bool ours = x.isObject();
        f.startedAt = parseIsoTime(e.get("startedDateTime").asString(""));
        f.durationMs = e.get("time").asNumber(0);
        f.method = req.get("method").asString("GET");
        const std::string url = req.get("url").asString("");
        // scheme://host[:port]/path
        const size_t schemeEnd = url.find("://");
        const std::string scheme = schemeEnd == std::string::npos ? "http" : tex::asciiLower(url.substr(0, schemeEnd));
        const size_t hostAt = schemeEnd == std::string::npos ? 0 : schemeEnd + 3;
        const size_t slash = url.find('/', hostAt);
        std::string hostPort = url.substr(hostAt, slash == std::string::npos ? std::string::npos : slash - hostAt);
        f.path = slash == std::string::npos ? "/" : url.substr(slash);
        f.port = scheme == "https" || scheme == "wss" ? 443 : 80;
        const size_t colon = hostPort.rfind(':');
        if (colon != std::string::npos && hostPort.find(']') == std::string::npos) {
            f.port = std::atoi(hostPort.c_str() + colon + 1);
            hostPort.resize(colon);
        } else if (colon != std::string::npos && hostPort.back() != ']') {
            f.port = std::atoi(hostPort.c_str() + colon + 1);
            hostPort.resize(colon);
        }
        if (hostPort.size() > 2 && hostPort.front() == '[' && hostPort.back() == ']') hostPort = hostPort.substr(1, hostPort.size() - 2);
        f.host = hostPort;
        f.https = scheme == "https" || scheme == "wss";
        if (f.https) f.sni = f.host;
        f.status = static_cast<int>(resp.get("status").asInt(0));

        // Request.
        const std::string reqVersion = req.get("httpVersion").asString("HTTP/1.1");
        f.request.startLine = f.method + " " + f.path + " " + (reqVersion.rfind("HTTP/", 0) == 0 ? reqVersion : "HTTP/1.1");
        std::string rawReq;
        const bool haveRawReq = ours && codec::base64Decode(x.get("rawRequestBody").asString(""), rawReq) && !rawReq.empty();
        f.request.headers = headersFrom(req.get("headers"), !haveRawReq);
        if (haveRawReq) f.request.body = rawReq;
        else if (req.get("postData").isObject()) {
            const Json& post = req.get("postData");
            std::string body = post.get("text").asString("");
            std::string decoded;
            if (post.get("encoding").asString("") == "base64" && codec::base64Decode(body, decoded)) body = decoded;
            f.request.body = body;
        }
        f.request.bodySize = f.request.body.size();
        // Response.
        if (f.status != 0 || resp.get("headers").size() > 0) {
            const std::string respVersion = resp.get("httpVersion").asString("HTTP/1.1");
            f.response.startLine = (respVersion.rfind("HTTP/", 0) == 0 ? respVersion : std::string("HTTP/1.1")) + " " +
                                   std::to_string(f.status) + " " + resp.get("statusText").asString("");
            std::string rawResp;
            const bool haveRawResp = ours && codec::base64Decode(x.get("rawResponseBody").asString(""), rawResp) && !rawResp.empty();
            f.response.headers = headersFrom(resp.get("headers"), !haveRawResp);
            if (haveRawResp) f.response.body = rawResp;
            else {
                const Json& content = resp.get("content");
                std::string body = content.get("text").asString("");
                std::string decoded;
                if (content.get("encoding").asString("") == "base64" && codec::base64Decode(body, decoded)) body = decoded;
                f.response.body = body;
            }
            f.response.bodySize = f.response.body.size();
        }
        f.complete = true;
        f.bytesUp = f.request.bodySize;
        f.bytesDown = f.response.bodySize;

        if (ours) {
            f.host = x.get("host").asString(f.host);
            f.port = static_cast<int>(x.get("port").asInt(f.port));
            f.path = x.get("path").asString(f.path);
            f.request.startLine = x.get("requestLine").asString(f.request.startLine);
            if (x.has("responseLine")) f.response.startLine = x.get("responseLine").asString("");
            f.request.truncated = x.get("requestTruncated").asBool(false);
            f.response.truncated = x.get("responseTruncated").asBool(false);
            f.tunnel = x.get("tunnel").asBool(false);
            f.https = x.get("https").asBool(f.https);
            f.websocket = x.get("websocket").asBool(false);
            f.edited = x.get("edited").asBool(false);
            f.bytesUp = static_cast<uint64_t>(x.get("bytesUp").asNumber(static_cast<double>(f.bytesUp)));
            f.bytesDown = static_cast<uint64_t>(x.get("bytesDown").asNumber(static_cast<double>(f.bytesDown)));
            f.sni = x.get("sni").asString(f.tunnel || !f.https ? "" : f.sni);
            f.tlsVersion = x.get("tlsVersion").asString("");
            f.tlsCipher = x.get("tlsCipher").asString("");
            f.alpn = x.get("alpn").asString("");
            f.tlsError = x.get("tlsError").asString("");
            f.error = x.get("error").asString("");
            f.note = x.get("note").asString("");
            f.transport = x.get("transport").asString("");
        }
        if (e.get("_webSocketMessages").isArray()) {
            for (const Json& m : e.get("_webSocketMessages").items()) {
                TrafficProxy::WsFrame w;
                w.fromClient = m.get("type").asString("") == "send";
                w.at = m.get("time").asNumber(0);
                w.opcode = static_cast<int>(m.get("opcode").asInt(1));
                std::string data = m.get("data").asString("");
                std::string decoded;
                if (m.get("_encoding").asString("") == "base64" && codec::base64Decode(data, decoded)) data = decoded;
                w.size = static_cast<uint64_t>(m.get("size").asNumber(static_cast<double>(data.size())));
                w.preview = data.substr(0, 4096);
                if (f.wsFrames.size() < TrafficProxy::kMaxWsFrames) f.wsFrames.push_back(std::move(w));
            }
            if (!f.wsFrames.empty()) f.websocket = true;
        }
        if (marks) {
            Mark mk;
            mk.color = static_cast<int>(x.get("highlight").asInt(0));
            mk.comment = x.get("comment").asString(e.get("comment").asString(""));
            marks->push_back(mk);
        }
        out.push_back(std::move(f));
    }
    return true;
}

}  // namespace flowarchive

namespace flowexport {

namespace {

// The request as it should be re-sent: headers without hop-by-hop / framing
// ones, and the body dechunked (and decompressed, with its header dropped).
struct Prepared {
    std::string method, url;
    TrafficProxy::Headers headers;
    std::string body;
};

Prepared prepare(const TrafficProxy::Flow& f) {
    Prepared p;
    p.method = f.method.empty() ? "GET" : f.method;
    p.url = f.url();
    p.body = TrafficProxy::decodeBody(f.request, nullptr);
    const bool decoded = p.body != f.request.body;
    for (const auto& h : f.request.headers) {
        const std::string n = tex::asciiLower(h.first);
        if (n == "host" || n == "content-length" || n == "connection" || n == "proxy-connection" || n == "keep-alive" ||
            n == "transfer-encoding" || (decoded && n == "content-encoding") || (!n.empty() && n[0] == ':'))
            continue;
        p.headers.push_back(h);
    }
    return p;
}

std::string shq(const std::string& s) {  // POSIX shell
    std::string o = "'";
    for (char c : s) o += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return o + "'";
}

std::string psq(const std::string& s) {  // PowerShell
    std::string o = "'";
    for (char c : s) o += c == '\'' ? std::string("''") : std::string(1, c);
    return o + "'";
}

std::string jsq(const std::string& s) {  // JSON / JavaScript / Python str literal
    std::string o;
    json::appendQuoted(o, json::sanitizeUtf8(s));
    return o;
}

std::string pyBytes(const std::string& s) {
    std::string o = "b'";
    for (unsigned char c : s) {
        if (c == '\\' || c == '\'') o += '\\', o += static_cast<char>(c);
        else if (c >= 32 && c < 127) o += static_cast<char>(c);
        else {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\x%02x", c);
            o += buf;
        }
    }
    return o + "'";
}

bool isText(const std::string& s) { return json::sanitizeUtf8(s) == s; }

}  // namespace

const char* formatName(Format f) {
    switch (f) {
        case Format::Curl: return "cURL";
        case Format::Httpie: return "HTTPie";
        case Format::PythonRequests: return "Python requests";
        case Format::Fetch: return "JavaScript fetch";
        case Format::PowerShell: return "PowerShell";
        case Format::Raw: return "Raw HTTP";
    }
    return "?";
}

std::string render(Format fmt, const TrafficProxy::Flow& f) {
    const Prepared p = prepare(f);
    std::string out;
    switch (fmt) {
        case Format::Curl:
            out = "curl -X " + p.method + " " + shq(p.url);
            for (const auto& [n, v] : p.headers) out += " \\\n  -H " + shq(n + ": " + v);
            if (!p.body.empty()) out += " \\\n  --data-binary " + shq(p.body);
            return out + "\n";
        case Format::Httpie:
            out = "http " + p.method + " " + shq(p.url);
            for (const auto& [n, v] : p.headers) out += " \\\n  " + shq(n + ":" + v);
            if (!p.body.empty()) out = "printf %s " + shq(p.body) + " | " + out;
            return out + "\n";
        case Format::PythonRequests: {
            out = "import requests\n\nresponse = requests.request(\n    " + jsq(p.method) + ",\n    " + jsq(p.url) + ",\n    headers={\n";
            for (const auto& [n, v] : p.headers) out += "        " + jsq(n) + ": " + jsq(v) + ",\n";
            out += "    },\n";
            if (!p.body.empty()) out += "    data=" + (isText(p.body) ? jsq(p.body) + ".encode()" : pyBytes(p.body)) + ",\n";
            out += ")\nprint(response.status_code)\nprint(response.text)\n";
            return out;
        }
        case Format::Fetch: {
            out = "const response = await fetch(" + jsq(p.url) + ", {\n  method: " + jsq(p.method) + ",\n  headers: {\n";
            for (const auto& [n, v] : p.headers) out += "    " + jsq(n) + ": " + jsq(v) + ",\n";
            out += "  },\n";
            if (!p.body.empty()) {
                if (isText(p.body)) out += "  body: " + jsq(p.body) + ",\n";
                else {
                    out += "  body: new Uint8Array([";
                    for (size_t i = 0; i < p.body.size(); ++i)
                        out += (i ? "," : "") + std::to_string(static_cast<unsigned char>(p.body[i]));
                    out += "]),\n";
                }
            }
            out += "});\nconsole.log(response.status, await response.text());\n";
            return out;
        }
        case Format::PowerShell: {
            out = "$headers = @{\n";
            std::string contentType;
            for (const auto& [n, v] : p.headers) {
                if (tex::asciiIEqual(n, "content-type")) contentType = v;  // a parameter of its own
                else if (!tex::asciiIEqual(n, "user-agent")) out += "    " + psq(n) + " = " + psq(v) + "\n";
            }
            out += "}\nInvoke-WebRequest -Uri " + psq(p.url) + " -Method " + p.method + " -Headers $headers";
            for (const auto& [n, v] : p.headers)
                if (tex::asciiIEqual(n, "user-agent")) out += " -UserAgent " + psq(v);
            if (!contentType.empty()) out += " -ContentType " + psq(contentType);
            if (!p.body.empty()) {
                if (isText(p.body)) out += " -Body " + psq(p.body);
                else out += " -Body ([Convert]::FromBase64String(" + psq(codec::base64Encode(p.body)) + "))";
            }
            return out + "\n";
        }
        case Format::Raw: {
            out = f.request.startLine.empty() ? p.method + " " + f.path + " HTTP/1.1" : f.request.startLine;
            out += "\r\n";
            for (const auto& [n, v] : f.request.headers) out += n + ": " + v + "\r\n";
            out += "\r\n" + f.request.body;
            return out;
        }
    }
    return out;
}

}  // namespace flowexport
