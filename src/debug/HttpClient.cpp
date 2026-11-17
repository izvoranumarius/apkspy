#include "debug/HttpClient.hpp"
#include <chrono>
#include <cstdlib>
#include <vector>
#include "core/Socket.hpp"
#include "core/TextUtils.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace httpclient {

namespace {

using Clock = std::chrono::steady_clock;

double msSince(Clock::time_point t0) { return std::chrono::duration<double, std::milli>(Clock::now() - t0).count(); }

// Head and body of a prepared request.
struct Parts {
    std::string method, target, version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

bool split(const std::string& prepared, Parts& p) {
    const size_t end = prepared.find("\r\n\r\n");
    if (end == std::string::npos) return false;
    TrafficProxy::Message m;
    if (!TrafficProxy::parseHead(prepared.substr(0, end + 2), m)) return false;
    const size_t sp1 = m.startLine.find(' '), sp2 = m.startLine.rfind(' ');
    if (sp1 == std::string::npos) return false;
    p.method = m.startLine.substr(0, sp1);
    if (sp2 > sp1) {
        p.target = m.startLine.substr(sp1 + 1, sp2 - sp1 - 1);
        p.version = m.startLine.substr(sp2 + 1);
    } else {
        p.target = m.startLine.substr(sp1 + 1);
        p.version = "HTTP/1.1";
    }
    p.headers = std::move(m.headers);
    p.body = prepared.substr(end + 4);
    return true;
}

}  // namespace

bool readResponse(Socket& s, const std::string& method, Result& r, int timeoutMs, const std::atomic<bool>* cancel) {
    std::string buf;
    char chunk[16384];
    bool closed = false;
    const auto more = [&]() -> bool {
        const auto t0 = Clock::now();
        while (!s.waitReadable(200)) {
            if (cancel && cancel->load()) {
                r.error = "cancelled";
                return false;
            }
            if (msSince(t0) > timeoutMs) {
                r.error = "timed out waiting for the server";
                return false;
            }
        }
        const long n = s.recvSome(chunk, sizeof chunk);
        if (n <= 0) {
            closed = true;
            return false;
        }
        buf.append(chunk, static_cast<size_t>(n));
        return true;
    };
    size_t headEnd;
    for (;;) {  // the head (skipping interim 1xx responses)
        while ((headEnd = buf.find("\r\n\r\n")) == std::string::npos) {
            if (buf.size() > (1u << 20)) return r.error = "response head larger than 1 MB", false;
            if (!more()) {
                if (closed && r.error.empty()) r.error = buf.empty() ? "the server closed the connection without answering" : "incomplete response head";
                return false;
            }
        }
        if (!TrafficProxy::parseHead(buf.substr(0, headEnd + 2), r.response)) return r.error = "malformed response", false;
        r.status = std::atoi(r.response.startLine.c_str() + std::min<size_t>(9, r.response.startLine.size()));
        if (r.status >= 100 && r.status < 200 && r.status != 101) {
            buf.erase(0, headEnd + 4);
            continue;
        }
        break;
    }
    std::string body = buf.substr(headEnd + 4);
    buf.clear();
    const bool noBody = tex::asciiIEqual(method, "HEAD") || r.status == 204 || r.status == 304 || r.status == 101;
    const std::string te = tex::asciiLower(r.response.header("transfer-encoding"));
    const std::string cl = r.response.header("content-length");
    const auto pull = [&]() {
        buf.clear();
        if (!more()) return false;
        body += buf;
        return true;
    };
    if (noBody) {
        body.clear();
    } else if (te.find("chunked") != std::string::npos) {
        // Walk the chunk framing to find the end; the body keeps the framing (decodeBody removes it).
        size_t pos = 0;
        for (;;) {
            const size_t eol = body.find("\r\n", pos);
            if (eol == std::string::npos) {
                if (!pull()) break;
                continue;
            }
            const size_t size = std::strtoull(body.c_str() + pos, nullptr, 16);
            if (size == 0) {  // last chunk, then trailers up to a blank line
                if (body.find("\r\n\r\n", eol) != std::string::npos || body.compare(eol, 4, "\r\n\r\n") == 0) break;
                if (!pull()) break;
                continue;
            }
            const size_t next = eol + 2 + size + 2;
            while (body.size() < next && body.size() < kMaxBody)
                if (!pull()) break;
            if (body.size() < next) break;
            pos = next;
        }
    } else if (!cl.empty()) {
        const uint64_t want = std::strtoull(cl.c_str(), nullptr, 10);
        while (body.size() < want && body.size() < kMaxBody)
            if (!pull()) break;
        if (body.size() > want) body.resize(static_cast<size_t>(want));
    } else {
        while (body.size() < kMaxBody)  // no length: the body ends with the connection
            if (!pull()) break;
    }
    if (cancel && cancel->load()) return r.error = "cancelled", false;
    r.response.bodySize = body.size();
    r.response.truncated = body.size() >= kMaxBody;
    if (r.response.truncated) body.resize(kMaxBody);
    r.response.body = std::move(body);
    // A body cut short (the server closed or went quiet) is still shown, with the reason as a note.
    if (!r.error.empty()) r.note = "the response ended early: " + r.error, r.error.clear();
    else if (closed && (!cl.empty() || te.find("chunked") != std::string::npos) && r.response.body.size() < std::strtoull(cl.c_str(), nullptr, 10))
        r.note = "the server closed the connection before the whole body arrived";
    return true;
}

std::string rawMessage(const TrafficProxy::Message& m) {
    std::string out = m.startLine + "\r\n";
    for (const auto& [name, value] : m.headers) out += name + ": " + value + "\r\n";
    out += "\r\n";
    out += m.body;
    return out;
}

namespace {

Result sendPlain(const Target& t, const std::string& prepared, const std::string& method, const Options& o, const std::atomic<bool>* cancel) {
    Result r;
    r.sent = prepared;
    const auto t0 = Clock::now();
    Socket s;
    std::string error;
    if (!Socket::initNetworking() || !s.connectHost(t.host, t.port, std::min(o.timeoutMs, 15000), error)) {
        r.error = "could not connect to " + t.host + ":" + std::to_string(t.port) + (error.empty() ? "" : ": " + error);
        return r;
    }
    if (!s.sendAll(prepared)) {
        r.error = "the connection closed while sending";
        return r;
    }
    r.ok = readResponse(s, method, r, o.timeoutMs, cancel);
    r.ms = msSince(t0);
    return r;
}

#ifdef _WIN32
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string winhttpError(DWORD code) {
    switch (code) {
    case ERROR_WINHTTP_SECURE_FAILURE:
    case ERROR_WINHTTP_SECURE_INVALID_CA:
    case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
    case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
        return "the server's certificate is not trusted (tick Ignore certificate errors to send anyway)";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: return "the host name could not be resolved";
    case ERROR_WINHTTP_CANNOT_CONNECT: return "could not connect to the server";
    case ERROR_WINHTTP_TIMEOUT: return "timed out waiting for the server";
    case ERROR_WINHTTP_CONNECTION_ERROR: return "the connection was reset (is the port really HTTPS?)";
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE: return "the server's answer is not valid HTTP";
    default: break;
    }
    wchar_t* text = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
                   GetModuleHandleW(L"winhttp.dll"), code, 0, reinterpret_cast<wchar_t*>(&text), 0, nullptr);
    std::string msg = text ? narrow(text) : std::string();
    if (text) LocalFree(text);
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ' || msg.back() == '.')) msg.pop_back();
    return msg.empty() ? "WinHTTP error " + std::to_string(code) : msg + " (" + std::to_string(code) + ")";
}

struct Handle {
    HINTERNET h = nullptr;
    ~Handle() {
        if (h) WinHttpCloseHandle(h);
    }
};

Result sendTls(const Target& t, const std::string& prepared, const Options& o, const std::atomic<bool>* cancel) {
    Result r;
    r.sent = prepared;
    const auto t0 = Clock::now();
    Parts p;
    if (!split(prepared, p)) return r.error = "the request has no start line", r;
    const auto fail = [&](const char* what) {
        r.error = std::string(what) + ": " + winhttpError(GetLastError());
        r.ms = msSince(t0);
        return r;
    };
    Handle session, connect, request;
    session.h = WinHttpOpen(L"ApkSpy-Repeater", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session.h) return fail("WinHTTP");
    WinHttpSetTimeouts(session.h, o.timeoutMs, std::min(o.timeoutMs, 15000), o.timeoutMs, o.timeoutMs);
    connect.h = WinHttpConnect(session.h, wide(t.host).c_str(), static_cast<INTERNET_PORT>(t.port), 0);
    if (!connect.h) return fail("connect");
    const std::wstring version = wide(p.version);
    request.h = WinHttpOpenRequest(connect.h, wide(p.method).c_str(), wide(p.target).c_str(), version.c_str(), WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE |
                                                                    WINHTTP_FLAG_ESCAPE_DISABLE_QUERY);
    if (!request.h) return fail("request");
    // One send, as typed: no redirects, cookies or automatic sign-in.
    DWORD disable = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    WinHttpSetOption(request.h, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof disable);
    if (o.ignoreCertErrors) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.h, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags);
    }
    std::string headers;
    for (const auto& [name, value] : p.headers) {
        // WinHTTP frames the body itself.
        if (tex::asciiIEqual(name, "content-length") || tex::asciiIEqual(name, "transfer-encoding")) continue;
        headers += name + ": " + value + "\r\n";
    }
    const std::wstring wheaders = wide(headers);
    if (!WinHttpSendRequest(request.h, wheaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wheaders.c_str(),
                            static_cast<DWORD>(wheaders.size()), p.body.empty() ? WINHTTP_NO_REQUEST_DATA : p.body.data(),
                            static_cast<DWORD>(p.body.size()), static_cast<DWORD>(p.body.size()), 0))
        return fail("send");
    if (!WinHttpReceiveResponse(request.h, nullptr)) return fail("receive");
    DWORD size = 0;
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    std::wstring raw(size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(request.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &size, WINHTTP_NO_HEADER_INDEX))
        return fail("headers");
    raw.resize(size / sizeof(wchar_t));
    TrafficProxy::parseHead(narrow(raw), r.response);
    // WinHTTP removes the chunk framing: drop the header so the body reads as plain.
    bool dechunked = false;
    for (auto it = r.response.headers.begin(); it != r.response.headers.end();)
        if (tex::asciiIEqual(it->first, "transfer-encoding")) it = r.response.headers.erase(it), dechunked = true;
        else ++it;
    r.status = std::atoi(r.response.startLine.c_str() + std::min<size_t>(9, r.response.startLine.size()));
    std::string body;
    for (;;) {
        if (cancel && cancel->load()) return r.error = "cancelled", r.ms = msSince(t0), r;
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request.h, &avail)) return fail("read");
        if (avail == 0) break;
        const size_t at = body.size();
        body.resize(at + avail);
        DWORD got = 0;
        if (!WinHttpReadData(request.h, body.data() + at, avail, &got)) return fail("read");
        body.resize(at + got);
        if (body.size() >= kMaxBody) {
            r.response.truncated = true;
            body.resize(kMaxBody);
            break;
        }
    }
    r.response.bodySize = body.size();
    r.response.body = std::move(body);
    r.note = dechunked ? "sent through WinHTTP; it removed the chunked framing" : "sent through WinHTTP";
    r.ms = msSince(t0);
    r.ok = true;
    return r;
}
#endif

}  // namespace

std::string Target::label() const {
    const bool standard = (https && port == 443) || (!https && port == 80);
    return std::string(https ? "https://" : "http://") + host + (standard ? "" : ":" + std::to_string(port));
}

std::string prepare(std::string_view typed, bool fixContentLength) {
    // The head ends at the first blank line (LF or CRLF); the body follows untouched.
    size_t headEnd = std::string_view::npos, bodyAt = typed.size();
    for (size_t i = 0; i < typed.size(); ++i) {
        if (typed[i] != '\n') continue;
        size_t j = i + 1;
        if (j < typed.size() && typed[j] == '\r') ++j;
        if (j < typed.size() && typed[j] == '\n') {
            headEnd = i;
            bodyAt = j + 1;
            break;
        }
    }
    std::string_view head = typed.substr(0, headEnd == std::string_view::npos ? typed.size() : headEnd);
    std::string_view body = headEnd == std::string_view::npos ? std::string_view() : typed.substr(bodyAt);
    while (!head.empty() && (head.front() == '\n' || head.front() == '\r' || head.front() == ' ')) head.remove_prefix(1);
    std::vector<std::string> lines;
    for (size_t pos = 0; pos <= head.size();) {
        size_t e = head.find('\n', pos);
        if (e == std::string_view::npos) e = head.size();
        std::string line(head.substr(pos, e - pos));
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
        pos = e + 1;
    }
    if (lines.empty()) return {};
    bool chunked = false;
    int lengthLine = -1;
    for (size_t i = 1; i < lines.size(); ++i) {
        const size_t colon = lines[i].find(':');
        const std::string name = tex::asciiLower(lines[i].substr(0, colon));
        if (name == "content-length") lengthLine = static_cast<int>(i);
        if (name == "transfer-encoding" && tex::asciiLower(lines[i]).find("chunked") != std::string::npos) chunked = true;
    }
    if (fixContentLength && !chunked) {
        const std::string method = lines[0].substr(0, lines[0].find(' '));
        const bool wantsBody = !body.empty() || tex::asciiIEqual(method, "POST") || tex::asciiIEqual(method, "PUT") ||
                               tex::asciiIEqual(method, "PATCH");
        const std::string value = "Content-Length: " + std::to_string(body.size());
        if (lengthLine >= 0) lines[static_cast<size_t>(lengthLine)] = value;
        else if (wantsBody) lines.push_back(value);
    }
    std::string out;
    for (const std::string& l : lines) out += l + "\r\n";
    out += "\r\n";
    out.append(body);
    return out;
}

bool targetFromRequest(std::string_view request, Target& target) {
    TrafficProxy::Message m;
    const std::string prepared = prepare(request, false);
    const size_t end = prepared.find("\r\n\r\n");
    if (end == std::string::npos || !TrafficProxy::parseHead(prepared.substr(0, end + 2), m)) return false;
    std::string host = m.header("host");
    while (!host.empty() && host.back() == ' ') host.pop_back();
    if (host.empty()) return false;
    int port = target.https ? 443 : 80;
    const size_t colon = host.rfind(':');
    if (colon != std::string::npos && host.find(']', colon) == std::string::npos && host.find(':') == colon) {
        port = std::atoi(host.c_str() + colon + 1);
        host.resize(colon);
    }
    if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    target.host = host;
    target.port = port > 0 && port < 65536 ? port : (target.https ? 443 : 80);
    return true;
}

std::string editableRequest(const TrafficProxy::Flow& f) {
    const std::string& line = f.request.startLine;
    const size_t sp2 = line.rfind(' ');
    const std::string version = sp2 == std::string::npos ? "HTTP/1.1" : line.substr(sp2 + 1);
    std::string out = f.method + " " + (f.path.empty() ? "/" : f.path) + " " + version + "\n";
    bool hasHost = false;
    for (const auto& [name, value] : f.request.headers) {
        if (tex::asciiIEqual(name, "proxy-connection") || tex::asciiIEqual(name, "proxy-authorization")) continue;
        if (tex::asciiIEqual(name, "host")) hasHost = true;
        out += name + ": " + value + "\n";
    }
    if (!hasHost) out += "Host: " + f.host + (f.port == 80 ? "" : ":" + std::to_string(f.port)) + "\n";
    out += "\n";
    out += f.request.body;
    return out;
}

Result send(const Target& target, std::string_view typed, const Options& options, const std::atomic<bool>* cancel) {
    Result r;
    if (target.host.empty()) return r.error = "no host: fill in the target (or a Host header)", r;
    const std::string prepared = prepare(typed, options.fixContentLength);
    if (prepared.empty()) return r.error = "the request is empty", r;
    const std::string method = prepared.substr(0, prepared.find(' '));
    if (target.https) {
#ifdef _WIN32
        return sendTls(target, prepared, options, cancel);
#else
        r.error = "sending HTTPS needs the Windows build (WinHTTP)";
        return r;
#endif
    }
    return sendPlain(target, prepared, method, options, cancel);
}

}  // namespace httpclient
