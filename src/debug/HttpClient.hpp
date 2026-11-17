#pragma once
#include <atomic>
#include <string>
#include <string_view>
#include "debug/TrafficProxy.hpp"

class Socket;

// Sends one hand-edited HTTP request and reads the whole answer: the engine of
// the Repeater (as in Burp). Plain HTTP goes out over a socket exactly as
// typed; HTTPS goes through the system's HTTP stack (WinHTTP on Windows).
// No proxy, no redirects followed, no cookies kept: each send stands alone.
namespace httpclient {

struct Target {
    std::string host;
    int port = 80;
    bool https = false;
    std::string label() const;  // "https://api.example.com" (":port" when not the default)
};

struct Options {
    bool fixContentLength = true;   // set Content-Length to the body's size
    bool ignoreCertErrors = false;  // HTTPS: accept self-signed, expired or mismatched certificates
    int timeoutMs = 30000;
};

struct Result {
    bool ok = false;
    std::string error;
    TrafficProxy::Message response;  // start line, headers, body (as received; may be chunked / compressed)
    std::string sent;                // the request bytes that went out
    std::string note;                // how it was sent ("HTTPS through WinHTTP: chunked body decoded")
    double ms = 0;
    int status = 0;
};

constexpr size_t kMaxBody = 32u << 20;

// A request as typed (LF or CRLF lines) made ready to send: CRLF in the head,
// one blank line, the body unchanged, Content-Length updated when asked.
std::string prepare(std::string_view typed, bool fixContentLength);
// Host and port from the request's Host header; false when it has none. `https`
// stays as given (the Host header cannot tell).
bool targetFromRequest(std::string_view request, Target& target);
// The editable text of a captured request: origin-form start line, LF lines,
// proxy-only headers dropped, the body as captured.
std::string editableRequest(const TrafficProxy::Flow& f);

Result send(const Target& target, std::string_view typed, const Options& options, const std::atomic<bool>* cancel = nullptr);

// Reads one whole response from a connected socket (head, then the body by
// Content-Length, chunked framing or the end of the stream); the proxy uses it
// to hold responses at the intercept.
bool readResponse(Socket& s, const std::string& method, Result& r, int timeoutMs, const std::atomic<bool>* cancel = nullptr);
// A response or request as raw bytes: start line, headers, blank line, body.
std::string rawMessage(const TrafficProxy::Message& m);

}  // namespace httpclient
