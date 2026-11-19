#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include "debug/TrafficProxy.hpp"

// Saving and loading captured flows as HAR 1.2 (HTTP Archive), the format
// browsers' dev tools, Burp, mitmproxy (har_dump) and Charles read and write.
//
//  - Export writes standard HAR (decoded bodies in content.text, base64 when
//    binary) plus ApkSpy's extras in "_apkspy" fields: the raw captured
//    bodies, tunnel / TLS details, errors and edit marks, so an ApkSpy session
//    saved and reopened is unchanged. WebSocket frames go in
//    "_webSocketMessages" (Chrome's extension).
//  - Import reads any HAR 1.2 file. Flows from other tools carry decoded
//    bodies, so their Content-Encoding / Transfer-Encoding headers are dropped
//    to keep the bodies readable.
namespace flowarchive {

// A flow's highlight and comment (the UI keeps them; HAR stores them in
// "_apkspy" so they survive a save / open).
struct Mark {
    int color = 0;  // 0 none, else 1 + palette index
    std::string comment;
};
using Marks = std::unordered_map<uint64_t, Mark>;  // by flow id

std::string toHar(const std::vector<TrafficProxy::Flow>& flows, const Marks* marks = nullptr);
// `marks` (optional) gets one entry per flow read, in order.
bool fromHar(const std::string& text, std::vector<TrafficProxy::Flow>& out, std::string& error,
             std::vector<Mark>* marks = nullptr);

// ISO 8601 (UTC, milliseconds) <-> unix seconds. Exposed for tests.
std::string isoTime(double unix);
double parseIsoTime(const std::string& s);

}  // namespace flowarchive

// "Copy as": a captured request as a command or code that sends it again.
namespace flowexport {

enum class Format { Curl, Httpie, PythonRequests, Fetch, PowerShell, Raw };
constexpr int kFormatCount = 6;
const char* formatName(Format f);
std::string render(Format f, const TrafficProxy::Flow& flow);

}  // namespace flowexport
