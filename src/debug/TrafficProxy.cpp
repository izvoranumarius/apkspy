#include "debug/TrafficProxy.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <miniz.h>
#include "core/TextUtils.hpp"
#include "debug/Adb.hpp"

namespace {

constexpr size_t kMaxHead = 64 * 1024;
constexpr size_t kMaxRequestBody = 64u << 20;  // requests above this are refused (413)
constexpr int kIdleMs = 60000;

double unixNow() {
    using namespace std::chrono;
    return static_cast<double>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()) / 1000.0;
}

bool iequals(const std::string& a, const char* b) { return tex::asciiIEqual(a, b); }

// Reads until "\r\n\r\n"; returns the head (without the blank line) and
// leaves the bytes after it in `rest`.
bool readHead(Socket& s, std::string& head, std::string& rest) {
    std::string buf = std::move(rest);
    rest.clear();
    char chunk[16384];
    for (;;) {
        const size_t end = buf.find("\r\n\r\n");
        if (end != std::string::npos) {
            head = buf.substr(0, end);
            rest = buf.substr(end + 4);
            return true;
        }
        if (buf.size() > kMaxHead || !s.waitReadable(kIdleMs)) return false;
        const long n = s.recvSome(chunk, sizeof chunk);
        if (n <= 0) return false;
        buf.append(chunk, static_cast<size_t>(n));
    }
}

bool readMore(Socket& s, std::string& buf) {
    char chunk[65536];
    if (!s.waitReadable(kIdleMs)) return false;
    const long n = s.recvSome(chunk, sizeof chunk);
    if (n <= 0) return false;
    buf.append(chunk, static_cast<size_t>(n));
    return true;
}

// Length of a complete chunked body at the start of `b`, or npos when more
// bytes are needed (malformed sizes count as "complete" to stop reading).
size_t chunkedLength(const std::string& b) {
    size_t pos = 0;
    for (;;) {
        const size_t eol = b.find("\r\n", pos);
        if (eol == std::string::npos) return std::string::npos;
        const unsigned long long size = std::strtoull(b.c_str() + pos, nullptr, 16);
        pos = eol + 2;
        if (size == 0) {
            // Trailers until an empty line.
            for (;;) {
                const size_t t = b.find("\r\n", pos);
                if (t == std::string::npos) return std::string::npos;
                if (t == pos) return t + 2;
                pos = t + 2;
            }
        }
        if (size > kMaxRequestBody) return b.size();
        if (pos + size + 2 > b.size()) return std::string::npos;
        pos += static_cast<size_t>(size) + 2;
    }
}

void capture(TrafficProxy::Message& m, const char* data, size_t len) {
    m.bodySize += len;
    const size_t room = m.body.size() < TrafficProxy::kMaxBody ? TrafficProxy::kMaxBody - m.body.size() : 0;
    if (len > room) m.truncated = true;
    m.body.append(data, std::min(room, len));
}

}  // namespace

std::string TrafficProxy::Message::header(const std::string& name) const {
    for (const auto& h : headers)
        if (tex::asciiIEqual(h.first, name)) return h.second;
    return {};
}

std::string TrafficProxy::Flow::url() const {
    if (tunnel) return "https://" + (sni.empty() ? host : sni) + (port == 443 ? "" : ":" + std::to_string(port));
    return "http://" + host + (port == 80 ? "" : ":" + std::to_string(port)) + path;
}

bool TrafficProxy::parseHead(const std::string& head, Message& m) {
    m.headers.clear();
    size_t eol = head.find("\r\n");
    m.startLine = head.substr(0, eol);
    if (m.startLine.empty()) return false;
    size_t pos = eol == std::string::npos ? head.size() : eol + 2;
    while (pos < head.size()) {
        size_t e = head.find("\r\n", pos);
        if (e == std::string::npos) e = head.size();
        const std::string line = head.substr(pos, e - pos);
        pos = e + 2;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
        m.headers.emplace_back(line.substr(0, colon), value);
    }
    return true;
}

bool TrafficProxy::start(int port, std::string& error) {
    stop();
    if (!listener_.listenLoopback(port, error)) return false;
    port_ = listener_.localPort();
    running_ = true;
    acceptThread_ = std::thread(&TrafficProxy::acceptLoop, this);
    return true;
}

void TrafficProxy::stop() {
    if (running_.exchange(false)) listener_.shutdownBoth();
    if (acceptThread_.joinable()) acceptThread_.join();
    listener_.close();
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        for (auto& w : clients_)
            if (auto c = w.lock()) c->shutdownBoth();
        clients_.clear();
    }
    workers_.joinAll();
}

void TrafficProxy::acceptLoop() {
    while (running_.load()) {
        Socket client = listener_.accept(250);
        workers_.reap();
        if (!client.valid()) continue;
        auto shared = std::make_shared<Socket>(std::move(client));
        {
            std::lock_guard<std::mutex> lock(clientsMutex_);
            clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
                                          [](const std::weak_ptr<Socket>& w) { return w.expired(); }),
                           clients_.end());
            clients_.push_back(shared);
        }
        workers_.spawn([this, shared] { serve(shared); });
    }
}

std::shared_ptr<TrafficProxy::Flow> TrafficProxy::newFlow() {
    auto f = std::make_shared<Flow>();
    f->startedAt = unixNow();
    std::lock_guard<std::mutex> lock(mutex_);
    f->id = nextId_++;
    flows_.push_back(f);
    while (flows_.size() > kMaxFlows) flows_.pop_front();  // bounded history
    return f;
}

void TrafficProxy::finish(const std::shared_ptr<Flow>& f, std::chrono::steady_clock::time_point t0) {
    std::lock_guard<std::mutex> lock(mutex_);
    f->durationMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    f->complete = true;
}

void TrafficProxy::serve(std::shared_ptr<Socket> client) {
    std::string head, rest;
    if (!readHead(*client, head, rest)) return;
    Message req;
    if (!parseHead(head, req)) return;
    const std::string& line = req.startLine;
    const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
    if (sp1 == std::string::npos || sp2 <= sp1) {
        client->sendAll("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    auto flow = newFlow();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = line.substr(0, sp1);
        flow->request = req;
    }
    const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (iequals(flow->method, "CONNECT")) {
        const size_t colon = target.rfind(':');
        std::lock_guard<std::mutex> lock(mutex_);
        flow->tunnel = true;
        flow->host = target.substr(0, colon);
        flow->port = colon == std::string::npos ? 443 : std::atoi(target.c_str() + colon + 1);
    } else {
        // Absolute form "http://host[:port]/path" (proxy requests) or
        // origin form with a Host header.
        std::string hostPort, path = target;
        if (target.rfind("http://", 0) == 0) {
            const size_t slash = target.find('/', 7);
            hostPort = target.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
            path = slash == std::string::npos ? "/" : target.substr(slash);
        } else {
            hostPort = req.header("host");
        }
        const size_t colon = hostPort.rfind(':');
        std::lock_guard<std::mutex> lock(mutex_);
        flow->host = colon == std::string::npos ? hostPort : hostPort.substr(0, colon);
        flow->port = colon == std::string::npos ? 80 : std::atoi(hostPort.c_str() + colon + 1);
        flow->path = path;
    }
    if (flow->host.empty() || flow->port <= 0 || flow->port > 65535) {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->error = "unparsable request target";
        flow->complete = true;
        client->sendAll("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    if (flow->tunnel) serveTunnel(*client, flow, std::move(rest));
    else serveHttp(*client, flow, std::move(rest));
}

void TrafficProxy::serveTunnel(Socket& client, std::shared_ptr<Flow> flow, std::string pending) {
    const auto t0 = std::chrono::steady_clock::now();
    Socket upstream;
    std::string error;
    std::string host;
    int port;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        host = flow->host;
        port = flow->port;
    }
    if (!upstream.connectHost(host, port, 15000, error)) {
        client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        std::lock_guard<std::mutex> lock(mutex_);
        flow->error = error;
        flow->status = 502;
        flow->complete = true;
        return;
    }
    client.sendAll("HTTP/1.1 200 Connection Established\r\n\r\n");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->status = 200;
    }
    // The first client bytes are the TLS ClientHello: read the server name.
    if (pending.empty() && client.waitReadable(10000)) {
        char chunk[16384];
        const long n = client.recvSome(chunk, sizeof chunk);
        if (n > 0) pending.assign(chunk, static_cast<size_t>(n));
    }
    if (!pending.empty()) {
        const std::string sni = parseSni(reinterpret_cast<const uint8_t*>(pending.data()), pending.size());
        std::lock_guard<std::mutex> lock(mutex_);
        flow->sni = sni;
        flow->bytesUp += pending.size();
    }
    if (!pending.empty() && !upstream.sendAll(pending)) {
        finish(flow, t0);
        return;
    }
    // Relay both directions; whichever side closes first ends the tunnel.
    std::thread up([&] {
        char buf[65536];
        for (;;) {
            const long n = client.recvSome(buf, sizeof buf);
            if (n <= 0 || !upstream.sendAll(buf, static_cast<size_t>(n))) break;
            std::lock_guard<std::mutex> lock(mutex_);
            flow->bytesUp += static_cast<uint64_t>(n);
        }
        upstream.shutdownBoth();
        client.shutdownBoth();
    });
    char buf[65536];
    for (;;) {
        const long n = upstream.recvSome(buf, sizeof buf);
        if (n <= 0 || !client.sendAll(buf, static_cast<size_t>(n))) break;
        std::lock_guard<std::mutex> lock(mutex_);
        flow->bytesDown += static_cast<uint64_t>(n);
    }
    client.shutdownBoth();
    upstream.shutdownBoth();
    up.join();
    finish(flow, t0);
}

void TrafficProxy::serveHttp(Socket& client, std::shared_ptr<Flow> flow, std::string pending) {
    const auto t0 = std::chrono::steady_clock::now();
    Message req;
    std::string host, path, method;
    int port;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        req = flow->request;
        host = flow->host;
        path = flow->path;
        method = flow->method;
        port = flow->port;
    }
    // Request body (Content-Length or chunked), read completely first.
    std::string body = std::move(pending);
    const std::string te = tex::asciiLower(req.header("transfer-encoding"));
    const std::string cl = req.header("content-length");
    if (te.find("chunked") != std::string::npos) {
        while (chunkedLength(body) == std::string::npos)
            if (body.size() > kMaxRequestBody || !readMore(client, body)) break;
    } else if (!cl.empty()) {
        const unsigned long long want = std::strtoull(cl.c_str(), nullptr, 10);
        if (want > kMaxRequestBody) {
            client.sendAll("HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            std::lock_guard<std::mutex> lock(mutex_);
            flow->status = 413;
            flow->error = "request body too large for the sniffer";
            flow->complete = true;
            return;
        }
        while (body.size() < want)
            if (!readMore(client, body)) break;
        if (body.size() > want) body.resize(static_cast<size_t>(want));
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->request.body.clear();
        flow->request.bodySize = 0;
        capture(flow->request, body.data(), body.size());
        flow->bytesUp = body.size();
    }

    Socket upstream;
    std::string error;
    if (!upstream.connectHost(host, port, 15000, error)) {
        client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = error;
            flow->status = 502;
        }
        finish(flow, t0);
        return;
    }
    // Origin-form request; hop-by-hop proxy headers dropped, one request per
    // connection (Connection: close) so the response ends with the stream.
    const size_t sp2 = req.startLine.rfind(' ');
    std::string out = method + " " + path + req.startLine.substr(sp2) + "\r\n";
    bool hasHost = false;
    for (const auto& h : req.headers) {
        if (iequals(h.first, "proxy-connection") || iequals(h.first, "proxy-authorization") ||
            iequals(h.first, "connection") || iequals(h.first, "keep-alive"))
            continue;
        if (iequals(h.first, "host")) hasHost = true;
        out += h.first + ": " + h.second + "\r\n";
    }
    if (!hasHost) out += "Host: " + host + (port == 80 ? "" : ":" + std::to_string(port)) + "\r\n";
    out += "Connection: close\r\n\r\n";
    if (!upstream.sendAll(out) || (!body.empty() && !upstream.sendAll(body))) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = "upstream write failed";
        }
        finish(flow, t0);
        return;
    }

    // Response: streamed to the client as it arrives, captured on the side.
    std::string captured;  // head(s) + body prefix
    bool headDone = false;
    size_t bodyStart = 0;
    uint64_t expected = UINT64_MAX;  // total response bytes when Content-Length is known
    uint64_t total = 0;
    char buf[65536];
    for (;;) {
        if (!upstream.waitReadable(kIdleMs)) break;
        const long n = upstream.recvSome(buf, sizeof buf);
        if (n <= 0) break;
        if (!client.sendAll(buf, static_cast<size_t>(n))) break;
        total += static_cast<uint64_t>(n);
        if (!headDone) {
            captured.append(buf, static_cast<size_t>(n));
            // Skip interim 1xx responses (100 Continue).
            for (;;) {
                const size_t end = captured.find("\r\n\r\n");
                if (end == std::string::npos) break;
                Message resp;
                parseHead(captured.substr(0, end), resp);
                const int status = std::atoi(resp.startLine.c_str() + std::min<size_t>(9, resp.startLine.size()));
                if (status >= 100 && status < 200) {
                    captured.erase(0, end + 4);
                    continue;
                }
                headDone = true;
                bodyStart = end + 4;
                const std::string len = resp.header("content-length");
                if (!len.empty()) expected = (total - captured.size()) + bodyStart + std::strtoull(len.c_str(), nullptr, 10);
                std::lock_guard<std::mutex> lock(mutex_);
                flow->response = resp;
                flow->status = status;
                capture(flow->response, captured.data() + bodyStart, captured.size() - bodyStart);
                break;
            }
            if (captured.size() > kMaxHead && !headDone) break;  // not HTTP
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            capture(flow->response, buf, static_cast<size_t>(n));
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->bytesDown = total;
        }
        if (total >= expected) break;  // Content-Length satisfied
    }
    client.shutdownBoth();
    finish(flow, t0);
}

std::vector<TrafficProxy::Flow> TrafficProxy::flows(uint64_t sinceId, size_t limit) const {
    std::vector<Flow> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& f : flows_) {
        if (f->id <= sinceId) continue;
        Flow copy;  // summary copy: bodies are fetched on demand with flow()
        copy.id = f->id;
        copy.startedAt = f->startedAt;
        copy.durationMs = f->durationMs;
        copy.tunnel = f->tunnel;
        copy.complete = f->complete;
        copy.method = f->method;
        copy.host = f->host;
        copy.port = f->port;
        copy.path = f->path;
        copy.sni = f->sni;
        copy.status = f->status;
        copy.bytesUp = f->bytesUp;
        copy.bytesDown = f->bytesDown;
        copy.error = f->error;
        copy.response.headers = f->response.headers;
        copy.response.bodySize = f->response.bodySize;
        copy.request.bodySize = f->request.bodySize;
        out.push_back(std::move(copy));
    }
    if (out.size() > limit) out.erase(out.begin(), out.begin() + static_cast<ptrdiff_t>(out.size() - limit));
    return out;
}

bool TrafficProxy::flow(uint64_t id, Flow& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& f : flows_)
        if (f->id == id) {
            out = *f;
            return true;
        }
    return false;
}

uint64_t TrafficProxy::lastId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nextId_ - 1;
}

void TrafficProxy::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    flows_.clear();
    std::deque<std::shared_ptr<Flow>>().swap(flows_);
}

std::vector<TrafficProxy::Endpoint> TrafficProxy::endpoints() const {
    std::vector<Endpoint> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& f : flows_) {
        const std::string tmpl = f->tunnel ? std::string() : pathTemplate(f->path);
        const std::string host = f->tunnel && !f->sni.empty() ? f->sni : f->host;
        auto it = std::find_if(out.begin(), out.end(), [&](const Endpoint& e) {
            return e.method == f->method && e.host == host && e.pathTemplate == tmpl;
        });
        if (it == out.end()) {
            out.push_back({f->method, host, tmpl, 0, {}, 0, 0, f->tunnel});
            it = out.end() - 1;
        }
        ++it->count;
        it->bytes += f->bytesUp + f->bytesDown;
        it->lastFlow = f->id;
        if (f->status && std::find(it->statuses.begin(), it->statuses.end(), f->status) == it->statuses.end())
            it->statuses.push_back(f->status);
    }
    for (auto& e : out) std::sort(e.statuses.begin(), e.statuses.end());
    std::sort(out.begin(), out.end(), [](const Endpoint& a, const Endpoint& b) {
        return a.host != b.host ? a.host < b.host : a.pathTemplate != b.pathTemplate ? a.pathTemplate < b.pathTemplate
                                                                                      : a.method < b.method;
    });
    return out;
}

std::string TrafficProxy::pathTemplate(const std::string& path) {
    const std::string p = path.substr(0, path.find('?'));
    std::string out;
    size_t pos = 0;
    while (pos <= p.size()) {
        size_t slash = p.find('/', pos);
        if (slash == std::string::npos) slash = p.size();
        const std::string seg = p.substr(pos, slash - pos);
        bool digits = !seg.empty(), hex = seg.size() >= 16, alnumMix = seg.size() >= 24;
        bool hasDigit = false, hasAlpha = false;
        for (char c : seg) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (!std::isdigit(u)) digits = false;
            if (!std::isxdigit(u) && c != '-') hex = false;
            if (!(std::isalnum(u) || c == '-' || c == '_')) alnumMix = false;
            hasDigit |= std::isdigit(u) != 0;
            hasAlpha |= std::isalpha(u) != 0;
        }
        const bool uuid = seg.size() == 36 && seg[8] == '-' && seg[13] == '-' && seg[18] == '-' && seg[23] == '-';
        const bool id = digits || uuid || (hex && hasDigit) || (alnumMix && hasDigit && hasAlpha);
        out += id ? "{id}" : seg;
        if (slash < p.size()) out += '/';
        pos = slash + 1;
    }
    return out.empty() ? "/" : out;
}

std::string TrafficProxy::decodeBody(const Message& m, std::string* note) {
    std::string body = m.body;
    if (tex::asciiLower(m.header("transfer-encoding")).find("chunked") != std::string::npos) {
        std::string plain;
        size_t pos = 0;
        while (pos < body.size()) {
            const size_t eol = body.find("\r\n", pos);
            if (eol == std::string::npos) break;
            const unsigned long long size = std::strtoull(body.c_str() + pos, nullptr, 16);
            pos = eol + 2;
            if (size == 0 || pos >= body.size()) break;
            const size_t take = static_cast<size_t>(std::min<unsigned long long>(size, body.size() - pos));
            plain.append(body, pos, take);
            pos += take + 2;
        }
        body.swap(plain);
    }
    const std::string enc = tex::asciiLower(m.header("content-encoding"));
    if (enc.find("gzip") != std::string::npos || enc.find("deflate") != std::string::npos) {
        const auto* d = reinterpret_cast<const uint8_t*>(body.data());
        size_t start = 0;
        int flags = 0;
        if (enc.find("gzip") != std::string::npos && body.size() > 18 && d[0] == 0x1f && d[1] == 0x8b) {
            const uint8_t flg = d[3];
            start = 10;
            if (flg & 4) start += 2 + static_cast<size_t>(d[start] | d[start + 1] << 8);  // FEXTRA
            if (flg & 8) while (start < body.size() && d[start++]) {}           // FNAME
            if (flg & 16) while (start < body.size() && d[start++]) {}          // FCOMMENT
            if (flg & 2) start += 2;                                             // FHCRC
        } else if (body.size() > 2 && (d[0] & 0x0F) == 8 && ((d[0] << 8 | d[1]) % 31) == 0) {
            flags = TINFL_FLAG_PARSE_ZLIB_HEADER;
        }
        if (start < body.size()) {
            size_t outLen = 0;
            void* inflated = tinfl_decompress_mem_to_heap(d + start, body.size() - start, &outLen, flags);
            if (inflated) {
                body.assign(static_cast<const char*>(inflated), std::min<size_t>(outLen, 16u << 20));
                mz_free(inflated);
                if (note) *note = "decoded from " + enc;
            } else if (note) {
                *note = m.truncated ? "compressed body was truncated by the capture limit" : "could not inflate the body";
            }
        }
    } else if (!enc.empty() && enc != "identity" && note) {
        *note = "content-encoding '" + enc + "' is not decoded";
    }
    return body;
}

std::string TrafficProxy::parseSni(const uint8_t* d, size_t len) {
    // TLS record (handshake) -> ClientHello -> extensions -> server_name.
    if (len < 43 || d[0] != 0x16 || d[5] != 0x01) return {};
    size_t p = 5 + 4 + 2 + 32;  // record hdr, handshake hdr, version, random
    if (p >= len) return {};
    p += 1 + d[p];  // session id
    if (p + 2 > len) return {};
    p += 2 + static_cast<size_t>(d[p] << 8 | d[p + 1]);  // cipher suites
    if (p + 1 > len) return {};
    p += 1 + d[p];  // compression methods
    if (p + 2 > len) return {};
    const size_t extEnd = std::min(len, p + 2 + static_cast<size_t>(d[p] << 8 | d[p + 1]));
    p += 2;
    while (p + 4 <= extEnd) {
        const unsigned type = static_cast<unsigned>(d[p] << 8 | d[p + 1]);
        const size_t elen = static_cast<size_t>(d[p + 2] << 8 | d[p + 3]);
        p += 4;
        if (type == 0 && p + 5 <= extEnd) {  // server_name list -> host_name
            const size_t nameLen = static_cast<size_t>(d[p + 3] << 8 | d[p + 4]);
            if (d[p + 2] == 0 && p + 5 + nameLen <= extEnd) {
                std::string name(reinterpret_cast<const char*>(d) + p + 5, nameLen);
                for (char c : name)
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-')) return {};
                return name;
            }
            return {};
        }
        p += elen;
    }
    return {};
}

std::string TrafficProxy::curl(const Flow& f) {
    const auto q = [](const std::string& s) {
        std::string o = "'";
        for (char c : s) o += c == '\'' ? std::string("'\\''") : std::string(1, c);
        return o + "'";
    };
    std::string out = "curl -X " + f.method + " " + q(f.url());
    for (const auto& h : f.request.headers) {
        if (tex::asciiIEqual(h.first, "proxy-connection") || tex::asciiIEqual(h.first, "content-length")) continue;
        out += " -H " + q(h.first + ": " + h.second);
    }
    if (!f.request.body.empty()) out += " --data-binary " + q(f.request.body);
    return out;
}

bool TrafficProxy::routeDevice(adb::Adb& adb, const std::string& serial, std::string& error) {
    if (!running()) {
        error = "start the proxy first";
        return false;
    }
    if (!adb.reverse(serial, port_, error)) return false;
    if (!adb.setGlobalHttpProxy(serial, "127.0.0.1:" + std::to_string(port_), error)) return false;
    routedSerial_ = serial;
    return true;
}

bool TrafficProxy::restoreDevice(adb::Adb& adb, const std::string& serial, std::string& error) {
    const bool ok = adb.setGlobalHttpProxy(serial, ":0", error);
    std::string ignored;
    if (port_) adb.removeReverse(serial, port_, ignored);
    if (ok && serial == routedSerial_) routedSerial_.clear();
    return ok;
}
