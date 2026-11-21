#include "debug/TrafficProxy.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <brotli/decode.h>
#include <miniz.h>
#include <random>
#include <zstd.h>
#include <filesystem>
#include <fstream>
#include "core/Codec.hpp"
#include "core/Paths.hpp"
#include "debug/ContentView.hpp"
#include "debug/Http2.hpp"
#include "core/TextUtils.hpp"
#include "debug/Adb.hpp"
#include "debug/HttpClient.hpp"

namespace {

constexpr size_t kMaxHead = 64 * 1024;
constexpr size_t kMaxRequestBody = 64u << 20;  // requests above this are refused (413)
constexpr int kIdleMs = 60000;

double unixNow() {
    using namespace std::chrono;
    return static_cast<double>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()) / 1000.0;
}

bool iequals(const std::string& a, const char* b) { return tex::asciiIEqual(a, b); }

// An edited request still ends its connection after one exchange (the relay
// reads the response to the end of the stream).
std::string withConnectionClose(const std::string& raw) {
    const size_t headEnd = raw.find("\r\n\r\n");
    if (headEnd == std::string::npos) return raw;
    std::string out;
    size_t pos = 0;
    bool first = true;
    bool upgrade = false;
    while (pos < headEnd + 2) {
        const size_t eol = raw.find("\r\n", pos);
        const std::string line = raw.substr(pos, eol - pos);
        pos = eol + 2;
        const std::string name = tex::asciiLower(line.substr(0, line.find(':')));
        if (!first && (name == "connection" || name == "keep-alive" || name == "proxy-connection")) continue;
        if (!first && name == "upgrade") upgrade = true;
        out += line + "\r\n";
        first = false;
    }
    out += upgrade ? "Connection: Upgrade\r\n\r\n" : "Connection: close\r\n\r\n";
    out.append(raw, headEnd + 4, std::string::npos);
    return out;
}

// Reads until "\r\n\r\n"; returns the head (without the blank line) and
// leaves the bytes after it in `rest`.
bool readHead(net::Stream& s, std::string& head, std::string& rest) {
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

bool readMore(net::Stream& s, std::string& buf) {
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

std::atomic<size_t> gMaxBody{TrafficProxy::kMaxBody};  // setLimits (one capture limit per process)

void capture(TrafficProxy::Message& m, const char* data, size_t len) {
    m.bodySize += len;
    const size_t limit = gMaxBody.load();
    const size_t room = m.body.size() < limit ? limit - m.body.size() : 0;
    if (len > room) m.truncated = true;
    m.body.append(data, std::min(room, len));
}

// Drops hop-by-hop headers and sets the Connection header, so a decrypted
// response does not carry the upstream's "Connection: close" into a TLS
// session the proxy wants to reuse for the next request.
std::string reframeResponseHead(const std::string& head, bool keepAlive) {
    std::string out;
    size_t pos = 0;
    bool first = true;
    while (pos <= head.size()) {
        size_t eol = head.find("\r\n", pos);
        if (eol == std::string::npos) eol = head.size();
        const std::string line = head.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.empty()) break;
        if (!first) {
            const std::string name = tex::asciiLower(line.substr(0, line.find(':')));
            if (name == "connection" || name == "keep-alive" || name == "proxy-connection") continue;
        }
        out += line + "\r\n";
        first = false;
    }
    out += keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    return out;
}

// A raw response message reframed for a persistent (TLS) client: hop-by-hop
// headers out, Connection: keep-alive in, and a Content-Length added when the
// upstream framed the body only by closing the connection (the whole body is
// in hand by then).
std::string reframeForClient(const std::string& raw, const TrafficProxy::Message& resp) {
    const size_t headEnd = raw.find("\r\n\r\n");
    if (headEnd == std::string::npos) return raw;
    const std::string body = raw.substr(headEnd + 4);
    const bool hasLength = !resp.header("content-length").empty();
    const bool chunked = tex::asciiLower(resp.header("transfer-encoding")).find("chunked") != std::string::npos;
    std::string head = reframeResponseHead(raw.substr(0, headEnd + 2), true) + "\r\n";  // + the blank line
    // 1xx / 204 / 304 never carry a body; everything else needs explicit
    // framing on a keep-alive session, an empty body included (Content-Length:
    // 0), or the client waits for bytes that never come.
    const int status = std::atoi(resp.startLine.c_str() + std::min<size_t>(9, resp.startLine.size()));
    const bool bodyless = (status >= 100 && status < 200) || status == 204 || status == 304;
    if (!hasLength && !chunked && !bodyless) head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    return head + body;
}

// A plain request rewritten for an upstream HTTP proxy: absolute-form target
// ("GET http://host:port/path HTTP/1.1") and the proxy's credentials.
std::string toAbsoluteForm(const std::string& raw, const std::string& host, int port, const std::string& auth) {
    const size_t eol = raw.find("\r\n");
    if (eol == std::string::npos) return raw;
    const std::string line = raw.substr(0, eol);
    const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
    if (sp1 == std::string::npos || sp2 <= sp1) return raw;
    const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const bool v6 = host.find(':') != std::string::npos;
    const std::string authority = (v6 ? "[" + host + "]" : host) + (port == 80 ? "" : ":" + std::to_string(port));
    std::string out = line.substr(0, sp1 + 1) + (target.rfind("http://", 0) == 0 ? target : "http://" + authority + target) +
                      line.substr(sp2) + "\r\n";
    if (!auth.empty()) out += "Proxy-Authorization: Basic " + codec::base64Encode(auth) + "\r\n";
    out.append(raw, eol + 2, std::string::npos);
    return out;
}

constexpr size_t kMaxDecoded = 16u << 20;  // a decoded body is cut here (decompression bombs)

// Brotli / zstd bodies. `complete`: the stream ended properly (a capped
// capture decodes partially). False when nothing could be decoded.
bool brotliDecode(const std::string& in, std::string& out, bool& complete) {
    BrotliDecoderState* s = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!s) return false;
    size_t availIn = in.size();
    const uint8_t* next = reinterpret_cast<const uint8_t*>(in.data());
    uint8_t buf[65536];
    BrotliDecoderResult r;
    do {
        size_t availOut = sizeof buf;
        uint8_t* o = buf;
        r = BrotliDecoderDecompressStream(s, &availIn, &next, &availOut, &o, nullptr);
        out.append(reinterpret_cast<const char*>(buf), sizeof buf - availOut);
    } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT && out.size() < kMaxDecoded);
    BrotliDecoderDestroyInstance(s);
    complete = r == BROTLI_DECODER_RESULT_SUCCESS;
    return complete || (r != BROTLI_DECODER_RESULT_ERROR && !out.empty());
}

bool zstdDecode(const std::string& in, std::string& out, bool& complete) {
    ZSTD_DCtx* d = ZSTD_createDCtx();
    if (!d) return false;
    ZSTD_inBuffer src{in.data(), in.size(), 0};
    char buf[65536];
    size_t rc = 1;
    bool error = false;
    while (out.size() < kMaxDecoded) {
        ZSTD_outBuffer dst{buf, sizeof buf, 0};
        rc = ZSTD_decompressStream(d, &dst, &src);
        if (ZSTD_isError(rc)) {
            error = true;
            break;
        }
        out.append(buf, dst.pos);
        if (src.pos == src.size && dst.pos < sizeof buf) break;  // input used up, output drained
    }
    ZSTD_freeDCtx(d);
    complete = !error && rc == 0;
    return complete || (!error && !out.empty());
}

// Reads until `buf` holds at least `n` bytes (it may already hold some).
bool readExact(Socket& s, std::string& buf, size_t n) {
    char chunk[4096];
    while (buf.size() < n) {
        if (!s.waitReadable(15000)) return false;
        const long got = s.recvSome(chunk, sizeof chunk);
        if (got <= 0) return false;
        buf.append(chunk, static_cast<size_t>(got));
    }
    return true;
}

// A client stream under the network conditions' bandwidth caps.
class ThrottledStream final : public net::Stream {
public:
    ThrottledStream(net::Stream& inner, std::function<void(size_t, bool)> pace) : s_(inner), pace_(std::move(pace)) {}
    bool waitReadable(int ms) override { return s_.waitReadable(ms); }
    long recvSome(void* buf, size_t len) override {
        const long n = s_.recvSome(buf, len);
        if (n > 0) pace_(static_cast<size_t>(n), false);
        return n;
    }
    bool sendAll(const void* buf, size_t len) override {
        const char* p = static_cast<const char*>(buf);
        while (len > 0) {  // in slices, so the pacing is smooth
            const size_t n = std::min<size_t>(len, 8192);
            if (!s_.sendAll(p, n)) return false;
            pace_(n, true);
            p += n;
            len -= n;
        }
        return true;
    }
    void shutdown() override { s_.shutdown(); }
    using Stream::sendAll;

private:
    net::Stream& s_;
    std::function<void(size_t, bool)> pace_;
};

}  // namespace

std::string TrafficProxy::Message::header(const std::string& name) const {
    for (const auto& h : headers)
        if (tex::asciiIEqual(h.first, name)) return h.second;
    return {};
}

std::string TrafficProxy::Flow::url() const {
    if (!transport.empty()) {  // raw TCP / UDP: scheme://host:port, a DNS name after it
        const std::string scheme = method == "DNS" ? "dns" : transport;
        const bool v6 = host.find(':') != std::string::npos;
        return scheme + "://" + (v6 ? "[" + host + "]" : host) + ":" + std::to_string(port) + (path.empty() ? "" : " " + path);
    }
    if (tunnel) return "https://" + (sni.empty() ? host : sni) + (port == 443 ? "" : ":" + std::to_string(port));
    if (https)  // the name the app asked for, not the tunnel's address
        return "https://" + (sni.empty() ? host : sni) + (port == 443 ? "" : ":" + std::to_string(port)) + path;
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
    {
        std::lock_guard<std::mutex> lock(interceptMutex_);
        interceptCv_.notify_all();  // held messages go on unchanged
    }
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
    while (flows_.size() > maxFlows_.load()) flows_.pop_front();  // bounded history
    return f;
}

void TrafficProxy::finish(const std::shared_ptr<Flow>& f, std::chrono::steady_clock::time_point t0) {
    Flow copy;
    bool failed;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        f->durationMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        f->complete = true;
        failed = !f->error.empty() || !f->tlsError.empty();
        if (failed) copy = *f;
    }
    if (!failed) return;
    std::shared_ptr<Hooks> hooks;
    {
        std::lock_guard<std::mutex> lock(modeMutex_);
        hooks = hooks_;
    }
    if (hooks && hooks->wantsErrors()) hooks->onError(copy);
}

void TrafficProxy::serve(std::shared_ptr<Socket> client) {
    std::string head, rest;
    // The first byte tells the protocols apart: 0x05 opens a SOCKS5 greeting,
    // anything else is an HTTP request line.
    if (!client->waitReadable(kIdleMs)) return;
    {
        char chunk[16384];
        const long n = client->recvSome(chunk, sizeof chunk);
        if (n <= 0) return;
        rest.assign(chunk, static_cast<size_t>(n));
    }
    if (static_cast<unsigned char>(rest[0]) == 0x05) {
        serveSocks(client, std::move(rest));
        return;
    }
    net::PlainStream first(*client);
    if (!readHead(first, head, rest)) return;
    Message req;
    if (!parseHead(head, req)) return;
    const std::string& line = req.startLine;
    const size_t sp1 = line.find(' '), sp2 = line.rfind(' ');
    if (sp1 == std::string::npos || sp2 <= sp1) {
        client->sendAll("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    const std::string method = line.substr(0, sp1);
    const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (iequals(method, "CONNECT")) {
        const size_t colon = target.rfind(':');
        const std::string host = target.substr(0, colon);
        const int port = colon == std::string::npos ? 443 : std::atoi(target.c_str() + colon + 1);
        if (host.empty() || port <= 0 || port > 65535) {
            auto flow = newFlow();
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = method;
            flow->tunnel = true;
            flow->error = "unparsable CONNECT target";
            flow->complete = true;
            return;
        }
        // With a CA the CONNECT is intercepted (the TLS is terminated here and
        // the HTTP inside decrypted); without one the bytes go through blind.
        std::shared_ptr<ca::Store> ca;
        {
            std::lock_guard<std::mutex> lock(caMutex_);
            ca = ca_;
        }
        if (ca && running_.load() && interceptsHost(host)) serveHttps(*client, host, port, std::move(rest));
        else {
            auto flow = newFlow();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->method = method;
                flow->tunnel = true;
                flow->host = host;
                flow->port = port;
                flow->request = req;
            }
            serveTunnel(*client, flow, std::move(rest));
        }
        return;
    }
    // Plain HTTP: one exchange per connection, as before.
    auto flow = newFlow();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = method;
        flow->request = req;
    }
    net::PlainStream plain(*client);
    ThrottledStream stream(plain, [this](size_t n, bool down) { pace(n, down); });
    const auto t0 = std::chrono::steady_clock::now();
    serveExchange(stream, flow, nullptr, head + "\r\n\r\n" + rest, false);
    finish(flow, t0);
}

// Relay both directions of a blind tunnel; whichever side closes first ends it.
void TrafficProxy::relayTunnelBytes(Socket& client, Socket& upstream, const std::shared_ptr<Flow>& flow, bool record) {
    // Each read is one "message" of the stream when its bytes are kept.
    const auto keep = [&](const char* data, long n, bool fromClient) {
        if (record) {
            WsFrame fr;
            fr.fromClient = fromClient;
            fr.opcode = 2;
            fr.size = static_cast<uint64_t>(n);
            fr.preview.assign(data, std::min<size_t>(static_cast<size_t>(n), kMaxWsPayload));
            fr.truncated = static_cast<size_t>(n) > kMaxWsPayload;
            fr.at = unixNow();
            recordWs(flow, std::move(fr), static_cast<uint64_t>(n));
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        (fromClient ? flow->bytesUp : flow->bytesDown) += static_cast<uint64_t>(n);
    };
    std::thread up([&] {
        char buf[65536];
        for (;;) {
            const long n = client.recvSome(buf, sizeof buf);
            if (n <= 0 || !upstream.sendAll(buf, static_cast<size_t>(n))) break;
            pace(static_cast<size_t>(n), false);
            keep(buf, n, true);
        }
        upstream.shutdownBoth();
        client.shutdownBoth();
    });
    char buf[65536];
    for (;;) {
        const long n = upstream.recvSome(buf, sizeof buf);
        if (n <= 0 || !client.sendAll(buf, static_cast<size_t>(n))) break;
        pace(static_cast<size_t>(n), true);
        keep(buf, n, false);
    }
    client.shutdownBoth();
    upstream.shutdownBoth();
    up.join();
}

void TrafficProxy::serveTunnel(Socket& client, std::shared_ptr<Flow> flow, std::string pending, bool established) {
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
    if (!connectOut(upstream, host, port, true, error)) {
        if (!established) client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        std::lock_guard<std::mutex> lock(mutex_);
        flow->error = error;
        flow->status = 502;
        flow->complete = true;
        return;
    }
    if (!established) client.sendAll("HTTP/1.1 200 Connection Established\r\n\r\n");
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
    // Not TLS: a readable protocol, whose bytes are kept on the flow.
    const bool readable = !pending.empty() && !(pending.size() >= 3 && static_cast<unsigned char>(pending[0]) == 0x16 &&
                                                 static_cast<unsigned char>(pending[1]) == 0x03);
    if (!pending.empty()) {
        const std::string sni = parseSni(reinterpret_cast<const uint8_t*>(pending.data()), pending.size());
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->sni = sni;
            if (readable) flow->transport = "tcp";
        }
        if (readable) {
            WsFrame fr;
            fr.fromClient = true;
            fr.opcode = 2;
            fr.size = pending.size();
            fr.preview = pending.substr(0, kMaxWsPayload);
            fr.at = unixNow();
            recordWs(flow, std::move(fr), pending.size());
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->bytesUp += pending.size();
        }
    }
    if (!pending.empty() && !upstream.sendAll(pending)) {
        finish(flow, t0);
        return;
    }
    if (readable && pending.compare(0, std::min(pending.size(), http2::kPrefaceLen), http2::kPreface,
                                    std::min(pending.size(), http2::kPrefaceLen)) == 0 && pending.size() >= 3) {
        // Plain-text HTTP/2 through the tunnel: its streams become flows.
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->wsFrames.clear();
            flow->wsKept = 0;
            flow->transport.clear();
        }
        net::PlainStream c(client), u(upstream);
        relayH2c(c, u, host, port, pending, flow);
        finish(flow, t0);
        return;
    }
    relayTunnelBytes(client, upstream, flow, readable);
    finish(flow, t0);
}

// ---------------------------------------------------------------------------
// HTTPS interception
// ---------------------------------------------------------------------------

void TrafficProxy::serveHttps(Socket& client, const std::string& connectHost, int port, std::string pending,
                              bool established) {
    const auto t0 = std::chrono::steady_clock::now();
    std::shared_ptr<ca::Store> ca;
    {
        std::lock_guard<std::mutex> lock(caMutex_);
        ca = ca_;
    }
    if (!ca) return;  // interception turned off while queued
    // The tunnel is up before anything else: the app only starts its TLS
    // handshake after the 200.
    if (!established && !client.sendAll("HTTP/1.1 200 Connection Established\r\n\r\n")) return;
    // First bytes = the TLS ClientHello (usually already in `pending`).
    if (pending.empty() && client.waitReadable(10000)) {
        char chunk[16384];
        const long n = client.recvSome(chunk, sizeof chunk);
        if (n == 0) return;  // the app gave up on the tunnel
        if (n > 0) pending.assign(chunk, static_cast<size_t>(n));
    }
    // Not TLS (0x16 0x03 = handshake record, version 3.x), or nothing at all
    // (a protocol where the server speaks first: SMTP, FTP, databases...):
    // relay it blindly, as a tunnel, exactly as without interception.
    if (pending.size() < 3 || static_cast<unsigned char>(pending[0]) != 0x16 ||
        static_cast<unsigned char>(pending[1]) != 0x03) {
        auto flow = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "CONNECT";
            flow->tunnel = true;
            flow->host = connectHost;
            flow->port = port;
            flow->note = pending.empty() ? "the app sent nothing first (a server-first protocol?) - relayed as a raw TCP stream"
                                         : "not a TLS connection - relayed as a raw TCP stream";
            flow->transport = "tcp";
        }
        if (!pending.empty()) {
            WsFrame fr;
            fr.fromClient = true;
            fr.opcode = 2;
            fr.size = pending.size();
            fr.preview = pending.substr(0, kMaxWsPayload);
            fr.at = unixNow();
            recordWs(flow, std::move(fr), pending.size());
        }
        Socket upstream;
        std::string error;
        if (connectOut(upstream, connectHost, port, true, error) && (pending.empty() || upstream.sendAll(pending))) {
            relayTunnelBytes(client, upstream, flow, true);
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error += "; upstream connection failed: " + error;
        }
        finish(flow, t0);
        return;
    }

    // A leaf certificate for the name the app asked for (SNI), or the CONNECT
    // host when the ClientHello carries no SNI.
    const std::string sni = parseSni(reinterpret_cast<const uint8_t*>(pending.data()), pending.size());
    const std::string host = sni.empty() ? connectHost : sni;
    std::string error;
    // The server name is known only now: an ignored (or not allowed) one is
    // relayed blind, as a tunnel.
    if (!interceptsHost(host)) {
        auto flow = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "CONNECT";
            flow->tunnel = true;
            flow->host = connectHost;
            flow->port = port;
            flow->sni = sni;
            flow->status = 200;
            flow->note = "ignored host - relayed without decrypting";
            flow->bytesUp = pending.size();
        }
        Socket upstream;
        if (connectOut(upstream, connectHost, port, true, error) && upstream.sendAll(pending)) relayTunnelBytes(client, upstream, flow);
        else {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = "upstream connection failed: " + error;
        }
        finish(flow, t0);
        return;
    }
    const std::shared_ptr<const tls::Identity> leaf = ca->leafFor(host, error);
    if (!leaf) {
        auto flow = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "CONNECT";
            flow->host = connectHost;
            flow->port = port;
            flow->sni = sni;
            flow->https = true;
            flow->error = "could not sign a certificate for " + host + ": " + error;
            flow->complete = true;
        }
        client.shutdownBoth();
        return;
    }

    // TLS with the app, presenting the leaf. The ClientHello was pre-read for
    // its server name - feed it back before the handshake.
    tls::Connection tls;
    tls.pushBack(pending.data(), pending.size());
    std::string note;
    if (!tls.accept(client, *leaf, 15000, error, note)) {
        // The app refused: pinning, an untrusted CA, a TLS version we did not
        // offer... Record the reason instead of a silent failure.
        auto flow = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "CONNECT";
            flow->host = connectHost;
            flow->port = port;
            flow->sni = sni;
            flow->https = true;  // an interception was attempted
            flow->tlsError = note.empty() ? error : note;
            flow->error = "TLS handshake with the app failed: " + error;
            flow->complete = true;
        }
        client.shutdownBoth();
        return;
    }

    // HTTP exchanges over the TLS session, until the app closes it.
    net::TlsStream tlsStream(client, tls);
    ThrottledStream clientStream(tlsStream, [this](size_t n, bool down) { pace(n, down); });
    const std::string tlsVersion = tls.version(), tlsCipher = tls.cipher(), alpn = tls.alpn();
    Flow preset;  // what every exchange on this session carries
    preset.https = true;
    preset.host = connectHost;
    preset.port = port;
    preset.sni = sni;
    preset.tlsVersion = tlsVersion;
    preset.tlsCipher = tlsCipher;
    preset.alpn = alpn;
    std::string carry;  // bytes of the next request that arrived with the previous one
    for (;;) {
        std::shared_ptr<Flow> flow;  // created when the next request arrives
        const auto ex0 = std::chrono::steady_clock::now();
        std::string pending = std::move(carry);
        carry.clear();
        const bool more = serveExchange(clientStream, flow, &preset, std::move(pending), true, &carry);
        if (flow) finish(flow, ex0);  // an idle session that never sends again leaves no empty row
        if (!more || !running_.load()) break;
    }
    tls.close();
}

bool TrafficProxy::serveExchange(net::Stream& client, std::shared_ptr<Flow>& flow, const Flow* preset,
                                 std::string pending, bool persistent, std::string* leftover) {
    // ---- Request -------------------------------------------------------
    std::string head, rest = std::move(pending);
    if (!readHead(client, head, rest)) return false;
    // The h2 client preface: the app insists on HTTP/2, which this proxy
    // cannot decrypt (it negotiates http/1.1 through ALPN).
    if (head.rfind("PRI * HTTP/2.0", 0) == 0 && !preset) {
        // Plain-text HTTP/2 with prior knowledge: only a reverse proxy knows
        // where it goes (a forward proxy request names no server).
        const Mode m = mode();
        flow = flow ? flow : newFlow();
        std::string error;
        if (!m.reverse() || m.reverseTls) {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "PRI";
            flow->error = m.reverseTls ? "plain-text HTTP/2 (h2c) to an https:// reverse target is not supported"
                                       : "plain-text HTTP/2 (h2c) needs reverse mode (Settings > Network) to know its server";
            flow->complete = true;
            return false;
        }
        Socket up;
        if (!connectOut(up, m.reverseHost, m.reversePort, false, error)) {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "PRI";
            flow->error = error;
            flow->complete = true;
            return false;
        }
        const std::string seed = head + "\r\n\r\n" + rest;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "PRI";
            flow->host = m.reverseHost;
            flow->port = m.reversePort;
            flow->alpn = "h2c";
        }
        net::PlainStream upStream(up);
        if (up.sendAll(seed)) relayH2c(client, upStream, m.reverseHost, m.reversePort, seed, flow);
        return false;
    }
    // A client preface inside a decrypted HTTPS exchange (the app negotiated h2
    // over TLS): the preset knows the server, so relay it as h2c would be but
    // over the established tunnel and decode it passively.
    if (head.rfind("PRI * HTTP/2.0", 0) == 0 && preset && preset->https) {
        flow = flow ? flow : newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = "PRI";
            flow->https = true;
            flow->host = preset->host;
            flow->port = preset->port;
            flow->sni = preset->sni;
            flow->tlsVersion = preset->tlsVersion;
            flow->tlsCipher = preset->tlsCipher;
            flow->alpn = "h2";
        }
        const std::string seed = head + "\r\n\r\n" + rest;
        if (!client.sendAll(seed)) return false;
        relayH2c(client, client, preset->host, preset->port, seed, flow);
        return false;
    }
    if (head.rfind("PRI * HTTP/2.0", 0) == 0) {
        flow = flow ? flow : newFlow();  // a persistent session's flow exists only now
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = "PRI";
        if (preset) {
            flow->https = preset->https;
            flow->host = preset->host;
            flow->port = preset->port;
            flow->sni = preset->sni;
            flow->tlsVersion = preset->tlsVersion;
            flow->tlsCipher = preset->tlsCipher;
            flow->alpn = preset->alpn;
        }
        flow->error = "the app speaks HTTP/2 over this connection; ApkSpy's HTTPS proxy decodes HTTP/1.1 (it offers "
                      "http/1.1 in ALPN - an app that still sends h2 cannot be inspected)";
        flow->complete = true;
        return false;
    }
    Message req;
    if (!parseHead(head, req)) {
        flow = flow ? flow : newFlow();
        std::lock_guard<std::mutex> lock(mutex_);
        flow->error = "malformed request head";
        flow->complete = true;
        return false;
    }
    if (!flow) {  // a request arrived on a persistent TLS session: its flow exists from here
        flow = newFlow();
        if (preset) {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->https = preset->https;
            flow->host = preset->host;
            flow->port = preset->port;
            flow->sni = preset->sni;
            flow->tlsVersion = preset->tlsVersion;
            flow->tlsCipher = preset->tlsCipher;
            flow->alpn = preset->alpn;
        }
    }
    const size_t sp1 = req.startLine.find(' '), sp2 = req.startLine.rfind(' ');
    std::string method, path;
    if (sp1 != std::string::npos && sp2 > sp1) {
        method = req.startLine.substr(0, sp1);
        path = req.startLine.substr(sp1 + 1, sp2 - sp1 - 1);
    } else {
        method = req.startLine;
        path = "/";
    }
    // Host/port: absolute form (proxy request) or the Host header. An
    // intercepted flow already knows host/port from the CONNECT.
    std::string hostPort;
    if (path.rfind("http://", 0) == 0) {
        const size_t slash = path.find('/', 7);
        hostPort = path.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
        path = slash == std::string::npos ? "/" : path.substr(slash);
    } else {
        hostPort = req.header("host");
    }
    Mode mode;
    std::shared_ptr<Hooks> hooks;
    {
        std::lock_guard<std::mutex> lock(modeMutex_);
        mode = mode_;
        hooks = hooks_;
    }
    std::string host = hostPort;
    int port = 80;
    {
        const size_t colon = hostPort.rfind(':');
        if (colon != std::string::npos && hostPort.find(':', colon + 1) == std::string::npos &&
            hostPort.find(']') == std::string::npos) {
            host = hostPort.substr(0, colon);
            port = std::atoi(hostPort.c_str() + colon + 1);
        }
        if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    }
    // Reverse proxy: whatever the app asked for goes to the one configured
    // server (a decrypted CONNECT keeps its own target).
    const bool reverse = mode.reverse() && !flow->https;
    if (reverse) {
        host = mode.reverseHost;
        port = mode.reversePort;
    }
    if (host.empty() || port <= 0 || port > 65535) {
        client.sendAll("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = method;
        flow->request = req;
        flow->error = "unparsable request target";
        flow->complete = true;
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = method;
        flow->request = req;
        if (reverse) {
            flow->host = host;
            flow->port = port;
            flow->https = mode.reverseTls;  // TLS to the server (the app spoke plain HTTP to us)
            flow->sni = mode.reverseTls ? host : std::string();
        } else if (!flow->https) {
            flow->host = host;
            flow->port = port;
        }
        flow->path = path;
    }
    const std::string url = flow->url();

    // Request body (Content-Length or chunked), read completely first. Bytes
    // past its end belong to the client's next request.
    std::string body = std::move(rest);
    std::string extra;
    const std::string te = tex::asciiLower(req.header("transfer-encoding"));
    const std::string cl = req.header("content-length");
    if (te.find("chunked") != std::string::npos) {
        while (chunkedLength(body) == std::string::npos)
            if (body.size() > kMaxRequestBody || !readMore(client, body)) break;
        const size_t len = chunkedLength(body);
        if (len != std::string::npos && len < body.size()) {
            extra = body.substr(len);
            body.resize(len);
        }
    } else if (!cl.empty()) {
        const unsigned long long want = std::strtoull(cl.c_str(), nullptr, 10);
        if (want > kMaxRequestBody) {
            client.sendAll("HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            std::lock_guard<std::mutex> lock(mutex_);
            flow->status = 413;
            flow->error = "request body too large for the sniffer";
            flow->complete = true;
            return false;
        }
        while (body.size() < want)
            if (!readMore(client, body)) break;
        if (body.size() > want) {
            extra = body.substr(static_cast<size_t>(want));
            body.resize(static_cast<size_t>(want));
        }
    } else {
        // No Content-Length, not chunked: a request without a body.
        extra = std::move(body);
        body.clear();
    }
    if (leftover) *leftover = extra;  // (also seeds a WebSocket relay below)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->request.body.clear();
        flow->request.bodySize = 0;
        capture(flow->request, body.data(), body.size());
        flow->bytesUp = body.size();
    }

    // Origin-form request; hop-by-hop proxy headers dropped, one request per
    // upstream connection (Connection: close) so the response ends with the stream.
    const size_t sp2r = req.startLine.rfind(' ');
    std::string out = method + " " + path + req.startLine.substr(sp2r) + "\r\n";
    bool hasHost = false;
    for (const auto& h : req.headers) {
        if (iequals(h.first, "proxy-connection") || iequals(h.first, "proxy-authorization") ||
            iequals(h.first, "connection") || iequals(h.first, "keep-alive"))
            continue;
        // WebSocket compression (permessage-deflate) is not offered upstream,
        // so frames stay readable, editable and injectable.
        if (iequals(h.first, "sec-websocket-extensions")) continue;
        if (iequals(h.first, "host")) {
            hasHost = true;
            if (reverse) {  // the server's own name, not the proxy's address the app used
                const bool defaultPort = port == (mode.reverseTls ? 443 : 80);
                out += h.first + ": " + host + (defaultPort ? "" : ":" + std::to_string(port)) + "\r\n";
                continue;
            }
        }
        out += h.first + ": " + h.second + "\r\n";
    }
    if (!hasHost)
        out += "Host: " + host + ((flow->https && flow->port == 443) || (!flow->https && port == 80) ? ""
                                                                                                      : ":" + std::to_string(flow->https ? flow->port : port)) +
               "\r\n";
    // An Upgrade (WebSocket...) needs "Connection: Upgrade" or the server
    // refuses it; everything else is one request per upstream connection.
    out += req.header("upgrade").empty() ? "Connection: close\r\n\r\n" : "Connection: Upgrade\r\n\r\n";
    out += body;

    // The request as it goes out, recorded when match & replace or the intercept changed it.
    const auto recordRequest = [&] {
        Message edited;
        const size_t headEnd = out.find("\r\n\r\n");
        if (headEnd == std::string::npos || !parseHead(out.substr(0, headEnd + 2), edited)) return;
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t s1 = edited.startLine.find(' '), s2 = edited.startLine.rfind(' ');
        if (s1 != std::string::npos && s2 > s1) {
            flow->method = method = edited.startLine.substr(0, s1);
            flow->path = edited.startLine.substr(s1 + 1, s2 - s1 - 1);
        }
        flow->request = edited;
        // Plain HTTP follows an edited Host header (a script or the intercept
        // redirecting the request); TLS flows are already bound to their server.
        if (!flow->https && !reverse && edited.header("host") != req.header("host")) {
            std::string hp = edited.header("host");
            while (!hp.empty() && hp.back() == ' ') hp.pop_back();
            int newPort = 80;
            const size_t c = hp.rfind(':');
            if (c != std::string::npos && hp.find(']', c) == std::string::npos) {
                newPort = std::atoi(hp.c_str() + c + 1);
                hp.resize(c);
            }
            if (hp.size() > 2 && hp.front() == '[' && hp.back() == ']') hp = hp.substr(1, hp.size() - 2);
            if (!hp.empty() && newPort > 0 && newPort < 65536) {
                flow->host = hp;
                flow->port = newPort;
            }
        }
        capture(flow->request, out.data() + headEnd + 4, out.size() - headEnd - 4);
        flow->bytesUp = out.size() - headEnd - 4;
        flow->edited = true;
    };
    std::shared_ptr<const matchreplace::RuleSet> rules;
    {
        std::lock_guard<std::mutex> lock(rulesMutex_);
        rules = rules_;
    }
    if (rules) {
        std::vector<int> hits;
        if (rules->apply(false, out, &hits) > 0) {
            out = withConnectionClose(out);
            recordRequest();
            countHits(hits);
        }
    }

    // Answers the app without contacting the server (a script, map local,
    // server replay); `note` says who answered.
    const auto answerLocally = [&](std::string reply, const std::string& note) {
        reply = httpclient::prepare(reply, true);
        Message resp;
        const size_t headEnd = reply.find("\r\n\r\n");
        if (headEnd == std::string::npos || !parseHead(reply.substr(0, headEnd + 2), resp)) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->error = note + ": malformed response";
                flow->complete = true;
            }
            client.shutdown();
            return false;
        }
        const std::string sent = persistent ? reframeForClient(reply, resp) : withConnectionClose(reply);
        const bool ok = client.sendAll(sent);
        std::lock_guard<std::mutex> lock(mutex_);
        flow->response = resp;
        capture(flow->response, reply.data() + headEnd + 4, reply.size() - headEnd - 4);
        flow->status = std::atoi(resp.startLine.c_str() + std::min<size_t>(9, resp.startLine.size()));
        flow->bytesDown = reply.size() - headEnd - 4;
        flow->edited = true;
        flow->note = note + " (the server was not contacted)";
        return ok && persistent;
    };

    // Scripts see the request after match & replace, before the intercept.
    if (hooks) {
        Flow snapshot;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snapshot = *flow;
        }
        std::string reply;
        std::string changed = out;
        const Hooks::Verdict v = hooks->onRequest(snapshot, changed, reply);
        if (v == Hooks::Verdict::Kill) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->error = "killed by a script";
                flow->edited = true;
                flow->complete = true;
            }
            client.shutdown();
            return false;
        }
        if (v == Hooks::Verdict::Modified && !changed.empty() && changed != out) {
            out = withConnectionClose(httpclient::prepare(changed, false));
            recordRequest();
        }
        if (v == Hooks::Verdict::Respond) return answerLocally(reply, "answered by a script");
    }

    // Intercept: the request waits for the user here.
    bool holdRequest, holdResponse;
    {
        std::lock_guard<std::mutex> lock(interceptMutex_);
        holdRequest = interceptMatches(false, url);
        holdResponse = interceptMatches(true, url);
    }
    if (holdRequest) {
        auto w = std::make_shared<Waiter>();
        w->held = {0, flow->id, false, url, out};
        if (!hold(w)) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->error = "request dropped at the intercept";
                flow->complete = true;
            }
            client.shutdown();
            return false;
        }
        if (w->raw != out) {
            out = withConnectionClose(w->raw);
            recordRequest();
        }
    }

    // Map local / server replay answer here; map remote changes the target.
    {
        std::string reply, why;
        if (localAnswer(method, flow->url(), reply, why)) return answerLocally(reply, why);
        Routing r;
        {
            std::lock_guard<std::mutex> lock(modeMutex_);
            r = routing_;
        }
        const std::string cur = flow->url();
        for (const auto& m : r.mapRemote) {
            if (!m.enabled || m.from.empty() || cur.size() < m.from.size() || !tex::asciiIEqual(cur.substr(0, m.from.size()), m.from))
                continue;
            const std::string target = m.to + cur.substr(m.from.size());
            const size_t schemeEnd = target.find("://");
            if (schemeEnd == std::string::npos) break;
            const bool tlsTarget = tex::asciiLower(target.substr(0, schemeEnd)) == "https";
            const size_t slash = target.find('/', schemeEnd + 3);
            std::string hp = target.substr(schemeEnd + 3, slash == std::string::npos ? std::string::npos : slash - schemeEnd - 3);
            const std::string newPath = slash == std::string::npos ? "/" : target.substr(slash);
            int newPort = tlsTarget ? 443 : 80;
            const size_t c = hp.rfind(':');
            if (c != std::string::npos && hp.find(']', c) == std::string::npos) {
                newPort = std::atoi(hp.c_str() + c + 1);
                hp.resize(c);
            }
            if (hp.size() > 2 && hp.front() == '[' && hp.back() == ']') hp = hp.substr(1, hp.size() - 2);
            if (hp.empty() || newPort <= 0 || newPort > 65535) break;
            // The request line and Host header follow the new target.
            const size_t eol = out.find("\r\n");
            const std::string line = out.substr(0, eol);
            const size_t s1 = line.find(' '), s2 = line.rfind(' ');
            if (s1 == std::string::npos || s2 <= s1) break;
            std::string rebuilt = line.substr(0, s1 + 1) + newPath + line.substr(s2) + "\r\n";
            const bool defaultPort = newPort == (tlsTarget ? 443 : 80);
            const std::string hostValue = hp + (defaultPort ? "" : ":" + std::to_string(newPort));
            size_t pos = eol + 2;
            const size_t headEnd = out.find("\r\n\r\n");
            while (pos < headEnd + 2) {
                const size_t e = out.find("\r\n", pos);
                const std::string hline = out.substr(pos, e - pos);
                rebuilt += tex::asciiLower(hline.substr(0, hline.find(':'))) == "host" ? "Host: " + hostValue : hline;
                rebuilt += "\r\n";
                pos = e + 2;
            }
            out = rebuilt + out.substr(headEnd + 2);
            std::lock_guard<std::mutex> lock(mutex_);
            flow->host = hp;
            flow->port = newPort;
            flow->https = tlsTarget;
            flow->sni = tlsTarget ? hp : std::string();
            flow->path = newPath;
            flow->edited = true;
            flow->note = "map remote: " + cur + " -> " + target;
            break;
        }
    }

    // ---- Upstream ------------------------------------------------------
    Socket upstreamSock;
    std::string error;
    if (!connectOut(upstreamSock, flow->host, flow->port, flow->https, error)) {
        client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = error;
            flow->status = 502;
            flow->complete = true;
        }
        return false;
    }
    net::Stream* upstream = nullptr;
    net::PlainStream plainUpstream(upstreamSock);
    std::unique_ptr<tls::Connection> upstreamTls;
    std::unique_ptr<net::TlsStream> tlsUpstream;
    if (flow->https) {
        // Re-encrypt to the real server, verifying its certificate.
        std::shared_ptr<tls::TrustStore> roots;
        bool verify = true;
        {
            std::lock_guard<std::mutex> lock(caMutex_);
            roots = upstreamRoots_;
            verify = verifyUpstream_;
        }
        const std::string sniHost = flow->sni.empty() ? flow->host : flow->sni;
        upstreamTls = std::make_unique<tls::Connection>();
        if (!upstreamTls->connect(upstreamSock, sniHost, roots.get(), verify, 15000, error)) {
            client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->error = "upstream TLS to " + sniHost + " failed: " + error;
                flow->tlsError = "upstream: " + error;
                flow->status = 502;
                flow->complete = true;
            }
            return false;
        }
        tlsUpstream = std::make_unique<net::TlsStream>(upstreamSock, *upstreamTls);
        upstream = tlsUpstream.get();
    } else {
        upstream = &plainUpstream;
    }
    // Through an upstream proxy, plain HTTP goes out in absolute form.
    if (!flow->https && mode.chained()) out = toAbsoluteForm(out, flow->host, flow->port, mode.upstreamAuth);
    if (!upstream->sendAll(out)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = "upstream write failed";
            flow->complete = true;
        }
        return false;
    }

    // ---- Response ------------------------------------------------------
    const bool wantsWebSocket = tex::asciiLower(req.header("upgrade")).find("websocket") != std::string::npos;
    // The whole response when it must be rewritten or held; streamed to the
    // app as it arrives otherwise.
    const bool hookResponses = hooks && hooks->wantsResponses();
    if (holdResponse || hookResponses || (rules && rules->appliesTo(true))) {
        httpclient::Result r;
        httpclient::readResponse(*upstream, method, r, kIdleMs);
        if (r.response.startLine.empty()) {
            client.sendAll("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = r.error.empty() ? "no response" : r.error;
            flow->status = 502;
            flow->complete = true;
            return false;
        }
        if (r.status == 101 && wantsWebSocket) {
            // The 101 (held or not) goes on, then the frames relay.
            std::string sent = httpclient::rawMessage(r.response);
            if (holdResponse) {
                auto w = std::make_shared<Waiter>();
                w->held = {0, flow->id, true, url, sent};
                if (!hold(w)) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    flow->error = "response dropped at the intercept";
                    flow->response = r.response;
                    flow->status = r.status;
                    flow->complete = true;
                    return false;
                }
                sent = w->raw;
            }
            client.sendAll(sent);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->response = r.response;
                flow->status = 101;
                flow->websocket = true;
            }
            relayWebSockets(client, *upstream, flow, extra, {});
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->complete = true;
            }
            return false;
        }
        const std::string received = httpclient::rawMessage(r.response);
        std::string rewritten = received;
        if (rules) {
            std::vector<int> hits;
            if (rules->apply(true, rewritten, &hits) > 0) countHits(hits);
        }
        if (hookResponses) {
            Flow snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot = *flow;
            }
            snapshot.response = r.response;
            snapshot.status = r.status;
            std::string changed = rewritten;
            const Hooks::Verdict v = hooks->onResponse(snapshot, out, changed);
            if (v == Hooks::Verdict::Kill) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    flow->error = "response killed by a script";
                    flow->response = r.response;
                    flow->status = r.status;
                    flow->edited = true;
                    flow->complete = true;
                }
                client.shutdown();
                return false;
            }
            if (v == Hooks::Verdict::Modified && !changed.empty()) rewritten = httpclient::prepare(changed, false);
        }
        auto w = std::make_shared<Waiter>();
        w->held = {0, flow->id, true, url, rewritten};
        const bool forwarded = holdResponse ? hold(w) : (w->raw = rewritten, true);
        std::string sent = forwarded ? w->raw : std::string();
        if (forwarded && persistent) sent = reframeForClient(sent, r.response);
        if (forwarded) client.sendAll(sent);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!forwarded) {
                flow->error = "response dropped at the intercept";
                flow->response = r.response;
                flow->status = r.status;
            } else {
                Message resp;
                const size_t headEnd = sent.find("\r\n\r\n");
                if (headEnd != std::string::npos && parseHead(sent.substr(0, headEnd + 2), resp)) {
                    flow->response = resp;
                    capture(flow->response, sent.data() + headEnd + 4, sent.size() - headEnd - 4);
                    flow->status = std::atoi(resp.startLine.c_str() + std::min<size_t>(9, resp.startLine.size()));
                }
                flow->edited = flow->edited || sent != received;
                flow->bytesDown = sent.size();
            }
        }
        return forwarded && persistent;
    }

    // Streamed response: read the head, then the body by its framing.
    std::string rhead, rrest;
    Message resp;
    int status = 0;
    for (;;) {  // skip interim 1xx responses
        if (!readHead(*upstream, rhead, rrest)) {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = "no response from " + flow->host;
            flow->complete = true;
            return false;
        }
        if (!parseHead(rhead, resp)) {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->error = "malformed response";
            flow->complete = true;
            return false;
        }
        status = std::atoi(resp.startLine.c_str() + std::min<size_t>(9, resp.startLine.size()));
        if (status >= 100 && status < 200 && status != 101) {
            client.sendAll(rhead + "\r\n\r\n");  // 100 Continue goes straight through
            rrest.clear();
            continue;
        }
        break;  // (101 is a final response: the Upgrade itself)
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->response = resp;
        flow->status = status;
    }
    const bool noBody = iequals(method, "HEAD") || status == 204 || status == 304;
    std::string headOut = resp.startLine + "\r\n";
    for (const auto& h : resp.headers) headOut += h.first + ": " + h.second + "\r\n";
    if (status == 101) {
        if (wantsWebSocket) {
            // 101: no body, no framing. Bytes that arrived with the head are
            // already WebSocket frames - they go through the frame relay.
            {
                std::lock_guard<std::mutex> lock(mutex_);
                flow->websocket = true;
            }
            client.sendAll(headOut + "\r\n");
            relayWebSockets(client, *upstream, flow, extra, rrest);
        } else {
            // Unknown upgrade: relay blindly so it is not broken by us.
            client.sendAll(headOut + "\r\n" + rrest);
            if (!extra.empty()) upstream->sendAll(extra);  // client bytes that came with the request
            std::thread up([&] {
                char buf[65536];
                for (;;) {
                    if (!waitLongLived(client)) break;
                    const long n = client.recvSome(buf, sizeof buf);
                    if (n <= 0 || !upstream->sendAll(buf, static_cast<size_t>(n))) break;
                    std::lock_guard<std::mutex> lock(mutex_);
                    flow->bytesUp += static_cast<uint64_t>(n);
                }
                upstream->shutdown();
                client.shutdown();
            });
            char buf[65536];
            for (;;) {
                if (!waitLongLived(*upstream)) break;
                const long n = upstream->recvSome(buf, sizeof buf);
                if (n <= 0 || !client.sendAll(buf, static_cast<size_t>(n))) break;
                std::lock_guard<std::mutex> lock(mutex_);
                flow->bytesDown += static_cast<uint64_t>(n);
            }
            client.shutdown();
            upstream->shutdown();
            up.join();
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->complete = true;
        }
        return false;
    }

    // Framing: explicit (Content-Length / chunked) or end-of-stream.
    const std::string rcl = resp.header("content-length");
    const std::string rte = tex::asciiLower(resp.header("transfer-encoding"));
    const bool chunked = rte.find("chunked") != std::string::npos;
    uint64_t want = UINT64_MAX;
    if (!rcl.empty()) want = std::strtoull(rcl.c_str(), nullptr, 10);
    if (noBody) want = 0;

    // Persistent clients need a delimited body: an upstream that only closes
    // gets buffered (up to kMaxBody) and sent with a Content-Length.
    if (persistent && want == UINT64_MAX && !chunked && !noBody) {
        std::string buffered = std::move(rrest);
        while (buffered.size() < kMaxBody) {
            char buf[65536];
            if (!upstream->waitReadable(kIdleMs)) break;
            const long n = upstream->recvSome(buf, sizeof buf);
            if (n <= 0) break;
            buffered.append(buf, static_cast<size_t>(n));
        }
        const bool overflowed = buffered.size() >= kMaxBody;
        std::string outHead = resp.startLine + "\r\n";
        for (const auto& h : resp.headers) {
            const std::string name = tex::asciiLower(h.first);
            if (name == "connection" || name == "keep-alive" || name == "proxy-connection" || name == "transfer-encoding")
                continue;
            outHead += h.first + ": " + h.second + "\r\n";
        }
        if (overflowed)
            outHead += "Connection: close\r\n\r\n";
        else
            outHead += "Content-Length: " + std::to_string(buffered.size()) + "\r\n\r\n";
        if (!client.sendAll(outHead) || !client.sendAll(buffered)) return false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            capture(flow->response, buffered.data(), buffered.size());
            flow->bytesDown = buffered.size();
        }
        if (!overflowed) return true;
        // Too big to buffer: the rest streams through and the closed
        // connection ends the body (the head said Connection: close).
        char buf[65536];
        for (;;) {
            if (!upstream->waitReadable(kIdleMs)) break;
            const long n = upstream->recvSome(buf, sizeof buf);
            if (n <= 0 || !client.sendAll(buf, static_cast<size_t>(n))) break;
            std::lock_guard<std::mutex> lock(mutex_);
            capture(flow->response, buf, static_cast<size_t>(n));
            flow->bytesDown += static_cast<uint64_t>(n);
        }
        return false;
    }

    // Explicit framing: forward the head (minus the upstream's close headers
    // for a persistent client), then stream the body.
    client.sendAll(persistent ? reframeForClient(headOut + "\r\n", resp) : headOut + "\r\n");
    client.sendAll(rrest);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        capture(flow->response, rrest.data(), rrest.size());
        flow->bytesDown = rrest.size();
    }
    // The body may already be complete in what came with the head.
    std::string chunkBuf = rrest;  // chunked progress bookkeeping
    uint64_t got = rrest.size();   // body bytes forwarded so far
    bool clean = false;
    if (want != UINT64_MAX && got >= want) clean = true;
    else if (chunked && chunkedLength(chunkBuf) != std::string::npos) clean = true;
    char buf[65536];
    while (!clean) {
        if (!upstream->waitReadable(kIdleMs)) break;
        const long n = upstream->recvSome(buf, sizeof buf);
        if (n <= 0) break;
        if (!client.sendAll(buf, static_cast<size_t>(n))) break;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            capture(flow->response, buf, static_cast<size_t>(n));
            flow->bytesDown += static_cast<uint64_t>(n);
        }
        if (want != UINT64_MAX) {
            got += static_cast<uint64_t>(n);
            if (got >= want) clean = true;  // Content-Length satisfied
        } else if (chunked) {
            chunkBuf.append(buf, static_cast<size_t>(n));
            if (chunkedLength(chunkBuf) != std::string::npos) clean = true;
            else if (chunkBuf.size() > kMaxRequestBody) break;
        }
    }
    return clean && persistent;
}

// ---------------------------------------------------------------------------
// WebSocket relay
// ---------------------------------------------------------------------------

namespace {

// One WebSocket frame header (RFC 6455): opcode, mask, length.
struct WsHeader {
    int opcode = 0;
    bool masked = false;
    uint64_t length = 0;
    unsigned char mask[4] = {0, 0, 0, 0};
    size_t headerLen = 0;
};

bool parseWsHeader(const std::string& b, WsHeader& h) {
    if (b.size() < 2) return false;
    h.opcode = b[0] & 0x0f;
    h.masked = (b[1] & 0x80) != 0;
    uint64_t len = b[1] & 0x7f;
    size_t at = 2;
    if (len == 126) {
        if (b.size() < 4) return false;
        len = (static_cast<uint64_t>(static_cast<unsigned char>(b[2])) << 8) | static_cast<unsigned char>(b[3]);
        at = 4;
    } else if (len == 127) {
        if (b.size() < 10) return false;
        len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | static_cast<unsigned char>(b[at + i]);
        at = 10;
    }
    if (h.masked) {
        if (b.size() < at + 4) return false;
        for (int i = 0; i < 4; ++i) h.mask[i] = static_cast<unsigned char>(b[at + i]);
        at += 4;
    }
    h.length = len;
    h.headerLen = at;
    return true;
}

}  // namespace

// The two streams of a live WebSocket relay, for injection. Each direction's
// writes go through its lock, so an injected frame never lands inside a
// forwarded one.
struct TrafficProxy::WsSession {
    net::Stream* client = nullptr;
    net::Stream* upstream = nullptr;
    std::mutex clientWrite, upstreamWrite;
    bool open = true;  // under both write locks
};

std::string TrafficProxy::wsFrame(int opcode, const std::string& payload, bool mask) {
    std::string f;
    f += static_cast<char>(0x80 | (opcode & 0x0f));
    const uint64_t n = payload.size();
    const char maskBit = mask ? static_cast<char>(0x80) : 0;
    if (n < 126) f += static_cast<char>(maskBit | static_cast<char>(n));
    else if (n < 65536) {
        f += static_cast<char>(maskBit | 126);
        f += static_cast<char>(n >> 8);
        f += static_cast<char>(n & 0xff);
    } else {
        f += static_cast<char>(maskBit | 127);
        for (int i = 7; i >= 0; --i) f += static_cast<char>((n >> (i * 8)) & 0xff);
    }
    if (!mask) return f + payload;
    static std::mt19937 rng{std::random_device{}()};
    static std::mutex rngMutex;
    unsigned char key[4];
    {
        std::lock_guard<std::mutex> lock(rngMutex);
        const uint32_t r = rng();
        std::memcpy(key, &r, 4);
    }
    f.append(reinterpret_cast<const char*>(key), 4);
    for (size_t i = 0; i < payload.size(); ++i) f += static_cast<char>(payload[i] ^ key[i % 4]);
    return f;
}

void TrafficProxy::recordWs(const std::shared_ptr<Flow>& flow, WsFrame frame, uint64_t wireBytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (frame.fromClient) flow->bytesUp += wireBytes;
    else flow->bytesDown += wireBytes;
    if (flow->wsFrames.size() >= kMaxWsFrames) return;
    // Past the per-connection budget only the frame's facts are kept.
    if (flow->wsKept + frame.preview.size() > kMaxWsFlowBytes) {
        frame.truncated = frame.truncated || !frame.preview.empty();
        frame.preview.clear();
    }
    flow->wsKept += frame.preview.size();
    flow->wsFrames.push_back(std::move(frame));
}

// WebSocket frames of one direction, recorded on the flow while relayed.
// Returns when the stream ends (close frame, error or timeout). Whole text /
// binary messages go past the scripts and the intercept when those want
// them; everything else streams through untouched.
void TrafficProxy::relayWsDirection(net::Stream& from, net::Stream& to, std::mutex& toWrite, const std::shared_ptr<Flow>& flow,
                                     bool fromClient, const std::string& seed) {
    std::string buf = seed;
    char chunk[65536];
    const auto more = [&] {
        if (!waitLongLived(from)) return false;
        const long n = from.recvSome(chunk, sizeof chunk);
        if (n <= 0) return false;
        buf.append(chunk, static_cast<size_t>(n));
        return true;
    };
    std::string url;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        url = flow->url();
    }
    for (;;) {
        WsHeader h;
        while (!parseWsHeader(buf, h)) {  // need (more of) the frame header
            if (!more()) return;
            if (buf.size() > 14 + 65536) return;  // no sane header is this long
        }
        const uint64_t total = h.headerLen + h.length;
        const bool fin = (static_cast<unsigned char>(buf[0]) & 0x80) != 0;
        const bool data = h.opcode == 1 || h.opcode == 2;
        std::shared_ptr<Hooks> hooks;
        {
            std::lock_guard<std::mutex> lock(modeMutex_);
            hooks = hooks_;
        }
        const bool hookWs = hooks && hooks->wantsWebSocket();
        bool holdWs;
        {
            std::lock_guard<std::mutex> lock(interceptMutex_);
            holdWs = interceptWs_ && (interceptFilter_.empty() || tex::ciFind(url, interceptFilter_) != std::string_view::npos);
        }
        WsFrame rec;
        rec.fromClient = fromClient;
        rec.opcode = h.opcode;
        rec.size = h.length;
        rec.at = unixNow();
        if (data && fin && h.length <= kMaxWsEditable && (hookWs || holdWs)) {
            // The whole message, then the scripts, then the intercept.
            while (buf.size() < total)
                if (!more()) return;
            std::string payload = buf.substr(static_cast<size_t>(h.headerLen), static_cast<size_t>(h.length));
            if (h.masked)
                for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(payload[i] ^ h.mask[i % 4]);
            buf.erase(0, static_cast<size_t>(total));
            const std::string original = payload;
            bool dropped = false;
            if (hookWs) {
                Flow snapshot;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    snapshot = *flow;
                }
                snapshot.wsFrames.clear();
                const Hooks::Verdict v = hooks->onWebSocket(snapshot, fromClient, h.opcode, payload);
                if (v == Hooks::Verdict::Kill) dropped = true;
            }
            if (!dropped && holdWs) {
                auto w = std::make_shared<Waiter>();
                w->held.flowId = flow->id;
                w->held.response = !fromClient;
                w->held.url = url;
                w->held.raw = payload;
                w->held.websocket = true;
                w->held.wsOpcode = h.opcode;
                if (!hold(w)) dropped = true;
                else payload = w->raw;
            }
            if (!dropped) {
                std::lock_guard<std::mutex> lock(toWrite);
                if (!to.sendAll(wsFrame(h.opcode, payload, fromClient))) return;
            }
            rec.size = payload.size();
            rec.edited = !dropped && payload != original;
            rec.dropped = dropped;
            rec.truncated = payload.size() > kMaxWsPayload;
            rec.preview = payload.substr(0, kMaxWsPayload);
            recordWs(flow, std::move(rec), total);
            continue;
        }
        // Streamed: forwarded as it arrives (a big frame in pieces), under the
        // write lock so an injected frame cannot split it.
        std::unique_lock<std::mutex> writeLock(toWrite);
        const bool frameInBuf = buf.size() >= total;
        uint64_t forwarded = std::min<uint64_t>(buf.size(), total);
        if (forwarded > 0 && !to.sendAll(buf.data(), static_cast<size_t>(forwarded))) return;
        const auto keep = [&](const char* p, uint64_t payloadAt, uint64_t avail) {
            const uint64_t room = kMaxWsPayload > rec.preview.size() ? kMaxWsPayload - rec.preview.size() : 0;
            const size_t take = static_cast<size_t>(std::min<uint64_t>(avail, room));
            for (size_t i = 0; i < take; ++i) {
                char c = p[i];
                if (h.masked) c = static_cast<char>(c ^ h.mask[(payloadAt + i) % 4]);
                rec.preview.push_back(c);
            }
            if (avail > take) rec.truncated = true;
        };
        if (h.length > 0 && buf.size() > h.headerLen)
            keep(buf.data() + h.headerLen, 0, std::min<uint64_t>(h.length, buf.size() - h.headerLen));
        while (forwarded < total) {  // the rest of a big frame
            if (!from.waitReadable(kIdleMs)) return;
            const long n = from.recvSome(chunk, sizeof chunk);
            if (n <= 0) return;
            const uint64_t take = std::min<uint64_t>(static_cast<uint64_t>(n), total - forwarded);
            if (!to.sendAll(chunk, static_cast<size_t>(take))) return;
            const uint64_t payloadAt = forwarded >= h.headerLen ? forwarded - h.headerLen : 0;
            keep(chunk, payloadAt, take);
            forwarded += take;
            // Bytes past this frame start the next one.
            if (take < static_cast<uint64_t>(n)) buf.assign(chunk + take, static_cast<size_t>(static_cast<uint64_t>(n) - take));
            else buf.clear();
        }
        writeLock.unlock();
        if (frameInBuf) buf.erase(0, static_cast<size_t>(total));
        recordWs(flow, std::move(rec), total);
        if (h.opcode == 8) return;  // close frame: this direction is done
    }
}

void TrafficProxy::relayWebSockets(net::Stream& client, net::Stream& upstream, const std::shared_ptr<Flow>& flow,
                                    const std::string& clientSeed, const std::string& upstreamSeed) {
    auto session = std::make_shared<WsSession>();
    session->client = &client;
    session->upstream = &upstream;
    {
        std::lock_guard<std::mutex> lock(wsMutex_);
        wsSessions_[flow->id] = session;
    }
    std::thread up([&] { relayWsDirection(client, upstream, session->upstreamWrite, flow, true, clientSeed); });
    relayWsDirection(upstream, client, session->clientWrite, flow, false, upstreamSeed);
    client.shutdown();
    upstream.shutdown();
    up.join();
    {
        std::scoped_lock lock(session->clientWrite, session->upstreamWrite);
        session->open = false;  // the streams go away with this call
    }
    std::lock_guard<std::mutex> lock(wsMutex_);
    wsSessions_.erase(flow->id);
}

bool TrafficProxy::webSocketLive(uint64_t flowId) const {
    std::lock_guard<std::mutex> lock(wsMutex_);
    const auto it = wsSessions_.find(flowId);
    return it != wsSessions_.end() && !it->second.expired();
}

bool TrafficProxy::injectWebSocket(uint64_t flowId, bool toServer, int opcode, const std::string& payload, std::string& error) {
    std::shared_ptr<WsSession> s;
    {
        std::lock_guard<std::mutex> lock(wsMutex_);
        const auto it = wsSessions_.find(flowId);
        if (it != wsSessions_.end()) s = it->second.lock();
    }
    if (!s) return error = "the WebSocket connection is closed", false;
    if (opcode != 1 && opcode != 2) return error = "only text and binary messages can be sent", false;
    const std::string frame = wsFrame(opcode, payload, toServer);  // client -> server frames are masked
    {
        std::lock_guard<std::mutex> lock(toServer ? s->upstreamWrite : s->clientWrite);
        if (!s->open) return error = "the WebSocket connection is closed", false;
        if (!(toServer ? s->upstream : s->client)->sendAll(frame)) return error = "the connection refused the write", false;
    }
    std::shared_ptr<Flow> flow;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& f : flows_)
            if (f->id == flowId) flow = f;
    }
    if (flow) {
        WsFrame rec;
        rec.fromClient = toServer;
        rec.opcode = opcode;
        rec.size = payload.size();
        rec.preview = payload.substr(0, kMaxWsPayload);
        rec.truncated = payload.size() > kMaxWsPayload;
        rec.injected = true;
        rec.at = unixNow();
        recordWs(flow, std::move(rec), frame.size());
    }
    return true;
}

// ---------------------------------------------------------------------------
// Modes: SOCKS5, upstream proxy, reverse proxy
// ---------------------------------------------------------------------------

bool TrafficProxy::parseReverseTarget(const std::string& url, Mode& mode, std::string& error) {
    std::string u = url;
    while (!u.empty() && (u.back() == '/' || u.back() == ' ')) u.pop_back();
    while (!u.empty() && u.front() == ' ') u.erase(u.begin());
    bool tlsTarget;
    if (tex::asciiLower(u).rfind("https://", 0) == 0) tlsTarget = true, u = u.substr(8);
    else if (tex::asciiLower(u).rfind("http://", 0) == 0) tlsTarget = false, u = u.substr(7);
    else return error = "the reverse target must start with http:// or https://", false;
    if (u.find('/') != std::string::npos) return error = "the reverse target is a server, without a path", false;
    std::string host = u;
    int port = tlsTarget ? 443 : 80;
    const size_t colon = u.rfind(':');
    if (colon != std::string::npos && u.find(']', colon) == std::string::npos) {
        host = u.substr(0, colon);
        port = std::atoi(u.c_str() + colon + 1);
    }
    if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    if (host.empty() || port <= 0 || port > 65535) return error = "the reverse target needs a host and a valid port", false;
    mode.kind = Mode::Kind::Reverse;
    mode.reverseTls = tlsTarget;
    mode.reverseHost = host;
    mode.reversePort = port;
    return true;
}

bool TrafficProxy::parseUpstream(const std::string& hostPort, Mode& mode, std::string& error) {
    std::string s = hostPort;
    while (!s.empty() && s.back() == ' ') s.pop_back();
    while (!s.empty() && s.front() == ' ') s.erase(s.begin());
    if (tex::asciiLower(s).rfind("http://", 0) == 0) s = s.substr(7);
    while (!s.empty() && s.back() == '/') s.pop_back();
    if (s.empty()) {
        mode.upstreamHost.clear();
        mode.upstreamPort = 0;
        return true;
    }
    const size_t colon = s.rfind(':');
    if (colon == std::string::npos || s.find(']', colon) != std::string::npos)
        return error = "the upstream proxy is host:port", false;
    std::string host = s.substr(0, colon);
    const int port = std::atoi(s.c_str() + colon + 1);
    if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    if (host.empty() || port <= 0 || port > 65535) return error = "the upstream proxy needs a host and a valid port", false;
    mode.upstreamHost = host;
    mode.upstreamPort = port;
    return true;
}

void TrafficProxy::setMode(const Mode& mode) {
    std::lock_guard<std::mutex> lock(modeMutex_);
    mode_ = mode;
}

TrafficProxy::Mode TrafficProxy::mode() const {
    std::lock_guard<std::mutex> lock(modeMutex_);
    return mode_;
}

bool TrafficProxy::globMatch(const std::string& pattern, const std::string& text) {
    // Iterative wildcard match with backtracking to the last '*'.
    size_t p = 0, t = 0, star = std::string::npos, mark = 0;
    const auto eq = [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); };
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || eq(pattern[p], text[t]))) {
            ++p, ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            mark = t;
        } else if (star != std::string::npos) {
            p = star + 1;
            t = ++mark;
        } else
            return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

bool TrafficProxy::hostMatches(const std::string& pattern, const std::string& host) {
    std::string pat = pattern;
    while (!pat.empty() && pat.back() == ' ') pat.pop_back();
    while (!pat.empty() && pat.front() == ' ') pat.erase(pat.begin());
    if (pat.empty() || host.empty()) return false;
    if (pat.find_first_of("*?") != std::string::npos) return globMatch(pat, host);
    if (pat.front() == '.') pat.erase(pat.begin());
    // A plain name covers itself and its subdomains.
    if (tex::asciiIEqual(host, pat)) return true;
    return host.size() > pat.size() && host[host.size() - pat.size() - 1] == '.' &&
           tex::asciiIEqual(host.substr(host.size() - pat.size()), pat);
}

bool TrafficProxy::Routing::intercepts(const std::string& host) const {
    for (const auto& p : ignoreHosts)
        if (hostMatches(p, host)) return false;
    bool anyAllow = false;
    for (const auto& p : allowHosts) {
        if (p.find_first_not_of(' ') == std::string::npos) continue;
        anyAllow = true;
        if (hostMatches(p, host)) return true;
    }
    return !anyAllow;
}

bool TrafficProxy::interceptsHost(const std::string& host) const {
    std::lock_guard<std::mutex> lock(modeMutex_);
    return routing_.intercepts(host);
}

void TrafficProxy::setRouting(Routing routing) {
    std::lock_guard<std::mutex> lock(modeMutex_);
    routing_ = std::move(routing);
}

TrafficProxy::Routing TrafficProxy::routing() const {
    std::lock_guard<std::mutex> lock(modeMutex_);
    return routing_;
}

namespace {

std::string replayKey(const std::string& method, std::string url, bool ignoreQuery) {
    if (ignoreQuery) url = url.substr(0, url.find('?'));
    return tex::asciiLower(method) + " " + url;
}

const char* mimeFor(const std::string& path) {
    static const std::pair<const char*, const char*> kTypes[] = {
        {".json", "application/json"}, {".html", "text/html; charset=utf-8"}, {".htm", "text/html; charset=utf-8"},
        {".xml", "application/xml"},   {".js", "application/javascript"},     {".css", "text/css"},
        {".txt", "text/plain; charset=utf-8"}, {".png", "image/png"},          {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},       {".gif", "image/gif"},                 {".webp", "image/webp"},
        {".svg", "image/svg+xml"},     {".pb", "application/x-protobuf"},     {".bin", "application/octet-stream"},
        {".mp4", "video/mp4"},         {".mp3", "audio/mpeg"},                {".pdf", "application/pdf"}};
    const std::string lower = tex::asciiLower(path);
    for (const auto& [ext, type] : kTypes) {
        const size_t n = std::char_traits<char>::length(ext);
        if (lower.size() >= n && lower.compare(lower.size() - n, n, ext) == 0) return type;
    }
    return "application/octet-stream";
}

}  // namespace

bool TrafficProxy::localAnswer(const std::string& method, const std::string& url, std::string& reply, std::string& why) {
    const Routing r = routing();
    for (const auto& m : r.mapLocal) {
        if (!m.enabled || m.urlPattern.empty() || m.localPath.empty() || !globMatch(m.urlPattern, url)) continue;
        std::error_code ec;
        std::filesystem::path file = pathutil::fromUtf8(m.localPath);
        if (std::filesystem::is_directory(file, ec)) {
            // The URL past the pattern's fixed start names a file in the directory.
            const std::string prefix = m.urlPattern.substr(0, m.urlPattern.find_first_of("*?"));
            std::string rest = url.size() > prefix.size() ? url.substr(prefix.size()) : std::string();
            rest = rest.substr(0, rest.find('?'));
            while (!rest.empty() && rest.front() == '/') rest.erase(rest.begin());
            if (rest.empty() || rest.back() == '/') rest += "index.html";
            if (rest.find("..") != std::string::npos) rest = "index.html";  // stay inside the directory
            file /= pathutil::fromUtf8(rest);
        }
        std::ifstream in(file, std::ios::binary);
        why = "map local: " + pathutil::toUtf8(file);
        if (!in) {
            reply = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nApkSpy map local: no file " + pathutil::toUtf8(file);
            return true;
        }
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const std::string type = m.contentType.empty() ? mimeFor(pathutil::toUtf8(file)) : m.contentType;
        reply = "HTTP/1.1 200 OK\r\nContent-Type: " + type + "\r\nContent-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;
        return true;
    }
    std::lock_guard<std::mutex> lock(replayMutex_);
    if (!replayOn_) return false;
    const std::string key = replayKey(method, url, replayOptions_.ignoreQuery);
    for (auto& e : replay_)
        if (e.key == key && (!e.used || replayOptions_.reuse)) {
            e.used = true;
            reply = e.response;
            why = "server replay";
            return true;
        }
    if (replayOptions_.refuseUnmatched) {
        reply = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nApkSpy server replay: no recorded response for " + method + " " + url;
        why = "server replay (no recorded response)";
        return true;
    }
    return false;
}

void TrafficProxy::setServerReplay(std::vector<Flow> recorded, ReplayOptions options) {
    std::lock_guard<std::mutex> lock(replayMutex_);
    replay_.clear();
    for (const auto& f : recorded) {
        if (f.tunnel || f.status == 0 || f.response.startLine.empty()) continue;
        Message resp = f.response;
        // Headers describe the body as captured; a capped body is re-framed to what was kept.
        if (resp.truncated) {
            Headers kept;
            for (auto& h : resp.headers)
                if (!tex::asciiIEqual(h.first, "content-length")) kept.push_back(h);
            kept.emplace_back("Content-Length", std::to_string(resp.body.size()));
            resp.headers = kept;
        }
        replay_.push_back({replayKey(f.method, f.url(), options.ignoreQuery), httpclient::rawMessage(resp), false});
    }
    replayOptions_ = options;
    replayOn_ = true;
}

void TrafficProxy::clearServerReplay() {
    std::lock_guard<std::mutex> lock(replayMutex_);
    replay_.clear();
    replayOn_ = false;
}

size_t TrafficProxy::serverReplayLeft() const {
    std::lock_guard<std::mutex> lock(replayMutex_);
    if (!replayOn_) return 0;
    return static_cast<size_t>(std::count_if(replay_.begin(), replay_.end(), [](const ReplayEntry& e) { return !e.used; }));
}

void TrafficProxy::setConditions(const Conditions& c) {
    latencyMs_ = std::max(0, c.latencyMs);
    downBps_ = std::max(0, c.downKbps) * 1000 / 8;
    upBps_ = std::max(0, c.upKbps) * 1000 / 8;
    failPercent_ = std::clamp(c.failPercent, 0, 100);
}

TrafficProxy::Conditions TrafficProxy::conditions() const {
    Conditions c;
    c.latencyMs = latencyMs_.load();
    c.downKbps = downBps_.load() * 8 / 1000;
    c.upKbps = upBps_.load() * 8 / 1000;
    c.failPercent = failPercent_.load();
    return c;
}

bool TrafficProxy::waitLongLived(net::Stream& s) const {
    while (!s.waitReadable(1000))
        if (!running_.load()) return false;
    return true;
}

void TrafficProxy::pace(size_t n, bool down) const {
    const int bps = down ? downBps_.load() : upBps_.load();
    if (bps > 0) std::this_thread::sleep_for(std::chrono::microseconds(static_cast<long long>(n) * 1000000 / bps));
}

void TrafficProxy::setLimits(size_t maxFlows, size_t maxBody) {
    maxFlows_ = std::max<size_t>(100, maxFlows);
    gMaxBody = std::max<size_t>(1024, maxBody);
    std::lock_guard<std::mutex> lock(mutex_);
    while (flows_.size() > maxFlows_.load()) flows_.pop_front();
}

size_t TrafficProxy::maxBody() { return gMaxBody.load(); }

void TrafficProxy::setHooks(std::shared_ptr<Hooks> hooks) {
    std::lock_guard<std::mutex> lock(modeMutex_);
    hooks_ = std::move(hooks);
}

bool TrafficProxy::connectOut(Socket& sock, const std::string& host, int port, bool viaConnect, std::string& error) {
    if (const int fail = failPercent_.load(); fail > 0) {
        static std::mt19937 rng{std::random_device{}()};
        static std::mutex rngMutex;
        std::lock_guard<std::mutex> lock(rngMutex);
        if (static_cast<int>(rng() % 100) < fail) return error = "connection dropped by the network conditions (ApkSpy)", false;
    }
    if (const int latency = latencyMs_.load(); latency > 0) std::this_thread::sleep_for(std::chrono::milliseconds(latency));
    const Mode m = mode();
    if (!m.chained()) return sock.connectHost(host, port, 15000, error);
    if (!sock.connectHost(m.upstreamHost, m.upstreamPort, 15000, error)) {
        error = "upstream proxy " + m.upstreamHost + ":" + std::to_string(m.upstreamPort) + ": " + error;
        return false;
    }
    if (!viaConnect) return true;  // plain HTTP: the request itself goes to the proxy
    const bool v6 = host.find(':') != std::string::npos;
    const std::string authority = (v6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
    std::string req = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
    if (!m.upstreamAuth.empty()) req += "Proxy-Authorization: Basic " + codec::base64Encode(m.upstreamAuth) + "\r\n";
    req += "\r\n";
    if (!sock.sendAll(req)) return error = "upstream proxy closed the connection", false;
    // Read exactly the head, a byte at a time: what follows belongs to the tunnel.
    std::string head;
    char c;
    while (head.size() < kMaxHead && head.find("\r\n\r\n") == std::string::npos) {
        if (!sock.waitReadable(15000) || sock.recvSome(&c, 1) != 1) return error = "no answer from the upstream proxy", false;
        head += c;
    }
    const int status = head.size() > 12 ? std::atoi(head.c_str() + 9) : 0;
    if (status < 200 || status > 299) {
        error = "upstream proxy refused CONNECT " + authority + ": " + head.substr(0, head.find("\r\n"));
        return false;
    }
    return true;
}

void TrafficProxy::serveSocks(std::shared_ptr<Socket> client, std::string buf) {
    const auto t0 = std::chrono::steady_clock::now();
    Socket& c = *client;
    // Greeting: VER NMETHODS METHODS... - only "no authentication" is offered.
    if (!readExact(c, buf, 2) || !readExact(c, buf, 2 + static_cast<unsigned char>(buf[1]))) return;
    const size_t nMethods = static_cast<unsigned char>(buf[1]);
    bool noAuth = false;
    for (size_t i = 0; i < nMethods; ++i) noAuth |= buf[2 + i] == 0;
    if (!noAuth) {
        c.sendAll(std::string("\x05\xff", 2));
        return;
    }
    if (!c.sendAll(std::string("\x05\x00", 2))) return;
    buf.erase(0, 2 + nMethods);
    // Request: VER CMD RSV ATYP ADDR PORT.
    if (!readExact(c, buf, 5)) return;
    const auto reply = [&](unsigned char code) {
        const char r[10] = {5, static_cast<char>(code), 0, 1, 0, 0, 0, 0, 0, 0};
        return c.sendAll(r, sizeof r);
    };
    const unsigned char cmd = static_cast<unsigned char>(buf[1]), atyp = static_cast<unsigned char>(buf[3]);
    const auto byte = [&](size_t i) { return static_cast<unsigned>(static_cast<unsigned char>(buf[i])); };
    std::string host;
    size_t addrEnd;
    if (atyp == 1) {  // IPv4
        if (!readExact(c, buf, 4 + 4 + 2)) return;
        host = std::to_string(byte(4)) + "." + std::to_string(byte(5)) + "." + std::to_string(byte(6)) + "." + std::to_string(byte(7));
        addrEnd = 8;
    } else if (atyp == 3) {  // domain name
        const size_t len = byte(4);
        if (!readExact(c, buf, 5 + len + 2)) return;
        host = buf.substr(5, len);
        addrEnd = 5 + len;
    } else if (atyp == 4) {  // IPv6
        if (!readExact(c, buf, 4 + 16 + 2)) return;
        char text[48];
        std::snprintf(text, sizeof text, "%x:%x:%x:%x:%x:%x:%x:%x", byte(4) << 8 | byte(5), byte(6) << 8 | byte(7),
                      byte(8) << 8 | byte(9), byte(10) << 8 | byte(11), byte(12) << 8 | byte(13), byte(14) << 8 | byte(15),
                      byte(16) << 8 | byte(17), byte(18) << 8 | byte(19));
        host = text;
        addrEnd = 20;
    } else {
        reply(8);  // address type not supported
        return;
    }
    const int port = static_cast<int>(byte(addrEnd) << 8 | byte(addrEnd + 1));
    std::string pending = buf.substr(addrEnd + 2);
    if (cmd == 3) {  // UDP ASSOCIATE: the datagrams go through a relay port
        serveSocksUdp(c);
        return;
    }
    if (cmd != 1) {  // CONNECT and UDP ASSOCIATE only (no BIND)
        reply(7);
        auto flow = newFlow();
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = "SOCKS";
        flow->tunnel = true;
        flow->host = host;
        flow->port = port;
        flow->error = "SOCKS5 command " + std::to_string(cmd) + " is not supported (only CONNECT)";
        flow->complete = true;
        return;
    }
    if (host.empty() || port <= 0) {
        reply(1);
        return;
    }
    if (!reply(0)) return;
    // What the app sends first decides how the connection is handled, as
    // after an HTTP CONNECT: TLS, plain HTTP, or anything else relayed blind.
    if (pending.empty() && c.waitReadable(10000)) {
        char chunk[16384];
        const long n = c.recvSome(chunk, sizeof chunk);
        if (n == 0) return;
        if (n > 0) pending.assign(chunk, static_cast<size_t>(n));
    }
    const bool tlsHello = pending.size() >= 3 && static_cast<unsigned char>(pending[0]) == 0x16 &&
                          static_cast<unsigned char>(pending[1]) == 0x03;
    const size_t sp = pending.find(' ');
    bool httpRequest = sp != std::string::npos && sp >= 3 && sp <= 7;
    for (size_t i = 0; httpRequest && i < sp; ++i) httpRequest = std::isupper(static_cast<unsigned char>(pending[i])) != 0;
    std::shared_ptr<ca::Store> ca;
    {
        std::lock_guard<std::mutex> lock(caMutex_);
        ca = ca_;
    }
    if (tlsHello && ca && running_.load()) {
        serveHttps(c, host, port, std::move(pending), true);
        return;
    }
    if (httpRequest) {
        // Plain HTTP over SOCKS: an origin-form request to the SOCKS target.
        auto flow = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            flow->method = pending.substr(0, sp);
        }
        net::PlainStream plain(c);
        ThrottledStream stream(plain, [this](size_t n, bool down) { pace(n, down); });
        serveExchange(stream, flow, nullptr, std::move(pending), false);
        finish(flow, t0);
        return;
    }
    auto flow = newFlow();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        flow->method = "SOCKS";
        flow->tunnel = true;
        flow->host = host;
        flow->port = port;
    }
    serveTunnel(c, flow, std::move(pending), true);
}

void TrafficProxy::relayH2c(net::Stream& client, net::Stream& upstream, const std::string& host, int port,
                            const std::string& clientSeed, const std::shared_ptr<Flow>& conn) {
    std::unordered_map<uint32_t, std::pair<std::shared_ptr<Flow>, std::chrono::steady_clock::time_point>> streams;
    size_t count = 0;
    const auto apply = [&](const http2::Exchange& e, bool done) {
        auto it = streams.find(e.stream);
        if (it == streams.end()) return;
        const std::shared_ptr<Flow>& f = it->second.first;
        std::lock_guard<std::mutex> lock(mutex_);
        f->method = e.method;
        f->path = e.path;
        std::string authority = e.authority;
        f->host = host;
        f->port = port;
        f->request.startLine = e.method + " " + e.path + " HTTP/2";
        f->request.headers.clear();
        if (!authority.empty()) f->request.headers.emplace_back("host", authority);
        for (const auto& hd : e.requestHeaders) f->request.headers.push_back(hd);
        f->request.body = e.requestBody;
        f->request.bodySize = e.requestBody.size();
        f->bytesUp = e.requestBody.size();
        if (e.status) {
            f->status = e.status;
            f->response.startLine = "HTTP/2 " + std::to_string(e.status);
            f->response.headers = e.responseHeaders;
            f->response.body = e.responseBody;
            f->response.bodySize = e.responseBody.size();
            f->bytesDown = e.responseBody.size();
        }
        if (done) {
            if (e.reset) f->error = "stream reset (RST_STREAM)";
            f->durationMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - it->second.second).count();
            f->complete = true;
        }
    };
    http2::Observer::Callbacks cb;
    cb.started = [&](const http2::Exchange& e) {
        auto f = newFlow();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            f->alpn = "h2c";
            f->note = "HTTP/2 stream " + std::to_string(e.stream) + " (plain text, h2c)";
        }
        streams[e.stream] = {f, std::chrono::steady_clock::now()};
        ++count;
        apply(e, false);
    };
    cb.updated = [&](const http2::Exchange& e) { apply(e, false); };
    cb.finished = [&](const http2::Exchange& e) {
        apply(e, true);
        streams.erase(e.stream);
    };
    http2::Observer obs(cb, maxBody());
    if (!clientSeed.empty()) obs.feed(true, clientSeed.data(), clientSeed.size());
    const auto pump = [&](net::Stream& from, net::Stream& to, bool fromClient) {
        char buf[65536];
        for (;;) {
            if (!waitLongLived(from)) break;
            const long n = from.recvSome(buf, sizeof buf);
            if (n <= 0 || !to.sendAll(buf, static_cast<size_t>(n))) break;
            obs.feed(fromClient, buf, static_cast<size_t>(n));
            std::lock_guard<std::mutex> lock(mutex_);
            (fromClient ? conn->bytesUp : conn->bytesDown) += static_cast<uint64_t>(n);
        }
        to.shutdown();
        from.shutdown();
    };
    std::thread up([&] { pump(client, upstream, true); });
    pump(upstream, client, false);
    up.join();
    obs.close();
    std::lock_guard<std::mutex> lock(mutex_);
    conn->alpn = "h2c";
    conn->note = "plain-text HTTP/2 connection: " + std::to_string(count) + " stream(s), each listed as its own request" +
                 (obs.error().empty() ? std::string() : " (decoding stopped: " + obs.error() + ")");
    conn->complete = true;
}

void TrafficProxy::serveSocksUdp(Socket& control) {
    UdpSocket relay, out;
    std::string error;
    const bool ok = relay.bind(true, 0, error) && out.bind(false, 0, error);
    // Reply: success, relay at 127.0.0.1:<port> (or a general failure).
    const int rport = ok ? relay.localPort() : 0;
    const char r[10] = {5, static_cast<char>(ok ? 0 : 1), 0, 1, 127, 0, 0, 1, static_cast<char>(rport >> 8), static_cast<char>(rport & 0xff)};
    if (!control.sendAll(r, sizeof r) || !ok) return;
    std::string clientHost;
    int clientPort = 0;
    // One flow per destination (DNS servers get "DNS" flows).
    std::unordered_map<std::string, std::shared_ptr<Flow>> flows;
    const auto flowFor = [&](const std::string& host, int port) {
        auto& f = flows[host + ":" + std::to_string(port)];
        if (!f) {
            f = newFlow();
            std::lock_guard<std::mutex> lock(mutex_);
            f->method = port == 53 ? "DNS" : "UDP";
            f->transport = "udp";
            f->host = host;
            f->port = port;
        }
        return f;
    };
    const auto record = [&](const std::shared_ptr<Flow>& f, bool fromClient, const std::string& data) {
        if (f->port == 53 && fromClient) {
            const std::string name = contentview::dnsName(data);
            std::lock_guard<std::mutex> lock(mutex_);
            if (f->path.empty() && !name.empty()) f->path = name;
        }
        WsFrame fr;
        fr.fromClient = fromClient;
        fr.opcode = 2;
        fr.size = data.size();
        fr.preview = data.substr(0, kMaxWsPayload);
        fr.at = unixNow();
        recordWs(f, std::move(fr), data.size());
    };
    const auto t0 = std::chrono::steady_clock::now();
    auto lastTraffic = t0;
    char buf[65536];
    while (running_.load()) {
        // The association lives as long as the TCP control connection.
        if (control.waitReadable(0)) {
            char b;
            if (control.recvSome(&b, 1) <= 0) break;
        }
        if (std::chrono::steady_clock::now() - lastTraffic > std::chrono::seconds(120)) break;
        if (relay.waitReadable(25)) {
            std::string from;
            int fromPort = 0;
            const long n = relay.recvFrom(buf, sizeof buf, from, fromPort);
            // RSV RSV FRAG ATYP ADDR PORT DATA; fragments are not supported.
            if (n >= 10 && buf[2] == 0) {
                const unsigned char atyp = static_cast<unsigned char>(buf[3]);
                std::string host;
                size_t at = 4;
                if (atyp == 1) {
                    host = std::to_string(static_cast<unsigned char>(buf[4])) + "." + std::to_string(static_cast<unsigned char>(buf[5])) + "." +
                           std::to_string(static_cast<unsigned char>(buf[6])) + "." + std::to_string(static_cast<unsigned char>(buf[7]));
                    at = 8;
                } else if (atyp == 3) {
                    const size_t len = static_cast<unsigned char>(buf[4]);
                    if (5 + len + 2 <= static_cast<size_t>(n)) host.assign(buf + 5, len);
                    at = 5 + len;
                }
                if (!host.empty() && at + 2 <= static_cast<size_t>(n)) {
                    const int port = static_cast<unsigned char>(buf[at]) << 8 | static_cast<unsigned char>(buf[at + 1]);
                    const std::string data(buf + at + 2, static_cast<size_t>(n) - at - 2);
                    clientHost = from;
                    clientPort = fromPort;
                    lastTraffic = std::chrono::steady_clock::now();
                    std::string e;
                    if (out.sendTo(host, port, data.data(), data.size(), e)) record(flowFor(host, port), true, data);
                    else {
                        auto f = flowFor(host, port);
                        std::lock_guard<std::mutex> lock(mutex_);
                        f->error = e;
                    }
                }
            }
        }
        while (out.waitReadable(0)) {
            std::string from;
            int fromPort = 0;
            const long n = out.recvFrom(buf, sizeof buf, from, fromPort);
            if (n < 0 || clientPort == 0) break;
            // Back to the client with the SOCKS header naming the sender.
            std::string pkt("\x00\x00\x00\x01", 4);
            unsigned a, b2, c2, d;
            if (std::sscanf(from.c_str(), "%u.%u.%u.%u", &a, &b2, &c2, &d) != 4) continue;
            pkt += static_cast<char>(a), pkt += static_cast<char>(b2), pkt += static_cast<char>(c2), pkt += static_cast<char>(d);
            pkt += static_cast<char>(fromPort >> 8), pkt += static_cast<char>(fromPort & 0xff);
            const std::string data(buf, static_cast<size_t>(n));
            pkt += data;
            std::string e;
            relay.sendTo(clientHost, clientPort, pkt.data(), pkt.size(), e);
            lastTraffic = std::chrono::steady_clock::now();
            // A reply from an address the client named by host name lands on that flow when one matches.
            std::shared_ptr<Flow> f;
            for (auto& [key, fl] : flows)
                if (fl->port == fromPort && (fl->host == from || flows.size() == 1)) f = fl;
            record(f ? f : flowFor(from, fromPort), false, data);
        }
    }
    for (auto& [key, f] : flows) finish(f, t0);
}

void TrafficProxy::setCa(const std::shared_ptr<ca::Store>& store) {
    std::lock_guard<std::mutex> lock(caMutex_);
    ca_ = store;
}

void TrafficProxy::setUpstreamTrust(const std::shared_ptr<tls::TrustStore>& roots, bool verify) {
    std::lock_guard<std::mutex> lock(caMutex_);
    upstreamRoots_ = roots;
    verifyUpstream_ = verify;
}
// ---------------------------------------------------------------------------
// Intercept
// ---------------------------------------------------------------------------

void TrafficProxy::setRules(matchreplace::RuleSet rules) {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    ruleHits_.assign(rules.rules().size(), 0);
    rules_ = std::make_shared<const matchreplace::RuleSet>(std::move(rules));
}

std::vector<int> TrafficProxy::ruleHits() const {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    return ruleHits_;
}

void TrafficProxy::countHits(const std::vector<int>& hits) {
    std::lock_guard<std::mutex> lock(rulesMutex_);
    for (size_t i = 0; i < hits.size() && i < ruleHits_.size(); ++i) ruleHits_[i] += hits[i];
}

void TrafficProxy::setIntercept(bool requests, bool responses, const std::string& filter, bool websocket) {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    interceptRequests_ = requests;
    interceptResponses_ = responses;
    interceptWs_ = websocket;
    interceptFilter_ = filter;
    interceptCv_.notify_all();  // a kind turned off: what waits for it goes on
}

bool TrafficProxy::interceptMatches(bool response, const std::string& url) const {
    if (!(response ? interceptResponses_ : interceptRequests_)) return false;
    return interceptFilter_.empty() || tex::ciFind(url, interceptFilter_) != std::string_view::npos;
}

bool TrafficProxy::hold(const std::shared_ptr<Waiter>& w) {
    std::unique_lock<std::mutex> lock(interceptMutex_);
    w->held.id = nextHeldId_++;
    waiting_.push_back(w);
    interceptCv_.wait(lock, [&] {
        const bool kindOn = w->held.websocket ? interceptWs_ : (w->held.response ? interceptResponses_ : interceptRequests_);
        return w->decided || !running_.load() || !kindOn;
    });
    waiting_.erase(std::remove(waiting_.begin(), waiting_.end(), w), waiting_.end());
    if (!w->decided) w->raw = w->held.raw;  // released (intercept off, proxy stopping): unchanged
    return !w->dropped;
}

std::vector<TrafficProxy::Held> TrafficProxy::held() const {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    std::vector<Held> out;
    for (const auto& w : waiting_)
        if (!w->decided) out.push_back(w->held);
    return out;
}

size_t TrafficProxy::heldCount() const {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    size_t n = 0;
    for (const auto& w : waiting_) n += !w->decided;
    return n;
}

void TrafficProxy::forward(uint64_t heldId, const std::string& edited) {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    for (const auto& w : waiting_)
        if (w->held.id == heldId && !w->decided) {
            w->decided = true;
            if (w->held.websocket) w->raw = edited.empty() ? w->held.raw : edited;  // a payload, sent as typed
            else {
                w->raw = edited.empty() ? w->held.raw : httpclient::prepare(edited, true);
                if (w->raw.empty()) w->raw = w->held.raw;
            }
        }
    interceptCv_.notify_all();
}

void TrafficProxy::drop(uint64_t heldId) {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    for (const auto& w : waiting_)
        if (w->held.id == heldId && !w->decided) w->decided = w->dropped = true;
    interceptCv_.notify_all();
}

void TrafficProxy::forwardAll() {
    std::lock_guard<std::mutex> lock(interceptMutex_);
    for (const auto& w : waiting_)
        if (!w->decided) w->decided = true, w->raw = w->held.raw;
    interceptCv_.notify_all();
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
        copy.https = f->https;
        copy.complete = f->complete;
        copy.websocket = f->websocket;
        copy.edited = f->edited;
        copy.method = f->method;
        copy.host = f->host;
        copy.port = f->port;
        copy.path = f->path;
        copy.sni = f->sni;
        copy.tlsVersion = f->tlsVersion;
        copy.tlsCipher = f->tlsCipher;
        copy.alpn = f->alpn;
        copy.tlsError = f->tlsError;
        copy.status = f->status;
        copy.bytesUp = f->bytesUp;
        copy.bytesDown = f->bytesDown;
        copy.error = f->error;
        copy.note = f->note;
        copy.transport = f->transport;
        copy.response.headers = f->response.headers;
        copy.response.bodySize = f->response.bodySize;
        copy.request.bodySize = f->request.bodySize;
        out.push_back(std::move(copy));
    }
    if (out.size() > limit) out.erase(out.begin(), out.begin() + static_cast<ptrdiff_t>(out.size() - limit));
    return out;
}

std::vector<uint64_t> TrafficProxy::searchFlows(const std::string& text, uint64_t sinceId) const {
    std::vector<uint64_t> out;
    if (text.empty()) return out;
    std::vector<std::shared_ptr<Flow>> all;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& f : flows_)
            if (f->id > sinceId) all.push_back(f);
    }
    // One flow copied at a time, decoded outside the lock: the relay is not held up.
    const auto contains = [&](const Message& m) {
        if (tex::ciFind(m.startLine, text) != std::string_view::npos) return true;
        for (const auto& [name, value] : m.headers)
            if (tex::ciFind(name + ": " + value, text) != std::string_view::npos) return true;
        return !m.body.empty() && tex::ciFind(decodeBody(m, nullptr), text) != std::string_view::npos;
    };
    for (const auto& f : all) {
        Message req, resp;
        std::string url;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            req = f->request;
            resp = f->response;
            url = f->url();
        }
        if (tex::ciFind(url, text) != std::string_view::npos || contains(req) || contains(resp)) out.push_back(f->id);
    }
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

std::vector<uint64_t> TrafficProxy::selectFlows(const std::function<bool(const Flow&)>& pred, uint64_t sinceId) const {
    std::vector<std::shared_ptr<Flow>> all;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& f : flows_)
            if (f->id > sinceId) all.push_back(f);
    }
    std::vector<uint64_t> out;
    for (const auto& f : all) {
        Flow copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            copy = *f;
        }
        if (pred(copy)) out.push_back(copy.id);
    }
    return out;
}

std::vector<TrafficProxy::Flow> TrafficProxy::fullFlows(const std::vector<uint64_t>& ids) const {
    std::vector<Flow> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint64_t id : ids)
        for (const auto& f : flows_)
            if (f->id == id) {
                out.push_back(*f);
                break;
            }
    return out;
}

size_t TrafficProxy::importFlows(std::vector<Flow> flows, std::vector<uint64_t>* ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& f : flows) {
        auto shared = std::make_shared<Flow>(std::move(f));
        shared->id = nextId_++;
        if (ids) ids->push_back(shared->id);
        shared->complete = true;
        flows_.push_back(std::move(shared));
    }
    while (flows_.size() > maxFlows_.load()) flows_.pop_front();
    return flows.size();
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
    } else if (enc.find("br") != std::string::npos || enc.find("zstd") != std::string::npos) {
        std::string plain;
        bool complete = false;
        const bool ok = enc.find("br") != std::string::npos ? brotliDecode(body, plain, complete) : zstdDecode(body, plain, complete);
        if (ok) {
            body.swap(plain);
            if (note) *note = "decoded from " + enc + (complete ? "" : " (the captured body was cut short)");
        } else if (note) {
            *note = m.truncated ? "compressed body was truncated by the capture limit" : "could not decode the " + enc + " body";
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
    // Reverse mode: the app is pointed at localhost:<port> itself (adb reverse
    // carries it here); the device's global proxy stays untouched.
    if (!mode().reverse() && !adb.setGlobalHttpProxy(serial, "127.0.0.1:" + std::to_string(port_), error)) return false;
    routedSerial_ = serial;
    return true;
}

bool TrafficProxy::restoreDevice(adb::Adb& adb, const std::string& serial, std::string& error) {
    const bool ok = adb.clearGlobalHttpProxy(serial, error);
    std::string ignored;
    if (port_) adb.removeReverse(serial, port_, ignored);
    if (ok && serial == routedSerial_) routedSerial_.clear();
    return ok;
}
