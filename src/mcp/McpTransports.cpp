#include "mcp/McpTransports.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <random>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

namespace {

constexpr size_t kMaxMessage = 16u << 20;  // a single JSON-RPC message
constexpr int kMaxConcurrent = 8;          // in-flight stdio requests

// ---- raw stdio (works for GUI-subsystem executables on Windows, whose CRT
// streams are not attached to the inherited pipe handles) -------------------
long readStdin(char* buf, size_t len) {
#ifdef _WIN32
    DWORD got = 0;
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, static_cast<DWORD>(len), &got, nullptr)) return -1;
    return static_cast<long>(got);
#else
    ssize_t n;
    do n = ::read(0, buf, len);
    while (n < 0 && errno == EINTR);
    return static_cast<long>(n);
#endif
}

std::mutex gStdoutMutex;
void writeStdoutLine(const std::string& line) {
    std::lock_guard<std::mutex> lock(gStdoutMutex);
    std::string out = line;
    out.push_back('\n');
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    size_t off = 0;
    while (off < out.size()) {
        DWORD wrote = 0;
        if (!WriteFile(h, out.data() + off, static_cast<DWORD>(out.size() - off), &wrote, nullptr) || wrote == 0) return;
        off += wrote;
    }
    FlushFileBuffers(h);
#else
    size_t off = 0;
    while (off < out.size()) {
        ssize_t n = ::write(1, out.data() + off, out.size() - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return;
        }
        off += static_cast<size_t>(n);
    }
#endif
}

bool ciEquals(const std::string& a, const char* b) {
    size_t n = std::char_traits<char>::length(b);
    if (a.size() != n) return false;
    for (size_t i = 0; i < n; ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
    return true;
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

// Origin values a local MCP client (or a page on localhost) may send.
bool originAllowed(const std::string& origin) {
    if (origin.empty() || origin == "null") return true;  // non-browser clients send none
    for (const char* prefix : {"http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost",
                               "http://[::1]", "https://[::1]"}) {
        const size_t n = std::char_traits<char>::length(prefix);
        if (origin.compare(0, n, prefix) == 0 && (origin.size() == n || origin[n] == ':' || origin[n] == '/'))
            return true;
    }
    return false;
}

struct HttpRequest {
    std::string method, target;
    std::unordered_map<std::string, std::string> headers;  // lower-case keys
    std::string body;
    bool keepAlive = true;
};

std::string reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    default: return "Error";
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------

int runMcpStdio(McpServer& server, std::atomic<bool>& stop) {
    std::mutex m;
    std::condition_variable cv;
    int running = 0;
    WorkerSet threads;
    const McpServer::Notifier notify = [](const std::string& msg) { writeStdoutLine(msg); };

    const auto dispatch = [&](std::string line) {
        {
            std::unique_lock<std::mutex> lock(m);
            cv.wait(lock, [&] { return running < kMaxConcurrent || stop.load(); });
            ++running;
        }
        threads.spawn([&, line = std::move(line)] {
            const std::string reply = server.handleMessage(line, "stdio", notify);
            if (!reply.empty()) writeStdoutLine(reply);
            std::lock_guard<std::mutex> lock(m);
            --running;
            cv.notify_all();
        });
    };

    std::string pending;
    char buf[65536];
    while (!stop.load()) {
        const long n = readStdin(buf, sizeof buf);
        if (n <= 0) break;  // client closed stdin: shut down
        pending.append(buf, static_cast<size_t>(n));
        size_t start = 0;
        for (size_t nl = pending.find('\n'); nl != std::string::npos; nl = pending.find('\n', start)) {
            std::string line = pending.substr(start, nl - start);
            start = nl + 1;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (!line.empty()) dispatch(std::move(line));
        }
        pending.erase(0, start);
        if (pending.size() > kMaxMessage) {
            writeStdoutLine(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"message too large"}})");
            pending.clear();
        }
        threads.reap();
    }
    stop = true;
    server.cancelAll();
    cv.notify_all();
    threads.joinAll();
    return 0;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

std::string McpHttpServer::randomToken() {
    std::random_device rd;
    std::string out;
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) out.push_back(hex[rd() & 0xF]);
    return out;
}

bool McpHttpServer::start(McpServer& server, int port, std::string token, std::string& error) {
    stop();
    if (!listener_.listenLoopback(port, error)) return false;
    server_ = &server;
    token_ = std::move(token);
    port_ = listener_.localPort();
    running_ = true;
    acceptThread_ = std::thread(&McpHttpServer::acceptLoop, this);
    return true;
}

void McpHttpServer::stop() {
    if (!running_.exchange(false)) {
        if (acceptThread_.joinable()) acceptThread_.join();
        return;
    }
    listener_.shutdownBoth();
    if (acceptThread_.joinable()) acceptThread_.join();
    listener_.close();
    if (server_) server_->cancelAll();
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        for (auto& w : clients_)
            if (auto c = w.lock()) c->shutdownBoth();  // unblock reads
        clients_.clear();
    }
    workers_.joinAll();
}

void McpHttpServer::acceptLoop() {
    while (running_.load()) {
        Socket client = listener_.accept(250);
        workers_.reap();
        if (!client.valid()) continue;
        if (active_.load() >= 32) {  // refuse floods
            client.sendAll("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        auto shared = std::make_shared<Socket>(std::move(client));
        {
            std::lock_guard<std::mutex> lock(clientsMutex_);
            clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
                                          [](const std::weak_ptr<Socket>& w) { return w.expired(); }),
                           clients_.end());
            clients_.push_back(shared);
        }
        ++active_;
        workers_.spawn([this, shared] { serve(shared); });
    }
}

void McpHttpServer::serve(std::shared_ptr<Socket> client) {
    const std::string sessionKey = "http-" + std::to_string(reinterpret_cast<uintptr_t>(client.get()));
    std::string buffer;
    char chunk[16384];
    const auto respond = [&](int status, const std::string& body, const std::string& extraHeaders, bool keepAlive) {
        std::string head = "HTTP/1.1 " + std::to_string(status) + " " + reason(status) + "\r\n";
        if (!body.empty()) head += "Content-Type: application/json\r\n";
        head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        head += "Cache-Control: no-store\r\n";
        head += keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
        head += extraHeaders;
        head += "\r\n";
        return client->sendAll(head) && client->sendAll(body);
    };

    while (running_.load()) {
        // Read the header block.
        size_t headerEnd;
        while ((headerEnd = buffer.find("\r\n\r\n")) == std::string::npos) {
            if (buffer.size() > 64 * 1024 || !client->waitReadable(30000)) goto done;  // idle / oversized
            const long n = client->recvSome(chunk, sizeof chunk);
            if (n <= 0) goto done;
            buffer.append(chunk, static_cast<size_t>(n));
        }
        {
            HttpRequest req;
            const std::string head = buffer.substr(0, headerEnd);
            buffer.erase(0, headerEnd + 4);
            size_t lineEnd = head.find("\r\n");
            const std::string requestLine = head.substr(0, lineEnd);
            const size_t sp1 = requestLine.find(' '), sp2 = requestLine.rfind(' ');
            if (sp1 == std::string::npos || sp2 == sp1) {
                respond(400, "", "", false);
                goto done;
            }
            req.method = requestLine.substr(0, sp1);
            req.target = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
            size_t pos = lineEnd == std::string::npos ? head.size() : lineEnd + 2;
            while (pos < head.size()) {
                size_t e = head.find("\r\n", pos);
                if (e == std::string::npos) e = head.size();
                const std::string line = head.substr(pos, e - pos);
                pos = e + 2;
                const size_t colon = line.find(':');
                if (colon == std::string::npos) continue;
                std::string key = line.substr(0, colon);
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                std::string value = line.substr(colon + 1);
                while (!value.empty() && value.front() == ' ') value.erase(value.begin());
                req.headers[key] = value;
            }
            if (req.headers.count("connection") && ciEquals(req.headers["connection"], "close")) req.keepAlive = false;
            size_t length = 0;
            if (req.headers.count("content-length")) length = static_cast<size_t>(std::strtoull(req.headers["content-length"].c_str(), nullptr, 10));
            if (length > kMaxMessage) {
                respond(413, "", "", false);
                goto done;
            }
            while (buffer.size() < length) {
                if (!client->waitReadable(30000)) goto done;
                const long n = client->recvSome(chunk, sizeof chunk);
                if (n <= 0) goto done;
                buffer.append(chunk, static_cast<size_t>(n));
            }
            req.body = buffer.substr(0, length);
            buffer.erase(0, length);

            const std::string path = req.target.substr(0, req.target.find('?'));
            if (!originAllowed(req.headers["origin"])) {
                respond(403, R"({"error":"origin not allowed"})", "", false);
                goto done;
            }
            if (!token_.empty()) {
                const std::string& auth = req.headers["authorization"];
                const std::string expected = "Bearer " + token_;
                if (!constantTimeEquals(auth, expected)) {
                    respond(401, R"({"error":"missing or invalid bearer token"})", "WWW-Authenticate: Bearer\r\n",
                            req.keepAlive);
                    if (!req.keepAlive) goto done;
                    continue;
                }
            }
            if (path != "/mcp" && path != "/") {
                if (!respond(404, "", "", req.keepAlive) || !req.keepAlive) goto done;
                continue;
            }
            if (req.method == "GET") {
                if (!respond(405, "", "Allow: POST, DELETE\r\n", req.keepAlive) || !req.keepAlive) goto done;
                continue;
            }
            if (req.method == "DELETE") {
                server_->cancelSession(req.headers["mcp-session-id"]);
                if (!respond(200, "", "", req.keepAlive) || !req.keepAlive) goto done;
                continue;
            }
            if (req.method != "POST") {
                if (!respond(405, "", "Allow: POST, DELETE\r\n", req.keepAlive) || !req.keepAlive) goto done;
                continue;
            }
            // Sessions: issue an id on initialize; requests are keyed by it
            // (or by the connection when the client sends none).
            std::string session = req.headers["mcp-session-id"];
            std::string extra;
            if (req.body.find("\"initialize\"") != std::string::npos) {
                session = randomToken();
                extra = "Mcp-Session-Id: " + session + "\r\n";
            }
            const std::string reply = server_->handleMessage(req.body, session.empty() ? sessionKey : session, nullptr);
            const bool ok = reply.empty() ? respond(202, "", extra, req.keepAlive) : respond(200, reply, extra, req.keepAlive);
            if (!ok || !req.keepAlive) goto done;
        }
    }
done:
    server_->cancelSession(sessionKey);
    client->close();
    --active_;
}
