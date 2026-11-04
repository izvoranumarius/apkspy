#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/Socket.hpp"
#include "core/WorkerSet.hpp"
#include "mcp/McpServer.hpp"

// stdio transport: newline-delimited JSON-RPC on stdin/stdout (the MCP
// stdio convention). Requests are handled concurrently (bounded) so a
// long-running tool never blocks cancellation or ping messages; responses
// are written atomically per line. Returns when stdin closes or `stop`.
int runMcpStdio(McpServer& server, std::atomic<bool>& stop);

// Streamable-HTTP transport (POST /mcp, JSON responses) bound to 127.0.0.1.
//
// Security: loopback only; requests carrying a non-local Origin header are
// rejected (DNS-rebinding protection for browsers); an optional bearer token
// must match (constant-time compare) when configured. No server-initiated
// streams: GET returns 405, progress notifications are not sent over HTTP.
class McpHttpServer {
public:
    McpHttpServer() = default;
    ~McpHttpServer() { stop(); }
    McpHttpServer(const McpHttpServer&) = delete;
    McpHttpServer& operator=(const McpHttpServer&) = delete;

    bool start(McpServer& server, int port, std::string token, std::string& error);
    void stop();
    bool running() const { return running_.load(); }
    int port() const { return port_; }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_) + "/mcp"; }
    const std::string& token() const { return token_; }
    int activeConnections() const { return active_.load(); }

    static std::string randomToken();

private:
    void acceptLoop();
    void serve(std::shared_ptr<Socket> client);

    McpServer* server_ = nullptr;
    Socket listener_;
    std::thread acceptThread_;
    std::atomic<bool> running_{false};
    std::atomic<int> active_{0};
    int port_ = 0;
    std::string token_;
    std::mutex clientsMutex_;
    std::vector<std::weak_ptr<Socket>> clients_;
    WorkerSet workers_;
};
