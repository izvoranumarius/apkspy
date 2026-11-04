#pragma once
#include <memory>
#include <string>
#include "mcp/McpServer.hpp"
#include "mcp/McpTools.hpp"
#include "mcp/McpTransports.hpp"

// Owns the MCP pieces for one process: the owner-thread dispatcher, the
// server with the ApkSpy tool set and (in the GUI) the HTTP endpoint.
// pump() must be called regularly from the thread that owns the Workspace.
class McpHost {
public:
    McpHost(Workspace& workspace, DeviceService* devices, bool gui,
            std::function<bool(const std::string&)> showPanel = {});
    ~McpHost();

    McpDispatcher& dispatcher() { return dispatcher_; }
    McpServer& server() { return *server_; }
    McpHttpServer& http() { return http_; }

    bool startHttp(int port, const std::string& token, std::string& error);
    // A private endpoint for scripts: a free port and a fresh token, independent
    // of the user's MCP server setting. Started on first use.
    bool scriptEndpoint(std::string& url, std::string& token, std::string& error);
    void stopHttp() { http_.stop(); }
    void pump() { dispatcher_.pump(); }
    void shutdown();

private:
    McpDispatcher dispatcher_;
    std::unique_ptr<McpServer> server_;
    McpHttpServer http_;
    McpHttpServer scriptHttp_;
};
