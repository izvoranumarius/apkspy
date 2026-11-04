#include "mcp/McpHost.hpp"

McpHost::McpHost(Workspace& workspace, DeviceService* devices, bool gui,
                 std::function<bool(const std::string&)> showPanel) {
    McpServer::Info info;
    info.name = "apkspy";
    info.version = "1.0.0";
    info.instructions = apkSpyMcpInstructions();
    server_ = std::make_unique<McpServer>(dispatcher_, info);
    McpToolEnv env;
    env.workspace = &workspace;
    env.devices = devices;
    env.gui = gui;
    env.showPanel = std::move(showPanel);
    registerApkSpyTools(*server_, env);
}

McpHost::~McpHost() { shutdown(); }

bool McpHost::startHttp(int port, const std::string& token, std::string& error) {
    return http_.start(*server_, port, token, error);
}

bool McpHost::scriptEndpoint(std::string& url, std::string& token, std::string& error) {
    if (!scriptHttp_.running() && !scriptHttp_.start(*server_, 0, McpHttpServer::randomToken(), error)) return false;
    url = scriptHttp_.url();
    token = scriptHttp_.token();
    return true;
}

void McpHost::shutdown() {
    // Order matters: stop accepting, cancel running calls, then release any
    // transport thread waiting for the owner thread.
    http_.stop();
    scriptHttp_.stop();
    server_->cancelAll();
    dispatcher_.shutdown();
}
