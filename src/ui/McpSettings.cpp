#include "ui/McpSettings.hpp"
#include <algorithm>
#include <cstdio>
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "ui/UiUtil.hpp"

namespace {
const ImVec4 kGood(0.45f, 0.8f, 0.45f, 1.f);
const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);
}  // namespace

void McpSettings::loadSettings() {
    port_ = std::clamp(settings_.getInt(Settings::kMcpPort, 8765), 0, 65535);
    requireToken_ = settings_.getBool(Settings::kMcpRequireToken, true);
    autoStart_ = settings_.getBool(Settings::kMcpAutoStart, false);
    token_ = settings_.getString(Settings::kMcpToken, "");
    if (token_.size() < 16) token_ = McpHttpServer::randomToken();
    loaded_ = true;
}

void McpSettings::autoStart() {
    if (autoStart_ && !host_.http().running()) start();
}

void McpSettings::storeSettings() {
    if (!loaded_) return;
    settings_.set(Settings::kMcpPort, port_);
    settings_.set(Settings::kMcpRequireToken, requireToken_);
    settings_.set(Settings::kMcpAutoStart, autoStart_);
    settings_.set(Settings::kMcpToken, token_);
}

bool McpSettings::start() {
    error_.clear();
    if (!host_.startHttp(port_, requireToken_ ? token_ : std::string(), error_)) {
        workspace_.log("MCP server: " + error_, "mcp");
        return false;
    }
    workspace_.log("MCP server listening on " + host_.http().url(), "mcp");
    return true;
}

void McpSettings::draw() {
    McpHttpServer& http = host_.http();
    const bool running = http.running();
    if (running) {
        if (ImGui::Button("Stop")) {
            host_.stopHttp();
            workspace_.log("MCP server stopped", "mcp");
        }
        ImGui::SameLine();
        ImGui::TextColored(kGood, "Running");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s\n%d connection(s), %zu tools", http.url().c_str(), http.activeConnections(), host_.server().tools().size());
    } else {
        if (ImGui::Button("Start")) start();
        ImGui::SameLine();
        ImGui::TextDisabled("Stopped");
    }
    if (!error_.empty()) ui::wrappedColored(kWarn, error_);
    ImGui::Spacing();

    // Connecting a client is one paste: the details stay out of the way until needed.
    const std::string url = running ? http.url() : "http://127.0.0.1:" + std::to_string(port_) + "/mcp";
    const std::string auth = requireToken_ ? token_ : std::string();
    ImGui::TextUnformatted("Connect a client");
    if (ImGui::Button("Copy for Claude Code"))
        ImGui::SetClipboardText(("claude mcp add --transport http apkspy " + url +
                                 (auth.empty() ? std::string() : " --header \"Authorization: Bearer " + auth + "\"")).c_str());
    if (ui::flowButton("Copy JSON config")) {
        std::string json = "{\n  \"mcpServers\": {\n    \"apkspy\": {\n      \"type\": \"http\",\n      \"url\": \"" + url + "\"";
        if (!auth.empty()) json += ",\n      \"headers\": { \"Authorization\": \"Bearer " + auth + "\" }";
        json += "\n    }\n  }\n}";
        ImGui::SetClipboardText(json.c_str());
    }
    if (ui::flowButton("Copy headless config")) {
        std::string exe = pathutil::exeDir();
#ifdef _WIN32
        exe += "\\ApkSpy.exe";
        for (size_t p = exe.find('\\'); p != std::string::npos; p = exe.find('\\', p + 2)) exe.replace(p, 1, "\\\\");
#else
        exe += "/apkspy";
#endif
        const std::string json = "{\n  \"mcpServers\": {\n    \"apkspy\": {\n      \"command\": \"" + exe +
                                 "\",\n      \"args\": [\"--mcp\", \"--project\", \"<path to .apkspy>\"]\n    }\n  }\n}";
        ImGui::SetClipboardText(json.c_str());
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("The client starts ApkSpy itself, without a window");
    ImGui::Spacing();

    ImGui::Separator();
    ImGui::Checkbox("Start with ApkSpy", &autoStart_);
    ImGui::BeginDisabled(running);
    ImGui::SetNextItemWidth(ui::em(5.f));
    ImGui::InputInt("Port", &port_, 0, 0);
    port_ = std::clamp(port_, 0, 65535);
    ImGui::Checkbox("Require bearer token", &requireToken_);
    ImGui::EndDisabled();
    if (requireToken_) {
        if (ui::smallButton("Copy token")) ImGui::SetClipboardText(token_.c_str());
        ImGui::SameLine();
        ImGui::BeginDisabled(running);
        if (ui::smallButton("New token")) token_ = McpHttpServer::randomToken();
        ImGui::EndDisabled();
    } else {
        ui::wrappedColored(kWarn, "Without a token any local process can use the endpoint.");
    }
}
