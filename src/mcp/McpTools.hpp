#pragma once
#include <functional>
#include <string>
#include "mcp/McpServer.hpp"

class Workspace;
class DeviceService;

// The ApkSpy tool set exposed over MCP: project/APK exploration, manifest,
// decompiled sources, bytecode analysis (classes, methods, xrefs, call
// graphs, CFGs), strings/endpoints, native libraries, hex dumps, APK
// comparison and the live device / debugger state.
//
// Every tool reuses the application's own services (Workspace, ApkInfo,
// AxmlDecoder, AnalysisService, DeviceService); nothing here duplicates
// project logic. Access is confined to what the project already contains:
// files are looked up through the project trees (never by raw filesystem
// path) and device commands are fixed adb templates with validated input.
struct McpToolEnv {
    Workspace* workspace = nullptr;
    DeviceService* devices = nullptr;
    bool gui = false;  // enables UI-only tools (open_in_editor, show_panel)
    // GUI: brings a panel to the front (applied on the next frame); returns
    // false for an unknown panel title.
    std::function<bool(const std::string&)> showPanel;
};

void registerApkSpyTools(McpServer& server, const McpToolEnv& env);

// Server instructions sent in the initialize result.
std::string apkSpyMcpInstructions();
