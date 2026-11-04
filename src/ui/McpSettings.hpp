#pragma once
#include <string>
#include "core/Settings.hpp"
#include "core/Workspace.hpp"
#include "mcp/McpHost.hpp"

// The AI page of the Settings dialog: starts/stops the local MCP endpoint and
// copies client configuration (Claude Code, JSON config, headless stdio mode).
// Unlike the rest of the dialog it acts at once: Start needs no OK.
class McpSettings {
public:
    McpSettings(Workspace& workspace, Settings& settings, McpHost& host)
        : workspace_(workspace), settings_(settings), host_(host) {}

    // Reads the persisted choices. Must run before anything can save the
    // settings file (restoring the last session saves it), or the defaults
    // would overwrite the user's configuration.
    void loadSettings();
    // Starts the endpoint when "Start with ApkSpy" is set. Called once the
    // application is fully initialised.
    void autoStart();
    // Persists the current choices into Settings (caller saves the file).
    void storeSettings();
    void draw();

private:
    bool start();
    Workspace& workspace_;
    Settings& settings_;
    McpHost& host_;
    int port_ = 8765;
    bool requireToken_ = true;
    bool autoStart_ = false;
    bool loaded_ = false;  // storeSettings() is a no-op before loadSettings()
    std::string token_;
    std::string error_;
};
