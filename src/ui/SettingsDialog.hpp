#pragma once
#include <future>
#include <string>
#include "core/Settings.hpp"
#include "debug/DeviceService.hpp"
#include "core/Workspace.hpp"
#include "ui/FileBrowser.hpp"

// Visual-Studio-style options dialog: a category list on the left, the
// settings page on the right, OK / Cancel / Apply at the bottom.
class McpSettings;

class SettingsDialog {
public:
    SettingsDialog(Workspace& workspace, Settings& settings, DeviceService& devices)
        : workspace_(workspace), settings_(settings), devices_(devices) {}

    void setMcp(McpSettings* mcp) { mcp_ = mcp; }
    void open();
    // Call every frame; returns true when the dialog was closed with OK or
    // Apply so the application can persist the settings file.
    bool render();
    bool isOpen() const { return open_; }

private:
    void drawGeneralPage();
    void drawJadxPage();
    void drawEditorPage();
    void drawAndroidPage();
    void drawScriptsPage();

    Workspace& workspace_;
    Settings& settings_;
    DeviceService& devices_;
    McpSettings* mcp_ = nullptr;
    FileBrowser adbBrowser_;
    char adbPath_[1024] = {};
    char pythonPath_[1024] = {};
    int trafficPort_ = 8899;
    std::future<std::string> adbTest_;
    std::string adbTestResult_;
    FileBrowser browser_;

    bool open_ = false;
    int category_ = 0;

    // Working copies, committed by OK/Apply.
    char jadxPath_[1024] = {};
    char jadxArgs_[512] = {};
    bool restoreSession_ = true;
    bool lineNumbers_ = true;
    bool fullCjk_ = false;
};
