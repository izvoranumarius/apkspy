#pragma once
#include <functional>
#include <future>
#include <string>
#include "app/Theme.hpp"
#include "core/Settings.hpp"
#include "core/Workspace.hpp"
#include "debug/DeviceService.hpp"
#include "ui/FileBrowser.hpp"

class McpSettings;

// Options dialog: grouped pages in a list on the left, the page on the right,
// OK / Cancel / Apply at the bottom. Appearance changes (theme, colours, zoom)
// preview live; Cancel or closing the window restores what was there.
class SettingsDialog {
public:
    SettingsDialog(Workspace& workspace, Settings& settings, DeviceService& devices)
        : workspace_(workspace), settings_(settings), devices_(devices) {}

    void setMcp(McpSettings* mcp) { mcp_ = mcp; }
    // UI zoom lives in the application (it rebuilds the fonts).
    void setZoomControl(std::function<float()> get, std::function<void(float)> set) {
        getZoom_ = std::move(get);
        setZoom_ = std::move(set);
    }
    void setResetLayout(std::function<void()> reset) { resetLayout_ = std::move(reset); }
    void open();
    // Call every frame; returns true when the dialog was closed with OK or
    // Apply so the application can persist the settings file.
    bool render();
    bool isOpen() const { return open_; }

    enum class Page { General, Appearance, Editor, Decompiler, Android, Network, Terminal, Ai, Count };

private:
    void drawGeneralPage();
    void drawAppearancePage();
    void drawThemeCards();
    void drawColorEditor();
    void drawEditorPage();
    void drawDecompilerPage();
    void drawAndroidPage();
    void drawNetworkPage();
    void drawTerminalPage();
    void drawAiPage();
    void commit();  // working copies -> settings / services
    void revertPreview();

    Workspace& workspace_;
    Settings& settings_;
    DeviceService& devices_;
    McpSettings* mcp_ = nullptr;
    std::function<float()> getZoom_;
    std::function<void(float)> setZoom_;
    std::function<void()> resetLayout_;

    bool open_ = false;
    Page page_ = Page::General;

    // Working copies, committed by OK / Apply.
    char jadxPath_[1024] = {};
    char jadxArgs_[512] = {};
    char adbPath_[1024] = {};
    char pythonPath_[1024] = {};
    char terminalShell_[1024] = {};
    int trafficPort_ = 8899;
    bool restoreSession_ = true;
    bool lineNumbers_ = true;
    bool fullCjk_ = false;

    // Live-previewed appearance, restored on Cancel.
    Theme::State themeAtOpen_;
    float zoomAtOpen_ = 1.f;
    char colorFilter_[64] = {};

    FileBrowser jadxBrowser_;
    FileBrowser adbBrowser_;
    std::future<std::string> adbTest_;
    std::string adbTestResult_;
};
