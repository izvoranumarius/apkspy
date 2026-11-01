#pragma once
#include <string>
#include "core/Settings.hpp"
#include "core/Workspace.hpp"
#include "ui/FileBrowser.hpp"

// Visual-Studio-style options dialog: a category list on the left, the
// settings page on the right, OK / Cancel / Apply at the bottom.
class SettingsDialog {
public:
    SettingsDialog(Workspace& workspace, Settings& settings) : workspace_(workspace), settings_(settings) {}

    void open();
    // Call every frame; returns true when the dialog was closed with OK or
    // Apply so the application can persist the settings file.
    bool render();
    bool isOpen() const { return open_; }

private:
    void drawGeneralPage();
    void drawJadxPage();
    void drawEditorPage();

    Workspace& workspace_;
    Settings& settings_;
    FileBrowser browser_;

    bool open_ = false;
    int category_ = 0;

    // Working copies, committed by OK/Apply.
    char jadxPath_[1024] = {};
    char jadxArgs_[512] = {};
    bool restoreSession_ = true;
    bool lineNumbers_ = true;
};
