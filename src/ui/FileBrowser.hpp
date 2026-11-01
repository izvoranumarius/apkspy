#pragma once
#include <set>
#include <string>
#include <vector>
#include "imgui.h"

// Self-contained modal file browser so "Browse..." works on every platform
// without native dialogs. Used for picking APK files (multi-select),
// project files and the jadx executable.
class FileBrowser {
public:
    enum class Mode {
        OpenApkMulti,   // multiple .apk files (click toggles selection)
        OpenProject,    // single .apkspy project file
        SaveProject,    // new .apkspy project file (name input)
        SaveFile,       // export target: single file, any name (M5)
        SelectFolder,   // export target: an existing directory (M5)
        SelectExecutable
    };

    void open(Mode mode);
    // Prefills the name field (SaveProject mode).
    void setDefaultName(const std::string& name);
    // Renders the popup (if open). Call once per frame.
    void render();
    // True when the user accepted a file this frame; consumed by the caller.
    bool takeAccepted(std::string& outPath);
    // Multi-select result (OpenApkMulti); same consumption semantics.
    bool takeAcceptedMulti(std::vector<std::string>& outPaths);
    bool isOpen() const { return open_; }

private:
    void refresh();
    void goTo(const std::string& dir);
    void applyFilter();
    const char* popupTitle() const;
    // Project file name with a guaranteed .apkspy extension.
    std::string projectFileName(const std::string& name) const;

    Mode mode_ = Mode::OpenApkMulti;
    bool open_ = false;
    bool openRequest_ = false;  // open() sets it; render() calls OpenPopup in its own ID context
    bool accepted_ = false;
    bool acceptedMulti_ = false;
    std::string result_;
    std::vector<std::string> results_;
    std::string currentDir_;
    std::string selectedFile_;            // relative name inside currentDir_ (single modes)
    std::set<std::string> selectedNames_;  // relative names (OpenApkMulti)
    char pathBuffer_[1024] = {};
    char nameBuffer_[256] = {};
    struct Entry {
        std::string name;
        bool isDir;
    };
    std::vector<Entry> entries_;  // filtered, dirs first
    std::vector<Entry> all_;      // unfiltered directory contents
};
