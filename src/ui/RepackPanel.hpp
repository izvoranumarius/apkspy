#pragma once
#include <future>
#include <string>
#include <utility>
#include <vector>
#include "core/ApkRepack.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

class Settings;

// "Repack": rebuild an APK with replaced entries and (re-)sign it so it can be
// installed. Replacements are whole zip entries (AndroidManifest.xml,
// resources.arsc, classes.dex, a .so, ...) - this does not assemble smali.
// Signing uses a debug keystore by default, or a keystore you provide.
class RepackPanel : public Panel {
public:
    RepackPanel(Workspace& workspace, Settings& settings) : Panel(workspace, "Repack"), settings_(settings) {}

protected:
    void drawContents() override;

private:
    void build();
    Settings& settings_;
    char source_[1024] = {};
    char output_[1024] = {};
    int keyMode_ = 0;  // 0 debug keystore, 1 custom
    char ksPath_[1024] = {};
    char ksPass_[128] = {};
    char ksAlias_[128] = {};
    char keyPass_[128] = {};
    bool align_ = true;
    bool sign_ = true;
    bool prefilled_ = false;

    struct Entry {
        std::string zipPath;
        std::string file;
    };
    std::vector<Entry> replacements_;
    char newZipPath_[256] = {};

    FileBrowser sourceBrowser_, outputBrowser_, ksBrowser_, replFileBrowser_;
    std::future<repack::Result> job_;
    std::string log_;
    std::string status_;
};
