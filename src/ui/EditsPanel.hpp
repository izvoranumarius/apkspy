#pragma once
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "edit/Edits.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

class ApkAnalysis;

// Every file edited this session (decompiled sources and smali listings):
// per-file line counts, smali validation diagnostics and the unified diff,
// with export of the edited source files to a folder and a text report.
// Source text only - nothing here builds, signs or packages anything.
class EditsPanel : public Panel {
public:
    explicit EditsPanel(Workspace& workspace) : Panel(workspace, "Edits") {}

protected:
    void drawContents() override;

private:
    void rebuild();
    std::vector<edits::EditedFile> collect();
    const smali::ClassUniverse* universeFor(const std::string& group);
    void drawDiff(const std::string& diff);
    void doExport(const std::string& dir);
    void saveReport(const std::string& file);

    edits::EditReport report_;
    uint64_t builtEdits_ = UINT64_MAX, builtSerial_ = UINT64_MAX, builtState_ = UINT64_MAX;
    std::chrono::steady_clock::time_point lastBuild_{};
    int selected_ = -1;
    bool overwrite_ = false;
    bool writePatch_ = true;
    bool validate_ = true;
    FileBrowser exportBrowser_, reportBrowser_;
    std::string status_;
    struct Universe {
        std::shared_ptr<const ApkAnalysis> analysis;
        std::unique_ptr<smali::DexUniverse> universe;
    };
    std::map<std::string, Universe> universes_;
};
