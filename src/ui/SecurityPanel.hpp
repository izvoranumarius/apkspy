#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include "analysis/SecurityScanner.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

// Security workspace: the static scanner's findings for one APK - severity,
// confidence, evidence, location, CWE / MASVS - with filters, a details pane,
// navigation to the code, manifest, resource or file, and Markdown / JSON
// export. Scans run on a worker; the inputs are gathered on the UI thread.
class SecurityPanel : public Panel {
public:
    SecurityPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Security"), showPanel_(std::move(showPanel)) {}
    ~SecurityPanel() override;

protected:
    void drawContents() override;

private:
    void start(const std::string& group);
    void cancel();
    void drawToolbar();
    void drawTable();
    void drawDetails(const security::Finding& f);
    // Opens the finding's location in the Editor. `focus` false: the code shows
    // beside the list (preview tab, Editor brought forward) but the keyboard
    // stays in the findings, so the arrow keys keep walking them.
    void navigate(const security::Finding& f, bool focus = true);
    bool visible(const security::Finding& f) const;
    void drawExport();

    std::function<void(const std::string&)> showPanel_;
    int apkIdx_ = 0;
    std::string group_;
    const ApkAnalysis* scannedWith_ = nullptr;  // identity: rescan when the analysis arrives / changes
    bool scanned_ = false;
    std::future<security::Report> job_;
    std::shared_ptr<std::atomic<bool>> cancel_;
    std::shared_ptr<std::atomic<size_t>> progress_;
    security::Report report_;
    ApkInfo info_;  // of the scanned APK (export header)

    bool showSeverity_[5] = {true, true, true, true, true};  // Info .. Critical
    int category_ = 0;  // 0 = all, else index + 1 into categories_
    std::vector<std::string> categories_;
    bool hideLibraries_ = false;
    char filter_[128] = {};
    int selected_ = -1;  // index into report_.findings

    FileBrowser exportBrowser_;
    bool exportJson_ = false;
};
