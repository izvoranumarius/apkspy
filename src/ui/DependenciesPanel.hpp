#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include "analysis/Dependencies.hpp"
#include "core/ScriptRunner.hpp"
#include "ui/GraphView.hpp"
#include "ui/Panel.hpp"

class Settings;

// Dependency Intelligence (Security workspace): the libraries and frameworks
// an APK bundles with versions, licenses and known vulnerabilities, as a
// table, a graph (app -> categories -> libraries) or by license. "Update"
// refreshes the vulnerability data from OSV.dev through the configured
// Python (no network code in ApkSpy itself).
class DependenciesPanel : public Panel {
public:
    DependenciesPanel(Workspace& workspace, Settings& settings) : Panel(workspace, "Dependencies"), settings_(settings) {}
    ~DependenciesPanel() override;

protected:
    void drawContents() override;

private:
    void start(Root& apk);
    void startUpdate();
    void pollUpdate();
    void drawToolbar();
    void drawTable();
    void drawGraph();
    void drawLicenses();
    void drawDetails(const deps::Dependency& d);
    void buildGraph();

    Settings& settings_;
    int apkIdx_ = 0;
    std::string group_;
    const ApkAnalysis* builtWith_ = nullptr;
    bool built_ = false;
    std::future<deps::Report> job_;
    deps::Report report_;
    int view_ = 0;  // 0 table, 1 graph, 2 licenses
    char filter_[128] = {};
    bool vulnerableOnly_ = false;
    int selected_ = -1;
    GraphView graph_;
    std::vector<int> graphNodes_;  // block -> dependency index (-1 for app / category blocks)
    bool graphDirty_ = true;
    bool graphVulnerableOnly_ = false;  // filter the graph was built with

    // Vulnerability database update (Python + OSV.dev).
    ScriptRunner updater_;
    bool updating_ = false;
    std::string updateStatus_;
};
