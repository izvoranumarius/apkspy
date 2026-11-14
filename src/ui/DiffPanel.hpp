#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "analysis/ApkDiff.hpp"
#include "core/TextDiff.hpp"
#include "ui/Panel.hpp"

// Version comparison of two APKs of the project (Analysis workspace). The
// inputs are gathered on the UI thread (Workspace::diffSide) and compared on a
// worker; the panel lists every section with its counts and shows a changed
// method side by side - the normalised smali the diff compared, or the
// built-in decompiler's output - with the changed lines highlighted.
class DiffPanel : public Panel {
public:
    DiffPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Diff"), showPanel_(std::move(showPanel)) {}
    ~DiffPanel() override;

protected:
    void drawContents() override;
    bool codeArea() const override { return true; }

private:
    enum Section { Summary, Manifest, Components, Classes, Methods, Resources, Native, Libraries, Endpoints, Files, SectionCount };

    void start();
    void cancel();
    void drawToolbar(const std::vector<Root*>& apks);
    void drawSectionList();
    void drawSection();
    void drawSummary();
    void drawMethods();
    void drawSideBySide();
    void selectMethod(int index);
    void openMethod(const std::string& signature, bool sideB);
    size_t sectionCount(Section s) const;
    bool passes(std::string_view text) const;

    std::function<void(const std::string&)> showPanel_;
    std::string groupA_, groupB_;
    std::string autoCompared_;  // the A/B pair last compared automatically
    std::string pendingMethod_;  // show_diff: method to select once the comparison is ready
    std::future<ApkDiff> job_;
    std::shared_ptr<std::atomic<bool>> cancel_;
    bool valid_ = false;
    ApkDiff diff_;
    std::shared_ptr<const ApkAnalysis> analysisA_, analysisB_;  // what the diff saw
    std::string titleA_, titleB_;
    Section section_ = Summary;
    char filter_[128] = {};

    // Side by side
    int method_ = -1;           // index into diff_.methodDetails
    bool decompiled_ = false;   // decompiler output instead of smali
    std::string textA_, textB_;
    std::vector<std::string_view> linesA_, linesB_;
    std::vector<textdiff::Row> rows_;
    std::vector<int> changes_;  // first row of each change block
    int scrollToRow_ = -1;
    int changeCursor_ = 0;  // change block the last Prev / Next jumped to
    std::string sideError_;
};
