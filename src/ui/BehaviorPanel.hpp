#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include "analysis/BehaviorGraph.hpp"
#include "ui/GraphView.hpp"
#include "ui/Panel.hpp"

// Behavior graph of the selected APK (Analysis workspace): manifest
// components, the app methods they reach and the permissions, endpoints,
// storage and native code those methods touch. Built on a worker from the
// bytecode analysis; the panel only projects the result (kind filters,
// method or class granularity, neighbourhood focus, flagged paths) into the
// shared GraphView. Double-click navigates: methods and classes open their
// source (the Function, References and Decompiler panels follow), native
// symbols and libraries open in the native listing.
class BehaviorPanel : public Panel {
public:
    BehaviorPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Behavior"), showPanel_(std::move(showPanel)) {}
    ~BehaviorPanel() override;

protected:
    void drawContents() override;
    bool codeArea() const override { return true; }

private:
    void startBuild(Root& apk, const std::shared_ptr<const ApkAnalysis>& analysis);
    void cancelBuild();
    void project();  // model -> view_
    void drawToolbar();
    void drawDetails();
    void select(int node, bool focusInGraph);
    void navigate(int node);
    std::string nativeLibraryFor(int node) const;
    std::vector<int> neighbours(int node, bool incoming) const;

    std::function<void(const std::string&)> showPanel_;
    int apkIdx_ = 0;
    std::string group_;
    const ApkAnalysis* owner_ = nullptr;  // identity only
    std::vector<std::string> libEntries_;  // lib/<abi>/*.so of the APK, preferred ABI first

    std::future<behavior::Graph> job_;
    std::shared_ptr<std::atomic<bool>> cancel_;
    bool built_ = false;
    behavior::Graph graph_;
    std::string error_;

    // View options
    bool showKind_[behavior::kNodeKinds] = {true, true, true, true, true, true, true};
    int granularity_ = 0;  // 0 overview (components -> capabilities), 1 classes, 2 methods
    bool flaggedOnly_ = false;
    bool hideIsolated_ = true;
    int focus_ = -1;       // model node the view is centred on, -1 = whole graph
    int focusDepth_ = 2;
    char search_[128] = {};
    std::string searchApplied_;
    int searchCursor_ = -1;

    // Projection
    bool dirty_ = true;
    GraphView view_;
    std::vector<int> viewToModel_;
    std::vector<int> modelToView_;
    std::vector<int> owner_of_;  // method -> its class / component node
    size_t hiddenByCap_ = 0;
    int selected_ = -1;  // model node
    int lastViewSelected_ = -1;
    std::vector<behavior::Reach> reach_;  // capabilities of the selected component
    int reachOf_ = -1;
};
