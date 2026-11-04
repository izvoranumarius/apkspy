#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "analysis/AnalysisService.hpp"
#include "core/Annotations.hpp"
#include "core/ApkArchive.hpp"
#include "core/ResourceTable.hpp"
#include "core/ContentSource.hpp"
#include "core/ExportJob.hpp"
#include "core/NavHistory.hpp"
#include "core/RootKind.hpp"
#include "core/SymbolIndex.hpp"
#include "document/Document.hpp"
#include "core/JadxRunner.hpp"
#include "core/SearchService.hpp"

struct Root {
    using Kind = RootKind;
    // Unique group name, shared by the APK entry and its decompiled tree so
    // both panels group and label an APK identically.
    std::string title;
    Kind kind = Kind::Apk;
    std::string apkPath;  // (Apk) absolute path of the APK on disk
    std::string outDir;   // (Decompiled) jadx output directory (owned by ApkSpy)
    std::unique_ptr<TreeNode> tree;
    std::shared_ptr<ContentSource> source;
    // (Apk) parsed resources.arsc, loaded on first use (Workspace::resources).
    std::shared_ptr<const ResourceTable> resources;
    bool resourcesLoaded = false;
};

// A tab saved by a project (or session) that still has to be re-opened
// (decompiled files can only be restored once jadx has produced them).
struct PendingTab {
    RootKind rootKind = RootKind::Apk;
    std::string group;  // group name of the owning APK ("" = first of kind)
    std::string path;
    bool active = false;
};

// The workspace owns everything opened from one or more APKs: the archive
// trees, the decompiled trees, the documents and the jadx runs. It supports
// multiple APKs at once - one jadx decompilation runs at a time, further APKs
// are queued.
//
// jadx output directories live under <temp>/apkspy/<stem>_<hash>, where the
// hash covers the APK's path, size and mtime: two APKs with the same file
// name never share results, and rebuilding an APK invalidates stale results.
// Every directory ApkSpy creates there carries a marker file; results are
// only reused when the marker says a previous jadx run finished cleanly.
class Workspace {
public:
    // How an explorer click should open a document.
    enum class OpenMode { Preview, Permanent };

    Workspace() = default;

    // Multi-APK project model ------------------------------------------------
    // Adds an APK (without disturbing the others) and starts or queues its
    // decompilation. The jadx output directory is always derived from the
    // APK itself - callers (and project files) have no say in it, so a
    // malicious .apkspy file can never point ApkSpy at arbitrary directories.
    // 'group' must be unique (Application generates it via Project).
    bool addApk(std::string path, std::string group);
    // Removes an APK entry, its decompiled results (the output directory is
    // deleted when ApkSpy owns it) and all related documents. The APK file
    // itself is never touched. Refuses while that APK is being decompiled.
    bool removeApk(Root* apkRoot);
    Root* findApkByPath(const std::string& path) const;
    std::vector<Root*> apkRoots() const;
    std::vector<Root*> decompiledRoots() const;
    // Root of the given kind by group name; an empty group means the first
    // root of that kind.
    Root* rootByGroup(const std::string& group, Root::Kind kind) const;
    // True while the given group's jadx run is actively merging results into
    // its decompiled tree (searches on that tree are stopped meanwhile).
    bool isGroupDecompiling(const std::string& group) const {
        return jadx_.state() == JadxRunner::State::Running && jadxActiveGroup_ == group;
    }

    // The directory ApkSpy keeps decompiled results in.
    static std::string jadxCacheRoot();
    // True when the directory was created by ApkSpy (marker file present) -
    // only such directories are ever remove_all'ed.
    static bool isOwnedOutDir(const std::string& dir);

    void update();
    // Kills a running jadx and drops all queued runs; the output of the
    // cancelled run is discarded (no completion marker is written).
    void cancelDecompile();
    void openNode(Root& root, const TreeNode& node, int line = -1, OpenMode mode = OpenMode::Permanent);
    void openByPath(RootKind rootKind, const std::string& group, const std::string& path, OpenMode mode);

    // Back/Forward navigation (M2) -----------------------------------------
    // Records a jump in the history and opens the destination as a permanent
    // tab at `line` (0-based; -1 keeps the file's current view). `origin` is
    // the location the user is leaving (active document + top visible line);
    // pass nullptr when there is none. This is THE entry point for explicit
    // jumps (search hits, symbol navigation, explorer jumps).
    void navigateTo(Root& root, const TreeNode& node, int line, const NavLocation* origin);
    // Records an already-performed same-document jump (Go to Line) without
    // re-opening the node - the document stays exactly as it is.
    void recordJump(const NavLocation& origin, const NavLocation& dest) { nav_.navigate(&origin, dest); }
    // Walk the history; skipped entries (removed files/APKs) are logged.
    bool navBack();
    bool navForward();
    bool canNavBack() const { return nav_.canBack(); }
    bool canNavForward() const { return nav_.canForward(); }
    // A document's position as a history location (uses its top visible line).
    NavLocation locationOf(const Document& doc) const;
    NavHistory& nav() { return nav_; }

    // Ctrl+click navigation (M3) -------------------------------------------
    // The symbol index maps class names to files of one decompiled tree. The
    // workspace owns the epoch: it bumps whenever a group's tree changed, so
    // a stale index is rebuilt exactly once per change.
    SymbolIndex& symbols() { return symbols_; }
    uint64_t treeEpoch(const std::string& group) const;
    // Snapshots the group's candidate files on the UI thread (never while
    // that group is decompiling - the tree is being mutated then) and hands
    // them to the background builder. Safe to call repeatedly.
    void ensureSymbolIndex(const std::string& group);
    // Resolves `identifier` in the group's index and jumps to the class file
    // (history-recorded). Returns false when unresolved - callers decide on
    // the fallback (the Overview panel opens the manifest instead).
    bool openSymbol(const std::string& group, const std::string& identifier, const std::string& hintDir,
                    const NavLocation* origin);

    // Export / extract (M5) -------------------------------------------------
    // Writes one node to `destFile` (a user-picked path): raw bytes, or the
    // decoded XML text for compiled Android XML when `decoded` is set. Runs
    // synchronously on the UI thread (single ContentSource read).
    bool exportNode(Root& root, const TreeNode& node, const std::string& destFile, bool decoded);
    // Queues a folder export; the job is pumped from update() (one item per
    // frame, UI thread). Names from archive content are sanitized per the
    // SafePath module.
    void exportFolder(Root& root, const TreeNode& folder, const std::string& destDir, bool decoded);
    ExportJob& exportJob() { return export_; }
    // resources.arsc of the APK group (parsed once, UI thread); nullptr when
    // the APK has none or it is malformed.
    std::shared_ptr<const ResourceTable> resources(const std::string& group);
    // Generated documents (M6): shows `text` as a read-only tab of the
    // group's virtual root (created on demand) at `path` ("smali/Lfoo;.smali"),
    // replacing the content when the path is reopened, and jumps to `line`
    // (0-based) through the navigation history. Closing the tab frees it.
    void openGenerated(const std::string& group, const std::string& path, const std::string& title,
                       std::string text, int line = 0);
    // Smali listing of a method, on the instruction at `pc` when given.
    void openMethodListing(const std::string& group, const ApkAnalysis& a, const ApkAnalysis::MethodDef& m,
                           uint32_t pc = UINT32_MAX);
    // Promotes a preview tab so it survives further explorer clicks.
    void promoteDocument(Document* doc);
    void closeDocument(const Document* doc);
    void closeAllDocuments();
    void closeAll();
    Document* takeFocusRequest();
    bool hasFocusRequest() const { return pendingFocus_ != nullptr; }
    void requestFocus(Document* doc) { pendingFocus_ = doc; }
    // Every line starts with its source: "[jadx] ...". See logsev::kSources.
    void log(std::string message, const char* source = "app");
    void clearLog() { log_.clear(); }
    size_t logTrims() const { return logTrims_; }  // changes when old lines are dropped

    // The document whose tab is currently visible in the editor. Plain UI
    // view state, set by EditorPanel every frame; the shared View menu uses
    // it for enable states and as the origin of navigation jumps (M2).
    Document* activeDocument() const { return activeDocument_; }
    void setActiveDocument(Document* doc) { activeDocument_ = doc; }

    // Bumped by every structural change (roots added/removed, documents
    // opened/closed/promoted). Together with Document::editSerial() this
    // lets the title bar skip its per-frame dirty check.
    uint64_t stateVersion() const { return stateVersion_; }

    // Session restore: tabs that could not be opened yet.
    void setPendingTabs(std::vector<PendingTab> tabs) { pendingTabs_ = std::move(tabs); }

    // Merges the running (or just finished) jadx output for `group` into its
    // Decompiled tree. Nodes are merged incrementally so already-open
    // documents stay valid; this is what makes partially generated results
    // browsable while jadx is still running. An empty group means the
    // currently active run.
    void refreshDecompiledTree(const std::string& group = {});

    std::vector<std::unique_ptr<Root>>& roots() { return roots_; }
    std::vector<std::unique_ptr<Document>>& documents() { return documents_; }
    const std::vector<std::unique_ptr<Document>>& documents() const { return documents_; }
    const std::vector<std::string>& logLines() const { return log_; }
    SearchService& search() { return search_; }
    // Bytecode analysis (DEX parsing, xrefs, call graphs) per APK group.
    AnalysisService& analysis() { return analysis_; }
    Annotations& annotations() { return annotations_; }
    const Annotations& annotations() const { return annotations_; }

    // UI request (owner thread): show a native function / address of a library in the Analysis panel.
    struct NativeViewRequest {
        std::string group, entry, target;
        std::string view = {};  // "listing", "graph", "calls" or empty to keep the current one
    };
    void requestNativeView(NativeViewRequest r) {
        nativeView_ = std::move(r);
        nativeViewPending_ = true;
    }
    // Same for a bytecode method; view is "listing", "graph" or "calls".
    struct MethodViewRequest {
        std::string group, method, view;
    };
    void requestMethodView(MethodViewRequest r) {
        methodView_ = std::move(r);
        methodViewPending_ = true;
    }
    bool takeMethodView(MethodViewRequest& out) {
        if (!methodViewPending_) return false;
        out = std::move(methodView_);
        methodViewPending_ = false;
        return true;
    }
    bool takeNativeView(NativeViewRequest& out) {
        if (!nativeViewPending_) return false;
        out = std::move(nativeView_);
        nativeViewPending_ = false;
        return true;
    }
    // Starts the analysis of `group` (no-op while running / ready).
    void startAnalysis(const std::string& group, bool force = false);
    const JadxRunner& jadx() const { return jadx_; }
    JadxRunner& jadx() { return jadx_; }
    const std::string& jadxPath() const { return jadxPath_; }
    void setJadxPath(std::string path) { jadxPath_ = std::move(path); }
    const std::string& jadxArgs() const { return jadxArgs_; }
    void setJadxArgs(std::string args) { jadxArgs_ = std::move(args); }

    // Set once when a decompilation completes; consumed by the explorer to
    // switch to the Decompiled tab automatically.
    bool takeDecompileSwitch();
    // Set once when jadx fails to start or exits with an error.
    bool takeDecompileFailure();

private:
    Document* findDocument(const TreeNode& node);
    bool navStep(bool forward);
    static void collectSymbolFiles(const TreeNode& node, std::vector<SymbolIndex::File>& out);
    void collectExportItems(Root& root, const TreeNode& folder, const TreeNode& node,
                            std::vector<ExportJob::Item>& items) const;
    void applyPendingTabs(Root::Kind kind, const std::string& group);
    void startNextJadx();
    // Creates (or reuses) the decompiled root for an APK. Finished results
    // (completion marker + sources/) are attached from disk, otherwise jadx
    // is queued to produce them.
    void attachDecompiled(Root& apkRoot, const std::string& outDir);
    // The sources/ subdirectory of a jadx output directory - the Decompiled
    // panel only shows sources (resources stay on disk, browsable via Files).
    static std::string sourcesDir(const std::string& outDir);
    void bumpVersion() { ++stateVersion_; }

    std::vector<std::unique_ptr<Root>> roots_;
    std::vector<std::unique_ptr<Document>> documents_;
    std::vector<std::string> log_;
    size_t logTrims_ = 0;
    std::string jadxPath_ = "jadx";
    std::string jadxArgs_;
    JadxRunner jadx_;
    SearchService search_;
    AnalysisService analysis_;
    std::unordered_set<std::string> analysisReported_;  // groups whose completion was logged
    Document* pendingFocus_ = nullptr;
    Annotations annotations_;
    NativeViewRequest nativeView_;
    MethodViewRequest methodView_;
    bool methodViewPending_ = false;
    bool nativeViewPending_ = false;
    Document* activeDocument_ = nullptr;  // visible tab, set by the editor panel
    bool decompileSwitch_ = false;
    bool decompileFailure_ = false;
    std::chrono::steady_clock::time_point lastTreeRefresh_ = std::chrono::steady_clock::now();
    std::vector<PendingTab> pendingTabs_;
    NavHistory nav_;              // Back/Forward across explicit jumps (per session)
    bool suppressNav_ = false;    // true while navStep re-opens a document
    SymbolIndex symbols_;         // class name -> file index for Ctrl+click (M3)
    ExportJob export_;            // running folder export (M5)
    std::unordered_map<std::string, uint64_t> treeEpochs_;  // per-group tree change counter
    uint64_t stateVersion_ = 1;

    // Decompile scheduling: one jadx run at a time, queued per APK group.
    std::vector<std::string> jadxQueue_;
    std::string jadxActiveGroup_;  // group being decompiled right now
};
