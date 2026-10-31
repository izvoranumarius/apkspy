#pragma once
#include <memory>
#include <string>
#include <vector>
#include "core/ApkArchive.hpp"
#include "core/ContentSource.hpp"
#include "document/Document.hpp"
#include "core/JadxRunner.hpp"
#include "core/SearchService.hpp"

struct Root {
    enum class Kind { Apk, Decompiled };
    // Unique group name, shared by the APK entry and its decompiled tree so
    // both panels group and label an APK identically.
    std::string title;
    Kind kind = Kind::Apk;
    std::string apkPath;  // (Apk) absolute path of the APK on disk
    std::string outDir;   // (Decompiled) jadx output directory
    std::unique_ptr<TreeNode> tree;
    std::shared_ptr<ContentSource> source;
};

// A tab saved by a project (or session) that still has to be re-opened
// (decompiled files can only be restored once jadx has produced them).
struct PendingTab {
    int rootKind = 0;   // 0 = APK root, 1 = decompiled root
    std::string group;  // group name of the owning APK ("" = first of kind)
    std::string path;
    bool active = false;
};

// The workspace owns everything opened from one or more APKs: the archive
// trees, the decompiled trees, the documents and the jadx runs. It supports
// multiple APKs at once - one jadx decompilation runs at a time, further APKs
// are queued.
class Workspace {
public:
    // How an explorer click should open a document.
    enum class OpenMode { Preview, Permanent };

    Workspace() = default;

    // Multi-APK project model ------------------------------------------------
    // Adds an APK (without disturbing the others) and starts or queues its
    // decompilation. jadxOutHint re-attaches decompiled results saved by a
    // project without re-running jadx when the directory still exists.
    // 'group' must be unique (Application generates it via Project).
    bool addApk(std::string path, std::string group, std::string jadxOutHint = {});
    // Removes an APK entry, its decompiled results and all related documents.
    // The APK file itself is never touched. Refuses while that APK is being
    // decompiled.
    bool removeApk(Root* apkRoot);
    Root* findApkByPath(const std::string& path) const;
    std::vector<Root*> apkRoots() const;
    std::vector<Root*> decompiledRoots() const;
    // Root of the given kind by group name; an empty group means the first
    // root of that kind.
    Root* rootByGroup(const std::string& group, Root::Kind kind) const;

    void update();
    void openNode(Root& root, const TreeNode& node, int line = -1, OpenMode mode = OpenMode::Permanent);
    void openByPath(int rootKind, const std::string& group, const std::string& path, OpenMode mode);
    // Promotes a preview tab so it survives further explorer clicks.
    void promoteDocument(Document* doc);
    void closeDocument(const Document* doc);
    void closeAllDocuments();
    void closeAll();
    Document* takeFocusRequest();
    void log(std::string message);
    void clearLog() { log_.clear(); }

    // Session restore: tabs that could not be opened yet.
    void setPendingTabs(std::vector<PendingTab> tabs) { pendingTabs_ = std::move(tabs); }

    // Merges the running (or just finished) jadx output into the Decompiled
    // tree. Nodes are merged incrementally so already-open documents stay
    // valid; this is what makes partially generated results browsable while
    // jadx is still running.
    void refreshDecompiledTree();

    std::vector<std::unique_ptr<Root>>& roots() { return roots_; }
    std::vector<std::unique_ptr<Document>>& documents() { return documents_; }
    const std::vector<std::unique_ptr<Document>>& documents() const { return documents_; }
    const std::vector<std::string>& logLines() const { return log_; }
    SearchService& search() { return search_; }
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
    void applyPendingTabs(Root::Kind kind, const std::string& group);
    void startNextJadx();
    // Creates (or reuses) the decompiled root for an APK. If the sources
    // directory already exists the tree is attached from disk, otherwise jadx
    // is queued to produce it.
    void attachDecompiled(Root& apkRoot, const std::string& outDir);
    // The sources/ subdirectory of a jadx output directory - the Decompiled
    // panel only shows sources (resources stay on disk, browsable via Files).
    static std::string sourcesDir(const std::string& outDir);

    std::vector<std::unique_ptr<Root>> roots_;
    std::vector<std::unique_ptr<Document>> documents_;
    std::vector<std::string> log_;
    std::string jadxPath_ = "jadx";
    std::string jadxArgs_;
    JadxRunner jadx_;
    SearchService search_;
    Document* pendingFocus_ = nullptr;
    bool decompileSwitch_ = false;
    bool decompileFailure_ = false;
    std::chrono::steady_clock::time_point lastTreeRefresh_ = std::chrono::steady_clock::now();
    std::vector<PendingTab> pendingTabs_;

    // Decompile scheduling: one jadx run at a time, queued per APK group.
    std::vector<std::string> jadxQueue_;
    std::string jadxActiveGroup_;  // group being decompiled right now
};
