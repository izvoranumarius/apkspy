#pragma once
#include <memory>
#include <string>
#include <vector>
#include "core/ContentSource.hpp"
#include "core/TreeNode.hpp"

// Folder export (M5): copies a whole subtree out of a root (APK archive or
// decompiled output) into a destination directory.
//
// Threading: the job is intentionally COOPERATIVE. One item is read and
// written per pump() call, and pump() runs from Workspace::update() on the
// UI thread - exactly the thread that may call ContentSource::read on an
// APK root (ApkArchive is not thread-safe). A large entry costs one frame,
// but the thread-safety rules of the code base stay untouched and no second
// tree snapshot is needed (the walk happened on the UI thread).
class ExportJob {
public:
    enum class State { Idle, Running, Done, Cancelled };

    // One file to copy: `node` must stay valid for the job's lifetime (nodes
    // are only invalidated by tree removals, which cancel the job first) and
    // `source` is the owning root's ContentSource.
    struct Item {
        std::shared_ptr<ContentSource> source;
        const TreeNode* node;
        std::string relativePath;  // archive-entry path relative to the exported folder
    };

    // Starts a job. `destDir` is normalized once here; item names are
    // sanitized at write time (they come from archive content).
    void start(std::string destDir, std::vector<Item> items, bool decoded);
    // Stops after the current item; remaining items are dropped.
    void cancel();
    // Processes one item. Call from Workspace::update() (UI thread).
    void pump();

    bool busy() const { return state_ == State::Running; }
    State state() const { return state_; }
    int total() const { return static_cast<int>(items_.size()); }
    int done() const { return done_; }
    int failed() const { return failed_; }
    const std::string& currentName() const { return currentName_; }
    const std::string& destDir() const { return destDir_; }
    // Consumed error note for the last item (empty when none).
    std::string takeLastError() {
        std::string e = std::move(lastError_);
        lastError_.clear();
        return e;
    }

private:
    void writeOne(const Item& item);

    std::vector<Item> items_;
    size_t next_ = 0;
    int done_ = 0;
    int failed_ = 0;
    bool decoded_ = false;
    bool cancelRequested_ = false;
    State state_ = State::Idle;
    std::string destDir_;
    std::string currentName_;
    std::string lastError_;
};
