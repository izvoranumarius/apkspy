#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include "core/ContentSource.hpp"

// Ctrl+click navigation (M3): maps class names to the source files that
// declare them inside one decompiled tree, so a Ctrl+click on an identifier
// can open the defining file. Also used by the Overview panel (M4) to jump
// from a component row to its class.
//
// Threading: the workspace UI thread owns the TreeNode tree and mutates it
// while jadx streams results - workers must never touch it. The caller
// therefore snapshots the candidate file list on the UI thread (only while
// the group is idle) and hands plain paths + a DiskSource-backed
// ContentSource (safe for concurrent reads) to the builder, which reads and
// parses the files off-thread. Lookups hit an immutable snapshot guarded by
// a mutex, so resolve() is safe from any thread.
class SymbolIndex {
public:
    // One candidate file from the UI-thread tree snapshot.
    struct File {
        std::string path;  // absolute disk path (decompiled tree node path)
        bool kotlin = false;
    };

    SymbolIndex() = default;
    ~SymbolIndex();
    SymbolIndex(const SymbolIndex&) = delete;
    SymbolIndex& operator=(const SymbolIndex&) = delete;

    // Rebuilds the index for `group` unless a table for exactly `epoch`
    // already exists (the workspace bumps its epoch whenever the tree
    // changes). Files are read on the worker thread; building never blocks
    // the caller.
    void ensureIndex(const std::string& group, uint64_t epoch, std::vector<File> files,
                     std::shared_ptr<ContentSource> source);

    // Drops one group's table (Remove from Project).
    void purgeGroup(const std::string& group);

    // Drops everything (project closed).
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        tables_.clear();
        queue_.clear();
    }

    // True while a worker is still chewing through this group's files.
    bool building(const std::string& group) const;

    // Resolves `identifier` (short "Foo", nested "Foo$Bar"/"Foo.Bar" or fully
    // qualified "com.example.Foo") inside `group` to a file path. `hintDir`
    // (directory of the file the user clicked in) breaks ties towards the
    // same package. Returns "" when unresolved or still building.
    std::string resolve(const std::string& group, const std::string& identifier,
                        const std::string& hintDir = {}) const;

    // All fully qualified class names whose simple or qualified name contains
    // `needle` (case-insensitive), capped at `limit`. Used by the MCP tools.
    std::vector<std::pair<std::string, std::string>> findClasses(const std::string& group,
                                                                  const std::string& needle,
                                                                  size_t limit) const;

private:
    // Immutable name -> path mapping produced by one build pass.
    struct Table {
        uint64_t epoch = 0;
        // Every indexed file path, stored exactly once; the maps refer to it
        // by index (paths are long absolute strings - storing a copy per
        // declared name multiplied the index size for large APKs).
        std::vector<std::string> paths;
        // Short name (Foo, Bar from Foo$Bar.java) -> candidate path indices.
        std::unordered_map<std::string, std::vector<uint32_t>> byName;
        // Fully qualified name (com.example.Foo) -> path index.
        std::unordered_map<std::string, uint32_t> byQualifiedName;
    };

    struct Request {
        std::string group;
        uint64_t epoch = 0;
        std::vector<File> files;
        std::shared_ptr<ContentSource> source;
    };

    void workerLoop();
    static std::shared_ptr<const Table> buildTable(const Request& req, const std::atomic<bool>& stop);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<const Table>> tables_;
    std::deque<Request> queue_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> workerActive_{false};
};
