#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include "core/ContentSource.hpp"

struct SearchHit {
    const TreeNode* node;
    int line;
    std::string text;  // trimmed matching line, capped in length
};

class SearchService {
public:
    enum class Mode { Text, Filenames, Classes, Methods, Fields };

    SearchService() = default;
    ~SearchService();
    SearchService(const SearchService&) = delete;
    SearchService& operator=(const SearchService&) = delete;

    // Starts a search over one decompiled tree. 'group' is the owning APK's
    // group name; it is remembered so hits can always be opened with their
    // own root, even after the panel switched to another APK.
    void start(const TreeNode* root, const ContentSource* source, std::string query, Mode mode,
               std::string group);
    void stop();
    bool running() const { return running_.load(); }
    Mode mode() const { return mode_; }
    const std::string& group() const { return group_; }

    // True when the hit limit was reached (the result list was truncated).
    bool truncated() const { return truncated_.load(); }
    // Number of files skipped because they exceeded the size limit.
    int skippedFiles() const { return skipped_.load(); }

    // The per-line matcher shared with the MCP code search (pure, thread
    // safe). `query` must already be lowered ASCII (as start() does).
    static bool lineMatches(Mode mode, std::string_view line, std::string_view query);

    template <typename F>
    void withHits(F&& fn) const {
        std::lock_guard<std::mutex> lock(mutex_);
        fn(hits_);
    }

private:
    void run(const TreeNode* root, const ContentSource* source, std::string query);
    void scan(const TreeNode& node, const ContentSource& source, const std::string& query);
    void scanFileNames(const TreeNode& node, const std::string& query);
    bool addHit(const TreeNode& node, int line, const char* begin, const char* end);

    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::vector<SearchHit> hits_;
    std::vector<uint8_t> readBuffer_;  // worker-thread only: reused per scanned file
    Mode mode_ = Mode::Text;
    std::string group_;
    std::atomic<bool> truncated_{false};
    std::atomic<int> skipped_{0};
};
