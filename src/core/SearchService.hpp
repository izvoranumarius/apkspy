#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/ContentSource.hpp"

struct SearchHit {
    const TreeNode* node;
    std::string label;
    int line;
    std::string text;
};

class SearchService {
public:
    enum class Mode { Text, Filenames, Classes, Methods, Fields };

    static const char* modeName(Mode mode) {
        switch (mode) {
        case Mode::Text: return "Full text";
        case Mode::Filenames: return "Filenames";
        case Mode::Classes: return "Classes";
        case Mode::Methods: return "Methods";
        case Mode::Fields: return "Fields";
        }
        return "Full text";
    }

    SearchService() = default;
    ~SearchService();
    SearchService(const SearchService&) = delete;
    SearchService& operator=(const SearchService&) = delete;

    void start(const TreeNode* root, const ContentSource* source, std::string query, Mode mode);
    void stop();
    bool running() const { return running_.load(); }
    Mode mode() const { return mode_; }

    template <typename F>
    void withHits(F&& fn) const {
        std::lock_guard<std::mutex> lock(mutex_);
        fn(hits_);
    }

private:
    void run(const TreeNode* root, const ContentSource* source, std::string query);
    void scan(const TreeNode& node, const ContentSource& source, const std::string& query);
    void scanFileNames(const TreeNode& node, const std::string& query);
    bool addHit(const TreeNode& node, int line, std::string text);

    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::vector<SearchHit> hits_;
    Mode mode_ = Mode::Text;
};
