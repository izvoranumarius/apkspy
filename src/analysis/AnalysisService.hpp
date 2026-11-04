#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/NativeCode.hpp"

// Runs the bytecode analysis (ApkAnalysis) for APK groups in the background.
//
// Threading: start/cancel/purge/clear are called from the owning thread (the
// UI thread in the app, the dispatcher in headless MCP mode). Each job runs
// on its own worker and opens a PRIVATE ApkArchive on the APK path - the
// workspace's archive is not thread-safe and is never touched here. Results
// are immutable shared_ptrs: readers on any thread keep what they hold alive
// even if the group is purged meanwhile, and memory is released as soon as
// the last reader lets go.
class AnalysisService {
public:
    enum class State { None, Running, Ready, Failed, Cancelled };

    struct Status {
        State state = State::None;
        size_t done = 0;
        size_t total = 0;
        std::string error;
        std::string phase;  // "reading classes.dex", "indexing", ...
    };

    AnalysisService() = default;
    ~AnalysisService();
    AnalysisService(const AnalysisService&) = delete;
    AnalysisService& operator=(const AnalysisService&) = delete;

    // Starts (or restarts) the analysis of `group`. No-op while it is already
    // running or ready for the same APK path, unless `force`.
    void start(const std::string& group, const std::string& apkPath, bool force = false);
    void cancel(const std::string& group);
    // Drops a group's job and result (Remove from Project).
    void purge(const std::string& group);
    void clear();

    Status status(const std::string& group) const;
    std::shared_ptr<const ApkAnalysis> get(const std::string& group) const;
    // Groups that have a job (any state).
    std::vector<std::string> groups() const;

    // Reaps finished worker threads; call periodically from the owning thread.
    void update();

    // Loads and parses one native library entry from the APK (own archive,
    // so it is safe from any thread). Results are cached per (apk, entry).
    std::shared_ptr<const ElfFile> loadElf(const std::string& apkPath, const std::string& entry, std::string& error);
    // Builds (or returns the cached) code analysis of an AArch64 library: function
    // list, reference index, listings. Same threading rules as loadElf.
    std::shared_ptr<const NativeCode> loadNative(const std::string& apkPath, const std::string& entry,
                                                 const std::atomic<bool>* cancel, std::string& error);

private:
    struct Job {
        std::string apkPath;
        std::thread worker;
        std::atomic<bool> stop{false};
        std::atomic<bool> finished{false};
        std::atomic<size_t> done{0};
        std::atomic<size_t> total{0};
        mutable std::mutex mutex;  // guards the fields below
        State state = State::Running;
        std::string error;
        std::string phase;
        std::shared_ptr<const ApkAnalysis> result;
    };
    static void run(Job* job);
    void stopJob(Job& job);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<Job>> jobs_;
    // Detached-but-not-joined jobs (purged while running): joined in update().
    std::vector<std::unique_ptr<Job>> retired_;

    std::mutex elfMutex_;
    std::unordered_map<std::string, std::weak_ptr<const ElfFile>> elfCache_;
    std::unordered_map<std::string, std::weak_ptr<const NativeCode>> nativeCache_;
    // The most recent library stays alive so consecutive tool calls do not re-sweep it.
    std::shared_ptr<const NativeCode> lastNative_;
};
