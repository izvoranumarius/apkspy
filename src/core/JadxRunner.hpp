#pragma once
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Runs jadx as a child process WITHOUT a shell: the command is passed as an
// argv array (CreateProcessW on Windows, posix_spawn elsewhere), so file
// names can never inject commands. The process handle is kept around so a
// running decompilation can be cancelled (and is killed on shutdown instead
// of blocking the exit for minutes).
class JadxRunner {
public:
    enum class State { Idle, Running, Done, Failed, Cancelled };

    JadxRunner() = default;
    ~JadxRunner();
    JadxRunner(const JadxRunner&) = delete;
    JadxRunner& operator=(const JadxRunner&) = delete;

    // Launches "<jadxPath> [extraArgs] -d <outDir> <apkPath>" on a worker
    // thread. jadxPath is used as a single argument (quote it in Settings if
    // it contains spaces); extraArgs is split on whitespace, honouring
    // "double quotes".
    bool start(const std::string& jadxPath, const std::string& apkPath, const std::string& outDir,
               const std::string& extraArgs = {});
    // Kills a running jadx process; the worker thread then finishes with
    // State::Cancelled. Returns true when a run was active.
    bool cancel();
    State state() const { return state_.load(); }
    // Process exit code of the last finished run (0 = clean, -1 = killed).
    int exitCode() const { return exitCode_.load(); }
    const std::string& outDir() const { return outDir_; }
    std::vector<std::string> drainLog();

    // Live progress information while the process runs.
    int warningCount() const { return warnings_.load(); }
    int errorCount() const { return errors_.load(); }
    int processedCount() const { return processed_.load(); }
    // Total classes reported by jadx's "progress: X of Y" lines (0 = unknown).
    int totalCount() const { return total_.load(); }
    // True when the last Done run exited non-zero because some classes
    // failed to decompile (jadx still writes everything else).
    bool finishedWithErrors() const { return finishedWithErrors_.load(); }
    // Error count jadx reported at the end ("finished with errors, count: N").
    int failedClasses() const { return failedClasses_.load(); }
    int elapsedSeconds() const;

    // Runs "jadx --version" on a worker thread and captures the first line.
    // Ignored while a previous test is still running (the UI disables the
    // button for exactly that window).
    void testInstall(const std::string& jadxPath);
    bool testRunning() const { return testRunning_.load(); }
    // Returns the finished test result: an empty string while still running.
    std::string takeTestResult(bool& ok);

private:
    void runDecompile(std::vector<std::string> argv);
    void countLine(const std::string& line);
    void pushLine(std::string line);

    std::thread worker_;
    std::atomic<State> state_{State::Idle};
    std::atomic<int> exitCode_{0};
    std::mutex mutex_;               // guards pending_
    std::vector<std::string> pending_;
    std::string outDir_;
    std::chrono::steady_clock::time_point started_;
    std::atomic<int> warnings_{0};
    std::atomic<int> errors_{0};
    std::atomic<int> processed_{0};
    std::atomic<int> total_{0};
    std::atomic<int> failedClasses_{0};
    std::atomic<bool> finishedWithErrors_{false};
    std::atomic<bool> cancelRequested_{false};
    std::mutex handleMutex_;         // guards the live child handle below
#ifdef _WIN32
    void* childProcess_ = nullptr;   // HANDLE
#else
    int childPid_ = -1;
#endif

    std::thread testWorker_;
    std::mutex testMutex_;
    std::string testResult_;
    std::atomic<bool> testRunning_{false};
    std::atomic<bool> testOk_{false};
};
