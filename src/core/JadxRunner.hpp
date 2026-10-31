#pragma once
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class JadxRunner {
public:
    enum class State { Idle, Running, Done, Failed };

    JadxRunner() = default;
    ~JadxRunner();
    JadxRunner(const JadxRunner&) = delete;
    JadxRunner& operator=(const JadxRunner&) = delete;

    // Launches "jadx [extraArgs] -d <outDir> <apkPath>" on a worker thread.
    bool start(const std::string& jadxPath, const std::string& apkPath, const std::string& outDir,
               const std::string& extraArgs = {});
    State state() const { return state_.load(); }
    const std::string& outDir() const { return outDir_; }
    std::vector<std::string> drainLog();

    // Live progress information while the process runs.
    int warningCount() const { return warnings_.load(); }
    int errorCount() const { return errors_.load(); }
    int processedCount() const { return processed_.load(); }
    int elapsedSeconds() const;

    // Runs "jadx --version" on a worker thread and captures the first line.
    void testInstall(const std::string& jadxPath);
    bool testRunning() const { return testRunning_.load(); }
    // Returns the finished test result: an empty string while still running.
    std::string takeTestResult(bool& ok);

private:
    void run(std::string command);
    void countLine(const std::string& line);

    std::thread worker_;
    std::atomic<State> state_{State::Idle};
    std::mutex mutex_;
    std::vector<std::string> pending_;
    std::string outDir_;
    std::chrono::steady_clock::time_point started_;
    std::atomic<int> warnings_{0};
    std::atomic<int> errors_{0};
    std::atomic<int> processed_{0};

    std::thread testWorker_;
    std::mutex testMutex_;
    std::string testResult_;
    std::atomic<bool> testRunning_{false};
    std::atomic<bool> testOk_{false};
};
