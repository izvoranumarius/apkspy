#include "core/JadxRunner.hpp"
#include "core/LogSeverity.hpp"
#include "core/TextUtils.hpp"
#include "core/Paths.hpp"
#include "core/Process.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <signal.h>
#endif


JadxRunner::~JadxRunner() {
    if (worker_.joinable()) {
        cancel();  // never block the shutdown on a live jadx
        worker_.join();
    }
    if (testWorker_.joinable()) testWorker_.join();
}

bool JadxRunner::start(const std::string& jadxPath, const std::string& apkPath, const std::string& outDir,
                       const std::string& extraArgs) {
    if (state_ == State::Running) return false;
    if (worker_.joinable()) worker_.join();
    if (jadxPath.empty() || apkPath.empty() || outDir.empty()) return false;

    outDir_ = outDir;
    warnings_ = 0;
    errors_ = 0;
    processed_ = 0;
    total_ = 0;
    failedClasses_ = 0;
    finishedWithErrors_ = false;
    exitCode_ = 0;
    cancelRequested_ = false;

    std::vector<std::string> argv;
    argv.push_back(jadxPath);
    for (std::string& a : proc::splitArgs(extraArgs)) argv.push_back(std::move(a));
    argv.push_back("-d");
    argv.push_back(outDir);
    argv.push_back(apkPath);

    started_ = std::chrono::steady_clock::now();
    state_ = State::Running;
    worker_ = std::thread(&JadxRunner::runDecompile, this, std::move(argv));
    return true;
}

bool JadxRunner::cancel() {
    if (state_.load() != State::Running) return false;
    cancelRequested_ = true;
    std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
    if (childProcess_) TerminateJobObject((HANDLE)childProcess_, 1);
#else
    if (childPid_ > 0) ::kill(-childPid_, SIGTERM);  // the whole process group
#endif
    return true;
}

int JadxRunner::elapsedSeconds() const {
    if (state_.load() != State::Running) return 0;
    return (int)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_)
        .count();
}

std::vector<std::string> JadxRunner::drainLog() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.swap(pending_);
    return out;
}

void JadxRunner::pushLine(std::string line) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.push_back(std::move(line));
}

// "INFO  - progress: 319 of 11389 (2%)" -> 319 / 11389.
static bool parseProgress(const std::string& line, int& done, int& total) {
    const size_t at = line.find("progress: ");
    if (at == std::string::npos) return false;
    return std::sscanf(line.c_str() + at, "progress: %d of %d", &done, &total) == 2;
}

void JadxRunner::countLine(const std::string& line) {
    switch (logsev::classify(line)) {
    case LogSeverity::Warn: warnings_++; break;
    case LogSeverity::Error: errors_++; break;
    default: break;
    }
    int done = 0, total = 0;
    if (parseProgress(line, done, total)) {
        processed_ = done;
        total_ = total;
    }
    // "ERROR - finished with errors, count: 102" is jadx's own total.
    const size_t at = line.find("finished with errors, count: ");
    if (at != std::string::npos) failedClasses_ = std::atoi(line.c_str() + at + 29);
}

void JadxRunner::runDecompile(std::vector<std::string> argv) {
    ChildProcess proc = ChildProcess::spawn(argv);
    if (!proc.valid()) {
        state_ = State::Failed;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
        childProcess_ = proc.killHandle();  // job object: kills the tree
#else
        childPid_ = proc.killHandle();      // process group id
#endif
    }
    int lastLoggedPercent = -10;
    proc.readAll([this, &lastLoggedPercent](std::string line) {
        countLine(line);
        // Progress lines arrive many times per second: keep one per 10%.
        int done = 0, total = 0;
        if (parseProgress(line, done, total)) {
            const int percent = total > 0 ? (int)(100LL * done / total) : 0;
            if (percent < lastLoggedPercent + 10) return;
            lastLoggedPercent = percent;
        }
        pushLine(std::move(line));
    });
    int code = proc.waitForExit();
    {
        std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
        childProcess_ = nullptr;
#else
        childPid_ = -1;
#endif
    }
    exitCode_ = code;
    if (code != 0 && cancelRequested_.load()) {
        state_ = State::Cancelled;
        return;
    }
    std::error_code ec;
    bool hasSources = std::filesystem::is_directory(
        std::filesystem::path(pathutil::fromUtf8(outDir_)) / "sources", ec);
    // jadx exits with 1 as soon as ANY class fails ("finished with errors,
    // count: N") - routine for real-world apps. The output is still
    // complete for every other class, so that is a success with errors,
    // not a failure (previously the whole result was discarded).
    finishedWithErrors_ = code != 0 && hasSources;
    state_ = hasSources ? State::Done : State::Failed;
}

void JadxRunner::testInstall(const std::string& jadxPath) {
    if (testRunning_.load()) return;  // never join a live test on the UI thread
    if (testWorker_.joinable()) testWorker_.join();
    {
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_.clear();
    }
    testRunning_ = true;
    testWorker_ = std::thread([this, jadxPath] {
        ChildProcess proc = ChildProcess::spawn({jadxPath, "--version"});
        std::string first;
        int code = -1;
        if (proc.valid()) {
            proc.readAll([&first](std::string line) {
                if (first.empty() && !line.empty()) first = std::move(line);
            });
            code = proc.waitForExit();
        }
        bool ok = code == 0 && !first.empty();
        std::string result = first;
        if (result.empty()) result = ok ? "jadx is installed" : "jadx could not be executed";
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_ = std::move(result);
        testOk_ = ok;
        testRunning_ = false;
    });
}

std::string JadxRunner::takeTestResult(bool& ok) {
    std::lock_guard<std::mutex> lock(testMutex_);
    if (testResult_.empty()) return {};
    std::string out = testResult_;
    ok = testOk_.load();
    return out;
}
