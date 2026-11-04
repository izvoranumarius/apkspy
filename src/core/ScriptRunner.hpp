#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/Process.hpp"

// Runs one external script at a time and collects its output. Scripts use the
// installed Python rather than an embedded interpreter, so ApkSpy gains no
// dependency and scripts can use any package of that Python.
class ScriptRunner {
public:
    ScriptRunner() = default;
    ~ScriptRunner();
    ScriptRunner(const ScriptRunner&) = delete;
    ScriptRunner& operator=(const ScriptRunner&) = delete;

    bool start(const std::vector<std::string>& argv, std::string& error);
    void stop();  // kills the process tree; output so far stays readable
    bool running() const { return running_.load(); }
    int exitCode() const { return exitCode_.load(); }  // -1 when killed
    std::vector<std::string> takeOutput();

    static constexpr size_t kMaxQueuedLines = 20000;

private:
    void join();

    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<int> exitCode_{0};
    std::mutex mutex_;
    std::deque<std::string> output_;
    size_t dropped_ = 0;
    bool killable_ = false;
    ChildProcess::Handle kill_{};
};

// The Python side of the scripting API, written next to the user's scripts.
namespace scripting {

// Writes apkspy.py, run_script.py and the private endpoint's session file into `dir`.
bool writeSupport(const std::string& dir, const std::string& url, const std::string& token, std::string& error);
// argv that runs `script` with the API on its import path.
std::vector<std::string> command(const std::string& python, const std::string& dir, const std::string& script);
const char* exampleScript();

}  // namespace scripting
