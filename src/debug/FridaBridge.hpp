#pragma once
#include <deque>
#include <mutex>
#include <string>
#include <vector>

class ScriptRunner;
namespace adb {
class Adb;
}

// Runtime hooking through Frida, without linking frida-core: the `frida` CLI
// is spawned as an external process (like scripts run the installed Python)
// and its console output is collected as events. If frida is not installed
// every call fails with a clear error - nothing else degrades.
//
// A session is `frida -U -f <package> -l <script>` (spawn) or
// `frida -U -n <process> -l <script>` (attach). Loading more scripts while a
// session runs restarts it with the full set (the CLI takes several -l).
class FridaBridge {
public:
    struct Event {
        uint64_t seq = 0;
        std::string tag;      // "log", "send", "error"
        std::string message;  // one console line (JSON payloads kept as text)
    };

    explicit FridaBridge(ScriptRunner& runner) : runner_(runner) {}

    // Starts a session (kills a running one first). `script` is a JS file
    // path; empty = spawn without instrumentation.
    bool spawn(const std::string& serial, const std::string& package, const std::string& script,
               std::string& error);
    bool attach(const std::string& serial, const std::string& process, const std::string& script,
                std::string& error);
    // Adds a script to the running session (restarts it with all scripts).
    bool loadScript(const std::string& script, std::string& error);
    void stop();
    bool running() const;

    // Drains new console lines into events (call periodically from the UI).
    void poll();
    // Events with seq > since (newest last), bounded.
    std::vector<Event> events(uint64_t since, size_t max = 500) const;
    uint64_t head() const;

    static constexpr size_t kMaxEvents = 5000;

private:
    bool start(std::string& error);
    std::string fridaPath_ = "frida";
    ScriptRunner& runner_;
    std::string serial_, target_;
    bool spawnMode_ = false;
    std::vector<std::string> scripts_;
    mutable std::mutex m_;
    std::deque<Event> events_;
    uint64_t seq_ = 0;
};
