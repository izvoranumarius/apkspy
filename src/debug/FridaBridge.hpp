#pragma once
#include <deque>
#include "analysis/Abi.hpp"
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

// Deploying and running frida-server on a device: Frida needs a matching
// frida-server binary running (usually as root) before the CLI can connect.
// These helpers push a binary the user supplies and run it; the external
// `frida` CLI and a rooted device remain prerequisites.
namespace fridaserver {

// A remote path safe to drop into an adb shell command ([A-Za-z0-9._/-]).
bool validRemotePath(const std::string& p);

// Checks that `localBinary` is an ELF for an ABI the device runs (frida-server must match the device, not the host).
// Returns the ABI name ("arm64-v8a", ...) in `abiName`; false with a message when the file is not an ELF, is for an
// architecture Android does not run, or for an ABI missing from `device`.
bool checkBinary(const std::string& localBinary, const abi::DeviceAbis& device, std::string& abiName, std::string& error);

// `adb root` (best effort), then push `localBinary` to `remotePath` and
// chmod it 0755. Synchronous; blocking. False (with error) when push or
// chmod fail. `adbPath` is the adb executable.
bool deploy(const std::string& adbPath, const std::string& serial, const std::string& localBinary,
            const std::string& remotePath, std::string& error);

// argv that runs the server in the foreground of an adb shell, so a
// ChildProcess the caller keeps alive owns the running server.
std::vector<std::string> runArgv(const std::string& adbPath, const std::string& serial, const std::string& remotePath);

// True when a frida-server process is running on the device (pidof).
bool running(const std::string& adbPath, const std::string& serial);

}  // namespace fridaserver
