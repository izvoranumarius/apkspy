#include "debug/FridaBridge.hpp"
#include <cctype>
#include "core/Process.hpp"
#include "core/ScriptRunner.hpp"

namespace {

bool validToken(const std::string& s, bool allowDots) {
    if (s.empty()) return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-' || c == ':' || (allowDots && c == '.');
        if (!ok) return false;
    }
    return true;
}

const char* kFridaScript = R"(
// Minimal default: log when the app's classes are loaded.
Java.perform(function () {
    send({ type: 'ready' });
});
)";

}  // namespace

bool FridaBridge::spawn(const std::string& serial, const std::string& package, const std::string& script,
                        std::string& error) {
    if (!validToken(serial, true) || !validToken(package, true)) {
        error = "invalid serial or package";
        return false;
    }
    stop();
    serial_ = serial;
    target_ = package;
    spawnMode_ = true;
    scripts_.clear();
    if (!script.empty()) scripts_.push_back(script);
    return start(error);
}

bool FridaBridge::attach(const std::string& serial, const std::string& process, const std::string& script,
                         std::string& error) {
    if (!validToken(serial, true) || process.empty()) {
        error = "invalid serial or process";
        return false;
    }
    stop();
    serial_ = serial;
    target_ = process;
    spawnMode_ = false;
    scripts_.clear();
    if (!script.empty()) scripts_.push_back(script);
    return start(error);
}

bool FridaBridge::loadScript(const std::string& script, std::string& error) {
    if (target_.empty()) {
        error = "no Frida session";
        return false;
    }
    scripts_.push_back(script);
    return start(error);
}

bool FridaBridge::start(std::string& error) {
    // frida CLI: `frida -U -D <serial> [-f <package> | -n <process>] -l <script>...`
    std::vector<std::string> argv = {fridaPath_, "-U"};
    if (!serial_.empty()) {
        argv.push_back("-D");
        argv.push_back(serial_);
    }
    if (spawnMode_) {
        argv.push_back("-f");
        argv.push_back(target_);
    } else {
        argv.push_back("-n");
        argv.push_back(target_);
    }
    // The CLI wants a script file; without one, use the built-in default.
    if (scripts_.empty()) {
        for (const char* line : {"-e", kFridaScript}) argv.push_back(line);
    } else {
        for (const auto& s : scripts_) {
            argv.push_back("-l");
            argv.push_back(s);
        }
    }
    if (!runner_.start(argv, error)) return false;
    std::lock_guard<std::mutex> lock(m_);
    events_.push_back(Event{seq_++, "log", "Frida session started: " +
                                               std::string(spawnMode_ ? "spawn " : "attach ") + target_});
    while (events_.size() > kMaxEvents) events_.pop_front();
    return true;
}

void FridaBridge::stop() {
    runner_.stop();
    scripts_.clear();
    target_.clear();
}

bool FridaBridge::running() const { return runner_.running(); }

void FridaBridge::poll() {
    // The CLI prints one console entry per line; send() payloads are JSON on
    // one line. Classify crude but usefully: lines containing "message" are
    // send() payloads, "Error" the script errors.
    std::vector<std::string> lines = runner_.takeOutput();
    std::lock_guard<std::mutex> lock(m_);
    for (const auto& line : lines) {
        const std::string tag = line.find("\"type\":\"error\"") != std::string::npos      ? "error"
                                : line.find("\"type\"") != std::string::npos              ? "send"
                                : line.find("Error") != std::string::npos                 ? "error"
                                                                                         : "log";
        events_.push_back(Event{seq_++, tag, line});
        while (events_.size() > kMaxEvents) events_.pop_front();
    }
}

std::vector<FridaBridge::Event> FridaBridge::events(uint64_t since, size_t max) const {
    std::lock_guard<std::mutex> lock(m_);
    std::vector<Event> out;
    for (const auto& e : events_) {
        if (e.seq <= since) continue;
        out.push_back(e);
        if (out.size() >= max) break;
    }
    return out;
}

uint64_t FridaBridge::head() const {
    std::lock_guard<std::mutex> lock(m_);
    return seq_;
}

namespace fridaserver {

bool validRemotePath(const std::string& p) {
    if (p.empty() || p[0] != '/') return false;
    for (char c : p)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '/' || c == '-')) return false;
    return true;
}

bool deploy(const std::string& adbPath, const std::string& serial, const std::string& localBinary,
            const std::string& remotePath, std::string& error) {
    if (!validToken(serial, true)) {
        error = "invalid serial";
        return false;
    }
    if (!validRemotePath(remotePath)) {
        error = "invalid remote path";
        return false;
    }
    // Best effort: a Google-APIs emulator takes `adb root`; a production
    // device will refuse it and need an already-rooted frida-server path.
    proc::run({adbPath, "-s", serial, "root"}, 15000);
    proc::run({adbPath, "-s", serial, "wait-for-device"}, 15000);
    const proc::RunResult push = proc::run({adbPath, "-s", serial, "push", localBinary, remotePath}, 120000);
    if (!push.started) {
        error = "adb not found";
        return false;
    }
    if (push.exitCode != 0) {
        error = push.output.empty() ? "adb push failed" : push.output;
        return false;
    }
    const proc::RunResult chmod = proc::run({adbPath, "-s", serial, "shell", "chmod", "755", remotePath}, 10000);
    if (chmod.exitCode != 0) {
        error = "chmod failed: " + chmod.output;
        return false;
    }
    return true;
}

std::vector<std::string> runArgv(const std::string& adbPath, const std::string& serial, const std::string& remotePath) {
    // Foreground in the adb shell: the owning ChildProcess keeps it alive,
    // and its stdout/stderr stream back as the server's log.
    return {adbPath, "-s", serial, "shell", remotePath};
}

bool running(const std::string& adbPath, const std::string& serial) {
    const proc::RunResult r = proc::run({adbPath, "-s", serial, "shell", "pidof", "frida-server"}, 8000);
    if (!r.started) return false;
    for (char c : r.output)
        if (std::isdigit(static_cast<unsigned char>(c))) return true;
    return false;
}

}  // namespace fridaserver
