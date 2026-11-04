#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

// Thin, shell-free wrappers around the `adb` command line tool.
//
// Safety: adb is executed directly (proc::run, no local shell). Remote
// `adb shell` commands ARE interpreted by the device shell, so every value
// that ends up in one (serials, package names, pids) is validated against a
// strict character whitelist first; commands are fixed templates, never
// free text from a project file, a page or an MCP client.
namespace adb {

struct Device {
    std::string serial;
    std::string state;  // device, offline, unauthorized, ...
    std::string model;
    std::string product;
    std::string transportId;
    bool emulator() const { return serial.rfind("emulator-", 0) == 0; }
};

struct ProcessInfo {
    int pid = 0;
    int ppid = 0;
    std::string user;
    uint64_t rssKb = 0;
    std::string name;
};

struct ThreadInfo {
    int tid = 0;
    std::string name;
    std::string state;  // R, S, D, T, Z ...
};

struct ProcStat {
    bool ok = false;
    uint64_t cpuTotalJiffies = 0;  // /proc/stat aggregate
    uint64_t procJiffies = 0;      // utime + stime of the process
    uint64_t rssKb = 0;
    uint64_t vmSizeKb = 0;
    int threads = 0;
};

struct MemInfo {
    bool ok = false;
    uint64_t totalPssKb = 0;
    uint64_t javaHeapKb = 0;
    uint64_t nativeHeapKb = 0;
    uint64_t codeKb = 0;
    uint64_t graphicsKb = 0;
    std::string raw;  // dumpsys output (trimmed)
};

// Whitelists: serial = [A-Za-z0-9._:-]+, package = java-ish dotted name.
bool validSerial(const std::string& s);
bool validPackage(const std::string& s);

// `adb` executable to use (configurable in Settings; "adb" = PATH lookup).
class Adb {
public:
    explicit Adb(std::string path = "adb") : path_(std::move(path)) {}
    const std::string& path() const { return path_; }
    void setPath(std::string p) { path_ = std::move(p); }

    // "adb version" first line; empty + error when adb is missing.
    std::string version(std::string& error) const;
    std::vector<Device> devices(std::string& error) const;
    std::vector<ProcessInfo> processes(const std::string& serial, std::string& error) const;
    int pidOf(const std::string& serial, const std::string& package, std::string& error) const;
    std::vector<ThreadInfo> threads(const std::string& serial, int pid, std::string& error) const;
    ProcStat procStat(const std::string& serial, int pid, std::string& error) const;
    MemInfo memInfo(const std::string& serial, int pid, std::string& error) const;
    // PIDs of debuggable (JDWP) processes; `adb jdwp` streams forever, so it
    // is sampled for `sampleMs`.
    std::vector<int> jdwpPids(const std::string& serial, int sampleMs, std::string& error) const;
    // Forwards a local TCP port to the process' JDWP endpoint; returns the
    // local port (0 on failure). removeForward() undoes it.
    int forwardJdwp(const std::string& serial, int pid, std::string& error) const;
    void removeForward(const std::string& serial, int localPort) const;
    // Device -> host port mapping (adb reverse tcp:P tcp:P), used to route
    // the device's traffic into the sniffer on 127.0.0.1.
    bool reverse(const std::string& serial, int port, std::string& error) const;
    void removeReverse(const std::string& serial, int port, std::string& error) const;
    // `settings put global http_proxy <value>` ("host:port", or ":0" to clear).
    bool setGlobalHttpProxy(const std::string& serial, const std::string& value, std::string& error) const;
    // Native + Java backtraces through debuggerd (requires a debuggable app
    // or a rooted device); returns the raw text.
    std::string backtrace(const std::string& serial, int pid, std::string& error) const;
    // getprop summary (model, Android version, ABI).
    std::vector<std::pair<std::string, std::string>> properties(const std::string& serial, std::string& error) const;

    // Parsers (exposed for tests).
    static std::vector<Device> parseDevices(const std::string& out);
    static std::vector<ProcessInfo> parseProcesses(const std::string& out);
    static std::vector<ThreadInfo> parseThreads(const std::string& out);
    static ProcStat parseProcStat(const std::string& out);
    static MemInfo parseMemInfo(const std::string& out);

private:
    std::vector<std::string> base(const std::string& serial) const;
    std::string run(const std::vector<std::string>& args, std::string& error, int timeoutMs = 10000) const;
    std::string path_;
};

}  // namespace adb
