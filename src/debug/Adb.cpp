#include "debug/Adb.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>
#include "core/Process.hpp"
#include "core/Socket.hpp"

namespace adb {
namespace {

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) {
        if (cur.back() == '\r') cur.pop_back();
        out.push_back(std::move(cur));
    }
    return out;
}

std::vector<std::string> splitWs(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string w;
    while (in >> w) out.push_back(w);
    return out;
}

uint64_t toU64(const std::string& s) { return std::strtoull(s.c_str(), nullptr, 10); }

}  // namespace

bool validSerial(const std::string& s) {
    if (s.empty() || s.size() > 128) return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c) || c == '.' || c == '_' || c == ':' || c == '-')) return false;
    return true;
}

bool validPackage(const std::string& s) {
    if (s.empty() || s.size() > 255) return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c) || c == '.' || c == '_' || c == ':')) return false;  // ':' = process suffix
    return std::isalpha((unsigned char)s[0]) != 0;
}

std::vector<std::string> Adb::base(const std::string& serial) const {
    std::vector<std::string> argv{path_};
    if (!serial.empty()) {
        argv.push_back("-s");
        argv.push_back(serial);
    }
    return argv;
}

std::string Adb::run(const std::vector<std::string>& args, std::string& error, int timeoutMs) const {
    proc::RunResult r = proc::run(args, timeoutMs, 8u << 20);
    if (!r.started) {
        error = "adb could not be started (" + path_ + "). Install Android platform-tools or set the adb path in Settings.";
        return {};
    }
    if (r.timedOut) error = "adb timed out";
    else if (r.exitCode != 0 && error.empty()) {
        std::string first = r.output.substr(0, r.output.find('\n'));
        error = "adb exited with code " + std::to_string(r.exitCode) + (first.empty() ? "" : ": " + first);
    }
    return std::move(r.output);
}

std::string Adb::version(std::string& error) const {
    std::string out = run({path_, "version"}, error, 5000);
    return out.substr(0, out.find('\n'));
}

std::vector<Device> Adb::parseDevices(const std::string& out) {
    std::vector<Device> devices;
    for (const std::string& line : splitLines(out)) {
        if (line.empty() || line.rfind("List of devices", 0) == 0 || line[0] == '*') continue;
        std::vector<std::string> w = splitWs(line);
        if (w.size() < 2) continue;
        Device d;
        d.serial = w[0];
        d.state = w[1];
        for (size_t i = 2; i < w.size(); ++i) {
            const size_t colon = w[i].find(':');
            if (colon == std::string::npos) continue;
            const std::string k = w[i].substr(0, colon), v = w[i].substr(colon + 1);
            if (k == "model") d.model = v;
            else if (k == "product") d.product = v;
            else if (k == "transport_id") d.transportId = v;
        }
        if (validSerial(d.serial)) devices.push_back(std::move(d));
    }
    return devices;
}

std::vector<Device> Adb::devices(std::string& error) const { return parseDevices(run({path_, "devices", "-l"}, error)); }

std::vector<ProcessInfo> Adb::parseProcesses(const std::string& out) {
    std::vector<ProcessInfo> procs;
    bool header = true;
    for (const std::string& line : splitLines(out)) {
        if (header) {
            header = false;
            if (line.find("PID") != std::string::npos) continue;
        }
        std::vector<std::string> w = splitWs(line);
        if (w.size() < 5) continue;
        ProcessInfo p;
        p.pid = std::atoi(w[0].c_str());
        p.ppid = std::atoi(w[1].c_str());
        p.user = w[2];
        p.rssKb = toU64(w[3]);
        p.name = w[4];
        for (size_t i = 5; i < w.size(); ++i) p.name += " " + w[i];
        if (p.pid > 0) procs.push_back(std::move(p));
    }
    return procs;
}

std::vector<ProcessInfo> Adb::processes(const std::string& serial, std::string& error) const {
    if (!validSerial(serial)) {
        error = "invalid device serial";
        return {};
    }
    std::vector<std::string> argv = base(serial);
    for (const char* a : {"shell", "ps", "-A", "-o", "PID,PPID,USER,RSS,NAME"}) argv.push_back(a);
    return parseProcesses(run(argv, error));
}

int Adb::pidOf(const std::string& serial, const std::string& package, std::string& error) const {
    if (!validSerial(serial) || !validPackage(package)) {
        error = "invalid serial or package name";
        return 0;
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("shell");
    argv.push_back("pidof");
    argv.push_back(package);
    std::string ignored;
    const std::string out = run(argv, ignored);
    const std::vector<std::string> w = splitWs(out);
    if (!w.empty()) return std::atoi(w[0].c_str());
    // Older devices without pidof: scan ps.
    for (const ProcessInfo& p : processes(serial, error))
        if (p.name == package) return p.pid;
    if (error.empty()) error = "process not running: " + package;
    return 0;
}

std::vector<ThreadInfo> Adb::parseThreads(const std::string& out) {
    std::vector<ThreadInfo> threads;
    bool header = true;
    for (const std::string& line : splitLines(out)) {
        if (header) {
            header = false;
            if (line.find("TID") != std::string::npos) continue;
        }
        std::vector<std::string> w = splitWs(line);
        if (w.size() < 3) continue;
        ThreadInfo t;
        t.tid = std::atoi(w[0].c_str());
        t.state = w[1];
        t.name = w[2];
        for (size_t i = 3; i < w.size(); ++i) t.name += " " + w[i];
        if (t.tid > 0) threads.push_back(std::move(t));
    }
    return threads;
}

std::vector<ThreadInfo> Adb::threads(const std::string& serial, int pid, std::string& error) const {
    if (!validSerial(serial) || pid <= 0) {
        error = "invalid serial or pid";
        return {};
    }
    std::vector<std::string> argv = base(serial);
    for (const char* a : {"shell", "ps", "-T", "-p"}) argv.push_back(a);
    argv.push_back(std::to_string(pid));
    argv.push_back("-o");
    argv.push_back("TID,S,CMD");
    return parseThreads(run(argv, error));
}

ProcStat Adb::parseProcStat(const std::string& out) {
    ProcStat st;
    bool haveCpu = false, haveProc = false;
    for (const std::string& line : splitLines(out)) {
        if (line.rfind("cpu ", 0) == 0) {
            const std::vector<std::string> w = splitWs(line);
            for (size_t i = 1; i < w.size() && i <= 8; ++i) st.cpuTotalJiffies += toU64(w[i]);
            haveCpu = true;
        } else if (line.rfind("VmRSS:", 0) == 0) {
            st.rssKb = toU64(splitWs(line.substr(6)).empty() ? "0" : splitWs(line.substr(6))[0]);
        } else if (line.rfind("VmSize:", 0) == 0) {
            const auto w = splitWs(line.substr(7));
            if (!w.empty()) st.vmSizeKb = toU64(w[0]);
        } else if (line.rfind("Threads:", 0) == 0) {
            const auto w = splitWs(line.substr(8));
            if (!w.empty()) st.threads = std::atoi(w[0].c_str());
        } else {
            // /proc/<pid>/stat: "pid (comm) S ppid ..." - comm may contain
            // spaces, so fields are counted after the closing parenthesis.
            const size_t close = line.rfind(')');
            if (close == std::string::npos || line.find('(') == std::string::npos) continue;
            const std::vector<std::string> w = splitWs(line.substr(close + 1));
            // w[0] = state (field 3); utime = field 14, stime = field 15.
            if (w.size() > 12) {
                st.procJiffies = toU64(w[11]) + toU64(w[12]);
                haveProc = true;
            }
        }
    }
    st.ok = haveCpu && haveProc;
    return st;
}

ProcStat Adb::procStat(const std::string& serial, int pid, std::string& error) const {
    if (!validSerial(serial) || pid <= 0) {
        error = "invalid serial or pid";
        return {};
    }
    const std::string p = "/proc/" + std::to_string(pid);
    std::vector<std::string> argv = base(serial);
    argv.push_back("shell");
    argv.push_back("cat");
    argv.push_back("/proc/stat");
    argv.push_back(p + "/stat");
    argv.push_back(p + "/status");
    return parseProcStat(run(argv, error));
}

MemInfo Adb::parseMemInfo(const std::string& out) {
    MemInfo m;
    for (const std::string& line : splitLines(out)) {
        std::vector<std::string> w = splitWs(line);
        if (w.size() < 2) continue;
        const auto num = [&](size_t from) -> uint64_t {
            for (size_t i = from; i < w.size(); ++i)
                if (!w[i].empty() && std::isdigit((unsigned char)w[i][0])) return toU64(w[i]);
            return 0;
        };
        if (w[0] == "TOTAL" && w.size() > 1 && std::isdigit((unsigned char)w[1][0])) {
            m.totalPssKb = toU64(w[1]);
            m.ok = true;
        } else if (w[0] == "TOTAL" && w.size() > 2 && w[1] == "PSS:") {
            m.totalPssKb = toU64(w[2]);
            m.ok = true;
        } else if (line.find("Java Heap:") != std::string::npos) {
            m.javaHeapKb = num(2);
        } else if (line.find("Native Heap:") != std::string::npos) {
            m.nativeHeapKb = num(2);
        } else if (w[0] == "Code:") {
            m.codeKb = num(1);
        } else if (w[0] == "Graphics:") {
            m.graphicsKb = num(1);
        }
    }
    m.raw = out.size() > 16384 ? out.substr(0, 16384) : out;
    return m;
}

MemInfo Adb::memInfo(const std::string& serial, int pid, std::string& error) const {
    if (!validSerial(serial) || pid <= 0) {
        error = "invalid serial or pid";
        return {};
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("shell");
    argv.push_back("dumpsys");
    argv.push_back("meminfo");
    argv.push_back(std::to_string(pid));
    return parseMemInfo(run(argv, error, 15000));
}

std::vector<int> Adb::jdwpPids(const std::string& serial, int sampleMs, std::string& error) const {
    if (!validSerial(serial)) {
        error = "invalid device serial";
        return {};
    }
    // Preferred: the adb server's own protocol. `adb jdwp` streams forever
    // and writes through a buffered pipe, so sampling the child process and
    // killing it loses the list (it was always empty in practice).
    {
        Socket s;
        std::string ignored;
        int port = 5037;
        if (const char* env = std::getenv("ANDROID_ADB_SERVER_PORT")) port = std::atoi(env) > 0 ? std::atoi(env) : 5037;
        if (s.connectLoopback(port, 1000, ignored)) {
            s.setRecvTimeout(3000);  // a stalled server must not hang the caller
            const auto request = [&](const std::string& msg) {
                char len[5];
                std::snprintf(len, sizeof len, "%04x", (unsigned)msg.size());
                char status[4];
                return s.sendAll(std::string(len) + msg) && s.waitReadable(3000) && s.recvAll(status, 4) &&
                       std::memcmp(status, "OKAY", 4) == 0;
            };
            if (!request("host:transport:" + serial) || !request("track-jdwp")) {
                error = "adb server refused the jdwp request for " + serial;
                return {};
            }
            // track-jdwp pushes "<hex len><one pid per line>" whenever the
            // set changes; nothing arrives while no process is debuggable.
            std::set<int> pids;
            char hex[5] = {};
            if (s.waitReadable(sampleMs) && s.recvAll(hex, 4)) {
                const unsigned long n = std::strtoul(hex, nullptr, 16);
                std::string data(std::min<unsigned long>(n, 1u << 20), '\0');
                if (data.empty() || s.recvAll(data.data(), data.size()))
                    for (const std::string& line : splitLines(data))
                        if (std::atoi(line.c_str()) > 0) pids.insert(std::atoi(line.c_str()));
            }
            return std::vector<int>(pids.begin(), pids.end());
        }
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("jdwp");
    proc::RunResult r = proc::run(argv, sampleMs, 1 << 20);
    if (!r.started) {
        error = "adb could not be started";
        return {};
    }
    std::set<int> pids;
    for (const std::string& line : splitLines(r.output)) {
        const int pid = std::atoi(line.c_str());
        if (pid > 0) pids.insert(pid);
    }
    return std::vector<int>(pids.begin(), pids.end());
}

int Adb::forwardJdwp(const std::string& serial, int pid, std::string& error) const {
    if (!validSerial(serial) || pid <= 0) {
        error = "invalid serial or pid";
        return 0;
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("forward");
    argv.push_back("tcp:0");
    argv.push_back("jdwp:" + std::to_string(pid));
    const std::string out = run(argv, error);
    const int port = std::atoi(out.c_str());
    if (port <= 0 && error.empty()) error = "adb forward failed: " + out;
    return port > 0 ? port : 0;
}

void Adb::removeForward(const std::string& serial, int localPort) const {
    if (!validSerial(serial) || localPort <= 0) return;
    std::vector<std::string> argv = base(serial);
    argv.push_back("forward");
    argv.push_back("--remove");
    argv.push_back("tcp:" + std::to_string(localPort));
    std::string ignored;
    run(argv, ignored, 5000);
}

bool Adb::reverse(const std::string& serial, int port, std::string& error) const {
    if (!validSerial(serial) || port <= 0 || port > 65535) {
        error = "invalid serial or port";
        return false;
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("reverse");
    argv.push_back("tcp:" + std::to_string(port));
    argv.push_back("tcp:" + std::to_string(port));
    run(argv, error);
    return error.empty();
}

void Adb::removeReverse(const std::string& serial, int port, std::string& error) const {
    if (!validSerial(serial) || port <= 0) return;
    std::vector<std::string> argv = base(serial);
    argv.push_back("reverse");
    argv.push_back("--remove");
    argv.push_back("tcp:" + std::to_string(port));
    run(argv, error, 5000);
}

bool Adb::setGlobalHttpProxy(const std::string& serial, const std::string& value, std::string& error) const {
    // The value reaches the device shell: digits, dots and one colon only.
    bool ok = validSerial(serial) && !value.empty() && value.size() < 64;
    for (char c : value) ok = ok && (std::isdigit((unsigned char)c) || c == '.' || c == ':');
    if (!ok) {
        error = "invalid serial or proxy value";
        return false;
    }
    std::vector<std::string> argv = base(serial);
    for (const char* a : {"shell", "settings", "put", "global", "http_proxy"}) argv.push_back(a);
    argv.push_back(value);
    run(argv, error);
    return error.empty();
}

std::string Adb::backtrace(const std::string& serial, int pid, std::string& error) const {
    if (!validSerial(serial) || pid <= 0) {
        error = "invalid serial or pid";
        return {};
    }
    std::vector<std::string> argv = base(serial);
    argv.push_back("shell");
    argv.push_back("debuggerd");
    argv.push_back("-b");
    argv.push_back(std::to_string(pid));
    return run(argv, error, 20000);
}

std::vector<std::pair<std::string, std::string>> Adb::properties(const std::string& serial, std::string& error) const {
    std::vector<std::pair<std::string, std::string>> out;
    if (!validSerial(serial)) {
        error = "invalid device serial";
        return out;
    }
    static const char* kProps[] = {"ro.product.manufacturer", "ro.product.model",   "ro.build.version.release",
                                   "ro.build.version.sdk",     "ro.product.cpu.abi", "ro.debuggable",
                                   "ro.build.type",            "ro.secure"};
    // One `getprop` dump ("[key]: [value]" lines) instead of a call per key.
    std::vector<std::string> argv = base(serial);
    argv.push_back("shell");
    argv.push_back("getprop");
    const std::string dump = run(argv, error, 8000);
    for (const char* prop : kProps) {
        const std::string key = std::string("[") + prop + "]: [";
        const size_t at = dump.find(key);
        std::string v;
        if (at != std::string::npos) {
            const size_t start = at + key.size();
            const size_t end = dump.find(']', start);
            if (end != std::string::npos) v = dump.substr(start, end - start);
        }
        out.emplace_back(prop, v);
    }
    return out;
}

}  // namespace adb
