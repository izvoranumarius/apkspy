#include "debug/Emulator.hpp"
#include <cstdlib>
#include <cctype>
#include "core/Process.hpp"

namespace emulator {
namespace {

bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Lines of `text` (the merged output of a tool).
std::vector<std::string> lines(const std::string& text) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string::npos) nl = text.size();
        std::string l = trim(text.substr(start, nl - start));
        if (!l.empty()) out.push_back(l);
        start = nl + 1;
    }
    return out;
}

}  // namespace

bool validAvdName(const std::string& s) {
    if (s.empty() || s.size() > 64 || s[0] == '-' || s[0] == '.') return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) return false;
    return true;
}

bool validSystemImage(const std::string& s) {
    // "system-images;android-34;default;x86_64" (also "google_apis" etc.)
    if (!startsWith(s, "system-images;")) return false;
    int parts = 0;
    for (char c : s) {
        if (c == ';') {
            ++parts;
        } else if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.')) {
            return false;
        }
    }
    return parts == 3;
}

std::vector<Avd> list(const Tools& tools, std::string& error) {
    error.clear();
    std::vector<Avd> out;
    // `emulator -list-avds`: one name per line.
    const proc::RunResult r = proc::run({tools.emulator, "-list-avds"}, 10000);
    if (!r.started) {
        error = "emulator not found (" + tools.emulator + ")";
        return out;
    }
    for (const std::string& name : lines(r.output)) {
        if (!validAvdName(name)) continue;  // "INFO | ..." banner lines etc.
        out.push_back(Avd{name, "", "", ""});
    }
    return out;
}

bool create(const Tools& tools, const std::string& name, const std::string& systemImage,
            const std::string& device, std::string& error) {
    if (!validAvdName(name)) {
        error = "invalid AVD name";
        return false;
    }
    if (!validSystemImage(systemImage)) {
        error = "invalid system image id";
        return false;
    }
    std::vector<std::string> argv = {tools.avdmanager, "create", "avd", "-n", name, "-k", systemImage};
    if (!device.empty()) {
        argv.push_back("-d");
        argv.push_back(device);
    }
    const proc::RunResult r = proc::run(argv, 120000);
    if (!r.started) {
        error = "avdmanager not found (" + tools.avdmanager + ")";
        return false;
    }
    if (r.exitCode != 0) {
        error = trim(r.output);
        if (error.empty()) error = "avdmanager failed";
        return false;
    }
    return true;
}

bool launch(const Tools& tools, const std::string& name, std::string& error) {
    if (!validAvdName(name)) {
        error = "invalid AVD name";
        return false;
    }
    // Detached: no pipe to read, the emulator keeps running after the call.
    ChildProcess p = ChildProcess::spawn({tools.emulator, "-avd", name});
    if (!p.valid()) {
        error = "could not start emulator (" + tools.emulator + ")";
        return false;
    }
    // The process is intentionally leaked into the background: the emulator
    // outlives this call. On POSIX, detaching by not waiting is enough; the
    // handle is closed without killing (the job object only kills on close
    // for owned trees, which is what stop paths use).
    return true;
}

bool kill(const std::string& adbPath, const std::string& serial, std::string& error) {
    if (serial.rfind("emulator-", 0) != 0) {
        error = "not an emulator serial";
        return false;
    }
    const proc::RunResult r = proc::run({adbPath, "-s", serial, "emu", "kill"}, 10000);
    if (!r.started || r.exitCode != 0) {
        error = r.started ? trim(r.output) : "adb not found";
        if (error.empty()) error = "emu kill failed";
        return false;
    }
    return true;
}

}  // namespace emulator
