#include "debug/Emulator.hpp"
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include "core/Paths.hpp"
#include "core/Process.hpp"

namespace emulator {
namespace {

namespace fs = std::filesystem;

bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> splitLines(const std::string& text) {
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

// Reads one "key = value" from an AVD's config.ini / <name>.ini.
std::string iniValue(const fs::path& file, const std::string& key) {
    std::error_code ec;
    std::ifstream in(file);
    if (!in) return {};
    std::string line;
    while (std::getline(in, line)) {
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        if (trim(line.substr(0, eq)) == key) return trim(line.substr(eq + 1));
    }
    return {};
}

// The AVD home: $ANDROID_AVD_HOME, else $ANDROID_SDK_HOME/.android/avd, else
// ~/.android/avd.
fs::path avdHome() {
    if (const char* h = std::getenv("ANDROID_AVD_HOME"); h && *h) return pathutil::fromUtf8(h);
    if (const char* h = std::getenv("ANDROID_SDK_HOME"); h && *h) return pathutil::fromUtf8(h) / ".android" / "avd";
#ifdef _WIN32
    if (const char* up = std::getenv("USERPROFILE"); up && *up) return pathutil::fromUtf8(up) / ".android" / "avd";
#endif
    if (const char* home = std::getenv("HOME"); home && *home) return pathutil::fromUtf8(home) / ".android" / "avd";
    return {};
}

void enrichFromConfig(Avd& avd) {
    std::error_code ec;
    const fs::path dir = avdHome() / (avd.name + ".avd");
    const fs::path cfg = dir / "config.ini";
    if (!fs::exists(cfg, ec)) return;
    avd.device = iniValue(cfg, "hw.device.name");
    const std::string img = iniValue(cfg, "image.sysdir.1");  // "system-images/android-34/google_apis/x86_64/"
    // Parse "android-<n>" and the last path segment (abi) out of the sysdir.
    size_t a = img.find("android-");
    if (a != std::string::npos) {
        size_t e = img.find('/', a);
        avd.target = img.substr(a, (e == std::string::npos ? img.size() : e) - a);
    }
    std::string trimmed = img;
    while (!trimmed.empty() && (trimmed.back() == '/' || trimmed.back() == '\\')) trimmed.pop_back();
    const size_t slash = trimmed.find_last_of("/\\");
    if (slash != std::string::npos) avd.abi = trimmed.substr(slash + 1);
}

// serial -> AVD name via `adb -s <serial> emu avd name` (first line).
std::string avdNameOf(const std::string& adbPath, const std::string& serial) {
    const proc::RunResult r = proc::run({adbPath, "-s", serial, "emu", "avd", "name"}, 5000);
    if (!r.started) return {};
    for (const std::string& l : splitLines(r.output)) {
        if (l == "OK" || startsWith(l, "KO")) continue;  // the trailing status line
        return l;
    }
    return {};
}

}  // namespace

Tools Tools::fromAdb(const std::string& adbPath) {
    Tools t;
    std::error_code ec;
    if (adbPath.empty() || adbPath == "adb") return t;
    // <sdk>/platform-tools/adb[.exe] -> <sdk>/emulator/emulator[.exe]
    fs::path adb = pathutil::fromUtf8(adbPath);
    const fs::path sdk = adb.parent_path().parent_path();  // strip adb + platform-tools
    if (sdk.empty()) return t;
    const std::string exe =
#ifdef _WIN32
        ".exe";
#else
        "";
#endif
    const std::string bat =
#ifdef _WIN32
        ".bat";
#else
        "";
#endif
    const fs::path emu = sdk / "emulator" / ("emulator" + exe);
    if (fs::exists(emu, ec)) t.emulator = pathutil::toUtf8(emu);
    // avdmanager lives in cmdline-tools/latest/bin or tools/bin.
    for (const fs::path rel : {fs::path("cmdline-tools") / "latest" / "bin", fs::path("tools") / "bin"}) {
        const fs::path am = sdk / rel / ("avdmanager" + bat);
        if (fs::exists(am, ec)) {
            t.avdmanager = pathutil::toUtf8(am);
            break;
        }
    }
    return t;
}

bool validAvdName(const std::string& s) {
    if (s.empty() || s.size() > 64 || s[0] == '-' || s[0] == '.') return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) return false;
    return true;
}

bool validSystemImage(const std::string& s) {
    // "system-images;android-34;google_apis;x86_64"
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

bool validProxy(const std::string& s) {
    std::string h = s;
    if (startsWith(h, "http://")) h = h.substr(7);
    const size_t colon = h.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= h.size()) return false;
    const std::string host = h.substr(0, colon), port = h.substr(colon + 1);
    for (char c : host)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-')) return false;
    if (port.size() > 5) return false;
    int p = 0;
    for (char c : port) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        p = p * 10 + (c - '0');
    }
    return p >= 1 && p <= 65535;
}

std::vector<std::string> launchArgv(const Tools& tools, const std::string& name, const LaunchOptions& opts) {
    std::vector<std::string> argv = {tools.emulator, "-avd", name};
    if (!opts.httpProxy.empty() && validProxy(opts.httpProxy)) {
        argv.push_back("-http-proxy");
        argv.push_back(opts.httpProxy);
    }
    if (opts.writableSystem) argv.push_back("-writable-system");
    if (opts.wipeData) argv.push_back("-wipe-data");
    if (opts.coldBoot) argv.push_back("-no-snapshot-load");
    if (opts.noSnapshotSave) argv.push_back("-no-snapshot-save");
    if (opts.noAudio) argv.push_back("-no-audio");
    argv.push_back("-netdelay");
    argv.push_back("none");
    argv.push_back("-netspeed");
    argv.push_back("full");
    return argv;
}

std::vector<Avd> list(const Tools& tools, const std::string& adbPath, std::string& error) {
    error.clear();
    std::vector<Avd> out;
    const proc::RunResult r = proc::run({tools.emulator, "-list-avds"}, 10000);
    if (!r.started) {
        error = "emulator not found (" + tools.emulator + ")";
        return out;
    }
    for (const std::string& name : splitLines(r.output)) {
        if (!validAvdName(name)) continue;  // "INFO | ..." banner lines etc.
        Avd avd{name, "", "", "", false, ""};
        enrichFromConfig(avd);
        out.push_back(std::move(avd));
    }
    // Running state: match each emulator-<port> serial to its AVD name.
    if (!adbPath.empty()) {
        const proc::RunResult d = proc::run({adbPath, "devices"}, 5000);
        if (d.started)
            for (const std::string& line : splitLines(d.output)) {
                if (!startsWith(line, "emulator-")) continue;
                const size_t tab = line.find_first_of(" \t");
                const std::string serial = tab == std::string::npos ? line : line.substr(0, tab);
                const std::string name = avdNameOf(adbPath, serial);
                for (Avd& a : out)
                    if (a.name == name) {
                        a.running = true;
                        a.serial = serial;
                    }
            }
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
    std::vector<std::string> argv = {tools.avdmanager, "create", "avd", "-n", name, "-k", systemImage, "--force"};
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

ChildProcess launch(const Tools& tools, const std::string& name, const LaunchOptions& opts, std::string& error) {
    if (!validAvdName(name)) {
        error = "invalid AVD name";
        return ChildProcess{};
    }
    if (!opts.httpProxy.empty() && !validProxy(opts.httpProxy)) {
        error = "invalid proxy (use host:port)";
        return ChildProcess{};
    }
    ChildProcess p = ChildProcess::spawn(launchArgv(tools, name, opts));
    if (!p.valid()) {
        error = "could not start emulator (" + tools.emulator + ")";
        return ChildProcess{};
    }
    return p;
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
