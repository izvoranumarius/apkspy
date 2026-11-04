#include "app/HeadlessMcp.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <thread>
#include "core/Paths.hpp"
#include "core/Project.hpp"
#include "core/Settings.hpp"
#include "core/Workspace.hpp"
#include "debug/DeviceService.hpp"
#include "mcp/McpHost.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace fs = std::filesystem;

namespace {

void err(const std::string& line) {
#ifdef _WIN32
    // GUI-subsystem executable: write to the inherited handle directly.
    const std::string out = line + "\n";
    DWORD wrote = 0;
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) WriteFile(h, out.data(), (DWORD)out.size(), &wrote, nullptr);
#else
    std::fprintf(stderr, "%s\n", line.c_str());
#endif
}

const char* kUsage =
    "Usage: apkspy --mcp [--project <file.apkspy>] [--apk <file.apk>]... [--jadx <path>] [--adb <path>]\n"
    "                    [--no-decompile] [--no-devices] [--analyze]\n"
    "Runs the ApkSpy MCP server on stdin/stdout (newline-delimited JSON-RPC).";

}  // namespace

std::vector<std::string> commandLineArgs(int argc, char** argv) {
    std::vector<std::string> out;
#ifdef _WIN32
    (void)argc;
    (void)argv;
    int n = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &n);
    if (wargv) {
        for (int i = 0; i < n; ++i) out.push_back(pathutil::toUtf8(fs::path(wargv[i])));
        LocalFree(wargv);
    }
#else
    for (int i = 0; i < argc; ++i) out.emplace_back(argv[i]);
#endif
    return out;
}

int runHeadlessMcp(const std::vector<std::string>& args) {
    std::string projectPath, jadx, adbPath;
    std::vector<std::string> apks;
    bool decompile = true, withDevices = true, analyze = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& a = args[i];
        const auto next = [&]() -> std::string { return i + 1 < args.size() ? args[++i] : std::string(); };
        if (a == "--mcp") continue;
        else if (a == "--project") projectPath = next();
        else if (a == "--apk") apks.push_back(next());
        else if (a == "--jadx") jadx = next();
        else if (a == "--adb") adbPath = next();
        else if (a == "--no-decompile") decompile = false;
        else if (a == "--no-devices") withDevices = false;
        else if (a == "--analyze") analyze = true;
        else if (a == "--help" || a == "-h") {
            err(kUsage);
            return 0;
        } else {
            err("unknown argument: " + a + "\n" + kUsage);
            return 2;
        }
    }

    // Same preferences as the GUI (jadx / adb paths) unless overridden.
    Settings settings;
    settings.load(pathutil::configFile("apkspy.settings"));
    Workspace workspace;
    workspace.setJadxPath(jadx.empty() ? settings.getString(Settings::kJadxPath, "jadx") : jadx);
    workspace.setJadxArgs(settings.getString(Settings::kJadxArgs, ""));
    if (!decompile) workspace.setJadxPath("");  // an empty path makes every jadx start fail fast
    std::unique_ptr<DeviceService> devices;
    if (withDevices) {
        devices = std::make_unique<DeviceService>();
        devices->setAdbPath(adbPath.empty() ? settings.getString(Settings::kAdbPath, "adb") : adbPath);
    }

    Project project;
    if (!projectPath.empty()) {
        if (!project.load(projectPath)) {
            err("not a valid ApkSpy project: " + projectPath);
            return 1;
        }
        for (const ProjectApk& apk : project.apks()) {
            std::error_code ec;
            if (!fs::exists(pathutil::fromUtf8(apk.path), ec)) {
                err("missing APK: " + apk.path);
                continue;
            }
            workspace.addApk(apk.path, apk.group);
        }
        workspace.annotations().replaceAll(project.annotations());
    } else {
        project.reset();
    }
    const uint64_t loadedNotes = workspace.annotations().version();
    for (const std::string& path : apks) {
        const std::string group = project.uniqueGroupName(pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).stem()));
        if (workspace.addApk(path, group)) project.addApk(pathutil::normalize(path), group);
    }
    if (analyze)
        for (Root* r : workspace.apkRoots()) workspace.startAnalysis(r->title);

    McpHost host(workspace, devices.get(), false);
    std::atomic<bool> stop{false};
    std::thread io([&] {
        runMcpStdio(host.server(), stop);
        stop = true;
    });
    err("apkspy MCP server ready (" + std::to_string(workspace.apkRoots().size()) + " APK(s), " +
        std::to_string(host.server().tools().size()) + " tools)");

    // Owner loop: the only thread that touches the workspace.
    size_t logged = 0;
    while (!stop.load()) {
        host.pump();
        workspace.update();
        const auto& log = workspace.logLines();
        if (log.size() < logged) logged = 0;  // trimmed
        for (; logged < log.size(); ++logged) err(log[logged]);
        std::this_thread::sleep_for(std::chrono::milliseconds(host.dispatcher().hasPending() ? 0 : 5));
    }
    host.shutdown();
    io.join();
    workspace.cancelDecompile();
    if (workspace.annotations().version() != loadedNotes) {
        // Only the notes change: re-read the file so nothing else in it is touched.
        Project onDisk;
        if (project.hasPath() && onDisk.load(project.path())) {
            onDisk.setAnnotations(workspace.annotations().all());
            if (!onDisk.save(project.path())) err("could not save annotations to " + project.path());
        } else {
            err("annotations were not saved: the server was started without a project file");
        }
    }
    workspace.closeAll();
    return 0;
}
