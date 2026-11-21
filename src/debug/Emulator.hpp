#pragma once
#include <string>
#include <vector>
#include "core/Process.hpp"

// Manages Android emulators (AVDs): list, create, launch and stop them.
//
// Commands are executed directly (no local shell), like adb::Adb: the
// emulator binary is `emulator -avd <name>` and avdmanager is
// `avdmanager create avd -n <name> -k <package>`. Names and packages are
// validated before they reach the command line; everything is best effort
// when the SDK tools are not installed (the error says so).
namespace emulator {

struct Avd {
    std::string name;
    std::string target;   // e.g. "android-34" (best effort, from config.ini)
    std::string abi;      // e.g. "x86_64"
    std::string device;   // e.g. "pixel_6"
    bool running = false;  // a matching emulator-<port> is in `adb devices`
    std::string serial;    // its serial while running
};

// Where the SDK tools are. `emulator` / `avdmanager` default to a PATH
// lookup; fromAdb() derives them from the SDK that holds a known adb binary
// (adb lives in <sdk>/platform-tools, the emulator in <sdk>/emulator).
struct Tools {
    std::string emulator = "emulator";
    std::string avdmanager = "avdmanager";
    static Tools fromAdb(const std::string& adbPath);
};

// How to start an AVD. Everything off by default = a plain boot.
struct LaunchOptions {
    // "host:port" (or "http://host:port"): routes the whole VM's traffic
    // through this HTTP proxy at the QEMU level, so apps that ignore
    // Android's proxy setting are still captured. Point it at ApkSpy's proxy.
    std::string httpProxy;
    bool writableSystem = false;  // -writable-system (lets a CA land in the system store)
    bool wipeData = false;        // -wipe-data (factory reset)
    bool coldBoot = false;        // -no-snapshot-load (ignore the saved quickboot state)
    bool noSnapshotSave = false;  // -no-snapshot-save (discard state on exit)
    bool noAudio = false;         // -no-audio
};

// AVD names are user-visible file names: letters, digits, '.', '_', '-'.
bool validAvdName(const std::string& s);
// System image package ids ("system-images;android-34;google_apis;x86_64").
bool validSystemImage(const std::string& s);
// "host:port" or "http://host:port" with host = IPv4/hostname, port 1-65535.
bool validProxy(const std::string& s);

// The full argv for launching `name` with `opts` (pure, so it is testable).
std::vector<std::string> launchArgv(const Tools& tools, const std::string& name, const LaunchOptions& opts);

// `emulator -list-avds` merged with each AVD's config.ini (target, abi,
// device) and with `adb devices` (running state). Empty on a machine
// without the SDK (error says so). `adbPath` may be empty (no running state).
std::vector<Avd> list(const Tools& tools, const std::string& adbPath, std::string& error);

// Creates an AVD. `device` may be empty (default device).
bool create(const Tools& tools, const std::string& name, const std::string& systemImage,
            const std::string& device, std::string& error);

// Starts an AVD. The returned ChildProcess OWNS the emulator: keep it alive
// for as long as the emulator should run (destroying it ends the VM). An
// invalid process (with `error` set) means it could not be started.
ChildProcess launch(const Tools& tools, const std::string& name, const LaunchOptions& opts, std::string& error);

// `adb -s emulator-<port> emu kill` for a running emulator serial.
bool kill(const std::string& adbPath, const std::string& serial, std::string& error);

}  // namespace emulator
