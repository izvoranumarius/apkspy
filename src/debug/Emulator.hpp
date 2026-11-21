#pragma once
#include <string>
#include <vector>

// Manages Android emulators (AVDs): list, create, launch and kill them.
//
// Commands are executed directly (no local shell), like adb::Adb: the
// emulator binary is `emulator -avd <name>` and avdmanager is
// `avdmanager create avd -n <name> -k <package>`. Names and packages are
// validated before they reach the command line; everything is best effort
// when the SDK tools are not installed (the error says so).
namespace emulator {

struct Avd {
    std::string name;
    std::string target;  // e.g. "android-34"
    std::string abi;     // e.g. "x86_64"
    std::string path;    // the .avd directory
};

// Where the SDK tools are: set once from Settings (empty = PATH lookup).
struct Tools {
    std::string emulator = "emulator";
    std::string avdmanager = "avdmanager";  // resolved through sdkmanager's cmdline-tools
};

// AVD names are user-visible file names: letters, digits, '.', '_', '-'.
bool validAvdName(const std::string& s);
// System image package ids ("system-images;android-34;default;x86_64").
bool validSystemImage(const std::string& s);

// `emulator -list-avds` merged with the .ini files under the AVD home
// (name, target, abi, path). Empty on a machine without the SDK.
std::vector<Avd> list(const Tools& tools, std::string& error);

// Creates an AVD. `device` may be empty (default device).
bool create(const Tools& tools, const std::string& name, const std::string& systemImage,
            const std::string& device, std::string& error);

// Starts an AVD (detached: the caller owns the process). On success the
// emulator appears in adb devices as emulator-<port> once booted.
bool launch(const Tools& tools, const std::string& name, std::string& error);

// `adb -s emulator-<port> emu kill` for a running emulator serial.
bool kill(const std::string& adbPath, const std::string& serial, std::string& error);

}  // namespace emulator
