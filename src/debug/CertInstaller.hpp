#pragma once
#include <string>
#include "debug/Adb.hpp"

namespace ca {
class Store;
}

// Installing ApkSpy's CA on Android devices and checking whether a device
// actually trusts it. All remote commands are fixed templates; the only
// variable parts are the (validated) serial and the CA's own file name
// ("<hex>.0"), so nothing user-controlled ever reaches the device shell.
//
// Two stores, two layouts:
//  - User store ("install from storage" in Settings): every device, but apps
//    targeting SDK 24+ do not trust it unless their network security config
//    says so.
//  - System store (rooted devices): SDK < 34 writes
//    /system/etc/security/cacerts/<hash>.0; SDK 34+ moved the store into the
//    Conscrypt APEX, so a tmpfs overlay is mounted over the system directory
//    and bind-mounted into running processes. Both are reversible.
namespace certinstall {

struct DeviceInfo {
    bool devicePresent = false;
    std::string model;
    std::string androidRelease;  // "11"
    int sdk = 0;
    bool adbdRoot = false;      // adbd itself runs as root (userdebug emulator)
    bool suAvailable = false;   // `su -c id` answers uid=0
    bool userStoreReadable = false;
    bool caUserInstalled = false;    // our CA found in the user store
    bool caSystemInstalled = false;  // our CA found in a system store
    bool overlayMounted = false;     // SDK 34+: our tmpfs overlay is up
    std::string notes;               // what could not be checked and why
};

class Installer {
public:
    explicit Installer(const adb::Adb& adb) : adb_(adb) {}

    // Everything the Certificates dialog shows. Runs several adb commands
    // (a few hundred ms); call it from a worker when the UI must stay fluid.
    DeviceInfo inspect(const std::string& serial, const ca::Store& ca);

    // Pushes the CA and opens the device's security settings so the user can
    // install it (Android has no adb command for the user store).
    bool installUserCert(const std::string& serial, const ca::Store& ca, std::string& error);
    // System store install (needs root; asks nothing - the UI confirms first).
    bool installSystemCert(const std::string& serial, const ca::Store& ca, std::string& error);
    bool removeSystemCert(const std::string& serial, const ca::Store& ca, std::string& error);

    static const char* userInstallSteps(int sdk);
    // Why captured HTTPS may still be missing, in one sentence.
    static const char* quicNote();

private:
    // Runs `command` through su when needed; returns output ("" + error set).
    std::string runRoot(const std::string& serial, const DeviceInfo& info, const std::string& command,
                        std::string& error) const;
    // Writes the CA certificate into a temp file and returns its local path.
    static std::string exportToTemp(const ca::Store& ca, std::string& error);

    const adb::Adb& adb_;
};

}  // namespace certinstall
