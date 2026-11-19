#include "debug/CertInstaller.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include "core/Paths.hpp"
#include "debug/CaStore.hpp"

namespace fs = std::filesystem;

namespace certinstall {
namespace {

// A temp copy of the CA certificate (never the key) for adb push.
constexpr const char* kLocalCert = "apkspy-ca-export.pem";
constexpr const char* kRemoteCert = "/data/local/tmp/apkspy-ca.pem";

bool contains(const std::string& hay, const std::string& needle) { return !needle.empty() && hay.find(needle) != std::string::npos; }

std::string trimmed(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    size_t at = 0;
    while (at < s.size() && (s[at] == '\n' || s[at] == '\r' || s[at] == ' ')) ++at;
    return s.substr(at);
}

}  // namespace

std::string certinstall::Installer::exportToTemp(const ca::Store& ca, std::string& error) {
    const std::string dir = pathutil::configDir().string();
    std::error_code ec;
    fs::create_directories(pathutil::fromUtf8(dir), ec);
    const std::string path = dir + "/" + kLocalCert;
    std::string pem;
    if (!ca.caPem().empty() == false) {
        error = "the CA is not loaded";
        return {};
    }
    pem = ca.caPem();
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(pem.data(), static_cast<std::streamsize>(pem.size()));
    if (!out) {
        error = "could not write " + path;
        return {};
    }
    return path;
}

std::string certinstall::Installer::runRoot(const std::string& serial, const DeviceInfo& info,
                                            const std::string& command, std::string& error) const {
    if (info.adbdRoot) return adb_.shell(serial, command, error, 20000);
    if (info.suAvailable) {
        std::string ignored;
        return adb_.shell(serial, "su -c '" + command + "'", error, 20000);
    }
    return error = "the device is not rooted", std::string();
}

DeviceInfo certinstall::Installer::inspect(const std::string& serial, const ca::Store& ca) {
    DeviceInfo info;
    if (!adb::validSerial(serial)) {
        info.notes = "invalid device serial";
        return info;
    }
    info.devicePresent = true;
    std::string error;
    for (const auto& [key, value] : adb_.properties(serial, error)) {
        if (key == "ro.product.model") info.model = value;
        else if (key == "ro.build.version.release") info.androidRelease = value;
        else if (key == "ro.build.version.sdk") info.sdk = std::atoi(value.c_str());
    }
    if (!error.empty()) {
        info.notes = "adb: " + error;
        return info;
    }
    // Root: adbd itself, or su.
    const std::string id = trimmed(adb_.shell(serial, "id", error, 5000));
    info.adbdRoot = contains(id, "uid=0");
    std::string ignored;
    const std::string suId = trimmed(adb_.shell(serial, "su -c id", ignored, 8000));
    info.suAvailable = contains(suId, "uid=0");
    const std::string hashName = ca.androidFileName();
    const bool newStore = info.sdk >= 34;
    // User store: per-user added CAs; listing needs root on most builds.
    const std::string listUser = info.adbdRoot ? "ls /data/misc/user/0/cacerts-added/"
                                     : info.suAvailable ? "su -c 'ls /data/misc/user/0/cacerts-added/'"
                                                        : "ls /data/misc/user/0/cacerts-added/";
    const std::string user = adb_.shell(serial, listUser, ignored, 8000);
    info.userStoreReadable = !user.empty() && !contains(user, "Permission denied") && !contains(user, "denied");
    info.caUserInstalled = info.userStoreReadable && contains(user, hashName);
    if (!info.userStoreReadable) info.notes = "the user store cannot be listed without root";
    // System store: the classic directory, or the Conscrypt APEX on 14+.
    const std::string sysDir = newStore ? "/apex/com.android.conscrypt/cacerts" : "/system/etc/security/cacerts";
    const std::string sys = adb_.shell(serial, "ls " + sysDir + "/" + hashName, ignored, 8000);
    info.caSystemInstalled = !sys.empty() && !contains(sys, "No such file") && !contains(sys, "denied") &&
                             !contains(sys, "Not a directory");
    if (newStore) {
        // Our tmpfs overlay over the system directory (the install mechanism
        // below); `mount` output says whether it is up.
        const std::string mounts = adb_.shell(serial, "mount", ignored, 8000);
        info.overlayMounted = contains(mounts, "/system/etc/security/cacerts");
    }
    return info;
}

bool certinstall::Installer::installUserCert(const std::string& serial, const ca::Store& ca, std::string& error) {
    const std::string local = exportToTemp(ca, error);
    if (local.empty()) return false;
    if (!adb_.push(serial, local, "/sdcard/apkspy-ca.crt", error)) {
        error = "could not copy the certificate to the device: " + error;
        return false;
    }
    // Open the page where "Install a certificate" lives (there is no adb
    // command that installs into the user store).
    adb_.shell(serial, "am start -a android.settings.SECURITY_SETTINGS", error, 8000);
    return true;
}

bool certinstall::Installer::installSystemCert(const std::string& serial, const ca::Store& ca, std::string& error) {
    DeviceInfo info = inspect(serial, ca);
    if (!info.devicePresent) return false;
    if (!info.adbdRoot && !info.suAvailable)
        return error = "installing into the system store needs root (a rooted device, or an emulator with 'adb root')",
               false;
    const std::string local = exportToTemp(ca, error);
    if (local.empty()) return false;
    if (!adb_.push(serial, local, kRemoteCert, error)) return false;
    const std::string name = ca.androidFileName();
    std::string ignored;
    if (info.sdk >= 34) {
        // Android 14+: apps read the Conscrypt APEX store. Overlay the system
        // directory with a tmpfs containing all current certificates plus
        // ours, then bind it into running processes' mount namespaces (new
        // processes pick it up by themselves).
        const std::string steps[] = {
            "mkdir -p /data/local/tmp/apkspy-cacerts",
            "cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/apkspy-cacerts/",
            "cp /data/local/tmp/apkspy-ca.pem /data/local/tmp/apkspy-cacerts/" + name,
            "chmod 644 /data/local/tmp/apkspy-cacerts/*",
            "chown root:root /data/local/tmp/apkspy-cacerts/*",
            "mount -t tmpfs tmpfs /system/etc/security/cacerts",
            "cp /data/local/tmp/apkspy-cacerts/* /system/etc/security/cacerts/",
            "chmod 644 /system/etc/security/cacerts/*",
            "chown root:root /system/etc/security/cacerts/*",
        };
        for (const std::string& cmd : steps) runRoot(serial, info, cmd, ignored);
        // Propagate to already-running processes (zygote children keep their
        // old namespace otherwise). nsenter missing on older toybox: new
        // processes still see the store after they start.
        runRoot(serial, info,
                "for p in $(ls /proc | grep -E '^[0-9]+$'); do nsenter -t $p -m -- mount --bind "
                "/system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null; done",
                ignored);
        const std::string check = runRoot(serial, info, "ls /system/etc/security/cacerts/" + name, ignored);
        return !check.empty() && !contains(check, "No such file");
    }
    // Android 13 and older: the classic system store directory.
    const std::string steps[] = {
        "mount -o remount,rw /system",
        "cp /data/local/tmp/apkspy-ca.pem /system/etc/security/cacerts/" + name,
        "chmod 644 /system/etc/security/cacerts/" + name,
        "chown root:root /system/etc/security/cacerts/" + name,
        "restorecon /system/etc/security/cacerts/" + name,
        "mount -o remount,ro /system",
    };
    for (const std::string& cmd : steps) runRoot(serial, info, cmd, ignored);
    const std::string check = runRoot(serial, info, "ls /system/etc/security/cacerts/" + name, ignored);
    return !check.empty() && !contains(check, "No such file");
}

bool certinstall::Installer::removeSystemCert(const std::string& serial, const ca::Store& ca, std::string& error) {
    DeviceInfo info = inspect(serial, ca);
    if (!info.devicePresent) return false;
    if (!info.adbdRoot && !info.suAvailable) return error = "removing from the system store needs root", false;
    std::string ignored;
    if (info.sdk >= 34) {
        // The overlay disappears; already-running processes keep their mount
        // until they restart.
        runRoot(serial, info, "umount /system/etc/security/cacerts", ignored);
        return true;
    }
    const std::string name = ca.androidFileName();
    runRoot(serial, info, "mount -o remount,rw /system", ignored);
    runRoot(serial, info, "rm /system/etc/security/cacerts/" + name, ignored);
    runRoot(serial, info, "mount -o remount,ro /system", ignored);
    const std::string check = runRoot(serial, info, "ls /system/etc/security/cacerts/" + name, ignored);
    return contains(check, "No such file");
}

const char* certinstall::Installer::userInstallSteps(int sdk) {
    (void)sdk;  // the steps are the same; the SDK-24 trust restriction is in the text
    return "1. The certificate was copied to the device and Security settings opened.\n"
           "2. Tap 'Install a certificate' > 'CA certificate' (on older versions: 'Install from storage').\n"
           "3. Pick apkspy-ca.crt from the device storage (the dialog warns that the network may be "
           "monitored - that is what a debugging CA is for).\n"
           "4. Apps must trust user certificates: since Android 7 (SDK 24), apps that target SDK 24+ do not, "
           "unless their network security config opts in. System-store installation (rooted devices) or a "
           "debug build of the app are the ways around it.\n"
           "5. Verify back in this dialog with 'Re-check'.";
}

const char* certinstall::Installer::quicNote() {
    return "Apps using QUIC / HTTP3 (UDP port 443) bypass this TCP proxy: their traffic cannot be captured. "
           "On a rooted device, blocking UDP 443 forces them to fall back to TCP (and thus into the proxy):\n"
           "  adb shell su -c 'iptables -I OUTPUT -p udp --dport 443 -j REJECT'\n"
           "Some apps can also be told to disable QUIC in their settings (e.g. Chrome's flags).";
}

}  // namespace certinstall
