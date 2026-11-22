// "HTTPS & certificates" dialog of the Traffic panel: ApkSpy's certificate
// authority (status, export, regenerate) and the Android side (install into
// the user store, system store with root, trust diagnostics, QUIC note).
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include "app/Theme.hpp"
#include "core/ApkInfo.hpp"
#include "core/TextUtils.hpp"
#include "debug/CertInstaller.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

namespace {

// The opened APKs' trust-relevant manifest facts (cached per path).
struct AppTrust {
    std::string name;         // apk title
    std::string targetSdk;
    bool debuggable = false;
    std::string networkSecurityConfig;
};

}  // namespace

void TrafficPanel::refreshCertInfo() {
    ca::Store* ca = devices_.ca();
    certInfo_ = CertInfo{};
    if (!ca || !ca->ready()) {
        certInfo_.valid = false;
        return;
    }
    certInfo_.valid = true;
    certInfo_.subject = ca->ca()->subject();
    certInfo_.issuer = ca->ca()->issuer();
    certInfo_.serial = ca->ca()->serialHex();
    certInfo_.fingerprint = ca->ca()->sha256Fingerprint();
    certInfo_.notBefore = ca->ca()->notBefore();
    certInfo_.notAfter = ca->ca()->notAfter();
    certInfo_.secondsLeft = ca->ca()->secondsUntilExpiry();
}

void TrafficPanel::drawCertDialog() {
    // The device inspection runs a handful of adb commands: off the UI thread.
    if (certInfoJob_.valid() && certInfoJob_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        certInfo_ = certInfoJob_.get();
        certInfoBusy_ = false;
    }
    ImGui::SetNextWindowSize(ImVec2(ui::em(46.f), 0.f), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("HTTPS & certificates", nullptr, ImGuiWindowFlags_NoSavedSettings)) return;

    ca::Store* ca = devices_.ca();
    if (!ca || !ca->ready()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextWrapped("HTTPS interception is off (no CA loaded). Enable it in File > Settings > Network, "
                           "then come back to install the certificate on a device.");
        ImGui::PopTextWrapPos();
        if (ui::dialogButton("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }

    // ---- The CA -----------------------------------------------------------
    ImGui::SeparatorText("ApkSpy certificate authority");
    if (certInfo_.subject.empty()) refreshCertInfo();
    const bool expired = certInfo_.valid && certInfo_.secondsLeft <= 0;
    const bool soon = certInfo_.valid && certInfo_.secondsLeft > 0 && certInfo_.secondsLeft < 90ll * 24 * 3600;
    ImGui::TextWrapped("Subject:  %s", certInfo_.subject.c_str());
    ImGui::TextWrapped("Issuer:   %s", certInfo_.issuer.c_str());
    ImGui::TextWrapped("Serial:   %s", certInfo_.serial.c_str());
    ImGui::TextWrapped("SHA-256:  %s", certInfo_.fingerprint.c_str());
    ImGui::TextWrapped("Valid:    %s  to  %s", certInfo_.notBefore.c_str(), certInfo_.notAfter.c_str());
    if (expired)
        ui::wrappedColored(kError, "The CA has EXPIRED: regenerate it, then install the new certificate on the device.");
    else if (soon)
        ui::wrappedColored(kWarn, "The CA expires in less than 90 days.");
    if (ui::smallButton("Export PEM")) ImGui::OpenPopup("##expem");
    ImGui::SameLine();
    if (ui::smallButton("Export CER (DER)")) ImGui::OpenPopup("##expcer");
    ImGui::SameLine();
    ImGui::BeginDisabled(certInfoBusy_);
    if (ui::smallButton("Regenerate CA")) ImGui::OpenPopup("##regen");
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("A brand new CA. Devices that trusted the old one stop trusting ApkSpy's certificates "
                          "until the new CA is installed there.");
    if (!certExportPath_.empty()) ui::wrappedColored(kDim, "Exported to " + certExportPath_);
    if (ImGui::BeginPopup("##regen")) {
        ImGui::TextWrapped("Generate a new CA? Every device that has the current certificate installed must get "
                           "the new one (and re-trust it) before HTTPS can be captured again.");
        if (ui::dialogButton("Regenerate")) {
            std::string error;
            if (devices_.regenerateCa(error)) {
                refreshCertInfo();
                certStatus_ = "A new CA was generated.";
            } else
                certStatus_ = "Regeneration failed: " + error;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ui::dialogButton("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    // The exports go through the file browser (the key is never exported).
    static FileBrowser saver;
    if (ImGui::BeginPopup("##expem")) {
        saver.open(FileBrowser::Mode::SaveFile);
        saver.setDefaultName("apkspy-ca.pem");
        ImGui::CloseCurrentPopup();
        showCerts_ = true;
    }
    if (ImGui::BeginPopup("##expcer")) {
        saver.open(FileBrowser::Mode::SaveFile);
        saver.setDefaultName("apkspy-ca.cer");
        ImGui::CloseCurrentPopup();
    }
    saver.render();
    {
        std::string path;
        if (saver.takeAccepted(path)) {
            // .cer = DER (what Android's own tooling exports), else PEM.
            const bool der = path.size() > 4 && tex::asciiIEqual(path.substr(path.size() - 4), ".cer");
            const std::string bytes = der ? ca->caDer() : ca->caPem();
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            if (out.good()) {
                certExportPath_ = path;
                certStatus_ = "Certificate exported to " + path;
            } else
                certStatus_ = "Could not write " + path;
        }
    }

    ImGui::Spacing();

    // ---- The device -------------------------------------------------------
    ImGui::SeparatorText("Android device");
    const std::vector<adb::Device> devices = devices_.devices();
    std::string serial = devices_.selected();
    if (serial.empty())
        for (const auto& d : devices)
            if (d.state == "device") serial = d.serial;
    if (serial.empty()) {
        ImGui::TextWrapped("No device connected. Connect one (or start an emulator) to install the certificate.");
    } else {
        adb::Device dev;
        for (const auto& d : devices)
            if (d.serial == serial) dev = d;
        if (certInfoJob_.valid()) {
            ImGui::TextDisabled("checking %s...", dev.model.empty() ? serial.c_str() : dev.model.c_str());
        } else if (certInfo_.ran) {
            std::string line = std::string(dev.model.empty() ? serial.c_str() : dev.model.c_str());
            if (!certInfo_.androidRelease.empty()) line += ", Android " + certInfo_.androidRelease;
            line += certInfo_.caUserInstalled ? "  |  user store: CA installed" : "  |  user store: not installed";
            line += certInfo_.caSystemInstalled ? "  |  system store: CA installed" : "  |  system store: not installed";
            ui::wrappedColored(certInfo_.caUserInstalled || certInfo_.caSystemInstalled ? kGood : kWarn, line);
            if (certInfo_.sdk >= 24 && certInfo_.caUserInstalled && !certInfo_.caSystemInstalled)
                ui::wrappedColored(
                    kWarn, "Apps targeting Android 7+ do not trust user-installed CAs unless their network security "
                           "config allows it; for full coverage use the system store (root) or a debug build.");
            if (!certInfo_.notes.empty()) ui::wrappedColored(kDim, certInfo_.notes);
        }
        // Actions
        if (ui::smallButton("Install for the user (opens Settings)")) {
            certinstall::Installer installer(devices_.adb());
            std::string error;
            if (installer.installUserCert(serial, *ca, error)) {
                certStatus_ = "The certificate was copied to the device and Security settings opened.\n" +
                              std::string(certinstall::Installer::userInstallSteps(certInfo_.sdk));
                refreshCertInfo();
                certInfo_.ran = false;  // re-check after the user installed it
            } else
                certStatus_ = "Could not copy the certificate: " + error;
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(certInfoBusy_);
        if (ui::smallButton("Re-check")) {
            certInfoBusy_ = true;
            std::string caDir = ca->dir();
            // The installer needs the store outliving the job; the proxy holds
            // it, and we re-load from the same directory here (cheap).
            auto store = std::make_shared<ca::Store>();
            std::string error;
            store->loadOrGenerate(caDir, error);
            certInfoJob_ = std::async(std::launch::async, [serial, store, base = certInfo_, &adb = devices_.adb()] {
                certinstall::Installer installer(adb);
                CertInfo info = base;
                certinstall::DeviceInfo d = installer.inspect(serial, *store);
                info.ran = true;
                info.deviceSerial = serial;
                info.deviceModel = d.model;
                info.androidRelease = d.androidRelease;
                info.sdk = d.sdk;
                info.adbdRoot = d.adbdRoot;
                info.suAvailable = d.suAvailable;
                info.userStoreReadable = d.userStoreReadable;
                info.caUserInstalled = d.caUserInstalled;
                info.caSystemInstalled = d.caSystemInstalled;
                info.overlayMounted = d.overlayMounted;
                info.notes = d.notes;
                return info;
            });
        }
        ImGui::EndDisabled();
        ImGui::Spacing();
        ImGui::TextWrapped("System store (rooted devices - trusted by all apps):");
        if (ui::smallButton("Install into the system store")) ImGui::OpenPopup("##sysinst");
        ImGui::SameLine();
        if (ui::smallButton("Remove from the system store")) ImGui::OpenPopup("##sysrm");
        if (ImGui::BeginPopup("##sysinst")) {
            ImGui::TextWrapped("This modifies the device's system files (%s). A backup of the store is kept in "
                               "/data/local/tmp/apkspy-cacerts on Android 14+. Continue?",
                               certInfo_.sdk >= 34 ? "tmpfs overlay over the certificate directory, propagated to "
                                                    "running processes"
                                                   : "/system/etc/security/cacerts");
            if (ui::dialogButton("Install")) {
                certinstall::Installer installer(devices_.adb());
                std::string error;
                certStatus_ = installer.installSystemCert(serial, *ca, error) ? "Installed into the system store."
                                                                              : "System store install failed: " + error;
                ImGui::CloseCurrentPopup();
                certInfo_.ran = false;
            }
            ImGui::SameLine();
            if (ui::dialogButton("Cancel")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
        if (ImGui::BeginPopup("##sysrm")) {
            ImGui::TextWrapped("Remove ApkSpy's CA from the system store? Apps that trust only the system store "
                               "stop trusting the proxy afterwards.");
            if (ui::dialogButton("Remove")) {
                certinstall::Installer installer(devices_.adb());
                std::string error;
                certStatus_ = installer.removeSystemCert(serial, *ca, error)
                                  ? "Removed from the system store (running apps may need a restart)."
                                  : "Removal failed: " + error;
                ImGui::CloseCurrentPopup();
                certInfo_.ran = false;
            }
            ImGui::SameLine();
            if (ui::dialogButton("Cancel")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }

    ImGui::Spacing();

    // ---- App compatibility ------------------------------------------------
    ImGui::SeparatorText("App compatibility");
    std::vector<AppTrust> apps;
    for (Root* r : workspace_.apkRoots()) {
        static std::unordered_map<std::string, ApkInfo> cache;
        auto it = cache.find(r->apkPath);
        if (it == cache.end()) it = cache.emplace(r->apkPath, ApkInfo::extract(*r)).first;
        AppTrust t;
        t.name = r->title;
        t.targetSdk = it->second.targetSdk;
        t.debuggable = it->second.debuggable;
        t.networkSecurityConfig = it->second.networkSecurityConfig;
        apps.push_back(std::move(t));
    }
    if (apps.empty()) {
        ImGui::TextWrapped("Open the app's APK in the project to see whether it can trust user-installed "
                           "certificates (network security config, target SDK).");
    } else {
        for (const AppTrust& a : apps) {
            const int sdk = std::atoi(a.targetSdk.c_str());
            std::string line = a.name + "  (target SDK " + (a.targetSdk.empty() ? "?" : a.targetSdk) + ")";
            ui::wrappedColored(kAccent, line);
            if (a.debuggable)
                ui::wrappedColored(kGood, "  debuggable: debug builds usually trust user CAs (debug-overrides)");
            if (!a.networkSecurityConfig.empty())
                ui::wrappedColored(kWarn, "  network security config: " + a.networkSecurityConfig +
                                              " - open it (res/xml) and check its trust anchors and pinning");
            else if (sdk >= 24)
                ui::wrappedColored(kWarn, "  no network security config and target SDK >= 24: user-installed CAs are "
                                          "NOT trusted; use the system store or a rebuild with a config");
            else if (sdk > 0)
                ui::wrappedColored(kGood, "  target SDK < 24: user-installed CAs are trusted");
        }
    }
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("\nQUIC / HTTP3:");
    ImGui::SameLine();
    ImGui::TextWrapped("%s", certinstall::Installer::quicNote());
    ImGui::PopTextWrapPos();

    if (!certStatus_.empty()) {
        ImGui::Separator();
        ui::wrappedColored(kDim, certStatus_);
    }
    ImGui::Separator();
    if (ui::dialogButton("Close")) {
        ImGui::CloseCurrentPopup();
        certStatus_.clear();
    }
    ImGui::EndPopup();
}
