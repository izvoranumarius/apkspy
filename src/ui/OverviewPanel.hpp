#pragma once
#include "core/ApkInfo.hpp"
#include "ui/Panel.hpp"
#include <string>
#include <unordered_map>

// Read-only facts about each APK in the project (M4): manifest identity
// (package, version, SDKs, label), permissions, components (clicking a
// component jumps to its class via the symbol index, with the manifest as
// the fallback) and signing certificates (v1/v2/v3 fingerprints).
class OverviewPanel : public Panel {
public:
    explicit OverviewPanel(Workspace& workspace) : Panel(workspace, "Overview") {}

protected:
    void drawContents() override;

private:
    void drawApk(Root& apk, const ApkInfo& info);
    void openComponent(const std::string& group, const std::string& pkg, const ApkComponent& c);
    void openManifest(const std::string& group);
    // Facts are extracted on demand (UI thread) and cached per APK path;
    // entries of removed APKs are pruned.
    std::unordered_map<std::string, ApkInfo> cache_;
    int apkIdx_ = 0;
};
