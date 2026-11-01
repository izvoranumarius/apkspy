#include "ui/OverviewPanel.hpp"
#include <algorithm>
#include <cstdio>
#include "app/Theme.hpp"

void OverviewPanel::drawContents() {
    auto apks = workspace_.apkRoots();
    if (apks.empty()) {
        ImGui::TextDisabled("Add an APK to the project to see its overview");
        return;
    }
    // Drop cached facts of APKs that are no longer in the project.
    for (auto it = cache_.begin(); it != cache_.end();) {
        bool alive = false;
        for (const Root* r : apks)
            if (r->apkPath == it->first) alive = true;
        it = alive ? std::next(it) : cache_.erase(it);
    }
    if (apkIdx_ >= (int)apks.size()) apkIdx_ = 0;

    Root* apk = apks[(size_t)apkIdx_];
    if (apks.size() > 1) {
        ImGui::Text("APK:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(220.f);
        if (ImGui::BeginCombo("##apk", apk->title.c_str())) {
            for (int i = 0; i < (int)apks.size(); ++i)
                if (ImGui::Selectable(apks[(size_t)i]->title.c_str(), i == apkIdx_)) apkIdx_ = i;
            ImGui::EndCombo();
        }
        ImGui::Separator();
        apk = apks[(size_t)apkIdx_];
    }

    auto it = cache_.find(apk->apkPath);
    if (it == cache_.end()) it = cache_.emplace(apk->apkPath, ApkInfo::extract(*apk)).first;
    drawApk(*apk, it->second);
}

void OverviewPanel::drawApk(Root& apk, const ApkInfo& info) {
    if (!info.ok) {
        ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.3f, 1.f), "Could not read the manifest of %s", apk.title.c_str());
        ImGui::TextDisabled("The Overview panel needs a readable (binary) AndroidManifest.xml.");
        return;
    }
    const std::string label = !info.appLabel.empty() ? info.appLabel : info.packageName;
    ImGui::Text("%s", label.c_str());
    std::string sub = info.packageName;
    if (!info.versionName.empty() || !info.versionCode.empty()) {
        sub += "  |  version " + info.versionName;
        if (!info.versionCode.empty()) sub += " (" + info.versionCode + ")";
    }
    if (!info.minSdk.empty()) sub += "  |  minSdk " + info.minSdk;
    if (!info.targetSdk.empty()) sub += "  |  targetSdk " + info.targetSdk;
    ImGui::TextDisabled("%s", sub.c_str());
    if (info.debuggable || info.allowBackup) {
        if (info.debuggable) {
            ImGui::TextColored(ImVec4(0.95f, 0.6f, 0.3f, 1.f), "debuggable");
            ImGui::SameLine();
        }
        if (info.allowBackup) {
            ImGui::TextColored(ImVec4(0.95f, 0.6f, 0.3f, 1.f), "allowBackup");
            ImGui::SameLine();
        }
        ImGui::NewLine();
    }
    ImGui::Separator();

    // Permissions ----------------------------------------------------------
    char header[128];
    std::snprintf(header, sizeof header, "Permissions (%d)", (int)info.permissions.size());
    if (ImGui::CollapsingHeader(header)) {
        if (info.permissions.empty()) ImGui::TextDisabled("None declared");
        for (const std::string& p : info.permissions) {
            ImGui::BulletText("%s", p.c_str());
        }
    }

    // Components -----------------------------------------------------------
    std::snprintf(header, sizeof header, "Components (%d)", (int)info.components.size());
    if (ImGui::CollapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen)) {
        if (info.components.empty()) ImGui::TextDisabled("None declared");
        // Clicking a row jumps to the class in the decompiled sources (M3
        // symbol index); if that fails the manifest opens instead.
        workspace_.ensureSymbolIndex(apk.title);
        int i = 0;
        for (const ApkComponent& c : info.components) {
            ImGui::PushID(i++);
            std::string row = c.type + ":  " + (c.name.empty() ? "(unnamed)" : c.name);
            if (c.exported) row += "   [exported]";
            if (ImGui::Selectable(row.c_str())) {
                if (!c.name.empty()) openComponent(apk.title, info.packageName, c);
            }
            if (!c.actions.empty() || !c.categories.empty()) {
                std::string tip;
                for (const std::string& a : c.actions) tip += "action: " + a + "\n";
                for (const std::string& c2 : c.categories) tip += "category: " + c2 + "\n";
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip.c_str());
            }
            ImGui::PopID();
        }
        ImGui::Separator();
        if (ImGui::Selectable("AndroidManifest.xml")) openManifest(apk.title);
    }

    // Signing --------------------------------------------------------------
    std::snprintf(header, sizeof header, "Signing (%d)", (int)info.signatures.size());
    if (ImGui::CollapsingHeader(header)) {
        if (info.signatures.empty()) {
            ImGui::TextDisabled("No signatures found (unsigned or unsupported scheme)");
        }
        int i = 0;
        for (const ApkSigningInfo& s : info.signatures) {
            ImGui::PushID(i++);
            ImGui::Text("%s", s.scheme.c_str());
            ImGui::PushFont(Theme::monoFont());
            ImGui::TextDisabled("cert sha256: %s", s.certSha256.c_str());
            ImGui::PopFont();
            if (!s.subject.empty() || !s.issuer.empty()) {
                std::string who = "subject: " + (s.subject.empty() ? "?" : s.subject) +
                                  "   issuer: " + (s.issuer.empty() ? "?" : s.issuer);
                ImGui::TextDisabled("%s", who.c_str());
            }
            ImGui::PopID();
        }
    }
}

void OverviewPanel::openComponent(const std::string& group, const std::string& pkg, const ApkComponent& c) {
    // Manifest class names come in three shapes: fully qualified, relative
    // (".Main") and bare ("Main" - unusual but legal).
    std::string cls = c.name;
    if (!cls.empty()) {
        if (cls[0] == '.') cls = pkg + cls;
        else if (cls.find('.') == std::string::npos) cls = pkg + "." + cls;
    }
    NavLocation origin;
    NavLocation* originPtr = nullptr;
    if (Document* active = workspace_.activeDocument()) {
        origin = workspace_.locationOf(*active);
        originPtr = &origin;
    }
    if (workspace_.openSymbol(group, cls, "", originPtr)) return;
    // Graceful fallback: the class may be framework/library code that jadx
    // has no source for - open the manifest so the user sees the entry.
    openManifest(group);
    workspace_.log("Class not in the decompiled sources: " + cls);
}

void OverviewPanel::openManifest(const std::string& group) {
    Root* apk = workspace_.rootByGroup(group, Root::Kind::Apk);
    if (!apk || !apk->tree) return;
    const TreeNode* manifest = apk->tree->findChild("AndroidManifest.xml");
    if (!manifest) return;
    NavLocation origin;
    NavLocation* originPtr = nullptr;
    if (Document* active = workspace_.activeDocument()) {
        origin = workspace_.locationOf(*active);
        originPtr = &origin;
    }
    workspace_.navigateTo(*apk, *manifest, -1, originPtr);
}
