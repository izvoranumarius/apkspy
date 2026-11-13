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
    if (apkIdx_ >= static_cast<int>(apks.size())) apkIdx_ = 0;

    Root* apk = apks[static_cast<size_t>(apkIdx_)];
    if (apks.size() > 1) {
        ImGui::Text("APK:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(220.f);
        if (ImGui::BeginCombo("##apk", apk->title.c_str())) {
            for (int i = 0; i < static_cast<int>(apks.size()); ++i)
                if (ImGui::Selectable(apks[static_cast<size_t>(i)]->title.c_str(), i == apkIdx_)) apkIdx_ = i;
            ImGui::EndCombo();
        }
        ImGui::Separator();
        apk = apks[static_cast<size_t>(apkIdx_)];
    }

    auto it = cache_.find(apk->apkPath);
    if (it == cache_.end()) {
        workspace_.resources(apk->title);  // label + @ref ids resolved through resources.arsc
        it = cache_.emplace(apk->apkPath, ApkInfo::extract(*apk)).first;
    }
    drawApk(*apk, it->second);
}

void OverviewPanel::drawApk(Root& apk, const ApkInfo& info) {
    if (!info.ok) {
        ImGui::TextColored(theme::vec(Col::Warning), "Could not read the manifest of %s", apk.title.c_str());
        ImGui::TextDisabled("The Overview panel needs a readable (binary) AndroidManifest.xml.");
        return;
    }
    const std::string label = !info.appLabel.empty() ? info.appLabel : info.packageName;
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(label.c_str());
    ImGui::PopTextWrapPos();
    std::string sub = info.packageName;
    if (!info.versionName.empty() || !info.versionCode.empty()) {
        sub += "  |  version " + info.versionName;
        if (!info.versionCode.empty()) sub += " (" + info.versionCode + ")";
    }
    if (!info.minSdk.empty()) sub += "  |  minSdk " + info.minSdk;
    if (!info.targetSdk.empty()) sub += "  |  targetSdk " + info.targetSdk;
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("%s", sub.c_str());
    ImGui::PopTextWrapPos();
    if (info.debuggable || info.allowBackup) {
        if (info.debuggable) {
            ImGui::TextColored(theme::vec(Col::Warning), "debuggable");
            ImGui::SameLine();
        }
        if (info.allowBackup) {
            ImGui::TextColored(theme::vec(Col::Warning), "allowBackup");
            ImGui::SameLine();
        }
        ImGui::NewLine();
    }
    ImGui::Separator();

    // Permissions ----------------------------------------------------------
    char header[128];
    std::snprintf(header, sizeof header, "Permissions (%d)", static_cast<int>(info.permissions.size()));
    if (ImGui::CollapsingHeader(header)) {
        if (info.permissions.empty()) ImGui::TextDisabled("None declared");
        // Runtime ("dangerous") permissions are highlighted: they are what a
        // reviewer looks at first.
        static const char* kDangerous[] = {
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA",
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "PROCESS_OUTGOING_CALLS", "BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
            "READ_MEDIA_AUDIO", "ACTIVITY_RECOGNITION", "POST_NOTIFICATIONS", "NEARBY_WIFI_DEVICES",
            "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
            "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "BIND_ACCESSIBILITY_SERVICE"};
        for (const std::string& p : info.permissions) {
            bool dangerous = false;
            for (const char* d : kDangerous)
                if (p == std::string("android.permission.") + d) dangerous = true;
            ImGui::Bullet();
            ImGui::PushTextWrapPos(0.f);
            if (dangerous) ImGui::TextColored(theme::vec(Col::Warning), "%s", p.c_str());
            else ImGui::TextUnformatted(p.c_str());
            ImGui::PopTextWrapPos();
            if (dangerous && ImGui::IsItemHovered()) ImGui::SetTooltip("Runtime (dangerous) permission");
        }
    }

    // Components -----------------------------------------------------------
    std::snprintf(header, sizeof header, "Components (%d)", static_cast<int>(info.components.size()));
    if (ImGui::CollapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen)) {
        if (info.components.empty()) ImGui::TextDisabled("None declared");
        // Clicking a row jumps to the class in the decompiled sources (M3
        // symbol index); if that fails the manifest opens instead.
        workspace_.ensureSymbolIndex(apk.title);
        if (ImGui::BeginTable("##components", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 4.f);
            ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthStretch);
            int i = 0;
            for (const ApkComponent& c : info.components) {
                ImGui::PushID(i++);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                const ImVec4 typeColor = c.type == "activity" || c.type == "activity-alias" ? theme::vec(Col::Blue)
                                         : c.type == "service"  ? theme::vec(Col::Green)
                                         : c.type == "receiver" ? theme::vec(Col::Yellow)
                                                                : theme::vec(Col::Purple);
                ImGui::TextColored(typeColor, "%s", c.type == "activity-alias" ? "alias" : c.type.c_str());
                ImGui::TableNextColumn();
                // Short class name first (the part that tells components
                // apart), the package dimmed after it.
                const std::string full = c.name.empty() ? std::string("(unnamed)") : c.name;
                const size_t dot = full.rfind('.');
                const std::string simple = dot == std::string::npos ? full : full.substr(dot + 1);
                if (ImGui::Selectable(simple.c_str(), false, ImGuiSelectableFlags_SpanAllColumns |
                                                             ImGuiSelectableFlags_AllowOverlap) &&
                    !c.name.empty())
                    openComponent(apk.title, info.packageName, c);
                if (ImGui::IsItemHovered()) {
                    std::string tip = full + (c.exported ? "\nexported" : "");
                    for (const std::string& a : c.actions) tip += "\naction: " + a;
                    for (const std::string& c2 : c.categories) tip += "\ncategory: " + c2;
                    ImGui::SetTooltip("%s", tip.c_str());
                }
                if (c.exported) {
                    ImGui::SameLine();
                    ImGui::TextColored(theme::vec(Col::Warning), "exported");
                }
                if (dot != std::string::npos) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("%s", full.substr(0, dot).c_str());
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::Separator();
        if (ImGui::Selectable("AndroidManifest.xml")) openManifest(apk.title);
    }

    // Signing --------------------------------------------------------------
    std::snprintf(header, sizeof header, "Signing (%d)", static_cast<int>(info.signatures.size()));
    if (ImGui::CollapsingHeader(header)) {
        if (info.signatures.empty()) {
            ImGui::TextDisabled("No signatures found (unsigned or unsupported scheme)");
        }
        int i = 0;
        for (const ApkSigningInfo& s : info.signatures) {
            ImGui::PushID(i++);
            ImGui::Text("%s", s.scheme.c_str());
            ImGui::PushFont(Theme::monoFont());
            ImGui::PushTextWrapPos(0.f);
            ImGui::TextDisabled("cert sha256: %s", s.certSha256.c_str());
            ImGui::PopTextWrapPos();
            ImGui::PopFont();
            if (!s.subject.empty() || !s.issuer.empty()) {
                std::string who = "subject: " + (s.subject.empty() ? "?" : s.subject) +
                                  "   issuer: " + (s.issuer.empty() ? "?" : s.issuer);
                ImGui::PushTextWrapPos(0.f);
                ImGui::TextDisabled("%s", who.c_str());
                ImGui::PopTextWrapPos();
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
