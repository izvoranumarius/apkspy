#include "ui/RepackPanel.hpp"
#include <cstring>
#include <fstream>
#include <sstream>
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "core/Settings.hpp"
#include "ui/UiUtil.hpp"

namespace {
void setStr(char* buf, size_t n, const std::string& v) {
    std::snprintf(buf, n, "%s", v.c_str());
}
std::string readFile(const std::string& path, bool& ok) {
    std::ifstream in(pathutil::fromUtf8(path), std::ios::binary);
    if (!in) {
        ok = false;
        return {};
    }
    std::ostringstream s;
    s << in.rdbuf();
    ok = true;
    return s.str();
}
}  // namespace

void RepackPanel::build() {
    status_.clear();
    log_.clear();
    repack::Options opts;
    opts.sourceApk = source_;
    opts.outputApk = output_;
    opts.align = align_;
    opts.sign = sign_;
    if (keyMode_ == 1) {
        opts.keystorePath = ksPath_;
        opts.keystorePassword = ksPass_;
        opts.keyAlias = ksAlias_;
        opts.keyPassword = keyPass_;
    }
    if (opts.sourceApk.empty() || opts.outputApk.empty()) {
        status_ = "Set a source APK and an output path.";
        return;
    }
    if (opts.sourceApk == opts.outputApk) {
        status_ = "Output must differ from the source.";
        return;
    }
    for (const auto& e : replacements_) {
        bool ok = false;
        std::string bytes = readFile(e.file, ok);
        if (!ok) {
            status_ = "Cannot read replacement file: " + e.file;
            return;
        }
        opts.replacements.push_back({e.zipPath, std::move(bytes)});
    }
    const repack::Tools tools = repack::Tools::fromAdb(settings_.getString(Settings::kAdbPath, "adb"));
    status_ = "Building...";
    job_ = std::async(std::launch::async, [opts, tools] { return repack::run(opts, tools); });
}

void RepackPanel::drawContents() {
    if (!prefilled_) {
        prefilled_ = true;
        const auto apks = workspace_.apkRoots();
        if (!apks.empty() && !apks.front()->apkPath.empty()) {
            setStr(source_, sizeof source_, apks.front()->apkPath);
            const std::string src = apks.front()->apkPath;
            const size_t dot = src.rfind('.');
            setStr(output_, sizeof output_, (dot == std::string::npos ? src : src.substr(0, dot)) + "-repacked.apk");
        }
    }

    // Reap a finished build.
    if (job_.valid() && job_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        const repack::Result r = job_.get();
        log_ = r.log;
        if (r.ok && r.signedOutput) status_ = "Done: signed APK at " + r.outputApk;
        else if (r.ok) status_ = "Done (UNSIGNED): " + (r.error.empty() ? r.outputApk : r.error);
        else status_ = "Failed: " + r.error;
        workspace_.log("Repack: " + status_);
    }
    const bool busy = job_.valid();

    ImGui::TextUnformatted("Source APK");
    ImGui::SetNextItemWidth(-ui::em(6.f));
    ImGui::InputText("##src", source_, sizeof source_);
    ImGui::SameLine();
    if (ui::smallButton("Browse##src")) sourceBrowser_.open(FileBrowser::Mode::OpenFile);

    ImGui::TextUnformatted("Output APK");
    ImGui::SetNextItemWidth(-ui::em(6.f));
    ImGui::InputText("##out", output_, sizeof output_);
    ImGui::SameLine();
    if (ui::smallButton("Browse##out")) outputBrowser_.open(FileBrowser::Mode::SaveFile);

    std::string picked;
    if (sourceBrowser_.render(), sourceBrowser_.takeAccepted(picked)) setStr(source_, sizeof source_, picked);
    if (outputBrowser_.render(), outputBrowser_.takeAccepted(picked)) setStr(output_, sizeof output_, picked);

    // Replacements.
    ImGui::SeparatorText("Replaced entries");
    ImGui::TextDisabled("Replace whole zip entries (AndroidManifest.xml, resources.arsc, classes.dex, lib/.../*.so). Not smali.");
    if (ImGui::BeginTable("##repl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("Entry");
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##x", ImGuiTableColumnFlags_WidthFixed, ui::em(2.5f));
        int remove = -1;
        for (int i = 0; i < static_cast<int>(replacements_.size()); ++i) {
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(replacements_[i].zipPath.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", replacements_[i].file.c_str());
            ImGui::TableNextColumn();
            if (ui::smallButton("x")) remove = i;
            ImGui::PopID();
        }
        if (remove >= 0) replacements_.erase(replacements_.begin() + remove);
        ImGui::EndTable();
    }
    ImGui::SetNextItemWidth(ui::em(16.f));
    ImGui::InputTextWithHint("##newentry", "zip entry path, e.g. AndroidManifest.xml", newZipPath_, sizeof newZipPath_);
    ImGui::SameLine();
    if (ui::smallButton("Add file...") && newZipPath_[0]) replFileBrowser_.open(FileBrowser::Mode::OpenFile);
    if (replFileBrowser_.render(), replFileBrowser_.takeAccepted(picked)) {
        if (newZipPath_[0]) {
            replacements_.push_back({newZipPath_, picked});
            newZipPath_[0] = '\0';
        }
    }

    // Signing.
    ImGui::SeparatorText("Signing");
    ImGui::Checkbox("Align (zipalign)", &align_);
    ImGui::SameLine();
    ImGui::Checkbox("Sign", &sign_);
    if (sign_) {
        ImGui::RadioButton("Debug keystore", &keyMode_, 0);
        ImGui::SameLine();
        ImGui::RadioButton("Custom keystore", &keyMode_, 1);
        if (keyMode_ == 1) {
            ImGui::SetNextItemWidth(-ui::em(6.f));
            ImGui::InputText("Keystore", ksPath_, sizeof ksPath_);
            ImGui::SameLine();
            if (ui::smallButton("Browse##ks")) ksBrowser_.open(FileBrowser::Mode::OpenFile);
            if (ksBrowser_.render(), ksBrowser_.takeAccepted(picked)) setStr(ksPath_, sizeof ksPath_, picked);
            ImGui::InputText("Store password", ksPass_, sizeof ksPass_, ImGuiInputTextFlags_Password);
            ImGui::InputText("Key alias", ksAlias_, sizeof ksAlias_);
            ImGui::InputText("Key password", keyPass_, sizeof keyPass_, ImGuiInputTextFlags_Password);
            ImGui::TextDisabled("Key password defaults to the store password when blank.");
        } else {
            ImGui::TextDisabled("Uses ~/.android/debug.keystore (created with keytool if absent).");
        }
    }

    ImGui::Separator();
    ImGui::BeginDisabled(busy);
    if (ImGui::Button(busy ? "Building..." : "Build")) build();
    ImGui::EndDisabled();
    if (!status_.empty()) {
        ImGui::SameLine();
        const bool bad = status_.rfind("Failed", 0) == 0 || status_.rfind("Set ", 0) == 0 || status_.rfind("Cannot", 0) == 0 ||
                         status_.rfind("Output", 0) == 0;
        ImGui::TextColored(bad ? theme::vec(Col::Error) : theme::vec(Col::Success), "%s", status_.c_str());
    }
    if (!log_.empty()) {
        ImGui::BeginChild("##repacklog", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::PushFont(Theme::monoFont());
        ImGui::TextUnformatted(log_.c_str());
        ImGui::PopFont();
        ImGui::EndChild();
    }
}
