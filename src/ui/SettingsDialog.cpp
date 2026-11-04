#include "ui/SettingsDialog.hpp"
#include "ui/McpSettings.hpp"

namespace {
constexpr int kCategoryCount = 6;
const char* kCategories[kCategoryCount] = {"Environment", "JADX", "Text Editor", "Android / ADB", "Scripts", "AI (MCP)"};
}

void SettingsDialog::open() {
    open_ = true;
    category_ = 0;
    std::snprintf(jadxPath_, sizeof jadxPath_, "%s", workspace_.jadxPath().c_str());
    std::snprintf(jadxArgs_, sizeof jadxArgs_, "%s", workspace_.jadxArgs().c_str());
    restoreSession_ = settings_.getBool(Settings::kRestoreSession, true);
    lineNumbers_ = settings_.getBool(Settings::kLineNumbers, true);
    fullCjk_ = settings_.getBool(Settings::kFullCjkFonts, false);
    std::snprintf(adbPath_, sizeof adbPath_, "%s", devices_.adbPath().c_str());
    std::snprintf(pythonPath_, sizeof pythonPath_, "%s", settings_.getString(Settings::kPythonPath, "python").c_str());
    trafficPort_ = settings_.getInt(Settings::kTrafficPort, 8899);
    adbTestResult_.clear();
}

bool SettingsDialog::render() {
    bool resultPending = false;
    if (!open_) return false;

    ImGui::SetNextWindowSize(ImVec2(760, 480), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings;
    if (!ImGui::Begin("Settings", &open_, flags)) {
        ImGui::End();
        return false;
    }

    // Left category list ----------------------------------------------------
    ImGui::BeginChild("##categories", ImVec2(170, -ImGui::GetFrameHeightWithSpacing() - 8.f),
                      ImGuiChildFlags_Borders);
    for (int i = 0; i < kCategoryCount; ++i)
        if (ImGui::Selectable(kCategories[i], category_ == i)) category_ = i;
    ImGui::EndChild();
    ImGui::SameLine();

    // Right settings page ----------------------------------------------------
    ImGui::BeginChild("##page", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8.f));
    switch (category_) {
    case 0: drawGeneralPage(); break;
    case 1: drawJadxPage(); break;
    case 2: drawEditorPage(); break;
    case 3: drawAndroidPage(); break;
    case 4: drawScriptsPage(); break;
    case 5:
        if (mcp_) mcp_->draw();
        break;
    }
    ImGui::EndChild();

    // Bottom buttons ---------------------------------------------------------
    float okW = 88.f;
    float totalW = okW * 3 + 8.f * 2;
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - totalW - ImGui::GetStyle().WindowPadding.x);
    bool apply = false, ok = false;
    if (ImGui::Button("OK", ImVec2(okW, 0))) {
        ok = true;
        apply = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(okW, 0))) {
        open_ = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Apply", ImVec2(okW, 0))) apply = true;

    if (apply) {
        workspace_.setJadxPath(jadxPath_);
        workspace_.setJadxArgs(jadxArgs_);
        settings_.set(Settings::kJadxPath, jadxPath_);
        settings_.set(Settings::kJadxArgs, jadxArgs_);
        settings_.set(Settings::kRestoreSession, restoreSession_);
        settings_.set(Settings::kLineNumbers, lineNumbers_);
        settings_.set(Settings::kFullCjkFonts, fullCjk_);
        devices_.setAdbPath(adbPath_);
        settings_.set(Settings::kAdbPath, adbPath_);
        settings_.set(Settings::kPythonPath, std::string(pythonPath_));
        settings_.set(Settings::kTrafficPort, trafficPort_);
        devices_.refreshDevices();
        resultPending = true;
    }
    if (ok) open_ = false;

    ImGui::End();

    browser_.render();
    std::string picked;
    if (browser_.takeAccepted(picked)) std::snprintf(jadxPath_, sizeof jadxPath_, "%s", picked.c_str());
    adbBrowser_.render();
    if (adbBrowser_.takeAccepted(picked)) std::snprintf(adbPath_, sizeof adbPath_, "%s", picked.c_str());

    return resultPending;
}

void SettingsDialog::drawGeneralPage() {
    ImGui::TextDisabled("Session");
    ImGui::Checkbox("Restore last session on startup (open APK and editor tabs)", &restoreSession_);
    ImGui::Separator();
    ImGui::TextDisabled("Fonts");
    ImGui::Checkbox("Full CJK glyph coverage (more memory, needs a restart)", &fullCjk_);
    ImGui::Separator();
    ImGui::TextDisabled("Layout");
    ImGui::TextWrapped(
        "Panel positions and sizes are saved automatically when ApkSpy closes "
        "and are restored on the next start. Use View > Reset Workspace Layout to return "
        "to the default docking layout.");
}

void SettingsDialog::drawJadxPage() {
    ImGui::TextWrapped("jadx converts the APK into Java/Kotlin sources and resources. "
                       "ApkSpy needs the path of the jadx launcher script or executable.");
    ImGui::Spacing();

    ImGui::Text("jadx executable:");
    float browseW = 110.f;
    ImGui::SetNextItemWidth(-browseW - 8.f);
    ImGui::InputText("##jadxpath", jadxPath_, sizeof jadxPath_);
    ImGui::SameLine();
    if (ImGui::Button("Browse...", ImVec2(browseW, 0))) browser_.open(FileBrowser::Mode::SelectExecutable);

    ImGui::Text("Extra command line arguments:");
    ImGui::SetNextItemWidth(-browseW - 8.f);
    ImGui::InputText("##jadxargs", jadxArgs_, sizeof jadxArgs_);
    ImGui::SameLine();
    ImGui::Dummy(ImVec2(browseW, 0));

    ImGui::Spacing();
    // Disabled while a test is running (starting another would have to
    // join the live thread on the UI thread and freeze the dialog).
    if (workspace_.jadx().testRunning()) ImGui::BeginDisabled();
    if (ImGui::Button("Test installation")) workspace_.jadx().testInstall(jadxPath_);
    if (workspace_.jadx().testRunning()) {
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("testing...");
    } else {
        bool ok = false;
        std::string result = workspace_.jadx().takeTestResult(ok);
        if (!result.empty()) {
            ImGui::SameLine();
            if (ok) ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.f), "OK - %s", result.c_str());
            else ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.f), "%s", result.c_str());
        }
    }
    ImGui::Spacing();
    ImGui::TextDisabled("Hint: on Windows select jadx.bat, on Linux/macOS the jadx shell script.");
}

void SettingsDialog::drawEditorPage() {
    ImGui::Checkbox("Show line numbers", &lineNumbers_);
    ImGui::Separator();
    ImGui::TextWrapped("Single-clicking a file in the explorer opens it in a preview tab; "
                       "double-clicking keeps it permanently. Files open in a read-only view - "
                       "use the Edit toggle above the document to modify them. Modified files "
                       "are marked with a star (*) and ApkSpy asks for confirmation before "
                       "closing them.");
}

void SettingsDialog::drawScriptsPage() {
    ImGui::TextWrapped("Scripts run with your installed Python. Leave \"python\" to use the one on PATH.");
    ImGui::Spacing();
    ImGui::Text("Python executable:");
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputText("##pythonpath", pythonPath_, sizeof pythonPath_);
}

void SettingsDialog::drawAndroidPage() {
    ImGui::TextWrapped("The Devices, Logcat and Debugger panels use adb from the Android SDK platform-tools. "
                       "Leave \"adb\" to use the one on PATH.");
    ImGui::Spacing();
    ImGui::Text("adb executable:");
    const float browseW = 110.f;
    ImGui::SetNextItemWidth(-browseW - 8.f);
    ImGui::InputText("##adbpath", adbPath_, sizeof adbPath_);
    ImGui::SameLine();
    if (ImGui::Button("Browse...##adb", ImVec2(browseW, 0))) adbBrowser_.open(FileBrowser::Mode::SelectExecutable);
    ImGui::Spacing();
    ImGui::Text("Traffic capture port:");
    ImGui::SetNextItemWidth(120.f);
    ImGui::InputInt("##trafficport", &trafficPort_, 0, 0);
    trafficPort_ = std::clamp(trafficPort_, 1024, 65535);
    ImGui::Spacing();
    const bool testing = adbTest_.valid();
    if (testing) ImGui::BeginDisabled();
    if (ImGui::Button("Test adb")) {
        const std::string path = adbPath_;
        adbTest_ = std::async(std::launch::async, [path] {
            adb::Adb probe(path.empty() ? "adb" : path);
            std::string error;
            std::string version = probe.version(error);
            return version.empty() ? (error.empty() ? std::string("adb did not answer") : error) : "OK - " + version;
        });
    }
    if (testing) {
        ImGui::EndDisabled();
        if (adbTest_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) adbTestResult_ = adbTest_.get();
        else {
            ImGui::SameLine();
            ImGui::TextDisabled("testing...");
        }
    }
    if (!adbTestResult_.empty()) {
        ImGui::SameLine();
        const bool ok = adbTestResult_.rfind("OK", 0) == 0;
        ImGui::TextColored(ok ? ImVec4(0.4f, 0.8f, 0.4f, 1.f) : ImVec4(0.95f, 0.45f, 0.35f, 1.f), "%s",
                           adbTestResult_.c_str());
    }
    ImGui::Separator();
    ImGui::TextWrapped("Debugging needs a debuggable app (android:debuggable=\"true\", or any app on a "
                       "userdebug/eng build or emulator image). Only one debugger can be attached to a process "
                       "at a time - close Android Studio's debugger first.");
}
