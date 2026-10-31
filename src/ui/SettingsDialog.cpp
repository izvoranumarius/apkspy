#include "ui/SettingsDialog.hpp"

namespace {
constexpr int kCategoryCount = 3;
const char* kCategories[kCategoryCount] = {"Environment", "JADX", "Text Editor"};
}

void SettingsDialog::open() {
    open_ = true;
    category_ = 0;
    std::snprintf(jadxPath_, sizeof jadxPath_, "%s", workspace_.jadxPath().c_str());
    std::snprintf(jadxArgs_, sizeof jadxArgs_, "%s", workspace_.jadxArgs().c_str());
    restoreSession_ = settings_.getBool(Settings::kRestoreSession, true);
    lineNumbers_ = settings_.getBool(Settings::kLineNumbers, true);
}

bool SettingsDialog::render() {
    resultPending_ = false;
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
        resultPending_ = true;
    }
    if (ok) open_ = false;

    ImGui::End();

    browser_.render("Select jadx Executable");
    std::string picked;
    if (browser_.takeAccepted(picked)) std::snprintf(jadxPath_, sizeof jadxPath_, "%s", picked.c_str());

    return resultPending_;
}

void SettingsDialog::drawGeneralPage() {
    ImGui::TextDisabled("Session");
    ImGui::Checkbox("Restore last session on startup (open APK and editor tabs)", &restoreSession_);
    ImGui::Separator();
    ImGui::TextDisabled("Layout");
    ImGui::TextWrapped(
        "Panel positions and sizes are saved automatically when ApkSpy closes "
        "and are restored on the next start. Use View > Reset Layout to return "
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
    if (ImGui::Button("Test installation")) workspace_.jadx().testInstall(jadxPath_);

    bool running = workspace_.jadx().testRunning();
    if (running) {
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
                       "double-clicking keeps it permanently. Modified files are marked "
                       "with a dot and ApkSpy asks for confirmation before closing them.");
}
