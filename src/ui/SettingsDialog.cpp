#include "ui/SettingsDialog.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include "app/Icons.hpp"
#include "core/TextUtils.hpp"
#include "ui/McpSettings.hpp"
#include "ui/UiUtil.hpp"

namespace {

using Page = SettingsDialog::Page;

struct PageInfo {
    Page page;
    const char* icon;
    const char* title;
    const char* summary;  // shown under the page title
};

constexpr PageInfo kPages[] = {
    {Page::General, icons::SETTINGS, "General", "Startup and session."},
    {Page::Appearance, icons::EDIT, "Appearance", "Theme, colours, zoom and fonts."},
    {Page::Editor, icons::CODE, "Editor", "How files are shown and edited."},
    {Page::Decompiler, icons::PACKAGE, "Decompiler", "jadx turns the APK into Java / Kotlin sources and resources."},
    {Page::Android, icons::PHONE, "Android & Devices", "adb for the Devices, Logcat and Debugger panels."},
    {Page::Network, icons::GLOBE, "Network Capture", "The proxy the Traffic panel routes a device through."},
    {Page::Terminal, icons::TERMINAL, "Terminal & Scripts", "The shell of the Terminal panel and the Python for scripts."},
    {Page::Ai, icons::LINK, "AI (MCP)", "Let AI assistants use the open project."},
};

const PageInfo& info(Page p) { return kPages[static_cast<size_t>(p)]; }

// Section heading inside a page.
void section(const char* title) {
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
    ImGui::SeparatorText(title);
    ImGui::PopStyleColor();
}

// "label" above a full-width input with an optional Browse button.
bool pathInput(const char* label, const char* id, char* buf, size_t size, const char* hint, bool browse) {
    ImGui::TextUnformatted(label);
    const float browseW = browse ? ui::buttonWidth("Browse...") + ImGui::GetStyle().ItemSpacing.x : 0.f;
    ImGui::SetNextItemWidth(-browseW - 1.f);
    ImGui::InputTextWithHint(id, hint, buf, size);
    if (!browse) return false;
    ImGui::SameLine();
    ImGui::PushID(id);
    const bool clicked = ImGui::Button("Browse...");
    ImGui::PopID();
    return clicked;
}

void resultText(bool ok, const std::string& text) {
    ImGui::SameLine();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextColored(theme::vec(ok ? Col::Success : Col::Error), "%s", text.c_str());
    ImGui::PopTextWrapPos();
}

void hint(const char* text) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(text);
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
}

}  // namespace

void SettingsDialog::open() {
    open_ = true;
    std::snprintf(jadxPath_, sizeof jadxPath_, "%s", workspace_.jadxPath().c_str());
    std::snprintf(jadxArgs_, sizeof jadxArgs_, "%s", workspace_.jadxArgs().c_str());
    restoreSession_ = settings_.getBool(Settings::kRestoreSession, true);
    lineNumbers_ = settings_.getBool(Settings::kLineNumbers, true);
    fullCjk_ = settings_.getBool(Settings::kFullCjkFonts, false);
    std::snprintf(adbPath_, sizeof adbPath_, "%s", devices_.adbPath().c_str());
    std::snprintf(pythonPath_, sizeof pythonPath_, "%s", settings_.getString(Settings::kPythonPath, "python").c_str());
    std::snprintf(terminalShell_, sizeof terminalShell_, "%s", settings_.getString(Settings::kTerminalShell, "").c_str());
    trafficPort_ = settings_.getInt(Settings::kTrafficPort, 8899);
    adbTestResult_.clear();
    themeAtOpen_ = Theme::state();
    zoomAtOpen_ = getZoom_ ? getZoom_() : 1.f;
    colorFilter_[0] = '\0';
}

void SettingsDialog::revertPreview() {
    Theme::restore(themeAtOpen_);
    if (setZoom_ && getZoom_ && std::fabs(getZoom_() - zoomAtOpen_) > 0.001f) setZoom_(zoomAtOpen_);
}

void SettingsDialog::commit() {
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
    settings_.set(Settings::kTerminalShell, std::string(terminalShell_));
    settings_.set(Settings::kTrafficPort, trafficPort_);
    Theme::save(settings_);
    devices_.refreshDevices();
    // The applied appearance is the new baseline for Cancel.
    themeAtOpen_ = Theme::state();
    zoomAtOpen_ = getZoom_ ? getZoom_() : 1.f;
}

bool SettingsDialog::render() {
    if (!open_) return false;
    bool committed = false;

    ImGui::SetNextWindowSize(ImVec2(ui::em(52.f), ui::em(34.f)), ImGuiCond_Appearing);
    ImGui::SetNextWindowSizeConstraints(ImVec2(ui::em(36.f), ui::em(22.f)), ImVec2(FLT_MAX, FLT_MAX));
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings;
    bool keepOpen = true;
    if (!ImGui::Begin("Settings", &keepOpen, flags)) {
        ImGui::End();
        if (!keepOpen) {
            revertPreview();
            open_ = false;
        }
        return false;
    }

    const float footer = ImGui::GetFrameHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y * 2.f;

    // Page list ----------------------------------------------------------------
    ImGui::BeginChild("##pages", ImVec2(ui::em(11.5f), -footer), ImGuiChildFlags_Borders);
    for (const PageInfo& p : kPages) {
        const std::string label = ui::icon(p.icon, p.title);
        if (ImGui::Selectable(label.c_str(), page_ == p.page)) page_ = p.page;
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // Page ---------------------------------------------------------------------
    ImGui::BeginChild("##page", ImVec2(0, -footer), ImGuiChildFlags_None);
    const PageInfo& current = info(page_);
    ImGui::TextUnformatted(current.title);
    hint(current.summary);
    ImGui::Separator();
    ImGui::BeginChild("##pageBody", ImVec2(0, 0), ImGuiChildFlags_None);
    switch (page_) {
    case Page::General: drawGeneralPage(); break;
    case Page::Appearance: drawAppearancePage(); break;
    case Page::Editor: drawEditorPage(); break;
    case Page::Decompiler: drawDecompilerPage(); break;
    case Page::Android: drawAndroidPage(); break;
    case Page::Network: drawNetworkPage(); break;
    case Page::Terminal: drawTerminalPage(); break;
    case Page::Ai: drawAiPage(); break;
    case Page::Count: break;
    }
    ImGui::EndChild();
    ImGui::EndChild();

    // Buttons --------------------------------------------------------------------
    ImGui::Separator();
    const float buttonW = ui::em(5.5f);
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - buttonW * 3.f - spacing * 2.f - ImGui::GetStyle().WindowPadding.x);
    if (ImGui::Button("OK", ImVec2(buttonW, 0))) {
        commit();
        committed = true;
        open_ = false;
    }
    ImGui::SameLine();
    // Escape cancels, unless it is closing a colour picker or leaving a text field.
    const bool escape = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::IsAnyItemActive() &&
                        !ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId) && ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    if (ImGui::Button("Cancel", ImVec2(buttonW, 0)) || escape) {
        revertPreview();
        open_ = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Apply", ImVec2(buttonW, 0))) {
        commit();
        committed = true;
    }
    ImGui::End();
    if (!keepOpen && open_) {  // window close button = Cancel
        revertPreview();
        open_ = false;
    }

    jadxBrowser_.render();
    std::string picked;
    if (jadxBrowser_.takeAccepted(picked)) std::snprintf(jadxPath_, sizeof jadxPath_, "%s", picked.c_str());
    adbBrowser_.render();
    if (adbBrowser_.takeAccepted(picked)) std::snprintf(adbPath_, sizeof adbPath_, "%s", picked.c_str());
    return committed;
}

// ---- General ----------------------------------------------------------------

void SettingsDialog::drawGeneralPage() {
    section("Session");
    ImGui::Checkbox("Reopen the last project on startup (APKs and editor tabs)", &restoreSession_);
    section("Layout");
    hint("Panel positions and sizes are saved when ApkSpy closes and restored on the next start.");
    if (resetLayout_ && ImGui::Button("Reset the current workspace layout")) resetLayout_();
}

// ---- Appearance ---------------------------------------------------------------

void SettingsDialog::drawAppearancePage() {
    section("Theme");
    drawThemeCards();

    section("Zoom");
    if (getZoom_ && setZoom_) {
        int percent = static_cast<int>(std::lround(getZoom_() * 100.f));
        ImGui::SetNextItemWidth(ui::em(14.f));
        if (ImGui::SliderInt("##zoom", &percent, 60, 200, "%d%%")) setZoom_(static_cast<float>(percent) / 100.f);
        ImGui::SameLine();
        if (ImGui::Button("100%")) setZoom_(1.f);
        hint("Also Ctrl+= / Ctrl+- / Ctrl+0, or Ctrl + mouse wheel.");
    }

    section("Fonts");
    ImGui::Checkbox("Full CJK glyph coverage", &fullCjk_);
    hint("Every Chinese / Japanese ideograph instead of the common ones. Uses more memory; takes effect after a restart.");

    section("Colors");
    drawColorEditor();
}

void SettingsDialog::drawThemeCards() {
    const float cardW = ui::em(10.5f), cardH = ui::em(4.6f);
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float avail = ImGui::GetContentRegionAvail().x;
    const int perRow = std::max(1, static_cast<int>((avail + spacing) / (cardW + spacing)));
    int i = 0;
    for (const ThemePreset& p : Theme::presets()) {
        if (i % perRow != 0) ImGui::SameLine();
        ++i;
        ImGui::PushID(p.id.c_str());
        const ImVec2 pos = ImGui::GetCursorScreenPos();
        const bool selected = Theme::currentId() == p.id;
        if (ImGui::InvisibleButton("##card", ImVec2(cardW, cardH))) Theme::setPreset(p.id);
        const bool hovered = ImGui::IsItemHovered();
        // The card previews the theme with its own colours, whatever is active.
        const auto pc = [&](Col c) { return ImGui::ColorConvertFloat4ToU32(p.colors[static_cast<size_t>(c)]); };
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 end(pos.x + cardW, pos.y + cardH);
        const float r = ui::em(0.3f);
        dl->AddRectFilled(pos, end, pc(Col::EditorBackground), r);
        const float side = cardW * 0.28f;
        dl->AddRectFilled(pos, ImVec2(pos.x + side, end.y), pc(Col::Background), r, ImDrawFlags_RoundCornersLeft);
        // A few "code" lines in the theme's syntax colours.
        const float lineH = ui::em(0.32f), gap = ui::em(0.42f);
        const Col lines[][3] = {{Col::SynKeyword, Col::SynType, Col::SynDefault},
                                {Col::SynComment, Col::SynComment, Col::SynComment},
                                {Col::SynDefault, Col::SynString, Col::SynPunctuation},
                                {Col::SynKeyword, Col::SynNumber, Col::SynDefault}};
        const float codeX = pos.x + side + ui::em(0.5f);
        for (int l = 0; l < 4; ++l) {
            float x = codeX + (l == 2 || l == 3 ? ui::em(0.6f) : 0.f);
            const float y = pos.y + ui::em(0.45f) + static_cast<float>(l) * gap;
            const float widths[3] = {ui::em(1.2f), ui::em(1.6f), ui::em(0.9f)};
            for (int w = 0; w < 3 && x < end.x - ui::em(0.5f); ++w) {
                const float x2 = std::min(x + widths[w], end.x - ui::em(0.5f));
                dl->AddRectFilled(ImVec2(x, y), ImVec2(x2, y + lineH), pc(lines[l][w]), lineH * 0.5f);
                x = x2 + ui::em(0.25f);
            }
        }
        // Accent bar + name.
        const float nameY = end.y - ImGui::GetFontSize() - ui::em(0.35f);
        dl->AddRectFilled(ImVec2(pos.x + ui::em(0.4f), pos.y + ui::em(0.45f)), ImVec2(pos.x + side - ui::em(0.4f), pos.y + ui::em(0.75f)),
                          pc(Col::Accent), ui::em(0.15f));
        dl->AddText(ImVec2(codeX, nameY), pc(Col::Text), p.name.c_str());
        // Selection / hover outline in the active theme's accent.
        if (selected) dl->AddRect(pos, end, theme::u32(Col::Accent), r, 0, 2.f);
        else dl->AddRect(pos, end, hovered ? theme::u32(Col::TextMuted) : theme::u32(Col::Border), r);
        if (hovered) ImGui::SetTooltip("%s%s", p.name.c_str(), p.dark ? " (dark)" : " (light)");
        ImGui::PopID();
    }
}

void SettingsDialog::drawColorEditor() {
    hint("Changes apply on top of the selected theme and stay when you switch themes.");
    ImGui::SetNextItemWidth(ui::em(14.f));
    ImGui::InputTextWithHint("##colorFilter", ui::icon(icons::FILTER, "Filter colors").c_str(), colorFilter_, sizeof colorFilter_);
    const size_t modified = Theme::overrideCount();
    ImGui::SameLine();
    if (modified == 0) ImGui::BeginDisabled();
    const std::string resetAll = "Reset " + std::to_string(modified) + (modified == 1 ? " change" : " changes");
    if (ImGui::Button(modified ? resetAll.c_str() : "No changes")) Theme::clearOverrides();
    if (modified == 0) ImGui::EndDisabled();

    const std::string_view filter = colorFilter_;
    const char* openGroup = nullptr;
    bool groupOpen = false;
    for (size_t i = 0; i < kColCount; ++i) {
        const Col c = static_cast<Col>(i);
        const char* group = Theme::group(c);
        const bool match = filter.empty() || tex::ciFind(Theme::label(c), filter) != std::string_view::npos ||
                           tex::ciFind(group, filter) != std::string_view::npos;
        if (!match) continue;
        if (!openGroup || std::string_view(openGroup) != group) {
            if (openGroup && groupOpen) ImGui::TreePop();
            openGroup = group;
            ImGui::SetNextItemOpen(!filter.empty() || std::string_view(group) == "Interface", filter.empty() ? ImGuiCond_Appearing : ImGuiCond_Always);
            groupOpen = ImGui::TreeNodeEx(group, ImGuiTreeNodeFlags_SpanAvailWidth);
        }
        if (!groupOpen) continue;
        ImGui::PushID(static_cast<int>(i));
        ImVec4 value = theme::vec(c);
        const bool overridden = Theme::hasOverride(c);
        if (ImGui::ColorEdit4("##color", &value.x,
                              ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreviewHalf))
            Theme::setOverride(c, value);
        ImGui::SameLine();
        ImGui::TextUnformatted(Theme::label(c));
        ImGui::SameLine(std::max(ImGui::GetCursorPosX(), ui::em(16.f)));
        ImGui::TextDisabled("%s", Theme::toHex(value).c_str());
        if (overridden) {
            ImGui::SameLine();
            if (ui::smallButton("Reset")) Theme::clearOverride(c);
            ImGui::SameLine();
            ImGui::TextColored(theme::vec(Col::Accent), "changed");
        }
        ImGui::PopID();
    }
    if (openGroup && groupOpen) ImGui::TreePop();
    if (!openGroup) hint("No color matches the filter.");
}

// ---- Editor -----------------------------------------------------------------

void SettingsDialog::drawEditorPage() {
    section("Display");
    ImGui::Checkbox("Show line numbers", &lineNumbers_);
    section("Behaviour");
    hint("Single-click a file in the explorer to preview it in a temporary tab; double-click to keep it open. "
         "Files open read-only - use the Edit toggle above a document to change it. Modified files are marked "
         "with * and ApkSpy asks before closing them.");
}

// ---- Decompiler ---------------------------------------------------------------

void SettingsDialog::drawDecompilerPage() {
    section("jadx");
    if (pathInput("jadx executable", "##jadxpath", jadxPath_, sizeof jadxPath_, "jadx", true))
        jadxBrowser_.open(FileBrowser::Mode::SelectExecutable);
    hint("On Windows select jadx.bat, on Linux / macOS the jadx shell script.");
    pathInput("Extra command line arguments", "##jadxargs", jadxArgs_, sizeof jadxArgs_, "e.g. --deobf", false);

    ImGui::Spacing();
    // Disabled while a test runs (starting another would join the live thread
    // on the UI thread and freeze the dialog).
    const bool testing = workspace_.jadx().testRunning();
    if (testing) ImGui::BeginDisabled();
    if (ImGui::Button("Test installation")) workspace_.jadx().testInstall(jadxPath_);
    if (testing) {
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("testing...");
    } else {
        bool ok = false;
        const std::string result = workspace_.jadx().takeTestResult(ok);
        if (!result.empty()) resultText(ok, ok ? "OK - " + result : result);
    }
}

// ---- Android ------------------------------------------------------------------

void SettingsDialog::drawAndroidPage() {
    section("adb");
    if (pathInput("adb executable", "##adbpath", adbPath_, sizeof adbPath_, "adb", true))
        adbBrowser_.open(FileBrowser::Mode::SelectExecutable);
    hint("From the Android SDK platform-tools. Leave \"adb\" to use the one on PATH.");
    ImGui::Spacing();
    const bool testing = adbTest_.valid();
    if (testing) ImGui::BeginDisabled();
    if (ImGui::Button("Test adb")) {
        const std::string path = adbPath_;
        adbTest_ = std::async(std::launch::async, [path] {
            adb::Adb probe(path.empty() ? "adb" : path);
            std::string error;
            const std::string version = probe.version(error);
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
    if (!adbTestResult_.empty()) resultText(adbTestResult_.rfind("OK", 0) == 0, adbTestResult_);

    section("Debugging");
    hint("Debugging needs a debuggable app (android:debuggable=\"true\", or any app on a userdebug / eng build or "
         "emulator image). Only one debugger can attach to a process at a time - close Android Studio's first.");
}

// ---- Network ----------------------------------------------------------------

void SettingsDialog::drawNetworkPage() {
    section("Capture proxy");
    ImGui::TextUnformatted("Port");
    ImGui::SetNextItemWidth(ui::em(7.f));
    ImGui::InputInt("##trafficport", &trafficPort_, 0, 0);
    trafficPort_ = std::clamp(trafficPort_, 1024, 65535);
    hint("The local port the capture proxy listens on. The Traffic panel routes the device to it over adb.");
}

// ---- Terminal & Scripts -------------------------------------------------------------

void SettingsDialog::drawTerminalPage() {
    section("Terminal");
    pathInput("Shell", "##shell", terminalShell_, sizeof terminalShell_, "default shell", false);
    hint("Empty: PowerShell on Windows, your login shell elsewhere. cmd.exe, bash or a full path work too. "
         "Open the terminal with Ctrl+`.");
    section("Scripts");
    pathInput("Python executable", "##pythonpath", pythonPath_, sizeof pythonPath_, "python", false);
    hint("Scripts run with your installed Python. Leave \"python\" to use the one on PATH.");
}

// ---- AI -----------------------------------------------------------------------

void SettingsDialog::drawAiPage() {
    hint("The server controls on this page take effect immediately; OK / Cancel do not change them.");
    ImGui::Spacing();
    if (mcp_) mcp_->draw();
}
