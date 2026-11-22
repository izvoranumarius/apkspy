#include "ui/SettingsDialog.hpp"
#include <cctype>
#include "app/ShortcutKeys.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include "app/Icons.hpp"
#include "core/TextUtils.hpp"
#include "ui/McpSettings.hpp"
#include "ui/TrafficCommon.hpp"
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
    {Page::Keyboard, icons::LIST, "Keyboard", "Global shortcuts."},
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
    followSystemTheme_ = settings_.getBool(Settings::kFollowSystemTheme, false);
    std::snprintf(adbPath_, sizeof adbPath_, "%s", devices_.adbPath().c_str());
    std::snprintf(pythonPath_, sizeof pythonPath_, "%s", settings_.getString(Settings::kPythonPath, "python").c_str());
    std::snprintf(terminalShell_, sizeof terminalShell_, "%s", settings_.getString(Settings::kTerminalShell, "").c_str());
    trafficPort_ = settings_.getInt(Settings::kTrafficPort, 8899);
    interceptHttps_ = settings_.getBool(Settings::kTrafficInterceptHttps, true);
    verifyUpstream_ = settings_.getBool(Settings::kTrafficVerifyUpstream, true);
    proxyMode_ = settings_.getString(Settings::kTrafficMode, "regular") == "reverse" ? 1 : 0;
    std::snprintf(reverseTarget_, sizeof reverseTarget_, "%s", settings_.getString(Settings::kTrafficReverseTarget, "").c_str());
    std::snprintf(upstreamProxy_, sizeof upstreamProxy_, "%s", settings_.getString(Settings::kTrafficUpstream, "").c_str());
    std::snprintf(upstreamAuth_, sizeof upstreamAuth_, "%s", settings_.getString(Settings::kTrafficUpstreamAuth, "").c_str());
    modeStatus_.clear();
    maxFlows_ = settings_.getInt(Settings::kTrafficMaxFlows, 5000);
    maxBodyKb_ = settings_.getInt(Settings::kTrafficMaxBodyKb, 2048);
    caStatus_.clear();
    adbTestResult_.clear();
    themeAtOpen_ = Theme::state();
    if (shortcuts_) shortcutsAtOpen_ = *shortcuts_;
    capturing_.clear();
    shortcutNote_.clear();
    zoomAtOpen_ = getZoom_ ? getZoom_() : 1.f;
    colorFilter_[0] = '\0';
}

void SettingsDialog::revertPreview() {
    Theme::restore(themeAtOpen_);
    if (shortcuts_) *shortcuts_ = shortcutsAtOpen_;
    capturing_.clear();
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
    settings_.set(Settings::kFollowSystemTheme, followSystemTheme_);
    devices_.setAdbPath(adbPath_);
    settings_.set(Settings::kAdbPath, adbPath_);
    settings_.set(Settings::kPythonPath, std::string(pythonPath_));
    settings_.set(Settings::kTerminalShell, std::string(terminalShell_));
    settings_.set(Settings::kTrafficPort, trafficPort_);
    settings_.set(Settings::kTrafficInterceptHttps, interceptHttps_);
    settings_.set(Settings::kTrafficVerifyUpstream, verifyUpstream_);
    settings_.set(Settings::kTrafficMode, proxyMode_ == 1 ? "reverse" : "regular");
    settings_.set(Settings::kTrafficReverseTarget, std::string(reverseTarget_));
    settings_.set(Settings::kTrafficUpstream, std::string(upstreamProxy_));
    settings_.set(Settings::kTrafficUpstreamAuth, std::string(upstreamAuth_));
    settings_.set(Settings::kTrafficMaxFlows, maxFlows_);
    settings_.set(Settings::kTrafficMaxBodyKb, maxBodyKb_);
    devices_.traffic().setLimits(static_cast<size_t>(maxFlows_), static_cast<size_t>(maxBodyKb_) * 1024);
    {
        // New connections use the new mode at once (a running capture included).
        TrafficProxy::Mode mode;
        std::string error;
        modeStatus_ = trafficui::modeFromSettings(settings_, mode, error) ? std::string() : error;
        if (modeStatus_.empty()) devices_.traffic().setMode(mode);
    }
    {
        std::string error;
        if (!devices_.setTlsInterception(interceptHttps_, error)) caStatus_ = error;
        devices_.setUpstreamVerification(verifyUpstream_);
    }
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
    case Page::Keyboard: drawKeyboardPage(); break;
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
    ImGui::Checkbox("Follow the system light / dark setting", &followSystemTheme_);
    hint("Switches between Dark Modern and Light when the operating system does (Windows). Picking a theme below turns this off.");
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
        if (ImGui::InvisibleButton("##card", ImVec2(cardW, cardH))) {
            Theme::setPreset(p.id);
            followSystemTheme_ = false;  // an explicit choice wins
        }
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

    section("Capture limits");
    ImGui::SetNextItemWidth(ui::em(8.f));
    ImGui::InputInt("requests kept", &maxFlows_, 1000, 10000);
    maxFlows_ = std::clamp(maxFlows_, 100, 1000000);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(8.f));
    ImGui::InputInt("KB per body", &maxBodyKb_, 512, 4096);
    maxBodyKb_ = std::clamp(maxBodyKb_, 1, 1024 * 1024);
    hint("The oldest requests are dropped past the first number; bodies are kept up to the second (the traffic itself "
         "always passes whole). Large values use a lot of memory.");

    section("Proxy mode");
    ImGui::RadioButton("Regular", &proxyMode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Reverse", &proxyMode_, 1);
    if (proxyMode_ == 0) {
        hint("An HTTP proxy (plain requests and CONNECT tunnels); SOCKS5 clients are recognised on the same port. "
             "Start capture sets it as the device's global proxy.");
    } else {
        ImGui::SetNextItemWidth(-1.f);
        ImGui::InputTextWithHint("##reverse", "https://api.example.com", reverseTarget_, sizeof reverseTarget_);
        hint("Every request is sent to this server, whatever the app asked for (its Host header is rewritten). Point "
             "the app at http://localhost:<port> - Start capture only adds the adb reverse mapping and leaves the "
             "device's proxy setting alone. An https:// target is reached over TLS, verified like any upstream.");
    }

    section("Upstream proxy");
    ImGui::SetNextItemWidth(ui::em(16.f));
    ImGui::InputTextWithHint("##upstream", "host:port (empty = direct)", upstreamProxy_, sizeof upstreamProxy_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint("##upauth", "user:password (optional)", upstreamAuth_, sizeof upstreamAuth_,
                             ImGuiInputTextFlags_Password);
    hint("Chain every outgoing connection through another HTTP proxy (a corporate proxy, Burp, mitmproxy...): "
         "tunnels and HTTPS go through CONNECT, plain HTTP is forwarded in absolute form. Credentials are sent as "
         "Proxy-Authorization: Basic and stored in the settings file.");
    if (!modeStatus_.empty()) ImGui::TextColored(trafficui::kWarn, "%s", modeStatus_.c_str());

    section("HTTPS interception");
    ImGui::Checkbox("Decrypt HTTPS (CONNECT) with ApkSpy's certificate authority", &interceptHttps_);
    hint("On: the proxy terminates the app's TLS with a per-host certificate signed by ApkSpy's CA and shows the "
         "decrypted requests like any other. Off: HTTPS connections are relayed as blind tunnels. The apps must "
         "trust the CA - see the Traffic panel's 'HTTPS & certificates' to install it on a device.");
    ImGui::Checkbox("Verify upstream servers' certificates", &verifyUpstream_);
    hint("The proxy checks every origin server's certificate against the bundled Mozilla root store (assets/"
         "cacert.pem). Turn it off only for test setups; each unverified connection is marked in the flow.");
    ImGui::Spacing();

    // The certificate authority itself. These actions apply immediately (like
    // the AI page's controls); OK / Cancel do not roll them back.
    section("ApkSpy certificate authority");
    ca::Store* ca = devices_.ca();
    if (!ca || !ca->ready()) {
        ImGui::TextWrapped("No CA loaded: HTTPS interception is off. Tick the box above and apply to generate one "
                           "(first use creates it in the ApkSpy config directory).");
    } else {
        const long long left = ca->ca()->secondsUntilExpiry();
        char buf[256];
        std::snprintf(buf, sizeof buf, "%s\nSHA-256 %s\nvalid %s to %s (%.1f years left)", ca->ca()->subject().c_str(),
                      ca->ca()->sha256Fingerprint().c_str(), ca->ca()->notBefore().c_str(), ca->ca()->notAfter().c_str(),
                      left / (365.0 * 24 * 3600));
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextUnformatted(buf);
        ImGui::PopTextWrapPos();
        if (left <= 0) hint("The CA has expired - regenerate it and install the new certificate on the device.");
        if (ImGui::Button("Export PEM")) caExport_.open(FileBrowser::Mode::SaveFile), caExport_.setDefaultName("apkspy-ca.pem");
        ImGui::SameLine();
        if (ImGui::Button("Export CER (DER)"))
            caExport_.open(FileBrowser::Mode::SaveFile), caExport_.setDefaultName("apkspy-ca.cer");
        ImGui::SameLine();
        if (ImGui::Button("Regenerate...")) ImGui::OpenPopup("##caregen");
        if (ImGui::BeginPopup("##caregen")) {
            ImGui::TextWrapped("A new CA replaces the current one everywhere at once. Devices that trusted the old "
                               "certificate must get the new one before HTTPS can be captured there again. The old "
                               "CA's private key is overwritten.");
            if (ui::smallButton("Regenerate now")) {
                std::string error;
                caStatus_ = devices_.regenerateCa(error) ? "A new CA was generated." : ("Regeneration failed: " + error);
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ui::smallButton("Cancel")) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
        hint("The private key stays in the ApkSpy config directory (apkspy-ca.key) and is never part of an export.");
    }
    caExport_.render();
    {
        std::string path;
        if (caExport_.takeAccepted(path)) {
            ca::Store* store = devices_.ca();
            if (store) {
                const bool der = path.size() > 4 && tex::asciiIEqual(path.substr(path.size() - 4), ".cer");
                const std::string bytes = der ? store->caDer() : store->caPem();
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
                caStatus_ = out.good() ? ("Certificate exported to " + path) : ("Could not write " + path);
            }
        }
    }
    if (!caStatus_.empty()) hint(caStatus_.c_str());
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

// ---- Keyboard -----------------------------------------------------------------

void SettingsDialog::drawKeyboardPage() {
    if (!shortcuts_) {
        hint("Shortcuts are not available here.");
        return;
    }
    section("Global shortcuts");
    hint("Click a shortcut, then press the new keys. Esc cancels, Backspace disables it. Editor keys (find, go to line, "
         "bookmarks), the debugger F-keys, zoom and workspace switching (Ctrl+1..5) are fixed.");
    // Key capture: the pressed chord, or Esc / Backspace.
    if (!capturing_.empty()) {
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            capturing_.clear();
            shortcutNote_.clear();
        } else if (shortcuts::Chord c; shortcuts::captureChord(c)) {
            const bool bare = !c.ctrl && !c.shift && !c.alt;
            const bool fkey = c.key.size() >= 2 && c.key[0] == 'F' && std::isdigit(static_cast<unsigned char>(c.key[1]));
            if (bare && c.key == "Backspace") {
                shortcuts_->disable(capturing_);
                shortcutNote_ = "Disabled.";
                capturing_.clear();
            } else if (bare && !fkey) {
                shortcutNote_ = "Use Ctrl, Shift or Alt with that key (a bare key would take over typing).";  // keep capturing
            } else {
                std::string conflict;
                if (shortcuts_->set(capturing_, c, conflict)) {
                    shortcutNote_ = "Set to " + shortcuts::format(c) + ".";
                    capturing_.clear();
                } else if (!conflict.empty()) {
                    std::string other = conflict;
                    for (const auto& act : shortcuts::actions())
                        if (conflict == act.id) other = act.label;
                    shortcutNote_ = shortcuts::format(c) + " is already used by \"" + other + "\". Press another chord.";  // keep capturing
                } else {
                    capturing_.clear();
                }
            }
        }
    }
    if (ImGui::BeginTable("##shortcuts", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthStretch, 3.f);
        ImGui::TableSetupColumn("Shortcut", ImGuiTableColumnFlags_WidthFixed, ui::em(12.f));
        ImGui::TableSetupColumn("##reset", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        for (const auto& a : shortcuts::actions()) {
            ImGui::TableNextRow();
            ImGui::PushID(a.id);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(a.label);
            ImGui::TableNextColumn();
            const bool capturing = capturing_ == a.id;
            std::string label = capturing ? std::string("Press keys...") : shortcuts_->label(a.id);
            if (label.empty()) label = "(none)";
            if (shortcuts_->isCustom(a.id) && !capturing) label += "  *";
            if (ImGui::Button(label.c_str(), ImVec2(ui::em(11.f), 0))) {
                capturing_ = capturing ? std::string() : std::string(a.id);
                shortcutNote_.clear();
            }
            ImGui::TableNextColumn();
            ImGui::BeginDisabled(!shortcuts_->isCustom(a.id));
            if (ui::smallButton("Reset")) shortcuts_->reset(a.id);
            ImGui::EndDisabled();
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (!shortcutNote_.empty()) hint(shortcutNote_.c_str());
    if (ImGui::Button("Reset all shortcuts")) {
        shortcuts_->resetAll();
        capturing_.clear();
        shortcutNote_.clear();
    }
    hint("* marks a shortcut you changed. Changes apply with OK / Apply and are kept in the settings file.");
}

// ---- AI -----------------------------------------------------------------------

void SettingsDialog::drawAiPage() {
    hint("The server controls on this page take effect immediately; OK / Cancel do not change them.");
    ImGui::Spacing();
    if (mcp_) mcp_->draw();
}
