#include "app/Application.hpp"
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <GLFW/glfw3.h>
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "imgui_internal.h"
#include "ui/AnalysisPanel.hpp"
#include "ui/DevicePanels.hpp"
#include "ui/EditorPanel.hpp"
#include "ui/ExplorerPanel.hpp"
#include "ui/McpSettings.hpp"
#include "ui/BookmarksPanel.hpp"
#include "ui/ScriptPanel.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/OutputPanel.hpp"
#include "ui/OverviewPanel.hpp"
#include "ui/SearchPanel.hpp"
#include "ui/ShellIcons.hpp"
#include "app/Theme.hpp"
#include "core/IcoLoader.hpp"
#include "core/LogSeverity.hpp"
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"
#include "image/Texture.hpp"

namespace fs = std::filesystem;

namespace {
// Config files live in the per-user config directory (see Paths.hpp); the
// first start after the move imports the old files from the working
// directory so nothing is lost.
void migrateLegacyConfig(const char* name) {
    const std::string config = pathutil::configFile(name);
    std::error_code ec;
    if (fs::exists(pathutil::fromUtf8(config), ec)) return;
    if (fs::exists(name, ec)) fs::copy_file(name, pathutil::fromUtf8(config), ec);
}

// Snapshot of the open tabs to store in the project file.
std::vector<Project::Tab> collectTabs(const Workspace& workspace) {
    std::vector<Project::Tab> tabs;
    for (const auto& doc : workspace.documents()) {
        if (doc->isPreview() || !doc->node() || doc->rootKind() == RootKind::Virtual) continue;
        tabs.push_back({doc->rootKind(), doc->rootGroup(), doc->node()->path()});
    }
    return tabs;
}

// Snapshot of the APK references to store in the project file: the live
// workspace (so add/remove is reflected), plus entries whose APK file is
// currently missing - those stay in the project so the reference survives
// instead of being silently dropped by the save.
std::vector<ProjectApk> collectApks(const Workspace& workspace, const Project& project) {
    std::vector<ProjectApk> apks;
    for (const Root* root : workspace.apkRoots()) apks.push_back({root->apkPath, root->title});
    std::error_code ec;
    for (const ProjectApk& known : project.apks())
        if (!fs::exists(pathutil::fromUtf8(known.path), ec)) apks.push_back(known);
    return apks;
}
}  // namespace

namespace {
// Version of the default dock layout (see Settings::kLayoutVersion).
constexpr int kLayoutVersion = 10;
}  // namespace

Application::Application()
    : settingsDialog_(workspace_, settings_, devices_) {
    initWindow();
    initImGui();
    mcp_ = std::make_unique<McpHost>(workspace_, &devices_, true,
                                     [this](const std::string& title) { return showPanel(title); });
    // A queued MCP call wakes the event loop instead of waiting for input.
    mcp_->dispatcher().setWake([] { glfwPostEmptyEvent(); });
    panels_.push_back(std::make_unique<ExplorerPanel>(workspace_));
    auto editor = std::make_unique<EditorPanel>(workspace_, settings_);
    editor_ = editor.get();
    panels_.push_back(std::move(editor));
    panels_.push_back(std::make_unique<OutputPanel>(workspace_));
    panels_.push_back(std::make_unique<SearchPanel>(workspace_));
    panels_.push_back(std::make_unique<OverviewPanel>(workspace_));
    auto analysis = std::make_unique<AnalysisPanel>(workspace_);
    analysisPanel_ = analysis.get();
    panels_.push_back(std::move(analysis));
    const auto show = [this](const std::string& title) { showPanel(title); };
    panels_.push_back(std::make_unique<DevicesPanel>(workspace_, devices_, show));
    auto debugger = std::make_unique<DebuggerPanel>(workspace_, devices_);
    debuggerPanel_ = debugger.get();
    panels_.push_back(std::move(debugger));
    panels_.push_back(std::make_unique<LogcatPanel>(workspace_, devices_));
    panels_.push_back(std::make_unique<TrafficPanel>(workspace_, devices_, settings_));
    panels_.push_back(std::make_unique<BookmarksPanel>(workspace_, show));
    mcpSettings_ = std::make_unique<McpSettings>(workspace_, settings_, *mcp_);
    settingsDialog_.setMcp(mcpSettings_.get());
    auto scriptPanel = std::make_unique<ScriptPanel>(workspace_, settings_, *mcp_);
    scriptPanel_ = scriptPanel.get();
    panels_.push_back(std::move(scriptPanel));
    initPerspectives();
    loadSettings();
    initTitleBar();
    mcpSettings_->autoStart();
}

Application::~Application() { shutdown(); }

void Application::initWindow() {
    if (!glfwInit()) throw std::runtime_error("glfwInit failed");
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#ifdef _WIN32
    glfwWindowHint(GLFW_WIN32_KEYBOARD_MENU, GLFW_TRUE);
#endif
    window_ = glfwCreateWindow(1500, 900, "ApkSpy", nullptr, nullptr);
    if (!window_) throw std::runtime_error("window creation failed");
    glfwMakeContextCurrent(window_);
    glfwSwapInterval(1);
    glfwSetWindowUserPointer(window_, this);
    glfwSetDropCallback(window_, &Application::onDrop);
    glfwSetWindowRefreshCallback(window_, &Application::onRefresh);
    // The OS close (X / Alt+F4 / system menu) goes through the same
    // confirmation as File > Exit instead of discarding unsaved work.
    glfwSetWindowCloseCallback(window_, &Application::onCloseRequested);
    glfwSetWindowContentScaleCallback(window_, &Application::onContentScale);
    float sx = 1.f, sy = 1.f;
    glfwGetWindowContentScale(window_, &sx, &sy);
    contentScale_ = std::clamp(std::max(sx, sy), 0.75f, 3.f);
    loadWindowIcon();
}

void Application::loadWindowIcon() {
    const std::string icoPath = pathutil::assetsFile("favicon.ico");
    if (icoPath.empty()) return;  // no asset: keep the platform default icon
    std::vector<uint8_t> bytes;
    {
        std::ifstream in(pathutil::fromUtf8(icoPath), std::ios::binary);
        bytes.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    std::vector<ico::Image> frames;
    std::string err;
    if (bytes.empty() || !ico::decode(bytes, frames, err) || frames.empty()) {
        // The icon is decorative: never let a bad asset break the start-up.
        if (!err.empty()) workspace_.log("favicon.ico could not be used: " + err);
        return;
    }
    // OS window + taskbar icon: GLFW picks the size that fits each surface.
    std::vector<GLFWimage> images;
    images.reserve(frames.size());
    for (const ico::Image& f : frames)
        images.push_back({f.width, f.height, const_cast<unsigned char*>(f.rgba.data())});
    glfwSetWindowIcon(window_, (int)images.size(), images.data());
    // Best frame for the custom title bar (~32 logical px).
    if (const ico::Image* pick = ico::bestFrame(frames, 32))
        appIcon_ = std::make_unique<Texture>(pick->rgba.data(), pick->width, pick->height);
}

void Application::initTitleBar() {
    if (!WindowFrame::isSupported()) return;
    windowFrame_ = std::make_unique<WindowFrame>(window_);
    if (!windowFrame_->active()) {
        windowFrame_.reset();
        return;
    }
    titleBar_ = std::make_unique<TitleBar>(*windowFrame_);
    titleBar_->setCloseHandler([this] { requestAction(PendingAction::Exit); });
    titleBar_->addMenu("File", [this] { drawFileMenu(); });
    titleBar_->addMenu("View", [this] { drawViewMenu(); });
    titleBar_->addMenu("Navigate", [this] { drawNavigateMenu(); });
    if (appIcon_)
        titleBar_->setIcon((ImTextureID)(uintptr_t)appIcon_->id(), (float)appIcon_->width(),
                           (float)appIcon_->height());
}

void Application::initImGui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable | ImGuiConfigFlags_NavEnableKeyboard;
    migrateLegacyConfig("apkspy.ini");
    static const std::string iniPath = pathutil::configFile("apkspy.ini");
    io.IniFilename = iniPath.c_str();  // dock layout persistence between sessions
    {
        // The font choice is needed before the general settings are loaded.
        Settings early;
        early.load(pathutil::configFile("apkspy.settings"));
        fullCjkFonts_ = early.getBool(Settings::kFullCjkFonts, false);
        uiZoom_ = std::clamp(early.getInt(Settings::kUiZoomPercent, 100), 60, 200) / 100.f;
    }
    Theme::loadFonts(io, contentScale_ * uiZoom_, fullCjkFonts_);
    Theme::apply();
    Theme::scaleStyle(contentScale_ * uiZoom_);
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 130");
}

void Application::loadSettings() {
    migrateLegacyConfig("apkspy.settings");
    settings_.load(pathutil::configFile("apkspy.settings"));
    workspace_.setJadxPath(settings_.getString(Settings::kJadxPath, "jadx"));
    workspace_.setJadxArgs(settings_.getString(Settings::kJadxArgs, ""));
    devices_.setAdbPath(settings_.getString(Settings::kAdbPath, "adb"));
    mcpSettings_->loadSettings();  // before restoreSession(), which saves the settings
    // A new layout version resets the docks, so it also resets which panels they hold.
    const bool newLayout = settings_.getInt(Settings::kLayoutVersion, 1) < kLayoutVersion;
    if (!newLayout)
        for (Perspective& p : perspectives_)
            for (auto& [title, shown] : p.visible)
                shown = settings_.getBool(Settings::workspacePanelKey(p.name, title), shown);
    const std::string activeName = settings_.getString(Settings::kActiveWorkspace, "");
    for (size_t i = 0; i < perspectives_.size(); ++i)
        if (perspectives_[i].name == activeName) activePerspective_ = (int)i;
    if (newLayout) {
        resetAllLayouts_ = true;  // new panels: dock them into the default layouts once
        settings_.set(Settings::kLayoutVersion, kLayoutVersion);
    }
    int count = settings_.getInt(Settings::kRecentCount, 0);
    recents_.clear();
    for (int i = 0; i < count; ++i) {
        std::string path = settings_.getString(Settings::recentKey(i));
        if (!path.empty()) recents_.push_back(std::move(path));
    }
    restoreSession();
}

void Application::restoreSession() {
    if (!settings_.getBool(Settings::kRestoreSession, true)) return;
    std::string last = settings_.getString(Settings::kLastProject, "");
    if (last.empty()) return;
    std::error_code ec;
    if (!fs::exists(pathutil::fromUtf8(last), ec)) {
        workspace_.log("Last session: project no longer exists: " + last);
        return;
    }
    if (openProject(last)) workspace_.log("Restored last session: " + last);
}

void Application::saveSettings() {
    for (const Perspective& p : perspectives_)
        for (const auto& [title, shown] : p.visible) settings_.set(Settings::workspacePanelKey(p.name, title), shown);
    settings_.set(Settings::kActiveWorkspace, perspectives_[(size_t)activePerspective_].name);
    settings_.set(Settings::kJadxPath, workspace_.jadxPath());
    settings_.set(Settings::kJadxArgs, workspace_.jadxArgs());
    settings_.set(Settings::kAdbPath, devices_.adbPath());
    settings_.set(Settings::kUiZoomPercent, (int)std::lround(uiZoom_ * 100.f));
    if (mcpSettings_) mcpSettings_->storeSettings();
    settings_.set(Settings::kLastProject, project_.isOpen() ? project_.path() : "");
    int n = std::min<size_t>(recents_.size(), 10);
    settings_.set(Settings::kRecentCount, n);
    for (int i = 0; i < n; ++i) settings_.set(Settings::recentKey(i), recents_[(size_t)i]);
    settings_.save(pathutil::configFile("apkspy.settings"));
}

void Application::shutdown() {
    if (!window_) return;
    saveSettings();
    // MCP first: no tool call may run against a workspace being torn down.
    if (mcp_) mcp_->shutdown();
    // A device routed through the sniffer must get its proxy setting back.
    devices_.stopTraffic();
    // Stop a running jadx immediately instead of letting an invisible
    // process hold the exit hostage.
    workspace_.cancelDecompile();
    workspace_.closeAll();
    panels_.clear();
    titleBar_.reset();
    windowFrame_.reset();
    // Icon textures must be released while the GL context is still alive.
    ShellIcons::shutdown();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window_);
    glfwTerminate();
    window_ = nullptr;
}

void Application::onRefresh(GLFWwindow* window) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (app && app->window_) app->frame();
}

void Application::onCloseRequested(GLFWwindow* window) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (!app) return;
    // Cancel the OS close and take the File > Exit path instead: unsaved
    // edits get their confirmation, a clean project closes immediately.
    glfwSetWindowShouldClose(window, GLFW_FALSE);
    app->requestAction(PendingAction::Exit);
}

void Application::onContentScale(GLFWwindow* window, float x, float y) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (!app) return;
    app->pendingContentScale_ = std::clamp(std::max(x, y), 0.75f, 3.f);
}

void Application::onDrop(GLFWwindow* window, int count, const char** paths) {
    if (count <= 0) return;
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    // Dropping APKs always lands in a project: an implicit "Untitled
    // Project" is created when none is open.
    if (!app->project_.isOpen()) app->project_.reset();
    std::vector<std::string> apks;
    for (int i = 0; i < count; ++i) {
        std::string ext = tex::asciiLower(fs::path(paths[i]).extension().string());
        if (ext == ".apk") apks.push_back(paths[i]);
    }
    if (!apks.empty()) {
        app->addApkPaths(apks);
        app->saveSettings();
    }
}

int Application::run() {
    while (!glfwWindowShouldClose(window_)) {
        // Render continuously while something is in flight (jadx streaming
        // results, a running search); otherwise wait for input, waking up
        // ~10 times per second so the caret keeps blinking. Expose events
        // (onRefresh) trigger frames on their own.
        const bool busy = settleFrames_ > 0 || pendingZoom_ > 0.f || ImGui::IsAnyMouseDown() ||
                          workspace_.jadx().state() == JadxRunner::State::Running ||
                          workspace_.search().running() || ImGui::GetIO().WantTextInput ||
                          mcp_->dispatcher().hasPending() || devices_.logcatRunning() ||
                          devices_.monitoring();
        if (busy) glfwPollEvents();
        else glfwWaitEventsTimeout(0.10);
        // ImGui answers input over a few frames (a tab selected by a click only
        // shows its contents on the next one). No event wakes those frames, so
        // without this each of them waits out the timeout above.
        constexpr int kSettleFrames = 8;
        if (!ImGui::GetCurrentContext()->InputEventsQueue.empty() || mcp_->dispatcher().hasPending())
            settleFrames_ = kSettleFrames;
        else if (settleFrames_ > 0)
            --settleFrames_;
        if (glfwGetWindowAttrib(window_, GLFW_ICONIFIED)) {
            // Minimised: no rendering, but MCP clients and background work
            // keep being served.
            mcp_->pump();
            scriptPanel_->pollOutput();
            workspace_.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        frame();
    }
    return 0;
}

void Application::rebuildFonts() {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    Theme::loadFonts(io, contentScale_ * uiZoom_, fullCjkFonts_);
    Theme::scaleStyle(contentScale_ * uiZoom_);
    ImGui_ImplOpenGL3_DestroyFontsTexture();
    ImGui_ImplOpenGL3_CreateFontsTexture();
    fontBuildDataPending_ = true;
}

void Application::setZoom(float zoom) {
    // Snap to 10% steps so repeated zooming returns to round sizes.
    pendingZoom_ = std::clamp(std::round(zoom * 10.f) / 10.f, 0.6f, 2.0f);
    zoomRequestedAt_ = glfwGetTime();
}

void Application::frame() {
    if (inFrame_) return;
    inFrame_ = true;

    // DPI or zoom change: rebuild the font atlas and rescale the style
    // before anything renders with them (the atlas is locked mid-frame).
    bool rebuild = false;
    if (pendingContentScale_ > 0.f) {
        if (std::fabs(pendingContentScale_ - contentScale_) > 0.01f) {
            contentScale_ = pendingContentScale_;
            rebuild = true;
        }
        pendingContentScale_ = 0.f;
    }
    // A rebuild takes ~100 ms, so a run of wheel steps becomes one rebuild.
    if (pendingZoom_ > 0.f && glfwGetTime() - zoomRequestedAt_ >= 0.12) {
        if (std::fabs(pendingZoom_ - uiZoom_) > 0.001f) {
            uiZoom_ = pendingZoom_;
            rebuild = true;
        }
        pendingZoom_ = 0.f;
    }
    if (rebuild) rebuildFonts();

    mcp_->pump();  // MCP tool calls run here, on the thread that owns the workspace
    scriptPanel_->pollOutput();
    workspace_.update();
    ImGui_ImplOpenGL3_NewFrame();  // creates the font texture on the first frame
    if (fontBuildDataPending_) {
        // The texture is on the GPU now: drop the atlas' CPU copies.
        fontBuildDataPending_ = false;
        Theme::releaseFontBuildData(ImGui::GetIO());
    }
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) requestAction(PendingAction::OpenProject);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S, false)) saveRequested_ = true;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Comma, false)) settingsRequested_ = true;
    // Back/Forward (M2): Alt+Left / Alt+Right and mouse buttons 4/5. Alt+Arrow
    // is not used by ImGui text input, so no WantTextInput guard is needed -
    // adding one would block the legitimate case of focus in the editor.
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false)) workspace_.navBack();
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false)) workspace_.navForward();
    if (ImGui::IsMouseClicked(3)) workspace_.navBack();
    if (ImGui::IsMouseClicked(4)) workspace_.navForward();
    debuggerPanel_->processShortcuts();  // F7/F8/F9/F12 while a debug session is attached
    if (io.KeyCtrl && !io.KeyAlt && !io.KeyShift)
        for (int i = 0; i < (int)perspectives_.size(); ++i)
            if (ImGui::IsKeyPressed((ImGuiKey)(ImGuiKey_1 + i), false)) pendingPerspective_ = i;
    // Zoom: Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0 and Ctrl+mouse wheel.
    if (io.KeyCtrl && !io.KeyAlt) {
        if (ImGui::IsKeyPressed(ImGuiKey_Equal) || ImGui::IsKeyPressed(ImGuiKey_KeypadAdd)) setZoom(zoomTarget() + 0.1f);
        if (ImGui::IsKeyPressed(ImGuiKey_Minus) || ImGui::IsKeyPressed(ImGuiKey_KeypadSubtract)) setZoom(zoomTarget() - 0.1f);
        if (ImGui::IsKeyPressed(ImGuiKey_0, false) || ImGui::IsKeyPressed(ImGuiKey_Keypad0, false)) setZoom(1.f);
        if (io.MouseWheel != 0.f) setZoom(zoomTarget() + (io.MouseWheel > 0.f ? 0.1f : -0.1f));
    }

    updateTitle();
    if (titleBar_) titleBar_->render();
    else drawMenuBar();
    // A file opened from a workspace without an editor needs one.
    if (workspace_.hasFocusRequest() && pendingPerspective_ < 0 && !perspectives_[(size_t)activePerspective_].shows("Editor"))
        showPanel("Editor");
    drawDockHost();
    Perspective& perspective = perspectives_[(size_t)activePerspective_];
    for (auto& panel : panels_) {
        if (perspective.shows(panel->title())) panel->render(perspective.windowName(panel->title()));
    }
    if (!pendingTabs_.empty() && --pendingTabsDelay_ <= 0) {
        for (const std::string& name : pendingTabs_)
            if (ImGuiWindow* window = ImGui::FindWindowByName(name.c_str()))
                if (window->DockNode && window->DockNode->TabBar) window->DockNode->TabBar->NextSelectedTabId = window->TabId;
        ImGui::SetWindowFocus(pendingTabs_.back().c_str());  // listed last: the workspace's main tool
        pendingTabs_.clear();
    }
    // Waits for a pending switch: the target window does not exist yet.
    if (!pendingFocusPanel_.empty() && pendingPerspective_ < 0) {
        ImGui::SetWindowFocus(perspective.windowName(pendingFocusPanel_).c_str());
        pendingFocusPanel_.clear();
    }
    if (pendingPerspective_ >= 0 || !pendingTabs_.empty()) glfwPostEmptyEvent();  // no waiting for the next wake-up

    // Requested actions ----------------------------------------------------
    if (saveRequested_) {
        saveRequested_ = false;
        saveProject();
    }
    if (addApkRequested_) {
        addApkRequested_ = false;
        apkBrowser_.open(FileBrowser::Mode::OpenApkMulti);
    }

    // Modal file browsers ---------------------------------------------------
    std::string picked;
    if (projOpenBrowser_.render(), projOpenBrowser_.takeAccepted(picked))
        openProject(picked);
    if (projSaveBrowser_.render(), projSaveBrowser_.takeAccepted(picked)) {
        if (saveProjectAs(picked) && pendingAction_ != PendingAction::None) {
            PendingAction action = pendingAction_;
            pendingAction_ = PendingAction::None;
            performAction(action, pendingOpenPath_);
        }
        saveAsPending_ = false;
    }
    // The pending action is cancelled when the Save-As dialog is closed
    // without saving.
    if (saveAsPending_ && !projSaveBrowser_.isOpen()) {
        saveAsPending_ = false;
        pendingAction_ = PendingAction::None;
    }
    std::vector<std::string> apks;
    if (apkBrowser_.render(), apkBrowser_.takeAcceptedMulti(apks)) addApkPaths(apks);

    if (settingsRequested_) {
        settingsRequested_ = false;
        settingsDialog_.open();
    }
    if (settingsDialog_.render()) saveSettings();

    drawWindowBorder();

    ImGui::Render();
    int w = 0, h = 0;
    glfwGetFramebufferSize(window_, &w, &h);
    glViewport(0, 0, w, h);
    glClearColor(0.12f, 0.12f, 0.12f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window_);
    inFrame_ = false;
}

// ---------------------------------------------------------------------------
// Project flows
// ---------------------------------------------------------------------------

bool Application::projectHasUnsavedChanges() const {
    // Edited documents are part of the project (annotations).
    for (const auto& doc : workspace_.documents())
        if (doc->isDirty()) return true;
    if (workspace_.annotations().version() != savedAnnotations_) return true;  // bookmarks and comments
    // The open APK set must match the project. Entries whose file is
    // missing from disk are unresolved: they stay in the project (and in
    // the saved file) and are excluded here, so a missing APK neither
    // flags the project as dirty forever nor gets dropped by a save.
    std::vector<Root*> apks = workspace_.apkRoots();
    size_t resolved = 0;
    std::error_code ec;
    for (const ProjectApk& apk : project_.apks()) {
        if (!fs::exists(pathutil::fromUtf8(apk.path), ec)) continue;
        ++resolved;
        const Root* match = nullptr;
        for (const Root* r : apks)
            if (r->apkPath == apk.path) {
                match = r;
                break;
            }
        if (!match || match->title != apk.group) return true;
    }
    if (apks.size() != resolved) return true;  // added or removed an APK
    // Permanently opened tabs must match the saved session.
    std::vector<Project::Tab> tabs = collectTabs(workspace_);
    const std::vector<Project::Tab>& saved = project_.tabs();
    if (tabs.size() != saved.size()) return true;
    for (size_t i = 0; i < tabs.size(); ++i)
        if (tabs[i].rootKind != saved[i].rootKind || tabs[i].group != saved[i].group ||
            tabs[i].path != saved[i].path)
            return true;
    return false;
}

void Application::requestAction(PendingAction action, const std::string& path) {
    if (!project_.isOpen() || !projectHasUnsavedChanges()) {
        performAction(action, path);
        return;
    }
    pendingAction_ = action;
    pendingOpenPath_ = path;
}

void Application::performAction(PendingAction action, const std::string& path) {
    switch (action) {
    case PendingAction::NewProject:
        workspace_.closeAll();
        savedAnnotations_ = workspace_.annotations().version();
        project_.reset();
        workspace_.log("New project created");
        break;
    case PendingAction::OpenProject:
        if (path.empty()) projOpenBrowser_.open(FileBrowser::Mode::OpenProject);
        else openProject(path);
        break;
    case PendingAction::CloseProject:
        workspace_.closeAll();
        savedAnnotations_ = workspace_.annotations().version();
        project_.close();
        workspace_.log("Project closed");
        break;
    case PendingAction::Exit:
        glfwSetWindowShouldClose(window_, GLFW_TRUE);
        break;
    case PendingAction::None:
        break;
    }
}

void Application::drawProjectConfirm() {
    if (pendingAction_ == PendingAction::None || saveAsPending_) return;
    if (!ImGui::IsPopupOpen("Save project changes?")) ImGui::OpenPopup("Save project changes?");
    if (!ImGui::BeginPopupModal("Save project changes?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("The project has unsaved changes.");
    ImGui::Spacing();
    if (ImGui::Button("Save", ImVec2(120, 0))) {
        ImGui::CloseCurrentPopup();
        if (project_.hasPath()) {
            if (saveProject()) {
                PendingAction action = pendingAction_;
                pendingAction_ = PendingAction::None;
                performAction(action, pendingOpenPath_);
            }
        } else {
            // No location yet: ask for one, then run the pending action.
            projSaveBrowser_.setDefaultName(project_.name());
            projSaveBrowser_.open(FileBrowser::Mode::SaveProject);
            saveAsPending_ = true;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Don't Save", ImVec2(120, 0))) {
        ImGui::CloseCurrentPopup();
        PendingAction action = pendingAction_;
        pendingAction_ = PendingAction::None;
        performAction(action, pendingOpenPath_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0))) {
        ImGui::CloseCurrentPopup();
        pendingAction_ = PendingAction::None;
        pendingOpenPath_.clear();
    }
    ImGui::EndPopup();
}

bool Application::saveProject() {
    if (!project_.isOpen()) return false;
    if (!project_.hasPath()) {
        projSaveBrowser_.setDefaultName(project_.name());
        projSaveBrowser_.open(FileBrowser::Mode::SaveProject);
        saveAsPending_ = true;
        return false;
    }
    // Persist the annotations first: edited decompiled files are written to
    // disk so the project snapshot is consistent.
    for (auto& doc : workspace_.documents())
        if (doc->isDirty() && doc->canEdit() && !doc->save())
            workspace_.log("Could not save " + doc->title());
    project_.setApks(collectApks(workspace_, project_));
    project_.setTabs(collectTabs(workspace_));
    project_.setAnnotations(workspace_.annotations().all());
    if (!project_.save(project_.path())) {
        workspace_.log("Could not save the project - see the Output panel");
        return false;
    }
    savedAnnotations_ = workspace_.annotations().version();
    addRecent(project_.path());
    saveSettings();
    workspace_.log("Project saved: " + project_.path());
    return true;
}

bool Application::saveProjectAs(const std::string& path) {
    project_.setApks(collectApks(workspace_, project_));
    project_.setTabs(collectTabs(workspace_));
    project_.setAnnotations(workspace_.annotations().all());
    if (!project_.save(path)) {
        workspace_.log("Could not save the project - see the Output panel");
        return false;
    }
    savedAnnotations_ = workspace_.annotations().version();
    addRecent(project_.path());
    saveSettings();
    workspace_.log("Project saved: " + project_.path());
    return true;
}

bool Application::openProject(const std::string& path) {
    Project loaded;
    if (!loaded.load(path)) {
        workspace_.log("Not a valid ApkSpy project: " + path);
        return false;
    }
    workspace_.closeAll();
    project_ = std::move(loaded);
    workspace_.annotations().replaceAll(project_.annotations());
    savedAnnotations_ = workspace_.annotations().version();
    // Queued first: addApk opens the tabs of each APK as its trees attach.
    std::vector<PendingTab> pending;
    for (const Project::Tab& tab : project_.tabs()) {
        PendingTab p;
        p.rootKind = tab.rootKind;
        p.group = tab.group;
        p.path = tab.path;
        pending.push_back(std::move(p));
    }
    workspace_.setPendingTabs(std::move(pending));
    // Reopen every APK. The jadx output directory is derived from each APK
    // itself; a jadxOut key inside the project file is never trusted.
    // Missing files are reported and their entries stay in the project.
    for (const ProjectApk& apk : project_.apks()) {
        std::error_code ec;
        if (!fs::exists(pathutil::fromUtf8(apk.path), ec)) {
            workspace_.log("Missing APK file: " + apk.path);
            continue;
        }
        workspace_.addApk(apk.path, apk.group);
    }
    addRecent(path);
    saveSettings();
    return true;
}

void Application::addApkPaths(const std::vector<std::string>& paths) {
    if (!project_.isOpen()) project_.reset();
    for (const std::string& path : paths) {
        std::string group = project_.uniqueGroupName(
            pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).stem()));
        if (!workspace_.addApk(path, group)) continue;
        project_.addApk(pathutil::normalize(path), group);
    }
}

void Application::addRecent(const std::string& path) {
    for (auto it = recents_.begin(); it != recents_.end(); ++it) {
        if (*it == path) {
            recents_.erase(it);
            break;
        }
    }
    recents_.insert(recents_.begin(), path);
    if (recents_.size() > 10) recents_.resize(10);
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

void Application::drawFileMenu() {
    if (ImGui::MenuItem("New Project")) requestAction(PendingAction::NewProject);
    if (ImGui::MenuItem("Open Project...", "Ctrl+O")) requestAction(PendingAction::OpenProject);
    drawRecentProjects();
    ImGui::Separator();
    if (ImGui::MenuItem("Add APK(s) to Project...", nullptr, false, project_.isOpen())) addApkRequested_ = true;
    ImGui::Separator();
    if (ImGui::MenuItem("Save Project", "Ctrl+S", false, project_.isOpen())) saveRequested_ = true;
    ImGui::Separator();
    if (ImGui::MenuItem("Close Project", nullptr, false, project_.isOpen()))
        requestAction(PendingAction::CloseProject);
    if (ImGui::MenuItem("Exit")) requestAction(PendingAction::Exit);
    ImGui::Separator();
    if (ImGui::MenuItem("Settings...", "Ctrl+,")) settingsRequested_ = true;
}

void Application::drawRecentProjects() {
    if (ImGui::BeginMenu("Recent Projects")) {
        if (recents_.empty()) {
            ImGui::TextDisabled("No recent projects");
        } else {
            for (const std::string& path : recents_) {
                std::error_code ec;
                bool exists = fs::exists(pathutil::fromUtf8(path), ec);
                const std::string label = pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).filename());
                if (ImGui::MenuItem(label.c_str(), nullptr, false, exists))
                    requestAction(PendingAction::OpenProject, path);
                if (exists && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", path.c_str());
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Clear List")) {
                recents_.clear();
                saveSettings();
            }
        }
        ImGui::EndMenu();
    }
}

void Application::drawViewMenu() {
    for (int i = 0; i < (int)perspectives_.size(); ++i) {
        const Perspective& p = perspectives_[(size_t)i];
        const std::string shortcut = "Ctrl+" + std::to_string(i + 1);
        if (ImGui::MenuItem(p.name.c_str(), shortcut.c_str(), i == activePerspective_)) pendingPerspective_ = i;
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", p.description.c_str());
    }
    ImGui::Separator();
    if (ImGui::BeginMenu("Panels in this Workspace")) {
        Perspective& perspective = perspectives_[(size_t)activePerspective_];
        for (auto& panel : panels_) ImGui::MenuItem(panel->title().c_str(), nullptr, &perspective.visible[panel->title()]);
        ImGui::EndMenu();
    }
    if (ImGui::MenuItem("Reset Workspace Layout")) resetLayout_ = true;
    ImGui::Separator();
    if (ImGui::MenuItem("Zoom In", "Ctrl+=")) setZoom(zoomTarget() + 0.1f);
    if (ImGui::MenuItem("Zoom Out", "Ctrl+-")) setZoom(zoomTarget() - 0.1f);
    char zoomLabel[48];
    std::snprintf(zoomLabel, sizeof zoomLabel, "Reset Zoom (%d%%)", (int)std::lround(uiZoom_ * 100.f));
    if (ImGui::MenuItem(zoomLabel, "Ctrl+0")) setZoom(1.f);
}

void Application::drawNavigateMenu() {
    const Document* active = workspace_.activeDocument();
    const bool codeActive = active && active->mode() == Document::Mode::Code;
    if (ImGui::MenuItem("Back", "Alt+Left", false, workspace_.canNavBack())) workspace_.navBack();
    if (ImGui::MenuItem("Forward", "Alt+Right", false, workspace_.canNavForward())) workspace_.navForward();
    ImGui::Separator();
    if (ImGui::MenuItem("Find in File...", "Ctrl+F", false, codeActive)) editor_->requestFind();
    if (ImGui::MenuItem("Find in Project...")) showPanel("Search");
    if (ImGui::MenuItem("Go to Line...", "Ctrl+G", false, codeActive)) editor_->requestGoToLine();
    if (ImGui::MenuItem("Bookmarks")) showPanel("Bookmarks");
}

void Application::drawMenuBar() {
    if (!ImGui::BeginMainMenuBar()) return;
    if (ImGui::BeginMenu("File")) {
        drawFileMenu();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        drawViewMenu();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Navigate")) {
        drawNavigateMenu();
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
}

void Application::updateTitle() {
    // The dirty check walks the documents and roots; run it only when the
    // workspace, the project or a document actually changed.
    const uint64_t version = workspace_.stateVersion() + Document::editSerial() + workspace_.annotations().version();
    if (version != dirtyCheckVersion_ || project_.epoch() != dirtyCheckEpoch_) {
        dirtyCheckVersion_ = version;
        dirtyCheckEpoch_ = project_.epoch();
        dirtyCheckResult_ = projectHasUnsavedChanges();
    }
    const std::string& workspaceName = perspectives_[(size_t)activePerspective_].name;
    std::string title = workspaceName + " - ApkSpy";
    if (project_.isOpen()) {
        title = project_.name();
        if (dirtyCheckResult_) title += " *";
        title += " - " + workspaceName + " - ApkSpy";
    }
    if (titleBar_) titleBar_->setTitle(title);
    if (title != windowTitle_) {
        windowTitle_ = title;
        glfwSetWindowTitle(window_, title.c_str());
    }
}

void Application::drawWindowBorder() {
    if (!titleBar_ || windowFrame_->maximized()) return;
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImVec2 max(vp->Pos.x + vp->Size.x, vp->Pos.y + vp->Size.y);
    ImGui::GetForegroundDrawList()->AddRect(vp->Pos, max, IM_COL32(63, 63, 70, 255));
}

void Application::drawDockHost() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImVec2 hostPos = vp->WorkPos;
    ImVec2 hostSize = vp->WorkSize;
    if (titleBar_) {
        hostPos = ImVec2(vp->Pos.x, vp->Pos.y + titleBar_->height());
        hostSize = ImVec2(vp->Size.x, vp->Size.y - titleBar_->height());
    }
    if (resetAllLayouts_) {
        // Clearing the ini settings removes every dock tree; each default
        // layout is rebuilt when its workspace is first shown.
        ImGui::LoadIniSettingsFromMemory("");
        resetAllLayouts_ = false;
    }
    ImGui::SetNextWindowPos(hostPos);
    ImGui::SetNextWindowSize(hostSize);
    ImGui::SetNextWindowViewport(vp->ID);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground |
                             ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::Begin("##dockhost", nullptr, flags);
    ImGui::PopStyleVar(3);
    if (pendingPerspective_ >= 0) {
        switchPerspective(pendingPerspective_);
        pendingPerspective_ = -1;
    }
    Perspective& active = perspectives_[(size_t)activePerspective_];
    const ImGuiID dockId = ImGui::GetID(active.dockName().c_str());
    if (resetLayout_) {
        std::vector<std::string> titles;
        for (const auto& panel : panels_) titles.push_back(panel->title());
        active.resetVisibility(titles);
        ImGui::DockBuilderRemoveNode(dockId);
        resetLayout_ = false;
    }
    if (!ImGui::DockBuilderGetNode(dockId)) buildLayout(active, dockId, ImGui::GetContentRegionAvail());
    // A panel alone in its dock needs no tab: the workspace already says what it is.
    const float statusHeight = std::round(ImGui::GetFontSize() * 1.45f);
    ImGui::DockSpace(dockId, ImVec2(0.f, -statusHeight), ImGuiDockNodeFlags_AutoHideTabBar);
    drawStatusBar();
    // Hidden workspaces submit no windows: this keeps their dock trees intact.
    for (const Perspective& p : perspectives_) {
        const ImGuiID id = ImGui::GetID(p.dockName().c_str());
        if (id != dockId && ImGui::DockBuilderGetNode(id)) ImGui::DockSpace(id, ImVec2(0.f, 0.f), ImGuiDockNodeFlags_KeepAliveOnly);
    }
    drawProjectConfirm();  // popup needs a window context
    ImGui::End();
}

void Application::initPerspectives() {
    perspectives_ = {
        {"Code", "Browse the APK, read and search the sources", "Editor", {"Explorer", "Overview", "Editor", "Search", "Bookmarks", "Output"}, {}},
        {"Analysis", "Classes, native code, graphs, strings and resources", "Analysis", {"Analysis", "Editor", "Bookmarks"}, {}},
        {"Debug", "Attach to a process: threads, stack, locals and logs", "Debugger", {"Devices", "Debugger", "Editor", "Logcat"}, {}},
        {"Network", "Capture the app's traffic and map its API", "Traffic", {"Traffic", "Logcat"}, {}},
        {"Scripts", "Automate ApkSpy with Python", "Script", {"Script", "Output"}, {}},
    };
    std::vector<std::string> titles;
    for (const auto& panel : panels_) titles.push_back(panel->title());
    for (Perspective& p : perspectives_) p.resetVisibility(titles);
}

bool Application::showPanel(const std::string& title) {
    const bool known = std::any_of(panels_.begin(), panels_.end(), [&](const auto& p) { return p->title() == title; });
    if (!known) return false;
    const int current = pendingPerspective_ >= 0 ? pendingPerspective_ : activePerspective_;
    int target = current;
    if (!perspectives_[(size_t)current].shows(title)) {
        target = -1;
        for (int i = 0; i < (int)perspectives_.size() && target < 0; ++i)
            if (perspectives_[(size_t)i].shows(title)) target = i;
        if (target < 0) {  // closed everywhere: bring it back here
            target = current;
            perspectives_[(size_t)target].visible[title] = true;
        }
    }
    if (target != activePerspective_) pendingPerspective_ = target;
    pendingFocusPanel_ = title;  // ImGui focus calls are only valid inside a frame
    return true;
}

void Application::switchPerspective(int index) {
    if (index == activePerspective_) return;
    activePerspective_ = index;
    // Otherwise ImGui focuses whichever window comes next, which also flips its dock tab.
    if (pendingFocusPanel_.empty()) pendingFocusPanel_ = perspectives_[(size_t)index].mainPanel;
    // Each workspace has its own editor tab bar: keep it on the current file.
    if (perspectives_[(size_t)index].shows("Editor") && !workspace_.hasFocusRequest())
        workspace_.requestFocus(workspace_.activeDocument());
}

// One line under the docks: the latest message (click for the full log) and what
// is running. It stands in for keeping Output open in every workspace.
void Application::drawStatusBar() {
    const float height = std::round(ImGui::GetFontSize() * 1.45f);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetContentRegionAvail().x;
    const float pad = ImGui::GetFontSize() * 0.6f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height), ImGui::GetColorU32(ImGuiCol_MenuBarBg));

    std::string activity;
    const JadxRunner& jadx = workspace_.jadx();
    if (jadx.state() == JadxRunner::State::Running)
        activity = jadx.totalCount() > 0 ? "Decompiling " + std::to_string(jadx.processedCount()) + " / " + std::to_string(jadx.totalCount())
                                         : "Decompiling...";
    for (Root* r : workspace_.apkRoots()) {
        const AnalysisService::Status st = workspace_.analysis().status(r->title);
        if (st.state != AnalysisService::State::Running) continue;
        activity += (activity.empty() ? "" : "   ") + std::string("Analyzing ") + std::to_string(st.done) + " / " + std::to_string(st.total);
    }
    // What used to need a look at another workspace: visible from everywhere.
    const auto addActivity = [&](const char* text) { activity += (activity.empty() ? "" : "   ") + std::string(text); };
    const DebugSession::State debugger = devices_.debugger().state();
    if (debugger == DebugSession::State::Suspended) addActivity("Debugger paused");
    else if (debugger == DebugSession::State::Running) addActivity("Debugger running");
    if (devices_.traffic().running()) addActivity("Capturing traffic");
    if (scriptPanel_->running()) addActivity("Script running");
    if (mcp_->http().running()) addActivity("MCP on");
    const float activityW = ImGui::CalcTextSize(activity.c_str()).x;
    const float textY = origin.y + (height - ImGui::GetTextLineHeight()) * 0.5f;
    if (!activity.empty())
        dl->AddText(ImVec2(origin.x + width - activityW - pad, textY), IM_COL32(120, 180, 240, 255), activity.c_str());

    ImGui::SetCursorScreenPos(origin);
    const float logWidth = std::max(1.f, width - activityW - pad * 3.f);
    const bool clicked = ImGui::InvisibleButton("##status", ImVec2(logWidth, height));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Show or hide the log");
    const auto& lines = workspace_.logLines();
    if (!lines.empty()) {
        const LogSeverity severity = logsev::classify(lines.back());
        const ImU32 color = severity == LogSeverity::Error  ? IM_COL32(240, 120, 120, 255)
                            : severity == LogSeverity::Warn ? IM_COL32(235, 190, 110, 255)
                                                                    : ImGui::GetColorU32(ImGuiCol_TextDisabled);
        dl->PushClipRect(origin, ImVec2(origin.x + logWidth, origin.y + height), true);
        dl->AddText(ImVec2(origin.x + pad, textY), color, lines.back().c_str());
        dl->PopClipRect();
    }
    if (clicked) {
        Perspective& p = perspectives_[(size_t)activePerspective_];
        ImGuiWindow* output = ImGui::FindWindowByName(p.windowName("Output").c_str());
        if (p.shows("Output") && output && GImGui->NavWindow == output) {
            p.visible["Output"] = false;
        } else {
            p.visible["Output"] = true;
            pendingFocusPanel_ = "Output";
        }
    }
}

void Application::buildLayout(const Perspective& p, unsigned int dockId, ImVec2 size) {
    ImGui::DockBuilderRemoveNode(dockId);
    ImGui::DockBuilderAddNode(dockId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockId, size);
    const auto dock = [&](const char* title, ImGuiID node) { ImGui::DockBuilderDockWindow(p.windowName(title).c_str(), node); };
    // The tabs a new layout opens on: applied once their windows exist.
    pendingTabs_.clear();
    pendingTabsDelay_ = 3;
    const auto select = [&](const char* title) { pendingTabs_.push_back(p.windowName(title)); };
    ImGuiID main = 0, side = 0, bottom = 0, rest = 0;
    // The main tool of each workspace takes the central area.
    if (p.name == "Analysis") {
        side = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Right, 0.42f, nullptr, &main);
        bottom = ImGui::DockBuilderSplitNode(side, ImGuiDir_Down, 0.26f, nullptr, &side);
        dock("Analysis", main);
        dock("Editor", side);
        dock("Bookmarks", bottom);
        select("Analysis");
    } else if (p.name == "Debug") {
        side = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Left, 0.17f, nullptr, &rest);
        ImGuiID editor = ImGui::DockBuilderSplitNode(rest, ImGuiDir_Right, 0.30f, nullptr, &rest);
        bottom = ImGui::DockBuilderSplitNode(rest, ImGuiDir_Down, 0.24f, nullptr, &main);
        dock("Devices", side);
        dock("Debugger", main);
        dock("Editor", editor);
        dock("Logcat", bottom);
        select("Debugger");
    } else if (p.name == "Network") {
        bottom = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Down, 0.26f, nullptr, &main);
        dock("Traffic", main);
        dock("Logcat", bottom);
        select("Traffic");
    } else if (p.name == "Scripts") {
        bottom = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Down, 0.34f, nullptr, &main);
        dock("Script", main);
        dock("Output", bottom);
        select("Script");
    } else {
        side = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Left, 0.20f, nullptr, &rest);
        bottom = ImGui::DockBuilderSplitNode(rest, ImGuiDir_Down, 0.25f, nullptr, &main);
        dock("Explorer", side), dock("Overview", side);
        dock("Editor", main);
        dock("Search", bottom), dock("Bookmarks", bottom), dock("Output", bottom);
        select("Output"), select("Explorer"), select("Editor");
    }
    // Panels added later from the View menu start beside the streams.
    for (const auto& panel : panels_)
        if (std::find(p.defaultPanels.begin(), p.defaultPanels.end(), panel->title()) == p.defaultPanels.end())
            dock(panel->title().c_str(), bottom ? bottom : main);
    ImGui::DockBuilderFinish(dockId);
}
