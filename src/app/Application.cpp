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
#include "ui/EditorPanel.hpp"
#include "ui/ExplorerPanel.hpp"
#include "ui/OutputPanel.hpp"
#include "ui/OverviewPanel.hpp"
#include "ui/SearchPanel.hpp"
#include "ui/ShellIcons.hpp"
#include "app/Theme.hpp"
#include "core/IcoLoader.hpp"
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
        if (doc->isPreview() || !doc->node()) continue;
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

Application::Application()
    : settingsDialog_(workspace_, settings_) {
    initWindow();
    initImGui();
    panels_.push_back(std::make_unique<ExplorerPanel>(workspace_));
    auto editor = std::make_unique<EditorPanel>(workspace_, settings_);
    editor_ = editor.get();
    panels_.push_back(std::move(editor));
    panels_.push_back(std::make_unique<OutputPanel>(workspace_));
    panels_.push_back(std::make_unique<SearchPanel>(workspace_));
    panels_.push_back(std::make_unique<OverviewPanel>(workspace_));
    loadSettings();
    initTitleBar();
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
    Theme::loadFonts(io, contentScale_);
    Theme::apply();
    Theme::scaleStyle(contentScale_);
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 130");
}

void Application::loadSettings() {
    migrateLegacyConfig("apkspy.settings");
    settings_.load(pathutil::configFile("apkspy.settings"));
    workspace_.setJadxPath(settings_.getString(Settings::kJadxPath, "jadx"));
    workspace_.setJadxArgs(settings_.getString(Settings::kJadxArgs, ""));
    for (auto& panel : panels_)
        *panel->visiblePtr() = settings_.getBool(Settings::panelKey(panel->title()), true);
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
    for (auto& panel : panels_) settings_.set(Settings::panelKey(panel->title()), *panel->visiblePtr());
    settings_.set(Settings::kJadxPath, workspace_.jadxPath());
    settings_.set(Settings::kJadxArgs, workspace_.jadxArgs());
    settings_.set(Settings::kLastProject, project_.isOpen() ? project_.path() : "");
    int n = std::min<size_t>(recents_.size(), 10);
    settings_.set(Settings::kRecentCount, n);
    for (int i = 0; i < n; ++i) settings_.set(Settings::recentKey(i), recents_[(size_t)i]);
    settings_.save(pathutil::configFile("apkspy.settings"));
}

void Application::shutdown() {
    if (!window_) return;
    saveSettings();
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
        const bool busy = workspace_.jadx().state() == JadxRunner::State::Running ||
                          workspace_.search().running() || ImGui::GetIO().WantTextInput;
        if (busy) glfwPollEvents();
        else glfwWaitEventsTimeout(0.10);
        if (glfwGetWindowAttrib(window_, GLFW_ICONIFIED)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        frame();
    }
    return 0;
}

void Application::frame() {
    if (inFrame_) return;
    inFrame_ = true;

    // DPI change: rebuild the font atlas and rescale the style before
    // anything renders with them.
    if (pendingContentScale_ > 0.f) {
        if (std::fabs(pendingContentScale_ - contentScale_) > 0.01f) {
            contentScale_ = pendingContentScale_;
            ImGuiIO& io = ImGui::GetIO();
            io.Fonts->Clear();
            Theme::loadFonts(io, contentScale_);
            Theme::scaleStyle(contentScale_);
            ImGui_ImplOpenGL3_DestroyFontsTexture();
            ImGui_ImplOpenGL3_CreateFontsTexture();
        }
        pendingContentScale_ = 0.f;
    }

    workspace_.update();
    ImGui_ImplOpenGL3_NewFrame();
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

    updateTitle();
    if (titleBar_) titleBar_->render();
    else drawMenuBar();
    drawDockHost();
    for (auto& panel : panels_) panel->render();

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
        project_.reset();
        workspace_.log("New project created");
        break;
    case PendingAction::OpenProject:
        if (path.empty()) projOpenBrowser_.open(FileBrowser::Mode::OpenProject);
        else openProject(path);
        break;
    case PendingAction::CloseProject:
        workspace_.closeAll();
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
    if (!project_.save(project_.path())) {
        workspace_.log("Could not save the project - see the Output panel");
        return false;
    }
    addRecent(project_.path());
    saveSettings();
    workspace_.log("Project saved: " + project_.path());
    return true;
}

bool Application::saveProjectAs(const std::string& path) {
    project_.setApks(collectApks(workspace_, project_));
    project_.setTabs(collectTabs(workspace_));
    if (!project_.save(path)) {
        workspace_.log("Could not save the project - see the Output panel");
        return false;
    }
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
    std::vector<PendingTab> pending;
    for (const Project::Tab& tab : project_.tabs()) {
        PendingTab p;
        p.rootKind = tab.rootKind;
        p.group = tab.group;
        p.path = tab.path;
        pending.push_back(std::move(p));
    }
    workspace_.setPendingTabs(std::move(pending));
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
    for (auto& panel : panels_) ImGui::MenuItem(panel->title().c_str(), nullptr, panel->visiblePtr());
    ImGui::Separator();
    // Document commands live in the shared function so both menu bars (the
    // ImGui main menu bar and the custom title bar) offer them.
    const Document* active = workspace_.activeDocument();
    const bool codeActive = active && active->mode() == Document::Mode::Code;
    if (ImGui::MenuItem("Navigate Back", "Alt+Left", false, workspace_.canNavBack())) workspace_.navBack();
    if (ImGui::MenuItem("Navigate Forward", "Alt+Right", false, workspace_.canNavForward())) workspace_.navForward();
    if (ImGui::MenuItem("Find...", "Ctrl+F", false, codeActive)) editor_->requestFind();
    if (ImGui::MenuItem("Go to Line...", "Ctrl+G", false, codeActive)) editor_->requestGoToLine();
    ImGui::Separator();
    if (ImGui::MenuItem("Reset Layout")) resetLayout_ = true;
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
    ImGui::EndMainMenuBar();
}

void Application::updateTitle() {
    // The dirty check walks the documents and roots; run it only when the
    // workspace, the project or a document actually changed.
    const uint64_t version = workspace_.stateVersion() + Document::editSerial();
    if (version != dirtyCheckVersion_ || project_.epoch() != dirtyCheckEpoch_) {
        dirtyCheckVersion_ = version;
        dirtyCheckEpoch_ = project_.epoch();
        dirtyCheckResult_ = projectHasUnsavedChanges();
    }
    std::string title = "ApkSpy";
    if (project_.isOpen()) {
        title = project_.name();
        if (dirtyCheckResult_) title += " *";
        title += " - ApkSpy";
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
    if (resetLayout_) {
        // Clearing the ini settings removes the dock tree, so the default
        // layout is rebuilt on the next line.
        ImGui::LoadIniSettingsFromMemory("");
        resetLayout_ = false;
    }
    ImGui::SetNextWindowPos(hostPos);
    ImGui::SetNextWindowSize(hostSize);
    ImGui::SetNextWindowViewport(vp->ID);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::Begin("##dockhost", nullptr, flags);
    ImGui::PopStyleVar(3);
    ImGuiID dockId = ImGui::GetID("MainDock");
    if (!ImGui::DockBuilderGetNode(dockId)) buildDefaultLayout(dockId, hostSize);
    ImGui::DockSpace(dockId, ImVec2(0.f, 0.f));
    drawProjectConfirm();  // popup needs a window context
    ImGui::End();
}

void Application::buildDefaultLayout(unsigned int dockId, ImVec2 size) {
    ImGui::DockBuilderRemoveNode(dockId);
    ImGui::DockBuilderAddNode(dockId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockId, size);
    ImGuiID rest = 0;
    ImGuiID left = ImGui::DockBuilderSplitNode(dockId, ImGuiDir_Left, 0.25f, nullptr, &rest);
    ImGuiID center = 0;
    ImGuiID bottom = ImGui::DockBuilderSplitNode(rest, ImGuiDir_Down, 0.28f, nullptr, &center);
    ImGui::DockBuilderDockWindow("Explorer", left);
    ImGui::DockBuilderDockWindow("Overview", left);
    ImGui::DockBuilderDockWindow("Editor", center);
    ImGui::DockBuilderDockWindow("Output", bottom);
    ImGui::DockBuilderDockWindow("Search", bottom);
    ImGui::DockBuilderFinish(dockId);
}
