#include "app/Application.hpp"
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <thread>
#include <GLFW/glfw3.h>
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "imgui_internal.h"
#include "ui/EditorPanel.hpp"
#include "ui/ExplorerPanel.hpp"
#include "ui/OutputPanel.hpp"
#include "ui/SearchPanel.hpp"
#include "app/Theme.hpp"

namespace fs = std::filesystem;

static const char* kSettingsFile = "apkspy.settings";

Application::Application()
    : settingsDialog_(workspace_, settings_) {
    initWindow();
    initImGui();
    panels_.push_back(std::make_unique<ExplorerPanel>(workspace_));
    panels_.push_back(std::make_unique<EditorPanel>(workspace_, settings_));
    panels_.push_back(std::make_unique<OutputPanel>(workspace_));
    panels_.push_back(std::make_unique<SearchPanel>(workspace_));
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
}

void Application::initTitleBar() {
    if (!WindowFrame::isSupported()) return;
    windowFrame_ = std::make_unique<WindowFrame>(window_);
    if (!windowFrame_->active()) {
        windowFrame_.reset();
        return;
    }
    titleBar_ = std::make_unique<TitleBar>(*windowFrame_);
    titleBar_->addMenu("File", [this] { drawFileMenu(); });
    titleBar_->addMenu("View", [this] { drawViewMenu(); });
}

void Application::initImGui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable | ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "apkspy.ini";  // dock layout persistence between sessions
    Theme::loadFonts(io);
    Theme::apply();
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init("#version 130");
}

void Application::loadSettings() {
    settings_.load(kSettingsFile);
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
    if (!fs::exists(last, ec)) {
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
    settings_.save(kSettingsFile);
}

void Application::shutdown() {
    if (!window_) return;
    saveSettings();
    workspace_.closeAll();
    panels_.clear();
    titleBar_.reset();
    windowFrame_.reset();
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

void Application::onDrop(GLFWwindow* window, int count, const char** paths) {
    if (count <= 0) return;
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    // Dropping APKs always lands in a project: an implicit "Untitled
    // Project" is created when none is open.
    if (!app->project_.isOpen()) app->project_.reset();
    std::vector<std::string> apks;
    for (int i = 0; i < count; ++i) {
        std::string ext = fs::path(paths[i]).extension().string();
        for (char& c : ext) c = (char)std::tolower((unsigned char)c);
        if (ext == ".apk") apks.push_back(paths[i]);
    }
    if (!apks.empty()) {
        app->addApkPaths(apks);
        app->saveSettings();
    }
}

int Application::run() {
    while (!glfwWindowShouldClose(window_)) {
        glfwPollEvents();
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
    workspace_.update();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) requestAction(PendingAction::OpenProject);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S, false)) saveRequested_ = true;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Comma, false)) settingsRequested_ = true;

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
    if (projOpenBrowser_.render("Open Project"), projOpenBrowser_.takeAccepted(picked))
        openProject(picked);
    if (projSaveBrowser_.render("Save Project As"), projSaveBrowser_.takeAccepted(picked)) {
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
    if (apkBrowser_.render("Add APK Files"), apkBrowser_.takeAcceptedMulti(apks)) addApkPaths(apks);

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
    // The workspace APK set must match the project.
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.size() != project_.apks().size()) return true;
    for (size_t i = 0; i < apks.size(); ++i)
        if (apks[i]->apkPath != project_.apks()[i].path || apks[i]->title != project_.apks()[i].group)
            return true;
    // Permanently opened tabs must match the saved session.
    std::vector<Project::Tab> tabs;
    for (const auto& doc : workspace_.documents()) {
        if (doc->isPreview() || !doc->node()) continue;
        tabs.push_back({doc->rootKind(), doc->rootGroup(), doc->node()->path()});
    }
    const std::vector<Project::Tab>& saved = project_.tabs();
    if (tabs.size() != saved.size()) return true;
    for (size_t i = 0; i < tabs.size(); ++i)
        if (tabs[i].rootKind != saved[i].rootKind || tabs[i].group != saved[i].group ||
            tabs[i].path != saved[i].path)
            return true;
    return false;
}

namespace {
// Snapshot of the APK references to store in the project file: taken from
// the live workspace (so add/remove is reflected), keeping the jadx output
// directories already known for each APK.
std::vector<ProjectApk> collectApks(const Workspace& workspace, Project& project) {
    std::vector<ProjectApk> apks;
    for (const Root* root : workspace.apkRoots()) {
        // Prefer the live jadx output directory (set when the APK was added
        // or decompiled); fall back to what the project already knows.
        std::string jadxOut;
        if (const Root* dec = workspace.rootByGroup(root->title, Root::Kind::Decompiled))
            jadxOut = dec->outDir;
        else if (const ProjectApk* known = project.findApkByPath(root->apkPath))
            jadxOut = known->jadxOut;
        apks.push_back({root->apkPath, root->title, jadxOut});
    }
    return apks;
}

std::vector<Project::Tab> collectTabs(const Workspace& workspace) {
    std::vector<Project::Tab> tabs;
    for (const auto& doc : workspace.documents()) {
        if (doc->isPreview() || !doc->node()) continue;
        tabs.push_back({doc->rootKind(), doc->rootGroup(), doc->node()->path()});
    }
    return tabs;
}
}  // namespace

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
    // Reopen every APK; saved jadx results are reattached from disk when the
    // output directories still exist, otherwise jadx runs again.
    for (const ProjectApk& apk : project_.apks()) {
        std::error_code ec;
        if (!fs::exists(apk.path, ec)) {
            workspace_.log("Missing APK file: " + apk.path);
            continue;
        }
        workspace_.addApk(apk.path, apk.group, apk.jadxOut);
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
        std::string group = project_.uniqueGroupName(fs::path(path).stem().string());
        if (!workspace_.addApk(path, group)) continue;
        project_.addApk(fs::path(path).lexically_normal().string(), group);
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
                bool exists = fs::exists(path, ec);
                const std::string label = fs::path(path).filename().string();
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
    std::string title = "ApkSpy";
    if (project_.isOpen()) {
        title = project_.name();
        if (projectHasUnsavedChanges()) title += " *";
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
    ImGui::DockBuilderDockWindow("Editor", center);
    ImGui::DockBuilderDockWindow("Output", bottom);
    ImGui::DockBuilderDockWindow("Search", bottom);
    ImGui::DockBuilderFinish(dockId);
}
