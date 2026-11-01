#pragma once
#include <memory>
#include <vector>
#include <string>
#include "app/WindowFrame.hpp"
#include "ui/Panel.hpp"
#include "ui/TitleBar.hpp"
#include "core/Workspace.hpp"
#include "core/Project.hpp"
#include "core/Settings.hpp"
#include "ui/SettingsDialog.hpp"
#include "ui/FileBrowser.hpp"

struct GLFWwindow;
class EditorPanel;
class Texture;

class Application {
public:
    Application();
    ~Application();
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    int run();

private:
    // What the "unsaved project changes?" confirmation should do afterwards.
    enum class PendingAction { None, NewProject, OpenProject, CloseProject, Exit };

    void initWindow();
    void initImGui();
    void initTitleBar();
    // Loads assets/favicon.ico (found via pathutil::assetsFile): sets it as
    // the OS window / taskbar icon and keeps the best ~32px frame as a
    // texture for the custom title bar. Missing or undecodable assets keep
    // the defaults (no error is fatal here).
    void loadWindowIcon();
    void loadSettings();
    void saveSettings();
    void restoreSession();
    void shutdown();
    void frame();
    void drawMenuBar();
    void drawFileMenu();
    void drawViewMenu();
    void drawWindowBorder();
    void updateTitle();
    void drawDockHost();
    void buildDefaultLayout(unsigned int dockId, ImVec2 size);

    // Project flows ---------------------------------------------------------
    // True when the project or its open documents contain unsaved changes.
    // Cached: recomputed only when the workspace / project / documents
    // actually changed (version counters), not every frame.
    bool projectHasUnsavedChanges() const;
    // Asks to save unsaved changes first, then runs the action (or the
    // user cancels). 'path' is the project file for OpenProject.
    void requestAction(PendingAction action, const std::string& path = {});
    void performAction(PendingAction action, const std::string& path);
    void drawProjectConfirm();
    // Saves edited documents, then the project file (asks for a location
    // first when the project was never saved). Returns false if the save
    // still needs user input.
    bool saveProject();
    bool saveProjectAs(const std::string& path);
    bool openProject(const std::string& path);
    void addApkPaths(const std::vector<std::string>& paths);
    void addRecent(const std::string& path);
    void drawRecentProjects();

    static void onRefresh(GLFWwindow* window);
    static void onDrop(GLFWwindow* window, int count, const char** paths);
    // Intercepts the OS close (X button, Alt+F4) so unsaved changes are
    // confirmed instead of silently dropped.
    static void onCloseRequested(GLFWwindow* window);
    static void onContentScale(GLFWwindow* window, float x, float y);

    GLFWwindow* window_ = nullptr;
    float contentScale_ = 1.f;
    float pendingContentScale_ = 0.f;  // set by the DPI callback, applied next frame
    Workspace workspace_;
    Project project_;
    Settings settings_;
    std::vector<std::unique_ptr<Panel>> panels_;
    EditorPanel* editor_ = nullptr;  // non-owning; document commands (Find, Go to Line) go here
    std::unique_ptr<WindowFrame> windowFrame_;
    std::unique_ptr<TitleBar> titleBar_;
    std::unique_ptr<Texture> appIcon_;  // favicon frame drawn in the title bar
    SettingsDialog settingsDialog_;
    FileBrowser projOpenBrowser_;
    FileBrowser projSaveBrowser_;
    FileBrowser apkBrowser_;
    std::string windowTitle_;
    bool inFrame_ = false;
    bool settingsRequested_ = false;
    bool resetLayout_ = false;
    bool saveRequested_ = false;
    bool addApkRequested_ = false;
    PendingAction pendingAction_ = PendingAction::None;
    std::string pendingOpenPath_;
    bool saveAsPending_ = false;  // a Save-As is in flight for the pending action
    std::vector<std::string> recents_;
    // Dirty-check cache (see projectHasUnsavedChanges).
    uint64_t dirtyCheckVersion_ = 0;
    uint64_t dirtyCheckEpoch_ = 0;
    bool dirtyCheckResult_ = false;
};
