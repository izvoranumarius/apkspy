#pragma once
#include "ui/CommandPalette.hpp"
#include "ui/TerminalPanel.hpp"
#include <memory>
#include <vector>
#include <string>
#include "app/Perspective.hpp"
#include "app/WindowFrame.hpp"
#include "ui/Panel.hpp"
#include "ui/TitleBar.hpp"
#include "core/Workspace.hpp"
#include "core/Project.hpp"
#include "core/Settings.hpp"
#include "ui/SettingsDialog.hpp"
#include "ui/FileBrowser.hpp"
#include "debug/DeviceService.hpp"
#include "mcp/McpHost.hpp"

struct GLFWwindow;
class EditorPanel;
class AnalysisPanel;
class DebuggerPanel;
class McpSettings;
class ScriptPanel;
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
    void drawNavigateMenu();
    void drawWelcome();
    std::vector<CommandPalette::Command> paletteCommands();
    std::string projectFolder() const;
    void toggleTerminal();
    void drawWindowBorder();
    void updateTitle();
    void drawDockHost();
    void buildLayout(const Perspective& p, unsigned int dockId, ImVec2 size);
    void drawStatusBar();
    void initPerspectives();
    void switchPerspective(int index);
    // Shows a panel, switching to a workspace that has it when this one does not.
    bool showPanel(const std::string& title);

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
    bool fontBuildDataPending_ = true;  // atlas CPU copies to free after the texture upload
    bool fullCjkFonts_ = false;         // Settings::kFullCjkFonts (read before the first font build)
    float uiZoom_ = 1.f;                // View > Zoom (Ctrl+= / Ctrl+- / Ctrl+0 / Ctrl+wheel)
    float pendingZoom_ = 0.f;           // requested zoom, applied before the next frame
    void setZoom(float zoom);
    float zoomTarget() const { return pendingZoom_ > 0.f ? pendingZoom_ : uiZoom_; }
    double zoomRequestedAt_ = 0.0;
    int settleFrames_ = 0;  // frames still to draw after input, see run()
    void rebuildFonts();
    std::string pendingFocusPanel_;  // MCP show_panel, applied inside the next frame
    Workspace workspace_;
    Project project_;
    Settings settings_;
    DeviceService devices_;         // adb devices, Logcat, monitor, JDWP debugger
    std::unique_ptr<McpHost> mcp_;  // AI integration (declared after what it references)
    std::vector<std::unique_ptr<Panel>> panels_;
    std::vector<Perspective> perspectives_;  // the workspaces of the switcher
    int activePerspective_ = 0;
    int pendingPerspective_ = -1;            // applied at the start of the next dock host
    std::vector<std::string> pendingTabs_;   // windows to bring forward once a new layout is shown
    int pendingTabsDelay_ = 0;               // frames until their dock tab bars exist
    EditorPanel* editor_ = nullptr;  // non-owning; document commands (Find, Go to Line) go here
    AnalysisPanel* analysisPanel_ = nullptr;  // non-owning
    TerminalPanel* terminal_ = nullptr;        // non-owning
    std::unique_ptr<CommandPalette> palette_;
    DebuggerPanel* debuggerPanel_ = nullptr;  // non-owning; global debugger shortcuts
    std::unique_ptr<McpSettings> mcpSettings_;  // the AI page of the Settings dialog
    ScriptPanel* scriptPanel_ = nullptr;      // non-owning
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
    bool resetLayout_ = false;      // the active workspace
    bool resetAllLayouts_ = false;  // every workspace (new layout version)
    bool saveRequested_ = false;
    bool addApkRequested_ = false;
    PendingAction pendingAction_ = PendingAction::None;
    std::string pendingOpenPath_;
    bool saveAsPending_ = false;  // a Save-As is in flight for the pending action
    std::vector<std::string> recents_;
    // Dirty-check cache (see projectHasUnsavedChanges).
    uint64_t dirtyCheckVersion_ = 0;
    uint64_t dirtyCheckEpoch_ = 0;
    uint64_t savedAnnotations_ = 1;  // Annotations::version() of the saved state
    bool dirtyCheckResult_ = false;
};
