#pragma once
#include <string>
#include <unordered_map>

// Simple persistent key/value store backed by a plain text file
// ("apkspy.settings" in the per-user config directory - see Paths.hpp). It
// stores user preferences, the jadx configuration and the last session so
// they survive restarts. The ImGui dock layout itself is persisted separately
// by ImGui in "apkspy.ini" in the same directory.
class Settings {
public:
    // Loads the file if it exists; missing keys keep their defaults.
    void load(const std::string& path);
    // Writes all keys back to disk atomically (temp file + rename).
    bool save(const std::string& path) const;

    std::string getString(const std::string& key, const std::string& fallback = {}) const;
    int getInt(const std::string& key, int fallback = 0) const;
    bool getBool(const std::string& key, bool fallback = false) const;

    void set(const std::string& key, std::string value);
    void set(const std::string& key, const char* value);
    void set(const std::string& key, int value);
    void set(const std::string& key, bool value);

    void clear() { map_.clear(); }

    // Well-known keys (kept here so call sites stay typo-free).
    static constexpr const char* kJadxPath = "jadx.path";
    static constexpr const char* kJadxArgs = "jadx.args";
    static constexpr const char* kRestoreSession = "session.restore";
    static constexpr const char* kLineNumbers = "editor.lineNumbers";
    static constexpr const char* kLastProject = "project.last";
    static constexpr const char* kAdbPath = "adb.path";
    static constexpr const char* kPythonPath = "scripting.python";
    static constexpr const char* kTerminalShell = "terminal.shell";  // "" = PowerShell / $SHELL
    static constexpr const char* kTrafficPort = "traffic.port";
    static constexpr const char* kFullCjkFonts = "ui.fullCjkFonts";
    static constexpr const char* kUiZoomPercent = "ui.zoomPercent";  // text / UI zoom, 100 = default
    static constexpr const char* kMcpPort = "mcp.port";
    static constexpr const char* kMcpToken = "mcp.token";
    static constexpr const char* kMcpRequireToken = "mcp.requireToken";
    static constexpr const char* kMcpAutoStart = "mcp.autoStart";
    // Bumped when new panels join the default dock layout: an older saved
    // layout is reset once so they appear docked instead of floating.
    static constexpr const char* kLayoutVersion = "layout.version";

    static constexpr const char* kActiveWorkspace = "workspace.active";
    static std::string workspacePanelKey(const std::string& workspace, const std::string& title) {
        return "workspace." + workspace + "." + title + ".visible";
    }
    // Recently opened projects (most recent first).
    static constexpr const char* kRecentCount = "project.recent.count";
    static std::string recentKey(int i) { return "project.recent." + std::to_string(i); }

private:
    std::unordered_map<std::string, std::string> map_;
};
