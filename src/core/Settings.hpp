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

    void remove(const std::string& key) { map_.erase(key); }
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
    static constexpr const char* kTrafficRules = "traffic.rules";  // match & replace rules (JSON)
    // HTTPS interception: decrypt CONNECT tunnels with ApkSpy's own CA
    // (on by default; without it, tunnels are relayed blind as before).
    static constexpr const char* kTrafficInterceptHttps = "traffic.interceptHttps";
    // Verify upstream servers' certificates against the bundled root store.
    static constexpr const char* kTrafficVerifyUpstream = "traffic.verifyUpstream";
    // Proxy mode: "regular" (HTTP proxy + CONNECT, SOCKS5 on the same port)
    // or "reverse" (every request goes to traffic.reverseTarget).
    static constexpr const char* kTrafficMode = "traffic.mode";
    static constexpr const char* kTrafficReverseTarget = "traffic.reverseTarget";  // "https://api.example.com"
    static constexpr const char* kTrafficUpstream = "traffic.upstream";            // "host:port", "" = direct
    static constexpr const char* kTrafficUpstreamAuth = "traffic.upstreamAuth";    // "user:password"
    static constexpr const char* kScriptsAutorun = "scripts.autorun";              // scripts enabled as plugins: run at startup ('|'-separated names)
    static constexpr const char* kTrafficScript = "traffic.script";                // last loaded traffic scripts ('|'-separated)
    static constexpr const char* kTrafficRouting = "traffic.routing";              // ignore / allow hosts, map local / remote (JSON)
    static constexpr const char* kTrafficConditions = "traffic.conditions";        // network conditions (JSON)
    static constexpr const char* kTrafficMaxFlows = "traffic.maxFlows";
    static constexpr const char* kTrafficProtoDir = "traffic.protoDir";  // .proto files for the protobuf views
    static constexpr const char* kTrafficMaxBodyKb = "traffic.maxBodyKb";
    static constexpr const char* kFullCjkFonts = "ui.fullCjkFonts";
    static constexpr const char* kFollowSystemTheme = "ui.followSystemTheme";
    static constexpr const char* kHideLibs = "analysis.hideLibs";
    static constexpr const char* kHideLibsList = "analysis.hideLibsList";  // one package prefix per line, \n-joined
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
