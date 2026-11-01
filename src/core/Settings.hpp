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

    static std::string panelKey(const std::string& title) { return "panels." + title + ".visible"; }
    // Recently opened projects (most recent first).
    static constexpr const char* kRecentCount = "project.recent.count";
    static std::string recentKey(int i) { return "project.recent." + std::to_string(i); }

private:
    std::unordered_map<std::string, std::string> map_;
};
