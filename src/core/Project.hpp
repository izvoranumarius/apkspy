#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "core/RootKind.hpp"
#include "core/Settings.hpp"

// One APK entry inside an ApkSpy project.
struct ProjectApk {
    std::string path;   // absolute path of the APK on disk
    std::string group;  // unique display name, shared by the Files and
                        // Decompiled groups of this APK
};

// An ApkSpy project: a named, saveable collection of APKs plus the session
// (permanently opened tabs). The file format reuses the simple key=value
// store of Settings (see Settings.cpp) and is written as "<name>.apkspy".
// The APK files themselves are only referenced, never copied or modified.
//
// The jadx output location is NOT stored: it is always derived from the APK
// (path/size/mtime hash) under the ApkSpy cache directory, so a crafted
// project file cannot point the app at arbitrary directories. Older project
// files that still contain jadxOut keys load fine; the key is ignored.
class Project {
public:
    // Starts a fresh, unsaved, empty project ("Untitled Project").
    void reset();
    // Drops the project entirely (no project open).
    void close();

    bool isOpen() const { return open_; }
    bool hasPath() const { return !path_.empty(); }
    const std::string& path() const { return path_; }
    // Display name: the file stem once saved, "Untitled Project" before.
    std::string name() const;

    const std::vector<ProjectApk>& apks() const { return apks_; }
    ProjectApk* findApkByPath(const std::string& path);
    ProjectApk* findApkByGroup(const std::string& group);
    void addApk(std::string path, std::string group);
    void removeApk(const std::string& group);
    // Replaces the whole APK list (used when saving, to sync the project
    // model with the workspace).
    void setApks(std::vector<ProjectApk> apks) { apks_ = std::move(apks); ++epoch_; }

    // Returns a group name unique within the project ("name", "name (2)", ...).
    std::string uniqueGroupName(const std::string& stem) const;

    // Session: permanently opened tabs, stored inside the project file.
    struct Tab {
        RootKind rootKind = RootKind::Apk;
        std::string group;
        std::string path;
    };
    const std::vector<Tab>& tabs() const { return tabs_; }
    void setTabs(std::vector<Tab> tabs) { tabs_ = std::move(tabs); ++epoch_; }

    // Bumped by every mutation; lets the title bar cache its dirty check.
    uint64_t epoch() const { return epoch_; }

    // Disk IO. load() leaves the project untouched on failure.
    bool save(const std::string& path);
    bool load(const std::string& path);

private:
    bool open_ = false;
    uint64_t epoch_ = 1;
    std::string path_;
    std::vector<ProjectApk> apks_;
    std::vector<Tab> tabs_;
};
