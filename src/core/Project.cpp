#include "core/Project.hpp"
#include <filesystem>

namespace fs = std::filesystem;

static constexpr const char* kProjectFormat = "apkspy-project-1";

void Project::reset() {
    open_ = true;
    path_.clear();
    apks_.clear();
    tabs_.clear();
}

void Project::close() {
    open_ = false;
    path_.clear();
    apks_.clear();
    tabs_.clear();
}

std::string Project::name() const {
    if (path_.empty()) return "Untitled Project";
    return fs::path(path_).stem().string();
}

ProjectApk* Project::findApkByPath(const std::string& path) {
    for (ProjectApk& apk : apks_)
        if (apk.path == path) return &apk;
    return nullptr;
}

ProjectApk* Project::findApkByGroup(const std::string& group) {
    for (ProjectApk& apk : apks_)
        if (apk.group == group) return &apk;
    return nullptr;
}

void Project::addApk(std::string path, std::string group, std::string jadxOut) {
    apks_.push_back({std::move(path), std::move(group), std::move(jadxOut)});
}

void Project::removeApk(const std::string& group) {
    for (auto it = apks_.begin(); it != apks_.end(); ++it) {
        if (it->group == group) {
            apks_.erase(it);
            return;
        }
    }
}

void Project::setJadxOut(const std::string& group, std::string outDir) {
    if (ProjectApk* apk = findApkByGroup(group)) apk->jadxOut = std::move(outDir);
}

std::string Project::uniqueGroupName(const std::string& stem) const {
    std::string base = stem.empty() ? "apk" : stem;
    std::string candidate = base;
    int suffix = 2;
    auto taken = [&](const std::string& name) {
        for (const ProjectApk& apk : apks_)
            if (apk.group == name) return true;
        return false;
    };
    while (taken(candidate)) candidate = base + " (" + std::to_string(suffix++) + ")";
    return candidate;
}

bool Project::save(const std::string& path) {
    Settings out;
    out.set("format", kProjectFormat);
    out.set("apk.count", (int)apks_.size());
    for (size_t i = 0; i < apks_.size(); ++i) {
        const std::string idx = std::to_string(i);
        out.set("apk." + idx + ".path", apks_[i].path);
        out.set("apk." + idx + ".group", apks_[i].group);
        out.set("apk." + idx + ".jadxOut", apks_[i].jadxOut);
    }
    out.set("tab.count", (int)tabs_.size());
    for (size_t i = 0; i < tabs_.size(); ++i) {
        const std::string idx = std::to_string(i);
        out.set("tab." + idx + ".kind", tabs_[i].rootKind);
        out.set("tab." + idx + ".group", tabs_[i].group);
        out.set("tab." + idx + ".path", tabs_[i].path);
    }
    if (!out.save(path)) return false;
    path_ = path;
    open_ = true;
    return true;
}

bool Project::load(const std::string& path) {
    Settings in;
    in.load(path);
    if (in.getString("format") != kProjectFormat) return false;

    std::vector<ProjectApk> apks;
    int count = in.getInt("apk.count", 0);
    for (int i = 0; i < count; ++i) {
        const std::string idx = std::to_string(i);
        ProjectApk apk;
        apk.path = in.getString("apk." + idx + ".path");
        apk.group = in.getString("apk." + idx + ".group");
        apk.jadxOut = in.getString("apk." + idx + ".jadxOut");
        if (!apk.path.empty()) apks.push_back(std::move(apk));
    }

    std::vector<Tab> tabs;
    int tabCount = in.getInt("tab.count", 0);
    for (int i = 0; i < tabCount; ++i) {
        const std::string idx = std::to_string(i);
        Tab tab;
        tab.rootKind = in.getInt("tab." + idx + ".kind", 0);
        tab.group = in.getString("tab." + idx + ".group");
        tab.path = in.getString("tab." + idx + ".path");
        if (!tab.path.empty()) tabs.push_back(std::move(tab));
    }

    apks_ = std::move(apks);
    tabs_ = std::move(tabs);
    path_ = path;
    open_ = true;
    return true;
}
