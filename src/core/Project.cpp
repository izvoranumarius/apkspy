#include "core/Project.hpp"
#include <cstdlib>
#include <filesystem>
#include "core/Paths.hpp"

namespace fs = std::filesystem;

static constexpr const char* kProjectFormat = "apkspy-project-1";
// Sanity caps for untrusted input: a corrupt or hostile project file must not
// turn into gigabytes of allocations before the format check even runs.
static constexpr int kMaxApkEntries = 4096;
static constexpr int kMaxTabEntries = 10000;

void Project::reset() {
    open_ = true;
    path_.clear();
    apks_.clear();
    tabs_.clear();
    annotations_.clear();
    ++epoch_;
}

void Project::close() {
    open_ = false;
    path_.clear();
    apks_.clear();
    tabs_.clear();
    annotations_.clear();
    ++epoch_;
}

std::string Project::name() const {
    if (path_.empty()) return "Untitled Project";
    return pathutil::toUtf8(fs::path(pathutil::fromUtf8(path_)).stem());
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

void Project::addApk(std::string path, std::string group) {
    apks_.push_back({std::move(path), std::move(group)});
    ++epoch_;
}

void Project::removeApk(const std::string& group) {
    for (auto it = apks_.begin(); it != apks_.end(); ++it) {
        if (it->group == group) {
            apks_.erase(it);
            ++epoch_;
            return;
        }
    }
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
    out.set("apk.count", static_cast<int>(apks_.size()));
    for (size_t i = 0; i < apks_.size(); ++i) {
        const std::string idx = std::to_string(i);
        out.set("apk." + idx + ".path", apks_[i].path);
        out.set("apk." + idx + ".group", apks_[i].group);
    }
    out.set("tab.count", static_cast<int>(tabs_.size()));
    for (size_t i = 0; i < tabs_.size(); ++i) {
        const std::string idx = std::to_string(i);
        out.set("tab." + idx + ".kind", static_cast<int>(tabs_[i].rootKind));
        out.set("tab." + idx + ".group", tabs_[i].group);
        out.set("tab." + idx + ".path", tabs_[i].path);
    }
    out.set("note.count", static_cast<int>(annotations_.size()));
    for (size_t i = 0; i < annotations_.size(); ++i) {
        const Annotation& a = annotations_[i];
        const std::string k = "note." + std::to_string(i) + ".";
        out.set(k + "kind", static_cast<int>(a.kind));
        out.set(k + "target", static_cast<int>(a.target));
        out.set(k + "group", a.group);
        out.set(k + "root", static_cast<int>(a.root));
        out.set(k + "path", a.path);
        out.set(k + "line", a.line);
        out.set(k + "addr", std::to_string(a.addr));
        out.set(k + "text", Annotations::escape(a.text));
        out.set(k + "context", Annotations::escape(a.context));
    }
    if (!out.save(path)) return false;
    path_ = path;
    open_ = true;
    ++epoch_;
    return true;
}

bool Project::load(const std::string& path) {
    Settings in;
    in.load(path);
    if (in.getString("format") != kProjectFormat) return false;

    std::vector<ProjectApk> apks;
    int count = in.getInt("apk.count", 0);
    if (count < 0 || count > kMaxApkEntries) return false;
    for (int i = 0; i < count; ++i) {
        const std::string idx = std::to_string(i);
        ProjectApk apk;
        apk.path = in.getString("apk." + idx + ".path");
        apk.group = in.getString("apk." + idx + ".group");
        if (!apk.path.empty()) apks.push_back(std::move(apk));
    }

    std::vector<Tab> tabs;
    int tabCount = in.getInt("tab.count", 0);
    if (tabCount < 0 || tabCount > kMaxTabEntries) return false;
    for (int i = 0; i < tabCount; ++i) {
        const std::string idx = std::to_string(i);
        Tab tab;
        int kind = in.getInt("tab." + idx + ".kind", 0);
        if (kind != static_cast<int>(RootKind::Apk) && kind != static_cast<int>(RootKind::Decompiled)) continue;
        tab.rootKind = static_cast<RootKind>(kind);
        tab.group = in.getString("tab." + idx + ".group");
        tab.path = in.getString("tab." + idx + ".path");
        if (!tab.path.empty()) tabs.push_back(std::move(tab));
    }

    std::vector<Annotation> notes;
    const int noteCount = in.getInt("note.count", 0);
    if (noteCount < 0 || noteCount > static_cast<int>(Annotations::kMaxItems)) return false;
    for (int i = 0; i < noteCount; ++i) {
        const std::string k = "note." + std::to_string(i) + ".";
        Annotation a;
        const int kind = in.getInt(k + "kind", 0), target = in.getInt(k + "target", 0), root = in.getInt(k + "root", 0);
        if (kind < 0 || kind > 1 || target < 0 || target > 1) continue;
        if (root != static_cast<int>(RootKind::Apk) && root != static_cast<int>(RootKind::Decompiled)) continue;
        a.kind = static_cast<Annotation::Kind>(kind);
        a.target = static_cast<Annotation::Target>(target);
        a.root = static_cast<RootKind>(root);
        a.group = in.getString(k + "group");
        a.path = in.getString(k + "path");
        a.line = in.getInt(k + "line", 0);
        a.addr = std::strtoull(in.getString(k + "addr", "0").c_str(), nullptr, 10);
        a.text = Annotations::unescape(in.getString(k + "text"));
        a.context = Annotations::unescape(in.getString(k + "context"));
        notes.push_back(std::move(a));
    }

    apks_ = std::move(apks);
    tabs_ = std::move(tabs);
    annotations_ = std::move(notes);
    path_ = path;
    open_ = true;
    ++epoch_;
    return true;
}
