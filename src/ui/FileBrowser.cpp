#include "ui/FileBrowser.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"

namespace fs = std::filesystem;

namespace {
std::string homeDir() {
#ifdef _WIN32
    const char* d = std::getenv("USERPROFILE");
#else
    const char* d = std::getenv("HOME");
#endif
    return d ? d : ".";
}

bool hasExtension(const std::string& name, const char* ext) {
    std::string n = tex::asciiLower(name);
    std::string e = tex::asciiLower(ext);
    return n.size() >= e.size() && n.compare(n.size() - e.size(), e.size(), e) == 0;
}
}  // namespace

void FileBrowser::open(Mode mode) {
    mode_ = mode;
    open_ = true;
    openRequest_ = true;
    accepted_ = false;
    acceptedMulti_ = false;
    result_.clear();
    results_.clear();
    selectedFile_.clear();
    selectedNames_.clear();
    nameBuffer_[0] = 0;
    if (mode_ == Mode::SaveProject) setDefaultName("project");
    goTo(currentDir_.empty() ? homeDir() : currentDir_);
    // Do NOT call ImGui::OpenPopup() here. open() may run inside a different
    // ID scope (e.g. a child of the Settings window) than the render() call,
    // and a popup opened in one scope cannot be begun in another - the Browse
    // button then silently did nothing. render() consumes the request in its
    // own ID context instead, so the two always match.
}

void FileBrowser::setDefaultName(const std::string& name) {
    std::snprintf(nameBuffer_, sizeof nameBuffer_, "%s", name.c_str());
}

void FileBrowser::goTo(const std::string& dir) {
    std::error_code ec;
    fs::path p = fs::absolute(pathutil::fromUtf8(dir)).lexically_normal();
    if (!fs::is_directory(p, ec)) return;
    currentDir_ = pathutil::toUtf8(p);
    std::snprintf(pathBuffer_, sizeof pathBuffer_, "%s", currentDir_.c_str());
    refresh();
}

void FileBrowser::applyFilter() {
    entries_.clear();
    for (const Entry& e : all_) {
        if (e.isDir) {
            entries_.push_back(e);
            continue;
        }
        if (mode_ == Mode::OpenApkMulti) {
            if (hasExtension(e.name, ".apk")) entries_.push_back(e);
        } else if (mode_ == Mode::OpenProject) {
            if (hasExtension(e.name, ".apkspy")) entries_.push_back(e);
        } else {
            entries_.push_back(e);
        }
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const Entry& a, const Entry& b) {
        if (a.isDir != b.isDir) return a.isDir;
        return tex::asciiLower(a.name) < tex::asciiLower(b.name);
    });
}

void FileBrowser::refresh() {
    all_.clear();
    std::error_code ec;
    for (fs::directory_iterator it(pathutil::fromUtf8(currentDir_), ec), end; !ec && it != end; it.increment(ec)) {
        std::string name = pathutil::toUtf8(it->path().filename());
        if (name.empty()) continue;
        if (name.front() == '.') continue;  // keep the list tidy
        all_.push_back({name, it->is_directory(ec)});
    }
    applyFilter();
}

const char* FileBrowser::popupTitle() const {
    switch (mode_) {
    case Mode::OpenApkMulti: return "Select APK Files";
    case Mode::OpenProject: return "Open Project";
    case Mode::SaveProject: return "Save Project As";
    case Mode::SaveFile: return "Export File";
    case Mode::SelectFolder: return "Export Folder";
    default: return "Select jadx Executable";
    }
}

std::string FileBrowser::projectFileName(const std::string& name) const {
    std::string n = name;
    if (!hasExtension(n, ".apkspy")) n += ".apkspy";
    return n;
}

bool FileBrowser::takeAccepted(std::string& outPath) {
    if (!accepted_) return false;
    accepted_ = false;
    outPath = result_;
    return true;
}

bool FileBrowser::takeAcceptedMulti(std::vector<std::string>& outPaths) {
    if (!acceptedMulti_) return false;
    acceptedMulti_ = false;
    outPaths = std::move(results_);
    results_.clear();
    return true;
}

void FileBrowser::render() {
    if (!open_) return;
    const char* popupTitle = this->popupTitle();
    // Consume the open request in the same ID scope as the BeginPopupModal()
    // below, whatever context render() is invoked from.
    if (openRequest_) {
        ImGui::OpenPopup(popupTitle);
        openRequest_ = false;
    }
    ImGui::SetNextWindowSize(ImVec2(720, 460), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal(popupTitle, &open_, ImGuiWindowFlags_NoSavedSettings)) return;
    const bool multi = mode_ == Mode::OpenApkMulti;

    // Path row ------------------------------------------------------------
    float buttonW = 90.f;
    ImGui::SetNextItemWidth(-buttonW - 140.f);
    if (ImGui::InputText("##path", pathBuffer_, sizeof pathBuffer_, ImGuiInputTextFlags_EnterReturnsTrue)) {
        std::error_code ec;
        fs::path p = pathutil::fromUtf8(pathBuffer_).lexically_normal();
        if (fs::is_directory(p, ec)) {
            currentDir_ = pathutil::toUtf8(p);
            refresh();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Up", ImVec2(60, 0))) {
        fs::path parent = pathutil::fromUtf8(currentDir_).parent_path();
        if (!parent.empty()) goTo(pathutil::toUtf8(parent));
        else {
            std::error_code ec;
            fs::path cur = pathutil::fromUtf8(currentDir_);
            if (!cur.has_root_path() || pathutil::toUtf8(cur.root_path()) != currentDir_) goTo("/");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh", ImVec2(70, 0))) refresh();

    // Quick places ---------------------------------------------------------
    if (ImGui::Button("Home")) goTo(homeDir());
#ifdef _WIN32
    ImGui::SameLine();
    if (ImGui::Button("Desktop")) goTo(homeDir() + "\\Desktop");
    ImGui::SameLine();
    if (ImGui::Button("Downloads")) goTo(homeDir() + "\\Downloads");
    ImGui::SameLine();
    if (ImGui::Button("Program Files")) goTo("C:\\Program Files");
#else
    ImGui::SameLine();
    if (ImGui::Button("Desktop")) goTo(homeDir() + "/Desktop");
    ImGui::SameLine();
    if (ImGui::Button("Downloads")) goTo(homeDir() + "/Downloads");
    ImGui::SameLine();
    if (ImGui::Button("Root")) goTo("/");
#endif

    ImGui::Separator();

    // Entries (virtualized: a Downloads folder with thousands of files
    // must not submit every row every frame) ------------------------------
    ImGui::BeginChild("##entries", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() * 2.f),
                      ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    std::string pendingDir;
    bool pendingAccept = false;
    ImGuiListClipper clipper;
    clipper.Begin((int)entries_.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const Entry& e = entries_[(size_t)i];
            ImGui::PushID(i);
            const bool folderMode = mode_ == Mode::SelectFolder;
            const bool selected = multi       ? selectedNames_.count(e.name) > 0
                                  : folderMode ? (selectedFile_ == e.name && e.isDir)
                                               : (selectedFile_ == e.name && !e.isDir);
            if (ImGui::Selectable(e.name.c_str(), selected, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (e.isDir) {
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) pendingDir = e.name;
                    else if (folderMode) selectedFile_ = e.name;  // folder highlight
                    else if (!multi) selectedFile_ = e.name;      // remember highlight only
                } else if (folderMode) {
                    // Files are not valid export destinations here; enter on
                    // double click is handled above only for dirs.
                } else if (multi) {
                    // Click toggles the file in the multi-selection.
                    if (selectedNames_.count(e.name)) selectedNames_.erase(e.name);
                    else selectedNames_.insert(e.name);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        selectedNames_.clear();
                        selectedNames_.insert(e.name);
                        pendingAccept = true;
                    }
                } else {
                    selectedFile_ = e.name;
                    std::snprintf(nameBuffer_, sizeof nameBuffer_, "%s", e.name.c_str());
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) pendingAccept = true;
                }
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();

    // Name + buttons --------------------------------------------------------
    if (multi) {
        ImGui::TextDisabled("%d file(s) selected", (int)selectedNames_.size());
    } else {
        ImGui::SetNextItemWidth(-buttonW * 2 - 12.f);
        ImGui::InputText("##name", nameBuffer_, sizeof nameBuffer_);
    }
    ImGui::SameLine();
    const char* acceptLabel = multi      ? "Add"
                              : mode_ == Mode::OpenProject ? "Open"
                              : mode_ == Mode::SelectFolder ? "Select Folder"
                                                            : "Save";
    if (ImGui::Button(acceptLabel, ImVec2(buttonW, 0))) pendingAccept = true;
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(buttonW, 0))) {
        open_ = false;
        ImGui::CloseCurrentPopup();
    }

    if (!pendingDir.empty()) {
        goTo(pathutil::toUtf8(pathutil::fromUtf8(currentDir_) / pendingDir));
        selectedFile_.clear();
    }
    if (pendingAccept) {
        if (multi) {
            if (!selectedNames_.empty()) {
                results_.clear();
                for (const std::string& name : selectedNames_)
                    results_.push_back(pathutil::toUtf8(pathutil::fromUtf8(currentDir_) / name));
                acceptedMulti_ = true;
                open_ = false;
                ImGui::CloseCurrentPopup();
            }
        } else if (mode_ == Mode::SelectFolder) {
            // The highlighted folder wins; otherwise the current directory.
            std::error_code ec;
            fs::path chosen = selectedFile_.empty()
                                  ? fs::path(pathutil::fromUtf8(currentDir_))
                                  : pathutil::fromUtf8(currentDir_) / selectedFile_;
            if (fs::is_directory(chosen, ec)) {
                result_ = pathutil::toUtf8(chosen);
                accepted_ = true;
                open_ = false;
                ImGui::CloseCurrentPopup();
            }
        } else if (nameBuffer_[0]) {
            std::string name = nameBuffer_;
            if (mode_ == Mode::SaveProject) name = projectFileName(name);
            std::error_code ec;
            fs::path candidate = pathutil::fromUtf8(currentDir_) / name;
            if (mode_ != Mode::SaveProject && mode_ != Mode::SaveFile && fs::is_directory(candidate, ec)) {
                goTo(pathutil::toUtf8(candidate));
            } else {
                result_ = pathutil::toUtf8(candidate);
                accepted_ = true;
                open_ = false;
                ImGui::CloseCurrentPopup();
            }
        }
    }
    ImGui::EndPopup();
}
