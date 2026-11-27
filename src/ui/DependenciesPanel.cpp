#include "ui/DependenciesPanel.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "core/Settings.hpp"
#include "mcp/Json.hpp"
#include "ui/UiUtil.hpp"

namespace {

ImVec4 severityColor(int rank) {
    switch (rank) {
    case 4: return theme::vec(Col::Red);
    case 3: return theme::vec(Col::Orange);
    case 2: return theme::vec(Col::Yellow);
    case 1: return theme::vec(Col::Blue);
    default: return theme::vec(Col::TextMuted);
    }
}

int severityRank(const std::string& s) { return s == "Critical" ? 4 : s == "High" ? 3 : s == "Medium" ? 2 : s == "Low" ? 1 : 0; }

ImVec4 licenseColor(deps::LicenseKind k) {
    switch (k) {
    case deps::LicenseKind::Permissive: return theme::vec(Col::Success);
    case deps::LicenseKind::WeakCopyleft: return theme::vec(Col::Yellow);
    case deps::LicenseKind::Copyleft: return theme::vec(Col::Orange);
    case deps::LicenseKind::Proprietary: return theme::vec(Col::Purple);
    case deps::LicenseKind::Unknown: return theme::vec(Col::TextMuted);
    }
    return theme::vec(Col::Text);
}

bool containsNoCase(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           }) != hay.end();
}

}  // namespace

DependenciesPanel::~DependenciesPanel() {
    if (job_.valid()) job_.wait();
    updater_.stop();
}

void DependenciesPanel::start(Root& apk) {
    auto* archive = dynamic_cast<ApkArchive*>(apk.source.get());
    if (!archive) return;
    std::vector<std::string> paths;
    for (const ApkArchive::Entry& e : archive->entries()) paths.push_back(e.path);
    auto analysis = workspace_.analysis().get(apk.title);
    builtWith_ = analysis.get();
    selected_ = -1;
    graphDirty_ = true;
    job_ = std::async(std::launch::async, [analysis, apkPath = apk.apkPath, paths = std::move(paths)] {
        std::string note;
        const vulndb::Database db = vulndb::loadPreferred(&note);
        if (note.empty()) note = "built-in data";
        return deps::analyze(analysis.get(), apkPath, paths, db, note);
    });
}

void DependenciesPanel::drawContents() {
    pollUpdate();
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.empty()) {
        ui::emptyState("No APK open", "Add an APK to list the libraries it bundles and their known vulnerabilities.");
        return;
    }
    if (apkIdx_ >= static_cast<int>(apks.size())) apkIdx_ = 0;
    if (apks.size() > 1) {
        ImGui::SetNextItemWidth(ui::em(16.f));
        if (ImGui::BeginCombo("##apk", apks[static_cast<size_t>(apkIdx_)]->title.c_str())) {
            for (int i = 0; i < static_cast<int>(apks.size()); ++i)
                if (ImGui::Selectable(apks[static_cast<size_t>(i)]->title.c_str(), i == apkIdx_)) apkIdx_ = i;
            ImGui::EndCombo();
        }
        ImGui::SameLine();
    }
    Root& apk = *apks[static_cast<size_t>(apkIdx_)];
    if (apk.title != group_) {
        if (job_.valid()) job_.wait();
        group_ = apk.title;
        built_ = false;
        report_ = {};
    }
    if (workspace_.analysis().status(group_).state == AnalysisService::State::None) workspace_.startAnalysis(group_);
    const auto analysis = workspace_.analysis().get(group_);
    // Classes count once the analysis is in; version files and native libraries count at once.
    if (!job_.valid() && (!built_ || (analysis && analysis.get() != builtWith_))) start(apk);
    if (job_.valid() && job_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        report_ = job_.get();
        built_ = true;
        graphDirty_ = true;
    }
    drawToolbar();
    if (!built_) {
        ImGui::TextDisabled("Identifying libraries...");
        return;
    }
    const float detailsHeight = selected_ >= 0 ? std::min(ui::em(14.f), ImGui::GetContentRegionAvail().y * 0.45f) : 0.f;
    ImGui::BeginChild("##view", ImVec2(0, -detailsHeight));
    if (view_ == 0) drawTable();
    else if (view_ == 1) drawGraph();
    else drawLicenses();
    ImGui::EndChild();
    if (selected_ >= 0 && selected_ < static_cast<int>(report_.dependencies.size())) {
        ui::horizontalDivider();
        ImGui::BeginChild("##details", ImVec2(0, 0));
        drawDetails(report_.dependencies[static_cast<size_t>(selected_)]);
        ImGui::EndChild();
    }
}

void DependenciesPanel::drawToolbar() {
    const char* views[] = {"Table", "Graph", "Licenses"};
    ImGui::PushID("view");
    ui::segmented(views, 3, view_);
    ImGui::PopID();
    if (!built_) return;
    size_t vulnerable = 0, vulns = 0;
    for (const auto& d : report_.dependencies) {
        if (!d.vulnerabilities.empty()) ++vulnerable;
        vulns += d.vulnerabilities.size();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu libraries", report_.dependencies.size());
    if (report_.totalClasses) {
        ImGui::SameLine();
        ImGui::TextDisabled("- %.0f%% of %zu classes", 100.0 * static_cast<double>(report_.libraryClasses) / static_cast<double>(report_.totalClasses),
                            report_.totalClasses);
    }
    if (vulnerable) {
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Error), "%zu vulnerable (%zu advisories)", vulnerable, vulns);
    }
    ui::flowCheckbox("Vulnerable only", &vulnerableOnly_);
    ui::sameLineIfFits(ui::em(14.f));
    ImGui::SetNextItemWidth(ui::em(12.f));
    ImGui::InputTextWithHint("##filter", "Filter libraries", filter_, sizeof filter_);
    ImGui::SameLine();
    if (updating_) {
        ImGui::TextDisabled("updating...");
        ImGui::SameLine();
        if (ui::smallButton("Stop")) updater_.stop();
    } else if (ui::smallButton(ui::icon(icons::REFRESH, "Update vulnerability data").c_str())) {
        startUpdate();
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Ask OSV.dev about these libraries (needs Python and network access).\nData: %s", report_.databaseNote.c_str());
    if (!updateStatus_.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", updateStatus_.c_str());
    }
    ui::toolbarSeparator();
}

void DependenciesPanel::drawTable() {
    if (!ImGui::BeginTable("##deps", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch, 2.5f);
    ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, ui::em(6.f));
    ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, ui::em(7.f));
    ImGui::TableSetupColumn("License", ImGuiTableColumnFlags_WidthFixed, ui::em(7.f));
    ImGui::TableSetupColumn("Code share", ImGuiTableColumnFlags_WidthStretch, 1.f);
    ImGui::TableSetupColumn("Vulnerabilities", ImGuiTableColumnFlags_WidthFixed, ui::em(7.f));
    ImGui::TableHeadersRow();
    size_t maxClasses = 1;
    for (const auto& d : report_.dependencies) maxClasses = std::max(maxClasses, d.classes);
    for (int i = 0; i < static_cast<int>(report_.dependencies.size()); ++i) {
        const deps::Dependency& d = report_.dependencies[static_cast<size_t>(i)];
        if (vulnerableOnly_ && d.vulnerabilities.empty()) continue;
        if (!containsNoCase(d.name, filter_) && !containsNoCase(d.maven, filter_) && !containsNoCase(d.category, filter_)) continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID(i);
        if (ImGui::Selectable(d.name.c_str(), selected_ == i, ImGuiSelectableFlags_SpanAllColumns)) selected_ = i;
        ImGui::PopID();
        ImGui::TableNextColumn();
        if (d.version.empty()) ImGui::TextDisabled("?");
        else ImGui::TextUnformatted(d.version.c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", d.category.c_str());
        ImGui::TableNextColumn();
        ImGui::TextColored(licenseColor(d.licenseKind), "%s", d.license.empty() ? "unknown" : d.license.c_str());
        ImGui::TableNextColumn();
        if (d.classes) {
            // The count right-aligned in its own slot, a thin bar beside it:
            // the bar no longer runs under (and through) the digits.
            char count[24];
            std::snprintf(count, sizeof count, "%zu", d.classes);
            const float slot = ImGui::CalcTextSize("000000").x;
            const ImVec2 p = ImGui::GetCursorScreenPos();
            const float textW = ImGui::CalcTextSize(count).x;
            ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + slot - textW, p.y), theme::u32(Col::TextMuted), count);
            const float barX = p.x + slot + ui::em(0.6f);
            const float room = std::max(0.f, ImGui::GetContentRegionAvail().x - slot - ui::em(0.6f));
            const float w = room * static_cast<float>(d.classes) / static_cast<float>(maxClasses);
            const float lh = ImGui::GetTextLineHeight(), barH = std::max(3.f, lh * 0.3f);
            ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(barX, p.y + (lh - barH) * 0.5f), ImVec2(barX + std::max(w, 2.f), p.y + (lh + barH) * 0.5f),
                                                      theme::u32(Col::Info, 0.55f), barH * 0.5f);
            ImGui::Dummy(ImVec2(slot, lh));
        } else if (!d.nativeLibs.empty()) {
            ImGui::TextDisabled("native");
        }
        ImGui::TableNextColumn();
        if (!d.vulnerabilities.empty()) {
            ImGui::TextColored(severityColor(deps::worstSeverity(d)), "%zu", d.vulnerabilities.size());
        } else if (d.advisoriesAnyVersion) {
            ImGui::TextDisabled("%zu?", d.advisoriesAnyVersion);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Version unknown: %zu advisories affect some versions", d.advisoriesAnyVersion);
        }
    }
    ImGui::EndTable();
    if (!report_.unidentifiedNative.empty()) {
        std::string list;
        for (const auto& n : report_.unidentifiedNative) list += (list.empty() ? "" : ", ") + n;
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("Unidentified native libraries: %s", list.c_str());
        ImGui::PopTextWrapPos();
    }
}

void DependenciesPanel::buildGraph() {
    graphDirty_ = false;
    graphNodes_.clear();
    std::vector<GraphView::Block> blocks;
    std::vector<graphlayout::Edge> edges;
    GraphView::Block app;
    app.lines.push_back({{"App", Col::Text}});
    if (report_.totalClasses)
        app.lines.push_back({{std::to_string(report_.totalClasses - std::min(report_.totalClasses, report_.libraryClasses)) + " own classes", Col::TextMuted}});
    app.border = Col::Accent;
    blocks.push_back(std::move(app));
    graphNodes_.push_back(-1);
    std::map<std::string, int> categories;
    for (int i = 0; i < static_cast<int>(report_.dependencies.size()); ++i) {
        const deps::Dependency& d = report_.dependencies[static_cast<size_t>(i)];
        if (vulnerableOnly_ && d.vulnerabilities.empty()) continue;
        auto it = categories.find(d.category);
        if (it == categories.end()) {
            GraphView::Block c;
            c.lines.push_back({{d.category, Col::Cyan}});
            it = categories.emplace(d.category, static_cast<int>(blocks.size())).first;
            blocks.push_back(std::move(c));
            graphNodes_.push_back(-1);
            graphlayout::Edge e;
            e.from = 0;
            e.to = it->second;
            e.kind = graphlayout::EdgeKind::Call;
            edges.push_back(std::move(e));
        }
        GraphView::Block b;
        b.lines.push_back({{d.name, Col::Text}});
        std::string info = d.version.empty() ? "version ?" : d.version;
        if (d.classes) info += "  " + std::to_string(d.classes) + " classes";
        b.lines.push_back({{info, Col::TextMuted}});
        if (!d.vulnerabilities.empty()) {
            const int worst = deps::worstSeverity(d);
            b.lines.push_back({{std::to_string(d.vulnerabilities.size()) + " vulnerabilit" + (d.vulnerabilities.size() == 1 ? "y" : "ies"), Col::Error}});
            b.border = worst >= 3 ? Col::Error : Col::Warning;
        }
        const int index = static_cast<int>(blocks.size());
        blocks.push_back(std::move(b));
        graphNodes_.push_back(i);
        graphlayout::Edge e;
        e.from = it->second;
        e.to = index;
        e.kind = graphlayout::EdgeKind::Fallthrough;
        edges.push_back(std::move(e));
    }
    graph_.set(std::move(blocks), std::move(edges), true);
}

void DependenciesPanel::drawGraph() {
    if (graphVulnerableOnly_ != vulnerableOnly_) {
        graphVulnerableOnly_ = vulnerableOnly_;
        graphDirty_ = true;
    }
    if (graphDirty_) buildGraph();
    graph_.draw("##depgraph", ImGui::GetFont());
    const int sel = graph_.selected();
    if (sel >= 0 && sel < static_cast<int>(graphNodes_.size()) && graphNodes_[static_cast<size_t>(sel)] >= 0) selected_ = graphNodes_[static_cast<size_t>(sel)];
}

void DependenciesPanel::drawLicenses() {
    std::map<std::string, std::vector<int>> byLicense;
    for (int i = 0; i < static_cast<int>(report_.dependencies.size()); ++i)
        byLicense[report_.dependencies[static_cast<size_t>(i)].license.empty() ? std::string("unknown") : report_.dependencies[static_cast<size_t>(i)].license]
            .push_back(i);
    for (const auto& [license, list] : byLicense) {
        const deps::LicenseKind kind = deps::licenseKind(license == "unknown" ? "" : license);
        ImGui::PushStyleColor(ImGuiCol_Text, licenseColor(kind));
        const bool open = ui::collapsingHeader((license + "  (" + std::to_string(list.size()) + ", " + deps::licenseKindName(kind) + ")").c_str(),
                                                  ImGuiTreeNodeFlags_DefaultOpen);
        ImGui::PopStyleColor();
        if (!open) continue;
        ImGui::Indent();
        for (int i : list) {
            const deps::Dependency& d = report_.dependencies[static_cast<size_t>(i)];
            ImGui::PushID(i);
            if (ImGui::Selectable(d.name.c_str(), selected_ == i)) selected_ = i;
            ImGui::PopID();
        }
        ImGui::Unindent();
    }
    ImGui::Spacing();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("Licenses come from ApkSpy's catalogue of known libraries; check the project page before relying on them. "
                        "Copyleft (GPL) code may require publishing the app's source; proprietary SDKs come with their own terms.");
    ImGui::PopTextWrapPos();
}

void DependenciesPanel::drawDetails(const deps::Dependency& d) {
    ImGui::TextUnformatted(d.name.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%s  %s", d.version.empty() ? "version unknown" : d.version.c_str(), d.category.c_str());
    ImGui::PushTextWrapPos(0.f);
    if (!d.maven.empty()) ImGui::TextDisabled("Maven: %s", d.maven.c_str());
    if (!d.versionSource.empty()) ImGui::TextDisabled("Version from %s", d.versionSource.c_str());
    ImGui::TextColored(licenseColor(d.licenseKind), "License: %s (%s)", d.license.empty() ? "unknown" : d.license.c_str(), deps::licenseKindName(d.licenseKind));
    if (!d.url.empty()) {
        ImGui::TextDisabled("%s", d.url.c_str());
        if (ImGui::BeginPopupContextItem("##url")) {
            if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(d.url.c_str());
            ImGui::EndPopup();
        }
    }
    if (!d.prefixes.empty()) {
        std::string list;
        for (const auto& p : d.prefixes) list += (list.empty() ? "" : ", ") + p;
        ImGui::TextDisabled("Packages: %s", list.c_str());
    }
    if (!d.nativeLibs.empty()) {
        std::string list;
        for (const auto& p : d.nativeLibs) list += (list.empty() ? "" : ", ") + p;
        ImGui::TextDisabled("Native: %s", list.c_str());
    }
    for (const vulndb::Vulnerability& v : d.vulnerabilities) {
        ImGui::Spacing();
        ImGui::TextColored(severityColor(severityRank(v.severity)), "%s  %s", v.severity.c_str(), v.id.c_str());
        ImGui::SameLine();
        ImGui::TextUnformatted(v.summary.c_str());
        std::string ranges;
        for (const vulndb::Range& r : v.ranges)
            ranges += (ranges.empty() ? "" : "; ") + (r.introduced == "0" ? std::string("all") : ">= " + r.introduced) +
                      (r.fixed.empty() ? (r.lastAffected.empty() ? "" : ", <= " + r.lastAffected) : ", fixed in " + r.fixed);
        ImGui::TextDisabled("Affected: %s   %s", ranges.c_str(), v.url.c_str());
    }
    if (d.vulnerabilities.empty() && d.advisoriesAnyVersion)
        ImGui::TextColored(theme::vec(Col::Warning), "The version could not be determined; %zu known advisories affect some versions of %s.",
                           d.advisoriesAnyVersion, d.maven.c_str());
    ImGui::PopTextWrapPos();
}

void DependenciesPanel::startUpdate() {
    // packages.json for the updater: every dependency with coordinates.
    Json list = Json::array();
    for (const auto& d : report_.dependencies)
        if (!d.maven.empty()) list.push(Json::obj({{"package", d.maven}, {"version", d.version}}));
    const std::string packages = pathutil::configFile("vulndb_packages.json");
    const std::string script = pathutil::configFile("vulndb_update.py");
    {
        std::ofstream p(pathutil::fromUtf8(packages), std::ios::binary);
        std::ofstream s(pathutil::fromUtf8(script), std::ios::binary);
        if (!p || !s) {
            updateStatus_ = "cannot write to the config directory";
            return;
        }
        p << list.dump();
        s << vulndb::updaterScript();
    }
    const std::string python = settings_.getString(Settings::kPythonPath, "python");
    std::string error;
    if (!updater_.start({python, script, packages, vulndb::userDatabasePath()}, error)) {
        updateStatus_ = "could not run Python (" + error + "): set it under File > Settings > Scripts";
        return;
    }
    updating_ = true;
    updateStatus_ = "contacting OSV.dev...";
    workspace_.log("Updating the vulnerability database from OSV.dev for " + std::to_string(list.size()) + " libraries", "analysis");
}

void DependenciesPanel::pollUpdate() {
    if (!updating_) return;
    for (std::string& line : updater_.takeOutput()) {
        updateStatus_ = line;
        workspace_.log("[vulndb] " + line, "analysis");
    }
    if (updater_.running()) return;
    updating_ = false;
    if (updater_.exitCode() == 0) {
        updateStatus_ = "vulnerability data updated";
        built_ = false;  // re-evaluate with the new data
    } else {
        updateStatus_ = "update failed (exit code " + std::to_string(updater_.exitCode()) + "): see Output";
    }
}
