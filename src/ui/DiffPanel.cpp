#include "ui/DiffPanel.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include "analysis/Decompiler.hpp"
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "ui/UiUtil.hpp"

namespace {

const char* const kSectionNames[] = {"Summary", "Manifest", "Components", "Classes", "Methods",
                                     "Resources", "Native libraries", "Libraries", "Endpoints", "Files"};

ImVec4 kindColor(ApkDiff::Kind k) {
    switch (k) {
    case ApkDiff::Kind::Added: return theme::vec(Col::Success);
    case ApkDiff::Kind::Removed: return theme::vec(Col::Error);
    case ApkDiff::Kind::Changed: return theme::vec(Col::Warning);
    }
    return theme::vec(Col::Text);
}

const char* kindMark(ApkDiff::Kind k) {
    switch (k) {
    case ApkDiff::Kind::Added: return "+";
    case ApkDiff::Kind::Removed: return "-";
    case ApkDiff::Kind::Changed: return "~";
    }
    return " ";
}

bool containsNoCase(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           }) != hay.end();
}

// A table of strings with a +/- mark, clipped, filtered by `keep`.
void markedList(const char* id, ApkDiff::Kind kind, const std::vector<std::string>& items, const std::function<bool(std::string_view)>& keep,
                const std::function<void(const std::string&)>& activate = {}) {
    std::vector<const std::string*> rows;
    for (const std::string& s : items)
        if (keep(s)) rows.push_back(&s);
    ImGui::PushID(id);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()));
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const std::string& s = *rows[static_cast<size_t>(i)];
            ImGui::PushID(i);
            ImGui::TextColored(kindColor(kind), "%s", kindMark(kind));
            ImGui::SameLine();
            if (ImGui::Selectable(s.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) && activate && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                activate(s);
            if (ImGui::BeginPopupContextItem("##copy")) {
                if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(s.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    ImGui::PopID();
}

}  // namespace

DiffPanel::~DiffPanel() { cancel(); }

void DiffPanel::cancel() {
    if (cancel_) cancel_->store(true);
    if (job_.valid()) job_.wait();
    job_ = {};
    cancel_.reset();
}

void DiffPanel::start() {
    cancel();
    ApkDiff::Side a, b;
    if (!workspace_.diffSide(groupA_, a) || !workspace_.diffSide(groupB_, b)) {
        workspace_.log("Diff: both APKs must be archives in the project", "analysis");
        return;
    }
    titleA_ = groupA_ + (a.info.versionName.empty() ? "" : " " + a.info.versionName);
    titleB_ = groupB_ + (b.info.versionName.empty() ? "" : " " + b.info.versionName);
    analysisA_ = a.analysis;
    analysisB_ = b.analysis;
    valid_ = false;
    method_ = -1;
    rows_.clear();
    auto flag = std::make_shared<std::atomic<bool>>(false);
    cancel_ = flag;
    job_ = std::async(std::launch::async, [a = std::move(a), b = std::move(b), flag] {
        return ApkDiff::compare(a, b, ApkDiff::Options{}, flag.get());
    });
}

void DiffPanel::drawContents() {
    const std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.size() < 2) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("Add a second APK (another version of the app) to the project to compare them: "
                            "File > Add APK to Project.");
        ImGui::PopTextWrapPos();
        return;
    }
    Workspace::DiffViewRequest request;
    if (workspace_.takeDiffView(request)) {
        // From MCP (show_diff): compare that pair, then show the method.
        const bool samePair = request.groupA == groupA_ && request.groupB == groupB_;
        groupA_ = request.groupA;
        groupB_ = request.groupB;
        pendingMethod_ = request.method;
        if (!samePair || !valid_) {
            autoCompared_ = groupA_ + '\n' + groupB_;
            start();
        }
    }
    drawToolbar(apks);
    if (job_.valid() && job_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        const bool cancelled = cancel_ && cancel_->load();
        diff_ = job_.get();
        cancel_.reset();
        valid_ = !cancelled;
    }
    if (valid_ && !pendingMethod_.empty() && !job_.valid()) {
        for (int i = 0; i < static_cast<int>(diff_.methodDetails.size()); ++i)
            if (diff_.methodDetails[static_cast<size_t>(i)].signature == pendingMethod_) {
                section_ = Methods;
                selectMethod(i);
            }
        pendingMethod_.clear();
    }
    if (!valid_) return;
    ImGui::Separator();
    const float listWidth = std::min(ui::em(13.f), ImGui::GetContentRegionAvail().x * 0.3f);
    ImGui::BeginChild("##sections", ImVec2(listWidth, 0), ImGuiChildFlags_Borders);
    drawSectionList();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##section", ImVec2(0, 0));
    drawSection();
    ImGui::EndChild();
}

void DiffPanel::drawToolbar(const std::vector<Root*>& apks) {
    const auto exists = [&](const std::string& g) {
        return std::any_of(apks.begin(), apks.end(), [&](const Root* r) { return r->title == g; });
    };
    // Defaults: the two most recently added APKs, older first.
    if (!exists(groupA_)) groupA_ = apks[apks.size() - 2]->title;
    if (!exists(groupB_) || groupB_ == groupA_) groupB_ = apks.back()->title == groupA_ ? apks.front()->title : apks.back()->title;
    const auto combo = [&](const char* id, std::string& group) {
        ImGui::SetNextItemWidth(ui::em(12.f));
        if (ImGui::BeginCombo(id, group.c_str())) {
            for (const Root* r : apks)
                if (ImGui::Selectable(r->title.c_str(), r->title == group)) group = r->title;
            ImGui::EndCombo();
        }
    };
    combo("##a", groupA_);
    ImGui::SameLine();
    ImGui::TextUnformatted("->");
    ImGui::SameLine();
    combo("##b", groupB_);
    ImGui::SameLine();
    if (ui::smallButton("Swap")) std::swap(groupA_, groupB_);
    ImGui::SameLine();
    const bool running = job_.valid();
    if (running) {
        ImGui::TextDisabled("comparing...");
        ImGui::SameLine();
        if (ui::smallButton("Cancel")) cancel();
    } else if (ImGui::Button(valid_ ? "Compare again" : "Compare")) {
        autoCompared_ = groupA_ + '\n' + groupB_;
        start();
    }
    const auto statusA = workspace_.analysis().status(groupA_).state, statusB = workspace_.analysis().status(groupB_).state;
    const bool readyA = statusA == AnalysisService::State::Ready, readyB = statusB == AnalysisService::State::Ready;
    // A pair seen for the first time compares itself once both analyses are ready.
    const std::string pair = groupA_ + '\n' + groupB_;
    if (readyA && readyB && !running && autoCompared_ != pair) {
        autoCompared_ = pair;
        start();
    }
    if (!readyA || !readyB) {
        const bool busy = statusA == AnalysisService::State::Running || statusB == AnalysisService::State::Running;
        ui::sameLineIfFits(ui::em(18.f));
        ImGui::TextColored(theme::vec(Col::Warning), busy ? "analysing..." : "code not compared");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Classes, methods and endpoints need the bytecode analysis of both APKs.");
        if (!busy) {
            ImGui::SameLine();
            if (ui::smallButton("Analyse both")) {
                workspace_.startAnalysis(groupA_);
                workspace_.startAnalysis(groupB_);
            }
        }
    }
    if (valid_) {
        ImGui::TextColored(theme::vec(Col::Info), "%s  ->  %s", titleA_.c_str(), titleB_.c_str());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(std::max(ui::em(8.f), ImGui::GetContentRegionAvail().x));
        ImGui::InputTextWithHint("##filter", "Filter the lists", filter_, sizeof filter_);
    }
}

bool DiffPanel::passes(std::string_view text) const { return containsNoCase(text, filter_); }

size_t DiffPanel::sectionCount(Section s) const {
    switch (s) {
    case Summary: return 0;
    case Manifest: return diff_.manifest.size() + diff_.permissionsAdded.size() + diff_.permissionsRemoved.size();
    case Components: return diff_.components.size();
    case Classes: return diff_.classesAdded.size() + diff_.classesRemoved.size() + diff_.classesRenamed.size();
    case Methods: return diff_.methodsChanged.size() + diff_.methodsAdded.size() + diff_.methodsRemoved.size();
    case Resources: return diff_.resources.size();
    case Native: return diff_.natives.size();
    case Libraries: return diff_.libraries.size();
    case Endpoints: return diff_.endpointsAdded.size() + diff_.endpointsRemoved.size();
    case Files: return diff_.entries.size();
    default: return 0;
    }
}

void DiffPanel::drawSectionList() {
    for (int s = 0; s < SectionCount; ++s) {
        const auto sec = static_cast<Section>(s);
        const size_t n = sectionCount(sec);
        char label[64];
        if (sec == Summary) std::snprintf(label, sizeof label, "%s", kSectionNames[s]);
        else std::snprintf(label, sizeof label, "%s (%zu)", kSectionNames[s], n);
        const bool empty = sec != Summary && n == 0;
        if (empty) ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
        if (ImGui::Selectable(label, section_ == sec)) section_ = sec;
        if (empty) ImGui::PopStyleColor();
    }
}

void DiffPanel::drawSummary() {
    ImGui::PushTextWrapPos(0.f);
    const auto line = [](const char* what, size_t n, const char* note = nullptr) {
        if (!n) return;
        ImGui::BulletText("%zu %s%s%s", n, what, note ? " " : "", note ? note : "");
    };
    if (!diff_.manifest.empty()) {
        ImGui::TextUnformatted("Manifest");
        for (const auto& f : diff_.manifest) ImGui::BulletText("%s: %s -> %s", f.field.c_str(), f.a.empty() ? "(none)" : f.a.c_str(), f.b.empty() ? "(none)" : f.b.c_str());
        const bool certChanged = std::any_of(diff_.manifest.begin(), diff_.manifest.end(), [](const auto& f) { return f.field == "certificate SHA-256"; });
        if (certChanged) ui::wrappedColored(theme::vec(Col::Error), "The signing certificate changed: the new APK cannot update the old one in place.");
        ImGui::Spacing();
    }
    ImGui::TextUnformatted("Changes");
    line("permissions added", diff_.permissionsAdded.size());
    line("permissions removed", diff_.permissionsRemoved.size());
    line("components added, removed or changed", diff_.components.size());
    if (diff_.codeCompared) {
        line("classes added", diff_.classesAdded.size());
        line("classes removed", diff_.classesRemoved.size());
        line("classes renamed", diff_.classesRenamed.size(), "(same code, new name: obfuscation)");
        line("methods changed", diff_.methodsChanged.size());
        line("methods with register-only changes (hidden)", diff_.methodsCosmetic);
        line("methods added", diff_.methodsAdded.size());
        line("methods removed", diff_.methodsRemoved.size());
        line("endpoints added", diff_.endpointsAdded.size());
        line("endpoints removed", diff_.endpointsRemoved.size());
    } else {
        ImGui::TextDisabled("Code was not compared: analyse both APKs and compare again.");
    }
    if (diff_.resourcesCompared) line("resources added, removed or changed", diff_.resources.size());
    line("native libraries changed", diff_.natives.size());
    line("bundled libraries added, removed or updated", diff_.libraries.size());
    ImGui::BulletText("%zu files changed, %zu unchanged", diff_.entries.size(), diff_.entriesUnchanged);
    if (diff_.truncated) ui::wrappedColored(theme::vec(Col::Warning), "Some lists were cut at their limit.");
    ImGui::PopTextWrapPos();
}

void DiffPanel::drawSection() {
    const auto keep = [this](std::string_view s) { return passes(s); };
    const auto tableBegin = [](const char* id, int columns) {
        return ImGui::BeginTable(id, columns, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable);
    };
    switch (section_) {
    case Summary: drawSummary(); break;
    case Manifest:
        if (tableBegin("##manifest", 3)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Field");
            ImGui::TableSetupColumn(titleA_.c_str());
            ImGui::TableSetupColumn(titleB_.c_str());
            ImGui::TableHeadersRow();
            for (const auto& f : diff_.manifest) {
                if (!passes(f.field) && !passes(f.a) && !passes(f.b)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(), ImGui::TextUnformatted(f.field.c_str());
                ImGui::TableNextColumn(), ImGui::TextColored(theme::vec(Col::Error), "%s", f.a.c_str());
                ImGui::TableNextColumn(), ImGui::TextColored(theme::vec(Col::Success), "%s", f.b.c_str());
            }
            const auto perms = [&](const std::vector<std::string>& list, bool added) {
                for (const std::string& p : list) {
                    if (!passes(p)) continue;
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(), ImGui::TextUnformatted("permission");
                    ImGui::TableNextColumn();
                    if (!added) ImGui::TextColored(theme::vec(Col::Error), "- %s", p.c_str());
                    ImGui::TableNextColumn();
                    if (added) ImGui::TextColored(theme::vec(Col::Success), "+ %s", p.c_str());
                }
            };
            perms(diff_.permissionsAdded, true);
            perms(diff_.permissionsRemoved, false);
            ImGui::EndTable();
        }
        break;
    case Components:
        if (tableBegin("##components", 3)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Component", ImGuiTableColumnFlags_WidthStretch, 2.f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, ui::em(6.f));
            ImGui::TableSetupColumn("Change", ImGuiTableColumnFlags_WidthStretch, 2.f);
            ImGui::TableHeadersRow();
            for (const auto& c : diff_.components) {
                if (!passes(c.name) && !passes(c.detail)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(), ImGui::TextColored(kindColor(c.kind), "%s %s", kindMark(c.kind), c.name.c_str());
                ImGui::TableNextColumn(), ImGui::TextUnformatted(c.type.c_str());
                ImGui::TableNextColumn(), ImGui::TextWrapped("%s", c.detail.empty() ? ApkDiff::kindName(c.kind) : c.detail.c_str());
            }
            ImGui::EndTable();
        }
        break;
    case Classes:
        if (!diff_.codeCompared) {
            ImGui::TextDisabled("Analyse both APKs to compare their classes.");
            break;
        }
        if (!diff_.classesRenamed.empty() && ImGui::CollapsingHeader(("Renamed (" + std::to_string(diff_.classesRenamed.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
            for (const auto& r : diff_.classesRenamed)
                if (passes(r.from) || passes(r.to)) ImGui::TextColored(kindColor(ApkDiff::Kind::Changed), "~ %s  ->  %s", r.from.c_str(), r.to.c_str());
        }
        if (ImGui::CollapsingHeader(("Added (" + std::to_string(diff_.classesAdded.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen))
            markedList("added", ApkDiff::Kind::Added, diff_.classesAdded, keep);
        if (ImGui::CollapsingHeader(("Removed (" + std::to_string(diff_.classesRemoved.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen))
            markedList("removed", ApkDiff::Kind::Removed, diff_.classesRemoved, keep);
        break;
    case Methods: drawMethods(); break;
    case Resources:
        if (!diff_.resourcesCompared) {
            ImGui::TextDisabled("One of the APKs has no resources.arsc.");
            break;
        }
        if (tableBegin("##resources", 3)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Resource");
            ImGui::TableSetupColumn(titleA_.c_str());
            ImGui::TableSetupColumn(titleB_.c_str());
            ImGui::TableHeadersRow();
            std::vector<const ApkDiff::ResourceChange*> rows;
            for (const auto& r : diff_.resources)
                if (passes(r.name) || passes(r.a) || passes(r.b)) rows.push_back(&r);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(rows.size()));
            while (clipper.Step())
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    const auto& r = *rows[static_cast<size_t>(i)];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(), ImGui::TextColored(kindColor(r.kind), "%s %s", kindMark(r.kind), r.name.c_str());
                    ImGui::TableNextColumn(), ImGui::TextUnformatted(r.a.c_str());
                    ImGui::TableNextColumn(), ImGui::TextUnformatted(r.b.c_str());
                }
            ImGui::EndTable();
        }
        break;
    case Native:
        for (size_t i = 0; i < diff_.natives.size(); ++i) {
            const auto& n = diff_.natives[i];
            if (!passes(n.path)) continue;
            char header[512];
            std::snprintf(header, sizeof header, "%s %s  (%llu -> %llu bytes, +%zu / -%zu exports)###n%zu", kindMark(n.kind), n.path.c_str(),
                          static_cast<unsigned long long>(n.sizeA), static_cast<unsigned long long>(n.sizeB), n.exportsAdded.size(),
                          n.exportsRemoved.size(), i);
            ImGui::PushStyleColor(ImGuiCol_Text, kindColor(n.kind));
            const bool open = ImGui::CollapsingHeader(header);
            ImGui::PopStyleColor();
            if (!open) continue;
            ImGui::Indent();
            for (const auto& s : n.exportsAdded) ImGui::TextColored(kindColor(ApkDiff::Kind::Added), "+ %s", s.c_str());
            for (const auto& s : n.exportsRemoved) ImGui::TextColored(kindColor(ApkDiff::Kind::Removed), "- %s", s.c_str());
            if (n.exportsAdded.empty() && n.exportsRemoved.empty()) ImGui::TextDisabled("Same exported symbols; the code changed.");
            ImGui::Unindent();
        }
        if (diff_.natives.empty()) ImGui::TextDisabled("No native library changed.");
        break;
    case Libraries:
        if (tableBegin("##libs", 4)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch, 2.f);
            ImGui::TableSetupColumn(titleA_.c_str());
            ImGui::TableSetupColumn(titleB_.c_str());
            ImGui::TableSetupColumn("Classes");
            ImGui::TableHeadersRow();
            for (const auto& l : diff_.libraries) {
                if (!passes(l.name)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(), ImGui::TextColored(kindColor(l.kind), "%s %s", kindMark(l.kind), l.name.c_str());
                ImGui::TableNextColumn(), ImGui::TextUnformatted(l.kind == ApkDiff::Kind::Added ? "" : l.versionA.empty() ? "present" : l.versionA.c_str());
                ImGui::TableNextColumn(), ImGui::TextUnformatted(l.kind == ApkDiff::Kind::Removed ? "" : l.versionB.empty() ? "present" : l.versionB.c_str());
                ImGui::TableNextColumn(), ImGui::Text("%zu -> %zu", l.classesA, l.classesB);
            }
            ImGui::EndTable();
        }
        break;
    case Endpoints:
        if (!diff_.codeCompared) {
            ImGui::TextDisabled("Analyse both APKs to compare their endpoints.");
            break;
        }
        if (ImGui::CollapsingHeader(("Added (" + std::to_string(diff_.endpointsAdded.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen))
            markedList("eadded", ApkDiff::Kind::Added, diff_.endpointsAdded, keep);
        if (ImGui::CollapsingHeader(("Removed (" + std::to_string(diff_.endpointsRemoved.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen))
            markedList("eremoved", ApkDiff::Kind::Removed, diff_.endpointsRemoved, keep);
        break;
    case Files:
        if (tableBegin("##files", 2)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Entry", ImGuiTableColumnFlags_WidthStretch, 3.f);
            ImGui::TableSetupColumn("Size");
            ImGui::TableHeadersRow();
            std::vector<const ApkDiff::EntryChange*> rows;
            for (const auto& e : diff_.entries)
                if (passes(e.path)) rows.push_back(&e);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(rows.size()));
            while (clipper.Step())
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    const auto& e = *rows[static_cast<size_t>(i)];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(), ImGui::TextColored(kindColor(e.kind), "%s %s", kindMark(e.kind), e.path.c_str());
                    ImGui::TableNextColumn(), ImGui::Text("%llu -> %llu", static_cast<unsigned long long>(e.sizeA), static_cast<unsigned long long>(e.sizeB));
                }
            ImGui::EndTable();
        }
        break;
    default: break;
    }
}

void DiffPanel::openMethod(const std::string& signature, bool sideB) {
    workspace_.requestMethodView({sideB ? groupB_ : groupA_, signature, "source"});
    if (showPanel_) showPanel_("Analysis");
}

void DiffPanel::drawMethods() {
    if (!diff_.codeCompared) {
        ImGui::TextDisabled("Analyse both APKs to compare their methods.");
        return;
    }
    const float listHeight = method_ >= 0 ? ImGui::GetContentRegionAvail().y * 0.38f : 0.f;
    ImGui::BeginChild("##methodLists", ImVec2(0, listHeight));
    char header[96];
    std::snprintf(header, sizeof header, "Changed (%zu)###changed", diff_.methodDetails.size());
    if (ImGui::CollapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen) &&
        ImGui::BeginTable("##changed", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthStretch, 3.f);
        ImGui::TableSetupColumn("+/-", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        ImGui::TableSetupColumn("What changed", ImGuiTableColumnFlags_WidthStretch, 3.f);
        std::vector<int> rows;
        for (int i = 0; i < static_cast<int>(diff_.methodDetails.size()); ++i) {
            const auto& m = diff_.methodDetails[static_cast<size_t>(i)];
            if (passes(m.signature) || passes(m.summary)) rows.push_back(i);
        }
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows.size()));
        while (clipper.Step())
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                const int i = rows[static_cast<size_t>(r)];
                const auto& m = diff_.methodDetails[static_cast<size_t>(i)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                if (ImGui::Selectable(m.signature.c_str(), method_ == i, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) openMethod(m.signature, true);
                    else selectMethod(i);
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                ImGui::TextColored(theme::vec(Col::Success), "+%d", m.added);
                ImGui::SameLine();
                ImGui::TextColored(theme::vec(Col::Error), "-%d", m.removed);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(m.summary.c_str());
            }
        ImGui::EndTable();
    }
    const auto keep = [this](std::string_view s) { return passes(s); };
    std::snprintf(header, sizeof header, "Added (%zu)###madded", diff_.methodsAdded.size());
    if (ImGui::CollapsingHeader(header))
        markedList("madded", ApkDiff::Kind::Added, diff_.methodsAdded, keep, [this](const std::string& s) { openMethod(s, true); });
    std::snprintf(header, sizeof header, "Removed (%zu)###mremoved", diff_.methodsRemoved.size());
    if (ImGui::CollapsingHeader(header))
        markedList("mremoved", ApkDiff::Kind::Removed, diff_.methodsRemoved, keep, [this](const std::string& s) { openMethod(s, false); });
    if (diff_.methodsCosmetic) ImGui::TextDisabled("%zu more differ only in register allocation (not listed).", diff_.methodsCosmetic);
    ImGui::EndChild();
    if (method_ >= 0) {
        ImGui::Separator();
        drawSideBySide();
    }
}

void DiffPanel::selectMethod(int index) {
    method_ = index;
    rows_.clear();
    changes_.clear();
    sideError_.clear();
    textA_.clear();
    textB_.clear();
    if (index < 0 || index >= static_cast<int>(diff_.methodDetails.size()) || !analysisA_ || !analysisB_) return;
    const std::string& sig = diff_.methodDetails[static_cast<size_t>(index)].signature;
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(sig, cls, name, proto)) return;
    const auto defsA = analysisA_->findMethodDefs(cls, name, proto);
    const auto defsB = analysisB_->findMethodDefs(cls, name, proto);
    if (defsA.empty() || defsB.empty()) {
        sideError_ = "The method has no bytecode on one side.";
        return;
    }
    if (decompiled_) {
        textA_ = decompiler::toText(decompiler::decompileMethod(*analysisA_, defsA.front()));
        textB_ = decompiler::toText(decompiler::decompileMethod(*analysisB_, defsB.front()));
    } else {
        textA_ = ApkDiff::normalizedListing(*analysisA_, defsA.front());
        textB_ = ApkDiff::normalizedListing(*analysisB_, defsB.front());
    }
    linesA_ = linediff::splitLines(textA_);
    linesB_ = linediff::splitLines(textB_);
    rows_ = linediff::sideBySide(linediff::diff(linesA_, linesB_));
    for (int r = 0; r < static_cast<int>(rows_.size()); ++r)
        if (rows_[static_cast<size_t>(r)].kind != linediff::Op::Equal && (r == 0 || rows_[static_cast<size_t>(r - 1)].kind == linediff::Op::Equal))
            changes_.push_back(r);
    scrollToRow_ = changes_.empty() ? -1 : changes_.front();
    changeCursor_ = 0;
}

void DiffPanel::drawSideBySide() {
    const auto& m = diff_.methodDetails[static_cast<size_t>(method_)];
    const char* views[] = {"Smali", "Decompiled"};
    int view = decompiled_ ? 1 : 0;
    ImGui::PushID("sbs");
    if (ui::segmented(views, 2, view)) {
        decompiled_ = view == 1;
        selectMethod(method_);
    }
    ImGui::PopID();
    ImGui::SameLine();
    // Previous / next change block, relative to the last jump.
    const int blocks = static_cast<int>(changes_.size());
    if (ui::smallButton("Prev change") && blocks) {
        changeCursor_ = (changeCursor_ + blocks - 1) % blocks;
        scrollToRow_ = changes_[static_cast<size_t>(changeCursor_)];
    }
    ImGui::SameLine();
    if (ui::smallButton("Next change") && blocks) {
        changeCursor_ = (changeCursor_ + 1) % blocks;
        scrollToRow_ = changes_[static_cast<size_t>(changeCursor_)];
    }
    ImGui::SameLine();
    if (ui::smallButton(ui::icon(icons::OPEN, "Open new").c_str())) openMethod(m.signature, true);
    ImGui::SameLine();
    ImGui::TextDisabled("%zu change blocks", changes_.size());
    if (!m.callsAdded.empty() || !m.callsRemoved.empty() || !m.stringsAdded.empty() || !m.stringsRemoved.empty()) {
        std::string tip;
        for (const auto& c : m.callsAdded) tip += "+ call " + c + "\n";
        for (const auto& c : m.callsRemoved) tip += "- call " + c + "\n";
        for (const auto& s : m.stringsAdded) tip += "+ \"" + s + "\"\n";
        for (const auto& s : m.stringsRemoved) tip += "- \"" + s + "\"\n";
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Info), "calls / strings");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip.c_str());
    }
    if (!sideError_.empty()) {
        ImGui::TextColored(theme::vec(Col::Warning), "%s", sideError_.c_str());
        return;
    }
    ImGui::PushFont(Theme::monoFont());
    if (ImGui::BeginTable("##sbs", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        const float numW = ImGui::CalcTextSize("00000").x;
        ImGui::TableSetupColumn("##na", ImGuiTableColumnFlags_WidthFixed, numW);
        ImGui::TableSetupColumn(titleA_.c_str(), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##nb", ImGuiTableColumnFlags_WidthFixed, numW);
        ImGui::TableSetupColumn(titleB_.c_str(), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        const ImU32 del = theme::u32(Col::Error, 0.22f), ins = theme::u32(Col::Success, 0.22f), chg = theme::u32(Col::Warning, 0.18f);
        const float rowH = ImGui::GetTextLineHeightWithSpacing();
        if (scrollToRow_ >= 0) {
            ImGui::SetScrollY(std::max(0.f, (static_cast<float>(scrollToRow_) - 3.f) * rowH));
            scrollToRow_ = -1;
        }
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows_.size()), rowH);
        while (clipper.Step())
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                const linediff::Row& row = rows_[static_cast<size_t>(r)];
                ImGui::TableNextRow(ImGuiTableRowFlags_None, rowH);
                const ImU32 bgA = row.kind == linediff::Op::Equal ? 0 : row.changed ? chg : row.a >= 0 ? del : 0;
                const ImU32 bgB = row.kind == linediff::Op::Equal ? 0 : row.changed ? chg : row.b >= 0 ? ins : 0;
                ImGui::TableNextColumn();
                if (row.a >= 0) ImGui::TextDisabled("%d", row.a + 1);
                ImGui::TableNextColumn();
                if (bgA) ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, bgA);
                // Long lines are clipped by the column: hovering shows them whole.
                const auto cell = [](std::string_view line) {
                    ImGui::TextUnformatted(line.data(), line.data() + line.size());
                    if (ImGui::IsItemHovered() && ImGui::CalcTextSize(line.data(), line.data() + line.size()).x > ImGui::GetColumnWidth()) {
                        ImGui::BeginTooltip();
                        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 50.f);
                        ImGui::TextUnformatted(line.data(), line.data() + line.size());
                        ImGui::PopTextWrapPos();
                        ImGui::EndTooltip();
                    }
                };
                if (row.a >= 0) cell(linesA_[static_cast<size_t>(row.a)]);
                ImGui::TableNextColumn();
                if (row.b >= 0) ImGui::TextDisabled("%d", row.b + 1);
                ImGui::TableNextColumn();
                if (bgB) ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, bgB);
                if (row.b >= 0) cell(linesB_[static_cast<size_t>(row.b)]);
            }
        ImGui::EndTable();
    }
    ImGui::PopFont();
}
