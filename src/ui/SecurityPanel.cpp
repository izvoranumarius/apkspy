#include "ui/SecurityPanel.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include "analysis/SourceMap.hpp"
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "core/TextDiff.hpp"
#include "ui/UiUtil.hpp"

using security::Severity;

namespace {

ImVec4 severityColor(Severity s) {
    switch (s) {
    case Severity::Critical: return theme::vec(Col::Red);
    case Severity::High: return theme::vec(Col::Orange);
    case Severity::Medium: return theme::vec(Col::Yellow);
    case Severity::Low: return theme::vec(Col::Blue);
    case Severity::Info: return theme::vec(Col::TextMuted);
    }
    return theme::vec(Col::Text);
}

bool containsNoCase(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           }) != hay.end();
}

std::string locationLabel(const security::Location& l) {
    switch (l.kind) {
    case security::Location::Kind::Method: {
        std::string cls, name, proto;
        if (!ApkAnalysis::splitMethodRef(l.ref, cls, name, proto)) return l.ref;
        std::string c = DexFile::descriptorToJava(cls);
        const size_t dot = c.rfind('.');
        if (dot != std::string::npos) c = c.substr(dot + 1);
        return c + "." + name + "()";
    }
    case security::Location::Kind::Manifest: return "Manifest: " + l.ref;
    case security::Location::Kind::Resource: return "@" + l.ref;
    case security::Location::Kind::File: return l.line >= 0 ? l.ref + ":" + std::to_string(l.line + 1) : l.ref;
    case security::Location::Kind::Class: return DexFile::descriptorToJava(l.ref);
    default: return "";
    }
}

}  // namespace

SecurityPanel::~SecurityPanel() { cancel(); }

void SecurityPanel::cancel() {
    if (cancel_) cancel_->store(true);
    if (job_.valid()) job_.wait();
    job_ = {};
    cancel_.reset();
}

void SecurityPanel::start(const std::string& group) {
    cancel();
    security::Input in;
    if (!workspace_.securityInput(group, in)) return;
    info_ = in.info;
    scannedWith_ = in.analysis.get();
    selected_ = -1;
    auto flag = std::make_shared<std::atomic<bool>>(false);
    auto progress = std::make_shared<std::atomic<size_t>>(0);
    cancel_ = flag;
    progress_ = progress;
    job_ = std::async(std::launch::async, [in = std::move(in), flag, progress] { return security::scan(in, flag.get(), progress.get()); });
}

void SecurityPanel::drawContents() {
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.empty()) {
        ImGui::TextDisabled("Open an APK to review its security.");
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
        cancel();
        group_ = apk.title;
        scanned_ = false;
        report_ = {};
    }
    // The bytecode rules need the analysis: start it, and scan again once it is ready.
    if (workspace_.analysis().status(group_).state == AnalysisService::State::None) workspace_.startAnalysis(group_);
    const auto analysis = workspace_.analysis().get(group_);
    if (!job_.valid() && (!scanned_ || (analysis && analysis.get() != scannedWith_))) start(group_);
    if (job_.valid() && job_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        report_ = job_.get();
        cancel_.reset();
        scanned_ = true;
        categories_.clear();
        for (const auto& f : report_.findings)
            if (const security::Rule* r = security::rule(f.rule))
                if (std::find(categories_.begin(), categories_.end(), r->category) == categories_.end()) categories_.push_back(r->category);
        std::sort(categories_.begin(), categories_.end());
    }
    drawToolbar();
    drawExport();
    if (!scanned_ && job_.valid()) return;
    const float detailsHeight = selected_ >= 0 ? std::min(ui::em(16.f), ImGui::GetContentRegionAvail().y * 0.45f) : 0.f;
    ImGui::BeginChild("##findings", ImVec2(0, -detailsHeight));
    drawTable();
    ImGui::EndChild();
    if (selected_ >= 0 && selected_ < static_cast<int>(report_.findings.size())) {
        ImGui::BeginChild("##details", ImVec2(0, 0), ImGuiChildFlags_Borders);
        drawDetails(report_.findings[static_cast<size_t>(selected_)]);
        ImGui::EndChild();
    }
}

bool SecurityPanel::visible(const security::Finding& f) const {
    if (!showSeverity_[static_cast<int>(f.severity)]) return false;
    if (hideLibraries_ && !f.library.empty()) return false;
    if (category_ > 0) {
        const security::Rule* r = security::rule(f.rule);
        if (!r || categories_[static_cast<size_t>(category_ - 1)] != r->category) return false;
    }
    const std::string_view q = filter_;
    return q.empty() || containsNoCase(f.title, q) || containsNoCase(f.evidence, q) || containsNoCase(f.location.ref, q) ||
           containsNoCase(f.library, q);
}

void SecurityPanel::drawToolbar() {
    if (job_.valid()) {
        const float frac = progress_ ? static_cast<float>(progress_->load()) / 100.f : 0.f;
        ImGui::ProgressBar(frac, ImVec2(ui::em(12.f), 0), "scanning...");
        ImGui::SameLine();
        if (ui::smallButton("Cancel")) cancel();
        if (!scanned_) return;
        ImGui::SameLine();
    } else if (ui::smallButton(ui::icon(icons::REFRESH, "Scan again").c_str())) {
        start(group_);
    }
    // Severity chips with their counts.
    for (int s = static_cast<int>(Severity::Critical); s >= 0; --s) {
        const auto sev = static_cast<Severity>(s);
        const auto n = std::count_if(report_.findings.begin(), report_.findings.end(),
                                     [&](const security::Finding& f) { return f.severity == sev && (!hideLibraries_ || f.library.empty()); });
        char label[48];
        std::snprintf(label, sizeof label, "%s %lld###sev%d", security::severityName(sev), static_cast<long long>(n), s);
        ImGui::PushStyleColor(ImGuiCol_CheckMark, severityColor(sev));
        ui::sameLineIfFits(ui::checkboxWidth(label));
        ImGui::Checkbox(label, &showSeverity_[s]);
        ImGui::PopStyleColor();
    }
    ui::sameLineIfFits(ui::em(12.f));
    ImGui::SetNextItemWidth(ui::em(10.f));
    if (ImGui::BeginCombo("##cat", category_ == 0 ? "All categories" : categories_[static_cast<size_t>(category_ - 1)].c_str())) {
        if (ImGui::Selectable("All categories", category_ == 0)) category_ = 0;
        for (size_t i = 0; i < categories_.size(); ++i)
            if (ImGui::Selectable(categories_[i].c_str(), category_ == static_cast<int>(i + 1))) category_ = static_cast<int>(i + 1);
        ImGui::EndCombo();
    }
    if (category_ > static_cast<int>(categories_.size())) category_ = 0;
    ui::flowCheckbox("Hide library code", &hideLibraries_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hide findings in bundled third-party libraries (OkHttp, Firebase, ads SDKs...)");
    ui::sameLineIfFits(ui::em(14.f));
    ImGui::SetNextItemWidth(ui::em(13.f));
    ImGui::InputTextWithHint("##filter", "Filter findings", filter_, sizeof filter_);
    ImGui::SameLine();
    if (ui::smallButton(ui::icon(icons::SAVE, "Export").c_str())) ImGui::OpenPopup("##export");
    if (ImGui::BeginPopup("##export")) {
        if (ImGui::MenuItem("Markdown report...")) {
            exportJson_ = false;
            exportBrowser_.open(FileBrowser::Mode::SaveFile);
            exportBrowser_.setDefaultName(info_.packageName + "-security.md");
        }
        if (ImGui::MenuItem("JSON report...")) {
            exportJson_ = true;
            exportBrowser_.open(FileBrowser::Mode::SaveFile);
            exportBrowser_.setDefaultName(info_.packageName + "-security.json");
        }
        ImGui::EndPopup();
    }
    if (!report_.bytecodeScanned && scanned_) {
        ImGui::TextColored(theme::vec(Col::Warning), "Manifest, resources and files only: the bytecode rules run once the analysis is ready.");
    }
}

void SecurityPanel::drawExport() {
    std::string picked;
    if (exportBrowser_.render(), !exportBrowser_.takeAccepted(picked)) return;
    std::ofstream out(pathutil::fromUtf8(pathutil::normalize(picked)), std::ios::binary);
    if (!out) {
        workspace_.log("Export failed: cannot write " + picked, "security");
        return;
    }
    out << (exportJson_ ? security::toJson(report_, info_) : security::toMarkdown(report_, info_));
    workspace_.log("Security report written to " + picked, "security");
}

void SecurityPanel::drawTable() {
    if (report_.findings.empty()) {
        ImGui::TextDisabled(scanned_ ? "No findings." : "Scanning...");
        return;
    }
    std::vector<int> rows;
    for (int i = 0; i < static_cast<int>(report_.findings.size()); ++i)
        if (visible(report_.findings[static_cast<size_t>(i)])) rows.push_back(i);
    if (!ImGui::BeginTable("##table", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
    ImGui::TableSetupColumn("Conf.", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
    ImGui::TableSetupColumn("Finding", ImGuiTableColumnFlags_WidthStretch, 3.f);
    ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 2.f);
    ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthFixed, ui::em(7.f));
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()));
    while (clipper.Step())
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const int i = rows[static_cast<size_t>(r)];
            const security::Finding& f = report_.findings[static_cast<size_t>(i)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            ImGui::PushStyleColor(ImGuiCol_Text, severityColor(f.severity));
            if (ImGui::Selectable(security::severityName(f.severity), selected_ == i,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_ = i;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) navigate(f);
            }
            ImGui::PopStyleColor();
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%d%%", f.confidence);
            ImGui::TableNextColumn();
            if (f.library.empty()) ImGui::TextUnformatted(f.title.c_str());
            else ImGui::TextDisabled("%s", f.title.c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.evidence.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(locationLabel(f.location).c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", f.library.c_str());
        }
    ImGui::EndTable();
}

void SecurityPanel::drawDetails(const security::Finding& f) {
    const security::Rule* r = security::rule(f.rule);
    ImGui::TextColored(severityColor(f.severity), "%s", security::severityName(f.severity));
    ImGui::SameLine();
    ImGui::TextUnformatted(f.title.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("confidence %d%%%s%s", f.confidence, r ? "  " : "", r ? (std::string(r->cwe) + "  " + r->masvs).c_str() : "");
    ImGui::PushTextWrapPos(0.f);
    if (r) ImGui::TextUnformatted(r->description);
    ImGui::Spacing();
    ImGui::TextDisabled("Evidence");
    ImGui::PushFont(Theme::monoFont());
    ImGui::TextUnformatted(f.evidence.c_str());
    ImGui::PopFont();
    if (ImGui::BeginPopupContextItem("##evidence")) {
        if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(f.evidence.c_str());
        ImGui::EndPopup();
    }
    if (f.location.kind != security::Location::Kind::None) {
        ImGui::TextDisabled("Location");
        ImGui::SameLine();
        if (ImGui::SmallButton((locationLabel(f.location) + "##loc").c_str())) navigate(f);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\nClick to open", f.location.ref.c_str());
    }
    if (!f.library.empty()) ImGui::TextDisabled("In bundled library: %s", f.library.c_str());
    if (r) {
        ImGui::Spacing();
        ImGui::TextDisabled("Recommendation");
        ImGui::TextUnformatted(r->recommendation);
    }
    ImGui::PopTextWrapPos();
}

void SecurityPanel::navigate(const security::Finding& f) {
    const security::Location& l = f.location;
    Root* apk = workspace_.rootByGroup(group_, Root::Kind::Apk);
    if (!apk) return;
    // Opens an APK entry and highlights the first line containing `needle`.
    const auto openEntry = [&](const std::string& path, int line, const std::string& needle) {
        const TreeNode* node = apk->tree ? apk->tree->findByPath(path) : nullptr;
        if (!node) {
            workspace_.log("Not in the APK: " + path, "security");
            return;
        }
        workspace_.openNode(*apk, *node, line);
        if (needle.empty() || line >= 0) return;
        for (const auto& d : workspace_.documents())
            if (d->node() == node)
                for (size_t i = 0; i < d->lineCount(); ++i)
                    if (d->line(i).find(needle) != std::string_view::npos) {
                        d->goTo(static_cast<int>(i));
                        return;
                    }
    };
    switch (l.kind) {
    case security::Location::Kind::Method: {
        const auto analysis = workspace_.analysis().get(group_);
        std::string cls, name, proto;
        if (!analysis || !ApkAnalysis::splitMethodRef(l.ref, cls, name, proto)) return;
        const auto defs = analysis->findMethodDefs(cls, name, proto);
        if (defs.empty()) return;
        // jadx's Java at the instruction's line when available, else the smali listing at the instruction.
        if (Document* doc = workspace_.openClassSource(group_, DexFile::descriptorToJava(cls), Workspace::OpenMode::Preview)) {
            std::vector<std::string_view> lines;
            for (size_t i = 0; i < doc->lineCount(); ++i) lines.push_back(doc->line(i));
            const sourcemap::JavaFile file(lines);
            int line = sourcemap::bytecodeToJava(*analysis, file, defs.front(), l.pc);
            if (line < 0) line = file.findMethod(DexFile::descriptorToJava(cls), name, sourcemap::paramSimpleTypes(proto));
            if (line >= 0) doc->goTo(line);
        } else {
            workspace_.openMethodListing(group_, *analysis, defs.front(), l.pc);
        }
        break;
    }
    case security::Location::Kind::Manifest: {
        // The component's name, or the attribute the finding is about.
        std::string needle = l.ref;
        if (f.rule == "manifest-debuggable") needle = "android:debuggable";
        else if (f.rule == "manifest-test-only") needle = "android:testOnly";
        else if (f.rule == "manifest-allow-backup") needle = "<application";
        else if (f.rule == "manifest-cleartext") needle = "<application";
        else if (f.rule == "manifest-old-target") needle = "targetSdkVersion";
        else needle = "\"" + l.ref + "\"";
        openEntry("AndroidManifest.xml", -1, needle);
        break;
    }
    case security::Location::Kind::Resource: {
        // resources.arsc has no text: show the value through the Analysis panel's Resources view instead.
        workspace_.log("@" + l.ref + " = " + f.evidence, "security");
        if (showPanel_) showPanel_("Output");
        return;
    }
    case security::Location::Kind::File: openEntry(l.ref, l.line, {}); break;
    default: return;
    }
    if (showPanel_) showPanel_("Editor");
}
