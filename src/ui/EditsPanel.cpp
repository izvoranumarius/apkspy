#include "ui/EditsPanel.hpp"
#include <cstdio>
#include <fstream>
#include "analysis/ApkAnalysis.hpp"
#include "core/Paths.hpp"
#include "ui/UiUtil.hpp"

namespace {
// "# Lcom/a/B;->name(proto)ret  (classes.dex)" -> "Lcom/a/B;" (method listing header).
std::string fragmentOwner(std::string_view text) {
    if (text.rfind("# L", 0) != 0) return {};
    const size_t arrow = text.find(";->");
    const size_t eol = text.find('\n');
    if (arrow == std::string_view::npos || (eol != std::string_view::npos && arrow > eol)) return {};
    return std::string(text.substr(2, arrow - 1));
}

bool hasClassDirective(std::string_view text) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        if (e == std::string_view::npos) e = text.size();
        std::string_view l = text.substr(pos, e - pos);
        const size_t p = l.find_first_not_of(" \t");
        if (p != std::string_view::npos) {
            l.remove_prefix(p);
            if (l.rfind(".class", 0) == 0) return true;
            if (l[0] != '#') return false;  // first non-comment line decides
        }
        pos = e + 1;
    }
    return false;
}
}  // namespace

const smali::ClassUniverse* EditsPanel::universeFor(const std::string& group) {
    auto a = workspace_.analysis().get(group);
    if (!a) return nullptr;
    Universe& u = universes_[group];
    if (u.analysis != a || !u.universe) {
        std::vector<std::shared_ptr<const DexFile>> dexes(a->dexes().begin(), a->dexes().end());
        u.universe = std::make_unique<smali::DexUniverse>(std::move(dexes));
        u.analysis = a;
    }
    return u.universe.get();
}

std::vector<edits::EditedFile> EditsPanel::collect() {
    workspace_.refreshEdits();
    std::vector<edits::EditedFile> out;
    for (const auto& r : workspace_.editRecords()) {
        edits::EditedFile f;
        f.path = r.display;
        f.original = r.original;
        f.edited = r.current;
        // Single-method listings are validated inside their class.
        if (f.isSmali() && !hasClassDirective(f.edited))
            if (const std::string owner = fragmentOwner(f.edited); !owner.empty())
                if (auto a = workspace_.analysis().get(r.group))
                    if (const auto* c = a->findClass(owner))
                        if (auto s = edits::spliceMethod(a->disassembleClass(*c), f.edited)) {
                            f.validationText = std::move(s->text);
                            f.validationLineOffset = s->lineOffset;
                            f.fragmentLines = s->fragmentLines;
                        }
        out.push_back(std::move(f));
    }
    return out;
}

void EditsPanel::rebuild() {
    const auto files = collect();
    const auto& records = workspace_.editRecords();
    edits::EditReport rep;
    rep.files.resize(files.size());
    // One report per APK (each validated against its own classes), merged
    // back into record order.
    std::map<std::string, std::vector<size_t>> byGroup;
    for (size_t i = 0; i < records.size() && i < files.size(); ++i) byGroup[records[i].group].push_back(i);
    for (const auto& [group, idx] : byGroup) {
        std::vector<edits::EditedFile> part;
        for (size_t i : idx) part.push_back(files[i]);
        const smali::ClassUniverse* u = validate_ ? universeFor(group) : nullptr;
        edits::EditReport r = edits::buildReport(part, u);
        for (size_t k = 0; k < idx.size(); ++k) rep.files[idx[k]] = std::move(r.files[k]);
    }
    for (const auto& f : rep.files) {
        if (f.changed) ++rep.changedFiles;
        rep.added += f.added;
        rep.removed += f.removed;
        rep.errors += static_cast<int>(f.errors.size());
        rep.warnings += static_cast<int>(f.warnings.size());
    }
    report_ = std::move(rep);
    if (selected_ >= static_cast<int>(report_.files.size())) selected_ = -1;
}

void EditsPanel::doExport(const std::string& dir) {
    const auto files = collect();
    edits::ExportOptions o;
    o.overwrite = overwrite_;
    o.writePatch = writePatch_;
    const auto r = edits::exportEdits(files, pathutil::fromUtf8(dir), o);
    char buf[256];
    std::snprintf(buf, sizeof buf, "Exported %d edited file(s) to %s%s", r.written, dir.c_str(), r.patchWritten ? " (+ edits.patch)" : "");
    status_ = buf;
    if (!r.error.empty()) status_ += " - " + r.error;
    for (const auto& it : r.items)
        if (it.status == edits::ExportItem::Status::Exists || it.status == edits::ExportItem::Status::Failed ||
            it.status == edits::ExportItem::Status::InvalidPath)
            workspace_.log("Export: " + it.path + ": " + it.reason);
    if (r.failed) status_ += " - " + std::to_string(r.failed) + " not written (see Output)";
    workspace_.log(status_);
}

void EditsPanel::saveReport(const std::string& file) {
    std::ofstream out(pathutil::fromUtf8(file), std::ios::binary);
    const std::string text = edits::renderText(report_);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    status_ = out ? "Report saved to " + file : "Could not write " + file;
    workspace_.log(status_);
}

void EditsPanel::drawDiff(const std::string& diff) {
    ImGui::PushFont(Theme::monoFont());
    size_t pos = 0;
    while (pos < diff.size()) {
        size_t e = diff.find('\n', pos);
        if (e == std::string::npos) e = diff.size();
        const std::string_view l(diff.data() + pos, e - pos);
        ImVec4 col = ImGui::GetStyleColorVec4(ImGuiCol_Text);
        if (l.rfind("+++", 0) == 0 || l.rfind("---", 0) == 0) col = theme::vec(Col::TextMuted);
        else if (l.rfind("@@", 0) == 0) col = theme::vec(Col::Info);
        else if (!l.empty() && l[0] == '+') col = theme::vec(Col::Success);
        else if (!l.empty() && l[0] == '-') col = theme::vec(Col::Error);
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextUnformatted(l.data(), l.data() + l.size());
        ImGui::PopStyleColor();
        pos = e + 1;
    }
    ImGui::PopFont();
}

void EditsPanel::drawContents() {
    // Rebuild on change, at most a few times a second while typing.
    const auto now = std::chrono::steady_clock::now();
    const bool changed = builtEdits_ != workspace_.editsVersion() || builtSerial_ != Document::editSerial() ||
                         builtState_ != workspace_.stateVersion();
    // Typing is throttled; a change of the record SET (revert, removal, project open) is not: the
    // rows index the workspace's records, so a stale list could point a click at the wrong file.
    const bool recordsChanged = builtEdits_ != workspace_.editsVersion();
    if (changed && (recordsChanged || now - lastBuild_ > std::chrono::milliseconds(400))) {
        builtEdits_ = workspace_.editsVersion();
        builtSerial_ = Document::editSerial();
        builtState_ = workspace_.stateVersion();
        lastBuild_ = now;
        rebuild();
    }

    const bool any = report_.changedFiles > 0;
    ImGui::BeginDisabled(!any);
    if (ui::smallButton("Export edited files...")) exportBrowser_.open(FileBrowser::Mode::SelectFolder);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Writes the edited source files (text only) into a folder you pick");
    ImGui::SameLine();
    if (ui::smallButton("Save report...")) {
        reportBrowser_.open(FileBrowser::Mode::SaveFile);
        reportBrowser_.setDefaultName("edit-report.txt");
    }
    ImGui::SameLine();
    if (ui::smallButton("Copy report")) {
        ImGui::SetClipboardText(edits::renderText(report_).c_str());
        status_ = "Report copied to the clipboard";
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ui::smallButton("Forget unchanged")) workspace_.forgetUnchangedEdits();
    ui::flowCheckbox("Overwrite", &overwrite_);
    ui::flowCheckbox("edits.patch", &writePatch_);
    if (ui::flowCheckbox("Validate smali", &validate_)) builtEdits_ = UINT64_MAX;

    std::string picked;
    if (exportBrowser_.render(), exportBrowser_.takeAccepted(picked)) doExport(picked);
    if (reportBrowser_.render(), reportBrowser_.takeAccepted(picked)) saveReport(picked);

    if (report_.files.empty()) {
        ImGui::TextDisabled("No edits yet. Use Edit on a decompiled file or a smali listing.");
        return;
    }
    ImGui::Text("%d changed file(s), +%d -%d, ", report_.changedFiles, report_.added, report_.removed);
    ImGui::SameLine(0, 0);
    ImGui::TextColored(report_.errors ? theme::vec(Col::Error) : theme::vec(Col::TextMuted), "%d error(s)", report_.errors);
    ImGui::SameLine();
    ImGui::TextColored(report_.warnings ? theme::vec(Col::Warning) : theme::vec(Col::TextMuted), "%d warning(s)", report_.warnings);
    if (!status_.empty()) ImGui::TextDisabled("%s", status_.c_str());

    const float listH = std::min(ImGui::GetContentRegionAvail().y * 0.4f,
                                 ImGui::GetFrameHeightWithSpacing() * (static_cast<float>(report_.files.size()) + 1.5f));
    if (ImGui::BeginTable("##edits", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV,
                          ImVec2(0, listH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("+", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
        ImGui::TableSetupColumn("-", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
        ImGui::TableSetupColumn("Errors", ImGuiTableColumnFlags_WidthFixed, ui::em(4.f));
        ImGui::TableSetupColumn("Warnings", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        ImGui::TableHeadersRow();
        for (int i = 0; i < static_cast<int>(report_.files.size()); ++i) {
            const auto& f = report_.files[static_cast<size_t>(i)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            if (!f.changed) ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
            if (ImGui::Selectable(f.path.c_str(), selected_ == i, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_ = i;
                if (ImGui::IsMouseDoubleClicked(0)) workspace_.openEdit(static_cast<size_t>(i), 0);
            }
            if (!f.changed) ImGui::PopStyleColor();
            if (ImGui::BeginPopupContextItem("##row")) {
                if (ImGui::MenuItem("Open")) workspace_.openEdit(static_cast<size_t>(i), 0);
                if (ImGui::MenuItem("Copy diff", nullptr, false, f.changed)) ImGui::SetClipboardText(f.diff.c_str());
                ImGui::Separator();
                if (ImGui::MenuItem("Revert to original", nullptr, false, f.changed)) {
                    if (!workspace_.revertEdit(static_cast<size_t>(i))) workspace_.log("Could not revert " + f.path);
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextColored(theme::vec(Col::Success), "%d", f.added);
            ImGui::TableNextColumn();
            ImGui::TextColored(theme::vec(Col::Error), "%d", f.removed);
            ImGui::TableNextColumn();
            if (f.validated) ImGui::Text("%zu", f.errors.size());
            else ImGui::TextDisabled("-");
            ImGui::TableNextColumn();
            if (f.validated) ImGui::Text("%zu", f.warnings.size());
            else ImGui::TextDisabled("-");
        }
        ImGui::EndTable();
    }

    if (selected_ < 0) {
        ImGui::TextDisabled("Select a file to see its diagnostics and diff.");
        return;
    }
    const auto& f = report_.files[static_cast<size_t>(selected_)];
    ImGui::BeginChild("##detail", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    const auto diag = [&](const smali::Diagnostic& d, bool error, int k) {
        ImGui::PushID(k);
        char label[64];
        std::snprintf(label, sizeof label, "%d:%d", d.line, d.column);
        ImGui::PushStyleColor(ImGuiCol_Text, error ? theme::vec(Col::Error) : theme::vec(Col::Warning));
        if (ImGui::Selectable(label, false, 0, ImVec2(ui::em(4.f), 0))) workspace_.openEdit(static_cast<size_t>(selected_), d.line - 1);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled("[%s]", smali::checkName(d.check));
        ImGui::SameLine();
        ImGui::TextUnformatted(d.message.c_str());
        ImGui::PopID();
    };
    int k = 0;
    for (const auto& d : f.errors) diag(d, true, k++);
    for (const auto& d : f.warnings) diag(d, false, k++);
    if (!f.errors.empty() || !f.warnings.empty()) ImGui::Separator();
    if (f.diff.empty()) ImGui::TextDisabled("No changes.");
    else drawDiff(f.diff);
    ImGui::EndChild();
}
