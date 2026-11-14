#include "ui/BookmarksPanel.hpp"
#include <algorithm>
#include <cstdio>
#include <tuple>
#include "core/TextUtils.hpp"

namespace {
std::string fileName(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string hex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}
}  // namespace

std::string BookmarksPanel::locationText(const Annotation& a) const {
    std::string where = fileName(a.path);
    where += a.target == Annotation::Target::Native ? " @ " + hex(a.addr) : ":" + std::to_string(a.line + 1);
    if (workspace_.apkRoots().size() > 1) where = a.group + ": " + where;
    return where;
}

void BookmarksPanel::rebuildRows() {
    const Annotations& notes = workspace_.annotations();
    if (appliedVersion_ == notes.version() && appliedFilter_ == filter_ && appliedKind_ == kindFilter_) return;
    appliedVersion_ = notes.version();
    appliedFilter_ = filter_;
    appliedKind_ = kindFilter_;
    const auto matches = [&](const Annotation& a) {
        if (a.variableNote()) return false;  // names and types are shown by the Decompiler, not here
        if (kindFilter_ == 1 && a.kind != Annotation::Kind::Bookmark) return false;
        if (kindFilter_ == 2 && a.kind != Annotation::Kind::Comment) return false;
        return appliedFilter_.empty() || tex::ciFind(a.text, appliedFilter_) != std::string_view::npos ||
               tex::ciFind(a.context, appliedFilter_) != std::string_view::npos ||
               tex::ciFind(a.path, appliedFilter_) != std::string_view::npos;
    };
    std::vector<const Annotation*> shown;
    for (const Annotation& a : notes.all())
        if (matches(a)) shown.push_back(&a);
    std::sort(shown.begin(), shown.end(), [](const Annotation* a, const Annotation* b) {
        return std::tie(a->group, a->path, a->line, a->addr, a->kind) < std::tie(b->group, b->path, b->line, b->addr, b->kind);
    });
    rows_.clear();
    for (const Annotation* a : shown) rows_.push_back(a->id);
}

void BookmarksPanel::go(const Annotation& a) {
    if (a.target == Annotation::Target::Native) {
        workspace_.requestNativeView({a.group, a.path, hex(a.addr)});
        showPanel_("Analysis");
        return;
    }
    Root* root = workspace_.rootByGroup(a.group, a.root);
    const TreeNode* node = root && root->tree ? root->tree->findByPath(a.path) : nullptr;
    if (!node) {
        workspace_.log("Not available in the current project: " + a.path +
                       (a.root == RootKind::Decompiled ? " (decompile the APK first)" : ""));
        return;
    }
    NavLocation origin;
    const NavLocation* originPtr = nullptr;
    if (Document* d = workspace_.activeDocument()) {
        origin = workspace_.locationOf(*d);
        originPtr = &origin;
    }
    workspace_.navigateTo(*root, *node, a.line, originPtr);
    showPanel_("Editor");
}

void BookmarksPanel::drawContents() {
    Annotations& notes = workspace_.annotations();
    // Same chip switch as the other view filters (radio circles looked heavy).
    static const char* const kKinds[] = {"All", "Bookmarks", "Comments"};
    ui::segmented(kKinds, 3, kindFilter_);
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##flt", "Filter text or file...", filter_, sizeof filter_);
    rebuildRows();
    if (notes.all().empty()) {
        ImGui::TextDisabled("Nothing yet. In the editor or a native listing press Ctrl+B for a bookmark or ; for a comment.");
        popup_.draw(notes);
        return;
    }
    int removeId = 0;
    if (ImGui::BeginTable("##notes", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, ui::em(1.f));
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch, 2.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows_.size()));
        while (clipper.Step())
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                const Annotation* a = notes.find(rows_[static_cast<size_t>(r)]);
                ImGui::TableNextRow();
                if (!a) continue;
                const bool bookmark = a->kind == Annotation::Kind::Bookmark;
                ImGui::TableNextColumn();
                ImGui::PushID(a->id);
                ImGui::TextColored(bookmark ? ui::kBookmarkColor() : ui::kNoteColor(), bookmark ? "B" : "C");
                ImGui::SameLine();
                const bool activated =
                    ImGui::Selectable("##row", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s  (%s)\n%s%s%s", a->path.c_str(), a->group.c_str(), a->text.c_str(),
                                      a->text.empty() ? "" : "\n", a->context.c_str());
                bool goThere = activated;
                if (ImGui::BeginPopupContextItem("##ctx")) {
                    if (ImGui::MenuItem("Go to")) goThere = true;
                    if (ImGui::MenuItem(bookmark ? "Edit label..." : "Edit comment...")) popup_.open(notes, *a, a->kind);
                    if (ImGui::MenuItem("Copy text")) ImGui::SetClipboardText(a->text.c_str());
                    if (ImGui::MenuItem("Delete")) removeId = a->id;
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(locationText(*a).c_str());
                ImGui::TableNextColumn();
                if (!a->text.empty()) ImGui::TextUnformatted(ui::noteFirstLine(a->text).c_str());
                else ImGui::TextDisabled("%s", a->context.c_str());
                ImGui::PopID();
                if (goThere) {
                    const Annotation target = *a;
                    go(target);
                }
            }
        ImGui::EndTable();
    }
    if (removeId) notes.remove(removeId);
    popup_.draw(notes);
}
