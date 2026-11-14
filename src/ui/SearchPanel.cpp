#include "ui/SearchPanel.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include "app/Theme.hpp"
#include "ui/UiUtil.hpp"

void SearchPanel::drawContents() {
    auto roots = workspace_.decompiledRoots();
    bool running = workspace_.jadx().state() == JadxRunner::State::Running;
    if (roots.empty()) {
        ImGui::TextWrapped("%s", running ? "Decompilation is starting - search will cover the results once it finishes"
                                         : "Search becomes available once an APK has been decompiled");
        return;
    }
    if (rootIdx_ >= static_cast<int>(roots.size())) rootIdx_ = 0;
    Root* root = roots[static_cast<size_t>(rootIdx_)];

    // The tree of a root that is currently being decompiled is mutated on
    // the UI thread while results stream in; searching it concurrently is a
    // data race, so searches on that root are stopped and new ones refused.
    const bool decompiling = running && workspace_.isGroupDecompiling(root->title);
    if (decompiling && workspace_.search().running()) workspace_.search().stop();

    // Sidebar layout: every control takes the full width, one per row.
    bool submit = false;
    if (decompiling) ImGui::BeginDisabled();
    if (focusQuery_) {
        ImGui::SetKeyboardFocusHere();
        focusQuery_ = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::InputTextWithHint("##query", "Find in project (Enter)", query_, sizeof query_, ImGuiInputTextFlags_EnterReturnsTrue))
        submit = true;
    if (decompiling) ImGui::EndDisabled();

    // With several APKs in the project, pick which decompiled tree to search.
    const float button = ui::buttonWidth("Search");
    if (roots.size() > 1) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::BeginCombo("##apk", root->title.c_str())) {
            for (int i = 0; i < static_cast<int>(roots.size()); ++i)
                if (ImGui::Selectable(roots[static_cast<size_t>(i)]->title.c_str(), i == rootIdx_)) rootIdx_ = i;
            ImGui::EndCombo();
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("APK to search");
    }
    const char* modes[] = {"Full text", "Filenames", "Classes", "Methods", "Fields"};
    ImGui::SetNextItemWidth(-(button + ImGui::GetStyle().ItemSpacing.x));
    ImGui::Combo("##mode", &mode_, modes, 5);
    ImGui::SameLine();
    if (decompiling) ImGui::BeginDisabled();
    if (ImGui::Button("Search")) submit = true;
    if (decompiling) ImGui::EndDisabled();
    if (submit && query_[0] && !decompiling)
        workspace_.search().start(root->tree.get(), root->source.get(), query_, static_cast<SearchService::Mode>(mode_), root->title);

    const SearchService& search = workspace_.search();
    if (decompiling) ImGui::TextDisabled("results still streaming in...");
    else if (search.running()) ImGui::TextDisabled("searching...");
    if (search.truncated()) ImGui::TextWrapped("Result list truncated at 3000 hits - refine the query");
    if (search.skippedFiles() > 0) ImGui::TextDisabled("%d oversized file(s) skipped (limit 4 MB)", search.skippedFiles());

    // Hits point into the root that was searched (not the one currently
    // selected in the combo), and only render while it still exists.
    Root* hitRoot = workspace_.rootByGroup(search.group(), Root::Kind::Decompiled);
    if (!hitRoot) return;
    ImGui::Separator();
    ImGui::BeginChild("##hits", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    workspace_.search().withHits([&](const std::vector<SearchHit>& hits) {
        // Rows: a header per file, then its hits (as VS Code groups them). -1 is a header.
        struct Row {
            int hit;
            size_t first;  // header: index of the file's first hit
        };
        std::vector<Row> rows;
        rows.reserve(hits.size() + 64);
        size_t files = 0;
        for (size_t i = 0; i < hits.size(); ++i) {
            if (i == 0 || hits[i].node != hits[i - 1].node) rows.push_back({-1, i}), ++files;
            rows.push_back({static_cast<int>(i), i});
        }
        ImGui::TextDisabled("%zu result%s in %zu file%s", hits.size(), hits.size() == 1 ? "" : "s", files, files == 1 ? "" : "s");
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows.size()));
        while (clipper.Step()) {
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                const Row& row = rows[static_cast<size_t>(r)];
                const SearchHit& h = hits[row.first];
                ImGui::PushID(r);
                if (row.hit < 0) {
                    // The file: its name, the folder dimmed after it.
                    ImGui::TextColored(theme::vec(Col::Info), "%s", h.node->name().c_str());
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", h.node->path().c_str());
                    const std::string& path = h.node->path();
                    const size_t slash = path.find_last_of('/');
                    if (slash != std::string::npos) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("%s", path.substr(0, slash).c_str());
                    }
                    ImGui::PopID();
                    continue;
                }
                // The text is drawn after the row, not used as its label:
                // "##" inside a line of code would hide the rest of it.
                const bool clicked = ImGui::Selectable("##hit", false, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s:%d\n%s", h.node->path().c_str(), h.line + 1, h.text.c_str());
                ImGui::SameLine(0.f, 0.f);
                ImGui::Indent(ui::em(0.8f));
                char line[16];
                std::snprintf(line, sizeof line, "%5d ", h.line + 1);
                ImGui::TextDisabled("%s", line);
                ImGui::SameLine(0.f, 0.f);
                // Leading indentation of the code says nothing here.
                size_t start = h.text.find_first_not_of(" \t");
                ImGui::PushFont(Theme::monoFont());
                ImGui::TextUnformatted(start == std::string::npos ? "" : h.text.c_str() + start);
                ImGui::PopFont();
                ImGui::Unindent(ui::em(0.8f));
                if (clicked) {
                    // Opening a hit is an explicit jump: it lands in the
                    // Back/Forward history (the current position is the
                    // origin, so Alt+Left returns to it).
                    NavLocation origin;
                    NavLocation* originPtr = nullptr;
                    if (Document* active = workspace_.activeDocument()) {
                        origin = workspace_.locationOf(*active);
                        originPtr = &origin;
                    }
                    const bool keep = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
                    workspace_.navigateTo(*hitRoot, *h.node, h.line, originPtr,
                                          keep ? Workspace::OpenMode::Permanent : Workspace::OpenMode::Preview);
                }
                ImGui::PopID();
            }
        }
    });
    ImGui::EndChild();
}
