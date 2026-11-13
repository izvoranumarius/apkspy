#include "ui/SearchPanel.hpp"
#include <cstdio>
#include "app/Theme.hpp"

void SearchPanel::drawContents() {
    auto roots = workspace_.decompiledRoots();
    bool running = workspace_.jadx().state() == JadxRunner::State::Running;
    if (roots.empty()) {
        ImGui::TextDisabled(running ? "Decompilation is starting - search will cover the results once it finishes"
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

    // With several APKs in the project, pick which decompiled tree to search.
    if (roots.size() > 1) {
        ImGui::Text("APK:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200.f);
        if (ImGui::BeginCombo("##apk", root->title.c_str())) {
            for (int i = 0; i < static_cast<int>(roots.size()); ++i)
                if (ImGui::Selectable(roots[static_cast<size_t>(i)]->title.c_str(), i == rootIdx_)) rootIdx_ = i;
            ImGui::EndCombo();
        }
    }

    ImGui::Text("Search in:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    const char* modes[] = {"Full text", "Filenames", "Classes", "Methods", "Fields"};
    ImGui::Combo("##mode", &mode_, modes, 5);

    bool submit = false;
    if (decompiling) ImGui::BeginDisabled();
    if (ImGui::InputText("##query", query_, sizeof query_, ImGuiInputTextFlags_EnterReturnsTrue)) submit = true;
    ImGui::SameLine();
    if (ImGui::Button("Search")) submit = true;
    if (submit && query_[0] && !decompiling)
        workspace_.search().start(root->tree.get(), root->source.get(), query_,
                                  static_cast<SearchService::Mode>(mode_), root->title);
    if (decompiling) {
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("results still streaming in...");
    } else {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", workspace_.search().running() ? "searching..." : "");
    }

    const SearchService& search = workspace_.search();
    if (search.truncated())
        ImGui::TextDisabled("Result list truncated at 3000 hits - refine the query");
    if (search.skippedFiles() > 0)
        ImGui::TextDisabled("%d oversized file(s) skipped (limit 4 MB)", search.skippedFiles());

    // Hits point into the root that was searched (not the one currently
    // selected in the combo), and only render while it still exists.
    Root* hitRoot = workspace_.rootByGroup(search.group(), Root::Kind::Decompiled);
    if (!hitRoot) return;
    ImGui::PushFont(Theme::monoFont());
    workspace_.search().withHits([&](const std::vector<SearchHit>& hits) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(hits.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const SearchHit& h = hits[static_cast<size_t>(i)];
                // The text is drawn after the row, not used as its label:
                // "##" inside a line of code would hide the rest of it.
                char label[640];
                std::snprintf(label, sizeof label, "%s:%d   %s", h.node->name().c_str(), h.line + 1, h.text.c_str());
                ImGui::PushID(i);
                const bool clicked = ImGui::Selectable("##hit", false, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap);
                ImGui::PopID();
                ImGui::SameLine(0.f, 0.f);
                ImGui::TextUnformatted(label);
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
            }
        }
    });
    ImGui::PopFont();
}
