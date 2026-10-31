#include "ui/SearchPanel.hpp"
#include <cstdio>
#include "app/Theme.hpp"

void SearchPanel::drawContents() {
    auto roots = workspace_.decompiledRoots();
    bool running = workspace_.jadx().state() == JadxRunner::State::Running;
    if (roots.empty()) {
        ImGui::TextDisabled(running ? "Decompilation is starting - search will cover the results as they appear"
                                    : "Search becomes available once an APK has been decompiled");
        return;
    }
    if (rootIdx_ >= (int)roots.size()) rootIdx_ = 0;
    Root* root = roots[(size_t)rootIdx_];

    // With several APKs in the project, pick which decompiled tree to search.
    if (roots.size() > 1) {
        ImGui::Text("APK:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(200.f);
        if (ImGui::BeginCombo("##apk", root->title.c_str())) {
            for (int i = 0; i < (int)roots.size(); ++i)
                if (ImGui::Selectable(roots[(size_t)i]->title.c_str(), i == rootIdx_)) rootIdx_ = i;
            ImGui::EndCombo();
        }
    }

    ImGui::Text("Search in:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    const char* modes[] = {"Full text", "Filenames", "Classes", "Methods", "Fields"};
    ImGui::Combo("##mode", &mode_, modes, 5);

    bool submit = ImGui::InputText("##query", query_, sizeof query_, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Search")) submit = true;
    if (submit && query_[0])
        workspace_.search().start(root->tree.get(), root->source.get(), query_,
                                  (SearchService::Mode)mode_);
    ImGui::SameLine();
    ImGui::TextDisabled("%s", workspace_.search().running() ? "searching..." : "");

    // Hits point into this root's tree; only render them while it still
    // exists (removing an APK clears them with the next stop()).
    ImGui::PushFont(Theme::monoFont());
    workspace_.search().withHits([&](const std::vector<SearchHit>& hits) {
        ImGuiListClipper clipper;
        clipper.Begin((int)hits.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const SearchHit& h = hits[(size_t)i];
                char label[640];
                std::snprintf(label, sizeof label, "%s:%d   %s##%d", h.label.c_str(), h.line + 1, h.text.c_str(), i);
                if (ImGui::Selectable(label, false, ImGuiSelectableFlags_AllowDoubleClick)) {
                    // Single click previews, double click keeps the tab open.
                    workspace_.openNode(*root, *h.node, h.line,
                                        ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)
                                            ? Workspace::OpenMode::Permanent
                                            : Workspace::OpenMode::Preview);
                }
            }
        }
    });
    ImGui::PopFont();
}
