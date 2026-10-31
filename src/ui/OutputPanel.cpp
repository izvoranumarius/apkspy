#include "ui/OutputPanel.hpp"
#include <cctype>
#include <string>
#include "app/Theme.hpp"

namespace {
enum class LineKind { Info, Warn, Error };

LineKind classify(const std::string& line) {
    auto contains = [&line](const char* word) { return line.find(word) != std::string::npos; };
    if (contains("ERROR") || contains("Error") || contains("error:")) return LineKind::Error;
    if (contains("WARN") || contains("Warn") || contains("warning:")) return LineKind::Warn;
    return LineKind::Info;
}
}

void OutputPanel::drawContents() {
    const auto& lines = workspace_.logLines();

    // Toolbar ---------------------------------------------------------------
    if (ImGui::Button("Clear")) workspace_.clearLog();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.f);
    ImGui::Combo("##filter", &filter_, "All\0Warnings\0Errors\0\0");
    ImGui::SameLine();
    const JadxRunner& jadx = workspace_.jadx();
    if (jadx.state() == JadxRunner::State::Running) {
        ImGui::TextColored(ImVec4(0.55f, 0.75f, 0.95f, 1.f), "jadx running (%d s) - warnings: %d, errors: %d",
                           jadx.elapsedSeconds(), jadx.warningCount(), jadx.errorCount());
    } else {
        ImGui::TextDisabled("Warnings: %d   Errors: %d", jadx.warningCount(), jadx.errorCount());
    }
    ImGui::Separator();

    // Log lines --------------------------------------------------------------
    ImGui::PushFont(Theme::monoFont());
    ImGuiListClipper clipper;
    clipper.Begin((int)lines.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const std::string& line = lines[(size_t)i];
            LineKind kind = classify(line);
            if (filter_ == 1 && kind != LineKind::Warn) continue;
            if (filter_ == 2 && kind != LineKind::Error) continue;
            switch (kind) {
            case LineKind::Warn:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(220, 190, 100, 255));
                break;
            case LineKind::Error:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 100, 90, 255));
                break;
            default:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 200, 255));
                break;
            }
            ImGui::TextUnformatted(line.c_str());
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopFont();
    if (lines.size() != lastCount_) {
        ImGui::SetScrollHereY(1.0f);
        lastCount_ = lines.size();
    }
}
