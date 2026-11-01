#include "ui/OutputPanel.hpp"
#include "core/LogSeverity.hpp"
#include "app/Theme.hpp"

void OutputPanel::drawContents() {
    const auto& lines = workspace_.logLines();

    // Toolbar ---------------------------------------------------------------
    if (ImGui::Button("Clear")) {
        workspace_.clearLog();
        severities_.clear();
        classifiedCount_ = 0;
        index_.clear();
        lastFilter_ = -1;  // force an index rebuild
        lastCount_ = 0;
    }
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

    const size_t prevCount = lastCount_;
    const bool trimmed = lines.size() < prevCount;  // workspace dropped old lines
    lastCount_ = lines.size();

    // Classify each line exactly once (not per frame per line).
    if (trimmed) {
        severities_.clear();
        classifiedCount_ = 0;
        index_.clear();
    }
    if (severities_.size() < lines.size()) {
        severities_.resize(lines.size());
        for (size_t i = classifiedCount_; i < lines.size(); ++i)
            severities_[i] = (char)logsev::classify(lines[i]);
        classifiedCount_ = lines.size();
    }

    // Remember whether the view is at the bottom BEFORE new lines are
    // appended - auto-scroll must never yank the user back down while they
    // read older output.
    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.f;

    // Filtered index: the clipper needs a dense row list, so rows are
    // skipped while building the index instead of inside its loop (the old
    // in-loop "continue" corrupted the clipper's measurements and left
    // blank gaps).
    auto matches = [this](size_t i) {
        if (filter_ == 0) return true;
        if (filter_ == 1) return severities_[i] == (char)LogSeverity::Warn;
        return severities_[i] == (char)LogSeverity::Error;
    };
    if (lastFilter_ != filter_) {
        index_.clear();
        for (size_t i = 0; i < lines.size(); ++i)
            if (matches(i)) index_.push_back((int)i);
    } else {
        for (size_t i = prevCount < lines.size() ? prevCount : lines.size(); i < lines.size(); ++i)
            if (matches(i)) index_.push_back((int)i);
    }
    lastFilter_ = filter_;

    // Log lines --------------------------------------------------------------
    ImGui::PushFont(Theme::monoFont());
    ImGuiListClipper clipper;
    clipper.Begin((int)index_.size());
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const size_t i = (size_t)index_[(size_t)r];
            switch ((LogSeverity)severities_[i]) {
            case LogSeverity::Warn:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(220, 190, 100, 255));
                break;
            case LogSeverity::Error:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(235, 100, 90, 255));
                break;
            default:
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(200, 200, 200, 255));
                break;
            }
            ImGui::TextUnformatted(lines[i].c_str());
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopFont();
    if (lines.size() > prevCount && atBottom) ImGui::SetScrollHereY(1.0f);
}
