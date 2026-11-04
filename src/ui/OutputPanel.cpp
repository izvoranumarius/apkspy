#include "ui/OutputPanel.hpp"
#include "core/LogSeverity.hpp"
#include "app/Theme.hpp"

namespace {

// The tag of each source keeps its colour, so a line's origin reads at a glance.
ImU32 sourceColor(std::string_view source) {
    if (source == "jadx") return IM_COL32(150, 180, 235, 255);
    if (source == "analysis") return IM_COL32(190, 150, 235, 255);
    if (source == "scripts") return IM_COL32(120, 205, 150, 255);
    if (source == "mcp") return IM_COL32(100, 200, 215, 255);
    if (source == "debug") return IM_COL32(225, 165, 110, 255);
    return IM_COL32(140, 140, 140, 255);
}

const char* sourceName(void*, int index) {
    return index == 0 ? "All sources" : logsev::kSources[index - 1];
}

}  // namespace

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
        warnings_ = errors_ = 0;
        selection_.reset();
    }
    ui::sameLineIfFits(ui::em(7.f));
    ImGui::SetNextItemWidth(ui::em(7.f));
    ImGui::Combo("##filter", &filter_, "All levels\0Warnings\0Errors\0\0");
    ui::sameLineIfFits(ui::em(7.f));
    ImGui::SetNextItemWidth(ui::em(7.f));
    ImGui::Combo("##source", &source_, sourceName, nullptr, 1 + (int)std::size(logsev::kSources));
    const JadxRunner& jadx = workspace_.jadx();
    char status[160];
    if (jadx.state() == JadxRunner::State::Running) {
        if (jadx.totalCount() > 0)
            std::snprintf(status, sizeof status, "jadx %d / %d classes (%d s) - warnings: %d, errors: %d",
                          jadx.processedCount(), jadx.totalCount(), jadx.elapsedSeconds(), jadx.warningCount(),
                          jadx.errorCount());
        else
            std::snprintf(status, sizeof status, "jadx running (%d s) - warnings: %d, errors: %d",
                          jadx.elapsedSeconds(), jadx.warningCount(), jadx.errorCount());
    } else {
        std::snprintf(status, sizeof status, "Warnings: %d   Errors: %d", warnings_, errors_);
    }
    ui::flowTextDisabled(status);
    ImGui::Separator();

    const size_t prevCount = lastCount_;
    const bool trimmed = workspace_.logTrims() != lastTrims_;  // workspace dropped old lines
    lastTrims_ = workspace_.logTrims();
    lastCount_ = lines.size();

    // Classify each line exactly once (not per frame per line).
    if (trimmed) {
        severities_.clear();
        classifiedCount_ = 0;
        index_.clear();
        lastFilter_ = -1;  // force an index rebuild
        warnings_ = errors_ = 0;
        selection_.reset();  // row numbers no longer mean the same lines
    }
    if (severities_.size() < lines.size()) {
        severities_.resize(lines.size());
        for (size_t i = classifiedCount_; i < lines.size(); ++i) {
            const LogSeverity severity = logsev::classify(lines[i]);
            severities_[i] = (char)severity;
            warnings_ += severity == LogSeverity::Warn;
            errors_ += severity == LogSeverity::Error;
        }
        classifiedCount_ = lines.size();
    }

    // Filtered index: the clipper needs a dense row list, so rows are
    // skipped while building the index instead of inside its loop (the old
    // in-loop "continue" corrupted the clipper's measurements and left
    // blank gaps).
    auto matches = [this, &lines](size_t i) {
        if (source_ > 0 && logsev::sourceOf(lines[i]) != logsev::kSources[source_ - 1]) return false;
        if (filter_ == 0) return true;
        if (filter_ == 1) return severities_[i] == (char)LogSeverity::Warn;
        return severities_[i] == (char)LogSeverity::Error;
    };
    const int filters = filter_ * 100 + source_;
    if (lastFilter_ != filters) {
        index_.clear();
        selection_.reset();
        for (size_t i = 0; i < lines.size(); ++i)
            if (matches(i)) index_.push_back((int)i);
    } else {
        for (size_t i = prevCount < lines.size() ? prevCount : lines.size(); i < lines.size(); ++i)
            if (matches(i)) index_.push_back((int)i);
    }
    lastFilter_ = filters;

    // Log lines --------------------------------------------------------------
    // Each row is a selectable (selection highlight + mouse handling) with
    // the colored text drawn over it.
    ImGui::BeginChild("##outputLines", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.f;
    ImGui::PushFont(Theme::monoFont());
    const float rowH = ImGui::GetTextLineHeight();
    ImGuiListClipper clipper;
    clipper.Begin((int)index_.size());
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const size_t i = (size_t)index_[(size_t)r];
            const ImVec2 rowPos = ImGui::GetCursorPos();
            ImGui::PushID(r);
            ImGui::Selectable("##row", selection_.contains(r), ImGuiSelectableFlags_AllowOverlap, ImVec2(0, rowH));
            selection_.handleRow(r);
            ImGui::PopID();
            ImGui::SetCursorPos(rowPos);
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
            const std::string_view source = logsev::sourceOf(lines[i]);
            const std::string_view message = logsev::messageOf(lines[i]);
            if (!source.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, sourceColor(source));
                ImGui::TextUnformatted(lines[i].data(), lines[i].data() + (lines[i].size() - message.size()));
                ImGui::PopStyleColor();
                ImGui::SameLine(0.f, 0.f);
            }
            ImGui::TextUnformatted(message.data(), message.data() + message.size());
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopFont();
    const std::string copied = selection_.handleCommands(
        (int)index_.size(), [&](int r) { return lines[(size_t)index_[(size_t)r]]; }, "##outputCtx");
    if (!copied.empty()) ImGui::SetClipboardText(copied.c_str());
    // Each workspace has its own Output window, so each follows the end by
    // itself: lines that arrived while it was hidden count as new when it
    // returns. A window scrolled up to read older lines stays where it is.
    ImGuiStorage* state = ImGui::GetStateStorage();
    const ImGuiID followId = ImGui::GetID("##follow"), seenId = ImGui::GetID("##seen");
    const int seen = state->GetInt(seenId, 0);
    if (seen == (int)index_.size()) state->SetBool(followId, atBottom);
    else if (state->GetBool(followId, true)) ImGui::SetScrollHereY(1.0f);
    state->SetInt(seenId, (int)index_.size());
    ImGui::EndChild();
}
