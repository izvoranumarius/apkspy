// Comparer of the Traffic panel, as in Burp: two items (requests, responses,
// Decoder output, pasted text) side by side, the lines that differ coloured and
// the words that differ inside them highlighted.
#include <algorithm>
#include <cstdio>
#include "app/Icons.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

void TrafficPanel::sendToComparer(std::string label, std::string text) {
    compareItems_.push_back({std::to_string(compareNext_++) + ". " + std::move(label), std::move(text)});
    // The two newest items face each other: send two things in a row and they are compared.
    const int n = static_cast<int>(compareItems_.size());
    compareB_ = n - 1;
    compareA_ = n >= 2 ? n - 2 : -1;
    compareDirty_ = true;
    showComparer_ = true;
}

void TrafficPanel::drawComparer() {
    if (compareItems_.empty()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("Send two requests or responses here (right-click > Send to Comparer, or To Comparer in the "
                            "Repeater and the Decoder), or paste text, to see what differs between them.");
        ImGui::PopTextWrapPos();
        if (ui::smallButton("Paste as item"))
            if (const char* clip = ImGui::GetClipboardText()) sendToComparer("pasted", clip);
        return;
    }
    // Which two items.
    const auto pick = [&](const char* id, int& sel) {
        ImGui::SetNextItemWidth(ui::em(16.f));
        const char* preview = sel >= 0 && sel < static_cast<int>(compareItems_.size()) ? compareItems_[static_cast<size_t>(sel)].label.c_str() : "(choose)";
        if (ImGui::BeginCombo(id, preview)) {
            for (int i = 0; i < static_cast<int>(compareItems_.size()); ++i)
                if (ImGui::Selectable(compareItems_[static_cast<size_t>(i)].label.c_str(), sel == i)) sel = i, compareDirty_ = true;
            ImGui::EndCombo();
        }
    };
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("A");
    ImGui::SameLine();
    pick("##cmpA", compareA_);
    ImGui::SameLine();
    if (ui::smallButton("Swap")) std::swap(compareA_, compareB_), compareDirty_ = true;
    ImGui::SameLine();
    ImGui::TextUnformatted("B");
    ImGui::SameLine();
    pick("##cmpB", compareB_);
    ImGui::SameLine();
    if (ui::smallButton("Paste as item"))
        if (const char* clip = ImGui::GetClipboardText()) sendToComparer("pasted", clip);
    ImGui::SameLine();
    if (ui::smallButton("Clear items")) {
        compareItems_.clear();
        compareA_ = compareB_ = -1;
        compareResult_.reset();
        return;
    }
    const bool ready = compareA_ >= 0 && compareB_ >= 0 && compareA_ < static_cast<int>(compareItems_.size()) &&
                       compareB_ < static_cast<int>(compareItems_.size());
    if (!ready) {
        ImGui::TextDisabled("Choose two items to compare.");
        return;
    }
    if (compareDirty_ || !compareResult_) {
        compareDirty_ = false;
        // Copies: the result's lines point into them, and the items may be cleared meanwhile.
        compareTextA_ = compareItems_[static_cast<size_t>(compareA_)].text;
        compareTextB_ = compareItems_[static_cast<size_t>(compareB_)].text;
        compareResult_ = std::make_unique<textdiff::Result>(textdiff::diff(compareTextA_, compareTextB_));
        compareHunks_.clear();
        for (size_t i = 0; i < compareResult_->rows.size(); ++i)
            if (compareResult_->rows[i].kind != textdiff::Kind::Same &&
                (i == 0 || compareResult_->rows[i - 1].kind == textdiff::Kind::Same))
                compareHunks_.push_back(static_cast<int>(i));
        compareHunk_ = -1;
        compareScroll_ = !compareHunks_.empty();
        if (compareScroll_) compareHunk_ = 0;
    }
    const textdiff::Result& r = *compareResult_;

    // Summary and difference navigation.
    if (r.identical()) {
        ImGui::TextColored(kGood, "Identical (%zu lines)", r.a.size());
    } else {
        ImGui::TextColored(kWarn, "%d changed, %d added, %d removed", r.changed, r.added, r.removed);
        ImGui::SameLine();
        ImGui::TextDisabled("(%zu difference%s%s)", compareHunks_.size(), compareHunks_.size() == 1 ? "" : "s",
                            r.approximate ? ", too many for an exact diff" : "");
        ImGui::SameLine();
        if (ImGui::ArrowButton("##prevDiff", ImGuiDir_Up) && !compareHunks_.empty()) {
            compareHunk_ = compareHunk_ <= 0 ? static_cast<int>(compareHunks_.size()) - 1 : compareHunk_ - 1;
            compareScroll_ = true;
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous difference");
        ImGui::SameLine();
        if (ImGui::ArrowButton("##nextDiff", ImGuiDir_Down) && !compareHunks_.empty()) {
            compareHunk_ = (compareHunk_ + 1) % static_cast<int>(compareHunks_.size());
            compareScroll_ = true;
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next difference");
        if (compareHunk_ >= 0) {
            ImGui::SameLine();
            ImGui::TextDisabled("%d/%zu", compareHunk_ + 1, compareHunks_.size());
        }
    }

    // Side by side: line numbers, then the line; colours by kind, differing words brighter.
    ImGui::PushFont(Theme::monoFont());
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::editorBackground());
    ImGui::BeginChild("##cmpView", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    const float lineH = ImGui::GetTextLineHeightWithSpacing();
    const float textH = ImGui::GetTextLineHeight();
    const float width = ImGui::GetContentRegionAvail().x;
    const float half = width * 0.5f;
    const float numW = ImGui::CalcTextSize("00000 ").x;
    if (compareScroll_ && compareHunk_ >= 0) {
        compareScroll_ = false;
        const float y = static_cast<float>(compareHunks_[static_cast<size_t>(compareHunk_)]) * lineH;
        ImGui::SetScrollY(std::max(0.f, y - ImGui::GetWindowHeight() * 0.3f));
    }
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 removedBg = theme::u32(Col::Error, 0.16f), addedBg = theme::u32(Col::Success, 0.16f),
                changedBg = theme::u32(Col::Warning, 0.12f);
    const ImU32 removedWord = theme::u32(Col::Error, 0.40f), addedWord = theme::u32(Col::Success, 0.40f);
    const ImU32 textCol = theme::u32(Col::Text), numCol = theme::u32(Col::TextMuted);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(r.rows.size()), lineH);
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const textdiff::Row& row = r.rows[static_cast<size_t>(i)];
            const ImVec2 p = ImGui::GetCursorScreenPos();
            const bool current = compareHunk_ >= 0 && i == compareHunks_[static_cast<size_t>(compareHunk_)];
            const auto side = [&](float x0, int line, const std::vector<std::string_view>& lines, const std::vector<textdiff::Span>& spans,
                                  ImU32 bg, ImU32 word) {
                const ImVec2 a(x0, p.y), b(x0 + half - 2.f, p.y + lineH);
                if (line < 0) {  // nothing on this side: hatched gap
                    dl->AddRectFilled(a, b, theme::u32(Col::TextMuted, 0.06f));
                    return;
                }
                if (bg) dl->AddRectFilled(a, b, bg);
                char num[16];
                std::snprintf(num, sizeof num, "%5d", line + 1);
                dl->AddText(ImVec2(x0, p.y), numCol, num);
                const std::string_view text = lines[static_cast<size_t>(line)];
                const float tx = x0 + numW;
                dl->PushClipRect(ImVec2(tx, p.y), b, true);
                for (const textdiff::Span& s : spans) {
                    const float sx = tx + ImGui::CalcTextSize(text.data(), text.data() + s.begin).x;
                    const float ex = tx + ImGui::CalcTextSize(text.data(), text.data() + s.end).x;
                    dl->AddRectFilled(ImVec2(sx, p.y), ImVec2(ex, p.y + textH), word);
                }
                dl->AddText(ImVec2(tx, p.y), textCol, text.data(), text.data() + text.size());
                dl->PopClipRect();
            };
            ImU32 lbg = 0, rbg = 0;
            if (row.kind == textdiff::Kind::Removed) lbg = removedBg;
            if (row.kind == textdiff::Kind::Added) rbg = addedBg;
            if (row.kind == textdiff::Kind::Changed) lbg = rbg = changedBg;
            side(p.x, row.left, r.a, row.leftSpans, lbg, removedWord);
            side(p.x + half + 2.f, row.right, r.b, row.rightSpans, rbg, addedWord);
            if (current) dl->AddRectFilled(ImVec2(p.x, p.y), ImVec2(p.x + 3.f, p.y + lineH), theme::u32(Col::Accent));
            ImGui::Dummy(ImVec2(width, lineH));
            if (ImGui::IsItemHovered() && row.kind != textdiff::Kind::Same) {
                const std::string_view la = row.left >= 0 ? r.a[static_cast<size_t>(row.left)] : std::string_view();
                const std::string_view lb = row.right >= 0 ? r.b[static_cast<size_t>(row.right)] : std::string_view();
                ImGui::SetTooltip("A: %.*s\nB: %.*s", static_cast<int>(std::min<size_t>(la.size(), 400)), la.data(),
                                  static_cast<int>(std::min<size_t>(lb.size(), 400)), lb.data());
            }
        }
    // The divider between the two sides.
    const ImVec2 wp = ImGui::GetWindowPos();
    dl->AddLine(ImVec2(wp.x + ImGui::GetStyle().WindowPadding.x + half, wp.y),
                ImVec2(wp.x + ImGui::GetStyle().WindowPadding.x + half, wp.y + ImGui::GetWindowHeight()), theme::u32(Col::Border));
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::PopFont();
}
