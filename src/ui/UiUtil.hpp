#pragma once
#include <algorithm>
#include <functional>
#include <string>
#include "imgui.h"
#include "app/Theme.hpp"

// Small layout helpers so panels adapt to their width and to the UI zoom
// instead of using fixed pixel sizes (which clipped content at the dock
// splitter in narrow panels).
namespace ui {

// `n` times the current font size - the unit for every width / height.
inline float em(float n) { return ImGui::GetFontSize() * n; }

// "<icon>  label" when the icon font is loaded, the label alone otherwise.
inline std::string icon(const char* glyph, const char* label = nullptr) {
    if (!Theme::hasIcons()) return label ? label : "";
    std::string s = glyph;
    if (label && *label) s += std::string("  ") + label;
    return s;
}

// Width a button with this label will take.
inline float buttonWidth(const char* label) {
    return ImGui::CalcTextSize(label, nullptr, true).x + ImGui::GetStyle().FramePadding.x * 2.f;
}
inline float checkboxWidth(const char* label) {
    return ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x + ImGui::CalcTextSize(label, nullptr, true).x;
}

// Puts the next item on the current row when `nextWidth` still fits in the
// window, otherwise lets it start a new row ("flow" layout).
inline void sameLineIfFits(float nextWidth) {
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float rowEnd = ImGui::GetItemRectMax().x + spacing + nextWidth;
    const float limit = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
    if (rowEnd <= limit) ImGui::SameLine();
}

// Compact toolbar button. ImGui::SmallButton has no vertical padding, so its
// label touched the button edges; this keeps a little room on every side.
inline ImVec2 smallButtonPadding() { return ImVec2(em(0.5f), em(0.12f)); }
inline float smallButtonWidth(const char* label) {
    return ImGui::CalcTextSize(label, nullptr, true).x + smallButtonPadding().x * 2.f;
}
inline bool smallButton(const char* label) {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, smallButtonPadding());
    const bool clicked = ImGui::Button(label);
    ImGui::PopStyleVar();
    return clicked;
}

// Flow-layout variants of common widgets.
inline bool flowButton(const char* label) {
    sameLineIfFits(buttonWidth(label));
    return ImGui::Button(label);
}
inline bool flowSmallButton(const char* label) {
    sameLineIfFits(smallButtonWidth(label));
    return smallButton(label);
}
inline bool flowCheckbox(const char* label, bool* v) {
    sameLineIfFits(checkboxWidth(label));
    return ImGui::Checkbox(label, v);
}
// Row of mutually exclusive choices, for switching views of the same data.
inline bool segmented(const char* const* labels, int count, int& active) {
    bool changed = false;
    for (int i = 0; i < count; ++i) {
        if (i) ImGui::SameLine(0.f, em(0.15f));
        const bool on = i == active;
        ImGui::PushStyleColor(ImGuiCol_Button, on ? theme::vec(Col::Accent) : ImVec4(0.f, 0.f, 0.f, 0.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, on ? theme::vec(Col::Accent) : theme::vec(Col::RowHover));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, on ? theme::vec(Col::Accent) : theme::vec(Col::ControlHover));
        ImGui::PushStyleColor(ImGuiCol_Text, on ? theme::vec(Col::TextOnAccent) : theme::vec(Col::TextMuted));
        if (smallButton(labels[i]) && !on) {
            active = i;
            changed = true;
        }
        ImGui::PopStyleColor(4);
    }
    return changed;
}
// Disabled-colored text after the previous item, wrapping to the panel.
inline void flowTextDisabled(const std::string& text) {
    const float w = ImGui::CalcTextSize(text.c_str()).x;
    sameLineIfFits(std::min(w, em(12.f)));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
}
inline void wrappedColored(const ImVec4& color, const std::string& text) {
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
}

// Row selection for read-only line views (Output, Logcat): click, shift +
// click, click-drag, Ctrl+A, Ctrl+C and a context menu with Copy / Copy all.
// Rows are indices into the view; call reset() when the view is rebuilt.
class RowSelection {
public:
    void reset() { anchor_ = end_ = -1; }
    bool contains(int row) const {
        if (anchor_ < 0) return false;
        return row >= std::min(anchor_, end_) && row <= std::max(anchor_, end_);
    }
    bool empty() const { return anchor_ < 0; }
    // Call right after the row's item was submitted.
    void handleRow(int row) {
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            if (ImGui::GetIO().KeyShift && anchor_ >= 0) end_ = row;
            else anchor_ = end_ = row;
            dragging_ = true;
        } else if (dragging_ && ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
                   ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
            end_ = row;
        }
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right) && !contains(row)) anchor_ = end_ = row;
    }
    // Keyboard + context menu; `count` rows, `text(i)` returns row i.
    // Returns the text to copy (empty = nothing requested).
    std::string handleCommands(int count, const std::function<std::string(int)>& text, const char* popupId) {
        if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) dragging_ = false;
        std::string out;
        const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
        const ImGuiIO& io = ImGui::GetIO();
        bool copy = false, copyAll = false;
        if (focused && io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false) && count > 0) {
            anchor_ = 0;
            end_ = count - 1;
        }
        if (focused && io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) copy = true;
        if (ImGui::BeginPopupContextWindow(popupId)) {
            if (ImGui::MenuItem("Copy", "Ctrl+C", false, !empty())) copy = true;
            if (ImGui::MenuItem("Copy all")) copyAll = true;
            if (ImGui::MenuItem("Select all", "Ctrl+A", false, count > 0)) {
                anchor_ = 0;
                end_ = count - 1;
            }
            ImGui::EndPopup();
        }
        if (copyAll) {
            for (int i = 0; i < count; ++i) (out += text(i)) += '\n';
        } else if (copy && !empty()) {
            const int a = std::max(0, std::min(anchor_, end_)), b = std::min(count - 1, std::max(anchor_, end_));
            for (int i = a; i <= b; ++i) (out += text(i)) += '\n';
        }
        return out;
    }

private:
    int anchor_ = -1;
    int end_ = -1;
    bool dragging_ = false;
};

}  // namespace ui
