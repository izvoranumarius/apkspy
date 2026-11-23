#pragma once
#include <algorithm>
#include <functional>
#include <string>
#include <utility>
#include <vector>
#include "imgui.h"
#include "imgui_internal.h"
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

// Toolbar button: narrower than a dialog button, but as tall as the inputs
// and combos beside it, so every control on a toolbar row lines up.
inline ImVec2 smallButtonPadding() { return ImVec2(em(0.55f), ImGui::GetStyle().FramePadding.y); }
inline float smallButtonWidth(const char* label) {
    return ImGui::CalcTextSize(label, nullptr, true).x + smallButtonPadding().x * 2.f;
}
inline bool smallButton(const char* label) {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, smallButtonPadding());
    const bool clicked = ImGui::Button(label);
    ImGui::PopStyleVar();
    return clicked;
}

// Action buttons of a dialog (Save / Cancel / OK ...): one width for all of them, scaled with the UI.
inline float dialogButtonWidth() { return em(7.f); }
inline bool dialogButton(const char* label) { return ImGui::Button(label, ImVec2(dialogButtonWidth(), 0.f)); }

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
        // The active choice reads as "pressed in" (a control fill, full-contrast
        // text and a short accent underline) rather than a block of accent:
        // accent stays reserved for focus and real highlights.
        ImGui::PushStyleColor(ImGuiCol_Button, on ? theme::vec(Col::Control) : ImVec4(0.f, 0.f, 0.f, 0.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, on ? theme::vec(Col::Control) : theme::vec(Col::RowHover));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, theme::vec(Col::ControlHover));
        ImGui::PushStyleColor(ImGuiCol_Text, on ? theme::vec(Col::Text) : theme::vec(Col::TextMuted));
        if (smallButton(labels[i]) && !on) {
            active = i;
            changed = true;
        }
        ImGui::PopStyleColor(4);
        if (on) {
            const ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
            const float inset = em(0.45f);
            ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(a.x + inset, b.y - 2.f), ImVec2(b.x - inset, b.y), theme::u32(Col::Accent));
        }
    }
    return changed;
}
// On/off filter as a pill ("chip"), for rows of filters (severities, node
// kinds...) where a row of checkboxes is heavy. Off: outlined, muted text.
// On: filled, full-contrast text. `dot` (optional) shows the category colour.
inline float toggleChipWidth(const char* label, bool hasDot = false) {
    return ImGui::CalcTextSize(label, nullptr, true).x + (hasDot ? em(0.9f) : 0.f) + ImGui::GetStyle().FramePadding.x * 2.f;
}
inline bool toggleChip(const char* label, bool* v, ImU32 dot = 0) {
    const ImGuiStyle& st = ImGui::GetStyle();
    const ImVec2 text = ImGui::CalcTextSize(label, nullptr, true);
    const ImVec2 size(toggleChipWidth(label, dot != 0), ImGui::GetFrameHeight());
    ImGui::PushID(label);
    const bool clicked = ImGui::InvisibleButton("##chip", size);
    ImGui::PopID();
    if (clicked) *v = !*v;
    const bool hovered = ImGui::IsItemHovered();
    const ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float r = size.y * 0.5f;
    if (*v) {
        dl->AddRectFilled(a, b, theme::u32(hovered ? Col::ControlHover : Col::Control), r);
    } else {
        if (hovered) dl->AddRectFilled(a, b, theme::u32(Col::RowHover), r);
        dl->AddRect(a, b, theme::u32(Col::Border), r);
    }
    float x = a.x + st.FramePadding.x;
    const float cy = (a.y + b.y) * 0.5f;
    if (dot) {
        const float rad = em(0.25f);
        if (*v) dl->AddCircleFilled(ImVec2(x + rad, cy), rad, dot);
        else dl->AddCircle(ImVec2(x + rad, cy), rad, dot, 0, 1.5f);
        x += em(0.9f);
    }
    dl->AddText(ImVec2(x, cy - text.y * 0.5f), theme::u32(*v ? Col::Text : Col::TextMuted), label, ImGui::FindRenderedTextEnd(label));
    return clicked;
}
inline bool flowToggleChip(const char* label, bool* v, ImU32 dot = 0) {
    sameLineIfFits(toggleChipWidth(label, dot != 0));
    return toggleChip(label, v, dot);
}

// A full-width hairline under a panel's toolbar: it separates the controls
// from the content they act on, instead of boxing either of them. It spans
// the window padding so it reads as a structural edge, not a widget.
inline void toolbarSeparator() {
    ImGui::Dummy(ImVec2(0.f, em(0.05f)));
    const ImGuiWindow* w = ImGui::GetCurrentWindow();
    const float y = ImGui::GetCursorScreenPos().y;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(w->Pos.x, y), ImVec2(w->Pos.x + w->Size.x, y), theme::u32(Col::Border));
    ImGui::Dummy(ImVec2(0.f, em(0.2f)));
}

// Hairline dividers between panes that sit side by side or stacked inside
// one panel - the alternative to giving each pane a border of its own.
// verticalDivider: call after SameLine(), before the next pane; `height` <= 0
// means "the space left minus -height".
inline void verticalDivider(float height = 0.f) {
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float h = height > 0.f ? height : ImGui::GetContentRegionAvail().y + height;
    const float x = p.x - ImGui::GetStyle().ItemSpacing.x * 0.5f;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(x, p.y), ImVec2(x, p.y + h), theme::u32(Col::Border));
}
// horizontalDivider: across the content width, with a little room around it.
inline void horizontalDivider() {
    ImGui::Dummy(ImVec2(0.f, em(0.05f)));
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(p, ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y), theme::u32(Col::Border));
    ImGui::Dummy(ImVec2(0.f, em(0.2f)));
}

// A quiet heading for a section of a panel (muted text, room above) in place
// of a bordered box or a filled bar.
inline void sectionHeader(const char* label) {
    if (ImGui::GetCursorPosY() > ImGui::GetStyle().WindowPadding.y + 1.f) ImGui::Dummy(ImVec2(0.f, em(0.3f)));
    ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
    ImGui::TextUnformatted(label, ImGui::FindRenderedTextEnd(label));
    ImGui::PopStyleColor();
}

// Collapsible section with a quiet header: no filled bar, the row only lights
// up on hover. Same signatures as ImGui::CollapsingHeader.
inline void pushQuietHeader() {
    ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.f, 0.f, 0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::vec(Col::RowHover));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::vec(Col::RowHover));
}
inline bool collapsingHeader(const char* label, ImGuiTreeNodeFlags flags = 0) {
    pushQuietHeader();
    const bool open = ImGui::CollapsingHeader(label, flags);
    ImGui::PopStyleColor(3);
    return open;
}
inline bool collapsingHeader(const char* label, bool* visible, ImGuiTreeNodeFlags flags = 0) {
    pushQuietHeader();
    const bool open = ImGui::CollapsingHeader(label, visible, flags);
    ImGui::PopStyleColor(3);
    return open;
}

// What a panel shows when it has nothing to show: a short title and an
// optional hint, centred in the space left and wrapped to a readable width.
// Lines of `hint` separated by '\n' stay separate.
inline void emptyState(const char* title, const char* hint = nullptr) {
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float maxW = std::max(em(8.f), std::min(avail.x - em(2.f), em(30.f)));
    std::vector<std::pair<std::string, bool>> lines;  // text, is part of the title
    const auto wrap = [&](const std::string& text, bool isTitle) {
        size_t start = 0;
        while (start <= text.size()) {
            size_t end = text.find('\n', start);
            if (end == std::string::npos) end = text.size();
            const std::string para = text.substr(start, end - start);
            std::string line;
            size_t i = 0;
            while (i < para.size()) {
                size_t sp = para.find(' ', i);
                if (sp == std::string::npos) sp = para.size();
                const std::string word = para.substr(i, sp - i);
                const std::string trial = line.empty() ? word : line + " " + word;
                if (!line.empty() && ImGui::CalcTextSize(trial.c_str()).x > maxW) {
                    lines.emplace_back(line, isTitle);
                    line = word;
                } else {
                    line = trial;
                }
                i = sp + 1;
            }
            lines.emplace_back(line, isTitle);
            start = end + 1;
        }
    };
    wrap(title, true);
    const bool hasHint = hint && *hint;
    if (hasHint) wrap(hint, false);
    const float lineH = ImGui::GetTextLineHeightWithSpacing();
    const float gap = hasHint ? em(0.5f) : 0.f;
    const float total = lineH * static_cast<float>(lines.size()) + gap;
    const ImVec2 origin = ImGui::GetCursorPos();
    float y = origin.y + std::max(0.f, (avail.y - total) * 0.42f);
    bool inHint = false;
    for (const auto& [text, isTitle] : lines) {
        if (!isTitle && !inHint) {
            y += gap;
            inHint = true;
        }
        const float w = ImGui::CalcTextSize(text.c_str()).x;
        ImGui::SetCursorPos(ImVec2(origin.x + std::max(0.f, (avail.x - w) * 0.5f), y));
        ImGui::PushStyleColor(ImGuiCol_Text, isTitle ? theme::vec(Col::Text, 0.75f) : theme::vec(Col::TextMuted));
        ImGui::TextUnformatted(text.c_str());
        ImGui::PopStyleColor();
        y += lineH;
    }
}

// Multi-line text box for code, HTTP messages, logs and lists: drawn on the
// editor background like every other code area, instead of a large light
// control-coloured block. Same arguments as ImGui::InputTextMultiline.
template <class... Args>
bool codeBox(Args&&... args) {
    const ImVec4 bg = theme::vec(Col::EditorBackground);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, bg);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, bg);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, bg);
    ImGui::PushStyleColor(ImGuiCol_Border, theme::vec(Col::Border));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
    const bool changed = ImGui::InputTextMultiline(std::forward<Args>(args)...);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(4);
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
