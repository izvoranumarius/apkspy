#pragma once
#include <algorithm>
#include <functional>
#include <string>
#include <string_view>
#include "imgui.h"
#include "app/Theme.hpp"

namespace ui {

// Text selection for read-only line views (code viewer, decompiler, Output),
// as in a text editor: drag to select, double-click a word, Shift+click to
// extend, Ctrl+A / Ctrl+C, and Copy / Copy All / Select All for a context
// menu. Positions are (line, byte column) of the view's lines.
//
// Per frame: row() for every visible line, before its text is drawn (the
// highlight goes under the glyphs), then finish() in the same window.
class TextSelect {
public:
    using LineFn = std::function<std::string(int)>;

    void reset() { a_ = b_ = Pos{}; dragging_ = false; }
    bool empty() const { return a_.line < 0 || (a_.line == b_.line && a_.col == b_.col); }
    bool dragging() const { return dragging_; }

    // `text` is the line as drawn from `pos` (screen top-left), `h` its row height.
    // `mouse` false: draw the highlight only (the view uses this click for itself).
    void row(int line, std::string_view text, ImVec2 pos, float h, bool mouse = true) {
        const ImGuiIO& io = ImGui::GetIO();
        if (firstSeen_ < 0 || line < firstSeen_) firstSeen_ = line;
        if (line >= lastSeen_) lastSeen_ = line, lastLen_ = static_cast<int>(text.size());
        const bool inRow = io.MousePos.y >= pos.y && io.MousePos.y < pos.y + h;
        if (mouse && inRow && ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem | ImGuiHoveredFlags_ChildWindows)) {
            const int col = colAt(text, pos.x, io.MousePos.x);
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                int s = col, e = col;  // the word under the mouse
                while (s > 0 && wordChar(text[static_cast<size_t>(s - 1)])) --s;
                while (e < static_cast<int>(text.size()) && wordChar(text[static_cast<size_t>(e)])) ++e;
                a_ = {line, s}, b_ = {line, e};
                dragging_ = false;
            } else if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                if (!(io.KeyShift && a_.line >= 0)) a_ = {line, col};
                b_ = {line, col};
                dragging_ = true;
            } else if (dragging_ && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                b_ = {line, col};
            }
        }
        if (empty()) return;
        // The highlight: the selected part of this line, plus a space for the line break.
        const Pos s = lo(), e = hi();
        if (line < s.line || line > e.line) return;
        const int from = line == s.line ? std::min(s.col, static_cast<int>(text.size())) : 0;
        const int to = line == e.line ? std::min(e.col, static_cast<int>(text.size())) : static_cast<int>(text.size());
        const float x0 = pos.x + ImGui::CalcTextSize(text.data(), text.data() + from).x;
        float x1 = pos.x + ImGui::CalcTextSize(text.data(), text.data() + to).x;
        if (line != e.line) x1 += ImGui::CalcTextSize(" ").x;
        if (x1 > x0)
            ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(x0, pos.y), ImVec2(x1, pos.y + h), theme::u32(Col::TextSelection, 0.85f));
    }

    // After the rows: ends a drag (scrolling while the mouse is past an edge) and handles
    // Ctrl+A / Ctrl+C while the view has focus. `count` lines, `text(i)` returns line i.
    void finish(int count, const LineFn& text, float lineH) {
        const ImGuiIO& io = ImGui::GetIO();
        if (dragging_) {
            if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                dragging_ = false;
            } else {
                const float top = ImGui::GetWindowPos().y, bottom = top + ImGui::GetWindowHeight();
                if (io.MousePos.y < top) {
                    ImGui::SetScrollY(std::max(0.f, ImGui::GetScrollY() - lineH));
                    if (firstSeen_ >= 0) b_ = {firstSeen_, 0};
                } else if (io.MousePos.y > bottom) {
                    ImGui::SetScrollY(ImGui::GetScrollY() + lineH);
                    if (lastSeen_ >= 0) b_ = {lastSeen_, lastLen_};
                }
            }
        }
        firstSeen_ = lastSeen_ = -1;
        lastLen_ = 0;
        if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) || io.WantTextInput || !io.KeyCtrl || io.KeyAlt) return;
        if (ImGui::IsKeyPressed(ImGuiKey_A, false)) selectAll(count, text);
        if (ImGui::IsKeyPressed(ImGuiKey_C, false) && !empty()) copy(text);
    }

    void selectAll(int count, const LineFn& text) {
        if (count <= 0) return;
        a_ = {0, 0};
        b_ = {count - 1, static_cast<int>(text(count - 1).size())};
    }

    std::string selected(const LineFn& text) const {
        if (empty()) return {};
        const Pos s = lo(), e = hi();
        std::string out;
        for (int i = s.line; i <= e.line; ++i) {
            const std::string t = text(i);
            const size_t from = i == s.line ? std::min(static_cast<size_t>(s.col), t.size()) : 0;
            const size_t to = i == e.line ? std::min(static_cast<size_t>(e.col), t.size()) : t.size();
            if (to > from) out.append(t.data() + from, to - from);
            if (i != e.line) out += '\n';
        }
        return out;
    }
    void copy(const LineFn& text) const {
        const std::string s = selected(text);
        if (!s.empty()) ImGui::SetClipboardText(s.c_str());
    }
    static void copyAll(int count, const LineFn& text) {
        std::string out;
        for (int i = 0; i < count; ++i) {
            out += text(i);
            if (i + 1 < count) out += '\n';
        }
        ImGui::SetClipboardText(out.c_str());
    }

    // Copy / Copy All / Select All, for the view's context menu (inside BeginPopup...).
    void menuItems(int count, const LineFn& text, const std::function<void(std::string)>& sendToDecoder = {}) {
        if (ImGui::MenuItem("Copy", "Ctrl+C", false, !empty())) copy(text);
        if (sendToDecoder && ImGui::MenuItem("Send to Decoder", nullptr, false, !empty())) sendToDecoder(selected(text));
        if (ImGui::MenuItem("Copy All", nullptr, false, count > 0)) copyAll(count, text);
        if (ImGui::MenuItem("Select All", "Ctrl+A", false, count > 0)) selectAll(count, text);
    }

    // The byte column nearest to screen x `mx` in `text` drawn from `x0`.
    static int colAt(std::string_view text, float x0, float mx) {
        float x = x0;
        size_t col = 0;
        while (col < text.size()) {
            size_t n = 1;  // a whole UTF-8 sequence
            while (col + n < text.size() && (static_cast<unsigned char>(text[col + n]) & 0xC0) == 0x80) ++n;
            const float w = ImGui::CalcTextSize(text.data() + col, text.data() + col + n).x;
            if (mx < x + w * 0.5f) break;
            x += w;
            col += n;
        }
        return static_cast<int>(col);
    }

private:
    struct Pos {
        int line = -1;
        int col = 0;
    };
    static bool wordChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' ||
               (static_cast<unsigned char>(c) & 0x80);
    }
    bool before(Pos x, Pos y) const { return x.line < y.line || (x.line == y.line && x.col < y.col); }
    Pos lo() const { return before(b_, a_) ? b_ : a_; }
    Pos hi() const { return before(b_, a_) ? a_ : b_; }

    Pos a_, b_;  // anchor and moving end
    bool dragging_ = false;
    int firstSeen_ = -1, lastSeen_ = -1, lastLen_ = 0;  // rows drawn this frame (for drags past the edges)
};

// Ctrl+C on the hovered item copies `text` (lists and tables without a text selection).
inline void copyHovered(const std::string& text) {
    const ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && !io.WantTextInput && ImGui::IsItemHovered() && ImGui::IsKeyPressed(ImGuiKey_C, false))
        ImGui::SetClipboardText(text.c_str());
}

// Ctrl+C on the last item, and a right-click menu with Copy (plus `more` items, if any).
inline void copyMenu(const char* id, const std::string& text, const std::function<void()>& more = {}) {
    copyHovered(text);
    if (ImGui::BeginPopupContextItem(id)) {
        if (ImGui::MenuItem("Copy", "Ctrl+C")) ImGui::SetClipboardText(text.c_str());
        if (more) more();
        ImGui::EndPopup();
    }
}

}  // namespace ui
