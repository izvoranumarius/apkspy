#pragma once
#include <algorithm>
#include "app/Theme.hpp"
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include "core/Annotations.hpp"
#include "imgui.h"
#include "ui/UiUtil.hpp"

namespace ui {

inline constexpr Col kNoteToken = Col::Green;
inline constexpr Col kBookmarkToken = Col::Orange;
inline ImVec4 kNoteColor() { return theme::vec(kNoteToken); }
inline ImVec4 kBookmarkColor() { return theme::vec(kBookmarkToken); }

// First line of a note, marked when more follows.
inline std::string noteFirstLine(const std::string& text) {
    const size_t nl = text.find('\n');
    return nl == std::string::npos ? text : text.substr(0, nl) + " ...";
}

// Modal editor for the text of a comment or the label of a bookmark. A panel
// owns one, calls open() from a menu or shortcut and draw() every frame.
class CommentPopup {
public:
    void open(const Annotations& notes, Annotation location, Annotation::Kind kind = Annotation::Kind::Comment) {
        location.kind = kind;
        location_ = std::move(location);
        const Annotation* existing = notes.at(kind, location_);
        exists_ = existing != nullptr;
        buf_.assign(Annotations::kMaxText + 1, '\0');
        if (existing) std::memcpy(buf_.data(), existing->text.data(), std::min(existing->text.size(), Annotations::kMaxText));
        request_ = focus_ = true;
    }

    void draw(Annotations& notes) {
        const char* id = "Annotation###annotationPopup";
        if (request_) {
            ImGui::OpenPopup(id);
            request_ = false;
        }
        if (!ImGui::BeginPopupModal(id, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
        const bool comment = location_.kind == Annotation::Kind::Comment;
        ImGui::TextUnformatted(comment ? "Comment" : "Bookmark label");
        if (!location_.context.empty()) {
            ImGui::PushTextWrapPos(ui::em(26.f));
            ImGui::TextDisabled("%s", location_.context.c_str());
            ImGui::PopTextWrapPos();
        }
        if (focus_) {
            ImGui::SetKeyboardFocusHere();
            focus_ = false;
        }
        ImGui::InputTextMultiline("##text", buf_.data(), buf_.size(), ImVec2(ui::em(26.f), ui::em(7.f)));
        const ImGuiIO& io = ImGui::GetIO();
        const bool save = ImGui::Button("Save") || (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Enter, false));
        ImGui::SameLine();
        if (save) {
            const std::string text = buf_.data();
            if (comment && text.empty()) {
                if (const Annotation* a = notes.at(location_.kind, location_)) notes.remove(a->id);  // nothing left to keep
            } else {
                Annotation a = location_;
                a.text = text;
                notes.set(std::move(a));
            }
            ImGui::CloseCurrentPopup();
        }
        if (exists_ && ImGui::Button("Delete")) {
            if (const Annotation* a = notes.at(location_.kind, location_)) notes.remove(a->id);
            ImGui::CloseCurrentPopup();
        }
        if (exists_) ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
        ImGui::SameLine();
        ImGui::TextDisabled("Ctrl+Enter saves");
        ImGui::EndPopup();
    }

private:
    Annotation location_;
    std::vector<char> buf_;
    bool exists_ = false;
    bool request_ = false;
    bool focus_ = false;
};

}  // namespace ui
