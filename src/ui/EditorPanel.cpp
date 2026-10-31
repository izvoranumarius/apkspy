#include "ui/EditorPanel.hpp"
#include <algorithm>
#include <cstdio>
#include "app/Theme.hpp"
#include "core/Settings.hpp"
#include "imgui_internal.h"
namespace ImStb {
#include "imstb_textedit.h"
}

namespace {
// Lets the multiline editor grow its std::string buffer as the user types.
int resizeCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* s = static_cast<std::string*>(data->UserData);
        s->resize(data->BufTextLen);
        data->Buf = &(*s)[0];
    }
    return 0;
}
}

const char* EditorPanel::tabLabel(const Document& doc) {
    static char buf[512];
    if (doc.isPreview())
        std::snprintf(buf, sizeof buf, "%s (preview)", doc.title().c_str());
    else if (doc.isDirty())
        std::snprintf(buf, sizeof buf, "%s *", doc.title().c_str());
    else
        std::snprintf(buf, sizeof buf, "%s", doc.title().c_str());
    return buf;
}

bool EditorPanel::lineNumbers() const { return settings_.getBool(Settings::kLineNumbers, true); }

void EditorPanel::drawContents() {
    auto& docs = workspace_.documents();
    if (docs.empty()) {
        ImGui::TextDisabled("Click a file in the Explorer to open it");
        return;
    }
    Document* focus = workspace_.takeFocusRequest();
    ImGuiTabBarFlags barFlags = ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs |
                                ImGuiTabBarFlags_FittingPolicyScroll;
    Document* promoted = nullptr;
    if (ImGui::BeginTabBar("##documents", barFlags)) {
        for (auto& doc : docs) {
            ImGuiTabItemFlags flags = doc.get() == focus ? ImGuiTabItemFlags_SetSelected : 0;
            bool open = true;
            ImGui::PushID(doc.get());
            if (ImGui::BeginTabItem(tabLabel(*doc), &open, flags)) {
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && doc->isPreview())
                    promoted = doc.get();  // preview tab double-clicked -> keep it
                drawDocument(*doc);
                ImGui::EndTabItem();
            }
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("##tab_ctx");
            if (ImGui::BeginPopup("##tab_ctx")) {
                if (ImGui::MenuItem("Close")) closingDoc_ = doc.get();
                if (ImGui::MenuItem("Close All")) {
                    batchClose_.clear();
                    for (auto& d : workspace_.documents()) batchClose_.push_back(d.get());
                }
                if (ImGui::MenuItem("Close Others")) {
                    batchClose_.clear();
                    for (auto& d : workspace_.documents())
                        if (d.get() != doc.get()) batchClose_.push_back(d.get());
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
            if (!open) requestClose(doc.get());
        }
        ImGui::EndTabBar();
    }
    if (promoted) workspace_.promoteDocument(promoted);

    processCloses();
    drawConfirmModal();
}

void EditorPanel::requestClose(Document* doc) {
    if (!doc) return;
    if (doc->isDirty()) {
        closingDoc_ = doc;
        saveOnConfirm_ = false;
        ImGui::OpenPopup("Close with unsaved changes?");
    } else {
        closeNow_.push_back(doc);
    }
}

void EditorPanel::closeMany(std::vector<Document*> docs) {
    bool anyDirty = false;
    for (Document* d : docs) anyDirty |= d->isDirty();
    if (anyDirty) {
        batchClose_ = std::move(docs);
        saveOnConfirm_ = false;
        ImGui::OpenPopup("Close with unsaved changes?");
    } else {
        closeNow_.insert(closeNow_.end(), docs.begin(), docs.end());
    }
}

void EditorPanel::processCloses() {
    if (closeNow_.empty()) return;
    for (Document* doc : closeNow_) workspace_.closeDocument(doc);
    closeNow_.clear();
    // Drop batch entries that no longer exist (they were just closed).
    batchClose_.erase(std::remove_if(batchClose_.begin(), batchClose_.end(),
                                     [this](Document* d) {
                                         return std::find_if(workspace_.documents().begin(),
                                                             workspace_.documents().end(),
                                                             [d](const std::unique_ptr<Document>& p) {
                                                                 return p.get() == d;
                                                             }) == workspace_.documents().end();
                                     }),
                      batchClose_.end());
}

void EditorPanel::drawConfirmModal() {
    if (closingDoc_ == nullptr && batchClose_.empty()) return;
    if (!ImGui::IsPopupOpen("Close with unsaved changes?")) ImGui::OpenPopup("Close with unsaved changes?");

    ImGui::SetNextWindowSize(ImVec2(460, 0), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Close with unsaved changes?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    if (closingDoc_) {
        ImGui::Text("\"%s\" has unsaved changes.", closingDoc_->title().c_str());
        ImGui::Spacing();
        bool canSave = closingDoc_->canEdit();
        if (!canSave) ImGui::BeginDisabled();
        if (ImGui::Button("Save", ImVec2(120, 0))) {
            if (closingDoc_->save()) {
                closeNow_.push_back(closingDoc_);
                closingDoc_ = nullptr;
            } else {
                workspace_.log("Could not save the file");
            }
            ImGui::CloseCurrentPopup();
        }
        if (!canSave) {
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip("APK entries cannot be saved; only decompiled files can.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Don't Save", ImVec2(120, 0))) {
            closingDoc_->cancelEdit();
            closeNow_.push_back(closingDoc_);
            closingDoc_ = nullptr;
            ImGui::CloseCurrentPopup();
        }
    } else {
        int dirty = 0;
        for (Document* d : batchClose_) dirty += d->isDirty() ? 1 : 0;
        ImGui::Text("%d tab(s) with unsaved changes are about to close.", dirty);
        ImGui::Spacing();
        if (ImGui::Button("Save All", ImVec2(120, 0))) {
            for (Document* d : batchClose_)
                if (d->isDirty() && d->canEdit() && !d->save()) workspace_.log("Could not save " + d->title());
            closeNow_.insert(closeNow_.end(), batchClose_.begin(), batchClose_.end());
            batchClose_.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Don't Save", ImVec2(120, 0))) {
            for (Document* d : batchClose_) d->cancelEdit();
            closeNow_.insert(closeNow_.end(), batchClose_.begin(), batchClose_.end());
            batchClose_.clear();
            ImGui::CloseCurrentPopup();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0))) {
        closingDoc_ = nullptr;
        batchClose_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void EditorPanel::drawDocument(Document& doc) {
    if (doc.mode() == Document::Mode::Image) {
        viewer_.drawToolbar(doc);
        ImGui::Separator();
        if (doc.imageView().showHex) drawScrollable(doc);
        else viewer_.drawCanvas(doc);
        return;
    }
    drawToolbar(doc);
    ImGui::Separator();
    if (!doc.note().empty()) ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.3f, 1.f), "%s", doc.note().c_str());
    // Files are editable by default; the highlighted read-only view only
    // remains for entries that cannot be edited (e.g. files inside the APK).
    if (doc.canEdit() && !doc.isEditing()) doc.beginEdit();
    if (doc.isEditing()) {
        drawEditable(doc);
        return;
    }
    drawScrollable(doc);
}

void EditorPanel::drawToolbar(Document& doc) {
    const char* path = doc.node() ? doc.node()->path().c_str() : "";
    ImGui::TextDisabled("%s", path);
}

void EditorPanel::drawScrollable(Document& doc) {
    ImGui::BeginChild("##content", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushFont(Theme::monoFont());
    if (doc.mode() == Document::Mode::Code) drawCode(doc);
    else drawHex(doc);
    ImGui::PopFont();
    ImGui::EndChild();
}

void EditorPanel::drawCode(Document& doc) {
    const auto& lines = doc.lines();
    const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
    int target = doc.takeGoTo();
    if (target >= 0) ImGui::SetScrollY(std::max(0.f, target * lineHeight - ImGui::GetWindowHeight() * 0.33f));

    ImDrawList* dl = ImGui::GetWindowDrawList();
    std::vector<Span> spans;
    ImGuiListClipper clipper;
    clipper.Begin((int)lines.size(), lineHeight);
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            if (lineNumbers()) {
                if (i == doc.highlight()) {
                    ImVec2 p = ImGui::GetCursorScreenPos();
                    float right = ImGui::GetWindowPos().x + ImGui::GetWindowWidth();
                    dl->AddRectFilled(p, ImVec2(right, p.y + lineHeight), IM_COL32(0, 122, 204, 70));
                }
                ImGui::TextDisabled("%5d", i + 1);
                ImGui::SameLine(0, 14);
            }
            bool inBlock = doc.blockStateAt((size_t)i);
            const std::string& line = lines[(size_t)i];
            SyntaxHighlighter::tokenize(line, doc.language(), inBlock, spans);
            if (spans.empty()) {
                ImGui::TextUnformatted("");
                continue;
            }
            for (size_t k = 0; k < spans.size(); ++k) {
                if (k > 0) ImGui::SameLine(0, 0);
                ImGui::PushStyleColor(ImGuiCol_Text, spans[k].color);
                ImGui::TextUnformatted(line.c_str() + spans[k].begin, line.c_str() + spans[k].end);
                ImGui::PopStyleColor();
            }
        }
    }
}

void EditorPanel::drawEditable(Document& doc) {
    ImGui::PushFont(Theme::monoFont());
    std::string& text = doc.editBuffer();
    const ImGuiID editId = ImGui::GetID("##edit");
    const float fontSize = ImGui::GetFontSize();
    const ImGuiStyle& style = ImGui::GetStyle();

    // The multiline input owns every interaction (caret, selection, clipboard,
    // undo/redo). Its own text is rendered fully transparent and is replaced
    // by a syntax-highlighted overlay appended straight into the same draw
    // list, so editing keeps the exact colours of the highlighted viewer.
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.f, 0.f, 0.f));
    ImGui::InputTextMultiline("##edit", &text[0], text.capacity() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                              ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize,
                              &resizeCallback, &text);
    ImGui::PopStyleColor();
    if (ImGui::IsItemEdited()) doc.markDirty();

    // Geometry of the input's internal child window, its scroll offsets and
    // its draw list. The overlay is recorded after EndChild, so it paints on
    // top of the frame background and the text selection highlight.
    const ImVec2 frameMin = ImGui::GetItemRectMin();
    const ImVec2 frameMax = ImGui::GetItemRectMax();
    const bool active = ImGui::IsItemActive();
    // The multiline widget wraps itself in a child window that BeginChildEx
    // names "<parent window>/##edit_<widget id>"; the WINDOW's id is the hash
    // of that full string, not the widget id - so FindWindowByID(editId)
    // always returns NULL (which silently disabled the caret below). Reproduce
    // the exact name instead.
    ImGuiWindow* inputWindow = nullptr;
    {
        char childName[256];
        std::snprintf(childName, sizeof childName, "%s/##edit_%08X", ImGui::GetCurrentWindow()->Name, editId);
        inputWindow = ImGui::FindWindowByName(childName);
    }
    const ImGuiInputTextState* state = ImGui::GetInputTextState(editId);
    const float scrollX = state ? state->Scroll.x : 0.f;
    const float scrollY = inputWindow ? inputWindow->Scroll.y : 0.f;
    ImDrawList* dl = inputWindow ? inputWindow->DrawList : ImGui::GetWindowDrawList();

    const ImVec2 textOrigin(frameMin.x + style.FramePadding.x, frameMin.y + style.FramePadding.y);
    const float right = frameMax.x - (inputWindow ? inputWindow->ScrollbarSizes.x : 0.f);
    dl->PushClipRect(frameMin, ImVec2(right, frameMax.y), true);

    const std::vector<std::string>& lines = doc.lines();
    const std::vector<size_t>& offsets = doc.lineOffsets();
    const int lineCount = (int)lines.size();
    const float viewHeight = frameMax.y - frameMin.y;
    const int first = std::max(0, (int)(scrollY / fontSize) - 1);
    const int last = std::min(lineCount, first + (int)(viewHeight / fontSize) + 3);

    std::vector<Span> spans;
    for (int i = first; i < last; ++i) {
        const std::string& line = lines[(size_t)i];
        const float y = textOrigin.y + (float)i * fontSize - scrollY;
        bool inBlock = doc.blockStateAt((size_t)i);
        SyntaxHighlighter::tokenize(line, doc.language(), inBlock, spans);
        float x = textOrigin.x - scrollX;
        for (const Span& span : spans) {
            if (span.end <= span.begin) continue;
            const char* s = line.c_str() + span.begin;
            const char* e = line.c_str() + span.end;
            dl->AddText(Theme::monoFont(), fontSize, ImVec2(x, y), span.color, s, e);
            x += ImGui::CalcTextSize(s, e).x;
        }
    }

    // The widget's own caret is drawn with ImGuiCol_Text, which is transparent
    // here - redraw it on top so typing keeps its blinking cursor.
    if (active && state && inputWindow && !offsets.empty()) {
        ImGuiIO& io = ImGui::GetIO();
        const bool blink = !io.ConfigInputTextCursorBlink || state->CursorAnim <= 0.f ||
                           ImFmod(state->CursorAnim, 1.20f) <= 0.80f;
        const int cursor = state->Stb->cursor;
        if (blink && cursor >= 0 && cursor <= (int)text.size()) {
            auto it = std::upper_bound(offsets.begin(), offsets.end(), (size_t)cursor);
            size_t lineIdx = it == offsets.begin() ? 0 : (size_t)(it - offsets.begin()) - 1;
            if (lineIdx < offsets.size() && lineIdx < lines.size()) {
                const char* lineStart = text.c_str() + offsets[lineIdx];
                const float cx = textOrigin.x - scrollX +
                                 ImGui::CalcTextSize(lineStart, lineStart + (cursor - (int)offsets[lineIdx])).x;
                const float cy = textOrigin.y + (float)lineIdx * fontSize - scrollY;
                dl->AddLine(ImVec2(cx, cy), ImVec2(cx, cy + fontSize), ImGui::GetColorU32(ImGuiCol_Text));
            }
        }
    }
    dl->PopClipRect();
    ImGui::PopFont();
}

void EditorPanel::drawHex(const Document& doc) {
    const auto& bytes = doc.bytes();
    const int rows = (int)((bytes.size() + 15) / 16);
    const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
    ImGuiListClipper clipper;
    clipper.Begin(rows, lineHeight);
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            size_t offset = (size_t)r * 16;
            char buf[160];
            int n = std::snprintf(buf, sizeof buf, "%08X  ", (unsigned)offset);
            for (size_t k = 0; k < 16; ++k) {
                if (offset + k < bytes.size()) n += std::snprintf(buf + n, sizeof buf - n, "%02X ", bytes[offset + k]);
                else n += std::snprintf(buf + n, sizeof buf - n, "   ");
            }
            buf[n++] = ' ';
            for (size_t k = 0; k < 16 && offset + k < bytes.size(); ++k) {
                uint8_t c = bytes[offset + k];
                buf[n++] = (c >= 32 && c < 127) ? (char)c : '.';
            }
            buf[n] = 0;
            ImGui::TextUnformatted(buf);
        }
    }
}
