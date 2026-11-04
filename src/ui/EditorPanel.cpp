#include "ui/EditorPanel.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "app/Theme.hpp"
#include <fstream>
#include "core/Paths.hpp"
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

// Colours of the find-match overlays (drawn under the code text).
constexpr ImU32 kMatchColor = IM_COL32(255, 213, 79, 40);
constexpr ImU32 kCurrentMatchColor = IM_COL32(255, 145, 0, 95);
constexpr ImU32 kSymbolUnderline = IM_COL32(120, 180, 255, 210);
// Error colour shared by the "No results" label.
constexpr ImVec4 kErrorColor(0.95f, 0.45f, 0.35f, 1.f);

// Toggle button that stays lit while `on` (find bar's Aa / W switches).
bool toggleButton(const char* label, bool on) {
    if (on) ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetColorU32(ImGuiCol_ButtonActive));
    bool clicked = ImGui::SmallButton(label);
    if (on) ImGui::PopStyleColor();
    return clicked;
}

// Byte offset the mouse sits on inside a rendered span (monospace column
// math via CalcTextSize, the same formula the find overlays use). Returns
// false when the mouse is outside the span's text range.
bool byteOffsetAtX(std::string_view line, const Span& span, float relX, int& offOut) {
    if (span.end <= span.begin) return false;
    int off = (int)span.end - 1;  // clicked at/behind the last glyph
    for (int c = (int)span.begin + 1; c <= (int)span.end; ++c) {
        if (ImGui::CalcTextSize(line.data() + span.begin, line.data() + c).x > relX) {
            off = c - 1;
            break;
        }
    }
    if (off < (int)span.begin || off >= (int)span.end) return false;
    offOut = off;
    return true;
}

// [a,b) bounds of the identifier under `off` (expands along the line, not
// just the span, so '$'-stitched nested names stay whole).
bool identifierAround(std::string_view line, int off, int& aOut, int& bOut) {
    if (off < 0 || off >= (int)line.size()) return false;
    if (!tex::isIdentChar(line[(size_t)off])) return false;
    int a = off;
    while (a > 0 && tex::isIdentChar(line[(size_t)a - 1])) --a;
    int b = off + 1;
    while (b < (int)line.size() && tex::isIdentChar(line[(size_t)b])) ++b;
    aOut = a;
    bOut = b;
    return true;
}
}  // namespace

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
            // The tab id comes from the "###doc" suffix, so the label can
            // grow a " *" or " (preview)" marker (or lose it) without the
            // tab jumping to the end of the bar.
            char label[640];
            const char* marker = doc->isPreview() ? " (preview)" : (doc->isDirty() ? " *" : "");
            std::snprintf(label, sizeof label, "%s%s###doc%p", doc->title().c_str(), marker, (void*)doc.get());
            const bool tabOpen = ImGui::BeginTabItem(label, &open, flags);
            const bool tabHovered = ImGui::IsItemHovered();  // read now: the document body adds items of its own
            if (tabOpen) {
                if (tabHovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && doc->isPreview())
                    promoted = doc.get();  // preview tab double-clicked -> keep it
                drawDocument(*doc);
                ImGui::EndTabItem();
            }
            if (tabHovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) ImGui::OpenPopup("##tab_ctx");
            if (ImGui::BeginPopup("##tab_ctx")) {
                if (doc->node() && !doc->node()->path().empty() && ImGui::MenuItem("Export...")) openExport(*doc);
                ImGui::Separator();
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

    // Menu-triggered find / go-to-line (View > Find..., Ctrl+G from the menu
    // bar). Consumed here so the popup opens in this window's ID scope.
    if (findRequest_ || goToRequest_) {
        Document* active = workspace_.activeDocument();
        if (active && active->mode() == Document::Mode::Code) {
            if (findRequest_) {
                findRequest_ = false;
                openFind(*active, *findState(*active));
            }
            if (goToRequest_) {
                goToRequest_ = false;
                openGoTo(*active);
            }
        } else {
            findRequest_ = goToRequest_ = false;  // no code document active: ignore
        }
    }
    if (gotoOpenRequest_) {
        ImGui::OpenPopup("Go to line");
        gotoOpenRequest_ = false;
    }
    drawGoToModal();
    comment_.draw(workspace_.annotations());
    drawExportBrowser();

    processCloses();
    drawConfirmModal();
    sweepFindStates();
}

void EditorPanel::requestClose(Document* doc) {
    if (!doc) return;
    if (doc->isDirty()) {
        closingDoc_ = doc;
        ImGui::OpenPopup("Close with unsaved changes?");
    } else {
        closeNow_.push_back(doc);
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
        if (ImGui::Button("Save", ImVec2(120, 0))) {
            if (closingDoc_->save()) {
                closeNow_.push_back(closingDoc_);
                closingDoc_ = nullptr;
            } else {
                workspace_.log("Could not save the file");
            }
            ImGui::CloseCurrentPopup();
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
                if (d->isDirty() && !d->save()) workspace_.log("Could not save " + d->title());
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
    workspace_.setActiveDocument(&doc);
    processShortcuts(doc);
    if (doc.mode() == Document::Mode::Image) {
        viewer_.drawToolbar(doc);
        ImGui::Separator();
        if (doc.imageView().showHex) drawScrollable(doc);
        else viewer_.drawCanvas(doc);
        return;
    }
    drawToolbar(doc);
    ImGui::Separator();
    FindState* f = findState(doc);
    if (f->open) {
        drawFindBar(doc, *f);
        ImGui::Separator();
    }
    if (!doc.note().empty()) ImGui::TextColored(ImVec4(0.9f, 0.6f, 0.3f, 1.f), "%s", doc.note().c_str());
    // Read-only viewer by default; only an explicit Edit toggle switches to
    // the editor (files from the APK archive can never be edited).
    if (doc.wantsEdit() && doc.canEdit()) {
        doc.beginEdit();
        drawEditable(doc);
        return;
    }
    drawScrollable(doc);
}

void EditorPanel::drawToolbar(Document& doc) {
    // Back/Forward buttons (Alt+Left / Alt+Right have the same effect).
    {
        ImGui::BeginDisabled(!workspace_.canNavBack());
        if (ImGui::SmallButton("<##navback")) workspace_.navBack();
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Navigate Back (Alt+Left)");
        ImGui::SameLine(0, 2.f);
        ImGui::BeginDisabled(!workspace_.canNavForward());
        if (ImGui::SmallButton(">##navfwd")) workspace_.navForward();
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Navigate Forward (Alt+Right)");
        ImGui::SameLine(0, 8.f);
    }
    const char* path = doc.node() ? doc.node()->path().c_str() : "";
    ImGui::TextDisabled("%s", path);
    const ImGuiStyle& style = ImGui::GetStyle();
    const bool canEdit = doc.canEdit();
    const char* editLabel = doc.isEditing() ? "View" : "Edit";
    const float editW = canEdit ? ImGui::CalcTextSize(editLabel).x + style.FramePadding.x * 2.f : 0.f;
    float x = ImGui::GetWindowWidth() - style.WindowPadding.x;
    if (canEdit) {
        x -= editW;
        ImGui::SameLine();
        ImGui::SetCursorPosX(x);
        if (ImGui::Button(editLabel)) {
            if (doc.isEditing()) doc.stopEditingView();
            else doc.setWantsEdit(true);
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", doc.isEditing() ? "Back to the read-only view (unsaved edits are kept)"
                                                    : "Edit this file in place (saved with Ctrl+S)");
    }
}

void EditorPanel::drawScrollable(Document& doc) {
    if (doc.mode() != Document::Mode::Code) {
        drawHexView(doc);
        return;
    }
    ImGui::BeginChild("##content", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushFont(Theme::monoFont());
    drawCode(doc);
    ImGui::PopFont();
    ImGui::EndChild();
}

namespace {
// Parses "DE AD be ef" / "deadbeef" into bytes; false on bad input.
bool parseHexPattern(const char* text, std::vector<uint8_t>& out) {
    out.clear();
    int nibble = -1;
    for (const char* p = text; *p; ++p) {
        const char c = *p;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c == ' ' || c == ',') continue;
        else return false;
        if (nibble < 0) nibble = v;
        else {
            out.push_back((uint8_t)(nibble << 4 | v));
            nibble = -1;
        }
    }
    return nibble < 0 && !out.empty();
}
}  // namespace

void EditorPanel::drawHexView(const Document& doc) {
    HexState& h = hex_[&doc];
    const auto& bytes = doc.bytes();
    // Toolbar: jump + search.
    ImGui::SetNextItemWidth(110.f);
    if (ImGui::InputTextWithHint("##hexgoto", "offset (hex)", h.gotoBuf, sizeof h.gotoBuf,
                                 ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal)) {
        const unsigned long long off = std::strtoull(h.gotoBuf, nullptr, 16);
        if (off < bytes.size()) {
            h.selected = (int64_t)off;
            h.scrollTo = (int64_t)off;
            h.status.clear();
        } else {
            h.status = "offset beyond end of file";
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.f);
    const bool findNow = ImGui::InputTextWithHint("##hexfind", h.findText ? "text to find" : "hex bytes, e.g. 64 65 78 0a",
                                                  h.findBuf, sizeof h.findBuf, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::Checkbox("Text", &h.findText);
    ImGui::SameLine();
    if ((ImGui::Button("Find next") || findNow) && h.findBuf[0]) {
        std::vector<uint8_t> pattern;
        if (h.findText) pattern.assign(h.findBuf, h.findBuf + std::strlen(h.findBuf));
        if (!h.findText && !parseHexPattern(h.findBuf, pattern)) {
            h.status = "invalid hex pattern";
        } else {
            const size_t from = h.selected >= 0 ? (size_t)h.selected + 1 : 0;
            auto it = std::search(bytes.begin() + (ptrdiff_t)std::min(from, bytes.size()), bytes.end(), pattern.begin(), pattern.end());
            if (it == bytes.end()) it = std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end());  // wrap
            if (it == bytes.end()) {
                h.status = "not found";
            } else {
                h.selected = it - bytes.begin();
                h.scrollTo = h.selected;
                h.status.clear();
            }
        }
    }
    ImGui::SameLine();
    if (!h.status.empty()) ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.35f, 1.f), "%s", h.status.c_str());
    else ImGui::TextDisabled("%zu bytes", bytes.size());

    const float inspectorW = ImGui::GetFontSize() * 17.f;  // fits 20-digit 64-bit values at any zoom
    ImGui::BeginChild("##content", ImVec2(-inspectorW, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushFont(Theme::monoFont());
    const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
    const float charW = ImGui::CalcTextSize("0").x;
    if (h.scrollTo >= 0) {
        ImGui::SetScrollY(std::max(0.f, (float)(h.scrollTo / 16) * lineHeight - ImGui::GetWindowHeight() * 0.33f));
        h.scrollTo = -1;
    }
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const int rows = (int)((bytes.size() + 15) / 16);
    ImGuiListClipper clipper;
    clipper.Begin(rows, lineHeight);
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const size_t offset = (size_t)r * 16;
            char buf[160];
            int n = std::snprintf(buf, sizeof buf, "%08X  ", (unsigned)offset);
            for (size_t k = 0; k < 16; ++k) {
                if (offset + k < bytes.size()) n += std::snprintf(buf + n, sizeof buf - n, "%02X ", bytes[offset + k]);
                else n += std::snprintf(buf + n, sizeof buf - n, "   ");
            }
            buf[n++] = ' ';
            for (size_t k = 0; k < 16 && offset + k < bytes.size(); ++k) {
                const uint8_t c = bytes[offset + k];
                buf[n++] = (c >= 32 && c < 127) ? (char)c : '.';
            }
            buf[n] = 0;
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            // Selection highlight in both columns, under the text.
            if (h.selected >= (int64_t)offset && h.selected < (int64_t)offset + 16) {
                const int k = (int)(h.selected - (int64_t)offset);
                const ImU32 sel = IM_COL32(0, 122, 204, 120);
                dl->AddRectFilled(ImVec2(pos.x + charW * (10 + 3 * k), pos.y), ImVec2(pos.x + charW * (12 + 3 * k), pos.y + lineHeight), sel);
                dl->AddRectFilled(ImVec2(pos.x + charW * (59 + k), pos.y), ImVec2(pos.x + charW * (60 + k), pos.y + lineHeight), sel);
            }
            ImGui::TextUnformatted(buf);
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                const int col = (int)((ImGui::GetIO().MousePos.x - pos.x) / charW);
                int k = -1;
                if (col >= 10 && col < 58) k = (col - 10) / 3;
                else if (col >= 59 && col < 75) k = col - 59;
                if (k >= 0 && offset + (size_t)k < bytes.size()) h.selected = (int64_t)(offset + (size_t)k);
            }
        }
    }
    ImGui::PopFont();
    ImGui::EndChild();
    ImGui::SameLine();
    drawHexInspector(doc, h);
}

void EditorPanel::drawHexInspector(const Document& doc, HexState& h) {
    const auto& bytes = doc.bytes();
    ImGui::BeginChild("##inspector", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextDisabled("Data inspector (little endian)");
    if (h.selected < 0 || h.selected >= (int64_t)bytes.size()) {
        ImGui::TextDisabled("Click a byte.");
        ImGui::EndChild();
        return;
    }
    const size_t off = (size_t)h.selected;
    const size_t avail = bytes.size() - off;
    const auto le = [&](size_t n) {
        uint64_t v = 0;
        for (size_t i = 0; i < n && i < avail; ++i) v |= (uint64_t)bytes[off + i] << (8 * i);
        return v;
    };
    ImGui::PushFont(Theme::monoFont());
    ImGui::Text("offset   0x%zX (%zu)", off, off);
    ImGui::Separator();
    ImGui::Text("int8     %d", (int)(int8_t)bytes[off]);
    ImGui::Text("uint8    %u", (unsigned)bytes[off]);
    if (avail >= 2) {
        ImGui::Text("int16    %d", (int)(int16_t)le(2));
        ImGui::Text("uint16   %u", (unsigned)le(2));
    }
    if (avail >= 4) {
        const uint32_t v = (uint32_t)le(4);
        float f;
        std::memcpy(&f, &v, 4);
        ImGui::Text("int32    %d", (int32_t)v);
        ImGui::Text("uint32   %u", v);
        ImGui::Text("hex32    0x%08X", v);
        ImGui::Text("float    %g", f);
    }
    if (avail >= 8) {
        const uint64_t v = le(8);
        double d;
        std::memcpy(&d, &v, 8);
        ImGui::Text("int64    %lld", (long long)v);
        ImGui::Text("uint64   %llu", (unsigned long long)v);
        ImGui::Text("double   %g", d);
    }
    // ULEB128 (DEX / DWARF encodings).
    {
        uint64_t v = 0;
        int shift = 0;
        size_t i = 0;
        for (; i < 10 && i < avail; ++i) {
            v |= (uint64_t)(bytes[off + i] & 0x7F) << shift;
            shift += 7;
            if (!(bytes[off + i] & 0x80)) break;
        }
        ImGui::Text("uleb128  %llu (%zu bytes)", (unsigned long long)v, i + 1);
    }
    std::string str;
    for (size_t i = 0; i < 48 && i < avail && bytes[off + i] >= 32 && bytes[off + i] < 127; ++i) str.push_back((char)bytes[off + i]);
    ImGui::TextWrapped("ascii    \"%s\"", str.c_str());
    ImGui::PopFont();
    if (ImGui::SmallButton("Copy offset")) {
        char b[32];
        std::snprintf(b, sizeof b, "0x%zX", off);
        ImGui::SetClipboardText(b);
    }
    ImGui::EndChild();
}

void EditorPanel::drawCode(Document& doc) {
    const auto& lines = doc.lines();
    const float lineHeight = ImGui::GetTextLineHeightWithSpacing();
    const float textHeight = ImGui::GetTextLineHeight();
    int target = doc.takeGoTo();
    if (target >= 0) ImGui::SetScrollY(std::max(0.f, target * lineHeight - ImGui::GetWindowHeight() * 0.33f));

    FindState* f = nullptr;
    if (!find_.empty()) {
        auto it = find_.find(&doc);
        if (it != find_.end() && it->second.open && !it->second.matches.empty()) f = &it->second;
    }
    // Consume a match jump: vertical via the shared goTo/highlight path,
    // horizontal here because only this view knows its own scroll offsets.
    if (f && f->pendingJump >= 0 && f->pendingJump < (int)f->matches.size()) {
        const textsearch::Match& m = f->matches[(size_t)f->pendingJump];
        f->pendingJump = -1;
        doc.goTo(m.line);
        float gutter = 0.f;
        if (lineNumbers()) gutter = ImGui::CalcTextSize("12345").x + 14.f;  // "%5d" + SameLine spacing
        const float matchX = gutter + columnToX(lines[(size_t)m.line], m.col + m.len);
        const float viewW = ImGui::GetWindowWidth();
        if (matchX > ImGui::GetScrollX() + viewW - 40.f)  // off-screen to the right
            ImGui::SetScrollX(std::max(0.f, matchX - viewW * 0.5f));
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGuiIO& io = ImGui::GetIO();
    std::vector<Span> spans;
    // Bookmarks and comments of this document, by line.
    struct LineNotes {
        const Annotation* bookmark = nullptr;
        const Annotation* comment = nullptr;
    };
    std::unordered_map<int, LineNotes> notes;
    Annotation here;
    const bool annotatable = annotationAt(doc, 0, here);
    if (annotatable)
        for (const Annotation& a : workspace_.annotations().all())
            if (a.target == Annotation::Target::File && a.group == here.group && a.root == here.root && a.path == here.path)
                (a.kind == Annotation::Kind::Bookmark ? notes[a.line].bookmark : notes[a.line].comment) = &a;
    const auto drawNote = [&](int i) {
        auto it = notes.find(i);
        if (it == notes.end()) return;
        const Annotation* a = it->second.comment;
        if (!a && it->second.bookmark && !it->second.bookmark->text.empty()) a = it->second.bookmark;
        if (!a) return;
        ImGui::SameLine(0, ImGui::GetFontSize());
        const std::string text = "// " + ui::noteFirstLine(a->text);
        ImGui::TextColored(a->kind == Annotation::Kind::Comment ? ui::kNoteColor : ui::kBookmarkColor, "%s", text.c_str());
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", a->text.c_str());
    };
    const bool viewHovered = ImGui::IsWindowHovered();
    ImGuiListClipper clipper;
    clipper.Begin((int)lines.size(), lineHeight);
    while (clipper.Step()) {
        // The top visible line feeds the Back/Forward history (M2).
        doc.setViewLine(std::min(clipper.DisplayStart, std::max(0, (int)lines.size() - 1)));
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ImVec2 rowPos = ImGui::GetCursorScreenPos();
            if (viewHovered && io.MousePos.y >= rowPos.y && io.MousePos.y < rowPos.y + lineHeight) {
                const bool right = ImGui::IsMouseClicked(ImGuiMouseButton_Right);
                if (right || (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !io.KeyCtrl)) {
                    lineDoc_ = &doc;
                    line_ = i;
                }
                if (right) ImGui::OpenPopup("##lineMenu");
            }
            if (lineDoc_ == &doc && line_ == i)
                dl->AddRectFilled(rowPos, ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowWidth(), rowPos.y + lineHeight),
                                  IM_COL32(255, 255, 255, 16));
            if (auto it = notes.find(i); it != notes.end() && it->second.bookmark)
                dl->AddCircleFilled(ImVec2(rowPos.x + textHeight * 0.3f, rowPos.y + textHeight * 0.5f), textHeight * 0.26f,
                                    ImGui::GetColorU32(ui::kBookmarkColor));
            if (lineNumbers()) {
                if (i == doc.highlight()) {
                    ImVec2 p = ImGui::GetCursorScreenPos();
                    float right = ImGui::GetWindowPos().x + ImGui::GetWindowWidth();
                    dl->AddRectFilled(p, ImVec2(right, p.y + lineHeight), IM_COL32(0, 122, 204, 70));
                }
                ImGui::TextDisabled("%5d", i + 1);
                ImGui::SameLine(0, 14);
            }
            // Match rects must be in the draw list BEFORE the line's text so
            // the glyphs stay on top.
            if (f) {
                if (auto it = f->byLine.find(i); it != f->byLine.end()) {
                    const std::string_view line = lines[(size_t)i];
                    const ImVec2 textPos = ImGui::GetCursorScreenPos();
                    for (int k = 0; k < it->second.second; ++k) {
                        const int idx = it->second.first + k;
                        const textsearch::Match& m = f->matches[(size_t)idx];
                        const float x0 = columnToX(line, m.col);
                        const float x1 = columnToX(line, m.col + m.len);
                        dl->AddRectFilled(ImVec2(textPos.x + x0, textPos.y),
                                          ImVec2(textPos.x + x1, textPos.y + textHeight),
                                          idx == f->current ? kCurrentMatchColor : kMatchColor);
                    }
                }
            }
            bool inBlock = doc.blockStateAt((size_t)i);
            const std::string_view line = lines[(size_t)i];
            SyntaxHighlighter::tokenize(line, doc.language(), inBlock, spans);
            if (spans.empty()) {
                ImGui::TextUnformatted("");
                drawNote(i);
                continue;
            }
            for (size_t k = 0; k < spans.size(); ++k) {
                if (k > 0) ImGui::SameLine(0, 0);
                ImGui::PushStyleColor(ImGuiCol_Text, spans[k].color);
                ImGui::TextUnformatted(line.data() + spans[k].begin, line.data() + spans[k].end);
                ImGui::PopStyleColor();
                // Ctrl+click navigation (M3): underline the identifier under
                // the cursor while Ctrl is held, open its file on click.
                if (io.KeyCtrl && ImGui::IsItemHovered()) {
                    int off = -1;
                    if (byteOffsetAtX(line, spans[k], io.MousePos.x - ImGui::GetItemRectMin().x, off)) {
                        int a = -1, b = -1;
                        if (identifierAround(line, off, a, b)) {
                            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                                symbolNavigate(doc, line, a, b);
                            } else if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                                const ImVec2 imin = ImGui::GetItemRectMin();
                                const ImVec2 imax = ImGui::GetItemRectMax();
                                const float x0 = imin.x + ImGui::CalcTextSize(line.data() + spans[k].begin,
                                                                              line.data() + a).x;
                                const float x1 = x0 + ImGui::CalcTextSize(line.data() + a, line.data() + b).x;
                                dl->AddLine(ImVec2(x0, imax.y), ImVec2(x1, imax.y), kSymbolUnderline, 1.3f);
                            }
                        }
                    }
                }
            }
            drawNote(i);
        }
    }
    drawLineMenu(doc);
}

bool EditorPanel::annotationAt(const Document& doc, int line, Annotation& out) const {
    const NavLocation loc = workspace_.locationOf(doc);
    if ((loc.kind != RootKind::Apk && loc.kind != RootKind::Decompiled) || loc.group.empty() || loc.path.empty()) return false;
    out = Annotation{};
    out.target = Annotation::Target::File;
    out.group = loc.group;
    out.root = loc.kind;
    out.path = loc.path;
    out.line = line;
    const auto& lines = doc.lines();
    if (line >= 0 && line < (int)lines.size()) {
        std::string_view text = lines[(size_t)line];
        while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
        out.context = std::string(text.substr(0, 200));
    }
    return true;
}

void EditorPanel::drawLineMenu(Document& doc) {
    if (!ImGui::BeginPopup("##lineMenu")) return;
    Annotation here;
    Annotations& notes = workspace_.annotations();
    if (lineDoc_ == &doc && annotationAt(doc, line_, here)) {
        const Annotation* comment = notes.at(Annotation::Kind::Comment, here);
        if (ImGui::MenuItem(notes.at(Annotation::Kind::Bookmark, here) ? "Remove bookmark" : "Add bookmark", "Ctrl+B"))
            notes.toggleBookmark(here);
        if (ImGui::MenuItem(comment ? "Edit comment..." : "Add comment...", ";")) comment_.open(notes, here);
        if (comment && ImGui::MenuItem("Remove comment")) notes.remove(comment->id);
    } else {
        ImGui::TextDisabled("Generated listings cannot be annotated");
    }
    ImGui::EndPopup();
}

void EditorPanel::drawEditable(Document& doc) {
    ImGui::PushFont(Theme::monoFont());
    std::string& text = doc.editBuffer();
    const ImGuiID editId = ImGui::GetID("##edit");
    const float fontSize = ImGui::GetFontSize();
    const ImGuiStyle& style = ImGui::GetStyle();

    // Give keyboard focus back to the editor after Esc closed the find bar.
    if (refocusEdit_) {
        refocusEdit_ = false;
        ImGui::SetKeyboardFocusHere();
    }

    // Jump to a search hit: consumed here as well, not only in the read-only
    // view (decompiled documents open in this editor).
    int goTo = doc.takeGoTo();

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

    // Remember the current selection (single line only) so Ctrl+F can prefill
    // the find bar with it - like every mainstream editor does.
    const ImGuiInputTextState* selState = ImGui::GetInputTextState(editId);
    if (selState && selState->Stb && selState->Stb->select_start != selState->Stb->select_end) {
        const int a = ImMin(selState->Stb->select_start, selState->Stb->select_end);
        const int b = ImMax(selState->Stb->select_start, selState->Stb->select_end);
        // Single line: the first newline at/after the selection start lies
        // beyond its end (npos counts as "beyond").
        if (a >= 0 && b <= (int)text.size() && text.find('\n', (size_t)a) > (size_t)b)
            selSnippet_ = text.substr((size_t)a, (size_t)(b - a));
    } else if (!selSnippet_.empty()) {
        selSnippet_.clear();  // selection gone: nothing to prefill next time
    }

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

    // Scroll the jumped-to line into view (applied on the child's next
    // layout pass, one frame later).
    if (goTo >= 0 && inputWindow) {
        float target = std::max(0.f, goTo * fontSize - (inputWindow->Size.y - fontSize) * 0.33f);
        ImGui::SetScrollY(inputWindow, target);
    }

    const ImVec2 textOrigin(frameMin.x + style.FramePadding.x, frameMin.y + style.FramePadding.y);
    const float right = frameMax.x - (inputWindow ? inputWindow->ScrollbarSizes.x : 0.f);
    dl->PushClipRect(frameMin, ImVec2(right, frameMax.y), true);

    // Highlight band behind the search hit (under the text and the caret).
    if (doc.highlight() >= 0 && inputWindow) {
        const float y = textOrigin.y + (float)doc.highlight() * fontSize - scrollY;
        if (y + fontSize >= frameMin.y && y <= frameMax.y)
            dl->AddRectFilled(ImVec2(frameMin.x, y), ImVec2(right, y + fontSize), IM_COL32(0, 122, 204, 60));
    }

    const auto lines = doc.lines();
    const std::vector<uint32_t>& offsets = doc.lineOffsets();
    const int lineCount = (int)lines.size();
    const float viewHeight = frameMax.y - frameMin.y;
    const int first = std::max(0, (int)(scrollY / fontSize) - 1);
    const int last = std::min(lineCount, first + (int)(viewHeight / fontSize) + 3);
    doc.setViewLine(std::min(first, std::max(0, lineCount - 1)));  // for the nav history

    // Match overlays: drawn into the same overlay list, below the line's
    // glyphs (the rects are added before the AddText calls of that line).
    FindState* f = nullptr;
    if (!find_.empty()) {
        auto it = find_.find(&doc);
        if (it != find_.end() && it->second.open && !it->second.matches.empty()) f = &it->second;
    }

    std::vector<Span> spans;
    for (int i = first; i < last; ++i) {
        const std::string_view line = lines[(size_t)i];
        const float y = textOrigin.y + (float)i * fontSize - scrollY;
        if (f) {
            if (auto it = f->byLine.find(i); it != f->byLine.end()) {
                const float xBase = textOrigin.x - scrollX;
                for (int k = 0; k < it->second.second; ++k) {
                    const int idx = it->second.first + k;
                    const textsearch::Match& m = f->matches[(size_t)idx];
                    const float x0 = columnToX(line, m.col);
                    const float x1 = columnToX(line, m.col + m.len);
                    dl->AddRectFilled(ImVec2(xBase + x0, y), ImVec2(xBase + x1, y + fontSize),
                                      idx == f->current ? kCurrentMatchColor : kMatchColor);
                }
            }
        }
        bool inBlock = doc.blockStateAt((size_t)i);
        SyntaxHighlighter::tokenize(line, doc.language(), inBlock, spans);
        float x = textOrigin.x - scrollX;
        for (const Span& span : spans) {
            if (span.end <= span.begin) continue;
            const char* s = line.data() + span.begin;
            const char* e = line.data() + span.end;
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

// ---------------------------------------------------------------------------
// Find in file (M1) and go to line
// ---------------------------------------------------------------------------

FindState* EditorPanel::findState(const Document& doc) { return &find_[&doc]; }

// Editor-scoped shortcuts: they must not steal Ctrl+F/G from a text field in
// another panel, hence the window-focus check. Runs only for the visible tab
// (drawDocument is called from inside its BeginTabItem).
void EditorPanel::processShortcuts(Document& doc) {
    if (doc.mode() != Document::Mode::Code) return;
    ImGuiIO& io = ImGui::GetIO();
    if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) return;
    FindState* f = findState(doc);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) openFind(doc, *f);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false)) openGoTo(doc);
    if (f->open && !io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F3, false))
        moveMatch(*f, io.KeyShift ? -1 : 1);
    if (lineDoc_ == &doc && !doc.isEditing() && !io.WantTextInput) {
        Annotation here;
        if (annotationAt(doc, line_, here)) {
            if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_B, false)) workspace_.annotations().toggleBookmark(here);
            if (!io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false)) comment_.open(workspace_.annotations(), here);
        }
    }
}

void EditorPanel::openFind(Document& doc, FindState& f) {
    (void)doc;
    f.open = true;
    f.focusInput = true;
    // Prefill with the editor selection (single line, captured while it was
    // drawn) before the user's own typing has a chance to overwrite it.
    if (!selSnippet_.empty() && selSnippet_.size() < sizeof f.query) {
        std::snprintf(f.query, sizeof f.query, "%s", selSnippet_.c_str());
        selSnippet_.clear();
    }
}

void EditorPanel::openGoTo(Document& doc) {
    const int n = std::max<int>((int)doc.lines().size(), 1);
    gotoValue_ = doc.highlight() >= 0 ? std::clamp(doc.highlight() + 1, 1, n) : 1;
    gotoOpenRequest_ = true;
    gotoFocus_ = true;
}

// Rebuilds the match list only when something actually changed: the query,
// the options or the document text (cheap revision counter, no text hash).
void EditorPanel::recomputeMatches(Document& doc, FindState& f) {
    const std::string query = f.query;
    if (query == f.lastQuery && f.opt.matchCase == f.lastCase && f.opt.wholeWord == f.lastWord &&
        f.docSerial == doc.textRevision())
        return;
    f.lastQuery = query;
    f.lastCase = f.opt.matchCase;
    f.lastWord = f.opt.wholeWord;
    f.docSerial = doc.textRevision();
    f.truncated = false;
    f.matches = textsearch::findAll(doc.lines(), query, f.opt, textsearch::kDefaultMaxMatches, f.truncated);
    f.byLine.clear();
    for (size_t i = 0; i < f.matches.size(); ++i) {
        auto& slot = f.byLine[f.matches[i].line];
        if (slot.second == 0) slot.first = (int)i;
        ++slot.second;
    }
    // Anchor the current match at the visible/highlighted line; an empty
    // query or a document without matches clears it.
    if (f.matches.empty()) {
        f.current = -1;
    } else {
        const int anchor = doc.highlight() >= 0 ? doc.highlight() : 0;
        f.current = textsearch::nextIndex(f.matches, anchor, 0);
        f.pendingJump = f.current;
    }
}

void EditorPanel::moveMatch(FindState& f, int dir) {
    if (f.matches.empty()) return;
    int idx = f.current;
    if (idx < 0 || idx >= (int)f.matches.size())
        idx = dir > 0 ? 0 : (int)f.matches.size() - 1;
    else
        idx = (idx + dir + (int)f.matches.size()) % (int)f.matches.size();
    f.current = idx;
    f.pendingJump = idx;
}

void EditorPanel::drawFindBar(Document& doc, FindState& f) {
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::PushID("##findbar");

    if (f.focusInput) {
        ImGui::SetKeyboardFocusHere();
        f.focusInput = false;
    }
    ImGui::SetNextItemWidth(220.f);
    const bool enter = ImGui::InputText("##find", f.query, sizeof f.query, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter) moveMatch(f, ImGui::GetIO().KeyShift ? -1 : 1);  // Enter / Shift+Enter

    ImGui::SameLine(0, style.ItemInnerSpacing.x);
    if (toggleButton("Aa", f.opt.matchCase)) f.opt.matchCase = !f.opt.matchCase;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Match case");
    ImGui::SameLine(0, 2.f);
    if (toggleButton("W", f.opt.wholeWord)) f.opt.wholeWord = !f.opt.wholeWord;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Whole word");

    ImGui::SameLine(0, style.ItemInnerSpacing.x);
    if (ImGui::SmallButton("<")) moveMatch(f, -1);  // Shift+F3 / Shift+Enter
    ImGui::SameLine(0, 2.f);
    if (ImGui::SmallButton(">")) moveMatch(f, 1);   // F3 / Enter

    ImGui::SameLine(0, style.ItemInnerSpacing.x);
    if (f.query[0] == 0) {
        ImGui::TextDisabled(" ");
    } else if (f.matches.empty()) {
        ImGui::TextColored(kErrorColor, "No results");
    } else if (f.truncated) {
        ImGui::TextDisabled("%d+ results", (int)textsearch::kDefaultMaxMatches);
    } else {
        const int at = f.current >= 0 ? f.current + 1 : 0;
        ImGui::TextDisabled("%d of %d", at, (int)f.matches.size());
    }

    ImGui::SameLine(0, style.ItemInnerSpacing.x);
    const bool editorFocused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    if (ImGui::SmallButton("x##closefind") || (editorFocused && ImGui::IsKeyPressed(ImGuiKey_Escape, false))) {
        if (!ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) {  // let modals keep Esc
            f.open = false;
            refocusEdit_ = doc.isEditing();  // give the keyboard back to the editor
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Close (Esc)");

    // Typing updates the matches incrementally; this call returns immediately
    // when query, options and text are unchanged.
    recomputeMatches(doc, f);
    ImGui::PopID();
}

void EditorPanel::drawGoToModal() {
    bool open = ImGui::BeginPopupModal("Go to line", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
    if (!open) return;
    Document* doc = workspace_.activeDocument();
    if (!doc || doc->mode() != Document::Mode::Code) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    const int n = std::max<int>((int)doc->lines().size(), 1);
    ImGui::Text("Go to line (1 - %d):", n);
    if (gotoFocus_) {
        ImGui::SetKeyboardFocusHere();
        gotoFocus_ = false;
    }
    ImGui::SetNextItemWidth(140.f);
    const bool submit = ImGui::InputInt("##gotoline", &gotoValue_, 0, 0, ImGuiInputTextFlags_EnterReturnsTrue);
    // Out-of-range input is clamped to [1, N] instead of being rejected.
    if (submit) {
        const int target = std::clamp(gotoValue_, 1, n) - 1;  // UI is 1-based, goTo is 0-based
        // Same-document jump: record it for Back/Forward without re-opening.
        const NavLocation origin = workspace_.locationOf(*doc);
        NavLocation dest = origin;
        dest.line = target;
        workspace_.recordJump(origin, dest);
        doc->goTo(target);
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

// Drops find state of documents that no longer exist (closed tab, replaced
// preview) so the map can never grow and addresses are never reused stale.
void EditorPanel::sweepFindStates() {
    auto& docs = workspace_.documents();
    for (auto it = hex_.begin(); it != hex_.end();) {
        const bool alive = std::any_of(docs.begin(), docs.end(),
                                       [&](const std::unique_ptr<Document>& d) { return d.get() == it->first; });
        if (alive) ++it;
        else it = hex_.erase(it);
    }
    if (find_.empty()) return;
    for (auto it = find_.begin(); it != find_.end();) {
        const bool alive = std::any_of(docs.begin(), docs.end(),
                                       [&](const std::unique_ptr<Document>& d) { return d.get() == it->first; });
        if (alive) ++it;
        else it = find_.erase(it);
    }
}

float EditorPanel::columnToX(std::string_view line, int col) const {
    if (col <= 0) return 0.f;
    if ((size_t)col >= line.size()) return ImGui::CalcTextSize(line.data(), line.data() + line.size()).x;
    return ImGui::CalcTextSize(line.data(), line.data() + col).x;
}

// Ctrl+click on an identifier (M3): resolve it against the document's group
// symbol index and jump to the declaring file. Unresolved identifiers get a
// quiet log line instead of failing silently.
void EditorPanel::symbolNavigate(Document& doc, std::string_view line, int a, int b) {
    if (a < 0 || b <= a || (size_t)b > line.size()) return;
    const std::string ident(line.substr((size_t)a, (size_t)(b - a)));
    std::string hintDir;
    if (doc.node()) {
        const std::string& p = doc.node()->path();
        const size_t slash = p.find_last_of('/');
        if (slash != std::string::npos) hintDir = p.substr(0, slash);
    }
    const NavLocation origin = workspace_.locationOf(doc);
    if (!workspace_.openSymbol(doc.rootGroup(), ident, hintDir, &origin))
        workspace_.log("No source file declares '" + ident + "'");
}

// ---------------------------------------------------------------------------
// Document export (M5)
// ---------------------------------------------------------------------------

void EditorPanel::openExport(Document& doc) {
    exportDoc_ = &doc;
    exportBrowser_.open(FileBrowser::Mode::SaveFile);
    exportBrowser_.setDefaultName(doc.title());  // after open(): open() resets the name
}

// Consumes the export destination browser; the raw-vs-decoded choice follows
// the document mode (code documents export their text, everything else the
// exact bytes). The explorer's context menu offers both variants explicitly.
void EditorPanel::drawExportBrowser() {
    std::string picked;
    if (exportBrowser_.render(), exportBrowser_.takeAccepted(picked)) {
        Document* doc = exportDoc_;
        exportDoc_ = nullptr;
        if (!doc) return;
        // Unsaved edits are exported as the user sees them: dirty code
        // documents write the edit buffer instead of the on-disk bytes.
        if (doc->mode() == Document::Mode::Code && doc->isDirty()) {
            std::ofstream out(pathutil::fromUtf8(pathutil::normalize(picked)), std::ios::binary);
            if (!out) {
                workspace_.log("Export failed: cannot write " + picked);
                return;
            }
            const auto lines = doc->lines();
            for (size_t i = 0; i < lines.size(); ++i) {
                if (i) out << '\n';
                out << lines[i];
            }
            workspace_.log("Exported " + doc->title() + " (with unsaved edits) to " + picked);
            return;
        }
        Root* root = workspace_.rootByGroup(doc->rootGroup(), doc->rootKind());
        if (root && doc->node())
            workspace_.exportNode(*root, *doc->node(), picked, doc->mode() == Document::Mode::Code);
        else
            workspace_.log("Export failed: the document is no longer available");
    } else if (!exportBrowser_.isOpen() && exportDoc_) {
        exportDoc_ = nullptr;  // browser closed without accepting
    }
}
