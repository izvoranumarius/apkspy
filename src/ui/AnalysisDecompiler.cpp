// Decompiler panel of the Analysis workspace, laid out like Cutter's and
// edited like IDA's pseudocode view: the code of the selection with its
// variables declared and typed, a text cursor (arrows, or a click) that
// highlights the identifier under it and keeps the listing in sync, N to
// rename a variable and Y to set its type. Names and types are project
// annotations, shared with MCP (rename_variable).
#include <algorithm>
#include <cstdio>
#include <cstring>
#include "analysis/Dalvik.hpp"
#include "app/Theme.hpp"
#include "document/SyntaxHighlighter.hpp"
#include "ui/AnalysisPanel.hpp"
#include "ui/UiUtil.hpp"

namespace {

std::string addrText(const decompiler::Line& l, bool native) {
    std::string out;
    char b[32];
    for (size_t i = 0; i < l.addrs.size() && i < 8; ++i) {
        std::snprintf(b, sizeof b, native ? "0x%llx" : "%04llx", static_cast<unsigned long long>(l.addrs[i]));
        out += (i ? ", " : "") + std::string(b);
    }
    if (l.addrs.size() > 8) out += ", ...";
    return out;
}

std::string shownText(const decompiler::Line& l) {
    return std::string(static_cast<size_t>(std::max(l.indent, 0)) * 4, ' ') + l.text;
}

// Removes the name / type the user gave a variable.
void removeVariableNote(Annotations& notes, const Annotation& slot) {
    for (const Annotation& a : notes.all())
        if (a.sameSlot(slot)) {
            notes.remove(a.id);
            return;
        }
}

}  // namespace

void AnalysisPanel::drawDecompiler() {
    // What the Function panel shows.
    auto analysis = current_.lock();
    int kind = 0;
    uint64_t key = UINT64_MAX;
    const void* owner = nullptr;
    const NativeCode::Function* func = nullptr;
    if (sel_ == Selection::Native && native_ && funcAddr_ != UINT64_MAX) {
        func = native_->functionAt(funcAddr_);
        if (func) kind = 2, key = func->addr, owner = native_.get();
    } else if (sel_ == Selection::Method && analysis && selMethod_.dex < analysis->dexes().size()) {
        kind = 1;
        key = static_cast<uint64_t>(selMethod_.dex) << 32 | selMethod_.method.methodIdx;
        owner = analysis.get();
    }

    Annotations& notes = workspace_.annotations();
    const bool stale = kind != decompKind_ || key != decompKey_ || owner != decompOwner_;
    if (kind != 0 && ((stale && (decompAuto_ || decompKind_ == 0)) || decompRefresh_)) {
        decompLoc_ = Annotation{};
        decompLoc_.kind = Annotation::Kind::Rename;
        if (kind == 2) {
            decompRaw_ = decompiler::decompileNative(*native_, *func);
            decompTitle_ = NativeCode::displayName(*func);
            decompLoc_.target = Annotation::Target::Native;
            decompLoc_.group = libsGroup_;
            decompLoc_.path = native_->elf().name();
            decompLoc_.addr = func->addr;
            decompSymLoc_ = decompLoc_;
            decompSymLoc_.addr = 0;  // the whole library
        } else {
            decompRaw_ = decompiler::decompileMethod(*analysis, selMethod_);
            decompTitle_ = analysis->methodSignature(selMethod_);
            decompLoc_.target = Annotation::Target::Method;
            decompLoc_.group = currentGroup_;
            decompLoc_.path = decompTitle_;
            decompSymLoc_ = decompLoc_;
            decompSymLoc_.path = "*";  // the whole APK
        }
        decompSymLoc_.kind = Annotation::Kind::Symbol;
        decompKind_ = kind;
        decompKey_ = key;
        decompOwner_ = owner;
        decompSynced_ = UINT64_MAX;
        decompLine_ = -1;
        decompCol_ = 0;
        decompScroll_ = false;
        decompNotesVersion_ = 0;
        decompToken_.clear();
        decompRenameOpen_ = false;
    }
    decompRefresh_ = false;
    const bool native = decompKind_ == 2;
    if (decompKind_ != 0 && decompNotesVersion_ != notes.version()) {  // the user's names and types
        decomp_ = decompRaw_;
        decompiler::applyUserNames(decomp_, notes.renames(decompLoc_), notes.retypes(decompLoc_), native,
                                   notes.variableNotes(decompSymLoc_, Annotation::Kind::Symbol));
        decompNotesVersion_ = notes.version();
    }
    const bool following = decompKind_ != 0 && !(kind != decompKind_ || key != decompKey_ || owner != decompOwner_);

    if (decompKind_ == 0) {
        ImGui::TextDisabled("Select a method in Classes, or a function in Native.");
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::Info));
        ImGui::TextUnformatted(decompTitle_.c_str());
        ImGui::PopStyleColor();
        if (!following) {
            ImGui::SameLine();
            ImGui::TextDisabled("(not the selection - Refresh to follow it)");
        }
    }

    // The listing's current instruction.
    uint64_t cur = UINT64_MAX;
    if (following && decompKind_ == 1 && listingPc_ >= 0) cur = static_cast<uint64_t>(listingPc_);
    if (following && decompKind_ == 2 && focusAddr_) cur = focusAddr_;
    const int lineCount = static_cast<int>(decomp_.lines.size());
    if (cur != decompSynced_) {
        decompSynced_ = cur;
        for (int i = 0; i < lineCount && cur != UINT64_MAX; ++i)
            if (decomp_.lines[static_cast<size_t>(i)].contains(cur)) {
                decompLine_ = i;
                decompScroll_ = true;
                break;
            }
    }

    // Puts the cursor on a line / column, highlights the identifier there and shows the line's code in the listing.
    const auto moveCursor = [&](int line, size_t col) {
        if (lineCount == 0) return;
        decompLine_ = std::clamp(line, 0, lineCount - 1);
        const decompiler::Line& l = decomp_.lines[static_cast<size_t>(decompLine_)];
        const std::string shown = shownText(l);
        decompCol_ = std::min(col, shown.size());
        decompToken_ = decompiler::identifierAt(shown, decompCol_);
        decompScroll_ = true;
        if (following && !l.addrs.empty()) {
            const uint64_t a = l.firstAddr();
            decompSynced_ = a;
            if (decompKind_ == 1) {
                listingPc_ = static_cast<int32_t>(a);
                listingScroll_ = true;
            } else {
                focusAddr_ = a;
                scrollToFocus_ = true;
            }
        }
    };
    // N renames what is under the cursor: a variable (this function) or any other name (everywhere).
    // Y sets a variable's type.
    const auto startEdit = [&](bool type) {
        if (!following) {
            decompStatus_ = "Refresh first: this is not the selection";
            return;
        }
        const std::string k = decompToken_.empty() ? std::string() : decompiler::keyOfShown(decomp_, decompToken_, native);
        const std::string sym = decompToken_.empty() ? std::string() : decompiler::symbolOfShown(decomp_, decompToken_, native);
        if (!k.empty()) {
            decompEditSymbol_ = false;
            decompRenameKey_ = k;
        } else if (!type && !sym.empty()) {
            decompEditSymbol_ = true;
            decompRenameKey_ = sym;
        } else {
            decompStatus_ = type ? "Y sets a variable's type: put the cursor on a variable (" + std::string(native ? "x19, sp_10" : "v3, arg0") + ")"
                                 : "Put the cursor on a name (keywords and built-in types cannot be renamed)";
            return;
        }
        decompRenameOpen_ = true;
        decompEditType_ = type;
        decompStatus_.clear();
    };

    // Bottom bar, as in Cutter: Auto Refresh, Refresh, shortcuts, engine.
    const float barH = ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("##decomp", ImVec2(0, -barH), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoNavInputs);
    if (!decomp_.error.empty()) ImGui::TextColored(theme::vec(Col::Warning), "%s", decomp_.error.c_str());
    ImGui::PushFont(Theme::monoFont());
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);

    // Keyboard, as in IDA: arrows move the cursor, Enter follows a call, N renames, Y sets the type.
    // The code view owns these keys: ImGui's keyboard navigation must not move to the bar's buttons.
    if (focused && !ImGui::GetIO().WantTextInput) {
        const ImGuiID keyOwner = ImGui::GetID("##decompKeys");
        for (ImGuiKey k : {ImGuiKey_UpArrow, ImGuiKey_DownArrow, ImGuiKey_LeftArrow, ImGuiKey_RightArrow, ImGuiKey_PageUp,
                           ImGuiKey_PageDown, ImGuiKey_Home, ImGuiKey_End, ImGuiKey_Enter, ImGuiKey_KeypadEnter, ImGuiKey_Space})
            ImGui::SetKeyOwner(k, keyOwner);
    }
    if (focused && !ImGui::GetIO().WantTextInput && lineCount > 0) {
        const int page = std::max(1, static_cast<int>(ImGui::GetWindowHeight() / lh) - 2);
        const int line = std::max(decompLine_, 0);
        const std::string shown = shownText(decomp_.lines[static_cast<size_t>(line)]);
        const bool ctrl = ImGui::GetIO().KeyCtrl;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) moveCursor(decompLine_ < 0 ? 0 : line + 1, decompCol_);
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) moveCursor(line - 1, decompCol_);
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) moveCursor(line + page, decompCol_);
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) moveCursor(line - page, decompCol_);
        if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) moveCursor(ctrl ? 0 : line, ctrl ? 0 : shown.find_first_not_of(' '));
        if (ImGui::IsKeyPressed(ImGuiKey_End, false)) moveCursor(ctrl ? lineCount - 1 : line, ctrl ? 0 : shown.size());
        if (ImGui::IsKeyPressed(ImGuiKey_RightArrow) || ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) {
            // Identifier by identifier, like a word cursor.
            const std::vector<size_t> starts = decompiler::identifierStarts(shown);
            const bool right = ImGui::IsKeyPressed(ImGuiKey_RightArrow);
            size_t col = decompCol_;
            if (right) {
                auto it = std::upper_bound(starts.begin(), starts.end(), decompCol_);
                if (it != starts.end()) col = *it;
            } else {
                auto it = std::lower_bound(starts.begin(), starts.end(), decompCol_);
                if (it != starts.begin()) col = *(it - 1);
            }
            moveCursor(line, col);
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false))
            if (following && decompLine_ >= 0) decompilerFollowCall(decomp_.lines[static_cast<size_t>(decompLine_)]);
        if (ImGui::IsKeyPressed(ImGuiKey_N, false) && !ctrl) startEdit(false);
        if (ImGui::IsKeyPressed(ImGuiKey_Y, false) && !ctrl) startEdit(true);
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) decompToken_.clear(), decompStatus_.clear();
    }
    if (decompScroll_ && decompLine_ >= 0) {
        decompScroll_ = false;
        const float y = static_cast<float>(decompLine_) * lh;
        if (y < ImGui::GetScrollY() || y > ImGui::GetScrollY() + ImGui::GetWindowHeight() - lh * 2)
            ImGui::SetScrollY(std::max(0.f, y - ImGui::GetWindowHeight() * 0.3f));
    }

    std::vector<Span> spans;
    bool inBlock = false;
    int clickedLine = -1;
    size_t clickedCol = 0;
    ImGuiListClipper clipper;
    clipper.Begin(lineCount, lh);
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const decompiler::Line& l = decomp_.lines[static_cast<size_t>(i)];
            ImGui::PushID(i);
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            const std::string shown = shownText(l);
            const bool atCur = cur != UINT64_MAX && l.contains(cur);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            if (atCur || i == decompLine_) {
                const ImVec2 end(pos.x + std::max(ImGui::GetContentRegionAvail().x, ImGui::GetWindowWidth()), pos.y + lh);
                dl->AddRectFilled(pos, end, theme::u32(i == decompLine_ ? Col::RowSelected : Col::RowHover));
            }
            // Positions are measured on the text: the code font is not strictly monospaced ($, some symbols).
            const auto xOf = [&](size_t c) { return pos.x + ImGui::CalcTextSize(shown.data(), shown.data() + std::min(c, shown.size())).x; };
            if (!decompToken_.empty())
                for (size_t at : decompiler::findIdentifier(shown, decompToken_))
                    dl->AddRectFilled(ImVec2(xOf(at), pos.y), ImVec2(xOf(at + decompToken_.size()), pos.y + ImGui::GetTextLineHeight()),
                                      theme::u32(Col::TextSelection));
            // The column under the mouse (for the cursor, highlighting and renaming): the nearest character boundary.
            const float mx = ImGui::GetIO().MousePos.x;
            size_t col = 0;
            for (float x = pos.x; col < shown.size(); ++col) {
                const float w = ImGui::CalcTextSize(shown.data() + col, shown.data() + col + 1).x;
                if (mx < x + w * 0.5f) break;
                x += w;
            }
            const bool hoveredRow = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + ImGui::GetWindowWidth() * 4, pos.y + lh));
            if (ImGui::Selectable("##dl", false, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(0, ImGui::GetTextLineHeight()))) {
                clickedLine = i;
                clickedCol = std::min(col, shown.size());
                if (following && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    // Double-click: a variable is renamed (as in many decompilers), a call is followed.
                    const std::string tok = decompiler::identifierAt(shown, clickedCol);
                    if (!decompiler::keyOfShown(decomp_, tok, native).empty()) decompRenameOpen_ = false, decompToken_ = tok, startEdit(false);
                    else decompilerFollowCall(l);
                }
            }
            if (hoveredRow && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                decompLine_ = i;
                decompCol_ = std::min(col, shown.size());
                decompToken_ = decompiler::identifierAt(shown, decompCol_);
            }
            if (ImGui::IsItemHovered() && !l.addrs.empty())
                ImGui::SetTooltip("%s %s", native ? "address" : "pc", addrText(l, native).c_str());
            if (ImGui::BeginPopupContextItem("##dctx")) {
                const std::string k = decompToken_.empty() ? std::string() : decompiler::keyOfShown(decomp_, decompToken_, native);
                const std::string sym = k.empty() && !decompToken_.empty() ? decompiler::symbolOfShown(decomp_, decompToken_, native)
                                                                           : std::string();
                if (!sym.empty() && following) {
                    if (ImGui::MenuItem(("Rename " + decompToken_ + " everywhere...").c_str(), "N")) startEdit(false);
                    if (decompToken_ != sym && ImGui::MenuItem(("Reset name (" + sym + ")").c_str())) {
                        Annotation slot = decompSymLoc_;
                        slot.context = sym;
                        removeVariableNote(notes, slot);
                        decompToken_ = sym;
                    }
                    ImGui::Separator();
                }
                if (!k.empty() && following) {
                    if (ImGui::MenuItem(("Rename " + decompToken_ + "...").c_str(), "N")) startEdit(false);
                    if (ImGui::MenuItem(("Set type of " + decompToken_ + "...").c_str(), "Y")) startEdit(true);
                    Annotation slot = decompLoc_;
                    slot.context = k;
                    if (decompToken_ != k && ImGui::MenuItem(("Reset name (" + k + ")").c_str())) {
                        removeVariableNote(notes, slot);
                        decompToken_ = k;
                    }
                    slot.kind = Annotation::Kind::Retype;
                    if (notes.variableNotes(decompLoc_, Annotation::Kind::Retype).size() &&
                        std::any_of(notes.all().begin(), notes.all().end(), [&](const Annotation& a) { return a.sameSlot(slot); }) &&
                        ImGui::MenuItem("Reset type"))
                        removeVariableNote(notes, slot);
                    ImGui::Separator();
                }
                if (ImGui::MenuItem("Copy line")) ImGui::SetClipboardText(l.text.c_str());
                if (ImGui::MenuItem("Copy function")) ImGui::SetClipboardText(decompiler::toText(decomp_).c_str());
                ImGui::EndPopup();
            }
            // Java colouring also suits the C-like output: strings, numbers, comments, keywords.
            inBlock = false;
            SyntaxHighlighter::tokenize(shown, Language::Java, inBlock, spans);
            float x = pos.x;
            for (const Span& s : spans) {
                const char* b = shown.data() + s.begin;
                const char* e = shown.data() + s.end;
                dl->AddText(ImVec2(x, pos.y), theme::syntax(s.token), b, e);
                x += ImGui::CalcTextSize(b, e).x;
            }
            // The text cursor.
            if (i == decompLine_ && focused) {
                const float cx = xOf(decompCol_);
                dl->AddLine(ImVec2(cx, pos.y), ImVec2(cx, pos.y + ImGui::GetTextLineHeight()), theme::u32(Col::Text), 1.5f);
            }
            ImGui::PopID();
        }
    // A click puts the cursor there: the identifier under it is highlighted everywhere.
    if (clickedLine >= 0 && !decompRenameOpen_) moveCursor(clickedLine, clickedCol);
    else if (clickedLine >= 0) decompLine_ = clickedLine, decompCol_ = clickedCol;
    ImGui::PopFont();
    ImGui::EndChild();

    ImGui::Checkbox("Auto Refresh", &decompAuto_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Decompile whatever the Function panel shows");
    ImGui::SameLine();
    if (ui::smallButton("Refresh")) decompRefresh_ = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Decompile the current selection again");
    ImGui::SameLine();
    const std::string tokenKey = decompToken_.empty() ? std::string() : decompiler::keyOfShown(decomp_, decompToken_, native);
    const char* engine = native ? "built-in (AArch64 -> C)" : "built-in (Dalvik -> Java)";
    const float engineW = ImGui::CalcTextSize(engine).x;
    const float right = ImGui::GetWindowContentRegionMax().x;
    // The hint gets the room left of the engine label (which goes first when space runs out).
    const bool tokenSymbol = tokenKey.empty() && !decompToken_.empty() && !decompiler::symbolOfShown(decomp_, decompToken_, native).empty();
    std::string hint = !decompStatus_.empty() ? decompStatus_
                       : !tokenKey.empty()    ? decompToken_ + ": N rename, Y set type"
                       : tokenSymbol          ? decompToken_ + ": N rename everywhere"
                                              : "arrows / click: cursor, N rename, Y set type";
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const bool roomForEngine = ImGui::GetCursorPosX() + ImGui::CalcTextSize(hint.c_str()).x + spacing * 2 + engineW <= right;
    if (!decompStatus_.empty()) ImGui::TextColored(theme::vec(Col::Warning), "%s", hint.c_str());
    else ImGui::TextDisabled("%s", hint.c_str());
    if (roomForEngine) {
        ImGui::SameLine(right - engineW);
        ImGui::TextDisabled("%s", engine);
    }

    decompilerRenamePopup();
}

void AnalysisPanel::decompilerRenamePopup() {
    const bool native = decompKind_ == 2;
    Annotations& notes = workspace_.annotations();
    const char* title = decompEditType_ ? "Set variable type" : decompEditSymbol_ ? "Rename everywhere" : "Rename variable";
    const std::vector<std::pair<std::string, std::string>>& shownNames = decompEditSymbol_ ? decomp_.renamedSymbols : decomp_.renamed;
    if (decompRenameOpen_) {
        decompRenameOpen_ = false;
        // Start from the current name / type.
        std::string current = decompRenameKey_;
        if (decompEditType_) {
            current = decompiler::typeOf(decomp_, decompRenameKey_, notes.retypes(decompLoc_));
        } else {
            for (const auto& [shown, key] : shownNames)
                if (key == decompRenameKey_) current = shown;
        }
        std::snprintf(decompRenameBuf_, sizeof decompRenameBuf_, "%s", current.c_str());
        decompRenameError_.clear();
        ImGui::OpenPopup(title);
    }
    if (!ImGui::BeginPopup(title)) return;
    std::string shownName = decompRenameKey_;
    for (const auto& [shown, key] : shownNames)
        if (key == decompRenameKey_) shownName = shown;
    if (decompEditType_) ImGui::Text("Type of %s", shownName.c_str());
    else if (decompEditSymbol_) ImGui::Text("Rename %s in every function of %s", shownName.c_str(), native ? decompSymLoc_.path.c_str() : "this APK");
    else ImGui::Text("Rename %s", shownName.c_str());
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(ui::em(18.f));
    bool apply = ImGui::InputText("##newname", decompRenameBuf_, sizeof decompRenameBuf_,
                                  ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
    if (decompEditType_) ImGui::TextDisabled("e.g. String, int, uint8_t *, MyStruct *. Empty restores the inferred type.");
    else ImGui::TextDisabled("Empty restores %s. Saved with the project.", decompRenameKey_.c_str());
    if (!decompRenameError_.empty()) ImGui::TextColored(theme::vec(Col::Error), "%s", decompRenameError_.c_str());
    apply |= ui::smallButton("OK");
    ImGui::SameLine();
    if (ui::smallButton("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
    if (apply) {
        std::string value = decompRenameBuf_;
        while (!value.empty() && value.back() == ' ') value.pop_back();
        while (!value.empty() && value.front() == ' ') value.erase(0, 1);
        Annotation slot = decompEditSymbol_ ? decompSymLoc_ : decompLoc_;
        slot.kind = decompEditType_ ? Annotation::Kind::Retype : decompEditSymbol_ ? Annotation::Kind::Symbol : Annotation::Kind::Rename;
        slot.context = decompRenameKey_;
        if (decompEditSymbol_) {
            if (value == decompRenameKey_) value.clear();  // the original name: same as resetting
            decompRenameError_ = decompiler::checkSymbolName(decomp_, value, native);
        } else if (decompEditType_) {
            std::string inferred;
            for (const decompiler::Var& v : decomp_.vars)
                if (v.key == decompRenameKey_) inferred = v.type;
            if (value == inferred) value.clear();  // the inferred type: same as resetting
            decompRenameError_ = decompiler::checkTypeName(value);
        } else {
            if (value == decompRenameKey_) value.clear();  // the original name: same as resetting
            decompRenameError_ = decompiler::checkNewName(decomp_, value, decompRenameKey_, native);
        }
        if (decompRenameError_.empty()) {
            if (value.empty()) {
                removeVariableNote(notes, slot);
            } else {
                slot.text = value;
                notes.set(slot);
            }
            if (!decompEditType_) decompToken_ = value.empty() ? decompRenameKey_ : value;
            ImGui::CloseCurrentPopup();
        }
    }
    ImGui::EndPopup();
}

// Enter / double-click: a line holding a call goes to the called method / function.
void AnalysisPanel::decompilerFollowCall(const decompiler::Line& line) {
    if (decompKind_ == 2 && native_) {
        for (uint64_t a : line.addrs)
            for (const NativeCode::Line& l : listing_)
                if (l.insn.addr == a && l.insn.flow == arm64::Flow::Call && l.insn.hasTarget && native_->functionAt(l.insn.target)) {
                    gotoNative(l.insn.target);
                    return;
                }
        return;
    }
    auto analysis = current_.lock();
    if (decompKind_ != 1 || !analysis || selMethod_.dex >= analysis->dexes().size()) return;
    const ApkAnalysis& a = *analysis;
    const DexFile& dex = *a.dexes()[selMethod_.dex];
    DexFile::CodeItem code;
    if (!selMethod_.method.codeOff || !dex.codeItem(selMethod_.method.codeOff, code)) return;
    for (uint64_t pc : line.addrs) {
        if (pc >= code.insnsSize) continue;
        const dalvik::Insn in = dalvik::decode(code, static_cast<uint32_t>(pc));
        const auto& info = dalvik::opInfo(in.opcode);
        if (!in.valid || info.flow != dalvik::Flow::Invoke || info.ref != dalvik::RefKind::Method || in.index >= dex.methodCount())
            continue;
        const std::string ref = dex.methodSignature(in.index);
        std::string cls, name, proto;
        if (!ApkAnalysis::splitMethodRef(ref, cls, name, proto)) continue;
        const auto defs = a.findMethodDefs(cls, name, proto);
        if (defs.empty()) {
            workspace_.log("Not in this APK: " + ref, "analysis");
            continue;
        }
        selectMethod(a, defs.front(), currentGroup_, false);
        return;
    }
}
