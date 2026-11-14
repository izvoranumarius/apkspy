// Native code views of the Analysis panel: AArch64 functions, disassembly,
// callers and string references (see NativeCode).
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include "app/Theme.hpp"
#include "core/TextUtils.hpp"
#include "ui/AnalysisPanel.hpp"
#include "ui/UiUtil.hpp"

namespace {

ImVec4 kDim() { return theme::vec(Col::TextMuted); }
ImVec4 kAccent() { return theme::vec(Col::Info); }
ImVec4 kWarn() { return theme::vec(Col::Warning); }
ImVec4 kString() { return theme::vec(Col::SynString); }
ImVec4 kLabel() { return theme::vec(Col::Purple); }

template <typename T>
bool ready(std::future<T>& f) {
    return f.valid() && f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::string hex(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

Col mnemonicToken(const arm64::Insn& in) {
    switch (in.flow) {
    case arm64::Flow::Call:
    case arm64::Flow::IndirectCall: return Col::Info;
    case arm64::Flow::Jump:
    case arm64::Flow::CondJump:
    case arm64::Flow::IndirectJump: return Col::Yellow;
    case arm64::Flow::Return:
    case arm64::Flow::Trap: return Col::Red;
    default: return in.known ? Col::Text : Col::TextMuted;
    }
}
ImVec4 mnemonicColor(const arm64::Insn& in) { return theme::vec(mnemonicToken(in)); }

ImVec4 functionColor(const NativeCode::Function& f) {
    if (f.name.rfind("Java_", 0) == 0 || f.name == "JNI_OnLoad" || f.name == "JNI_OnUnload") return kString();
    if (f.kind == NativeCode::FunctionKind::Plt) return kDim();
    if (f.exported) return kAccent();
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}

}  // namespace

AnalysisPanel::~AnalysisPanel() {
    // The worker polls this flag, so the future's destructor does not wait for a full sweep.
    if (nativeCancel_) *nativeCancel_ = true;
}

void AnalysisPanel::resetNative() {
    if (nativeCancel_) *nativeCancel_ = true;
    if (nativeLoad_.valid()) nativeLoad_.wait();
    nativeLoad_ = {};
    nativeCancel_.reset();
    native_.reset();
    nativeError_.clear();
    funcRows_.clear();
    funcFilterApplied_ = "\x01";
    funcAddr_ = UINT64_MAX;
    focusAddr_ = 0;
    pendingGoto_ = 0;
    nativeBack_.clear();
    listing_.clear();
    funcCallers_.clear();
    nativeGraph_.clear();
    nativeCfg_ = {};
    nativeCallNodes_.clear();
    nativeGraphFunc_ = UINT64_MAX;
    nstrRows_.clear();
    nstrApplied_ = "\x01";
}

void AnalysisPanel::ensureNativeCode(Root& apk) {
    if (ready(nativeLoad_)) {
        auto r = nativeLoad_.get();
        native_ = std::move(r.first);
        nativeError_ = std::move(r.second);
    }
    if (native_ || nativeLoad_.valid() || !nativeError_.empty() || selectedLib_ < 0 || !elf_) return;
    nativeCancel_ = std::make_shared<std::atomic<bool>>(false);
    AnalysisService* service = &workspace_.analysis();
    const std::string apkPath = apk.apkPath, entry = libs_[static_cast<size_t>(selectedLib_)].path;
    auto cancel = nativeCancel_;
    nativeLoad_ = std::async(std::launch::async, [service, apkPath, entry, cancel] {
        std::string err;
        auto code = service->loadNative(apkPath, entry, cancel.get(), err);
        return std::make_pair(code, err);
    });
}

void AnalysisPanel::gotoNative(uint64_t addr, bool record) {
    if (!native_) {
        pendingGoto_ = addr;
        return;
    }
    const NativeCode::Function* f = native_->functionAt(addr);
    if (!f) {
        workspace_.log("No code at " + hex(addr), "analysis");
        return;
    }
    if (record && funcAddr_ != UINT64_MAX) nativeBack_.push_back(focusAddr_ ? focusAddr_ : funcAddr_);
    if (nativeBack_.size() > 256) nativeBack_.erase(nativeBack_.begin());
    sel_ = Selection::Native;
    if (showPanel_) showPanel_("Function");
    if (f->addr != funcAddr_) {
        funcAddr_ = f->addr;
        listing_ = native_->disassembleFunction(*f, 50000);
        funcCallers_ = native_->refsTo(f->addr, 1000);
    }
    focusAddr_ = addr;
    scrollToFocus_ = true;
}

void AnalysisPanel::drawNativeCode(Root& apk) {
    ensureNativeCode(apk);
    if (nativeLoad_.valid()) {
        ImGui::TextDisabled("Disassembling and indexing references...");
        return;
    }
    if (!native_) {
        if (!nativeError_.empty()) ImGui::TextWrapped("%s", nativeError_.c_str());
        return;
    }
    const NativeCode& nc = *native_;
    if (!pendingTarget_.empty() && pendingLib_.empty()) {
        const std::string t = std::move(pendingTarget_);
        pendingTarget_.clear();
        uint64_t addr = 0;
        if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) addr = std::strtoull(t.c_str() + 2, nullptr, 16);
        else if (const auto* f = nc.findFunction(t)) addr = f->addr;
        if (addr) gotoNative(addr);
        else workspace_.log("No native function matches " + t, "analysis");
    }
    if (pendingGoto_) {
        const uint64_t a = pendingGoto_;
        pendingGoto_ = 0;
        gotoNative(a, false);
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##ff", "Filter functions (name or 0xaddress)...", funcFilter_, sizeof funcFilter_);
    if (funcFilterApplied_ != funcFilter_) {
        funcFilterApplied_ = funcFilter_;
        funcRows_.clear();
        const std::string flt = funcFilter_;
        uint64_t addr = 0;
        const bool byAddr = flt.size() > 2 && flt[0] == '0' && (flt[1] == 'x' || flt[1] == 'X') &&
                            (addr = std::strtoull(flt.c_str() + 2, nullptr, 16)) != 0;
        const auto& fns = nc.functions();
        for (uint32_t i = 0; i < static_cast<uint32_t>(fns.size()); ++i) {
            const auto& f = fns[i];
            if (byAddr) {
                if (addr >= f.addr && addr < f.addr + std::max<uint64_t>(f.size, 4)) funcRows_.push_back(i);
            } else if (flt.empty() || tex::ciFind(f.name, flt) != std::string_view::npos ||
                       tex::ciFind(NativeCode::displayName(f), flt) != std::string_view::npos) {
                funcRows_.push_back(i);
            }
        }
    }
    ImGui::BeginChild("##fns", ImVec2(0, 0));
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(funcRows_.size()));
    while (clipper.Step())
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const auto& f = nc.functions()[funcRows_[static_cast<size_t>(r)]];
            const std::string name = NativeCode::displayName(f);
            ImGui::PushID(r);
            ImGui::PushStyleColor(ImGuiCol_Text, functionColor(f));
            if (ImGui::Selectable(name.c_str(), f.addr == funcAddr_ && sel_ == Selection::Native)) gotoNative(f.addr);
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s  %llu bytes%s%s", f.name.c_str(), hex(f.addr).c_str(), static_cast<unsigned long long>(f.size),
                                  f.exported ? "  exported" : "",
                                  f.kind == NativeCode::FunctionKind::Plt ? "  import stub"
                                  : f.kind == NativeCode::FunctionKind::Discovered ? "  (found as a call target)"
                                                                                   : "");
            ImGui::PopID();
        }
    ImGui::EndChild();
}

Annotation AnalysisPanel::nativeLocation(const NativeCode& nc, const NativeCode::Line& line) const {
    Annotation a;
    a.target = Annotation::Target::Native;
    a.group = libsGroup_;
    a.path = nc.elf().name();
    a.addr = line.insn.addr;
    a.context = line.insn.mnemonic + " " + line.insn.operands;
    if (std::string where = nc.symbolize(line.insn.addr); !where.empty()) a.context = where + ":  " + a.context;
    return a;
}

void AnalysisPanel::drawNativeListing(const NativeCode& nc) {
    const NativeCode::Function* f = funcAddr_ != UINT64_MAX ? nc.functionAt(funcAddr_) : nullptr;
    if (!f) {
        ImGui::TextDisabled("Select a function. Double-click a call or jump to follow it; Backspace goes back.");
        return;
    }
    ImGui::BeginDisabled(nativeBack_.empty());
    if (ui::smallButton("<") || (!nativeBack_.empty() && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
                                    ImGui::IsKeyPressed(ImGuiKey_Backspace) && !ImGui::GetIO().WantTextInput)) {
        const uint64_t back = nativeBack_.back();
        nativeBack_.pop_back();
        gotoNative(back, false);
        f = nc.functionAt(funcAddr_);
        if (!f) {
            ImGui::EndDisabled();
            return;
        }
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("Back (Backspace)");
    ImGui::SameLine();
    const auto openInEditor = [&] {
        std::string text = "; " + NativeCode::displayName(*f) + "  " + hex(f->addr) + "  (" + std::to_string(f->size) +
                           " bytes)  " + nc.elf().name() + "\n";
        for (const auto& x : listing_) {
            char row[48];
            std::snprintf(row, sizeof row, "%08llx  %-8s ", static_cast<unsigned long long>(x.insn.addr), x.insn.mnemonic.c_str());
            text += row + x.insn.operands;
            if (!x.targetName.empty()) text += " <" + x.targetName + ">";
            if (!x.comment.empty()) text += "    ; " + x.comment;
            text += "\n";
        }
        int line = 0;
        for (size_t k = 0; k < listing_.size(); ++k)
            if (listing_[k].insn.addr == focusAddr_) line = static_cast<int>(k) + 1;
        std::string file = NativeCode::displayName(*f);
        for (char& c : file)
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.' && c != '@') c = '_';
        if (file.size() > 80) file.resize(80);
        workspace_.openGenerated(libsGroup_, "native/" + nc.elf().name() + "/" + file + "_" + hex(f->addr) + ".s",
                                 file + ".s", std::move(text), line);
    };
    const std::string title = NativeCode::displayName(*f);
    ui::wrappedColored(kAccent(), title + "   " + hex(f->addr) + "  (" + std::to_string(f->size) + " bytes)");
    static const char* const kModes[] = {"Listing", "Graph", "Calls"};
    ImGui::PushID("nmode");
    ui::segmented(kModes, 3, nativeMode_);
    ImGui::PopID();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Callers on the left, callees on the right");
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput &&
        ImGui::IsKeyPressed(ImGuiKey_Space, false))
        nativeMode_ = nativeMode_ == 0 ? 1 : 0;
    if (nativeMode_ != 0) {
        drawNativeGraph(nc, *f);
        return;
    }

    ImGui::PushFont(Theme::monoFont());
    ImGui::BeginChild("##asm", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    if (scrollToFocus_) {
        scrollToFocus_ = false;
        for (size_t i = 0; i < listing_.size(); ++i)
            if (listing_[i].insn.addr == focusAddr_) {
                ImGui::SetScrollY(std::max(0.f, static_cast<float>(i) * lh - ImGui::GetWindowHeight() * 0.3f));
                break;
            }
    }
    // Address column only as wide as this library's addresses need.
    const bool shortAddr = !listing_.empty() && listing_.back().insn.addr < 0x1000000;
    const float addrW = ImGui::CalcTextSize(shortAddr ? "000000 " : "00000000 ").x;
    const float mnemW = ImGui::CalcTextSize("fmaxnm ").x;
    // Bookmarks and comments of this library, by address.
    Annotations& notes = workspace_.annotations();
    std::unordered_map<uint64_t, const Annotation*> commentAt, bookmarkAt;
    for (const Annotation& a : notes.all())
        if (a.target == Annotation::Target::Native && !a.variableNote() && a.group == libsGroup_ &&
            a.path == nc.elf().name())
            (a.kind == Annotation::Kind::Comment ? commentAt : bookmarkAt)[a.addr] = &a;
    if (ImGui::IsWindowFocused()) nativeShortcuts(nc, listing_);
    // Following a branch replaces listing_: it waits until the rows are drawn.
    uint64_t follow = UINT64_MAX;
    ImGuiListClipper clip;
    clip.Begin(static_cast<int>(listing_.size()), lh);
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            const NativeCode::Line& l = listing_[static_cast<size_t>(i)];
            ImGui::PushID(i);
            const float x0 = ImGui::GetCursorPosX();
            if (ImGui::Selectable("##row", l.insn.addr == focusAddr_, ImGuiSelectableFlags_AllowDoubleClick,
                                  ImVec2(0, ImGui::GetTextLineHeight()))) {
                focusAddr_ = l.insn.addr;
                const bool dbl = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
                if (dbl && l.insn.hasTarget && l.insn.flow != arm64::Flow::Normal) follow = l.insn.target;
            }
            if (ImGui::BeginPopupContextItem("##ctx")) {
                focusAddr_ = l.insn.addr;
                const Annotation location = nativeLocation(nc, l);
                const Annotation* comment = notes.at(Annotation::Kind::Comment, location);
                if (ImGui::MenuItem(notes.at(Annotation::Kind::Bookmark, location) ? "Remove bookmark" : "Add bookmark", "Ctrl+B"))
                    notes.toggleBookmark(location);
                if (ImGui::MenuItem(comment ? "Edit comment..." : "Add comment...", ";")) nativeComment_.open(notes, location);
                if (comment && ImGui::MenuItem("Remove comment")) notes.remove(comment->id);
                ImGui::Separator();
                if (l.insn.hasTarget && l.insn.flow != arm64::Flow::Normal && ImGui::MenuItem("Follow target"))
                    follow = l.insn.target;
                if (l.dataAddr && ImGui::MenuItem("Copy referenced address")) ImGui::SetClipboardText(hex(l.dataAddr).c_str());
                if (ImGui::MenuItem("Open listing in editor")) openInEditor();
                if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(hex(l.insn.addr).c_str());
                if (ImGui::MenuItem("Copy line")) {
                    std::string text = hex(l.insn.addr) + "  " + l.insn.mnemonic + " " + l.insn.operands;
                    if (!l.targetName.empty()) text += " <" + l.targetName + ">";
                    if (!l.comment.empty()) text += "  ; " + l.comment;
                    ImGui::SetClipboardText(text.c_str());
                }
                if (ImGui::MenuItem("Copy function listing")) {
                    std::string text;
                    for (const auto& x : listing_) {
                        text += hex(x.insn.addr) + "  " + x.insn.mnemonic + " " + x.insn.operands;
                        if (!x.targetName.empty()) text += " <" + x.targetName + ">";
                        if (!x.comment.empty()) text += "  ; " + x.comment;
                        text += "\n";
                    }
                    ImGui::SetClipboardText(text.c_str());
                }
                ImGui::EndPopup();
            }
            ImGui::SameLine(x0);
            char addr[24];
            std::snprintf(addr, sizeof addr, shortAddr ? "%06llx" : "%08llx", static_cast<unsigned long long>(l.insn.addr));
            ImGui::TextColored(bookmarkAt.count(l.insn.addr) ? ui::kBookmarkColor() : l.label ? kLabel() : kDim(), "%s", addr);
            ImGui::SameLine(x0 + addrW);
            ImGui::TextColored(mnemonicColor(l.insn), "%s", l.insn.mnemonic.c_str());
            ImGui::SameLine(x0 + addrW + mnemW);
            ImGui::TextUnformatted(l.insn.operands.c_str());
            if (!l.targetName.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(kAccent(), "<%s>", l.targetName.c_str());
            }
            if (!l.comment.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(l.comment.front() == '"' ? kString() : kDim(), "; %s", l.comment.c_str());
            }
            if (auto note = commentAt.find(l.insn.addr); note != commentAt.end()) {
                ImGui::SameLine(0, ImGui::GetFontSize());
                ImGui::TextColored(ui::kNoteColor(), "// %s", ui::noteFirstLine(note->second->text).c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", note->second->text.c_str());
            }
            ImGui::PopID();
        }
    if (listing_.size() >= 50000) ImGui::TextColored(kWarn(), "(listing truncated at 50000 instructions)");
    ImGui::EndChild();
    ImGui::PopFont();
    if (follow != UINT64_MAX) gotoNative(follow);
}

void AnalysisPanel::nativeShortcuts(const NativeCode& nc, const std::vector<NativeCode::Line>& lines) {
    const ImGuiIO& io = ImGui::GetIO();
    if (io.WantTextInput) return;
    Annotations& notes = workspace_.annotations();
    for (const auto& l : lines) {
        if (l.insn.addr != focusAddr_) continue;
        if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_B, false)) notes.toggleBookmark(nativeLocation(nc, l));
        if (!io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false)) nativeComment_.open(notes, nativeLocation(nc, l));
        break;
    }
}

void AnalysisPanel::buildNativeCfg(const NativeCode& nc, const NativeCode::Function& f) {
    nativeCfg_ = nc.controlFlow(f, 50000);
    const Annotations& notes = workspace_.annotations();
    Annotation location;
    location.target = Annotation::Target::Native;
    location.group = libsGroup_;
    location.path = nc.elf().name();
    std::vector<GraphView::Block> blocks(nativeCfg_.blocks.size());
    std::vector<graphlayout::Edge> edges;
    int focusBlock = -1;
    for (size_t b = 0; b < nativeCfg_.blocks.size(); ++b) {
        const auto& block = nativeCfg_.blocks[b];
        for (size_t i = block.firstLine; i < block.firstLine + block.lineCount; ++i) {
            const NativeCode::Line& l = nativeCfg_.lines[i];
            if (l.insn.addr == focusAddr_) focusBlock = static_cast<int>(b);
            char addr[24];
            std::snprintf(addr, sizeof addr, "%06llx  ", static_cast<unsigned long long>(l.insn.addr));
            char mnemonic[24];
            std::snprintf(mnemonic, sizeof mnemonic, "%-7s ", l.insn.mnemonic.c_str());
            location.addr = l.insn.addr;
            GraphView::Line line;
            line.push_back({addr, notes.at(Annotation::Kind::Bookmark, location) ? ui::kBookmarkToken : l.label ? Col::Purple : Col::TextMuted});
            line.push_back({mnemonic, mnemonicToken(l.insn)});
            line.push_back({l.insn.operands, Col::Text});
            if (!l.targetName.empty()) line.push_back({" <" + l.targetName + ">", Col::Info});
            if (!l.comment.empty()) line.push_back({"  ; " + l.comment, l.comment.front() == '"' ? Col::SynString : Col::TextMuted});
            if (const Annotation* note = notes.at(Annotation::Kind::Comment, location))
                line.push_back({"  // " + ui::noteFirstLine(note->text), ui::kNoteToken});
            blocks[b].lines.push_back(std::move(line));
        }
        if (b == 0) blocks[b].border = Col::Green;
        else if (block.exit) blocks[b].border = Col::Red;
        for (size_t k = 0; k < block.successors.size(); ++k) {
            graphlayout::Edge e;
            e.from = static_cast<int>(b);
            e.to = block.successors[k];
            e.kind = !block.conditional ? graphlayout::EdgeKind::Jump
                     : k == 0           ? graphlayout::EdgeKind::Taken
                                        : graphlayout::EdgeKind::Fallthrough;
            edges.push_back(std::move(e));
        }
    }
    nativeGraph_.set(std::move(blocks), std::move(edges));
    if (focusBlock > 0) nativeGraph_.focusBlock(focusBlock);
}

void AnalysisPanel::buildNativeCalls(const NativeCode& nc, const NativeCode::Function& f) {
    constexpr size_t kMaxNeighbours = 40;
    nativeCallNodes_ = {f.addr};
    std::vector<GraphView::Block> blocks(1);
    blocks[0].lines.push_back({{NativeCode::displayName(f), Col::Text}});
    blocks[0].border = Col::Accent;
    blocks[0].fill = Col::RowSelected;
    std::vector<graphlayout::Edge> edges;
    const auto add = [&](const NativeCode::Function* other, bool caller) {
        if (!other) return;
        const auto seen = std::find(nativeCallNodes_.begin(), nativeCallNodes_.end(), other->addr);
        const int index = static_cast<int>(seen - nativeCallNodes_.begin());
        if (seen == nativeCallNodes_.end()) {
            if (nativeCallNodes_.size() > kMaxNeighbours * 2) return;
            nativeCallNodes_.push_back(other->addr);
            GraphView::Block block;
            const bool import = other->kind == NativeCode::FunctionKind::Plt;
            block.lines.push_back({{NativeCode::displayName(*other), import ? Col::TextMuted : Col::Text}});
            blocks.push_back(std::move(block));
        }
        graphlayout::Edge e;
        e.from = caller ? index : 0;
        e.to = caller ? 0 : index;
        e.kind = graphlayout::EdgeKind::Call;
        const bool duplicate = std::any_of(edges.begin(), edges.end(), [&](const graphlayout::Edge& o) { return o.from == e.from && o.to == e.to; });
        if (!duplicate) edges.push_back(std::move(e));
    };
    for (const auto& r : nc.refsTo(f.addr, 400))
        if (r.kind != NativeCode::RefKind::Data && r.kind != NativeCode::RefKind::Read) add(nc.functionAt(r.from), true);
    for (const auto& r : nc.refsFrom(f, 400))
        if (r.kind == NativeCode::RefKind::Call || r.kind == NativeCode::RefKind::Jump) add(nc.functionAt(r.target), false);
    nativeGraph_.set(std::move(blocks), std::move(edges), true);
}

void AnalysisPanel::drawNativeGraph(const NativeCode& nc, const NativeCode::Function& f) {
    const uint64_t notes = workspace_.annotations().version();
    if (nativeGraphFunc_ != f.addr || nativeGraphMode_ != nativeMode_ || nativeGraphNotes_ != notes) {
        nativeGraphFunc_ = f.addr;
        nativeGraphMode_ = nativeMode_;
        nativeGraphNotes_ = notes;
        if (nativeMode_ == 1) buildNativeCfg(nc, f);
        else buildNativeCalls(nc, f);
    }
    if (nativeMode_ == 2 && nativeGraph_.size() <= 1)
        ImGui::TextDisabled("No direct callers or callees found. Calls through function pointers are not visible here.");
    const GraphView::Result r = nativeGraph_.draw("##nativeGraph", Theme::monoFont());
    if (nativeMode_ == 2) {
        if (r.activated && r.block >= 0 && r.block < static_cast<int>(nativeCallNodes_.size())) gotoNative(nativeCallNodes_[static_cast<size_t>(r.block)]);
        return;
    }
    const NativeCode::Line* line = nullptr;
    if (r.block >= 0 && r.block < static_cast<int>(nativeCfg_.blocks.size()) && r.line >= 0 &&
        r.line < static_cast<int>(nativeCfg_.blocks[static_cast<size_t>(r.block)].lineCount))
        line = &nativeCfg_.lines[nativeCfg_.blocks[static_cast<size_t>(r.block)].firstLine + static_cast<size_t>(r.line)];
    if (line && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) focusAddr_ = line->insn.addr;
    if (r.activated && line) {
        if (line->insn.hasTarget && line->insn.flow != arm64::Flow::Normal) {
            gotoNative(line->insn.target);
        } else {
            nativeMode_ = 0;
            focusAddr_ = line->insn.addr;
            scrollToFocus_ = true;
        }
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) nativeShortcuts(nc, nativeCfg_.lines);
}

void AnalysisPanel::drawNativeStrings(Root& apk) {
    ensureNativeCode(apk);
    if (nativeLoad_.valid()) {
        ImGui::TextDisabled("Disassembling and indexing references...");
        return;
    }
    if (!native_) {
        if (!nativeError_.empty()) ImGui::TextWrapped("%s", nativeError_.c_str());
        return;
    }
    const NativeCode& nc = *native_;
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##nsf", "Filter strings referenced by code...", nstrFilter_, sizeof nstrFilter_);
    if (nstrApplied_ != nstrFilter_) {
        nstrApplied_ = nstrFilter_;
        nstrRows_ = nc.stringRefs(nstrFilter_, 20000);
    }
    ImGui::TextDisabled("%zu references%s - double-click to open the code", nstrRows_.size(),
                        nstrRows_.size() >= 20000 ? " (first 20000)" : "");
    if (!ImGui::BeginTable("##nstr", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("String", ImGuiTableColumnFlags_WidthStretch, 3.f);
    ImGui::TableSetupColumn("Used in", ImGuiTableColumnFlags_WidthStretch, 1.5f);
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(nstrRows_.size()));
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto& s = nstrRows_[static_cast<size_t>(i)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            ImGui::PushStyleColor(ImGuiCol_Text, kString());
            const bool open = ImGui::Selectable(s.text.c_str(), false,
                                                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick) &&
                              ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\nstring at %s, used at %s", s.text.c_str(), hex(s.addr).c_str(), hex(s.from).c_str());
            if (ImGui::BeginPopupContextItem("##sctx")) {
                if (ImGui::MenuItem("Open code")) {
                    symbolView_ = 5;
                    gotoNative(s.from);
                }
                if (ImGui::MenuItem("Copy string")) ImGui::SetClipboardText(s.text.c_str());
                ImGui::EndPopup();
            }
            ImGui::TableNextColumn();
            const std::string where = nc.symbolize(s.from);
            ImGui::TextDisabled("%s", where.empty() ? hex(s.from).c_str() : where.c_str());
            ImGui::PopID();
            if (open) {
                symbolView_ = 5;
                gotoNative(s.from);
            }
        }
    ImGui::EndTable();
}
