#include "ui/CommandPalette.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/DexFile.hpp"
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "core/Workspace.hpp"
#include "imgui.h"
#include "ui/UiUtil.hpp"

namespace {

constexpr size_t kMaxShown = 60;

bool isBoundary(char prev, char c) {
    return prev == '/' || prev == '\\' || prev == '.' || prev == '_' || prev == '-' || prev == ' ' || prev == '$' ||
           (std::islower(static_cast<unsigned char>(prev)) && std::isupper(static_cast<unsigned char>(c)));
}

// Path shown under a file: decompiled files relative to jadx's sources folder.
std::string shownPath(const Root& root, const TreeNode& node) {
    std::string p = node.path();
    if (root.kind == Root::Kind::Decompiled) {
        for (const char* marker : {"\\sources\\", "/sources/"}) {
            const size_t at = p.find(marker);
            if (at != std::string::npos) {
                p = p.substr(at + 9);
                break;
            }
        }
    }
    std::replace(p.begin(), p.end(), '\\', '/');
    return p;
}

void collectFiles(Root& root, const TreeNode& node, std::vector<std::pair<Root*, const TreeNode*>>& out) {
    for (const auto& c : node.children()) {
        if (c->isFolder()) collectFiles(root, *c, out);
        else out.push_back({&root, c.get()});
    }
}

}  // namespace

int CommandPalette::fuzzyScore(const std::string& pattern, const std::string& text) {
    if (pattern.empty()) return 0;
    // The file name starts after the last separator: matches there count more.
    const size_t nameStart = text.find_last_of("/\\") == std::string::npos ? 0 : text.find_last_of("/\\") + 1;
    int score = 0, run = 0;
    size_t t = 0, last = std::string::npos;
    for (size_t p = 0; p < pattern.size(); ++p) {
        const char want = static_cast<char>(std::tolower(static_cast<unsigned char>(pattern[p])));
        if (want == ' ') continue;
        bool found = false;
        for (; t < text.size(); ++t) {
            if (static_cast<char>(std::tolower(static_cast<unsigned char>(text[t]))) != want) {
                run = 0;
                continue;
            }
            int s = 1;
            if (t == 0 || isBoundary(text[t - 1], text[t])) s += 8;
            if (run > 0) s += 5 + run;  // consecutive letters
            if (t >= nameStart) s += 3;
            if (last != std::string::npos) s -= static_cast<int>(std::min<size_t>(t - last - 1, 6));  // letters far apart
            last = t;
            score += s;
            ++run;
            ++t;
            found = true;
            break;
        }
        if (!found) return -1;
    }
    // Shorter texts win ties: "Main.java" over "MainActivityHelper.java".
    return score * 4 - static_cast<int>(std::min<size_t>(text.size(), 200)) / 8;
}

void CommandPalette::open(const std::string& prefix) {
    openRequest_ = true;
    std::snprintf(query_, sizeof query_, "%s", prefix.c_str());
    applied_ = "\x01";
    selected_ = 0;
    collect();
}

void CommandPalette::collect() {
    files_.clear();
    classes_.clear();
    std::vector<std::pair<Root*, const TreeNode*>> nodes;
    for (auto& root : workspace_.roots())
        if (root->tree) collectFiles(*root, *root->tree, nodes);
    files_.reserve(nodes.size());
    for (const auto& [root, node] : nodes) {
        Item it;
        it.kind = 0;
        it.root = root;
        it.node = node;
        it.label = shownPath(*root, *node);
        it.detail = root->title + (root->kind == Root::Kind::Decompiled ? "  (decompiled)" : "");
        it.icon = icons::FILE;
        files_.push_back(std::move(it));
    }
    for (Root* apk : workspace_.apkRoots())
        if (auto a = workspace_.analysis().get(apk->title))
            for (const auto& c : a->classes()) {
                Item it;
                it.kind = 2;
                it.label = DexFile::descriptorToJava(a->classDescriptor(c));
                it.detail = apk->title;
                it.group = apk->title;
                it.icon = icons::CODE;
                classes_.push_back(std::move(it));
            }
    commandList_ = commands_ ? commands_() : std::vector<Command>{};
}

void CommandPalette::filter() {
    applied_ = query_;
    shown_.clear();
    selected_ = 0;
    scrollToSelected_ = true;
    const std::string q = query_;
    if (!q.empty() && q[0] == ':') {
        Item it;
        it.kind = 3;
        it.line = std::atoi(q.c_str() + 1);
        it.label = it.line > 0 ? "Go to line " + std::to_string(it.line) : "Type a line number";
        it.icon = icons::LIST;
        shown_.push_back(std::move(it));
        return;
    }
    if (!q.empty() && q[0] == '>') {
        const std::string pattern = q.substr(1);
        for (size_t i = 0; i < commandList_.size(); ++i) {
            const int s = fuzzyScore(pattern, commandList_[i].name);
            if (s < 0) continue;
            Item it;
            it.kind = 1;
            it.command = i;
            it.label = commandList_[i].name;
            it.detail = commandList_[i].shortcut;
            it.icon = commandList_[i].icon;
            it.score = pattern.empty() ? -static_cast<int>(i) : s;  // empty: keep the given order
            shown_.push_back(std::move(it));
        }
    } else {
        const bool classes = !q.empty() && q[0] == '@';
        const std::string pattern = classes ? q.substr(1) : q;
        const std::vector<Item>& pool = classes ? classes_ : files_;
        if (pattern.empty() && !classes) {
            // Nothing typed: the open files, most recent first.
            const auto& docs = workspace_.documents();
            for (auto it = docs.rbegin(); it != docs.rend() && shown_.size() < kMaxShown; ++it)
                for (const Item& f : files_)
                    if (f.node == (*it)->node()) {
                        shown_.push_back(f);
                        break;
                    }
            return;
        }
        for (const Item& item : pool) {
            const int s = fuzzyScore(pattern, item.label);
            if (s < 0) continue;
            Item copy = item;
            copy.score = s;
            shown_.push_back(std::move(copy));
        }
    }
    const size_t keep = std::min(shown_.size(), kMaxShown);
    std::partial_sort(shown_.begin(), shown_.begin() + static_cast<ptrdiff_t>(keep), shown_.end(),
                      [](const Item& a, const Item& b) { return a.score > b.score; });
    shown_.resize(keep);
}

void CommandPalette::accept(const Item& item) {
    switch (item.kind) {
    case 0:
        workspace_.openNode(*item.root, *item.node, -1, Workspace::OpenMode::Permanent);
        if (showEditor_) showEditor_();
        break;
    case 1:
        if (item.command < commandList_.size() && commandList_[item.command].run) commandList_[item.command].run();
        break;
    case 2:
        if (!workspace_.openClassSource(item.group, item.label, Workspace::OpenMode::Permanent)) {
            // No jadx output: the smali of the class.
            if (auto a = workspace_.analysis().get(item.group))
                if (const auto* c = a->findClass(item.label)) {
                    std::string path(a->classDescriptor(*c));
                    for (char& ch : path)
                        if (ch == '/' || ch == ';' || ch == '<' || ch == '>') ch = '_';
                    workspace_.openGenerated(item.group, "smali/" + path + ".smali", item.label + ".smali", a->disassembleClass(*c), 0);
                }
        }
        if (showEditor_) showEditor_();
        break;
    case 3:
        if (Document* d = workspace_.activeDocument(); d && item.line > 0) d->goTo(item.line - 1);
        break;
    }
}

void CommandPalette::draw() {
    if (openRequest_) {
        openRequest_ = false;
        ImGui::OpenPopup("##palette");
    }
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float width = std::min(vp->WorkSize.x * 0.6f, ui::em(42.f));
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + (vp->WorkSize.x - width) * 0.5f, vp->WorkPos.y + ui::em(2.4f)));
    ImGui::SetNextWindowSize(ImVec2(width, 0.f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ui::em(0.4f), ui::em(0.4f)));
    if (!ImGui::BeginPopup("##palette", ImGuiWindowFlags_NoMove)) {
        ImGui::PopStyleVar();
        return;
    }
    ImGui::PopStyleVar();
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-FLT_MIN);
    const auto onKey = [](ImGuiInputTextCallbackData* data) -> int {
        auto* self = static_cast<CommandPalette*>(data->UserData);
        if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory && !self->shown_.empty()) {
            const int n = static_cast<int>(self->shown_.size());
            self->selected_ = (self->selected_ + (data->EventKey == ImGuiKey_UpArrow ? n - 1 : 1)) % n;
            self->scrollToSelected_ = true;
        }
        return 0;
    };
    const bool enter = ImGui::InputTextWithHint("##q", "Search files  ( > commands   @ classes   : line )", query_, sizeof query_,
                                                ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory,
                                                onKey, this);
    if (applied_ != query_) filter();
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    if (enter && selected_ < static_cast<int>(shown_.size())) {
        const Item chosen = shown_[static_cast<size_t>(selected_)];
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        accept(chosen);
        return;
    }
    // Results.
    const float rowH = ImGui::GetTextLineHeightWithSpacing() + 4.f;
    const float listH = std::min(static_cast<float>(std::max<size_t>(shown_.size(), 1)) * rowH, rowH * 12.f);
    ImGui::BeginChild("##results", ImVec2(0, listH));
    if (shown_.empty()) ImGui::TextDisabled("%s", query_[0] == '@' && classes_.empty() ? "No analysed classes yet: open the Analysis workspace first."
                                                                                         : "No matches");
    for (int i = 0; i < static_cast<int>(shown_.size()); ++i) {
        const Item& it = shown_[static_cast<size_t>(i)];
        ImGui::PushID(i);
        const ImVec2 pos = ImGui::GetCursorScreenPos();
        if (ImGui::Selectable("##r", i == selected_, ImGuiSelectableFlags_None, ImVec2(0, rowH - ImGui::GetStyle().ItemSpacing.y))) {
            const Item chosen = it;
            ImGui::PopID();
            ImGui::EndChild();
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            accept(chosen);
            return;
        }
        if (i == selected_ && scrollToSelected_) {
            ImGui::SetScrollHereY(0.5f);
            scrollToSelected_ = false;
        }
        ImDrawList* dl = ImGui::GetWindowDrawList();
        float x = pos.x + 4.f;
        const float y = pos.y + 2.f;
        if (it.icon && Theme::hasIcons()) {
            dl->AddText(ImVec2(x, y), theme::u32(Col::Info), it.icon);
            x += ImGui::GetFontSize() * 1.6f;
        }
        // Files: the name first, the folder dimmed after it (as in VS Code).
        std::string main = it.label, dim = it.detail;
        if (it.kind == 0) {
            const size_t slash = it.label.rfind('/');
            if (slash != std::string::npos) {
                main = it.label.substr(slash + 1);
                dim = it.label.substr(0, slash) + "   " + it.detail;
            }
        } else if (it.kind == 2) {
            const size_t dot = it.label.rfind('.');
            if (dot != std::string::npos) {
                main = it.label.substr(dot + 1);
                dim = it.label.substr(0, dot) + "   " + it.detail;
            }
        }
        dl->AddText(ImVec2(x, y), ImGui::GetColorU32(ImGuiCol_Text), main.c_str());
        x += ImGui::CalcTextSize(main.c_str()).x + ImGui::GetFontSize() * 0.8f;
        if (!dim.empty()) {
            const float right = pos.x + ImGui::GetContentRegionAvail().x;
            if (it.kind == 1) {  // shortcut, right aligned
                const float w = ImGui::CalcTextSize(dim.c_str()).x;
                dl->AddText(ImVec2(right - w - 6.f, y), ImGui::GetColorU32(ImGuiCol_TextDisabled), dim.c_str());
            } else {
                dl->PushClipRect(ImVec2(x, pos.y), ImVec2(right, pos.y + rowH), true);
                dl->AddText(ImVec2(x, y), ImGui::GetColorU32(ImGuiCol_TextDisabled), dim.c_str());
                dl->PopClipRect();
            }
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::EndPopup();
}
