#include "ui/TerminalPanel.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "core/Settings.hpp"
#include "imgui_internal.h"
#include "ui/UiUtil.hpp"

namespace fs = std::filesystem;

namespace {

ImU32 toColor(uint32_t rgb, ImU32 fallback) {
    if (rgb == VtScreen::kDefault) return fallback;
    if (VtScreen::isIndexed(rgb)) return theme::ansi(VtScreen::indexOf(rgb));  // ANSI 0-15: theme colours
    return IM_COL32((rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255, 255);
}

void appendUtf8(std::string& out, char32_t c) {
    if (c < 0x80) out.push_back(static_cast<char>(c));
    else if (c < 0x800) out += {static_cast<char>(0xC0 | (c >> 6)), static_cast<char>(0x80 | (c & 0x3F))};
    else if (c < 0x10000) out += {static_cast<char>(0xE0 | (c >> 12)), static_cast<char>(0x80 | ((c >> 6) & 0x3F)), static_cast<char>(0x80 | (c & 0x3F))};
    else out += {static_cast<char>(0xF0 | (c >> 18)), static_cast<char>(0x80 | ((c >> 12) & 0x3F)), static_cast<char>(0x80 | ((c >> 6) & 0x3F)), static_cast<char>(0x80 | (c & 0x3F))};
}

// Folder of a configured tool path ("C:\\sdk\\adb.exe" -> "C:\\sdk"), or "" for a bare name.
std::string toolDir(const std::string& path) {
    if (path.find('/') == std::string::npos && path.find('\\') == std::string::npos) return {};
    return pathutil::toUtf8(pathutil::fromUtf8(path).parent_path());
}

bool onPath(const char* exe) {
    const char* path = std::getenv("PATH");
    if (!path) return false;
    std::string p = path;
#ifdef _WIN32
    const char sep = ';';
#else
    const char sep = ':';
#endif
    size_t start = 0;
    while (start <= p.size()) {
        const size_t end = p.find(sep, start);
        const std::string dir = p.substr(start, end == std::string::npos ? std::string::npos : end - start);
        std::error_code ec;
        if (!dir.empty() && fs::exists(fs::path(dir) / exe, ec)) return true;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

// Pasted text as typed keys: line breaks become Enter.
std::string pasteKeys(const char* clip) {
    std::string out;
    for (const char* p = clip; p && *p; ++p) {
        if (*p == '\r') continue;
        out.push_back(*p == '\n' ? '\r' : *p);
    }
    return out;
}

}  // namespace

std::string TerminalPanel::Session::label() const {
    if (!title.empty()) return title;
    std::string name = shellName;
    if (const size_t dot = name.rfind('.'); dot != std::string::npos && dot > 0) name.resize(dot);  // pwsh.exe -> pwsh
    return std::to_string(id) + ": " + (name.empty() ? "terminal" : name);
}

TerminalPanel::TerminalPanel(Workspace& workspace, Settings& settings, std::function<std::string()> folder)
    : Panel(workspace, "Terminal"), settings_(settings), folder_(std::move(folder)) {
    add();  // the first terminal starts when the panel is first shown
}

TerminalPanel::~TerminalPanel() {
    for (auto& s : sessions_)
        if (s->pty) s->pty->stop();
}

TerminalPanel::Session& TerminalPanel::add() {
    auto s = std::make_unique<Session>();
    s->id = nextId_++;
    sessions_.push_back(std::move(s));
    selectTab_ = sessions_.back()->id;
    focusTerminal_ = true;
    return *sessions_.back();
}

std::vector<std::string> TerminalPanel::shellCommand() const {
    const std::string configured = settings_.getString(Settings::kTerminalShell, "");
    if (!configured.empty()) return {configured};
#ifdef _WIN32
    if (onPath("pwsh.exe")) return {"pwsh.exe", "-NoLogo"};
    return {"powershell.exe", "-NoLogo"};
#else
    const char* shell = std::getenv("SHELL");
    return {shell && *shell ? shell : "/bin/sh"};
#endif
}

void TerminalPanel::start(Session& s, int cols, int rows) {
    s.started = true;
    s.error.clear();
    s.screen = VtScreen(cols, rows);
    s.pty = std::make_unique<Pty>();
    Session* self = &s;  // sessions are heap-allocated: the pointer stays valid while the session lives
    s.screen.setReply([self](const std::string& r) {
        if (self->pty) self->pty->write(r);
    });
    const std::vector<std::string> cmd = shellCommand();
    s.shellName = pathutil::toUtf8(pathutil::fromUtf8(cmd.front()).filename());
    std::string folder = folder_ ? folder_() : std::string();
    std::error_code ec;
    if (folder.empty() || !fs::is_directory(pathutil::fromUtf8(folder), ec)) folder = pathutil::toUtf8(fs::current_path(ec));
    const std::vector<std::string> extra = {toolDir(settings_.getString(Settings::kAdbPath, "adb")),
                                            toolDir(settings_.getString(Settings::kJadxPath, "jadx"))};
    if (!s.pty->start(cmd, folder, extra, cols, rows, s.error)) s.pty.reset();
    s.followOutput = true;
}

void TerminalPanel::restart() {
    for (auto& s : sessions_)
        if (s->id == active_) {
            if (s->pty) s->pty->stop();
            s->pty.reset();
            s->started = false;  // starts again at the panel's size on the next frame
            s->selA = -1;
        }
    if (sessions_.empty()) add();
}

void TerminalPanel::newTerminal() { add(); }

void TerminalPanel::killActive() {
    for (size_t i = 0; i < sessions_.size(); ++i)
        if (sessions_[i]->id == active_) {
            if (sessions_[i]->pty) sessions_[i]->pty->stop();
            sessions_.erase(sessions_.begin() + static_cast<std::ptrdiff_t>(i));
            if (!sessions_.empty()) selectTab_ = sessions_[std::min(i, sessions_.size() - 1)]->id;
            active_ = -1;
            return;
        }
}

std::string TerminalPanel::selectionText(const Session& s) {
    if (s.selA < 0) return {};
    long long a = s.selA, b = s.selB;
    int ca = s.selColA, cb = s.selColB;
    if (a > b || (a == b && ca > cb)) std::swap(a, b), std::swap(ca, cb);
    std::string out;
    for (long long l = a; l <= b && l < static_cast<long long>(s.screen.lineCount()); ++l) {
        const VtScreen::Line& line = s.screen.line(static_cast<size_t>(l));
        const int from = l == a ? ca : 0, to = l == b ? cb : static_cast<int>(line.size()) - 1;
        std::string text;
        for (int x = std::max(0, from); x <= to && x < static_cast<int>(line.size()); ++x) appendUtf8(text, line[static_cast<size_t>(x)].ch);
        while (!text.empty() && text.back() == ' ') text.pop_back();
        out += text;
        if (l != b) out += "\n";
    }
    return out;
}

void TerminalPanel::handleKeys(Session& s) {
    if (!s.pty) return;
    ImGuiIO& io = ImGui::GetIO();
    std::string out;
    for (int i = 0; i < io.InputQueueCharacters.Size; ++i) {
        const ImWchar c = io.InputQueueCharacters[i];
        if (c >= 0x20 && c != 0x7F) appendUtf8(out, static_cast<char32_t>(c));
    }
    io.InputQueueCharacters.resize(0);
    const auto pressed = [](ImGuiKey k) { return ImGui::IsKeyPressed(k, ImGuiInputFlags_Repeat, ImGuiKeyOwner_Any); };
    if (io.KeyCtrl && !io.KeyAlt) {
        // Ctrl+C copies a selection, otherwise interrupts; Ctrl+Shift+C always copies; Ctrl+V / Ctrl+Shift+V paste.
        if (pressed(ImGuiKey_C) && (io.KeyShift || s.selA >= 0)) {
            if (s.selA >= 0) ImGui::SetClipboardText(selectionText(s).c_str());
            s.selA = -1;
        } else if (pressed(ImGuiKey_V)) {
            out += pasteKeys(ImGui::GetClipboardText());
        } else if (pressed(ImGuiKey_A) && io.KeyShift) {
            s.selA = 0, s.selColA = 0;  // Ctrl+Shift+A: select everything
            s.selB = static_cast<long long>(s.screen.lineCount()) - 1, s.selColB = s.screen.cols() - 1;
        } else if (!io.KeyShift) {
            for (int k = 0; k < 26; ++k)
                if (pressed(static_cast<ImGuiKey>(ImGuiKey_A + k))) out.push_back(static_cast<char>(k + 1));
        }
    }
    if (pressed(ImGuiKey_Enter) || pressed(ImGuiKey_KeypadEnter)) out += "\r";
    if (pressed(ImGuiKey_Backspace)) out += "\x7f";
    if (pressed(ImGuiKey_Tab)) out += "\t";
    if (pressed(ImGuiKey_Escape)) out += "\x1b";
    if (pressed(ImGuiKey_UpArrow)) out += "\x1b[A";
    if (pressed(ImGuiKey_DownArrow)) out += "\x1b[B";
    if (pressed(ImGuiKey_RightArrow)) out += io.KeyCtrl ? "\x1b[1;5C" : "\x1b[C";
    if (pressed(ImGuiKey_LeftArrow)) out += io.KeyCtrl ? "\x1b[1;5D" : "\x1b[D";
    if (pressed(ImGuiKey_Home)) out += "\x1b[H";
    if (pressed(ImGuiKey_End)) out += "\x1b[F";
    if (pressed(ImGuiKey_Delete)) out += "\x1b[3~";
    if (pressed(ImGuiKey_PageUp)) out += "\x1b[5~";
    if (pressed(ImGuiKey_PageDown)) out += "\x1b[6~";
    if (!out.empty()) {
        s.pty->write(out);
        s.followOutput = true;  // typing jumps back to the prompt
        s.selA = -1;
    }
}

// The tab strip, as in VS Code's terminal list: one tab per shell, + for another.
void TerminalPanel::drawTabs() {
    int closeId = -1;
    const ImGuiTabBarFlags flags = ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_FittingPolicyScroll | ImGuiTabBarFlags_TabListPopupButton;
    if (!ImGui::BeginTabBar("##terminals", flags)) return;
    for (auto& sp : sessions_) {
        Session& s = *sp;
        bool open = true;
        ImGuiTabItemFlags tf = ImGuiTabItemFlags_NoPushId;
        if (selectTab_ == s.id) tf |= ImGuiTabItemFlags_SetSelected;
        const std::string name = ui::icon(icons::TERMINAL, s.label().c_str()) + "###term" + std::to_string(s.id);
        const bool selected = ImGui::BeginTabItem(name.c_str(), &open, tf);
        if (selected) active_ = s.id;
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            renaming_ = s.id, openRename_ = true;
            std::snprintf(renameBuf_, sizeof renameBuf_, "%s", s.label().c_str());
        }
        ImGui::PushID(s.id);
        if (ImGui::BeginPopupContextItem("##tabctx")) {
            if (ImGui::MenuItem("Rename...")) {
                renaming_ = s.id, openRename_ = true;
                std::snprintf(renameBuf_, sizeof renameBuf_, "%s", s.label().c_str());
            }
            if (ImGui::MenuItem("Restart shell")) {
                if (s.pty) s.pty->stop();
                s.pty.reset();
                s.started = false;
            }
            if (ImGui::MenuItem("Clear") && s.pty) {
                s.screen.feed("\x1b[2J\x1b[3J\x1b[H");
                s.pty->write("\r");
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Kill terminal")) closeId = s.id;
            ImGui::EndPopup();
        }
        ImGui::PopID();
        if (selected) ImGui::EndTabItem();
        if (!open) closeId = s.id;
    }
    if (selectTab_ >= 0) selectTab_ = -1;
    const std::string plus = Theme::hasIcons() ? std::string(icons::ADD) : std::string("+");
    if (ImGui::TabItemButton(plus.c_str(), ImGuiTabItemFlags_Trailing | ImGuiTabItemFlags_NoTooltip)) add();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("New terminal (Ctrl+Shift+`)");
    if (!sessions_.empty()) {
        const std::string trash = Theme::hasIcons() ? std::string(icons::TRASH) : std::string("Kill");
        if (ImGui::TabItemButton(trash.c_str(), ImGuiTabItemFlags_Trailing | ImGuiTabItemFlags_NoTooltip)) closeId = active_;
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Kill the terminal");
    }
    ImGui::EndTabBar();
    if (closeId >= 0) {
        const int keep = active_;
        active_ = closeId;
        killActive();
        if (keep != closeId) selectTab_ = keep;  // closing a background tab keeps the shown one
    }

    // Rename (double-click the tab or its menu); empty goes back to the shell's name.
    if (openRename_) ImGui::OpenPopup("Rename terminal"), openRename_ = false;
    if (ImGui::BeginPopup("Rename terminal")) {
        const int id = renaming_;
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        ImGui::SetNextItemWidth(ui::em(14.f));
        bool apply = ImGui::InputText("##termname", renameBuf_, sizeof renameBuf_,
                                      ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
        apply |= ui::smallButton("OK");
        ImGui::SameLine();
        if (ui::smallButton("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
        if (apply) {
            for (auto& s : sessions_)
                if (s->id == id) {
                    std::string t = renameBuf_;
                    s->title.clear();
                    if (t != s->label()) s->title = t;
                }
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void TerminalPanel::drawContents() {
    // Every shell's output is read each frame, shown or not, so none of them blocks on a full pipe.
    for (auto& s : sessions_)
        if (s->pty) {
            const std::string data = s->pty->take();
            if (!data.empty()) s->screen.feed(data);
        }

    drawTabs();
    Session* sp = nullptr;
    for (auto& s : sessions_)
        if (s->id == active_) sp = s.get();
    if (!sp && !sessions_.empty()) {  // a tab was just closed: show its neighbour at once
        sp = sessions_.front().get();
        for (auto& s : sessions_)
            if (s->id == selectTab_) sp = s.get();
        active_ = sp->id;
    }
    if (!sp) {
        ImGui::Spacing();
        ImGui::TextDisabled("No open terminals.");
        if (ui::smallButton(ui::icon(icons::ADD, "New Terminal").c_str())) add();
        return;
    }
    Session& s = *sp;
    const bool alive = s.pty && s.pty->running();
    if (!s.error.empty()) {
        ImGui::TextColored(theme::vec(Col::Error), "%s", s.error.c_str());
    } else if (s.started && !alive) {
        ImGui::TextDisabled("The shell exited (code %d). Press Enter to start a new one.", s.pty ? s.pty->exitCode() : 0);
    }

    ImGui::PushFont(Theme::monoFont());
    const float charW = ImGui::CalcTextSize("M").x;
    const float lineH = ImGui::GetTextLineHeight();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::editorBackground());
    if (focusTerminal_) ImGui::SetNextWindowFocus(), focusTerminal_ = false;
    ImGui::PushID(s.id);  // each terminal keeps its own scroll position
    ImGui::BeginChild("##term", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNavInputs);
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const int cols = std::max(20, static_cast<int>(avail.x / charW)), rows = std::max(4, static_cast<int>(avail.y / lineH));
    if (!s.started) start(s, cols, rows);
    if (cols != s.screen.cols() || rows != s.screen.rows()) {
        s.screen.resize(cols, rows);
        if (s.pty) s.pty->resize(cols, rows);
    }
    if (ImGui::IsWindowFocused()) {
        if (s.started && (!s.pty || !s.pty->running()) && ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
            if (s.pty) s.pty->stop();
            s.pty.reset();
            s.started = false;
        } else {
            handleKeys(s);
        }
    }
    drawScreen(s);
    ImGui::EndChild();
    ImGui::PopID();
    ImGui::PopStyleColor();
    ImGui::PopFont();
}

void TerminalPanel::drawScreen(Session& s) {
    VtScreen& screen = s.screen;
    const float charW = ImGui::CalcTextSize("M").x;
    const float lineH = ImGui::GetTextLineHeight();
    const size_t lines = screen.lineCount();
    const size_t screenTop = lines - static_cast<size_t>(screen.rows());
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 defaultFg = theme::u32(Col::Text);
    const ImU32 defaultBg = ImGui::ColorConvertFloat4ToU32(Theme::editorBackground());

    // Follow the output while the view sits at the bottom.
    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - lineH;
    if (ImGui::GetIO().MouseWheel != 0.f && ImGui::IsWindowHovered()) s.followOutput = false;  // reading back
    else if (atBottom) s.followOutput = true;
    const ImVec2 origin = ImGui::GetCursorScreenPos();

    // Mouse selection over (line, column); a double-click selects a word.
    const auto cellAt = [&](ImVec2 m, long long& line, int& col) {
        line = std::clamp(static_cast<long long>(std::floor((m.y - origin.y) / lineH)), 0LL, static_cast<long long>(lines) - 1);
        col = std::clamp(static_cast<int>(std::floor((m.x - origin.x) / charW)), 0, screen.cols() - 1);
    };
    if (ImGui::IsWindowHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        long long l;
        int c;
        cellAt(ImGui::GetIO().MousePos, l, c);
        const VtScreen::Line& line = screen.line(static_cast<size_t>(l));
        const auto word = [&](int x) { return x >= 0 && x < static_cast<int>(line.size()) && line[static_cast<size_t>(x)].ch > U' '; };
        if (word(c)) {
            int a = c, b = c;
            while (word(a - 1)) --a;
            while (word(b + 1)) ++b;
            s.selA = s.selB = l;
            s.selColA = a, s.selColB = b;
        }
        s.selecting = false;
    } else if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        if (ImGui::GetIO().KeyShift && s.selA >= 0) {
            cellAt(ImGui::GetIO().MousePos, s.selB, s.selColB);  // Shift+click extends
        } else {
            cellAt(ImGui::GetIO().MousePos, s.selA, s.selColA);
            s.selB = s.selA;
            s.selColB = s.selColA;
        }
        s.selecting = true;
    }
    if (s.selecting) {
        if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            cellAt(ImGui::GetIO().MousePos, s.selB, s.selColB);
            // Dragging past the edges scrolls.
            const float top = ImGui::GetWindowPos().y, bottom = top + ImGui::GetWindowHeight();
            const float my = ImGui::GetIO().MousePos.y;
            if (my < top) ImGui::SetScrollY(ImGui::GetScrollY() - lineH), s.followOutput = false;
            else if (my > bottom) ImGui::SetScrollY(ImGui::GetScrollY() + lineH);
        } else {
            s.selecting = false;
            if (s.selA == s.selB && s.selColA == s.selColB) s.selA = -1;  // a click, not a selection
        }
    }
    long long sa = s.selA, sb = s.selB;
    int sca = s.selColA, scb = s.selColB;
    if (sa > sb || (sa == sb && sca > scb)) std::swap(sa, sb), std::swap(sca, scb);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));  // rows exactly lineH apart
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(lines), lineH);
    std::string run;
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const VtScreen::Line& line = screen.line(static_cast<size_t>(i));
            const float y = origin.y + static_cast<float>(i) * lineH;
            int x = 0;
            const int n = static_cast<int>(line.size());
            while (x < n) {
                // A run of cells with the same look.
                const VtScreen::Cell& first = line[static_cast<size_t>(x)];
                int end = x + 1;
                while (end < n && line[static_cast<size_t>(end)].fg == first.fg && line[static_cast<size_t>(end)].bg == first.bg &&
                       line[static_cast<size_t>(end)].flags == first.flags)
                    ++end;
                ImU32 fg = toColor(first.fg, defaultFg), bg = toColor(first.bg, defaultBg);
                if (first.flags & VtScreen::kInverse) std::swap(fg, bg);
                if (bg != defaultBg)
                    dl->AddRectFilled(ImVec2(origin.x + static_cast<float>(x) * charW, y), ImVec2(origin.x + static_cast<float>(end) * charW, y + lineH), bg);
                run.clear();
                for (int k = x; k < end; ++k) appendUtf8(run, line[static_cast<size_t>(k)].ch);
                dl->AddText(ImVec2(origin.x + static_cast<float>(x) * charW, y), fg, run.c_str(), run.c_str() + run.size());
                if (first.flags & VtScreen::kBold)  // no bold font: draw it twice, a pixel apart
                    dl->AddText(ImVec2(origin.x + static_cast<float>(x) * charW + 1.f, y), fg, run.c_str(), run.c_str() + run.size());
                x = end;
            }
            if (sa >= 0 && i >= sa && i <= sb) {
                const int from = i == sa ? sca : 0, to = i == sb ? scb : screen.cols() - 1;
                dl->AddRectFilled(ImVec2(origin.x + static_cast<float>(from) * charW, y), ImVec2(origin.x + static_cast<float>(to + 1) * charW, y + lineH),
                                  theme::u32(Col::TextSelection, 0.85f));
            }
            ImGui::Dummy(ImVec2(static_cast<float>(screen.cols()) * charW, lineH));
        }
    }
    clipper.End();
    ImGui::PopStyleVar();
    // Cursor.
    if (s.pty && s.pty->running() && screen.cursorVisible()) {
        const float cx = origin.x + static_cast<float>(screen.cursorX()) * charW;
        const float cy = origin.y + static_cast<float>(screenTop + static_cast<size_t>(screen.cursorY())) * lineH;
        const bool focused = ImGui::IsWindowFocused();
        const bool blink = std::fmod(ImGui::GetTime(), 1.06) < 0.53;
        if (focused && blink) dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + charW, cy + lineH), theme::u32(Col::Caret, 0.8f));
        else if (!focused) dl->AddRect(ImVec2(cx, cy), ImVec2(cx + charW, cy + lineH), theme::u32(Col::Caret, 0.6f));
    }
    if (ImGui::BeginPopupContextWindow("##termctx")) {
        if (ImGui::MenuItem("Copy", "Ctrl+C", false, s.selA >= 0)) ImGui::SetClipboardText(selectionText(s).c_str());
        if (ImGui::MenuItem("Send to Decoder", nullptr, false, s.selA >= 0)) workspace_.sendToDecoder(selectionText(s));
        if (ImGui::MenuItem("Paste", "Ctrl+V") && s.pty) s.pty->write(pasteKeys(ImGui::GetClipboardText()));
        if (ImGui::MenuItem("Select All", "Ctrl+Shift+A")) {
            s.selA = 0, s.selColA = 0;
            s.selB = static_cast<long long>(lines) - 1, s.selColB = screen.cols() - 1;
        }
        if (ImGui::MenuItem("Copy All")) {
            const long long a = s.selA, b = s.selB;
            const int ca = s.selColA, cb = s.selColB;
            s.selA = 0, s.selColA = 0, s.selB = static_cast<long long>(lines) - 1, s.selColB = screen.cols() - 1;
            std::string text = selectionText(s);
            while (!text.empty() && text.back() == '\n') text.pop_back();
            ImGui::SetClipboardText(text.c_str());
            s.selA = a, s.selB = b, s.selColA = ca, s.selColB = cb;
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Clear") && s.pty) {
            screen.feed("\x1b[2J\x1b[3J\x1b[H");
            s.pty->write("\r");
        }
        if (ImGui::MenuItem("New Terminal", "Ctrl+Shift+`")) add();
        if (ImGui::MenuItem("Restart Shell")) {
            if (s.pty) s.pty->stop();
            s.pty.reset();
            s.started = false;
        }
        if (ImGui::MenuItem("Kill Terminal")) {
            ImGui::EndPopup();
            active_ = s.id;
            killActive();
            return;
        }
        ImGui::EndPopup();
    }
    if (screen.version() != s.drawnVersion) {
        s.drawnVersion = screen.version();
        if (s.followOutput) ImGui::SetScrollY(std::max(0.f, static_cast<float>(lines) * lineH - ImGui::GetWindowHeight()));
    }
}
