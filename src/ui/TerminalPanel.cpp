#include "ui/TerminalPanel.hpp"
#include <algorithm>
#include <cmath>
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
    return IM_COL32((rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255, 255);
}

void appendUtf8(std::string& out, char32_t c) {
    if (c < 0x80) out.push_back((char)c);
    else if (c < 0x800) out += {(char)(0xC0 | (c >> 6)), (char)(0x80 | (c & 0x3F))};
    else if (c < 0x10000) out += {(char)(0xE0 | (c >> 12)), (char)(0x80 | ((c >> 6) & 0x3F)), (char)(0x80 | (c & 0x3F))};
    else out += {(char)(0xF0 | (c >> 18)), (char)(0x80 | ((c >> 12) & 0x3F)), (char)(0x80 | ((c >> 6) & 0x3F)), (char)(0x80 | (c & 0x3F))};
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

}  // namespace

TerminalPanel::TerminalPanel(Workspace& workspace, Settings& settings, std::function<std::string()> folder)
    : Panel(workspace, "Terminal"), settings_(settings), folder_(std::move(folder)) {}

TerminalPanel::~TerminalPanel() {
    if (pty_) pty_->stop();
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

void TerminalPanel::start(int cols, int rows) {
    started_ = true;
    error_.clear();
    screen_ = VtScreen(cols, rows);
    pty_ = std::make_unique<Pty>();
    screen_.setReply([this](const std::string& r) {
        if (pty_) pty_->write(r);
    });
    const std::vector<std::string> cmd = shellCommand();
    shellName_ = pathutil::toUtf8(pathutil::fromUtf8(cmd.front()).filename());
    std::string folder = folder_ ? folder_() : std::string();
    std::error_code ec;
    if (folder.empty() || !fs::is_directory(pathutil::fromUtf8(folder), ec)) folder = pathutil::toUtf8(fs::current_path(ec));
    const std::vector<std::string> extra = {toolDir(settings_.getString(Settings::kAdbPath, "adb")),
                                            toolDir(settings_.getString(Settings::kJadxPath, "jadx"))};
    if (!pty_->start(cmd, folder, extra, cols, rows, error_)) pty_.reset();
    followOutput_ = true;
}

void TerminalPanel::restart() {
    if (pty_) pty_->stop();
    pty_.reset();
    started_ = false;  // starts again at the panel's size on the next frame
}

std::string TerminalPanel::selectionText() const {
    if (selA_ < 0) return {};
    long long a = selA_, b = selB_;
    int ca = selColA_, cb = selColB_;
    if (a > b || (a == b && ca > cb)) std::swap(a, b), std::swap(ca, cb);
    std::string out;
    for (long long l = a; l <= b && l < (long long)screen_.lineCount(); ++l) {
        const VtScreen::Line& line = screen_.line((size_t)l);
        const int from = l == a ? ca : 0, to = l == b ? cb : (int)line.size() - 1;
        std::string text;
        for (int x = std::max(0, from); x <= to && x < (int)line.size(); ++x) appendUtf8(text, line[(size_t)x].ch);
        while (!text.empty() && text.back() == ' ') text.pop_back();
        out += text;
        if (l != b) out += "\n";
    }
    return out;
}

void TerminalPanel::handleKeys() {
    if (!pty_) return;
    ImGuiIO& io = ImGui::GetIO();
    std::string out;
    for (int i = 0; i < io.InputQueueCharacters.Size; ++i) {
        const ImWchar c = io.InputQueueCharacters[i];
        if (c >= 0x20 && c != 0x7F) appendUtf8(out, (char32_t)c);
    }
    io.InputQueueCharacters.resize(0);
    const auto pressed = [](ImGuiKey k) { return ImGui::IsKeyPressed(k, ImGuiInputFlags_Repeat, ImGuiKeyOwner_Any); };
    if (io.KeyCtrl && !io.KeyAlt) {
        // Ctrl+C copies a selection, otherwise interrupts; Ctrl+V pastes.
        if (pressed(ImGuiKey_C) && (io.KeyShift || selA_ >= 0)) {
            ImGui::SetClipboardText(selectionText().c_str());
            selA_ = -1;
        } else if (pressed(ImGuiKey_V)) {
            if (const char* clip = ImGui::GetClipboardText()) {
                std::string text = clip;
                std::string fixed;
                for (size_t i = 0; i < text.size(); ++i) {
                    if (text[i] == '\r') continue;
                    fixed.push_back(text[i] == '\n' ? '\r' : text[i]);
                }
                out += fixed;
            }
        } else {
            for (int k = 0; k < 26; ++k)
                if (pressed((ImGuiKey)(ImGuiKey_A + k))) out.push_back((char)(k + 1));
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
        pty_->write(out);
        followOutput_ = true;  // typing jumps back to the prompt
        selA_ = -1;
    }
}

void TerminalPanel::drawContents() {
    // Toolbar.
    const bool alive = pty_ && pty_->running();
    ImGui::TextDisabled("%s", shellName_.empty() ? "Terminal" : shellName_.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton(ui::icon(icons::REFRESH, "Restart").c_str())) restart();
    ImGui::SameLine();
    if (ImGui::SmallButton(ui::icon(icons::CLOSE, "Clear").c_str()) && pty_) {
        screen_.feed("\x1b[2J\x1b[3J\x1b[H");
        pty_->write("\r");
    }
    if (!error_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.55f, 0.45f, 1.f), "%s", error_.c_str());
    } else if (started_ && !alive) {
        ImGui::SameLine();
        ImGui::TextDisabled("The shell exited (code %d). Press Enter to start a new one.", pty_ ? pty_->exitCode() : 0);
    }

    ImGui::PushFont(Theme::monoFont());
    const float charW = ImGui::CalcTextSize("M").x;
    const float lineH = ImGui::GetTextLineHeight();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Theme::editorBackground());
    ImGui::BeginChild("##term", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNavInputs);
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const int cols = std::max(20, (int)(avail.x / charW)), rows = std::max(4, (int)(avail.y / lineH));
    if (!started_) start(cols, rows);
    if (cols != screen_.cols() || rows != screen_.rows()) {
        screen_.resize(cols, rows);
        if (pty_) pty_->resize(cols, rows);
    }
    if (pty_) {
        const std::string data = pty_->take();
        if (!data.empty()) screen_.feed(data);
    }
    const bool focused = ImGui::IsWindowFocused();
    if (focused) {
        if (started_ && !pty_->running() && ImGui::IsKeyPressed(ImGuiKey_Enter, false)) restart();
        else handleKeys();
    }
    drawScreen();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::PopFont();
}

void TerminalPanel::drawScreen() {
    const float charW = ImGui::CalcTextSize("M").x;
    const float lineH = ImGui::GetTextLineHeight();
    const size_t lines = screen_.lineCount();
    const size_t screenTop = lines - (size_t)screen_.rows();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 defaultFg = IM_COL32(204, 204, 204, 255);
    const ImU32 defaultBg = ImGui::ColorConvertFloat4ToU32(Theme::editorBackground());

    // Follow the output while the view sits at the bottom.
    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - lineH;
    if (ImGui::GetIO().MouseWheel != 0.f && ImGui::IsWindowHovered()) followOutput_ = false;  // reading back
    else if (atBottom) followOutput_ = true;
    const ImVec2 origin = ImGui::GetCursorScreenPos();

    // Mouse selection over (line, column).
    const auto cellAt = [&](ImVec2 m, long long& line, int& col) {
        line = std::clamp((long long)std::floor((m.y - origin.y) / lineH), 0LL, (long long)lines - 1);
        col = std::clamp((int)std::floor((m.x - origin.x) / charW), 0, screen_.cols() - 1);
    };
    if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        cellAt(ImGui::GetIO().MousePos, selA_, selColA_);
        selB_ = selA_;
        selColB_ = selColA_;
        selecting_ = true;
    }
    if (selecting_) {
        if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) cellAt(ImGui::GetIO().MousePos, selB_, selColB_);
        else {
            selecting_ = false;
            if (selA_ == selB_ && selColA_ == selColB_) selA_ = -1;  // a click, not a selection
        }
    }
    long long sa = selA_, sb = selB_;
    int sca = selColA_, scb = selColB_;
    if (sa > sb || (sa == sb && sca > scb)) std::swap(sa, sb), std::swap(sca, scb);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));  // rows exactly lineH apart
    ImGuiListClipper clipper;
    clipper.Begin((int)lines, lineH);
    std::string run;
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const VtScreen::Line& line = screen_.line((size_t)i);
            const float y = origin.y + (float)i * lineH;
            int x = 0;
            const int n = (int)line.size();
            while (x < n) {
                // A run of cells with the same look.
                const VtScreen::Cell& first = line[(size_t)x];
                int end = x + 1;
                while (end < n && line[(size_t)end].fg == first.fg && line[(size_t)end].bg == first.bg &&
                       line[(size_t)end].flags == first.flags)
                    ++end;
                ImU32 fg = toColor(first.fg, defaultFg), bg = toColor(first.bg, defaultBg);
                if (first.flags & VtScreen::kInverse) std::swap(fg, bg);
                if (bg != defaultBg)
                    dl->AddRectFilled(ImVec2(origin.x + (float)x * charW, y), ImVec2(origin.x + (float)end * charW, y + lineH), bg);
                run.clear();
                for (int k = x; k < end; ++k) appendUtf8(run, line[(size_t)k].ch);
                dl->AddText(ImVec2(origin.x + (float)x * charW, y), fg, run.c_str(), run.c_str() + run.size());
                if (first.flags & VtScreen::kBold)  // no bold font: draw it twice, a pixel apart
                    dl->AddText(ImVec2(origin.x + (float)x * charW + 1.f, y), fg, run.c_str(), run.c_str() + run.size());
                x = end;
            }
            if (sa >= 0 && i >= sa && i <= sb) {
                const int from = i == sa ? sca : 0, to = i == sb ? scb : screen_.cols() - 1;
                dl->AddRectFilled(ImVec2(origin.x + (float)from * charW, y), ImVec2(origin.x + (float)(to + 1) * charW, y + lineH),
                                  IM_COL32(38, 79, 120, 140));
            }
            ImGui::Dummy(ImVec2((float)screen_.cols() * charW, lineH));
        }
    }
    clipper.End();
    ImGui::PopStyleVar();
    // Cursor.
    if (pty_ && pty_->running() && screen_.cursorVisible()) {
        const float cx = origin.x + (float)screen_.cursorX() * charW;
        const float cy = origin.y + (float)(screenTop + (size_t)screen_.cursorY()) * lineH;
        const bool focused = ImGui::IsWindowFocused();
        const bool blink = std::fmod(ImGui::GetTime(), 1.06) < 0.53;
        if (focused && blink) dl->AddRectFilled(ImVec2(cx, cy), ImVec2(cx + charW, cy + lineH), IM_COL32(204, 204, 204, 200));
        else if (!focused) dl->AddRect(ImVec2(cx, cy), ImVec2(cx + charW, cy + lineH), IM_COL32(204, 204, 204, 160));
    }
    if (ImGui::BeginPopupContextWindow("##termctx")) {
        if (ImGui::MenuItem("Copy", "Ctrl+C", false, selA_ >= 0)) ImGui::SetClipboardText(selectionText().c_str());
        if (ImGui::MenuItem("Paste", "Ctrl+V") && pty_)
            if (const char* clip = ImGui::GetClipboardText()) pty_->write(clip);
        ImGui::Separator();
        if (ImGui::MenuItem("Restart shell")) restart();
        ImGui::EndPopup();
    }
    if (screen_.version() != drawnVersion_) {
        drawnVersion_ = screen_.version();
        if (followOutput_) ImGui::SetScrollY(std::max(0.f, (float)lines * lineH - ImGui::GetWindowHeight()));
    }
}
