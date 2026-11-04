#include "ui/ScriptPanel.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "app/Theme.hpp"
#include "core/Paths.hpp"
#include "core/Settings.hpp"
#include "document/SyntaxHighlighter.hpp"
#include "mcp/McpHost.hpp"
#include "ui/UiUtil.hpp"
#include "imgui_internal.h"
namespace ImStb {
#include "imstb_textedit.h"
}

namespace fs = std::filesystem;

namespace {

fs::path scriptsDir() { return pathutil::configDir() / "scripts"; }
fs::path supportDir() { return pathutil::configDir() / "scripting"; }

int resizeText(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* text = static_cast<std::string*>(data->UserData);
        text->resize((size_t)data->BufTextLen);
        data->Buf = text->data();
    }
    return 0;
}

// A plain file name: script names can never leave the scripts folder.
std::string cleanName(std::string name) {
    std::string out;
    for (char c : name)
        if (std::isalnum((unsigned char)c) || c == '_' || c == '-') out.push_back(c);
        else if (c == '.' && out.find('.') == std::string::npos) break;
    return out.empty() ? out : out + ".py";
}

}  // namespace

ScriptPanel::ScriptPanel(Workspace& workspace, Settings& settings, McpHost& mcp)
    : Panel(workspace, "Script"), settings_(settings), mcp_(mcp) {}

void ScriptPanel::refreshFiles() {
    files_.clear();
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(scriptsDir(), ec))
        if (entry.path().extension() == ".py") files_.push_back(pathutil::toUtf8(entry.path().filename()));
    std::sort(files_.begin(), files_.end());
}

void ScriptPanel::openFile(const std::string& name) {
    std::ifstream in(scriptsDir() / pathutil::fromUtf8(name), std::ios::binary);
    if (!in) {
        report("Error: cannot open " + name);
        return;
    }
    std::ostringstream text;
    text << in.rdbuf();
    text_ = text.str();
    text_.erase(std::remove(text_.begin(), text_.end(), '\r'), text_.end());
    current_ = name;
    dirty_ = false;
    linesStale_ = true;
}

bool ScriptPanel::saveFile() {
    if (current_.empty()) return false;
    std::ofstream out(scriptsDir() / pathutil::fromUtf8(current_), std::ios::binary | std::ios::trunc);
    out << text_;
    out.flush();
    if (!out) {
        report("Error: cannot save " + current_);
        return false;
    }
    dirty_ = false;
    return true;
}

void ScriptPanel::run() {
    if (runner_.running() || !saveFile()) return;
    std::string url, token, error;
    if (!mcp_.scriptEndpoint(url, token, error)) {
        report("Error: scripting endpoint: " + error);
        return;
    }
    const std::string support = pathutil::toUtf8(supportDir());
    if (!scripting::writeSupport(support, url, token, error)) {
        report("Error: " + error);
        return;
    }
    ranName_ = current_;
    report("Running " + ranName_);
    const std::string script = pathutil::toUtf8(scriptsDir() / pathutil::fromUtf8(current_));
    const std::string python = settings_.getString(Settings::kPythonPath, "python");
    if (!runner_.start(scripting::command(python, support, script), error)) {
        report("Error: " + error + ". Set the Python executable under File > Settings > Scripts.");
        return;
    }
    wasRunning_ = true;
}

void ScriptPanel::pollOutput() {
    const bool running = runner_.running();  // read first: the last lines arrive before this turns false
    for (std::string& line : runner_.takeOutput()) report(std::move(line));
    if (wasRunning_ && !running) {
        wasRunning_ = false;
        const int code = runner_.exitCode();
        report(code == 0  ? "Finished " + ranName_
               : code < 0 ? "Stopped " + ranName_
                          : "Error: " + ranName_ + " exited with code " + std::to_string(code));
    }
}

void ScriptPanel::drawNewFilePopup() {
    if (openNewPopup_) {
        ImGui::OpenPopup("New script");
        openNewPopup_ = false;
        newName_[0] = 0;
    }
    if (!ImGui::BeginPopupModal("New script", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::TextUnformatted("Name");
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    const bool enter = ImGui::InputText("##name", newName_, sizeof newName_, ImGuiInputTextFlags_EnterReturnsTrue);
    const std::string name = cleanName(newName_);
    ImGui::BeginDisabled(name.empty());
    if (ImGui::Button("Create") || (enter && !name.empty())) {
        std::error_code ec;
        if (!fs::exists(scriptsDir() / pathutil::fromUtf8(name), ec)) {
            current_ = name;
            text_ = "import apkspy\n\nprint(apkspy.list_apks())\n";
            saveFile();
            refreshFiles();
        }
        openFile(name);
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

// The input owns editing (caret, selection, clipboard, undo). Its own text is
// transparent, with highlighted text drawn over it, as in the file editor.
void ScriptPanel::drawSource() {
    ImGui::PushFont(Theme::monoFont());
    const ImGuiID id = ImGui::GetID("##source");

    // Room for the line numbers, sized for at least three digits.
    const bool numbered = settings_.getBool(Settings::kLineNumbers, true);
    char widest[24];
    std::snprintf(widest, sizeof widest, "%zu", std::max<size_t>(lineStarts_.size(), 100));
    const float gutter = numbered ? ImGui::CalcTextSize(widest).x + ui::em(1.f) : 0.f;
    if (numbered) {
        ImGui::Dummy(ImVec2(gutter, ImGui::GetContentRegionAvail().y));
        ImGui::SameLine(0.f, 0.f);
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.f, 0.f, 0.f));
    if (ImGui::InputTextMultiline("##source", text_.data(), text_.capacity() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                                  ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize, resizeText, &text_)) {
        dirty_ = true;
        lastEdit_ = ImGui::GetTime();
        linesStale_ = true;
    }
    ImGui::PopStyleColor();

    const size_t size = std::strlen(text_.c_str());  // the active input can leave the string longer
    const std::string_view all(text_.c_str(), size);
    if (linesStale_) {
        linesStale_ = false;
        lineStarts_.assign(1, 0);
        for (size_t i = 0; i < size; ++i)
            if (all[i] == '\n') lineStarts_.push_back(i + 1);
        lineInString_.assign(lineStarts_.size(), 0);
        bool inString = false;
        std::vector<Span> scratch;
        for (size_t i = 0; i < lineStarts_.size(); ++i) {
            lineInString_[i] = inString;
            const size_t end = i + 1 < lineStarts_.size() ? lineStarts_[i + 1] - 1 : size;
            SyntaxHighlighter::tokenize(all.substr(lineStarts_[i], end - lineStarts_[i]), Language::Python, inString, scratch);
        }
    }

    // The input's inner child window, named by BeginChildEx: see EditorPanel::drawEditable.
    char childName[256];
    std::snprintf(childName, sizeof childName, "%s/##source_%08X", ImGui::GetCurrentWindow()->Name, id);
    ImGuiWindow* input = ImGui::FindWindowByName(childName);
    if (input) {
        const ImVec2 frameMin = ImGui::GetItemRectMin(), frameMax = ImGui::GetItemRectMax();
        const ImGuiStyle& style = ImGui::GetStyle();
        const ImGuiInputTextState* state = ImGui::GetInputTextState(id);
        const float fontSize = ImGui::GetFontSize();
        const float scrollX = state ? state->Scroll.x : 0.f, scrollY = input->Scroll.y;
        const ImVec2 origin(frameMin.x + style.FramePadding.x - scrollX, frameMin.y + style.FramePadding.y - scrollY);
        ImDrawList* dl = input->DrawList;
        dl->PushClipRect(frameMin, ImVec2(frameMax.x - input->ScrollbarSizes.x, frameMax.y), true);

        const auto lineAt = [&](size_t i) {
            const size_t end = i + 1 < lineStarts_.size() ? lineStarts_[i + 1] - 1 : size;
            return all.substr(lineStarts_[i], end - lineStarts_[i]);
        };
        const int first = std::max(0, (int)(scrollY / fontSize) - 1);
        const int last = std::min((int)lineStarts_.size(), first + (int)((frameMax.y - frameMin.y) / fontSize) + 3);
        std::vector<Span> spans;
        for (int i = first; i < last; ++i) {
            const std::string_view line = lineAt((size_t)i);
            bool inString = lineInString_[(size_t)i] != 0;
            SyntaxHighlighter::tokenize(line, Language::Python, inString, spans);
            float x = origin.x;
            const float y = origin.y + (float)i * fontSize;
            for (const Span& span : spans) {
                const char* s = line.data() + span.begin;
                const char* e = line.data() + span.end;
                dl->AddText(Theme::monoFont(), fontSize, ImVec2(x, y), span.color, s, e);
                x += ImGui::CalcTextSize(s, e).x;
            }
        }

        size_t caretLine = (size_t)-1;
        if (ImGui::IsItemActive() && state && (size_t)state->Stb->cursor <= size)
            caretLine = (size_t)(std::upper_bound(lineStarts_.begin(), lineStarts_.end(), (size_t)state->Stb->cursor) - lineStarts_.begin()) - 1;
        if (numbered) {
            ImDrawList* window = ImGui::GetWindowDrawList();
            window->PushClipRect(ImVec2(frameMin.x - gutter, frameMin.y), ImVec2(frameMin.x, frameMax.y), true);
            char number[16];
            for (int i = first; i < last; ++i) {
                std::snprintf(number, sizeof number, "%d", i + 1);
                const float x = frameMin.x - ImGui::CalcTextSize(number).x - ui::em(0.5f);
                window->AddText(ImVec2(x, origin.y + (float)i * fontSize),
                                (size_t)i == caretLine ? IM_COL32(200, 200, 200, 255) : IM_COL32(110, 110, 110, 255), number);
            }
            window->PopClipRect();
        }

        // The input draws its caret in the transparent text colour.
        if (ImGui::IsItemActive() && state) {
            const bool blink = !ImGui::GetIO().ConfigInputTextCursorBlink || state->CursorAnim <= 0.f ||
                               ImFmod(state->CursorAnim, 1.20f) <= 0.80f;
            const size_t cursor = (size_t)state->Stb->cursor;
            if (blink && cursor <= size) {
                const size_t index = (size_t)(std::upper_bound(lineStarts_.begin(), lineStarts_.end(), cursor) - lineStarts_.begin()) - 1;
                const float x = origin.x + ImGui::CalcTextSize(all.data() + lineStarts_[index], all.data() + cursor).x;
                const float y = origin.y + (float)index * fontSize;
                dl->AddLine(ImVec2(x, y), ImVec2(x, y + fontSize), ImGui::GetColorU32(ImGuiCol_Text));
            }
        }
        dl->PopClipRect();
    }
    ImGui::PopFont();
}

void ScriptPanel::drawContents() {
    if (!loaded_) {
        loaded_ = true;
        std::error_code ec;
        fs::create_directories(scriptsDir(), ec);
        refreshFiles();
        if (files_.empty()) {
            current_ = "summary.py";
            text_ = scripting::exampleScript();
            saveFile();
            refreshFiles();
        }
        openFile(files_.front());
    }

    const bool running = runner_.running();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && ImGui::IsKeyPressed(ImGuiKey_F5, false) && !running) run();
    ImGui::BeginDisabled(running || current_.empty());
    if (ImGui::Button("Run")) run();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("F5");
    ImGui::EndDisabled();
    ImGui::BeginDisabled(!running);
    if (ui::flowButton("Stop")) runner_.stop();
    ImGui::EndDisabled();
    if (ui::flowButton("New...")) openNewPopup_ = true;
    // Scripts save themselves shortly after the last keystroke.
    if (dirty_ && ImGui::GetTime() - lastEdit_ > 1.0) saveFile();
    drawNewFilePopup();

    const float availableW = ImGui::GetContentRegionAvail().x;
    const bool sideBySide = availableW > ui::em(36.f);
    ImGui::BeginChild("##scripts", sideBySide ? ImVec2(ui::em(11.f), 0) : ImVec2(0, ui::em(5.f)), ImGuiChildFlags_Borders);
    for (const std::string& name : files_) {
        const std::string label = name + (name == current_ && dirty_ ? " *" : "");
        if (ImGui::Selectable(label.c_str(), name == current_) && name != current_) {
            if (dirty_) saveFile();
            openFile(name);
        }
    }
    ImGui::EndChild();
    if (sideBySide) ImGui::SameLine();

    drawSource();
}
