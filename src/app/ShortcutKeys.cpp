#include "app/ShortcutKeys.hpp"
#include <cstdlib>

namespace shortcuts {

ImGuiKey toImGuiKey(const std::string& name) {
    if (name.size() == 1) {
        const char c = name[0];
        if (c >= 'A' && c <= 'Z') return static_cast<ImGuiKey>(ImGuiKey_A + (c - 'A'));
        if (c >= '0' && c <= '9') return static_cast<ImGuiKey>(ImGuiKey_0 + (c - '0'));
    }
    if (name.size() >= 2 && name[0] == 'F' && name[1] >= '0' && name[1] <= '9') {
        const int n = std::atoi(name.c_str() + 1);
        if (n >= 1 && n <= 12) return static_cast<ImGuiKey>(ImGuiKey_F1 + (n - 1));
    }
    struct Entry {
        const char* name;
        ImGuiKey key;
    };
    static const Entry kTable[] = {
        {"Comma", ImGuiKey_Comma},           {"Period", ImGuiKey_Period},       {"Minus", ImGuiKey_Minus},
        {"Equal", ImGuiKey_Equal},           {"GraveAccent", ImGuiKey_GraveAccent}, {"Slash", ImGuiKey_Slash},
        {"Backslash", ImGuiKey_Backslash},   {"Semicolon", ImGuiKey_Semicolon}, {"Apostrophe", ImGuiKey_Apostrophe},
        {"LeftBracket", ImGuiKey_LeftBracket}, {"RightBracket", ImGuiKey_RightBracket}, {"Space", ImGuiKey_Space},
        {"Enter", ImGuiKey_Enter},           {"Tab", ImGuiKey_Tab},             {"Left", ImGuiKey_LeftArrow},
        {"Right", ImGuiKey_RightArrow},      {"Up", ImGuiKey_UpArrow},          {"Down", ImGuiKey_DownArrow},
        {"Home", ImGuiKey_Home},             {"End", ImGuiKey_End},             {"PageUp", ImGuiKey_PageUp},
        {"PageDown", ImGuiKey_PageDown},     {"Insert", ImGuiKey_Insert},       {"Delete", ImGuiKey_Delete},
        {"Backspace", ImGuiKey_Backspace},   {"Escape", ImGuiKey_Escape},
    };
    for (const Entry& e : kTable)
        if (name == e.name) return e.key;
    return ImGuiKey_None;
}

bool pressed(const Chord& c) {
    if (!c.valid()) return false;
    const ImGuiKey key = toImGuiKey(c.key);
    if (key == ImGuiKey_None) return false;
    const ImGuiIO& io = ImGui::GetIO();
    return io.KeyCtrl == c.ctrl && io.KeyShift == c.shift && io.KeyAlt == c.alt && ImGui::IsKeyPressed(key, false);
}

bool captureChord(Chord& out) {
    const ImGuiIO& io = ImGui::GetIO();
    for (const std::string& name : keyNames()) {
        if (name == "Escape") continue;
        const ImGuiKey key = toImGuiKey(name);
        if (key == ImGuiKey_None || !ImGui::IsKeyPressed(key, false)) continue;
        Chord c;
        c.ctrl = io.KeyCtrl;
        c.shift = io.KeyShift;
        c.alt = io.KeyAlt;
        c.key = name;
        out = c;
        return true;
    }
    return false;
}

}  // namespace shortcuts
