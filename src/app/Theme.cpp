#include "app/Theme.hpp"
#include <filesystem>
#include <initializer_list>

ImFont* Theme::mono_ = nullptr;

namespace {
ImFont* tryLoad(ImGuiIO& io, std::initializer_list<const char*> candidates, float size) {
    for (const char* path : candidates)
        if (std::filesystem::exists(path)) return io.Fonts->AddFontFromFileTTF(path, size);
    return nullptr;
}
}

void Theme::loadFonts(ImGuiIO& io) {
    ImFont* ui = tryLoad(io, {"C:/Windows/Fonts/segoeui.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                              "/System/Library/Fonts/Supplemental/Arial.ttf"}, 16.f);
    if (!ui) io.Fonts->AddFontDefault();
    mono_ = tryLoad(io, {"C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                         "/System/Library/Fonts/Menlo.ttc"}, 15.f);
}

ImFont* Theme::monoFont() { return mono_ ? mono_ : ImGui::GetFont(); }

void Theme::apply() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 0.f;
    s.ChildRounding = 0.f;
    s.FrameRounding = 2.f;
    s.PopupRounding = 0.f;
    s.ScrollbarRounding = 0.f;
    s.TabRounding = 0.f;
    s.WindowBorderSize = 1.f;
    s.FrameBorderSize = 0.f;
    s.ItemSpacing = ImVec2(6.f, 2.f);
    s.WindowPadding = ImVec2(8.f, 6.f);
    s.IndentSpacing = 14.f;

    auto c = [](int r, int g, int b, int a = 255) { return ImVec4(r / 255.f, g / 255.f, b / 255.f, a / 255.f); };
    ImVec4* col = s.Colors;
    col[ImGuiCol_Text] = c(220, 220, 220);
    col[ImGuiCol_TextDisabled] = c(133, 133, 133);
    col[ImGuiCol_WindowBg] = c(30, 30, 30);
    col[ImGuiCol_ChildBg] = c(30, 30, 30);
    col[ImGuiCol_PopupBg] = c(37, 37, 38);
    col[ImGuiCol_Border] = c(63, 63, 70);
    col[ImGuiCol_FrameBg] = c(51, 51, 55);
    col[ImGuiCol_FrameBgHovered] = c(63, 63, 70);
    col[ImGuiCol_FrameBgActive] = c(63, 63, 70);
    col[ImGuiCol_TitleBg] = c(45, 45, 48);
    col[ImGuiCol_TitleBgActive] = c(0, 122, 204);
    col[ImGuiCol_TitleBgCollapsed] = c(45, 45, 48);
    col[ImGuiCol_MenuBarBg] = c(45, 45, 48);
    col[ImGuiCol_ScrollbarBg] = c(30, 30, 30);
    col[ImGuiCol_ScrollbarGrab] = c(80, 80, 80);
    col[ImGuiCol_ScrollbarGrabHovered] = c(110, 110, 110);
    col[ImGuiCol_ScrollbarGrabActive] = c(140, 140, 140);
    col[ImGuiCol_Button] = c(63, 63, 70);
    col[ImGuiCol_ButtonHovered] = c(0, 122, 204);
    col[ImGuiCol_ButtonActive] = c(0, 98, 163);
    col[ImGuiCol_Header] = c(51, 51, 55);
    col[ImGuiCol_HeaderHovered] = c(62, 62, 66);
    col[ImGuiCol_HeaderActive] = c(0, 122, 204);
    col[ImGuiCol_Separator] = c(63, 63, 70);
    col[ImGuiCol_Tab] = c(45, 45, 48);
    col[ImGuiCol_TabHovered] = c(28, 151, 234);
    col[ImGuiCol_TabSelected] = c(0, 122, 204);
    col[ImGuiCol_TabDimmed] = c(45, 45, 48);
    col[ImGuiCol_TabDimmedSelected] = c(63, 63, 70);
    col[ImGuiCol_DockingPreview] = c(0, 122, 204, 150);
    col[ImGuiCol_DockingEmptyBg] = c(30, 30, 30);
    col[ImGuiCol_ResizeGrip] = c(0, 0, 0, 0);
    col[ImGuiCol_TextSelectedBg] = c(38, 79, 120);
}
