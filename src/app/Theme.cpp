#include "app/Theme.hpp"
#include "app/Icons.hpp"
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <initializer_list>
#include <vector>

ImFont* Theme::mono_ = nullptr;
bool Theme::icons_ = false;
ImGuiStyle Theme::baseStyle_;
bool Theme::styleCaptured_ = false;

namespace {

ImFont* tryLoad(ImGuiIO& io, std::initializer_list<const char*> candidates, float size,
                const ImWchar* ranges, const ImFontConfig* config) {
    for (const char* path : candidates) {
        if (!std::filesystem::exists(path)) continue;
        if (ImFont* font = io.Fonts->AddFontFromFileTTF(path, size, config, ranges)) return font;
    }
    return nullptr;
}

bool fileExists(const char* path) { return std::filesystem::exists(path); }

// Appends a zero-terminated ImWchar range list into `out` (without its
// terminator), skipping the terminating 0.
void appendRanges(std::vector<ImWchar>& out, const ImWchar* ranges) {
    if (!ranges) return;
    for (const ImWchar* r = ranges; r[0] || r[1]; r += 2) {
        out.push_back(r[0]);
        out.push_back(r[1]);
    }
}

// Merges the collected (lo, hi) pairs into a sorted, de-duplicated,
// zero-terminated static array ImGui can use.
const ImWchar* mergedRanges(std::vector<ImWchar>&& flat) {
    std::vector<std::pair<ImWchar, ImWchar>> intervals;
    for (size_t i = 0; i + 1 < flat.size(); i += 2) intervals.emplace_back(flat[i], flat[i + 1]);
    std::sort(intervals.begin(), intervals.end());
    std::vector<ImWchar> merged;
    merged.reserve(intervals.size() * 2 + 1);
    for (auto [lo, hi] : intervals) {
        if (!merged.empty() && lo <= (ImWchar)(merged.back() + 1)) {
            if (hi > merged.back()) merged.back() = hi;  // extend the previous range
        } else {
            merged.push_back(lo);
            merged.push_back(hi);
        }
    }
    merged.push_back(0);
    static std::vector<ImWchar> storage;
    storage = std::move(merged);
    return storage.data();
}

// Base coverage shared by the UI and mono fonts: Latin, Greek, Cyrillic.
const ImWchar* baseRanges(ImGuiIO& io) {
    std::vector<ImWchar> r;
    appendRanges(r, io.Fonts->GetGlyphRangesDefault());
    appendRanges(r, io.Fonts->GetGlyphRangesGreek());
    appendRanges(r, io.Fonts->GetGlyphRangesCyrillic());
    return mergedRanges(std::move(r));
}

// CJK coverage used as a merged fallback - Segoe UI, Consolas and DejaVu ship
// none of these. The full unified-ideograph block is ~21k glyphs per font
// (two fonts -> an atlas of several hundred MB once the CPU, RGBA and driver
// copies are counted), so by default only the common Chinese (2500) and
// Japanese (2999 kanji) subsets plus kana / punctuation / fullwidth forms are
// baked; `full` restores the whole block.
const ImWchar* cjkRanges(ImGuiIO& io, bool full) {
    static const ImWchar fullRanges[] = {
        0x2018, 0x201F,  // quotes used by CJK text
        0x3000, 0x30FF,  // CJK symbols + kana
        0x31F0, 0x31FF,
        0x4E00, 0x9FFF,  // CJK unified ideographs
        0xFF00, 0xFFEF,  // fullwidth forms
        0,
    };
    if (full) return fullRanges;
    static std::vector<ImWchar> common;
    if (common.empty()) {
        std::vector<ImWchar> r;
        appendRanges(r, io.Fonts->GetGlyphRangesChineseSimplifiedCommon());
        appendRanges(r, io.Fonts->GetGlyphRangesJapanese());
        r.push_back(0x2018), r.push_back(0x201F);
        // Merge into sorted, non-overlapping intervals (own storage: the
        // static buffer of mergedRanges() is used by the base ranges).
        std::vector<std::pair<ImWchar, ImWchar>> iv;
        for (size_t i = 0; i + 1 < r.size(); i += 2) iv.emplace_back(r[i], r[i + 1]);
        std::sort(iv.begin(), iv.end());
        for (auto [lo, hi] : iv) {
            if (!common.empty() && lo <= (ImWchar)(common.back() + 1)) {
                if (hi > common.back()) common.back() = hi;
            } else {
                common.push_back(lo);
                common.push_back(hi);
            }
        }
        common.push_back(0);
    }
    return common.data();
}

}  // namespace

void Theme::loadFonts(ImGuiIO& io, float scale, bool fullCjk) {
    scale = std::clamp(scale, 0.75f, 3.0f);
    const float uiSize = std::round(16.f * scale);
    const float monoSize = std::round(15.f * scale);
    const ImWchar* base = baseRanges(io);

    // CJK-capable fallback found on the target system, merged into both
    // fonts so Chinese/Japanese comments and names keep rendering.
    const char* cjkFonts[] = {
        "C:/Windows/Fonts/msyh.ttc",        // Microsoft YaHei
        "C:/Windows/Fonts/simsun.ttc",      // SimSun
        "/usr/share/fonts/truetype/chinese/NotoSansSC-Regular.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    };
    const char* cjk = nullptr;
    for (const char* path : cjkFonts)
        if (fileExists(path)) {
            cjk = path;
            break;
        }

    ImFont* ui = tryLoad(io, {"C:/Windows/Fonts/segoeui.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                              "/System/Library/Fonts/Supplemental/Arial.ttf"},
                         uiSize, base, nullptr);
    if (!ui) ui = io.Fonts->AddFontDefault();
    if (ui && cjk) {
        ImFontConfig merge;
        merge.MergeMode = true;
        io.Fonts->AddFontFromFileTTF(cjk, uiSize, &merge, cjkRanges(io, fullCjk));
    }
    // Icons: the Windows icon font, merged into the UI font so menus, tabs and
    // buttons can carry them inline. Fixed advance keeps them in a column.
    icons_ = false;
    for (const char* path : {"C:/Windows/Fonts/SegoeIcons.ttf", "C:/Windows/Fonts/segmdl2.ttf"}) {
        if (!ui || !fileExists(path)) continue;
        ImFontConfig merge;
        merge.MergeMode = true;
        merge.PixelSnapH = true;
        merge.GlyphMinAdvanceX = std::round(uiSize * 1.05f);
        merge.GlyphOffset = ImVec2(0.f, std::round(uiSize * 0.12f));
        icons_ = io.Fonts->AddFontFromFileTTF(path, std::round(uiSize * 0.92f), &merge, icons::glyphRanges()) != nullptr;
        break;
    }

    mono_ = tryLoad(io, {"C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                         "/System/Library/Fonts/Menlo.ttc"},
                    monoSize, base, nullptr);
    if (!mono_) mono_ = io.Fonts->AddFontDefault();
    if (mono_ && cjk) {
        ImFontConfig merge;
        merge.MergeMode = true;
        io.Fonts->AddFontFromFileTTF(cjk, monoSize, &merge, cjkRanges(io, fullCjk));
    }
    io.Fonts->Build();
}

void Theme::releaseFontBuildData(ImGuiIO& io) {
    // Safe once the texture exists: rendering only needs the glyph tables
    // and the GPU texture. A DPI change rebuilds everything from scratch.
    io.Fonts->ClearTexData();
    io.Fonts->ClearInputData();
}

ImFont* Theme::monoFont() { return mono_ ? mono_ : ImGui::GetFont(); }

ImVec4 Theme::editorBackground() { return ImVec4(31 / 255.f, 31 / 255.f, 31 / 255.f, 1.f); }

void Theme::apply() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 0.f;
    s.ChildRounding = 0.f;
    s.FrameRounding = 3.f;
    s.PopupRounding = 4.f;
    s.ScrollbarRounding = 6.f;
    s.GrabRounding = 3.f;
    s.TabRounding = 0.f;
    s.TabBarOverlineSize = 2.f;  // accent line over the selected tab
    s.WindowBorderSize = 1.f;
    s.PopupBorderSize = 1.f;
    s.FrameBorderSize = 0.f;
    s.ScrollbarSize = 12.f;
    s.ItemSpacing = ImVec2(6.f, 2.f);
    s.FramePadding = ImVec2(6.f, 3.f);
    s.WindowPadding = ImVec2(8.f, 6.f);
    s.IndentSpacing = 14.f;

    auto c = [](int r, int g, int b, int a = 255) { return ImVec4(r / 255.f, g / 255.f, b / 255.f, a / 255.f); };
    ImVec4* col = s.Colors;
    const ImVec4 accent = c(0, 120, 212);
    col[ImGuiCol_Text] = c(204, 204, 204);
    col[ImGuiCol_TextDisabled] = c(157, 157, 157);
    col[ImGuiCol_WindowBg] = c(24, 24, 24);
    col[ImGuiCol_ChildBg] = c(0, 0, 0, 0);
    col[ImGuiCol_PopupBg] = c(31, 31, 31);
    col[ImGuiCol_Border] = c(43, 43, 43);
    col[ImGuiCol_BorderShadow] = c(0, 0, 0, 0);
    col[ImGuiCol_FrameBg] = c(49, 49, 49);
    col[ImGuiCol_FrameBgHovered] = c(60, 60, 60);
    col[ImGuiCol_FrameBgActive] = c(60, 60, 60);
    col[ImGuiCol_TitleBg] = c(24, 24, 24);
    col[ImGuiCol_TitleBgActive] = c(24, 24, 24);
    col[ImGuiCol_TitleBgCollapsed] = c(24, 24, 24);
    col[ImGuiCol_MenuBarBg] = c(24, 24, 24);
    col[ImGuiCol_ScrollbarBg] = c(0, 0, 0, 0);
    col[ImGuiCol_ScrollbarGrab] = c(121, 121, 121, 90);
    col[ImGuiCol_ScrollbarGrabHovered] = c(121, 121, 121, 150);
    col[ImGuiCol_ScrollbarGrabActive] = c(121, 121, 121, 200);
    col[ImGuiCol_CheckMark] = c(204, 204, 204);
    col[ImGuiCol_SliderGrab] = accent;
    col[ImGuiCol_SliderGrabActive] = c(38, 146, 230);
    col[ImGuiCol_Button] = c(49, 49, 49);
    col[ImGuiCol_ButtonHovered] = c(66, 66, 66);
    col[ImGuiCol_ButtonActive] = accent;
    col[ImGuiCol_Header] = c(4, 57, 94);           // selected row
    col[ImGuiCol_HeaderHovered] = c(42, 45, 46);   // hovered row
    col[ImGuiCol_HeaderActive] = c(4, 57, 94);
    col[ImGuiCol_Separator] = c(43, 43, 43);
    col[ImGuiCol_SeparatorHovered] = accent;
    col[ImGuiCol_SeparatorActive] = accent;
    col[ImGuiCol_ResizeGrip] = c(0, 0, 0, 0);
    col[ImGuiCol_ResizeGripHovered] = accent;
    col[ImGuiCol_ResizeGripActive] = accent;
    col[ImGuiCol_Tab] = c(24, 24, 24);
    col[ImGuiCol_TabHovered] = c(31, 31, 31);
    col[ImGuiCol_TabSelected] = c(31, 31, 31);
    col[ImGuiCol_TabSelectedOverline] = accent;
    col[ImGuiCol_TabDimmed] = c(24, 24, 24);
    col[ImGuiCol_TabDimmedSelected] = c(31, 31, 31);
    col[ImGuiCol_TabDimmedSelectedOverline] = c(80, 80, 80);
    col[ImGuiCol_DockingPreview] = c(0, 120, 212, 120);
    col[ImGuiCol_DockingEmptyBg] = c(24, 24, 24);
    col[ImGuiCol_TableHeaderBg] = c(31, 31, 31);
    col[ImGuiCol_TableBorderStrong] = c(43, 43, 43);
    col[ImGuiCol_TableBorderLight] = c(43, 43, 43);
    col[ImGuiCol_TableRowBg] = c(0, 0, 0, 0);
    col[ImGuiCol_TableRowBgAlt] = c(255, 255, 255, 8);
    col[ImGuiCol_TextSelectedBg] = c(38, 79, 120);
    col[ImGuiCol_NavCursor] = accent;
    col[ImGuiCol_ModalWindowDimBg] = c(0, 0, 0, 110);

    baseStyle_ = s;  // unscaled reference for DPI changes
    styleCaptured_ = true;
    (void)styleCaptured_;
}

void Theme::scaleStyle(float scale) {
    ImGui::GetStyle() = baseStyle_;
    if (scale != 1.f) ImGui::GetStyle().ScaleAllSizes(scale);
}
