#include "app/Theme.hpp"
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <initializer_list>
#include <vector>

ImFont* Theme::mono_ = nullptr;
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

    baseStyle_ = s;  // unscaled reference for DPI changes
    styleCaptured_ = true;
    (void)styleCaptured_;
}

void Theme::scaleStyle(float scale) {
    ImGui::GetStyle() = baseStyle_;
    if (scale != 1.f) ImGui::GetStyle().ScaleAllSizes(scale);
}
