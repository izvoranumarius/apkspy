#include "app/Theme.hpp"
#include "app/Icons.hpp"
#include "core/Settings.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <initializer_list>
#include <iterator>
#include <vector>

std::vector<ThemePreset> buildThemePresets();  // ThemePresets.cpp

ImFont* Theme::mono_ = nullptr;
bool Theme::icons_ = false;
ImGuiStyle Theme::baseStyle_;
std::string Theme::currentId_ = Theme::kDefaultTheme;

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
        if (!merged.empty() && lo <= static_cast<ImWchar>(merged.back() + 1)) {
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
            if (!common.empty() && lo <= static_cast<ImWchar>(common.back() + 1)) {
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
        // Slightly smaller than the text and centred on it, so icons stay
        // inside tabs and buttons instead of reaching their top edge.
        merge.GlyphOffset = ImVec2(0.f, std::round(uiSize * 0.16f));
        icons_ = io.Fonts->AddFontFromFileTTF(path, std::round(uiSize * 0.84f), &merge, icons::glyphRanges()) != nullptr;
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

// ---------------------------------------------------------------------------
// Colour themes
// ---------------------------------------------------------------------------

namespace {

struct TokenInfo {
    const char* key;
    const char* label;
    const char* group;
};

// Indexed by Col; the keys are persisted, so never rename one.
constexpr TokenInfo kTokens[] = {
    {"ui.background", "Background", "Interface"},
    {"ui.editorBackground", "Editor background", "Interface"},
    {"ui.popupBackground", "Popup background", "Interface"},
    {"ui.titleBar", "Title bar", "Interface"},
    {"ui.statusBar", "Status bar", "Interface"},
    {"ui.statusBarText", "Status bar text", "Interface"},
    {"ui.border", "Borders", "Interface"},
    {"ui.control", "Buttons and inputs", "Interface"},
    {"ui.controlHover", "Buttons and inputs (hover)", "Interface"},
    {"ui.rowHover", "Hovered row", "Interface"},
    {"ui.rowSelected", "Selected row", "Interface"},
    {"ui.textSelection", "Text selection", "Interface"},
    {"ui.text", "Text", "Interface"},
    {"ui.textMuted", "Secondary text", "Interface"},
    {"ui.textOnAccent", "Text on accent", "Interface"},
    {"ui.accent", "Accent", "Interface"},
    {"status.success", "Success", "Status"},
    {"status.warning", "Warning", "Status"},
    {"status.error", "Error", "Status"},
    {"status.info", "Information", "Status"},
    {"hue.red", "Red", "Hues"},
    {"hue.orange", "Orange", "Hues"},
    {"hue.yellow", "Yellow", "Hues"},
    {"hue.green", "Green", "Hues"},
    {"hue.cyan", "Cyan", "Hues"},
    {"hue.blue", "Blue", "Hues"},
    {"hue.purple", "Purple", "Hues"},
    {"hue.pink", "Pink", "Hues"},
    {"syntax.default", "Plain code", "Syntax"},
    {"syntax.keyword", "Keywords", "Syntax"},
    {"syntax.string", "Strings", "Syntax"},
    {"syntax.comment", "Comments", "Syntax"},
    {"syntax.number", "Numbers", "Syntax"},
    {"syntax.type", "Types", "Syntax"},
    {"syntax.punctuation", "Punctuation", "Syntax"},
    {"syntax.attribute", "Attributes", "Syntax"},
    {"syntax.directive", "Directives and annotations", "Syntax"},
    {"editor.lineHighlight", "Current line", "Editor"},
    {"editor.findMatch", "Search match", "Editor"},
    {"editor.findMatchCurrent", "Current search match", "Editor"},
    {"editor.symbolLink", "Symbol link underline", "Editor"},
    {"editor.lineNumber", "Line numbers", "Editor"},
    {"editor.lineNumberActive", "Current line number", "Editor"},
    {"editor.caret", "Caret", "Editor"},
    {"graph.node", "Block background", "Graphs"},
    {"graph.nodeBorder", "Block border", "Graphs"},
    {"terminal.ansi0", "Black", "Terminal"},
    {"terminal.ansi1", "Red", "Terminal"},
    {"terminal.ansi2", "Green", "Terminal"},
    {"terminal.ansi3", "Yellow", "Terminal"},
    {"terminal.ansi4", "Blue", "Terminal"},
    {"terminal.ansi5", "Magenta", "Terminal"},
    {"terminal.ansi6", "Cyan", "Terminal"},
    {"terminal.ansi7", "White", "Terminal"},
    {"terminal.ansi8", "Bright black", "Terminal"},
    {"terminal.ansi9", "Bright red", "Terminal"},
    {"terminal.ansi10", "Bright green", "Terminal"},
    {"terminal.ansi11", "Bright yellow", "Terminal"},
    {"terminal.ansi12", "Bright blue", "Terminal"},
    {"terminal.ansi13", "Bright magenta", "Terminal"},
    {"terminal.ansi14", "Bright cyan", "Terminal"},
    {"terminal.ansi15", "Bright white", "Terminal"},
};

static_assert(std::size(kTokens) == kColCount, "one TokenInfo per Col token, in enum order");

constexpr const char* kThemeKey = "theme.name";
constexpr const char* kColorKeyPrefix = "theme.color.";

std::array<ImVec4, kColCount> g_colors{};  // resolved: preset + overrides
std::array<ImVec4, kColCount> g_overrides{};
std::array<bool, kColCount> g_overridden{};
bool g_dark = true;

size_t idx(Col c) { return static_cast<size_t>(c); }

int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

ImVec4 mix(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t);
}

}  // namespace

namespace theme {
ImVec4 vec(Col c) { return g_colors[idx(c)]; }
ImVec4 vec(Col c, float alpha) {
    ImVec4 v = g_colors[idx(c)];
    v.w *= alpha;
    return v;
}
ImU32 u32(Col c) { return ImGui::ColorConvertFloat4ToU32(g_colors[idx(c)]); }
ImU32 u32(Col c, float alpha) { return ImGui::ColorConvertFloat4ToU32(vec(c, alpha)); }
ImU32 blend(Col a, Col b, float t) { return ImGui::ColorConvertFloat4ToU32(mix(vec(a), vec(b), t)); }
ImU32 syntax(SyntaxToken t) {
    static constexpr Col map[] = {Col::SynDefault, Col::SynKeyword, Col::SynString, Col::SynComment, Col::SynNumber,
                                  Col::SynType,    Col::SynPunctuation, Col::SynAttribute, Col::SynDirective};
    const size_t i = static_cast<size_t>(t);
    return u32(i < std::size(map) ? map[i] : Col::SynDefault);
}
ImU32 ansi(int index) { return u32(static_cast<Col>(static_cast<int>(Col::Ansi0) + std::clamp(index, 0, 15))); }
bool isDark() { return g_dark; }
}  // namespace theme

const std::vector<ThemePreset>& Theme::presets() {
    static const std::vector<ThemePreset> all = buildThemePresets();
    return all;
}

const ThemePreset& Theme::preset(const std::string& id) {
    for (const ThemePreset& p : presets())
        if (p.id == id) return p;
    return presets().front();
}

const char* Theme::key(Col c) { return kTokens[idx(c)].key; }
const char* Theme::label(Col c) { return kTokens[idx(c)].label; }
const char* Theme::group(Col c) { return kTokens[idx(c)].group; }

std::string Theme::toHex(const ImVec4& c) {
    const auto byte = [](float v) { return static_cast<int>(std::lround(std::clamp(v, 0.f, 1.f) * 255.f)); };
    char buf[16];
    if (byte(c.w) == 255) std::snprintf(buf, sizeof buf, "#%02X%02X%02X", byte(c.x), byte(c.y), byte(c.z));
    else std::snprintf(buf, sizeof buf, "#%02X%02X%02X%02X", byte(c.x), byte(c.y), byte(c.z), byte(c.w));
    return buf;
}

bool Theme::fromHex(std::string_view s, ImVec4& out) {
    if (!s.empty() && s.front() == '#') s.remove_prefix(1);
    if (s.size() != 6 && s.size() != 8) return false;
    int v[4] = {0, 0, 0, 255};
    for (size_t i = 0; i < s.size() / 2; ++i) {
        const int hi = hexDigit(s[i * 2]), lo = hexDigit(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        v[i] = hi * 16 + lo;
    }
    out = ImVec4(v[0] / 255.f, v[1] / 255.f, v[2] / 255.f, v[3] / 255.f);
    return true;
}

void Theme::resolve() {
    const ThemePreset& p = preset(currentId_);
    currentId_ = p.id;  // an unknown id falls back to the default
    g_dark = p.dark;
    for (size_t i = 0; i < kColCount; ++i) g_colors[i] = g_overridden[i] ? g_overrides[i] : p.colors[i];
}

void Theme::setPreset(const std::string& id) {
    currentId_ = id;
    resolve();
    applyColors();
}

void Theme::setOverride(Col c, const ImVec4& color) {
    g_overrides[idx(c)] = color;
    g_overridden[idx(c)] = true;
    resolve();
    applyColors();
}

void Theme::clearOverride(Col c) {
    g_overridden[idx(c)] = false;
    resolve();
    applyColors();
}

void Theme::clearOverrides() {
    g_overridden.fill(false);
    resolve();
    applyColors();
}

bool Theme::hasOverride(Col c) { return g_overridden[idx(c)]; }

size_t Theme::overrideCount() { return static_cast<size_t>(std::count(g_overridden.begin(), g_overridden.end(), true)); }

Theme::State Theme::state() { return State{currentId_, g_overridden, g_overrides}; }

void Theme::restore(const State& s) {
    currentId_ = s.id;
    g_overridden = s.overridden;
    g_overrides = s.overrides;
    resolve();
    applyColors();
}

void Theme::load(const Settings& settings) {
    currentId_ = settings.getString(kThemeKey, kDefaultTheme);
    for (size_t i = 0; i < kColCount; ++i) {
        ImVec4 c;
        g_overridden[i] = fromHex(settings.getString(std::string(kColorKeyPrefix) + kTokens[i].key), c);
        if (g_overridden[i]) g_overrides[i] = c;
    }
    resolve();
    applyColors();
}

void Theme::save(Settings& settings) {
    settings.set(kThemeKey, currentId_);
    for (size_t i = 0; i < kColCount; ++i) {
        const std::string k = std::string(kColorKeyPrefix) + kTokens[i].key;
        if (g_overridden[i]) settings.set(k, toHex(g_overrides[i]));
        else settings.remove(k);
    }
}

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
    // Room between and inside elements: with 2 px rows, inputs, buttons and
    // tab icons touched each other (and the tab's accent line).
    s.ItemSpacing = ImVec2(8.f, 4.f);
    s.ItemInnerSpacing = ImVec2(6.f, 4.f);
    s.FramePadding = ImVec2(8.f, 4.f);
    s.WindowPadding = ImVec2(10.f, 8.f);
    s.CellPadding = ImVec2(6.f, 3.f);
    s.IndentSpacing = 14.f;
    baseStyle_ = s;  // unscaled reference for DPI changes
    resolve();
    applyColors();
}

// ImGui's widget colours, derived from the tokens so every built-in widget
// matches the custom-drawn parts of the UI.
void Theme::applyColors() {
    using theme::vec;
    const ImVec4 none(0, 0, 0, 0);
    const ImVec4 bg = vec(Col::Background), editor = vec(Col::EditorBackground), accent = vec(Col::Accent);
    ImVec4 c[ImGuiCol_COUNT];
    for (ImVec4& v : c) v = none;
    c[ImGuiCol_Text] = vec(Col::Text);
    c[ImGuiCol_TextDisabled] = vec(Col::TextMuted);
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = none;
    c[ImGuiCol_PopupBg] = vec(Col::PopupBackground);
    c[ImGuiCol_Border] = vec(Col::Border);
    c[ImGuiCol_BorderShadow] = none;
    c[ImGuiCol_FrameBg] = vec(Col::Control);
    c[ImGuiCol_FrameBgHovered] = vec(Col::ControlHover);
    c[ImGuiCol_FrameBgActive] = vec(Col::ControlHover);
    c[ImGuiCol_TitleBg] = bg;
    c[ImGuiCol_TitleBgActive] = bg;
    c[ImGuiCol_TitleBgCollapsed] = bg;
    c[ImGuiCol_MenuBarBg] = bg;
    c[ImGuiCol_ScrollbarBg] = none;
    c[ImGuiCol_ScrollbarGrab] = vec(Col::TextMuted, 0.35f);
    c[ImGuiCol_ScrollbarGrabHovered] = vec(Col::TextMuted, 0.6f);
    c[ImGuiCol_ScrollbarGrabActive] = vec(Col::TextMuted, 0.8f);
    c[ImGuiCol_CheckMark] = vec(Col::Text);
    c[ImGuiCol_SliderGrab] = accent;
    c[ImGuiCol_SliderGrabActive] = mix(accent, vec(Col::Text), 0.2f);
    c[ImGuiCol_Button] = vec(Col::Control);
    c[ImGuiCol_ButtonHovered] = vec(Col::ControlHover);
    // Pressed: a step past hover, not a flash of accent (ImGui also uses this
    // colour for the docking corner triangle of a focused panel).
    c[ImGuiCol_ButtonActive] = mix(vec(Col::ControlHover), vec(Col::Text), 0.12f);
    c[ImGuiCol_Header] = vec(Col::RowSelected);
    c[ImGuiCol_HeaderHovered] = vec(Col::RowHover);
    c[ImGuiCol_HeaderActive] = vec(Col::RowSelected);
    c[ImGuiCol_Separator] = vec(Col::Border);
    c[ImGuiCol_SeparatorHovered] = accent;
    c[ImGuiCol_SeparatorActive] = accent;
    c[ImGuiCol_ResizeGrip] = none;
    c[ImGuiCol_ResizeGripHovered] = accent;
    c[ImGuiCol_ResizeGripActive] = accent;
    c[ImGuiCol_Tab] = bg;
    c[ImGuiCol_TabHovered] = editor;
    c[ImGuiCol_TabSelected] = editor;
    c[ImGuiCol_TabSelectedOverline] = accent;
    c[ImGuiCol_TabDimmed] = bg;
    c[ImGuiCol_TabDimmedSelected] = editor;
    c[ImGuiCol_TabDimmedSelectedOverline] = vec(Col::TextMuted, 0.5f);
    c[ImGuiCol_DockingPreview] = vec(Col::Accent, 0.47f);
    c[ImGuiCol_DockingEmptyBg] = bg;
    c[ImGuiCol_PlotLines] = vec(Col::Blue);
    c[ImGuiCol_PlotLinesHovered] = vec(Col::Orange);
    c[ImGuiCol_PlotHistogram] = vec(Col::Blue);
    c[ImGuiCol_PlotHistogramHovered] = vec(Col::Orange);
    c[ImGuiCol_TableHeaderBg] = vec(Col::PopupBackground);
    c[ImGuiCol_TableBorderStrong] = vec(Col::Border);
    c[ImGuiCol_TableBorderLight] = vec(Col::Border);
    c[ImGuiCol_TableRowBg] = none;
    c[ImGuiCol_TableRowBgAlt] = vec(Col::Text, 0.03f);
    c[ImGuiCol_TextLink] = vec(Col::Blue);
    c[ImGuiCol_TextSelectedBg] = vec(Col::TextSelection);
    c[ImGuiCol_DragDropTarget] = accent;
    c[ImGuiCol_NavCursor] = accent;
    c[ImGuiCol_NavWindowingHighlight] = vec(Col::Text, 0.7f);
    c[ImGuiCol_NavWindowingDimBg] = ImVec4(0, 0, 0, 0.2f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, g_dark ? 0.43f : 0.25f);
    for (int i = 0; i < ImGuiCol_COUNT; ++i) baseStyle_.Colors[i] = c[i];
    if (ImGui::GetCurrentContext())
        for (int i = 0; i < ImGuiCol_COUNT; ++i) ImGui::GetStyle().Colors[i] = c[i];
}

void Theme::scaleStyle(float scale) {
    ImGui::GetStyle() = baseStyle_;
    if (scale != 1.f) ImGui::GetStyle().ScaleAllSizes(scale);
}
