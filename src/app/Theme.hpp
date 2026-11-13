#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "imgui.h"
#include "document/SyntaxHighlighter.hpp"

class Settings;

// Semantic colour tokens. Every colour the UI draws comes from one of these,
// so a theme (and the user's per-colour overrides) reaches every panel, and
// ImGui's own widget colours are derived from the same tokens.
enum class Col : uint8_t {
    // Interface
    Background,        // panels, docks, tab strips
    EditorBackground,  // code, hex, terminal and graph areas
    PopupBackground,
    TitleBar,
    StatusBar,
    StatusBarText,
    Border,
    Control,       // buttons, inputs, checkboxes
    ControlHover,
    RowHover,
    RowSelected,
    TextSelection,
    Text,
    TextMuted,
    TextOnAccent,
    Accent,
    // Status
    Success,
    Warning,
    Error,
    Info,
    // Hues: categorical colours (file types, log sources, component kinds...)
    Red,
    Orange,
    Yellow,
    Green,
    Cyan,
    Blue,
    Purple,
    Pink,
    // Syntax
    SynDefault,
    SynKeyword,
    SynString,
    SynComment,
    SynNumber,
    SynType,
    SynPunctuation,
    SynAttribute,
    SynDirective,
    // Editor
    LineHighlight,
    FindMatch,
    FindMatchCurrent,
    SymbolLink,
    LineNumber,
    LineNumberActive,
    Caret,
    // Graphs
    GraphNode,
    GraphNodeBorder,
    // Terminal (ANSI 0-15)
    Ansi0, Ansi1, Ansi2, Ansi3, Ansi4, Ansi5, Ansi6, Ansi7,
    Ansi8, Ansi9, Ansi10, Ansi11, Ansi12, Ansi13, Ansi14, Ansi15,
    Count
};
inline constexpr size_t kColCount = static_cast<size_t>(Col::Count);

struct ThemePreset {
    std::string id;    // stable key stored in the settings ("dark-modern")
    std::string name;  // shown in the settings
    bool dark = true;
    std::array<ImVec4, kColCount> colors{};
};

// Colour lookups for drawing code.
namespace theme {
ImVec4 vec(Col c);
ImVec4 vec(Col c, float alpha);  // the token with its alpha multiplied
ImU32 u32(Col c);
ImU32 u32(Col c, float alpha);
ImU32 blend(Col a, Col b, float t);  // a mixed towards b by t (0..1)
ImU32 syntax(SyntaxToken t);
ImU32 ansi(int index);  // 0-15
bool isDark();
}  // namespace theme

// Fonts, style metrics and the active colour theme.
class Theme {
public:
    // Loads (or reloads, on a DPI change) every font at `scale` (1.0 = 96 DPI).
    // `fullCjk` merges every CJK unified ideograph (~21k glyphs per font)
    // instead of the common Chinese + Japanese subsets (~5k): complete
    // coverage, but a font atlas several times larger.
    static void loadFonts(ImGuiIO& io, float scale, bool fullCjk = false);
    // Frees the CPU-side copies the atlas keeps after the texture has been
    // uploaded (pixel buffers + the TTF files, ~20 MB each for CJK fonts).
    // Call after the renderer created the font texture.
    static void releaseFontBuildData(ImGuiIO& io);
    // Sets the style metrics and the colours of the active theme.
    static void apply();
    // Re-applies the base style scaled by `scale` (call after loadFonts).
    static void scaleStyle(float scale);
    static ImFont* monoFont();
    // True when the Windows icon font was found and merged (see Icons.hpp).
    static bool hasIcons() { return icons_; }
    static ImVec4 editorBackground() { return theme::vec(Col::EditorBackground); }

    // ---- colour themes ----------------------------------------------------
    static const std::vector<ThemePreset>& presets();
    static const ThemePreset& preset(const std::string& id);  // falls back to the default
    static const std::string& currentId() { return currentId_; }
    // Switches the preset; overrides stay (they are on top of any preset).
    static void setPreset(const std::string& id);
    static void setOverride(Col c, const ImVec4& color);
    static void clearOverride(Col c);
    static void clearOverrides();
    static bool hasOverride(Col c);
    static size_t overrideCount();
    // Preset id + overrides, as stored in the settings file.
    struct State {
        std::string id;
        std::array<bool, kColCount> overridden{};
        std::array<ImVec4, kColCount> overrides{};
    };
    static State state();
    static void restore(const State& s);
    static void load(const Settings& settings);
    static void save(Settings& settings);

    // Token metadata for the settings page.
    static const char* key(Col c);    // "syntax.keyword"
    static const char* label(Col c);  // "Keyword"
    static const char* group(Col c);  // "Syntax"
    static std::string toHex(const ImVec4& c);  // "#RRGGBB" or "#RRGGBBAA"
    static bool fromHex(std::string_view s, ImVec4& out);

    static constexpr const char* kDefaultTheme = "dark-modern";

private:
    static void applyColors();  // ImGui style colours from the tokens
    static void resolve();      // preset + overrides -> active colours

    static ImFont* mono_;
    static bool icons_;
    static ImGuiStyle baseStyle_;
    static std::string currentId_;
};
