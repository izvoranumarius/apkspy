#pragma once
#include "imgui.h"

// Fonts and colours. Fonts are loaded at a size derived from the monitor
// content scale and cover Latin, Greek, Cyrillic and the common CJK ranges,
// so decompiled code and file names from Asian apps render instead of
// turning into '?'.
class Theme {
public:
    // Loads (or reloads, on a DPI change) every font at `scale` (1.0 = 96 DPI).
    static void loadFonts(ImGuiIO& io, float scale);
    static void apply();
    // Re-applies the base style scaled by `scale` (call after loadFonts).
    static void scaleStyle(float scale);
    static ImFont* monoFont();

private:
    static ImFont* mono_;
    static ImGuiStyle baseStyle_;
    static bool styleCaptured_;
};
