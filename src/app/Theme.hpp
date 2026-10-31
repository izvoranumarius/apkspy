#pragma once
#include "imgui.h"

class Theme {
public:
    static void loadFonts(ImGuiIO& io);
    static void apply();
    static ImFont* monoFont();

private:
    static ImFont* mono_;
};
