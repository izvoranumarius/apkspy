#pragma once
#include <functional>
#include <string>
#include <vector>
#include "imgui.h"
#include "app/WindowFrame.hpp"

class TitleBar {
public:
    explicit TitleBar(WindowFrame& frame) : frame_(frame) {}

    void addMenu(std::string label, std::function<void()> contents);
    void setTitle(std::string title) { title_ = std::move(title); }
    float height() const { return height_; }
    void render();

private:
    struct Menu {
        std::string label;
        std::string popupId;
        std::function<void()> contents;
    };
    enum class Glyph { Minimize, Maximize, Restore, Close };

    void drawIcon(ImDrawList* dl, const Rect& area) const;
    void drawGlyph(ImDrawList* dl, const Rect& area, Glyph glyph, ImU32 color) const;
    void drawCaptionBackground(ImDrawList* dl, const Rect& area, ImU32 color) const;

    WindowFrame& frame_;
    std::vector<Menu> menus_;
    std::string title_;
    int openMenu_ = -1;
    float height_ = 32.f;
};
