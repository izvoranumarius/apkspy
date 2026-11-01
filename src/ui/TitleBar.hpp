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
    // Replaces the placeholder glyph in the caption's icon slot with the
    // favicon texture (Application::loadWindowIcon). Keeps the fallback when
    // never called or when the texture is empty.
    void setIcon(ImTextureID texture, float width, float height) {
        icon_ = texture;
        iconWidth_ = width;
        iconHeight_ = height;
    }
    // The caption X button goes through this handler (the Application routes
    // it through the unsaved-changes confirmation, exactly like Alt+F4 and
    // File > Exit). Without a handler the window simply closes.
    void setCloseHandler(std::function<void()> handler) { closeHandler_ = std::move(handler); }
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
    std::function<void()> closeHandler_;
    ImTextureID icon_ = 0;
    float iconWidth_ = 0.f;
    float iconHeight_ = 0.f;
    int openMenu_ = -1;
    float height_ = 32.f;
};
