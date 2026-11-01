#include "ui/TitleBar.hpp"
#include <algorithm>
#include <cmath>

namespace {
const ImU32 kBackground = IM_COL32(45, 45, 48, 255);
const ImU32 kHover = IM_COL32(62, 62, 66, 255);
const ImU32 kPressed = IM_COL32(84, 84, 88, 255);
const ImU32 kMenuOpen = IM_COL32(63, 63, 70, 255);
const ImU32 kCloseHover = IM_COL32(232, 17, 35, 255);
const ImU32 kClosePressed = IM_COL32(241, 112, 122, 255);
const ImU32 kGlyph = IM_COL32(225, 225, 225, 255);
const ImU32 kTitle = IM_COL32(170, 170, 170, 255);
const ImU32 kAccent = IM_COL32(0, 122, 204, 255);
const ImU32 kBorder = IM_COL32(63, 63, 70, 255);
constexpr float kButtonWidth = 46.f;
constexpr float kMenuPadding = 11.f;

ImVec2 center(const Rect& r) { return ImVec2(std::floor((r.left + r.right) * 0.5f), std::floor((r.top + r.bottom) * 0.5f)); }
}

void TitleBar::addMenu(std::string label, std::function<void()> contents) {
    Menu menu;
    menu.popupId = "##menu_" + label;
    menu.label = std::move(label);
    menu.contents = std::move(contents);
    menus_.push_back(std::move(menu));
}

void TitleBar::drawIcon(ImDrawList* dl, const Rect& area) const {
    ImVec2 c = center(area);
    if (icon_ != 0 && iconWidth_ > 0.f && iconHeight_ > 0.f) {
        // Fit the favicon into the same 16x16 box the placeholder uses.
        const float side = std::max(iconWidth_, iconHeight_);
        const float scale = std::min(1.f, 16.f / side);
        const float w = iconWidth_ * scale, h = iconHeight_ * scale;
        dl->AddImage(icon_, ImVec2(c.x - w * 0.5f, c.y - h * 0.5f), ImVec2(c.x + w * 0.5f, c.y + h * 0.5f));
        return;
    }
    dl->AddRectFilled(ImVec2(c.x - 8.f, c.y - 8.f), ImVec2(c.x + 8.f, c.y + 8.f), kAccent, 3.f);
    ImVec2 ts = ImGui::CalcTextSize("A");
    dl->AddText(ImVec2(std::floor(c.x - ts.x * 0.5f), std::floor(c.y - ts.y * 0.5f)), IM_COL32(255, 255, 255, 255), "A");
}

void TitleBar::drawCaptionBackground(ImDrawList* dl, const Rect& area, ImU32 color) const {
    dl->AddRectFilled(ImVec2(area.left, area.top), ImVec2(area.right, area.bottom), color);
}

void TitleBar::drawGlyph(ImDrawList* dl, const Rect& area, Glyph glyph, ImU32 color) const {
    ImVec2 c = center(area);
    switch (glyph) {
    case Glyph::Minimize:
        dl->AddLine(ImVec2(c.x - 5.f, c.y + 0.5f), ImVec2(c.x + 5.f, c.y + 0.5f), color, 1.f);
        break;
    case Glyph::Maximize:
        dl->AddRect(ImVec2(c.x - 4.5f, c.y - 4.5f), ImVec2(c.x + 5.5f, c.y + 5.5f), color, 0.f, 0, 1.f);
        break;
    case Glyph::Restore: {
        dl->AddRect(ImVec2(c.x - 4.5f, c.y - 2.5f), ImVec2(c.x + 3.5f, c.y + 5.5f), color, 0.f, 0, 1.f);
        ImVec2 back[5] = {ImVec2(c.x - 2.5f, c.y - 2.5f), ImVec2(c.x - 2.5f, c.y - 4.5f), ImVec2(c.x + 5.5f, c.y - 4.5f),
                          ImVec2(c.x + 5.5f, c.y + 3.5f), ImVec2(c.x + 3.5f, c.y + 3.5f)};
        dl->AddPolyline(back, 5, color, ImDrawFlags_None, 1.f);
        break;
    }
    case Glyph::Close:
        dl->AddLine(ImVec2(c.x - 5.f, c.y - 5.f), ImVec2(c.x + 5.f, c.y + 5.f), color, 1.f);
        dl->AddLine(ImVec2(c.x + 5.f, c.y - 5.f), ImVec2(c.x - 5.f, c.y + 5.f), color, 1.f);
        break;
    }
}

void TitleBar::render() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImVec2 origin = vp->Pos;
    const float width = vp->Size.x;

    ImGui::SetNextWindowPos(origin);
    ImGui::SetNextWindowSize(ImVec2(width, height_));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(kBackground));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                                   ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoFocusOnAppearing;
    ImGui::Begin("##titlebar", nullptr, flags);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const bool windowHovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
    const float top = origin.y;
    const float bottom = origin.y + height_;

    FrameLayout layout;
    layout.titleBarHeight = height_;
    layout.systemMenu = Rect{origin.x, top, origin.x + height_, bottom};
    drawIcon(dl, layout.systemMenu);

    int justClosed = -1;
    if (openMenu_ >= 0 && !ImGui::IsPopupOpen(menus_[(size_t)openMenu_].popupId.c_str())) {
        justClosed = openMenu_;
        openMenu_ = -1;
    }

    std::vector<Rect> menuRects;
    float x = origin.x + height_;
    for (size_t i = 0; i < menus_.size(); ++i) {
        const Menu& menu = menus_[i];
        const float w = ImGui::CalcTextSize(menu.label.c_str()).x + kMenuPadding * 2.f;
        Rect r{x, top, x + w, bottom};
        menuRects.push_back(r);
        layout.clientRects.push_back(r);
        x += w;

        const bool hovered = windowHovered && ImGui::IsMouseHoveringRect(ImVec2(r.left, r.top), ImVec2(r.right, r.bottom), false);
        const bool clicked = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
        if (clicked && (int)i != justClosed) {
            openMenu_ = (int)i;
            ImGui::OpenPopup(menu.popupId.c_str());
        } else if (hovered && openMenu_ >= 0 && openMenu_ != (int)i) {
            openMenu_ = (int)i;
            ImGui::OpenPopup(menu.popupId.c_str());
        }
        if (openMenu_ == (int)i) drawCaptionBackground(dl, r, kMenuOpen);
        else if (hovered) drawCaptionBackground(dl, r, kHover);
        ImVec2 textSize = ImGui::CalcTextSize(menu.label.c_str());
        dl->AddText(ImVec2(std::floor(r.left + kMenuPadding), std::floor(top + (height_ - textSize.y) * 0.5f)), kGlyph,
                    menu.label.c_str());
    }
    const float menusEnd = x;

    const bool overMax = frame_.maximizeHovered();
    const bool maximized = frame_.maximized();
    Rect closeRect{origin.x + width - kButtonWidth, top, origin.x + width, bottom};
    Rect maxRect{closeRect.left - kButtonWidth, top, closeRect.left, bottom};
    Rect minRect{maxRect.left - kButtonWidth, top, maxRect.left, bottom};
    layout.maximizeButton = maxRect;
    layout.clientRects.push_back(minRect);
    layout.clientRects.push_back(closeRect);

    const float captionStart = minRect.left;
    const ImVec2 titleSize = ImGui::CalcTextSize(title_.c_str());
    float titleX = std::floor((origin.x + width - titleSize.x) * 0.5f);
    titleX = std::max(titleX, menusEnd + 16.f);
    dl->PushClipRect(ImVec2(menusEnd, top), ImVec2(captionStart - 8.f, bottom), true);
    dl->AddText(ImVec2(titleX, std::floor(top + (height_ - titleSize.y) * 0.5f)), kTitle, title_.c_str());
    dl->PopClipRect();

    ImGui::SetCursorScreenPos(ImVec2(minRect.left, minRect.top));
    bool minClicked = ImGui::InvisibleButton("##minimize", ImVec2(kButtonWidth, height_));
    bool minHover = !overMax && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
    if (ImGui::IsItemActive()) drawCaptionBackground(dl, minRect, kPressed);
    else if (minHover) drawCaptionBackground(dl, minRect, kHover);
    drawGlyph(dl, minRect, Glyph::Minimize, kGlyph);

    if (frame_.maximizePressed()) drawCaptionBackground(dl, maxRect, kPressed);
    else if (overMax) drawCaptionBackground(dl, maxRect, kHover);
    drawGlyph(dl, maxRect, maximized ? Glyph::Restore : Glyph::Maximize, kGlyph);

    ImGui::SetCursorScreenPos(ImVec2(closeRect.left, closeRect.top));
    bool closeClicked = ImGui::InvisibleButton("##close", ImVec2(kButtonWidth, height_));
    bool closeHover = !overMax && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
    if (ImGui::IsItemActive()) drawCaptionBackground(dl, closeRect, kClosePressed);
    else if (closeHover) drawCaptionBackground(dl, closeRect, kCloseHover);
    drawGlyph(dl, closeRect, Glyph::Close, closeHover || ImGui::IsItemActive() ? IM_COL32(255, 255, 255, 255) : kGlyph);

    dl->AddLine(ImVec2(origin.x, bottom - 1.f), ImVec2(origin.x + width, bottom - 1.f), kBorder);

    if (openMenu_ >= 0) {
        const Menu& menu = menus_[(size_t)openMenu_];
        ImGui::SetNextWindowPos(ImVec2(menuRects[(size_t)openMenu_].left, bottom));
        if (ImGui::BeginPopup(menu.popupId.c_str(), ImGuiWindowFlags_NoMove)) {
            menu.contents();
            ImGui::EndPopup();
        }
    }

    frame_.updateLayout(layout);
    ImGui::End();

    if (minClicked) frame_.minimize();
    if (closeClicked) {
        // Same path as Alt+F4 / the system menu: the application decides
        // (after the unsaved-changes prompt) whether the window closes.
        if (closeHandler_) closeHandler_();
        else frame_.close();
    }
}
