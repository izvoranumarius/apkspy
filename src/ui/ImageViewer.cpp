#include "ui/ImageViewer.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>

namespace {
constexpr float kMinZoom = 0.02f;
constexpr float kMaxZoom = 64.f;
constexpr float kMaxFit = 8.f;
constexpr float kTile = 12.f;
}

std::string ImageViewer::formatSize(size_t bytes) {
    char buf[32];
    if (bytes >= 1024 * 1024) std::snprintf(buf, sizeof buf, "%.2f MB", bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024) std::snprintf(buf, sizeof buf, "%.1f KB", bytes / 1024.0);
    else std::snprintf(buf, sizeof buf, "%u B", (unsigned)bytes);
    return buf;
}

float ImageViewer::fitScale(const Texture& tex, ImVec2 view) {
    if (view.x < 8.f || view.y < 8.f) return 1.f;
    float s = std::min((view.x - 2.f) / (float)tex.width(), (view.y - 2.f) / (float)tex.height());
    return std::clamp(s, kMinZoom, kMaxFit);
}

void ImageViewer::drawToolbar(Document& doc) {
    ImageView& v = doc.imageView();
    if (ImGui::Button("Fit")) v.fit = true;
    ImGui::SameLine();
    if (ImGui::Button("100%")) {
        v.fit = false;
        v.zoom = 1.f;
    }
    ImGui::SameLine();
    if (ImGui::Button("-")) {
        v.fit = false;
        v.zoom = std::clamp(v.lastScale / 1.25f, kMinZoom, kMaxZoom);
    }
    ImGui::SameLine();
    if (ImGui::Button("+")) {
        v.fit = false;
        v.zoom = std::clamp(v.lastScale * 1.25f, kMinZoom, kMaxZoom);
    }
    ImGui::SameLine();
    ImGui::Text("%.0f%%", v.lastScale * 100.f);
    ImGui::SameLine();
    ImGui::Checkbox("Checkerboard", &v.checker);
    ImGui::SameLine();
    ImGui::Checkbox("Hex", &v.showHex);
    ImGui::SameLine();
    const Texture* tex = doc.texture();
    ImGui::TextDisabled("%s   %d x %d   %s", doc.imageFormat().c_str(), tex->width(), tex->height(),
                        formatSize(doc.bytes().size()).c_str());
}

void ImageViewer::drawChecker(ImDrawList* dl, ImVec2 min, ImVec2 max) {
    ImVec2 clipMin = dl->GetClipRectMin();
    ImVec2 clipMax = dl->GetClipRectMax();
    ImVec2 a(std::max(min.x, clipMin.x), std::max(min.y, clipMin.y));
    ImVec2 b(std::min(max.x, clipMax.x), std::min(max.y, clipMax.y));
    if (a.x >= b.x || a.y >= b.y) return;
    dl->AddRectFilled(a, b, IM_COL32(70, 70, 70, 255));
    int ix0 = (int)std::floor((a.x - min.x) / kTile);
    int iy0 = (int)std::floor((a.y - min.y) / kTile);
    for (int iy = iy0;; ++iy) {
        float y0 = min.y + iy * kTile;
        if (y0 >= b.y) break;
        for (int ix = ix0;; ++ix) {
            float x0 = min.x + ix * kTile;
            if (x0 >= b.x) break;
            if (((ix + iy) & 1) == 0) continue;
            ImVec2 p0(std::max(x0, a.x), std::max(y0, a.y));
            ImVec2 p1(std::min(x0 + kTile, b.x), std::min(y0 + kTile, b.y));
            dl->AddRectFilled(p0, p1, IM_COL32(100, 100, 100, 255));
        }
    }
}

void ImageViewer::drawCanvas(Document& doc) {
    ImageView& v = doc.imageView();
    Texture& tex = *doc.texture();
    const float footer = ImGui::GetFrameHeightWithSpacing();

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::BeginChild("##canvas", ImVec2(0.f, -footer), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PopStyleVar();

    ImVec2 view = ImGui::GetContentRegionAvail();
    float scale = v.fit ? fitScale(tex, view) : v.zoom;
    v.lastScale = scale;
    tex.setNearest(scale >= 2.f);

    ImVec2 size((float)tex.width() * scale, (float)tex.height() * scale);
    ImVec2 offset(std::max(0.f, (view.x - size.x) * 0.5f), std::max(0.f, (view.y - size.y) * 0.5f));

    if (v.hasPendingScroll) {
        ImGui::SetScrollX(v.pendingScroll.x);
        ImGui::SetScrollY(v.pendingScroll.y);
        v.hasPendingScroll = false;
    }

    ImGui::SetCursorPos(offset);
    ImVec2 origin = ImGui::GetCursorScreenPos();
    if (v.checker) drawChecker(ImGui::GetWindowDrawList(), origin, ImVec2(origin.x + size.x, origin.y + size.y));
    ImGui::Image((ImTextureID)(intptr_t)tex.id(), size);

    ImGuiIO& io = ImGui::GetIO();
    int px = -1, py = -1;
    if (ImGui::IsItemHovered()) {
        px = (int)std::floor((io.MousePos.x - origin.x) / scale);
        py = (int)std::floor((io.MousePos.y - origin.y) / scale);
    }

    bool hovered = ImGui::IsWindowHovered();
    if (hovered && io.KeyCtrl && io.MouseWheel != 0.f) {
        float newScale = std::clamp(scale * std::pow(1.15f, io.MouseWheel), kMinZoom, kMaxZoom);
        ImVec2 winPos = ImGui::GetWindowPos();
        ImVec2 m(io.MousePos.x - winPos.x, io.MousePos.y - winPos.y);
        ImVec2 point((m.x + ImGui::GetScrollX() - offset.x) / scale, (m.y + ImGui::GetScrollY() - offset.y) / scale);
        ImVec2 newSize((float)tex.width() * newScale, (float)tex.height() * newScale);
        ImVec2 newOffset(std::max(0.f, (view.x - newSize.x) * 0.5f), std::max(0.f, (view.y - newSize.y) * 0.5f));
        v.pendingScroll = ImVec2(std::max(0.f, point.x * newScale + newOffset.x - m.x),
                                 std::max(0.f, point.y * newScale + newOffset.y - m.y));
        v.hasPendingScroll = true;
        v.fit = false;
        v.zoom = newScale;
    }
    if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        ImGui::SetScrollX(ImGui::GetScrollX() - io.MouseDelta.x);
        ImGui::SetScrollY(ImGui::GetScrollY() - io.MouseDelta.y);
    }
    ImGui::EndChild();

    if (px >= 0 && py >= 0 && px < tex.width() && py < tex.height())
        ImGui::TextDisabled("x: %d   y: %d", px, py);
    else
        ImGui::TextDisabled("Ctrl + mouse wheel to zoom, drag to pan");
}
