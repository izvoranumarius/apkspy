#include "ui/GraphView.hpp"
#include "app/Theme.hpp"
#include "ui/UiUtil.hpp"
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdio>

namespace {

using graphlayout::EdgeKind;

constexpr float kMinZoom = 0.08f;
constexpr float kMaxZoom = 2.5f;
constexpr float kTextZoom = 0.32f;  // below this a block shows bars instead of text
constexpr float kPadding = 7.f;

ImU32 edgeColor(EdgeKind kind) {
    switch (kind) {
    case EdgeKind::Taken: return theme::u32(Col::Green);
    case EdgeKind::Fallthrough: return theme::u32(Col::Red);
    case EdgeKind::Exception: return theme::u32(Col::Orange, 0.9f);
    case EdgeKind::Call: return theme::u32(Col::TextMuted);
    default: return theme::u32(Col::Blue);
    }
}

ImU32 withAlpha(ImU32 color, int alpha) { return (color & ~IM_COL32_A_MASK) | (static_cast<ImU32>(alpha) << IM_COL32_A_SHIFT); }

void dashed(ImDrawList* dl, ImVec2 a, ImVec2 b, ImU32 color, float thickness) {
    const float length = std::hypot(b.x - a.x, b.y - a.y);
    const int segments = std::max(1, static_cast<int>(length / 12.f));
    for (int i = 0; i < segments; ++i) {
        const float t0 = static_cast<float>(i) / static_cast<float>(segments), t1 = (static_cast<float>(i) + 0.55f) / static_cast<float>(segments);
        dl->AddLine(ImVec2(a.x + (b.x - a.x) * t0, a.y + (b.y - a.y) * t0),
                    ImVec2(a.x + (b.x - a.x) * t1, a.y + (b.y - a.y) * t1), color, thickness);
    }
}

}  // namespace

void GraphView::set(std::vector<Block> blocks, std::vector<graphlayout::Edge> edges, bool leftToRight) {
    leftToRight_ = leftToRight;
    blocks_ = std::move(blocks);
    edges_ = std::move(edges);
    nodes_.clear();
    layoutFontSize_ = 0.f;
    selected_ = -1;
    focusRequest_ = -1;
    wantInitialView_ = true;
    draggingMinimap_ = false;
}

void GraphView::clear() { set({}, {}); }

void GraphView::focusBlock(int block) {
    focusRequest_ = block;
    selected_ = block;
}

void GraphView::ensureLayout(ImFont* font) {
    const float size = ImGui::GetFontSize();
    if (layoutFontSize_ == size && nodes_.size() == blocks_.size()) return;
    layoutFontSize_ = size;
    lineHeight_ = size * 1.15f;
    nodes_.assign(blocks_.size(), {});
    for (size_t i = 0; i < blocks_.size(); ++i) {
        float width = size * 5.f;
        for (const Line& line : blocks_[i].lines) {
            float w = 0;
            for (const Span& span : line) w += font->CalcTextSizeA(size, FLT_MAX, 0.f, span.text.c_str()).x;
            width = std::max(width, w);
        }
        nodes_[i].w = width + kPadding * 2.f;
        nodes_[i].h = lineHeight_ * static_cast<float>(std::max<size_t>(blocks_[i].lines.size(), 1)) + kPadding * 2.f;
    }
    graphlayout::Options options;
    options.gapX = leftToRight_ ? size * 5.f : size * 2.2f;
    options.gapY = leftToRight_ ? size * 0.8f : size * 3.2f;
    options.leftToRight = leftToRight_;
    extent_ = graphlayout::layout(nodes_, edges_, options);
}

void GraphView::fit(ImVec2 canvas) {
    if (extent_.width <= 0.f || extent_.height <= 0.f) return;
    zoom_ = std::clamp(std::min(canvas.x / extent_.width, canvas.y / extent_.height), kMinZoom, 1.f);
    pan_ = ImVec2((extent_.width - canvas.x / zoom_) * 0.5f, (extent_.height - canvas.y / zoom_) * 0.5f);
}

void GraphView::center(int block, ImVec2 canvas, bool top) {
    if (block < 0 || block >= static_cast<int>(nodes_.size())) return;
    const auto& n = nodes_[static_cast<size_t>(block)];
    pan_.x = n.x + n.w * 0.5f - canvas.x * 0.5f / zoom_;
    pan_.y = top ? n.y - ImGui::GetFontSize() * 1.5f : n.y + n.h * 0.5f - canvas.y * 0.5f / zoom_;
}

GraphView::Result GraphView::draw(const char* id, ImFont* font) {
    Result result;
    ImGui::PushID(id);
    ensureLayout(font);
    ImGui::BeginChild("##canvas", ImVec2(0, 0), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMove);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 canvas(std::max(ImGui::GetContentRegionAvail().x, 1.f), std::max(ImGui::GetContentRegionAvail().y, 1.f));
    ImGui::SetNextItemAllowOverlap();  // the Fit / 100% buttons sit on top
    ImGui::InvisibleButton("##surface", canvas,
                           ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonMiddle | ImGuiButtonFlags_MouseButtonRight);
    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();
    ImGuiIO& io = ImGui::GetIO();

    if (wantInitialView_) {
        // Small graphs fit; a large one opens on its entry block, readable.
        wantInitialView_ = false;
        fit(canvas);
        if (zoom_ < 0.55f) {
            zoom_ = 0.8f;
            center(0, canvas, true);
        }
    }
    if (wantFit_ || (ImGui::IsWindowFocused() && !io.WantTextInput && ImGui::IsKeyPressed(ImGuiKey_F, false))) {
        wantFit_ = false;
        fit(canvas);
    }
    if (focusRequest_ >= 0) {
        center(focusRequest_, canvas, false);
        focusRequest_ = -1;
    }
    const auto toGraph = [&](ImVec2 s) { return ImVec2(pan_.x + (s.x - origin.x) / zoom_, pan_.y + (s.y - origin.y) / zoom_); };
    const auto toScreen = [&](float x, float y) { return ImVec2(origin.x + (x - pan_.x) * zoom_, origin.y + (y - pan_.y) * zoom_); };

    if (hovered && io.MouseWheel != 0.f && !io.KeyCtrl) {
        const ImVec2 anchor = toGraph(io.MousePos);
        zoom_ = std::clamp(zoom_ * std::pow(1.15f, io.MouseWheel), kMinZoom, kMaxZoom);
        pan_ = ImVec2(anchor.x - (io.MousePos.x - origin.x) / zoom_, anchor.y - (io.MousePos.y - origin.y) / zoom_);
    }

    // Minimap: only when part of the graph is off-screen.
    const bool partial = extent_.width * zoom_ > canvas.x || extent_.height * zoom_ > canvas.y;
    const float mapMax = std::min(ImGui::GetFontSize() * 9.f, std::min(canvas.x, canvas.y) * 0.4f);
    const float mapScale = extent_.width > 0.f ? std::min(mapMax / extent_.width, mapMax / extent_.height) : 1.f;
    const ImVec2 mapSize(extent_.width * mapScale, extent_.height * mapScale);
    const ImVec2 mapMin(origin.x + canvas.x - mapSize.x - 8.f, origin.y + canvas.y - mapSize.y - 8.f);
    const bool onMap = partial && io.MousePos.x >= mapMin.x && io.MousePos.y >= mapMin.y &&
                       io.MousePos.x <= mapMin.x + mapSize.x && io.MousePos.y <= mapMin.y + mapSize.y;
    if (hovered && onMap && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) draggingMinimap_ = true;
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) draggingMinimap_ = false;
    if (draggingMinimap_) {
        pan_.x = (io.MousePos.x - mapMin.x) / mapScale - canvas.x * 0.5f / zoom_;
        pan_.y = (io.MousePos.y - mapMin.y) / mapScale - canvas.y * 0.5f / zoom_;
    } else if (active && (ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.f) || ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.f) ||
                          ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.f))) {
        pan_.x -= io.MouseDelta.x / zoom_;
        pan_.y -= io.MouseDelta.y / zoom_;
    }

    // Hit test.
    const ImVec2 mouseGraph = toGraph(io.MousePos);
    int hoveredBlock = -1;
    if (hovered && !onMap)
        for (int i = 0; i < static_cast<int>(nodes_.size()); ++i) {
            const auto& n = nodes_[static_cast<size_t>(i)];
            if (mouseGraph.x >= n.x && mouseGraph.x <= n.x + n.w && mouseGraph.y >= n.y && mouseGraph.y <= n.y + n.h) hoveredBlock = i;
        }
    if (hoveredBlock >= 0) {
        result.block = hoveredBlock;
        result.line = static_cast<int>((mouseGraph.y - nodes_[static_cast<size_t>(hoveredBlock)].y - kPadding) / lineHeight_);
    }
    if (hovered && !onMap && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) selected_ = hoveredBlock;
    if (hoveredBlock >= 0 && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) result.activated = true;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(origin, ImVec2(origin.x + canvas.x, origin.y + canvas.y), true);
    const float thickness = std::max(1.f, 1.5f * zoom_);
    for (int pass = 0; pass < 2; ++pass)  // edges of the selected block go on top
        for (const auto& e : edges_) {
            const bool emphasised = selected_ >= 0 && (e.from == selected_ || e.to == selected_);
            if (emphasised != (pass == 1) || e.points.size() < 2) continue;
            ImU32 color = edgeColor(e.kind);
            if (selected_ >= 0 && !emphasised) color = withAlpha(color, 90);
            const float width = emphasised ? thickness * 1.8f : thickness;
            ImVec2 previous = toScreen(e.points[0].x, e.points[0].y);
            for (size_t i = 1; i < e.points.size(); ++i) {
                const ImVec2 next = toScreen(e.points[i].x, e.points[i].y);
                if (e.kind == EdgeKind::Exception) dashed(dl, previous, next, color, width);
                else dl->AddLine(previous, next, color, width);
                previous = next;
            }
            const float head = std::max(3.5f, 6.f * zoom_);
            const ImVec2 before = toScreen(e.points[e.points.size() - 2].x, e.points[e.points.size() - 2].y);
            float dx = previous.x - before.x, dy = previous.y - before.y;
            const float length = std::max(std::hypot(dx, dy), 0.001f);
            dx /= length, dy /= length;
            dl->AddTriangleFilled(previous, ImVec2(previous.x - dx * head * 1.5f - dy * head, previous.y - dy * head * 1.5f + dx * head),
                                  ImVec2(previous.x - dx * head * 1.5f + dy * head, previous.y - dy * head * 1.5f - dx * head), color);
        }

    const float fontSize = ImGui::GetFontSize() * zoom_;
    for (int i = 0; i < static_cast<int>(nodes_.size()); ++i) {
        const auto& n = nodes_[static_cast<size_t>(i)];
        const ImVec2 lo = toScreen(n.x, n.y), hi = toScreen(n.x + n.w, n.y + n.h);
        if (hi.x < origin.x || hi.y < origin.y || lo.x > origin.x + canvas.x || lo.y > origin.y + canvas.y) continue;
        const Block& block = blocks_[static_cast<size_t>(i)];
        dl->AddRectFilled(lo, hi, block.fill.resolve(), 3.f * zoom_);
        const bool selected = i == selected_;
        dl->AddRect(lo, hi, selected ? theme::u32(Col::Accent) : i == hoveredBlock ? theme::u32(Col::TextMuted) : block.border.resolve(),
                    3.f * zoom_, 0, selected ? 2.f : 1.f);
        const float top = lo.y + kPadding * zoom_;
        for (size_t k = 0; k < block.lines.size(); ++k) {
            const float y = top + static_cast<float>(k) * lineHeight_ * zoom_;
            if (y > origin.y + canvas.y || y + lineHeight_ * zoom_ < origin.y) continue;
            float x = lo.x + kPadding * zoom_;
            if (zoom_ < kTextZoom) {  // too small to read: a bar per line keeps the block's shape
                float width = 0;
                for (const Span& span : block.lines[k]) width += font->CalcTextSizeA(fontSize, FLT_MAX, 0.f, span.text.c_str()).x;
                dl->AddRectFilled(ImVec2(x, y), ImVec2(x + width, y + fontSize * 0.55f), theme::u32(Col::TextMuted, 0.6f));
                continue;
            }
            for (const Span& span : block.lines[k]) {
                dl->AddText(font, fontSize, ImVec2(x, y), span.color.resolve(), span.text.c_str());
                x += font->CalcTextSizeA(fontSize, FLT_MAX, 0.f, span.text.c_str()).x;
            }
        }
    }

    if (partial) {
        dl->AddRectFilled(mapMin, ImVec2(mapMin.x + mapSize.x, mapMin.y + mapSize.y), theme::u32(Col::PopupBackground, 0.9f));
        for (const auto& n : nodes_)
            dl->AddRectFilled(ImVec2(mapMin.x + n.x * mapScale, mapMin.y + n.y * mapScale),
                              ImVec2(mapMin.x + (n.x + n.w) * mapScale, mapMin.y + (n.y + n.h) * mapScale), theme::u32(Col::TextMuted, 0.7f));
        const ImVec2 mapEnd(mapMin.x + mapSize.x, mapMin.y + mapSize.y);
        const ImVec2 viewLo(std::clamp(mapMin.x + pan_.x * mapScale, mapMin.x, mapEnd.x), std::clamp(mapMin.y + pan_.y * mapScale, mapMin.y, mapEnd.y));
        const ImVec2 viewHi(std::clamp(mapMin.x + (pan_.x + canvas.x / zoom_) * mapScale, mapMin.x, mapEnd.x),
                            std::clamp(mapMin.y + (pan_.y + canvas.y / zoom_) * mapScale, mapMin.y, mapEnd.y));
        dl->AddRect(mapMin, mapEnd, theme::u32(Col::Border));
        dl->AddRect(viewLo, viewHi, theme::u32(Col::Accent));
    }
    dl->PopClipRect();

    ImGui::SetCursorScreenPos(ImVec2(origin.x + 6.f, origin.y + 6.f));
    if (ui::smallButton("Fit")) fit(canvas);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Fit the graph (F). Drag to pan, wheel to zoom, double-click to follow.");
    ImGui::SameLine(0.f, 3.f);
    char zoomLabel[16];
    std::snprintf(zoomLabel, sizeof zoomLabel, "%d%%", static_cast<int>(std::lround(zoom_ * 100.f)));
    if (ui::smallButton(zoomLabel)) {
        const ImVec2 middle(pan_.x + canvas.x * 0.5f / zoom_, pan_.y + canvas.y * 0.5f / zoom_);
        zoom_ = 1.f;
        pan_ = ImVec2(middle.x - canvas.x * 0.5f, middle.y - canvas.y * 0.5f);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Reset to 100%%");
    ImGui::EndChild();
    ImGui::PopID();
    return result;
}
