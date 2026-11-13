#pragma once
#include <string>
#include <vector>
#include "analysis/GraphLayout.hpp"
#include "app/Theme.hpp"
#include "imgui.h"

// Interactive block graph shared by the bytecode and native views: drag to pan,
// wheel to zoom around the cursor, F to fit, a minimap for large graphs. Edges
// of the selected block are highlighted. Knows nothing about what it shows: the
// caller maps a block / line back to its own data through the draw() result.
class GraphView {
public:
    // A theme token (resolved at draw time, so a built graph follows theme
    // changes) or a fixed RGBA colour.
    struct Paint {
        Paint(Col c) : token(c) {}
        Paint(ImU32 c) : rgba(c), fixed(true) {}
        ImU32 resolve() const { return fixed ? rgba : theme::u32(token); }
        Col token = Col::Text;
        ImU32 rgba = 0;
        bool fixed = false;
    };
    struct Span {
        std::string text;
        Paint color = Col::Text;
    };
    using Line = std::vector<Span>;
    struct Block {
        std::vector<Line> lines;
        Paint border = Col::GraphNodeBorder;
        Paint fill = Col::GraphNode;
    };
    struct Result {
        int block = -1;          // block under the cursor when something happened
        int line = -1;           // line of that block
        bool activated = false;  // double-clicked
    };

    void set(std::vector<Block> blocks, std::vector<graphlayout::Edge> edges, bool leftToRight = false);
    void clear();
    bool empty() const { return blocks_.empty(); }
    size_t size() const { return blocks_.size(); }
    // Brings a block into view (after set(): applied on the next draw).
    void focusBlock(int block);

    // Fills the remaining space of the current window. `font` draws the block text.
    Result draw(const char* id, ImFont* font);

private:
    void ensureLayout(ImFont* font);
    void fit(ImVec2 canvas);
    void center(int block, ImVec2 canvas, bool top);

    std::vector<Block> blocks_;
    std::vector<graphlayout::Node> nodes_;
    std::vector<graphlayout::Edge> edges_;
    graphlayout::Size extent_;
    bool leftToRight_ = false;
    float layoutFontSize_ = 0.f;
    float lineHeight_ = 0.f;
    float zoom_ = 1.f;
    ImVec2 pan_{0.f, 0.f};  // graph position at the canvas's top-left corner
    bool wantInitialView_ = false;
    bool wantFit_ = false;
    int focusRequest_ = -1;
    int selected_ = -1;
    bool draggingMinimap_ = false;
};
