#pragma once
#include <cstdint>
#include <vector>

// Layered layout for control-flow and call graphs (Sugiyama style): back edges
// are found by DFS, nodes are assigned to layers by longest path, long edges
// get dummy nodes, crossings are reduced by barycenter sweeps and x positions
// are relaxed towards the neighbours. Edges come out as orthogonal polylines.
// Pure geometry: no UI dependency, sizes are whatever the caller measured.
namespace graphlayout {

struct Point {
    float x = 0, y = 0;
};

struct Node {
    float w = 0, h = 0;  // in: size
    float x = 0, y = 0;  // out: top-left corner
    int layer = 0;       // out
};

enum class EdgeKind : uint8_t { Jump, Taken, Fallthrough, Exception, Call };

struct Edge {
    int from = 0, to = 0;
    EdgeKind kind = EdgeKind::Jump;
    std::vector<Point> points;  // out
    bool back = false;          // out: points upward
};

struct Size {
    float width = 0, height = 0;
};

struct Options {
    float gapX = 36.f;
    float gapY = 54.f;
    float margin = 24.f;
    bool leftToRight = false;  // layers as columns: reads better for fan-outs like call graphs
};

// Node 0 is treated as the entry. Edges with out-of-range ends are ignored.
Size layout(std::vector<Node>& nodes, std::vector<Edge>& edges, const Options& options = {});

}  // namespace graphlayout
