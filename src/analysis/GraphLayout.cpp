#include "analysis/GraphLayout.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <utility>

namespace graphlayout {
namespace {

constexpr int kDummy = -1;
constexpr int kSweeps = 6;
constexpr int kPlacementPasses = 8;

// A vertex of the layered graph: a real node, or a dummy on a long edge.
struct Vertex {
    int node = kDummy;
    int layer = 0;
    float x = 0;  // centre
    float width = 0;
    int order = 0;
    std::vector<int> up, down;  // neighbouring vertices
};

// Marks the edges closing a DFS cycle. Iterative: a method can have thousands of blocks.
void markBackEdges(int n, std::vector<Edge>& edges, const std::vector<std::vector<int>>& out) {
    enum : char { White, Grey, Black };
    std::vector<char> colour((size_t)n, White);
    struct Frame {
        int node;
        size_t next;
    };
    std::vector<Frame> stack;
    for (int root = 0; root < n; ++root) {
        if (colour[(size_t)root] != White) continue;
        colour[(size_t)root] = Grey;
        stack.push_back({root, 0});
        while (!stack.empty()) {
            Frame& f = stack.back();
            const auto& list = out[(size_t)f.node];
            if (f.next >= list.size()) {
                colour[(size_t)f.node] = Black;
                stack.pop_back();
                continue;
            }
            Edge& e = edges[(size_t)list[f.next++]];
            if (colour[(size_t)e.to] == Grey) {
                e.back = true;
            } else if (colour[(size_t)e.to] == White) {
                colour[(size_t)e.to] = Grey;
                stack.push_back({e.to, 0});
            }
        }
    }
}

float mean(const std::vector<int>& neighbours, const std::vector<Vertex>& v, bool useOrder, float fallback) {
    if (neighbours.empty()) return fallback;
    float sum = 0;
    for (int n : neighbours) sum += useOrder ? (float)v[(size_t)n].order : v[(size_t)n].x;
    return sum / (float)neighbours.size();
}

}  // namespace

// Left-to-right is the top-down layout of the transposed graph.
static void transpose(std::vector<Node>& nodes, std::vector<Edge>& edges) {
    for (Node& node : nodes) {
        std::swap(node.w, node.h);
        std::swap(node.x, node.y);
    }
    for (Edge& e : edges)
        for (Point& p : e.points) std::swap(p.x, p.y);
}

Size layout(std::vector<Node>& nodes, std::vector<Edge>& edges, const Options& o) {
    if (o.leftToRight) {
        Options topDown = o;
        topDown.leftToRight = false;
        std::swap(topDown.gapX, topDown.gapY);
        transpose(nodes, edges);
        const Size size = layout(nodes, edges, topDown);
        transpose(nodes, edges);
        return {size.height, size.width};
    }
    const int n = (int)nodes.size();
    Size size;
    if (n == 0) return size;
    std::vector<std::vector<int>> out((size_t)n);
    for (size_t i = 0; i < edges.size(); ++i) {
        Edge& e = edges[i];
        e.back = false;
        e.points.clear();
        if (e.from >= 0 && e.from < n && e.to >= 0 && e.to < n) out[(size_t)e.from].push_back((int)i);
    }
    markBackEdges(n, edges, out);

    // Longest-path layering over the forward edges (Kahn order; self loops never count).
    std::vector<int> pending((size_t)n, 0);
    const auto forward = [&](const Edge& e) {
        return !e.back && e.from != e.to && e.from >= 0 && e.from < n && e.to >= 0 && e.to < n;
    };
    for (const Edge& e : edges)
        if (forward(e)) ++pending[(size_t)e.to];
    std::vector<int> ready;
    for (int i = 0; i < n; ++i)
        if (pending[(size_t)i] == 0) ready.push_back(i);
    for (size_t i = 0; i < ready.size(); ++i) {
        const int u = ready[i];
        for (int ei : out[(size_t)u]) {
            const Edge& e = edges[(size_t)ei];
            if (!forward(e)) continue;
            nodes[(size_t)e.to].layer = std::max(nodes[(size_t)e.to].layer, nodes[(size_t)u].layer + 1);
            if (--pending[(size_t)e.to] == 0) ready.push_back(e.to);
        }
    }

    // Vertices: real nodes first, then one dummy per layer crossed by a long edge.
    std::vector<Vertex> v((size_t)n);
    int layers = 0;
    for (int i = 0; i < n; ++i) {
        v[(size_t)i].node = i;
        v[(size_t)i].layer = nodes[(size_t)i].layer;
        v[(size_t)i].width = nodes[(size_t)i].w;
        layers = std::max(layers, nodes[(size_t)i].layer + 1);
    }
    std::vector<std::vector<int>> chain(edges.size());  // vertices an edge passes through, top to bottom
    for (size_t i = 0; i < edges.size(); ++i) {
        const Edge& e = edges[i];
        if (e.from < 0 || e.from >= n || e.to < 0 || e.to >= n || e.from == e.to) continue;
        const int top = e.back ? e.to : e.from, bottom = e.back ? e.from : e.to;
        int previous = top;
        chain[i].push_back(top);
        for (int layer = v[(size_t)top].layer + 1; layer < v[(size_t)bottom].layer; ++layer) {
            Vertex d;
            d.layer = layer;
            d.width = 2.f;
            v.push_back(d);
            const int id = (int)v.size() - 1;
            v[(size_t)previous].down.push_back(id);
            v.back().up.push_back(previous);
            chain[i].push_back(id);
            previous = id;
        }
        v[(size_t)previous].down.push_back(bottom);
        v[(size_t)bottom].up.push_back(previous);
        chain[i].push_back(bottom);
    }

    // Crossing reduction: order each layer by the barycenter of the layer next to it.
    std::vector<std::vector<int>> byLayer((size_t)layers);
    for (int i = 0; i < (int)v.size(); ++i) byLayer[(size_t)v[(size_t)i].layer].push_back(i);
    const auto renumber = [&](std::vector<int>& row) {
        for (int k = 0; k < (int)row.size(); ++k) v[(size_t)row[(size_t)k]].order = k;
    };
    for (auto& row : byLayer) renumber(row);
    std::vector<float> weight(v.size(), 0.f);
    for (int sweep = 0; sweep < kSweeps; ++sweep) {
        const bool downward = sweep % 2 == 0;
        for (int l = downward ? 1 : layers - 2; downward ? l < layers : l >= 0; l += downward ? 1 : -1) {
            auto& row = byLayer[(size_t)l];
            for (int id : row) {
                const Vertex& x = v[(size_t)id];
                weight[(size_t)id] = mean(downward ? x.up : x.down, v, true, (float)x.order);
            }
            std::stable_sort(row.begin(), row.end(), [&](int a, int b) { return weight[(size_t)a] < weight[(size_t)b]; });
            renumber(row);
        }
    }

    // Horizontal placement: start packed, then pull each vertex to its neighbours
    // while keeping the order and the minimum gap.
    for (auto& row : byLayer) {
        float x = 0;
        for (int id : row) {
            Vertex& a = v[(size_t)id];
            a.x = x + a.width * 0.5f;
            x += a.width + o.gapX;
        }
    }
    const float dummyGap = o.gapX * 0.4f;
    const auto spacing = [&](const Vertex& a, const Vertex& b) {
        const float gap = a.node == kDummy || b.node == kDummy ? dummyGap : o.gapX;
        return (a.width + b.width) * 0.5f + gap;
    };
    std::vector<float> wanted(v.size(), 0.f);
    for (int pass = 0; pass < kPlacementPasses; ++pass) {
        const bool downward = pass % 2 == 0;
        for (int l = downward ? 0 : layers - 1; downward ? l < layers : l >= 0; l += downward ? 1 : -1) {
            auto& row = byLayer[(size_t)l];
            for (int id : row) {
                const Vertex& a = v[(size_t)id];
                const auto& preferred = downward ? a.up : a.down;
                wanted[(size_t)id] = mean(preferred.empty() ? (downward ? a.down : a.up) : preferred, v, false, a.x);
            }
            // Left-to-right and right-to-left clamps; the average keeps the row balanced.
            std::vector<float> left(row.size()), right(row.size());
            for (size_t k = 0; k < row.size(); ++k) {
                left[k] = wanted[(size_t)row[k]];
                if (k) left[k] = std::max(left[k], left[k - 1] + spacing(v[(size_t)row[k - 1]], v[(size_t)row[k]]));
            }
            for (size_t k = row.size(); k-- > 0;) {
                right[k] = wanted[(size_t)row[k]];
                if (k + 1 < row.size())
                    right[k] = std::min(right[k], right[k + 1] - spacing(v[(size_t)row[k]], v[(size_t)row[k + 1]]));
            }
            for (size_t k = 0; k < row.size(); ++k) v[(size_t)row[k]].x = (left[k] + right[k]) * 0.5f;
            for (size_t k = 1; k < row.size(); ++k) {
                const float minX = v[(size_t)row[k - 1]].x + spacing(v[(size_t)row[k - 1]], v[(size_t)row[k]]);
                v[(size_t)row[k]].x = std::max(v[(size_t)row[k]].x, minX);
            }
        }
    }

    // Vertical placement and the graph's extent.
    float minX = 0, maxX = 0;
    bool any = false;
    for (const Vertex& a : v) {
        minX = any ? std::min(minX, a.x - a.width * 0.5f) : a.x - a.width * 0.5f;
        maxX = any ? std::max(maxX, a.x + a.width * 0.5f) : a.x + a.width * 0.5f;
        any = true;
    }
    std::vector<float> layerY((size_t)layers + 1, o.margin), layerH((size_t)layers, 0.f);
    for (const Node& node : nodes) layerH[(size_t)node.layer] = std::max(layerH[(size_t)node.layer], node.h);
    for (int l = 0; l < layers; ++l) layerY[(size_t)l + 1] = layerY[(size_t)l] + layerH[(size_t)l] + o.gapY;
    const float shift = o.margin - minX;
    for (Vertex& a : v) a.x += shift;
    for (int i = 0; i < n; ++i) {
        nodes[(size_t)i].x = v[(size_t)i].x - nodes[(size_t)i].w * 0.5f;
        nodes[(size_t)i].y = layerY[(size_t)nodes[(size_t)i].layer];
    }
    const float graphRight = maxX + shift;

    // Edge routing. Ports are spread along the node sides; each gap between layers
    // gets its own horizontal tracks so parallel edges stay apart.
    std::vector<int> outCount((size_t)n, 0), inCount((size_t)n, 0), outUsed((size_t)n, 0), inUsed((size_t)n, 0);
    for (size_t i = 0; i < edges.size(); ++i) {
        if (chain[i].empty()) continue;
        ++outCount[(size_t)edges[i].from];
        ++inCount[(size_t)edges[i].to];
    }
    std::vector<int> track((size_t)layers + 1, 0);
    const auto port = [](const Node& node, int index, int count) {
        return node.x + node.w * (float)(index + 1) / (float)(count + 1);
    };
    const auto trackY = [&](int layer) {  // in the gap below `layer`
        const int t = track[(size_t)layer]++ % 5;
        const float base = layerY[(size_t)layer] + layerH[(size_t)layer];
        return base + o.gapY * (0.25f + 0.125f * (float)t);
    };
    int sideLane = 0;
    for (size_t i = 0; i < edges.size(); ++i) {
        Edge& e = edges[i];
        if (e.from < 0 || e.from >= n || e.to < 0 || e.to >= n) continue;
        const Node& a = nodes[(size_t)e.from];
        const Node& b = nodes[(size_t)e.to];
        if (e.from == e.to) {  // self loop: out of the right side, back into it
            const float right = a.x + a.w + o.gapX * 0.4f;
            e.points = {{a.x + a.w, a.y + a.h * 0.7f}, {right, a.y + a.h * 0.7f}, {right, a.y + a.h * 0.3f}, {a.x + a.w, a.y + a.h * 0.3f}};
            e.back = true;
            continue;
        }
        const Point start{port(a, outUsed[(size_t)e.from]++, outCount[(size_t)e.from]), a.y + a.h};
        const Point end{port(b, inUsed[(size_t)e.to]++, inCount[(size_t)e.to]), b.y};
        if (e.back) {
            // Around the right side of the graph, so a loop never crosses the blocks.
            const float lane = graphRight + o.gapX * 0.5f + 8.f * (float)(sideLane++ % 12);
            const float below = trackY(a.layer), above = b.layer > 0 ? trackY(b.layer - 1) : b.y - o.gapY * 0.4f;
            e.points = {start, {start.x, below}, {lane, below}, {lane, above}, {end.x, above}, end};
            size.width = std::max(size.width, lane + o.margin);
            continue;
        }
        e.points.push_back(start);
        float x = start.x;
        const auto& path = chain[i];
        for (size_t k = 1; k < path.size(); ++k) {
            const bool last = k + 1 == path.size();
            const float nextX = last ? end.x : v[(size_t)path[k]].x;
            const int layer = v[(size_t)path[k - 1]].layer;
            const float y = trackY(layer);
            e.points.push_back({x, y});
            e.points.push_back({nextX, y});
            if (!last) {
                const float bottom = layerY[(size_t)layer + 1] + layerH[(size_t)layer + 1];
                e.points.push_back({nextX, bottom});
            }
            x = nextX;
        }
        e.points.push_back(end);
    }
    size.width = std::max(size.width, graphRight + o.margin);
    size.height = layerY[(size_t)layers] - o.gapY + o.margin;
    return size;
}

}  // namespace graphlayout
