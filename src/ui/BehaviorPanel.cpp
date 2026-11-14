#include "ui/BehaviorPanel.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <set>
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "core/ApkInfo.hpp"
#include "ui/UiUtil.hpp"

using BKind = behavior::NodeKind;
using BEdge = behavior::EdgeKind;

namespace {

constexpr size_t kMaxViewNodes = 350;
constexpr int kOverview = 0, kClasses = 1, kMethods = 2;  // granularity_

const char* const kKindLabels[behavior::kNodeKinds] = {"Components", "Classes", "Methods", "Permissions", "Endpoints", "Storage", "Native"};

Col kindColor(BKind k) {
    switch (k) {
    case BKind::Component: return Col::Blue;
    case BKind::Class: return Col::Cyan;
    case BKind::Method: return Col::Text;
    case BKind::Permission: return Col::Orange;
    case BKind::Endpoint: return Col::Green;
    case BKind::Storage: return Col::Purple;
    case BKind::Native: return Col::Pink;
    }
    return Col::Text;
}

// One-letter tag drawn before a node's label.
const char* kindTag(BKind k) {
    switch (k) {
    case BKind::Component: return "C ";
    case BKind::Class: return "c ";
    case BKind::Method: return "m ";
    case BKind::Permission: return "P ";
    case BKind::Endpoint: return "E ";
    case BKind::Storage: return "S ";
    case BKind::Native: return "N ";
    }
    return "";
}

// Lower numbers survive the node cap first.
int priority(BKind k) {
    switch (k) {
    case BKind::Component: return 0;
    case BKind::Permission:
    case BKind::Endpoint:
    case BKind::Storage:
    case BKind::Native: return 1;
    case BKind::Class: return 2;
    case BKind::Method: return 3;
    }
    return 4;
}

graphlayout::EdgeKind layoutKind(BEdge k) {
    switch (k) {
    case BEdge::Entry:
    case BEdge::Calls: return graphlayout::EdgeKind::Call;
    case BEdge::Callback: return graphlayout::EdgeKind::Exception;  // dashed: dispatched by the framework
    case BEdge::Contains: return graphlayout::EdgeKind::Fallthrough;
    default: return graphlayout::EdgeKind::Taken;  // a capability
    }
}

bool containsNoCase(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    const auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
    return it != hay.end();
}

std::string truncate(const std::string& s, size_t n) { return s.size() <= n ? s : s.substr(0, n - 3) + "..."; }

const char* flagReason(const behavior::Node& n) {
    switch (n.kind) {
    case BKind::Component: return "Exported: other apps can start or bind it.";
    case BKind::Permission: return "Used by reached code but not declared in the manifest.";
    case BKind::Endpoint: return "Cleartext: at least one URL uses http:// or ws://.";
    default: return "Flagged.";
    }
}

}  // namespace

BehaviorPanel::~BehaviorPanel() { cancelBuild(); }

void BehaviorPanel::cancelBuild() {
    if (cancel_) cancel_->store(true);
    if (job_.valid()) job_.wait();
    job_ = {};
    cancel_.reset();
}

void BehaviorPanel::startBuild(Root& apk, const std::shared_ptr<const ApkAnalysis>& analysis) {
    cancelBuild();
    built_ = false;
    error_.clear();
    graph_ = {};
    view_.clear();
    selected_ = focus_ = reachOf_ = -1;
    reach_.clear();
    // Manifest and library list are read here: the APK's content source is UI-thread only.
    const ApkInfo info = ApkInfo::extract(apk);
    behavior::Input input;
    input.packageName = info.packageName;
    input.components = info.components;
    input.declaredPermissions = info.permissions;
    input.targetSdk = std::atoi(info.targetSdk.c_str());
    if (!info.ok) error_ = "The manifest could not be decoded: no components to start from.";
    libEntries_.clear();
    if (const TreeNode* lib = apk.tree ? apk.tree->findChild("lib") : nullptr) {
        static constexpr std::string_view kAbiOrder[] = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86", "armeabi"};
        for (std::string_view abi : kAbiOrder)
            for (const auto& dir : lib->children())
                if (dir->name() == abi)
                    for (const auto& so : dir->children())
                        if (!so->isFolder()) libEntries_.push_back(so->path());
    }
    auto cancel = std::make_shared<std::atomic<bool>>(false);
    cancel_ = cancel;
    job_ = std::async(std::launch::async, [analysis, input = std::move(input), cancel] {
        return behavior::build(*analysis, input, behavior::Options{}, cancel.get());
    });
}

void BehaviorPanel::drawContents() {
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.empty()) {
        ImGui::TextDisabled("Open an APK to map its behavior.");
        return;
    }
    if (apkIdx_ >= static_cast<int>(apks.size())) apkIdx_ = 0;
    if (apks.size() > 1) {
        ImGui::SetNextItemWidth(ui::em(16.f));
        if (ImGui::BeginCombo("##apk", apks[static_cast<size_t>(apkIdx_)]->title.c_str())) {
            for (int i = 0; i < static_cast<int>(apks.size()); ++i)
                if (ImGui::Selectable(apks[static_cast<size_t>(i)]->title.c_str(), i == apkIdx_)) apkIdx_ = i;
            ImGui::EndCombo();
        }
    }
    Root& apk = *apks[static_cast<size_t>(apkIdx_)];
    if (apk.title != group_) {
        cancelBuild();
        group_ = apk.title;
        owner_ = nullptr;
        built_ = false;
        graph_ = {};
        view_.clear();
    }
    if (workspace_.analysis().status(apk.title).state == AnalysisService::State::None) workspace_.startAnalysis(apk.title);
    const AnalysisService::Status st = workspace_.analysis().status(apk.title);
    const std::shared_ptr<const ApkAnalysis> analysis = workspace_.analysis().get(apk.title);
    if (!analysis) {
        if (st.state == AnalysisService::State::Running)
            ImGui::TextDisabled("Waiting for the bytecode analysis (%s %zu / %zu)...", st.phase.c_str(), st.done, st.total);
        else if (st.state == AnalysisService::State::Failed)
            ui::wrappedColored(theme::vec(Col::Warning), "The bytecode analysis failed: " + st.error);
        else
            ImGui::TextDisabled("The bytecode analysis is not available.");
        return;
    }
    if (analysis.get() != owner_) {
        owner_ = analysis.get();
        startBuild(apk, analysis);
    }
    if (job_.valid()) {
        if (job_.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
            ImGui::TextDisabled("Mapping components, calls and capabilities...");
            ImGui::SameLine();
            if (ui::smallButton("Cancel")) {
                cancelBuild();
                error_ = "Cancelled.";
            }
            return;
        }
        graph_ = job_.get();
        cancel_.reset();
        built_ = true;
        dirty_ = true;
    }
    if (!built_) {
        if (!error_.empty()) ui::wrappedColored(theme::vec(Col::Warning), error_);
        if (ui::flowButton("Build graph")) {
            owner_ = nullptr;  // rebuilt next frame
        }
        return;
    }

    drawToolbar();
    if (dirty_) project();

    const float detailsWidth = std::min(ui::em(24.f), ImGui::GetContentRegionAvail().x * 0.4f);
    ImGui::BeginChild("##graphArea", ImVec2(ImGui::GetContentRegionAvail().x - detailsWidth - ImGui::GetStyle().ItemSpacing.x, 0));
    if (view_.empty()) {
        ImGui::TextDisabled(graph_.nodes.empty() ? "Nothing to show: no component reaches a permission, endpoint, storage or native code."
                                                 : "No node matches the current filters.");
    } else {
        const GraphView::Result r = view_.draw("##behavior", Theme::monoFont());
        const int viewSel = view_.selected();
        if (viewSel != lastViewSelected_) {
            lastViewSelected_ = viewSel;
            if (viewSel >= 0 && viewSel < static_cast<int>(viewToModel_.size())) selected_ = viewToModel_[static_cast<size_t>(viewSel)];
        }
        if (r.activated && r.block >= 0 && r.block < static_cast<int>(viewToModel_.size())) navigate(viewToModel_[static_cast<size_t>(r.block)]);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##details", ImVec2(0, 0), ImGuiChildFlags_Borders);
    drawDetails();
    ImGui::EndChild();
}

void BehaviorPanel::drawToolbar() {
    for (int k = 0; k < behavior::kNodeKinds; ++k) {
        const auto kind = static_cast<BKind>(k);
        if (granularity_ != kClasses && kind == BKind::Class) continue;  // classes only group methods
        if (granularity_ != kMethods && kind == BKind::Method) continue;
        char label[48];
        std::snprintf(label, sizeof label, "%s (%zu)", kKindLabels[k], graph_.count(kind));
        ImGui::PushStyleColor(ImGuiCol_CheckMark, theme::u32(kindColor(kind)));
        if (ui::flowCheckbox(label, &showKind_[k])) dirty_ = true;
        ImGui::PopStyleColor();
    }
    const char* grains[] = {"Overview", "Classes", "Methods"};
    ui::sameLineIfFits(ui::em(15.f));
    ImGui::PushID("grain");
    if (ui::segmented(grains, 3, granularity_)) dirty_ = true;
    ImGui::PopID();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Overview: each component and everything it can reach.\nClasses / Methods: the code paths in between.");
    if (ui::flowCheckbox("Flagged paths", &flaggedOnly_)) dirty_ = true;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Only what leads to or from flagged nodes: exported components,\nundeclared permissions, cleartext endpoints");
    if (ui::flowCheckbox("Hide unconnected", &hideIsolated_)) dirty_ = true;
    ui::sameLineIfFits(ui::em(18.f));
    ImGui::SetNextItemWidth(ui::em(14.f));
    const bool enter = ImGui::InputTextWithHint("##find", "Find node (Enter: next)", search_, sizeof search_, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter || searchApplied_ != search_) {
        const bool next = enter && searchApplied_ == search_;
        if (searchApplied_ != search_) dirty_ = true;  // repaint matches
        searchApplied_ = search_;
        if (!searchApplied_.empty()) {
            const int n = static_cast<int>(graph_.nodes.size());
            const int start = next ? searchCursor_ + 1 : 0;
            for (int i = 0; i < n; ++i) {
                const int k = (start + i) % n;
                const behavior::Node& node = graph_.nodes[static_cast<size_t>(k)];
                if (containsNoCase(node.label, searchApplied_) || containsNoCase(node.key, searchApplied_)) {
                    searchCursor_ = k;
                    if (enter) select(k, true);
                    break;
                }
            }
        }
    }
    if (focus_ >= 0) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ui::em(7.f));
        if (ImGui::SliderInt("##depth", &focusDepth_, 1, 6, "%d hops")) dirty_ = true;
        ImGui::SameLine();
        if (ui::smallButton("Whole graph")) {
            focus_ = -1;
            dirty_ = true;
        }
    }
    ImGui::SameLine();
    if (ui::smallButton(ui::icon(icons::REFRESH, "Rebuild").c_str())) owner_ = nullptr;
    if (graph_.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Warning), "partial");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("The walk stopped after %zu methods: deep call chains may be missing.", graph_.methodsVisited);
    }
    if (hiddenByCap_) {
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Warning), "%zu nodes hidden", hiddenByCap_);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("The view shows at most %zu nodes. Focus on a node or narrow the filters.", kMaxViewNodes);
    }
}

void BehaviorPanel::project() {
    dirty_ = false;
    const int n = static_cast<int>(graph_.nodes.size());
    owner_of_.assign(static_cast<size_t>(n), -1);
    for (const auto& e : graph_.edges)
        if (e.kind == BEdge::Contains) owner_of_[e.to] = static_cast<int>(e.from);

    // Each model node stands for itself, for its class (class granularity) or for nothing.
    const auto rep = [&](int i) {
        BKind kind = graph_.nodes[static_cast<size_t>(i)].kind;
        if (granularity_ == kOverview && (kind == BKind::Class || kind == BKind::Method)) return -1;
        if (granularity_ == kMethods && kind == BKind::Class) return -1;
        if (granularity_ == kClasses && kind == BKind::Method) {
            i = owner_of_[static_cast<size_t>(i)];
            if (i < 0) return -1;
            kind = graph_.nodes[static_cast<size_t>(i)].kind;
        }
        return showKind_[static_cast<int>(kind)] ? i : -1;
    };
    struct VEdge {
        int from, to;
        BEdge kind;
    };
    std::vector<VEdge> edges;
    std::set<std::pair<int, int>> seen;
    if (granularity_ == kOverview) {
        // Component -> every capability its code reaches, however deep.
        std::vector<std::vector<int>> out(static_cast<size_t>(n));
        for (size_t ei = 0; ei < graph_.edges.size(); ++ei)
            if (graph_.edges[ei].kind != BEdge::Contains) out[graph_.edges[ei].from].push_back(static_cast<int>(ei));
        for (int c = 0; c < n; ++c) {
            if (graph_.nodes[static_cast<size_t>(c)].kind != BKind::Component || rep(c) < 0) continue;
            std::vector<char> seenNode(static_cast<size_t>(n), 0);
            std::deque<int> q = {c};
            seenNode[static_cast<size_t>(c)] = 1;
            while (!q.empty()) {
                const int u = q.front();
                q.pop_front();
                for (int ei : out[static_cast<size_t>(u)]) {
                    const auto& e = graph_.edges[static_cast<size_t>(ei)];
                    const int v = static_cast<int>(e.to);
                    if (seenNode[static_cast<size_t>(v)]) continue;
                    seenNode[static_cast<size_t>(v)] = 1;
                    const BKind vk = graph_.nodes[static_cast<size_t>(v)].kind;
                    if (vk == BKind::Method || vk == BKind::Class) q.push_back(v);
                    else if (rep(v) >= 0 && seen.insert({c, v}).second) edges.push_back({c, v, e.kind});
                }
            }
        }
    } else {
        for (const auto& e : graph_.edges) {
            if (e.kind == BEdge::Contains) continue;
            const int u = rep(static_cast<int>(e.from)), v = rep(static_cast<int>(e.to));
            if (u < 0 || v < 0 || u == v || !seen.insert({u, v}).second) continue;
            edges.push_back({u, v, e.kind});
        }
    }
    std::vector<char> keep(static_cast<size_t>(n), 0);
    for (int i = 0; i < n; ++i) keep[static_cast<size_t>(i)] = rep(i) == i;

    std::vector<std::vector<int>> out(static_cast<size_t>(n)), in(static_cast<size_t>(n));
    for (const VEdge& e : edges) {
        out[static_cast<size_t>(e.from)].push_back(e.to);
        in[static_cast<size_t>(e.to)].push_back(e.from);
    }
    const auto reach = [&](const std::vector<int>& seeds, bool forward, bool backward, int maxDepth) {
        std::vector<int> depth(static_cast<size_t>(n), -1);
        std::deque<int> q;
        for (int s : seeds) {
            depth[static_cast<size_t>(s)] = 0;
            q.push_back(s);
        }
        while (!q.empty()) {
            const int u = q.front();
            q.pop_front();
            if (maxDepth >= 0 && depth[static_cast<size_t>(u)] >= maxDepth) continue;
            const auto visit = [&](int v) {
                if (depth[static_cast<size_t>(v)] < 0) {
                    depth[static_cast<size_t>(v)] = depth[static_cast<size_t>(u)] + 1;
                    q.push_back(v);
                }
            };
            if (forward)
                for (int v : out[static_cast<size_t>(u)]) visit(v);
            if (backward)
                for (int v : in[static_cast<size_t>(u)]) visit(v);
        }
        return depth;
    };
    if (flaggedOnly_) {
        std::vector<int> flagged;
        for (int i = 0; i < n; ++i)
            if (keep[static_cast<size_t>(i)] && graph_.nodes[static_cast<size_t>(i)].flagged) flagged.push_back(i);
        const auto down = reach(flagged, true, false, -1);
        const auto up = reach(flagged, false, true, -1);
        for (int i = 0; i < n; ++i)
            keep[static_cast<size_t>(i)] = keep[static_cast<size_t>(i)] && (down[static_cast<size_t>(i)] >= 0 || up[static_cast<size_t>(i)] >= 0);
    }
    int focus = focus_ >= 0 && focus_ < n ? rep(focus_) : -1;
    if (focus_ >= 0 && focus < 0) focus = -1;
    if (focus >= 0) {
        const auto near = reach({focus}, true, true, focusDepth_);
        for (int i = 0; i < n; ++i) keep[static_cast<size_t>(i)] = keep[static_cast<size_t>(i)] && near[static_cast<size_t>(i)] >= 0;
    }
    if (hideIsolated_) {
        std::vector<char> linked(static_cast<size_t>(n), 0);
        for (const VEdge& e : edges)
            if (keep[static_cast<size_t>(e.from)] && keep[static_cast<size_t>(e.to)]) linked[static_cast<size_t>(e.from)] = linked[static_cast<size_t>(e.to)] = 1;
        for (int i = 0; i < n; ++i)
            if (!linked[static_cast<size_t>(i)] && i != focus) keep[static_cast<size_t>(i)] = 0;
    }

    // Components first: the layout treats the first node as the entry.
    std::vector<int> order;
    for (int i = 0; i < n; ++i)
        if (keep[static_cast<size_t>(i)]) order.push_back(i);
    std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
        return priority(graph_.nodes[static_cast<size_t>(a)].kind) < priority(graph_.nodes[static_cast<size_t>(b)].kind);
    });
    hiddenByCap_ = order.size() > kMaxViewNodes ? order.size() - kMaxViewNodes : 0;
    if (hiddenByCap_) order.resize(kMaxViewNodes);

    viewToModel_ = order;
    modelToView_.assign(static_cast<size_t>(n), -1);
    for (size_t v = 0; v < order.size(); ++v) modelToView_[static_cast<size_t>(order[v])] = static_cast<int>(v);
    std::vector<GraphView::Block> blocks;
    blocks.reserve(order.size());
    for (int m : order) {
        const behavior::Node& node = graph_.nodes[static_cast<size_t>(m)];
        GraphView::Block b;
        GraphView::Line title = {{kindTag(node.kind), kindColor(node.kind)}, {truncate(node.label, 56), Col::Text}};
        if (node.flagged) title.push_back({"  !", Col::Error});
        b.lines.push_back(std::move(title));
        if (!node.detail.empty()) b.lines.push_back({{truncate(node.detail, 56), Col::TextMuted}});
        b.border = node.flagged ? GraphView::Paint(Col::Error) : GraphView::Paint(kindColor(node.kind));
        if (!searchApplied_.empty() && (containsNoCase(node.label, searchApplied_) || containsNoCase(node.key, searchApplied_)))
            b.fill = Col::FindMatch;
        blocks.push_back(std::move(b));
    }
    std::vector<graphlayout::Edge> layoutEdges;
    for (const VEdge& e : edges) {
        const int u = modelToView_[static_cast<size_t>(e.from)], v = modelToView_[static_cast<size_t>(e.to)];
        if (u < 0 || v < 0) continue;
        graphlayout::Edge le;
        le.from = u;
        le.to = v;
        le.kind = layoutKind(e.kind);
        layoutEdges.push_back(std::move(le));
    }
    view_.set(std::move(blocks), std::move(layoutEdges), true);
    lastViewSelected_ = -1;
    const int keepSel = selected_ >= 0 && selected_ < n ? modelToView_[static_cast<size_t>(selected_)] : -1;
    if (keepSel >= 0) view_.focusBlock(keepSel);
    else if (focus >= 0 && modelToView_[static_cast<size_t>(focus)] >= 0) view_.focusBlock(modelToView_[static_cast<size_t>(focus)]);
}

void BehaviorPanel::select(int node, bool focusInGraph) {
    if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return;
    selected_ = node;
    if (!focusInGraph) return;
    if (modelToView_.size() != graph_.nodes.size() || modelToView_[static_cast<size_t>(node)] < 0) {
        // Not in the current view: centre the view on it.
        focus_ = node;
        dirty_ = true;
        return;
    }
    view_.focusBlock(modelToView_[static_cast<size_t>(node)]);
    lastViewSelected_ = modelToView_[static_cast<size_t>(node)];
}

std::vector<int> BehaviorPanel::neighbours(int node, bool incoming) const {
    std::vector<int> out;
    for (size_t i = 0; i < graph_.edges.size(); ++i) {
        const auto& e = graph_.edges[i];
        if (incoming ? static_cast<int>(e.to) == node : static_cast<int>(e.from) == node) out.push_back(static_cast<int>(i));
    }
    return out;
}

std::string BehaviorPanel::nativeLibraryFor(int node) const {
    const auto entryFor = [&](const std::string& file) -> std::string {
        for (const std::string& e : libEntries_)
            if (e.size() >= file.size() && e.compare(e.size() - file.size(), file.size(), file) == 0) return e;
        return {};
    };
    const behavior::Node& n = graph_.nodes[static_cast<size_t>(node)];
    if (n.key.rfind("lib:", 0) == 0) return entryFor(n.label);
    // A native method: the library its callers load, else any library the app loads.
    for (int ei : neighbours(node, true)) {
        const int caller = static_cast<int>(graph_.edges[static_cast<size_t>(ei)].from);
        for (int eo : neighbours(caller, false)) {
            const auto& e = graph_.edges[static_cast<size_t>(eo)];
            if (e.kind != BEdge::LoadsLibrary) continue;
            const std::string entry = entryFor(graph_.nodes[e.to].label);
            if (!entry.empty()) return entry;
        }
    }
    for (const auto& other : graph_.nodes)
        if (other.kind == BKind::Native && other.key.rfind("lib:", 0) == 0)
            if (std::string entry = entryFor(other.label); !entry.empty()) return entry;
    return libEntries_.empty() ? std::string() : libEntries_.front();
}

void BehaviorPanel::navigate(int node) {
    if (node < 0 || node >= static_cast<int>(graph_.nodes.size())) return;
    const behavior::Node& n = graph_.nodes[static_cast<size_t>(node)];
    switch (n.kind) {
    case BKind::Method:
        workspace_.requestMethodView({group_, n.target, "source"});
        return;
    case BKind::Component:
    case BKind::Class:
        workspace_.requestMethodView({group_, n.target, "class"});
        return;
    case BKind::Native: {
        const std::string entry = nativeLibraryFor(node);
        if (entry.empty()) {
            workspace_.log("No native library in this APK for " + n.label, "analysis");
            return;
        }
        const bool library = n.key.rfind("lib:", 0) == 0;
        workspace_.requestNativeView({group_, entry, library ? std::string() : n.target, "listing"});
        if (showPanel_) showPanel_("Function");
        return;
    }
    default:
        // Permissions, endpoints and storage have no code of their own: show who uses them.
        focus_ = node;
        selected_ = node;
        if (focusDepth_ < 2) focusDepth_ = 2;
        dirty_ = true;
        return;
    }
}

void BehaviorPanel::drawDetails() {
    if (selected_ < 0 || selected_ >= static_cast<int>(graph_.nodes.size())) {
        ImGui::TextUnformatted("Behavior");
        ImGui::Separator();
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("%zu components (%zu with bytecode), %zu methods walked", graph_.count(BKind::Component),
                            graph_.componentsResolved, graph_.methodsVisited);
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        for (int k = 0; k < behavior::kNodeKinds; ++k) {
            const auto kind = static_cast<BKind>(k);
            size_t flagged = 0;
            for (const auto& node : graph_.nodes)
                if (node.kind == kind && node.flagged) ++flagged;
            ImGui::TextColored(theme::vec(kindColor(kind)), "%s", kindTag(kind));
            ImGui::SameLine(0.f, 0.f);
            if (flagged) ImGui::Text("%s  %zu  (%zu flagged)", kKindLabels[k], graph_.count(kind), flagged);
            else ImGui::Text("%s  %zu", kKindLabels[k], graph_.count(kind));
        }
        ImGui::Spacing();
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("Click a node for details, double-click to open its code. Solid edges are calls, "
                            "dashed ones framework callbacks (a listener or Runnable the method creates).");
        ImGui::PopTextWrapPos();
        return;
    }
    const behavior::Node& n = graph_.nodes[static_cast<size_t>(selected_)];
    ImGui::TextColored(theme::vec(kindColor(n.kind)), "%s", behavior::kindName(n.kind));
    if (n.flagged) {
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Error), "%s flagged", Theme::hasIcons() ? icons::FLAG : "!");
    }
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(n.label.c_str());
    ImGui::TextDisabled("%s", n.key.c_str());
    if (ImGui::BeginPopupContextItem("##keyMenu")) {
        if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(n.key.c_str());
        ImGui::EndPopup();
    }
    if (!n.detail.empty()) ImGui::TextUnformatted(n.detail.c_str());
    if (n.flagged) ui::wrappedColored(theme::vec(Col::Warning), flagReason(n));
    ImGui::PopTextWrapPos();

    const bool hasCode = n.kind == BKind::Method || n.kind == BKind::Component || n.kind == BKind::Class ||
                         n.kind == BKind::Native;
    if (hasCode && ui::flowSmallButton(ui::icon(icons::OPEN, "Open").c_str())) navigate(selected_);
    if (ui::flowSmallButton(focus_ == selected_ ? "Focused" : "Focus")) {
        focus_ = selected_;
        dirty_ = true;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Show only this node and its neighbours");
    if (ui::flowSmallButton(ui::icon(icons::COPY, "Copy").c_str())) ImGui::SetClipboardText(n.key.c_str());

    if (!n.evidence.empty() && ImGui::CollapsingHeader(("Evidence (" + std::to_string(n.evidence.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
        for (size_t i = 0; i < n.evidence.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            ImGui::PushTextWrapPos(0.f);
            ImGui::TextUnformatted(n.evidence[i].c_str());
            ImGui::PopTextWrapPos();
            if (ImGui::BeginPopupContextItem("##ev")) {
                if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(n.evidence[i].c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
    const auto edgeList = [&](const char* title, bool incoming) {
        const std::vector<int> list = neighbours(selected_, incoming);
        if (list.empty()) return;
        if (!ImGui::CollapsingHeader((std::string(title) + " (" + std::to_string(list.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen)) return;
        ImGui::PushID(title);
        int target = -1;
        bool open = false;
        for (int ei : list) {
            const auto& e = graph_.edges[static_cast<size_t>(ei)];
            const int other = static_cast<int>(incoming ? e.from : e.to);
            const behavior::Node& o = graph_.nodes[static_cast<size_t>(other)];
            ImGui::PushID(ei);
            ImGui::TextColored(theme::vec(kindColor(o.kind)), "%s", kindTag(o.kind));
            ImGui::SameLine(0.f, 0.f);
            if (ImGui::Selectable(o.label.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                target = other;
                open = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            }
            if (ImGui::IsItemHovered()) {
                std::string tip = std::string(behavior::edgeName(e.kind)) + (e.via.empty() ? "" : " via " + e.via) + "\n" + o.key;
                ImGui::SetTooltip("%s", tip.c_str());
            }
            ImGui::PopID();
        }
        ImGui::PopID();
        if (target >= 0) {
            if (open) navigate(target);
            else select(target, true);
        }
    };
    if (n.kind == BKind::Component) {
        // What the component can reach, with the call path to each capability.
        if (reachOf_ != selected_) {
            reachOf_ = selected_;
            reach_ = behavior::reachableCapabilities(graph_, static_cast<uint32_t>(selected_));
        }
        if (!reach_.empty() &&
            ImGui::CollapsingHeader(("Reaches (" + std::to_string(reach_.size()) + ")").c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
            int target = -1;
            for (size_t i = 0; i < reach_.size(); ++i) {
                const behavior::Node& cap = graph_.nodes[reach_[i].node];
                ImGui::PushID(static_cast<int>(i));
                ImGui::TextColored(theme::vec(kindColor(cap.kind)), "%s", kindTag(cap.kind));
                ImGui::SameLine(0.f, 0.f);
                const std::string label = cap.flagged ? cap.label + "  !" : cap.label;
                if (ImGui::Selectable(label.c_str())) target = static_cast<int>(reach_[i].node);
                if (ImGui::IsItemHovered()) {
                    std::string tip = "Call path:";
                    for (uint32_t step : reach_[i].path) tip += "\n  " + graph_.nodes[step].label;
                    ImGui::SetTooltip("%s", tip.c_str());
                }
                ImGui::PopID();
            }
            if (target >= 0) select(target, true);
        }
        edgeList("Methods", false);
        return;
    }
    edgeList("Used by", true);
    edgeList("Uses", false);
}
