#include "ui/ExplorerPanel.hpp"
#include "app/Theme.hpp"
#include "core/TextUtils.hpp"
#include <cstring>
#include <string>
#include "ui/ShellIcons.hpp"
#include <cstdio>
#include "imgui_internal.h"

namespace {
ImVec4 colorFor(NodeKind kind) {
    switch (kind) {
    case NodeKind::Folder: return theme::vec(Col::Text);
    case NodeKind::Java: return theme::vec(Col::Cyan);
    case NodeKind::Kotlin: return theme::vec(Col::Blue);
    case NodeKind::Xml: return theme::vec(Col::Blue);
    case NodeKind::Json: return theme::vec(Col::Yellow);
    case NodeKind::Smali: return theme::vec(Col::Red);
    case NodeKind::Groovy: return theme::vec(Col::Green);
    case NodeKind::Yaml: return theme::vec(Col::Green);
    case NodeKind::Web: return theme::vec(Col::Purple);
    case NodeKind::Text: return theme::vec(Col::Orange);
    case NodeKind::Image: return theme::vec(Col::Green);
    case NodeKind::Dex: return theme::vec(Col::Pink);
    case NodeKind::Native: return theme::vec(Col::Yellow);
    default: return theme::vec(Col::TextMuted);
    }
}

// ---------------------------------------------------------------------------
// Windows Explorer style default icons, drawn with ImDrawList primitives so
// no texture atlas or font icons are needed (non-Windows fallback). All
// coordinates are derived from the [mn, mx] box so they scale with the
// current font size.
// ---------------------------------------------------------------------------

// Classic two-tone yellow shell folder. 'archive' adds the dashed zipper
// strip the shell uses for .zip/.apk archives (used for APK root nodes).
void drawFolderIcon(ImDrawList* dl, const ImVec2& mn, const ImVec2& mx, bool archive) {
    const float w = mx.x - mn.x, h = mx.y - mn.y;
    const float r = 1.8f < h * 0.16f ? 1.8f : h * 0.16f;
    const ImU32 back   = IM_COL32(226, 168, 43, 255);
    const ImU32 front  = IM_COL32(252, 206, 64, 255);
    const ImU32 lip    = IM_COL32(255, 226, 120, 255);
    const ImU32 edge   = IM_COL32(186, 132, 20, 255);
    const ImU32 zipper = IM_COL32(122, 86, 8, 255);
    // Back panel + tab.
    dl->AddRectFilled(ImVec2(mn.x, mn.y + h * 0.16f), ImVec2(mn.x + w * 0.52f, mn.y + h * 0.46f), back, r,
                      ImDrawFlags_RoundCornersTop);
    // Front panel with a lighter lip along its top edge.
    ImVec2 f0(mn.x, mn.y + h * 0.32f), f1(mx.x, mx.y - h * 0.05f);
    dl->AddRectFilled(f0, f1, front, r);
    dl->AddRect(f0, f1, edge, r, 0, 1.0f);
    dl->AddRectFilled(ImVec2(f0.x + 1.f, f0.y + 1.f), ImVec2(f1.x - 1.f, f0.y + h * 0.15f), lip, r,
                      ImDrawFlags_RoundCornersTop);
    if (archive) {
        // Dashed vertical zipper on the left of the front panel.
        const float zx = mn.x + w * 0.26f;
        for (float y = f0.y + h * 0.16f; y < f1.y - h * 0.12f; y += h * 0.22f)
            dl->AddLine(ImVec2(zx, y), ImVec2(zx, y + h * 0.11f), zipper, 1.3f);
    }
}

// Document page with a folded top-right corner. 'picture' renders a tiny
// landscape (sky, mountain, sun) like the shell's image icon; otherwise a
// few text lines tinted with the file type's accent color are drawn.
void drawPageIcon(ImDrawList* dl, const ImVec2& mn, const ImVec2& mx, ImU32 accent, bool picture) {
    const float w = mx.x - mn.x, h = mx.y - mn.y;
    const float fold = 3.0f > w * 0.30f ? 3.0f : w * 0.30f;
    const ImU32 paper = IM_COL32(253, 253, 253, 255);
    const ImU32 edge  = IM_COL32(138, 144, 155, 255);
    const ImU32 foldC = IM_COL32(197, 203, 212, 255);
    const ImVec2 p0(mn.x + w * 0.05f, mn.y + h * 0.03f);
    const ImVec2 p1(mx.x - w * 0.05f, mx.y - h * 0.01f);
    const ImVec2 corner(p1.x - fold, p0.y);
    const ImVec2 foldEnd(p1.x, p0.y + fold);
    const ImVec2 pts[5] = {p0, corner, foldEnd, p1, ImVec2(p0.x, p1.y)};
    dl->AddConvexPolyFilled(pts, 5, paper);
    dl->AddPolyline(pts, 5, edge, 0, 1.0f);
    dl->AddTriangleFilled(corner, foldEnd, ImVec2(corner.x, foldEnd.y), foldC);

    if (picture) {
        // Miniature photo: sky rectangle, mountain triangle and a sun.
        const ImVec2 a(p0.x + w * 0.14f, p0.y + h * 0.36f);
        const ImVec2 b(p1.x - w * 0.10f, p1.y - h * 0.10f);
        dl->AddRectFilled(a, b, IM_COL32(203, 228, 244, 255));
        dl->AddTriangleFilled(ImVec2(a.x, b.y), ImVec2(a.x + (b.x - a.x) * 0.55f, a.y + (b.y - a.y) * 0.40f),
                              ImVec2(a.x + (b.x - a.x) * 0.22f, b.y), IM_COL32(88, 156, 84, 255));
        dl->AddCircleFilled(ImVec2(b.x - (b.x - a.x) * 0.22f, a.y + (b.y - a.y) * 0.26f), (b.y - a.y) * 0.14f,
                            IM_COL32(245, 176, 65, 255));
    } else {
        for (int i = 0; i < 4; ++i) {
            const float y = p0.y + h * (0.38f + 0.16f * i);
            if (y > p1.y - h * 0.04f) break;
            const float x1 = p1.x - w * (i == 3 ? 0.32f : 0.10f);
            dl->AddLine(ImVec2(p0.x + w * 0.16f, y), ImVec2(x1, y), accent, 1.4f);
        }
    }
}

// IDE-style file-type icon: a page with a colored badge carrying a short
// mnemonic ("J", "K", "<>", "{}", "DX", "SO"...). Used for every file type
// Windows has no meaningful icon for - .java, .kt, .smali, .dex, .so, .arsc
// and friends otherwise all resolve to the same blank page.
void drawBadgeIcon(ImDrawList* dl, const ImVec2& mn, const ImVec2& mx, ImU32 badge, const char* text) {
    const float w = mx.x - mn.x, h = mx.y - mn.y;
    // Page silhouette (narrower, so the badge can overhang on the left).
    const ImVec2 p0(mn.x + w * 0.22f, mn.y + h * 0.02f), p1(mx.x - w * 0.04f, mx.y - h * 0.02f);
    const float fold = w * 0.26f;
    const ImVec2 corner(p1.x - fold, p0.y), foldEnd(p1.x, p0.y + fold);
    const ImVec2 pts[5] = {p0, corner, foldEnd, p1, ImVec2(p0.x, p1.y)};
    dl->AddConvexPolyFilled(pts, 5, IM_COL32(236, 238, 242, 255));
    dl->AddPolyline(pts, 5, IM_COL32(138, 144, 155, 255), 0, 1.0f);
    dl->AddTriangleFilled(corner, foldEnd, ImVec2(corner.x, foldEnd.y), IM_COL32(197, 203, 212, 255));
    // Badge: rounded rectangle across the lower part with the mnemonic.
    const ImVec2 b0(mn.x, mn.y + h * 0.40f), b1(mx.x - w * 0.10f, mx.y - h * 0.04f);
    dl->AddRectFilled(b0, b1, badge, h * 0.14f);
    ImFont* font = ImGui::GetFont();
    const size_t len = std::strlen(text);
    const float fontSize = h * (len >= 3 ? 0.40f : len == 2 ? 0.48f : 0.58f);
    const ImVec2 ts = font->CalcTextSizeA(fontSize, FLT_MAX, 0.f, text);
    const ImVec2 at(b0.x + (b1.x - b0.x - ts.x) * 0.5f, b0.y + (b1.y - b0.y - ts.y) * 0.5f);
    dl->AddText(font, fontSize, ImVec2(at.x + 0.6f, at.y), IM_COL32(255, 255, 255, 255), text);  // faux bold
    dl->AddText(font, fontSize, at, IM_COL32(255, 255, 255, 255), text);
}

std::string lowerExt(const std::string& name) {
    const size_t dot = name.find_last_of('.');
    return dot == std::string::npos ? std::string() : tex::asciiLower(name.substr(dot + 1));
}

// Draws the icon for a file; false when the type has no drawn icon (the
// shell icon / plain page is used then).
bool drawFileTypeIcon(ImDrawList* dl, const ImVec2& mn, const ImVec2& mx, const TreeNode& node) {
    const std::string ext = lowerExt(node.name());
    switch (node.kind()) {
    case NodeKind::Java: drawBadgeIcon(dl, mn, mx, IM_COL32(231, 111, 0, 255), "J"); return true;
    case NodeKind::Kotlin: drawBadgeIcon(dl, mn, mx, IM_COL32(127, 82, 255, 255), "K"); return true;
    case NodeKind::Smali: drawBadgeIcon(dl, mn, mx, IM_COL32(192, 64, 64, 255), "S"); return true;
    case NodeKind::Xml: drawBadgeIcon(dl, mn, mx, IM_COL32(46, 139, 87, 255), "<>"); return true;
    case NodeKind::Json: drawBadgeIcon(dl, mn, mx, IM_COL32(201, 162, 39, 255), "{}"); return true;
    case NodeKind::Dex: drawBadgeIcon(dl, mn, mx, IM_COL32(155, 77, 202, 255), "DX"); return true;
    case NodeKind::Native: drawBadgeIcon(dl, mn, mx, IM_COL32(84, 110, 122, 255), "SO"); return true;
    case NodeKind::Groovy: drawBadgeIcon(dl, mn, mx, IM_COL32(66, 152, 184, 255), "G"); return true;
    case NodeKind::Yaml: drawBadgeIcon(dl, mn, mx, IM_COL32(203, 23, 30, 255), "Y"); return true;
    case NodeKind::Web:
        if (ext == "css") drawBadgeIcon(dl, mn, mx, IM_COL32(41, 101, 241, 255), "#");
        else if (ext == "js" || ext == "mjs") drawBadgeIcon(dl, mn, mx, IM_COL32(200, 170, 0, 255), "JS");
        else drawBadgeIcon(dl, mn, mx, IM_COL32(227, 79, 38, 255), "<>");
        return true;
    case NodeKind::Image:
        drawPageIcon(dl, mn, mx, IM_COL32(120, 170, 220, 255), true);
        return true;
    case NodeKind::Text:
        if (ext == "properties" || ext == "pro" || ext == "cfg" || ext == "ini" || ext == "conf" || ext == "prop") {
            drawBadgeIcon(dl, mn, mx, IM_COL32(110, 120, 135, 255), "=");
            return true;
        }
        if (ext == "mf" || ext == "sf") {
            drawBadgeIcon(dl, mn, mx, IM_COL32(70, 130, 110, 255), "MF");
            return true;
        }
        drawPageIcon(dl, mn, mx, IM_COL32(150, 156, 168, 255), false);
        return true;
    case NodeKind::Binary:
        if (ext == "arsc") drawBadgeIcon(dl, mn, mx, IM_COL32(0, 137, 123, 255), "RS");
        else if (ext == "rsa" || ext == "dsa" || ext == "ec") drawBadgeIcon(dl, mn, mx, IM_COL32(176, 120, 30, 255), "SIG");
        else if (ext == "ttf" || ext == "otf" || ext == "ttc") drawBadgeIcon(dl, mn, mx, IM_COL32(90, 90, 160, 255), "F");
        else if (ext == "ogg" || ext == "mp3" || ext == "wav" || ext == "flac" || ext == "m4a" || ext == "aac" ||
                 ext == "opus" || ext == "amr" || ext == "mid" || ext == "midi" || ext == "oga")
            drawBadgeIcon(dl, mn, mx, IM_COL32(200, 80, 120, 255), "AU");
        else if (ext == "mp4" || ext == "webm" || ext == "3gp" || ext == "mkv" || ext == "m4v" || ext == "mov") drawBadgeIcon(dl, mn, mx, IM_COL32(180, 60, 60, 255), "VID");
        else if (ext == "db" || ext == "sqlite" || ext == "realm") drawBadgeIcon(dl, mn, mx, IM_COL32(60, 120, 170, 255), "DB");
        else if (ext == "jar" || ext == "zip" || ext == "apk" || ext == "aar") drawBadgeIcon(dl, mn, mx, IM_COL32(150, 110, 40, 255), "ZIP");
        else if (ext == "kotlin_module" || ext == "kotlin_builtins") drawBadgeIcon(dl, mn, mx, IM_COL32(127, 82, 255, 255), "KM");
        else if (ext == "version") drawBadgeIcon(dl, mn, mx, IM_COL32(110, 120, 135, 255), "V");
        else drawBadgeIcon(dl, mn, mx, IM_COL32(96, 102, 112, 255), "01");
        return true;
    case NodeKind::Folder: break;
    }
    return false;
}
} // namespace

void ExplorerPanel::drawContents() {
    // Switch to the Decompiled tab as soon as results become available.
    if (workspace_.takeDecompileSwitch()) selectTab_ = 1;
    if (workspace_.pendingReveal().node && !revealTabSet_) {
        selectTab_ = workspace_.pendingReveal().kind == RootKind::Decompiled ? 1 : 0;
        revealTabSet_ = true;
    }

    // One-shot selection request: SetSelected must only be passed on the frame
    // that wants to force a tab. Re-asserting it every frame (from a mirrored
    // "active" variable) fights the user's click, because the flag queues the
    // selection again before the clicked tab's content ever ran - snapping the
    // bar straight back to the old tab.
    ImGuiTabItemFlags filesFlags = selectTab_ == 0 ? ImGuiTabItemFlags_SetSelected : 0;
    ImGuiTabItemFlags decFlags = selectTab_ == 1 ? ImGuiTabItemFlags_SetSelected : 0;
    selectTab_ = -1;

    // Drag-selection state: opening a file is deferred to mouse release so a
    // click-drag across rows selects them instead.
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) dragMoved_ = false;
    if (ImGui::IsMouseDragging(ImGuiMouseButton_Left, 6.0f)) dragMoved_ = true;

    if (ImGui::BeginTabBar("##explorer_tabs", ImGuiTabBarFlags_None)) {
        if (ImGui::BeginTabItem("Files", nullptr, filesFlags)) {
            auto apks = workspace_.apkRoots();
            if (apks.empty()) {
                ImGui::TextDisabled("No project open - use File > New Project or drop an APK here");
            } else {
                // One group per APK; the jadx output lives in its own tab.
                for (Root* apk : apks) drawTree(*apk);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Decompiled", nullptr, decFlags)) {
            auto decompiled = workspace_.decompiledRoots();
            bool running = workspace_.jadx().state() == JadxRunner::State::Running;
            if (decompiled.empty()) {
                if (running) {
                    drawJadxProgress();
                    ImGui::TextDisabled("Partial results will appear here while jadx is running");
                } else {
                    ImGui::TextDisabled("Add an APK to the project to decompile it with jadx");
                }
            } else {
                if (running) drawJadxProgress();
                ImGui::Separator();
                // One group per APK, named exactly like in the Files tab.
                for (Root* dec : decompiled) drawTree(*dec);
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    // Clicking empty space clears the selection.
    if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !hoveredAny_) {
        setSelection({});
        anchorNode_ = nullptr;
    }
    hoveredAny_ = false;
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Left)) pressNode_ = nullptr;

    // Drop selection entries that were not part of the walked tree this
    // frame (collapsed rows keep their selection only while visible - this
    // also discards pointers into trees that were removed from the project).
    selection_ = drawnSelection_;
    drawnSelection_.clear();
    allRows_.clear();

    // Ctrl+C copies the selected rows' names (the text shown in the panel).
    ImGuiIO& io = ImGui::GetIO();
    if (!selection_.empty() && io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false) &&
        ImGui::IsWindowFocused())
        copySelection();

    drawExportProgress();
    drawRemoveConfirm();
}

// Depth-first walk that collects the rows ImGui will need: one entry per
// visible node (open folders only), re-validating the selection on the way.
// Reading the open state from ImGui's own storage keeps the walk and the
// rendered arrows in sync (a toggle click applies on the next frame).
void ExplorerPanel::walk(Root& root, const TreeNode& node, int depth, bool isRoot) {
    rows_.push_back({&root, &node, depth, isRoot});
    if (selection_.count(&node)) drawnSelection_.insert(&node);
    if (!node.isFolder()) return;
    bool open = isRoot;
    if (ImGuiStorage* storage = ImGui::GetStateStorage())
        open = storage->GetInt(static_cast<int>(ImGui::GetID(&node)), isRoot ? 1 : 0) != 0;
    if (!open) return;
    for (const auto& c : node.children()) walk(root, *c, depth + 1, false);
}

void ExplorerPanel::setSelection(std::set<const TreeNode*> nodes) {
    drawnSelection_ = nodes;
    selection_ = std::move(nodes);
}

std::set<const TreeNode*> ExplorerPanel::rowRange(const Root* root, const TreeNode* a, const TreeNode* b) const {
    std::set<const TreeNode*> out;
    int ia = -1, ib = -1;
    for (int i = 0; i < static_cast<int>(allRows_.size()); ++i) {
        if (allRows_[static_cast<size_t>(i)].root != root) continue;
        if (allRows_[static_cast<size_t>(i)].node == a) ia = i;
        if (allRows_[static_cast<size_t>(i)].node == b) ib = i;
    }
    if (ia < 0 || ib < 0) {
        if (b) out.insert(b);
        return out;
    }
    for (int i = std::min(ia, ib); i <= std::max(ia, ib); ++i) out.insert(allRows_[static_cast<size_t>(i)].node);
    return out;
}

void ExplorerPanel::drawTree(Root& root) {
    rows_.clear();
    // Reveal: open the folders down to the node before walking the tree.
    const Workspace::RevealRequest reveal = workspace_.pendingReveal();
    const bool revealHere = reveal.node && reveal.group == root.title && reveal.kind == root.kind;
    if (revealHere)
        if (ImGuiStorage* storage = ImGui::GetStateStorage())
            for (const TreeNode* folder : Workspace::chainTo(*root.tree, reveal.node))
                if (folder != reveal.node || folder->isFolder()) storage->SetInt(static_cast<int>(ImGui::GetID(folder)), 1);
    const float startY = ImGui::GetCursorPosY();
    walk(root, *root.tree, 0, true);
    if (revealHere) {
        for (size_t i = 0; i < rows_.size(); ++i)
            if (rows_[i].node == reveal.node) {
                setSelection({reveal.node});
                anchorNode_ = reveal.node;
                const float y = startY + static_cast<float>(i) * ImGui::GetTextLineHeightWithSpacing();
                ImGui::SetScrollY(std::max(0.f, y - ImGui::GetWindowHeight() * 0.35f));
                break;
            }
        workspace_.clearReveal();
        revealTabSet_ = false;
    }
    allRows_.insert(allRows_.end(), rows_.begin(), rows_.end());
    // Virtualized rendering: only the rows in view are submitted, so huge
    // packages don't pay for thousands of hidden tree nodes per frame.
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows_.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const Row& row = rows_[static_cast<size_t>(i)];
            drawRow(*row.root, *row.node, row.depth, row.isRoot);
        }
    }
}

void ExplorerPanel::copySelection() {
    std::string text;
    for (const TreeNode* node : selection_) {
        if (!text.empty()) text += '\n';
        text += node->name();
    }
    if (text.empty()) return;
    ImGui::SetClipboardText(text.c_str());
    workspace_.log("Copied " + std::to_string(selection_.size()) + " item(s) to the clipboard");
}

void ExplorerPanel::drawRemoveConfirm() {
    if (!removeRequest_) return;
    if (!ImGui::IsPopupOpen("Remove from project?")) ImGui::OpenPopup("Remove from project?");
    if (!ImGui::BeginPopupModal("Remove from project?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    ImGui::Text("Remove \"%s\" from the project?", removeRequest_->title.c_str());
    ImGui::TextDisabled("Its decompiled results and related tabs will be closed.");
    ImGui::TextDisabled("The APK file itself is not deleted from disk.");
    ImGui::Spacing();
    if (ImGui::Button("Remove", ImVec2(120, 0))) {
        Root* root = removeRequest_;
        removeRequest_ = nullptr;
        pressNode_ = nullptr;
        selection_.clear();
        drawnSelection_.clear();
        workspace_.removeApk(root);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0))) {
        removeRequest_ = nullptr;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void ExplorerPanel::drawJadxProgress() {
    const JadxRunner& jadx = workspace_.jadx();
    char label[128];
    const int total = jadx.totalCount();
    if (total > 0) {
        std::snprintf(label, sizeof label, "Decompiling %d / %d classes - %d s", jadx.processedCount(), total,
                      jadx.elapsedSeconds());
        ImGui::ProgressBar(static_cast<float>(jadx.processedCount()) / static_cast<float>(total), ImVec2(-FLT_MIN, 0.f), label);
    } else {
        std::snprintf(label, sizeof label, "Decompiling... %d s", jadx.elapsedSeconds());
        // A negative fraction animates an indeterminate progress bar.
        ImGui::ProgressBar(-1.0f * static_cast<float>(ImGui::GetTime()), ImVec2(-FLT_MIN, 0.f), label);
    }
    ImGui::TextColored(theme::vec(Col::Warning), "Warnings: %d", jadx.warningCount());
    ImGui::SameLine();
    ImGui::TextColored(theme::vec(Col::Error), "Errors: %d", jadx.errorCount());
    ImGui::SameLine();

    if (ImGui::Button("Cancel")) workspace_.cancelDecompile();
}

void ExplorerPanel::drawRow(Root& root, const TreeNode& node, int depth, bool isRoot) {
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_OpenOnDoubleClick | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    if (isRoot) flags |= ImGuiTreeNodeFlags_DefaultOpen;
    if (!node.isFolder()) flags |= ImGuiTreeNodeFlags_Leaf;
    if (selection_.count(&node)) flags |= ImGuiTreeNodeFlags_Selected;

    // Windows Explorer look: [arrow] [icon] [name] at the row's depth.
    // ImGui renders the label right after the arrow, so we pad the label
    // with leading spaces to open a gap, then paint the icon over that gap
    // once the item rect is known. labelX = cursor + GetTreeNodeToLabelSpacing()
    // reproduces exactly where TreeNodeBehavior starts the text.
    const float iconSize = ImGui::GetTextLineHeight();
    const float spaceW = ImGui::CalcTextSize(" ").x;
    const int padSpaces = static_cast<int>((iconSize + ImGui::GetStyle().ItemInnerSpacing.x) / spaceW) + 1;
    char label[512];
    std::snprintf(label, sizeof label, "%*s%s", padSpaces, "", node.name().c_str());

    // Flat rendering: the depth indent is applied directly to the row's
    // cursor instead of nested TreePush/TreePop (which clipper rows can't do).
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + static_cast<float>(depth) * ImGui::GetStyle().IndentSpacing);
    const ImVec2 start = ImGui::GetCursorScreenPos();
    ImGui::TreeNodeEx(&node, flags, "%s", label);

    // Paint the icon into the reserved gap, vertically centered on the row.
    const ImVec2 itemMin = ImGui::GetItemRectMin();
    const float rowH = ImGui::GetItemRectSize().y;
    const float labelX = start.x + ImGui::GetTreeNodeToLabelSpacing();
    const ImVec2 mn(labelX, itemMin.y + (rowH - iconSize) * 0.5f);
    const ImVec2 mx(mn.x + iconSize, mn.y + iconSize);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const bool archiveRoot = isRoot && root.kind == Root::Kind::Apk;
    if (!node.isFolder() && !archiveRoot && drawFileTypeIcon(dl, mn, mx, node)) {
        // Drawn type icon (distinct per file type, scales with the zoom).
    } else if (ImTextureID tex = ShellIcons::instance().iconFor(node, archiveRoot)) {
        // Real Windows default icon (cached per extension, extracted once).
        dl->AddImage(tex, mn, mx);
    } else if (node.isFolder()) {
        // Fallback for non-Windows builds: drawn shell-style icons.
        drawFolderIcon(dl, mn, mx, archiveRoot);
    } else {
        drawPageIcon(dl, mn, mx, ImGui::GetColorU32(colorFor(node.kind())), node.kind() == NodeKind::Image);
    }

    const bool hovered = ImGui::IsItemHovered();
    hoveredAny_ |= hovered;
    // Names wider than the panel are clipped at its edge: show them whole.
    if (hovered && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        const float textEnd = mx.x + ImGui::GetStyle().ItemInnerSpacing.x + ImGui::CalcTextSize(node.name().c_str()).x;
        const float visibleEnd = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
        if (textEnd > visibleEnd) ImGui::SetTooltip("%s", node.name().c_str());
    }
    const bool inSelection = selection_.count(&node) > 0;

    (void)inSelection;
    const ImGuiIO& io = ImGui::GetIO();
    // Click-and-drag selects the contiguous rows between the press and the
    // row under the mouse (dragging back shrinks the range again).
    if (dragMoved_ && hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left) && pressNode_ && pressRoot_ == &root)
        setSelection(rowRange(&root, pressNode_, &node));

    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !pressNode_) {
        pressNode_ = &node;
        pressRoot_ = &root;
    }
    // Opening fires on release without a drag, so dragging selects instead.
    const bool plainClick = hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
                            pressNode_ == &node && !dragMoved_;
    const bool doubleClicked = !node.isFolder() && hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
    // Opening a file while a document is already active is an explicit jump
    // that lands in the Back/Forward history (M2); without an active code
    // document the plain open paths are used.
    const Document* activeDoc = workspace_.activeDocument();
    const bool jump = !node.isFolder() && activeDoc && activeDoc->mode() == Document::Mode::Code;
    NavLocation origin;
    if (jump) origin = workspace_.locationOf(*activeDoc);
    if (doubleClicked) {
        setSelection({&node});
        anchorNode_ = &node;
        // Double click: promote to a permanent tab.
        if (jump) workspace_.navigateTo(root, node, -1, &origin);
        else workspace_.openNode(root, node, -1, Workspace::OpenMode::Permanent);
    } else if (plainClick && io.KeyCtrl) {
        // Ctrl+click toggles one row without opening it.
        std::set<const TreeNode*> next = selection_;
        if (!next.erase(&node)) next.insert(&node);
        setSelection(std::move(next));
        anchorNode_ = &node;
    } else if (plainClick && io.KeyShift && anchorNode_) {
        // Shift+click extends from the anchor without opening.
        setSelection(rowRange(&root, anchorNode_, &node));
    } else if (plainClick) {
        setSelection({&node});
        anchorNode_ = &node;
        if (!node.isFolder()) {
            // Single click: open (or replace) the preview tab.
            if (jump) workspace_.navigateTo(root, node, -1, &origin, Workspace::OpenMode::Preview);
            else workspace_.openNode(root, node, -1, Workspace::OpenMode::Preview);
        }
    }

    // Right-click context menu ------------------------------------------------
    // str_id must be NULL so the popup id is tied to THIS tree node's item id.
    // A fixed string id ("##explorer_ctx") is shared by every node: while the
    // menu is open, BeginPopup() returns true for each node in the tree and
    // every node appends its items to the same popup - showing the options
    // cloned once per visible node.
    if (ImGui::BeginPopupContextItem(nullptr)) {
        if (!node.isFolder()) {
            if (ImGui::MenuItem("Open")) workspace_.openNode(root, node, -1, Workspace::OpenMode::Preview);
            if (ImGui::MenuItem("Open in New Tab"))
                workspace_.openNode(root, node, -1, Workspace::OpenMode::Permanent);
            ImGui::Separator();
            // Export (M5): raw copies the exact bytes, decoded converts
            // compiled Android XML to readable text.
            if (ImGui::MenuItem("Export Raw...")) openExportFile(root, node, false);
            if (ImGui::MenuItem("Export Decoded...")) openExportFile(root, node, true);
            ImGui::Separator();
        } else {
            // Folder export (M5): whole subtree, raw or decoded.
            if (ImGui::MenuItem("Export Folder (raw)...")) openExportFolder(root, node, false);
            if (ImGui::MenuItem("Export Folder (decoded)...")) openExportFolder(root, node, true);
            ImGui::Separator();
        }
        if (ImGui::MenuItem("Copy Path")) ImGui::SetClipboardText(node.path().c_str());
        if (isRoot && root.kind == Root::Kind::Apk) {
            ImGui::Separator();
            if (ImGui::MenuItem("Remove from Project")) removeRequest_ = &root;
        }
        ImGui::EndPopup();
    }
}

// ---------------------------------------------------------------------------
// Export / extract (M5)
// ---------------------------------------------------------------------------

void ExplorerPanel::openExportFile(Root& root, const TreeNode& node, bool decoded) {
    exportRequest_ = {&root, &node, decoded, false};
    exportFileBrowser_.open(FileBrowser::Mode::SaveFile);
    exportFileBrowser_.setDefaultName(node.name());  // after open(): open() resets the name

}

void ExplorerPanel::openExportFolder(Root& root, const TreeNode& node, bool decoded) {
    exportRequest_ = {&root, &node, decoded, true};
    exportFolderBrowser_.open(FileBrowser::Mode::SelectFolder);
    exportFolderBrowser_.setDefaultName(node.name());

}

// Draws the running export job's progress (folder exports); single-file
// exports finish synchronously and only log.
void ExplorerPanel::drawExportProgress() {
    // Browser accepts are consumed here so the export starts in the same
    // frame the user confirmed (the request survives the popup's frame).
    std::string picked;
    if (exportFileBrowser_.render(), exportFileBrowser_.takeAccepted(picked)) {
        if (exportRequest_.root && exportRequest_.node && !exportRequest_.folder)
            workspace_.exportNode(*exportRequest_.root, *exportRequest_.node, picked, exportRequest_.decoded);
        exportRequest_ = {};
    }
    if (exportFolderBrowser_.render(), exportFolderBrowser_.takeAccepted(picked)) {
        if (exportRequest_.root && exportRequest_.node && exportRequest_.folder)
            workspace_.exportFolder(*exportRequest_.root, *exportRequest_.node, picked, exportRequest_.decoded);
        exportRequest_ = {};
    }

    const ExportJob& job = workspace_.exportJob();
    if (!job.busy()) return;
    ImGui::Separator();
    const float frac = job.total() > 0 ? static_cast<float>(job.done()) / static_cast<float>(job.total()) : 0.f;
    char label[256];
    std::snprintf(label, sizeof label, "%s (%d/%d)", job.currentName().c_str(), job.done(), job.total());
    ImGui::ProgressBar(frac, ImVec2(-FLT_MIN, 0.f), label);
    ImGui::TextDisabled("Exporting to %s - %d failed", job.destDir().c_str(), job.failed());
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) workspace_.exportJob().cancel();
}
