#include "ui/ExplorerPanel.hpp"
#include "ui/ShellIcons.hpp"
#include <cstdio>
#include "imgui_internal.h"

namespace {
ImVec4 colorFor(NodeKind kind) {
    switch (kind) {
    case NodeKind::Folder: return ImVec4(0.86f, 0.86f, 0.86f, 1.f);
    case NodeKind::Java: return ImVec4(0.31f, 0.79f, 0.69f, 1.f);
    case NodeKind::Kotlin: return ImVec4(0.55f, 0.72f, 0.95f, 1.f);
    case NodeKind::Xml: return ImVec4(0.34f, 0.61f, 0.84f, 1.f);
    case NodeKind::Json: return ImVec4(0.85f, 0.75f, 0.45f, 1.f);
    case NodeKind::Smali: return ImVec4(0.75f, 0.55f, 0.55f, 1.f);
    case NodeKind::Groovy: return ImVec4(0.62f, 0.78f, 0.55f, 1.f);
    case NodeKind::Yaml: return ImVec4(0.65f, 0.70f, 0.55f, 1.f);
    case NodeKind::Web: return ImVec4(0.70f, 0.62f, 0.85f, 1.f);
    case NodeKind::Text: return ImVec4(0.81f, 0.57f, 0.47f, 1.f);
    case NodeKind::Image: return ImVec4(0.71f, 0.81f, 0.66f, 1.f);
    case NodeKind::Dex: return ImVec4(0.77f, 0.53f, 0.75f, 1.f);
    case NodeKind::Native: return ImVec4(0.86f, 0.86f, 0.67f, 1.f);
    default: return ImVec4(0.65f, 0.65f, 0.65f, 1.f);
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
} // namespace

void ExplorerPanel::drawContents() {
    // Switch to the Decompiled tab as soon as results become available.
    if (workspace_.takeDecompileSwitch()) selectTab_ = 1;

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
        selection_.clear();
    }
    hoveredAny_ = false;
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Left)) pressNode_ = nullptr;

    // Drop selection entries that were not part of the walked tree this
    // frame (collapsed rows keep their selection only while visible - this
    // also discards pointers into trees that were removed from the project).
    selection_ = drawnSelection_;
    drawnSelection_.clear();

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
        open = storage->GetInt((int)ImGui::GetID(&node), isRoot ? 1 : 0) != 0;
    if (!open) return;
    for (const auto& c : node.children()) walk(root, *c, depth + 1, false);
}

void ExplorerPanel::drawTree(Root& root) {
    rows_.clear();
    walk(root, *root.tree, 0, true);
    // Virtualized rendering: only the rows in view are submitted, so huge
    // packages don't pay for thousands of hidden tree nodes per frame.
    ImGuiListClipper clipper;
    clipper.Begin((int)rows_.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const Row& row = rows_[(size_t)i];
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
    std::snprintf(label, sizeof label, "Decompiling... %d s", jadx.elapsedSeconds());
    // A negative fraction animates an indeterminate progress bar.
    ImGui::ProgressBar(-1.0f * (float)ImGui::GetTime(), ImVec2(-FLT_MIN, 0.f), label);
    ImGui::TextColored(ImVec4(0.85f, 0.72f, 0.35f, 1.f), "Warnings: %d", jadx.warningCount());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.f), "Errors: %d", jadx.errorCount());
    ImGui::SameLine();
    ImGui::TextDisabled("Classes processed: %d", jadx.processedCount());
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
    const int padSpaces = (int)((iconSize + ImGui::GetStyle().ItemInnerSpacing.x) / spaceW) + 1;
    char label[512];
    std::snprintf(label, sizeof label, "%*s%s", padSpaces, "", node.name().c_str());

    // Flat rendering: the depth indent is applied directly to the row's
    // cursor instead of nested TreePush/TreePop (which clipper rows can't do).
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (float)depth * ImGui::GetStyle().IndentSpacing);
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
    if (ImTextureID tex = ShellIcons::instance().iconFor(node, archiveRoot)) {
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
    const bool inSelection = selection_.count(&node) > 0;

    // Click-and-drag text selection: rows the mouse passes over while the
    // button is down are added to the selection.
    if (dragMoved_ && hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left) && !inSelection) {
        selection_.insert(&node);
        drawnSelection_.insert(&node);
    }

    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !pressNode_) pressNode_ = &node;
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
        selection_ = {&node};
        drawnSelection_.insert(&node);
        // Double click: promote to a permanent tab.
        if (jump) workspace_.navigateTo(root, node, -1, &origin);
        else workspace_.openNode(root, node, -1, Workspace::OpenMode::Permanent);
    } else if (plainClick) {
        selection_ = {&node};
        drawnSelection_.insert(&node);
        if (!node.isFolder()) {
            // Single click: open (or replace) the preview tab.
            if (jump) workspace_.navigateTo(root, node, -1, &origin);
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
    const float frac = job.total() > 0 ? (float)job.done() / (float)job.total() : 0.f;
    char label[256];
    std::snprintf(label, sizeof label, "%s (%d/%d)", job.currentName().c_str(), job.done(), job.total());
    ImGui::ProgressBar(frac, ImVec2(-FLT_MIN, 0.f), label);
    ImGui::TextDisabled("Exporting to %s - %d failed", job.destDir().c_str(), job.failed());
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) workspace_.exportJob().cancel();
}
