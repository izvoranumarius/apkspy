#pragma once
#include <set>
#include <vector>
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"
#include "core/TreeNode.hpp"

struct Root;

// Dockable explorer window (docked at the left) with two tabs:
//  - "Files":       the APK contents straight from the archives.
//  - "Decompiled":  the jadx output trees (browsable while jadx runs).
// Both tabs group their trees by APK (one root per APK, same group name).
// Tree rows support click-and-drag multi-selection; Ctrl+C copies the
// selected items' names. Rows are virtualized: only the visible rows are
// submitted to ImGui, so packages with thousands of classes stay smooth.
class ExplorerPanel : public Panel {
public:
    explicit ExplorerPanel(Workspace& workspace) : Panel(workspace, "Explorer") {}

protected:
    void drawContents() override;

private:
    struct Row {
        Root* root;
        const TreeNode* node;
        int depth;
        bool isRoot;
    };

    // Depth-first walk of one tree, following only open folders; fills rows_
    // and re-validates the selection (entries pointing at nodes that are not
    // part of the walked tree are dropped at the end of the frame).
    void walk(Root& root, const TreeNode& node, int depth, bool isRoot);
    void drawRow(Root& root, const TreeNode& node, int depth, bool isRoot);
    void drawTree(Root& root);
    bool revealTabSet_ = false;  // the reveal's tab was requested
    void drawJadxProgress();
    void drawRemoveConfirm();
    void drawExportProgress();
    void copySelection();
    // M5 export helpers: open the matching browser, then export on accept.
    void openExportFile(Root& root, const TreeNode& node, bool decoded);
    void openExportFolder(Root& root, const TreeNode& node, bool decoded);

    std::vector<Row> rows_;                  // flat list of visible rows (rebuilt per frame)
    std::set<const TreeNode*> selection_;    // selected rows (re-validated against the walked tree every frame)
    std::set<const TreeNode*> drawnSelection_;  // scratch: selection entries seen while walking this frame
    const TreeNode* pressNode_ = nullptr;    // row the mouse went down on (open fires on release, so drags can select)
    bool dragMoved_ = false;                 // mouse moved past the drag threshold since the press
    // Replaces the whole selection (keeps drawnSelection_ in sync, which
    // otherwise re-applies the previous selection at the end of the frame).
    void setSelection(std::set<const TreeNode*> nodes);
    // Rows [a, b] of the tree `root` (inclusive, any order) as a selection.
    std::set<const TreeNode*> rowRange(const Root* root, const TreeNode* a, const TreeNode* b) const;
    const TreeNode* anchorNode_ = nullptr;   // Shift+click / drag range anchor
    const Root* pressRoot_ = nullptr;        // tree the press happened in
    std::vector<Row> allRows_;               // rows of every tree drawn this frame (range selection)
    bool hoveredAny_ = false;                // any tree row hovered this frame (empty-space click clears selection)
    Root* removeRequest_ = nullptr;          // APK awaiting "Remove from project?" confirmation
    FileBrowser exportFileBrowser_;          // single-file export target (M5)
    FileBrowser exportFolderBrowser_;        // folder export target (M5)
    struct ExportRequest {
        Root* root = nullptr;
        const TreeNode* node = nullptr;
        bool decoded = false;
        bool folder = false;
    };
    ExportRequest exportRequest_;            // consumed when the browser accepts
    // One-shot tab switch request: 0 = Files, 1 = Decompiled,
    // -1 = keep whatever the user selected. Cleared every frame.
    int selectTab_ = -1;
};
