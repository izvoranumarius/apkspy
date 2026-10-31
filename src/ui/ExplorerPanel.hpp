#pragma once
#include <set>
#include "ui/Panel.hpp"

// Dockable explorer window (docked at the left) with two tabs:
//  - "Files":       the APK contents straight from the archives.
//  - "Decompiled":  the jadx output trees (browsable while jadx runs).
// Both tabs group their trees by APK (one root per APK, same group name).
// Tree rows support click-and-drag multi-selection; Ctrl+C copies the
// selected items' names.
class ExplorerPanel : public Panel {
public:
    explicit ExplorerPanel(Workspace& workspace) : Panel(workspace, "Explorer") {}

protected:
    void drawContents() override;

private:
    void drawNode(Root& root, const TreeNode& node, bool isRoot);
    void drawJadxProgress();
    void drawRemoveConfirm();
    void copySelection();

    std::set<const TreeNode*> selection_;       // selected rows (re-validated against the drawn tree every frame)
    std::set<const TreeNode*> drawnSelection_;  // scratch: selection entries seen while drawing this frame
    const TreeNode* pressNode_ = nullptr;       // row the mouse went down on (open fires on release, so drags can select)
    bool dragMoved_ = false;                    // mouse moved past the drag threshold since the press
    bool hoveredAny_ = false;                   // any tree row hovered this frame (empty-space click clears selection)
    Root* removeRequest_ = nullptr;             // APK awaiting "Remove from project?" confirmation
    // One-shot tab switch request: 0 = Files, 1 = Decompiled,
    // -1 = keep whatever the user selected. Cleared every frame.
    int selectTab_ = -1;
};
