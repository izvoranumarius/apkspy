#pragma once
#include "ui/Panel.hpp"

// Find in project: searches the decompiled sources. Laid out as a sidebar
// (next to the Explorer, as in VS Code): query and options stacked, hits
// grouped under their file. Ctrl+Shift+F brings it up with the query focused.
class SearchPanel : public Panel {
public:
    explicit SearchPanel(Workspace& workspace) : Panel(workspace, "Search") {}

    // Puts the keyboard in the query box the next time the panel draws.
    void focusQuery() { focusQuery_ = true; }

protected:
    void drawContents() override;

private:
    char query_[256] = {};
    int mode_ = 0;       // SearchService::Mode
    int rootIdx_ = 0;    // which APK's decompiled tree to search (multi-APK projects)
    bool focusQuery_ = false;
};
