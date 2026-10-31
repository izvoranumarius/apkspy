#pragma once
#include "ui/Panel.hpp"

class SearchPanel : public Panel {
public:
    explicit SearchPanel(Workspace& workspace) : Panel(workspace, "Search") {}

protected:
    void drawContents() override;

private:
    char query_[256] = {};
    int mode_ = 0;       // SearchService::Mode
    int rootIdx_ = 0;    // which APK's decompiled tree to search (multi-APK projects)
};
