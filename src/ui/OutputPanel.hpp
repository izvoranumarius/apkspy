#pragma once
#include "ui/Panel.hpp"

class OutputPanel : public Panel {
public:
    explicit OutputPanel(Workspace& workspace) : Panel(workspace, "Output") {}

protected:
    void drawContents() override;

private:
    int filter_ = 0;  // 0 all, 1 warnings, 2 errors
    size_t lastCount_ = 0;
};
