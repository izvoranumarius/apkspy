#pragma once
#include <vector>
#include "ui/Panel.hpp"

class OutputPanel : public Panel {
public:
    explicit OutputPanel(Workspace& workspace) : Panel(workspace, "Output") {}

protected:
    void drawContents() override;

private:
    int filter_ = 0;  // 0 all, 1 warnings, 2 errors
    size_t lastCount_ = 0;
    int lastFilter_ = -1;          // filter used to build index_
    std::vector<int> index_;       // log line indices matching the filter
    std::vector<char> severities_; // classified severity per line (cache)
    size_t classifiedCount_ = 0;   // how many lines severities_ covers
};
