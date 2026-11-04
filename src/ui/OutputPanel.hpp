#pragma once
#include <vector>
#include "ui/Panel.hpp"
#include "ui/UiUtil.hpp"

class OutputPanel : public Panel {
public:
    explicit OutputPanel(Workspace& workspace) : Panel(workspace, "Output") {}

protected:
    void drawContents() override;

private:
    int filter_ = 0;  // 0 all, 1 warnings, 2 errors
    int source_ = 0;  // 0 all, else 1 + index into logsev::kSources
    size_t lastCount_ = 0;
    size_t lastTrims_ = 0;
    int lastFilter_ = -1;          // filters used to build index_
    int warnings_ = 0;
    int errors_ = 0;
    std::vector<int> index_;       // log line indices matching the filter
    std::vector<char> severities_; // classified severity per line (cache)
    size_t classifiedCount_ = 0;   // how many lines severities_ covers
    ui::RowSelection selection_;   // rows of index_ (reset when the index is rebuilt)
};
