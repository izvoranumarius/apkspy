#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "ui/AnnotationUi.hpp"
#include "ui/Panel.hpp"

// Every bookmark and comment of the project, filterable. Double-click jumps
// to the file line or to the native address in the Analysis panel.
class BookmarksPanel : public Panel {
public:
    BookmarksPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Bookmarks"), showPanel_(std::move(showPanel)) {}

protected:
    void drawContents() override;

private:
    void rebuildRows();
    void go(const Annotation& a);
    std::string locationText(const Annotation& a) const;

    std::function<void(const std::string&)> showPanel_;
    char filter_[128] = {};
    int kindFilter_ = 0;  // 0 all, 1 bookmarks, 2 comments
    std::string appliedFilter_ = "\x01";
    int appliedKind_ = -1;
    uint64_t appliedVersion_ = 0;
    std::vector<int> rows_;  // annotation ids, sorted by location
    ui::CommentPopup popup_;
};
