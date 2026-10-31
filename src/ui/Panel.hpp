#pragma once
#include <string>
#include "imgui.h"
#include "core/Workspace.hpp"

class Panel {
public:
    Panel(Workspace& workspace, std::string title) : workspace_(workspace), title_(std::move(title)) {}
    virtual ~Panel() = default;

    void render() {
        if (!visible_) return;
        if (ImGui::Begin(title_.c_str(), &visible_)) drawContents();
        ImGui::End();
    }

    const std::string& title() const { return title_; }
    bool* visiblePtr() { return &visible_; }

protected:
    virtual void drawContents() = 0;

    Workspace& workspace_;

private:
    std::string title_;
    bool visible_ = true;
};
