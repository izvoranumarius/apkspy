#pragma once
#include <string>
#include "imgui.h"
#include "imgui_internal.h"
#include "core/Workspace.hpp"

class Panel {
public:
    Panel(Workspace& workspace, std::string title) : workspace_(workspace), title_(std::move(title)) {}
    virtual ~Panel() = default;

    // One panel has a window per workspace layout: `windowName` picks which.
    // Panels come and go through View > Panels, so docks carry no menu or close buttons.
    void render(const std::string& windowName) {
        ImGuiWindowClass plain;
        plain.DockNodeFlagsOverrideSet = ImGuiDockNodeFlags_NoWindowMenuButton | ImGuiDockNodeFlags_NoCloseButton;
        ImGui::SetNextWindowClass(&plain);
        if (ImGui::Begin(windowName.c_str())) drawContents();
        ImGui::End();
    }

    const std::string& title() const { return title_; }

protected:
    virtual void drawContents() = 0;

    Workspace& workspace_;

private:
    std::string title_;
};
