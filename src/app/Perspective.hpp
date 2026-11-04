#pragma once
#include <map>
#include <string>
#include <vector>

// A task-focused arrangement of the panels, shown to the user as a workspace
// (Code, Analysis, Debug, ...). Not to be confused with core/Workspace, the
// project model. Each perspective has its own dock tree and its own ImGui
// window per panel, so ImGui persists every arrangement independently in the
// one ini file. Panel objects, and so their state, are shared by all of them.
struct Perspective {
    std::string name;
    std::string description;
    std::string mainPanel;  // takes the focus when the workspace opens
    std::vector<std::string> defaultPanels;
    std::map<std::string, bool> visible;  // by panel title

    bool shows(const std::string& title) const {
        auto it = visible.find(title);
        return it != visible.end() && it->second;
    }
    // ImGui window of a panel here: same tab label, an ID of its own.
    std::string windowName(const std::string& title) const { return title + "###" + name + "/" + title; }
    std::string dockName() const { return "Dock/" + name; }
    void resetVisibility(const std::vector<std::string>& allPanels) {
        for (const std::string& title : allPanels) visible[title] = false;
        for (const std::string& title : defaultPanels) visible[title] = true;
    }
};
