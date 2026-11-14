#pragma once
#include "app/Icons.hpp"
#include "app/Theme.hpp"
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
    // The label shows an icon before the title; the ID after ### stays the same.
    std::string windowName(const std::string& title) const {
        const char* glyph = panelIcon(title);
        const std::string label = glyph && Theme::hasIcons() ? std::string(glyph) + "  " + title : title;
        return label + "###" + name + "/" + title;
    }
    static const char* panelIcon(const std::string& title) {
        static const std::pair<const char*, const char*> kIcons[] = {
            {"Explorer", icons::FOLDER}, {"Overview", icons::INFO}, {"Editor", icons::FILE},
            {"Search", icons::SEARCH}, {"Bookmarks", icons::BOOKMARK}, {"Output", icons::PAGE},
            {"Analysis", icons::ANALYSIS}, {"Function", icons::CODE}, {"References", icons::LINK}, {"Decompiler", icons::FILE},
            {"Devices", icons::PHONE}, {"Debugger", icons::BUG}, {"Logcat", icons::LIST},
            {"Traffic", icons::GLOBE}, {"Script", icons::EDIT}, {"Terminal", icons::TERMINAL},
        };
        for (const auto& [t, glyph] : kIcons)
            if (title == t) return glyph;
        return nullptr;
    }
    static const char* workspaceIcon(const std::string& workspace) {
        if (workspace == "Code") return icons::FILE;
        if (workspace == "Analysis") return icons::ANALYSIS;
        if (workspace == "Debug") return icons::BUG;
        if (workspace == "Network") return icons::GLOBE;
        if (workspace == "Scripts") return icons::CODE;
        return nullptr;
    }
    std::string dockName() const { return "Dock/" + name; }
    void resetVisibility(const std::vector<std::string>& allPanels) {
        for (const std::string& title : allPanels) visible[title] = false;
        for (const std::string& title : defaultPanels) visible[title] = true;
    }
};
