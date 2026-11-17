#pragma once
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "core/Pty.hpp"
#include "core/VtScreen.hpp"
#include "ui/Panel.hpp"

class Settings;

// "Terminal": real shells (PowerShell or cmd on Windows, $SHELL elsewhere) in
// pseudo-terminals, started in the project folder with adb and jadx put first
// on PATH. As in VS Code there can be several, one per tab: + (or
// Ctrl+Shift+`) opens another, the tab's x ends it, double-click renames it.
// Keys go to the shell; drag to select (double-click: a word), Ctrl+C copies a
// selection (and interrupts otherwise), Ctrl+Shift+C copies, Ctrl+V pastes.
class TerminalPanel : public Panel {
public:
    TerminalPanel(Workspace& workspace, Settings& settings, std::function<std::string()> folder);
    ~TerminalPanel() override;

    void restart();      // the active terminal's shell
    void newTerminal();  // opens (and shows) another one on the next frame
    void killActive();   // ends the active terminal and closes its tab
    size_t count() const { return sessions_.size(); }

protected:
    void drawContents() override;

private:
    // One shell and its screen.
    struct Session {
        int id = 0;
        std::string title;  // user's name, or "" for the shell's
        std::unique_ptr<Pty> pty;
        VtScreen screen;
        std::string error;
        std::string shellName;
        bool started = false;
        bool followOutput = true;
        uint64_t drawnVersion = 0;
        // Selection in (line, column) of lineCount() space; -1 = none.
        long long selA = -1, selB = -1;
        int selColA = 0, selColB = 0;
        bool selecting = false;
        std::string label() const;
    };

    Session& add();
    void start(Session& s, int cols, int rows);
    void drawTabs();
    void handleKeys(Session& s);
    void drawScreen(Session& s);
    static std::string selectionText(const Session& s);
    std::vector<std::string> shellCommand() const;

    Settings& settings_;
    std::function<std::string()> folder_;
    std::vector<std::unique_ptr<Session>> sessions_;
    int active_ = -1;          // id of the shown session
    int selectTab_ = -1;       // id of the tab to select on the next frame
    int nextId_ = 1;
    int renaming_ = -1;        // id of the session being renamed
    bool openRename_ = false;
    char renameBuf_[64] = {};
    bool focusTerminal_ = false;
};
