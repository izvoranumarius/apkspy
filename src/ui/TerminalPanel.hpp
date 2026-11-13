#pragma once
#include <functional>
#include <memory>
#include <string>
#include "core/Pty.hpp"
#include "core/VtScreen.hpp"
#include "ui/Panel.hpp"

class Settings;

// "Terminal": a real shell (PowerShell or cmd on Windows, $SHELL elsewhere) in
// a pseudo-terminal, started in the project folder with adb and jadx put
// first on PATH. Keys go to the shell; drag to select, Ctrl+C copies a
// selection (and interrupts otherwise), Ctrl+V pastes.
class TerminalPanel : public Panel {
public:
    TerminalPanel(Workspace& workspace, Settings& settings, std::function<std::string()> folder);
    ~TerminalPanel() override;

    void restart();

protected:
    void drawContents() override;

private:
    void start(int cols, int rows);
    void handleKeys();
    void drawScreen();
    std::string selectionText() const;
    std::vector<std::string> shellCommand() const;

    Settings& settings_;
    std::function<std::string()> folder_;
    std::unique_ptr<Pty> pty_;
    VtScreen screen_;
    std::string error_;
    std::string shellName_;
    bool started_ = false;
    bool followOutput_ = true;
    uint64_t drawnVersion_ = 0;
    // Selection in (line, column) of lineCount() space; -1 = none.
    long long selA_ = -1, selB_ = -1;
    int selColA_ = 0, selColB_ = 0;
    bool selecting_ = false;
};
