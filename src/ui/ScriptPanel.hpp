#pragma once
#include <string>
#include <vector>
#include "core/ScriptRunner.hpp"
#include "ui/Panel.hpp"

class McpHost;
class Settings;

// "Script": edit and run Python scripts against the open project. Scripts use
// the installed Python and reach ApkSpy through a private MCP endpoint, so
// every MCP tool is a function of the `apkspy` module. Files live in the
// ApkSpy config folder; nothing runs until Run is pressed.
class ScriptPanel : public Panel {
public:
    ScriptPanel(Workspace& workspace, Settings& settings, McpHost& mcp);
    bool running() const { return runner_.running(); }
    void pollOutput();  // every frame: a script keeps reporting from any workspace

protected:
    void drawContents() override;

private:
    void refreshFiles();
    void openFile(const std::string& name);
    bool saveFile();
    void run();
    void drawNewFilePopup();
    void drawSource();
    void report(std::string line) { workspace_.log(std::move(line), "scripts"); }

    Settings& settings_;
    McpHost& mcp_;
    ScriptRunner runner_;
    bool wasRunning_ = false;
    std::vector<std::string> files_;
    std::string current_;  // file name inside the scripts folder
    std::string text_;
    bool dirty_ = false;
    bool loaded_ = false;
    double lastEdit_ = 0.0;
    char newName_[64] = {};
    bool openNewPopup_ = false;
    std::string ranName_;  // the script the last run started
    // Per line, refreshed when the text changes.
    std::vector<size_t> lineStarts_;
    std::vector<char> lineInString_;  // starts inside a triple-quoted string
    bool linesStale_ = true;
};
