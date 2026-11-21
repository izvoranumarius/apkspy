#pragma once
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
#include "core/ScriptRunner.hpp"
#include "debug/DeviceService.hpp"
#include "debug/FridaBridge.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

// "Frida": runtime instrumentation through the external `frida` CLI. Spawn an
// app (start it under Frida) or attach to a running process, load JS hooking
// scripts, and watch the console/send() output as events.
//
// Prerequisites (surfaced as errors, nothing else degrades): the `frida` CLI
// on PATH and a matching frida-server running on the device.
class FridaPanel : public Panel {
public:
    FridaPanel(Workspace& workspace, DeviceService& devices) : Panel(workspace, "Frida"), devices_(devices) {}

protected:
    void drawContents() override;
    bool codeArea() const override { return true; }

private:
    void start();
    void deployServer(const std::string& binary);
    DeviceService& devices_;
    ScriptRunner runner_;
    FridaBridge frida_{runner_};
    int mode_ = 0;  // 0 spawn (-f package), 1 attach (-n process)
    char package_[256] = {};
    char process_[256] = {};
    std::string scriptPath_;
    FileBrowser scriptBrowser_;
    std::string error_;
    bool autoScroll_ = true;
    uint64_t shown_ = 0;
    std::vector<FridaBridge::Event> events_;

    // frida-server lifecycle (owned here while it runs).
    FileBrowser serverBrowser_;
    ChildProcess serverProc_;
    bool serverStarted_ = false;
    std::string serverStatus_;
    std::chrono::steady_clock::time_point lastServerCheck_{};
    bool serverRunning_ = false;
};
