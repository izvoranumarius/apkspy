#pragma once
#include <chrono>
#include <functional>
#include <string>
#include <vector>
#include "debug/DeviceService.hpp"
#include "ui/Panel.hpp"
#include "ui/UiUtil.hpp"

// "Devices": adb devices, their processes (debuggable ones marked) and a live
// CPU / memory / thread monitor of one process.
class DevicesPanel : public Panel {
public:
    DevicesPanel(Workspace& workspace, DeviceService& devices, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Devices"), devices_(devices), showPanel_(std::move(showPanel)) {}

protected:
    void drawContents() override;

private:
    void drawMonitor();
    void attach(const std::string& serial, int pid);
    DeviceService& devices_;
    std::function<void(const std::string&)> showPanel_;
    char filter_[128] = {};
    bool onlyDebuggable_ = false;
    bool showKernel_ = false;  // kernel threads ([kworker/...], children of kthreadd)
    bool firstRefresh_ = true;
    std::chrono::steady_clock::time_point lastAutoRefresh_{};
};

// "Debugger": JDWP execution control (x64dbg-style toolbar + F-key
// shortcuts), threads, call stack, locals, breakpoints and the event log.
class DebuggerPanel : public Panel {
public:
    DebuggerPanel(Workspace& workspace, DeviceService& devices) : Panel(workspace, "Debugger"), devices_(devices) {}
    // Global debugger keys (F7/F8/F9/F12), active while a session is attached
    // and no text field has focus. Called by the application every frame.
    void processShortcuts();

protected:
    void drawContents() override;

private:
    void followFrame(const DebugSession::FrameRow& frame);
    DeviceService& devices_;
    std::string followed_;  // frame last shown in the editor
    char bpClass_[256] = {};
    char bpMethod_[128] = {};
    char bpLine_[12] = {};
    bool excCaught_ = true;
    bool excUncaught_ = true;
};

// "Logcat": streaming device log with level / pid / tag / text filters,
// pause and auto-scroll. Reads from DeviceService's bounded ring buffer.
class LogcatPanel : public Panel {
public:
    LogcatPanel(Workspace& workspace, DeviceService& devices) : Panel(workspace, "Logcat"), devices_(devices) {}

protected:
    void drawContents() override;

private:
    DeviceService& devices_;
    int level_ = 0;  // index into V D I W E F
    char query_[256] = {};  // the filter box; the three below are parsed from it
    char tag_[128] = {};
    char text_[256] = {};
    int pid_ = 0;
    bool paused_ = false;
    bool autoScroll_ = true;
    std::vector<DeviceService::LogEntry> view_;
    uint64_t viewHead_ = 0;
    std::string viewKey_;
    std::string error_;
    ui::RowSelection selection_;  // rows of view_
};
