#pragma once
#include <chrono>
#include <future>
#include <string>
#include <unordered_map>
#include <vector>
#include "core/Settings.hpp"
#include "debug/DeviceService.hpp"
#include "ui/Panel.hpp"

// "Traffic": network sniffer. Starts the local proxy, routes the selected
// device through it, and lists every request (method, host, path, status,
// size, time) with full headers / bodies for plain HTTP and host / SNI /
// byte counts for HTTPS tunnels. The Endpoints view groups requests into an
// API map (host + method + path template) and marks endpoints whose host or
// path also appears in the APK's bytecode strings.
class TrafficPanel : public Panel {
public:
    TrafficPanel(Workspace& workspace, DeviceService& devices, Settings& settings)
        : Panel(workspace, "Traffic"), devices_(devices), settings_(settings) {}

protected:
    void drawContents() override;

private:
    void drawToolbar();
    void drawRequests();
    void drawDetail();
    void drawEndpoints();
    bool inCode(const std::string& host, const std::string& path);
    void refreshCodeStrings();

    DeviceService& devices_;
    Settings& settings_;
    char filter_[256] = {};
    bool hideTunnels_ = false;
    bool devicesRequested_ = false;
    std::vector<TrafficProxy::Flow> rows_;
    uint64_t rowsHead_ = 0;
    uint64_t selected_ = 0;
    TrafficProxy::Flow detail_;
    uint64_t detailId_ = 0;
    std::string status_;
    // Lower-cased URL / path strings from the bytecode analyses.
    std::vector<std::string> codeStrings_;
    std::future<std::vector<std::string>> codeStringsJob_;
    std::unordered_map<std::string, bool> inCodeCache_;
    const void* codeStringsOwner_ = nullptr;
};
