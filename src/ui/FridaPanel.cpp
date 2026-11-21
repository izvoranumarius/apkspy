#include "ui/FridaPanel.hpp"
#include <algorithm>
#include "app/Theme.hpp"
#include "ui/UiUtil.hpp"

void FridaPanel::start() {
    error_.clear();
    const std::string serial = devices_.selected();
    if (serial.empty()) {
        error_ = "Select a device first (Devices panel).";
        return;
    }
    bool ok = false;
    if (mode_ == 0) {
        if (package_[0] == '\0') {
            error_ = "Enter the app package to spawn (e.g. com.example.app).";
            return;
        }
        ok = frida_.spawn(serial, package_, scriptPath_, error_);
    } else {
        if (process_[0] == '\0') {
            error_ = "Enter the process name or PID to attach to.";
            return;
        }
        ok = frida_.attach(serial, process_, scriptPath_, error_);
    }
    if (!ok && error_.empty()) error_ = "could not start Frida (is the 'frida' CLI installed?)";
}

void FridaPanel::deployServer(const std::string& binary) {
    const std::string serial = devices_.selected();
    if (serial.empty()) {
        serverStatus_ = "Select a device first.";
        return;
    }
    std::string err;
    const std::string remote = "/data/local/tmp/frida-server";
    if (!fridaserver::deploy(devices_.adbPath(), serial, binary, remote, err)) {
        serverStatus_ = "deploy failed: " + err;
        return;
    }
    // Run it; the ChildProcess keeps the server alive until stopped.
    serverProc_ = ChildProcess::spawn(fridaserver::runArgv(devices_.adbPath(), serial, remote));
    serverStarted_ = serverProc_.valid();
    serverStatus_ = serverStarted_ ? "frida-server deployed and started" : "deployed, but could not start it";
}

void FridaPanel::drawContents() {
    // frida-server deployment.
    const std::string serial = devices_.selected();
    const auto now = std::chrono::steady_clock::now();
    if (!serial.empty() && now - lastServerCheck_ > std::chrono::seconds(3)) {
        lastServerCheck_ = now;
        serverRunning_ = fridaserver::running(devices_.adbPath(), serial);
    }
    ImGui::TextUnformatted("frida-server:");
    ImGui::SameLine();
    if (serverRunning_) ImGui::TextColored(theme::vec(Col::Success), "running on device");
    else ImGui::TextColored(theme::vec(Col::TextMuted), "not detected");
    ImGui::SameLine();
    if (ui::smallButton("Deploy & start...")) serverBrowser_.open(FileBrowser::Mode::OpenFile);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Push a frida-server binary (matching the device ABI and your frida version) and run it");
    if (serverStarted_) {
        ImGui::SameLine();
        if (ui::smallButton("Stop server")) {
            serverProc_.killProcess();
            serverStarted_ = false;
            serverStatus_ = "frida-server stopped";
        }
    }
    std::string srvPicked;
    if (serverBrowser_.render(), serverBrowser_.takeAccepted(srvPicked)) deployServer(srvPicked);
    if (!serverStatus_.empty()) ImGui::TextDisabled("%s", serverStatus_.c_str());
    ImGui::Separator();

    // Device selector (shared with the other device panels).
    const std::vector<adb::Device> devices = devices_.devices();
    std::string selected = devices_.selected();
    std::string current = selected.empty() ? "(select a device)" : selected;
    for (const auto& d : devices)
        if (d.serial == selected && !d.model.empty()) current = d.model + "  [" + d.serial + "]";
    ImGui::SetNextItemWidth(ui::em(16.f));
    if (ImGui::BeginCombo("##fdev", current.c_str())) {
        for (const auto& d : devices) {
            const std::string label = (d.model.empty() ? d.serial : d.model + "  [" + d.serial + "]") + "  - " + d.state;
            if (ImGui::Selectable(label.c_str(), d.serial == selected, d.state == "device" ? 0 : ImGuiSelectableFlags_Disabled))
                devices_.select(d.serial);
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ui::smallButton("Refresh devices")) devices_.refreshDevices();

    // Spawn / attach.
    ImGui::RadioButton("Spawn", &mode_, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Attach", &mode_, 1);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(20.f));
    if (mode_ == 0) ImGui::InputTextWithHint("##pkg", "app package, e.g. com.example.app", package_, sizeof package_);
    else ImGui::InputTextWithHint("##proc", "process name or PID", process_, sizeof process_);

    // Optional script.
    ImGui::SetNextItemWidth(ui::em(24.f));
    const std::string scriptLabel = scriptPath_.empty() ? std::string("(default hook script)") : scriptPath_;
    ImGui::TextDisabled("Script: %s", scriptLabel.c_str());
    ImGui::SameLine();
    if (ui::smallButton("Choose...")) scriptBrowser_.open(FileBrowser::Mode::OpenFile);
    if (!scriptPath_.empty()) {
        ImGui::SameLine();
        if (ui::smallButton("Clear##script")) scriptPath_.clear();
    }
    std::string picked;
    if (scriptBrowser_.render(), scriptBrowser_.takeAccepted(picked)) scriptPath_ = picked;

    const bool running = frida_.running();
    if (!running) {
        if (ImGui::Button("Start")) start();
    } else {
        if (ImGui::Button("Stop")) frida_.stop();
        ImGui::SameLine();
        ImGui::TextColored(theme::vec(Col::Success), "session running");
    }
    ImGui::SameLine();
    if (ui::smallButton("Clear log")) {
        events_.clear();
        shown_ = frida_.head();
    }
    if (!error_.empty()) ui::wrappedColored(theme::vec(Col::Error), error_);

    // Drain new events.
    frida_.poll();
    for (auto& e : frida_.events(shown_, 1000)) {
        shown_ = std::max(shown_, e.seq);
        events_.push_back(std::move(e));
    }
    if (events_.size() > FridaBridge::kMaxEvents)
        events_.erase(events_.begin(), events_.begin() + (events_.size() - FridaBridge::kMaxEvents));

    ImGui::Separator();
    ImGui::BeginChild("##fridalog", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushFont(Theme::monoFont());
    for (const auto& e : events_) {
        const ImVec4 col = e.tag == "error"  ? theme::vec(Col::Error)
                           : e.tag == "send" ? theme::vec(Col::Info)
                                             : theme::vec(Col::Text);
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextUnformatted(e.message.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::PopFont();
    if (autoScroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.f) ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
}
