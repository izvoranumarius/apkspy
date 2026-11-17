#include "ui/TrafficPanel.hpp"
#include <algorithm>
#include <cstdio>
#include <ctime>
#include "app/Theme.hpp"
#include "core/TextUtils.hpp"
#include "mcp/Json.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

void TrafficPanel::refreshCodeStrings() {
    // URL / path constants of every analysed APK, for the "in code" column.
    // Collecting them takes a large part of a second, so it runs off the UI thread.
    if (codeStringsJob_.valid() && codeStringsJob_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        codeStrings_ = codeStringsJob_.get();
        inCodeCache_.clear();
    }
    const void* owner = nullptr;
    std::vector<std::shared_ptr<const ApkAnalysis>> analyses;
    for (Root* r : workspace_.apkRoots())
        if (auto a = workspace_.analysis().get(r->title)) {
            analyses.push_back(a);
            owner = a.get();
        }
    if (owner == codeStringsOwner_ && (owner || codeStrings_.empty())) return;
    if (codeStringsJob_.valid()) return;  // one at a time; the newest set is picked up afterwards
    codeStringsOwner_ = owner;
    codeStrings_.clear();
    inCodeCache_.clear();
    if (analyses.empty()) return;
    codeStringsJob_ = std::async(std::launch::async, [analyses = std::move(analyses)] {
        std::vector<std::string> out;
        for (const auto& a : analyses)
            for (auto cat : {ApkAnalysis::StringCategory::Url, ApkAnalysis::StringCategory::Path,
                             ApkAnalysis::StringCategory::Ip})
                for (const auto& s : a->strings({}, cat, 20000)) out.push_back(tex::asciiLower(s.value));
        return out;
    });
}

bool TrafficPanel::inCode(const std::string& host, const std::string& path) {
    // Asked for every row on every frame, and each answer scans all the strings.
    const auto cached = inCodeCache_.find(host + '\n' + path);
    if (cached != inCodeCache_.end()) return cached->second;
    const std::string h = tex::asciiLower(host);
    // Path templates match up to their first placeholder ("/users/{id}" -> "/users/").
    const std::string p = tex::asciiLower(path.substr(0, std::min(path.find('?'), path.find('{'))));
    bool found = false;
    for (const std::string& s : codeStrings_) {
        found = (!h.empty() && s.find(h) != std::string::npos) || (p.size() > 1 && s.find(p) != std::string::npos);
        if (found) break;
    }
    inCodeCache_[host + '\n' + path] = found;
    return found;
}

void TrafficPanel::drawContents() {
    loadRules();  // before the first capture: the proxy rewrites from the start
    for (auto& [label, text] : workspace_.takeComparerRequests()) sendToComparer(std::move(label), std::move(text));
    drawToolbar();
    TrafficProxy& proxy = devices_.traffic();
    // Incremental refresh of the summary rows.
    if (proxy.lastId() != rowsHead_ || rows_.empty()) {
        std::vector<TrafficProxy::Flow> fresh = proxy.flows(0);
        rows_.swap(fresh);
        rowsHead_ = proxy.lastId();
    } else {
        // In-progress flows update their status / sizes: refresh the tail.
        bool open = false;
        for (const auto& r : rows_) open |= !r.complete;
        if (open && ImGui::GetFrameCount() % 15 == 0) rows_ = proxy.flows(0);
    }
    refreshCodeStrings();
    if (!ImGui::BeginTabBar("##trafficTabs", ImGuiTabBarFlags_FittingPolicyScroll)) return;
    if (ImGui::BeginTabItem("Requests")) {
        drawRequests();
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Endpoints")) {
        drawEndpoints();
        ImGui::EndTabItem();
    }
    const size_t waiting = proxy.heldCount();
    const std::string interceptLabel = waiting ? "Intercept (" + std::to_string(waiting) + " waiting)###intercept" : std::string("Intercept###intercept");
    if (waiting) ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::Warning));
    const bool interceptOpen = ImGui::BeginTabItem(interceptLabel.c_str());
    if (waiting) ImGui::PopStyleColor();
    if (interceptOpen) {
        drawIntercept();
        ImGui::EndTabItem();
    }
    const size_t activeRules = std::count_if(rules_.begin(), rules_.end(), [](const auto& r) { return r.enabled; });
    const std::string rulesLabel = activeRules ? "Match & Replace (" + std::to_string(activeRules) + ")###rules" : std::string("Match & Replace###rules");
    if (ImGui::BeginTabItem(rulesLabel.c_str())) {
        drawRules();
        ImGui::EndTabItem();
    }
    const std::string comparerLabel =
        compareItems_.empty() ? std::string("Comparer###comparer") : "Comparer (" + std::to_string(compareItems_.size()) + ")###comparer";
    if (ImGui::BeginTabItem(comparerLabel.c_str(), nullptr, showComparer_ ? ImGuiTabItemFlags_SetSelected : 0)) {
        drawComparer();
        ImGui::EndTabItem();
    }
    showComparer_ = false;
    const std::string repeaterLabel = repeater_.empty() ? std::string("Repeater###repeater")
                                                        : "Repeater (" + std::to_string(repeater_.size()) + ")###repeater";
    if (ImGui::BeginTabItem(repeaterLabel.c_str(), nullptr, showRepeater_ ? ImGuiTabItemFlags_SetSelected : 0)) {
        drawRepeater();
        ImGui::EndTabItem();
    }
    showRepeater_ = false;
    ImGui::EndTabBar();
}

void TrafficPanel::drawToolbar() {
    TrafficProxy& proxy = devices_.traffic();
    if (!devicesRequested_) {
        devicesRequested_ = true;
        devices_.refreshDevices();
    }
    const std::vector<adb::Device> devices = devices_.devices();
    std::string serial = devices_.selected();
    if (serial.empty())
        for (const auto& d : devices)
            if (d.state == "device") {
                serial = d.serial;
                devices_.select(serial);
                break;
            }
    // One action: capture starts the proxy and routes the device, stop undoes both.
    if (proxy.running()) {
        if (ImGui::Button("Stop capture")) {
            devices_.stopTraffic();
            status_.clear();
        }
    } else {
        ImGui::BeginDisabled(serial.empty());
        if (ImGui::Button("Start capture")) {
            std::string err;
            if (!proxy.start(settings_.getInt(Settings::kTrafficPort, 8899), err)) status_ = err;
            else status_ = proxy.routeDevice(devices_.adb(), serial, err) ? std::string() : "Could not route the device: " + err;
        }
        ImGui::EndDisabled();
        if (serial.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("No device connected");
    }
    if (devices.size() > 1) {
        std::string current = serial;
        for (const auto& d : devices)
            if (d.serial == serial && !d.model.empty()) current = d.model;
        ui::sameLineIfFits(ui::em(10.f));
        ImGui::SetNextItemWidth(ui::em(10.f));
        ImGui::BeginDisabled(proxy.running());
        if (ImGui::BeginCombo("##device", current.c_str())) {
            for (const auto& d : devices)
                if (ImGui::Selectable(d.model.empty() ? d.serial.c_str() : d.model.c_str(), d.serial == serial)) devices_.select(d.serial);
            ImGui::EndCombo();
        }
        ImGui::EndDisabled();
    }
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-ui::buttonWidth("...") - ImGui::GetStyle().ItemSpacing.x);
    ImGui::InputTextWithHint("##tfilter", "Filter host, path, method or status...", filter_, sizeof filter_);
    ImGui::SameLine();
    if (ImGui::Button("...##trafficopts")) ImGui::OpenPopup("##trafficopts");
    if (ImGui::BeginPopup("##trafficopts")) {
        ImGui::Checkbox("Hide HTTPS connections", &hideTunnels_);
        if (ImGui::MenuItem("Clear captured requests")) {
            proxy.clear();
            rows_.clear();
            marks_.clear();
            bodyHits_.clear();
            selected_ = detailId_ = 0;
        }
        // Recovery when a crash left the device pointing at a proxy that is gone.
        if (ImGui::MenuItem("Reset device proxy", nullptr, false, !serial.empty() && !proxy.running())) {
            std::string err;
            status_ = proxy.restoreDevice(devices_.adb(), serial, err) ? std::string() : "Reset failed: " + err;
        }
        ImGui::EndPopup();
    }
    if (!status_.empty()) ui::wrappedColored(kWarn, status_);
}

void TrafficPanel::drawDetail() {
    // Refetch while the flow is still running, otherwise keep the snapshot.
    if (detailId_ != selected_ || !detail_.complete) {
        if (!devices_.traffic().flow(selected_, detail_)) {
            selected_ = 0;
            return;
        }
        detailId_ = selected_;
    }
    const TrafficProxy::Flow& f = detail_;
    ImGui::Separator();
    ImGui::BeginChild("##flowDetail", ImVec2(0, 0), ImGuiChildFlags_None);
    ui::wrappedColored(kAccent, f.method + " " + f.url());
    char line[256];
    std::snprintf(line, sizeof line, "status %d | %s up, %s down | %.0f ms%s%s", f.status, humanBytes(f.bytesUp).c_str(),
                  humanBytes(f.bytesDown).c_str(), f.durationMs, f.error.empty() ? "" : " | ", f.error.c_str());
    ui::wrappedColored(kDim, line);
    if (ui::smallButton("Send to Repeater")) sendToRepeater(f);
    if (!f.tunnel && ui::flowSmallButton("Response to Comparer"))
        sendToComparer(std::to_string(f.status) + " " + f.url(), messageText(f.response));
    if (ui::flowSmallButton("Copy URL")) ImGui::SetClipboardText(f.url().c_str());
    if (!f.tunnel && ui::flowSmallButton("Copy as cURL")) ImGui::SetClipboardText(TrafficProxy::curl(f).c_str());
    if (ui::flowSmallButton("Close")) selected_ = 0;
    if (f.tunnel) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled(
            "Encrypted HTTPS tunnel to %s:%d%s%s. ApkSpy relays the TLS bytes without decrypting them, so request "
            "and response contents are not visible - only the destination, timing and sizes.",
            f.host.c_str(), f.port, f.sni.empty() ? "" : ", server name ", f.sni.c_str());
        ImGui::PopTextWrapPos();
    } else if (ImGui::BeginTabBar("##rr")) {
        if (ImGui::BeginTabItem("Request")) {
            ImGui::BeginChild("##req");
            drawMessage("req", f.request);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Response")) {
            ImGui::BeginChild("##resp");
            drawMessage("resp", f.response);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();
}

void TrafficPanel::drawEndpoints() {
    const std::vector<TrafficProxy::Endpoint> eps = devices_.traffic().endpoints();
    if (eps.empty()) {
        ImGui::TextDisabled("Endpoints appear here once traffic is captured.");
        return;
    }
    if (codeStrings_.empty())
        ui::wrappedColored(kDim, "Open the Analysis workspace to mark endpoints that also appear in the code.");
    if (ImGui::BeginTable("##eps", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                          ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.5f);
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, ui::em(2.5f));
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        ImGui::TableSetupColumn("In code", ImGuiTableColumnFlags_WidthFixed, ui::em(3.5f));
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < eps.size(); ++i) {
            const auto& e = eps[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (ImGui::Selectable(e.method.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                selected_ = e.lastFlow;  // jump to the latest request of this endpoint
                std::snprintf(filter_, sizeof filter_, "%s", e.host.c_str());
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.host.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.tunnel ? "(TLS)" : e.pathTemplate.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%d", e.count);
            ImGui::TableNextColumn();
            std::string st;
            for (int s : e.statuses) st += (st.empty() ? "" : ",") + std::to_string(s);
            ImGui::TextDisabled("%s", st.c_str());
            ImGui::TableNextColumn();
            if (inCode(e.host, e.pathTemplate)) ImGui::TextColored(kGood, "yes");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}
