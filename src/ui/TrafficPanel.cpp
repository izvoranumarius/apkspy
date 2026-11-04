#include "ui/TrafficPanel.hpp"
#include <algorithm>
#include <cstdio>
#include <ctime>
#include "app/Theme.hpp"
#include "core/TextUtils.hpp"
#include "mcp/Json.hpp"
#include "ui/UiUtil.hpp"

namespace {

const ImVec4 kGood(0.45f, 0.8f, 0.45f, 1.f);
const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);
const ImVec4 kError(0.95f, 0.45f, 0.4f, 1.f);
const ImVec4 kAccent(0.55f, 0.75f, 0.95f, 1.f);
const ImVec4 kDim(0.6f, 0.6f, 0.6f, 1.f);

ImVec4 statusColor(int status) {
    if (status >= 500) return kError;
    if (status >= 400) return kWarn;
    if (status >= 300) return kAccent;
    if (status >= 200) return kGood;
    return kDim;
}

std::string clock(double unix) {
    const std::time_t t = (std::time_t)unix;
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec,
                  (int)((unix - (double)t) * 1000.0));
    return buf;
}

std::string humanBytes(uint64_t n) {
    char buf[32];
    if (n < 1024) std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)n);
    else if (n < 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f KB", (double)n / 1024.0);
    else std::snprintf(buf, sizeof buf, "%.1f MB", (double)n / (1024.0 * 1024.0));
    return buf;
}

// Pretty JSON when the body parses, otherwise the text (or a hex note).
std::string presentBody(const std::string& body, const std::string& contentType) {
    if (body.empty()) return {};
    Json j;
    if ((contentType.find("json") != std::string::npos || body.front() == '{' || body.front() == '[') &&
        Json::parse(body, j))
        return j.dump(true);
    size_t binary = 0;
    for (size_t i = 0; i < std::min<size_t>(body.size(), 4096); ++i) {
        const unsigned char c = (unsigned char)body[i];
        if (c < 9 || (c > 13 && c < 32)) ++binary;
    }
    if (binary > 16) return "(" + std::to_string(body.size()) + " bytes of binary data - " + contentType + ")";
    return json::sanitizeUtf8(body);
}

void drawMessage(const char* id, const TrafficProxy::Message& m) {
    ImGui::PushID(id);
    ImGui::PushFont(Theme::monoFont());
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextColored(kAccent, "%s", m.startLine.c_str());
    for (const auto& h : m.headers) {
        ImGui::TextColored(kDim, "%s:", h.first.c_str());
        ImGui::SameLine();
        ImGui::TextUnformatted(h.second.c_str());
    }
    ImGui::Separator();
    std::string note;
    const std::string body = TrafficProxy::decodeBody(m, &note);
    if (!note.empty()) ImGui::TextDisabled("(%s)", note.c_str());
    if (m.truncated) ImGui::TextDisabled("(body capped at %zu bytes of %llu)", TrafficProxy::kMaxBody, (unsigned long long)m.bodySize);
    const std::string shown = presentBody(body, m.header("content-type"));
    if (shown.empty()) ImGui::TextDisabled("(no body)");
    else ImGui::TextUnformatted(shown.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
    if (!body.empty() && ImGui::SmallButton("Copy body")) ImGui::SetClipboardText(body.c_str());
    ImGui::PopID();
}

}  // namespace

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

void TrafficPanel::drawRequests() {
    const std::string filter = filter_;
    std::vector<const TrafficProxy::Flow*> shown;
    shown.reserve(rows_.size());
    for (const auto& f : rows_) {
        if (hideTunnels_ && f.tunnel) continue;
        if (!filter.empty()) {
            const std::string hay = f.method + " " + f.host + " " + f.sni + " " + f.path + " " + std::to_string(f.status);
            if (tex::ciFind(hay, filter) == std::string_view::npos) continue;
        }
        shown.push_back(&f);
    }
    if (rows_.empty()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled(
            "Press Start capture, then use the app. HTTP requests appear with headers and bodies; HTTPS connections "
            "appear with their host and size, and their contents stay encrypted.");
        ImGui::PopTextWrapPos();
        return;
    }
    const bool hasDetail = selected_ != 0;
    const float tableH = hasDetail ? ImGui::GetContentRegionAvail().y * 0.5f : 0.f;
    // The URL is what matters: secondary columns only when there is room
    // for them next to a readable URL.
    const bool wide = ImGui::GetContentRegionAvail().x > ui::em(60.f);
    const int cols = wide ? 7 : 4;
    if (ImGui::BeginTable("##flows", cols, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                               ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit,
                          ImVec2(0, tableH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        if (wide) ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, ui::em(5.5f));
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
        if (wide) ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, ui::em(8.f));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        if (wide) ImGui::TableSetupColumn("ms", ImGuiTableColumnFlags_WidthFixed, ui::em(3.5f));
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin((int)shown.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const TrafficProxy::Flow& f = *shown[(size_t)i];
                ImGui::PushID((int)f.id);
                ImGui::TableNextRow();
                if (wide) {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", clock(f.startedAt).c_str());
                }
                ImGui::TableNextColumn();
                if (ImGui::Selectable(f.method.c_str(), selected_ == f.id, ImGuiSelectableFlags_SpanAllColumns))
                    selected_ = f.id;
                if (ImGui::BeginPopupContextItem("##flowctx")) {
                    selected_ = f.id;
                    TrafficProxy::Flow full;
                    if (ImGui::MenuItem("Copy URL")) ImGui::SetClipboardText(f.url().c_str());
                    if (!f.tunnel && ImGui::MenuItem("Copy as cURL") && devices_.traffic().flow(f.id, full))
                        ImGui::SetClipboardText(TrafficProxy::curl(full).c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                const std::string url = f.url();
                if (f.tunnel) ImGui::TextColored(kDim, "%s  (TLS)", url.c_str());
                else ImGui::TextUnformatted(url.c_str());
                if (ImGui::IsItemHovered()) {
                    std::string type = f.tunnel ? "TLS tunnel" : f.contentType();
                    ImGui::SetTooltip("%s\n%s  %s  %.0f ms", url.c_str(), clock(f.startedAt).c_str(), type.c_str(),
                                      f.durationMs);
                }
                ImGui::TableNextColumn();
                if (!f.complete && f.status == 0) ImGui::TextDisabled("...");
                else if (f.status) ImGui::TextColored(statusColor(f.status), "%d", f.status);
                else ImGui::TextColored(kError, "err");
                if (wide) {
                    ImGui::TableNextColumn();
                    std::string type = f.tunnel ? "tunnel" : f.contentType();
                    type = type.substr(0, type.find(';'));
                    ImGui::TextDisabled("%s", type.c_str());
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", humanBytes(f.tunnel ? f.bytesUp + f.bytesDown : f.response.bodySize).c_str());
                if (wide) {
                    ImGui::TableNextColumn();
                    if (f.complete) ImGui::TextDisabled("%.0f", f.durationMs);
                }
                ImGui::PopID();
            }
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - ui::em(2.f)) ImGui::SetScrollHereY(1.f);
        ImGui::EndTable();
    }
    if (hasDetail) drawDetail();
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
    if (ImGui::SmallButton("Copy URL")) ImGui::SetClipboardText(f.url().c_str());
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
            ImGui::PushID((int)i);
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
