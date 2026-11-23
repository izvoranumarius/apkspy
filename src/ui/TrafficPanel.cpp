#include "ui/TrafficPanel.hpp"
#include <algorithm>
#include <cstdio>
#include <ctime>
#include "app/Theme.hpp"
#include "core/Codec.hpp"
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
    loadRouting();
    for (auto& [label, text] : workspace_.takeComparerRequests()) sendToComparer(std::move(label), std::move(text));
    drawToolbar();
    drawSessionDialogs();
    pollScript();  // the script's log and reload run whichever tab is open
    drawCertDialog();
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
    // "(on)" only for rules that can take effect (a new, empty row does not count).
    const bool routingOn = !routing_.ignoreHosts.empty() || !routing_.allowHosts.empty() ||
                           std::any_of(routing_.mapLocal.begin(), routing_.mapLocal.end(),
                                       [](const auto& m) { return m.enabled && !m.urlPattern.empty() && !m.localPath.empty(); }) ||
                           std::any_of(routing_.mapRemote.begin(), routing_.mapRemote.end(),
                                       [](const auto& m) { return m.enabled && !m.from.empty() && !m.to.empty(); }) ||
                           proxy.serverReplayLeft() > 0 || conditions_.active();
    if (ImGui::BeginTabItem(routingOn ? "Map & Replay (on)###routing" : "Map & Replay###routing")) {
        ImGui::BeginChild("##routingScroll");
        drawRouting();
        ImGui::EndChild();
        ImGui::EndTabItem();
    }
    const bool scriptOn = script_ && script_->running();
    if (ImGui::BeginTabItem(scriptOn ? "Scripts (on)###scripts" : "Scripts###scripts")) {
        drawScripts();
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
        // Without a device the proxy still runs for clients pointed at it by
        // hand (desktop tools, SOCKS5 clients, reverse mode, an emulator via 10.0.2.2).
        if (ImGui::Button(serial.empty() ? "Start proxy" : "Start capture")) {
            std::string err;
            const int port = settings_.getInt(Settings::kTrafficPort, 8899);
            if (!proxy.start(port, err)) status_ = err;
            else if (serial.empty())
                status_ = "No device: the proxy listens on 127.0.0.1:" + std::to_string(proxy.port()) +
                          " (HTTP and SOCKS5) for clients set up by hand.";
            else status_ = proxy.routeDevice(devices_.adb(), serial, err) ? std::string() : "Could not route the device: " + err;
        }
        if (serial.empty() && ImGui::IsItemHovered())
            ImGui::SetTooltip("No device connected: starts the proxy on 127.0.0.1 without routing a device");
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
    ui::sameLineIfFits(ui::buttonWidth("HTTPS & certificates"));
    if (ImGui::Button("HTTPS & certificates")) {
        refreshCertInfo();
        ImGui::OpenPopup("HTTPS & certificates");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("ApkSpy's CA, exporting it, and installing / checking it on the device");
    ui::sameLineIfFits(ui::em(10.f));
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetNextItemWidth(-ui::buttonWidth("...") - ui::buttonWidth("?") - 2 * spacing);
    const bool badExpr = !exprError_.empty() && flowfilter::looksLikeExpression(filter_);
    if (badExpr) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.45f, 0.15f, 0.12f, 0.6f));
    ImGui::InputTextWithHint("##tfilter", "Filter text, or an expression: ~d host & ~m POST, ~c 500 | ~e ...", filter_,
                             sizeof filter_);
    if (badExpr) {
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", exprError_.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("?##filterhelp")) ImGui::OpenPopup("##filterhelpPopup");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filter expression syntax");
    if (ImGui::BeginPopup("##filterhelpPopup")) {
        drawFilterHelp();
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("...##trafficopts")) ImGui::OpenPopup("##trafficopts");
    if (ImGui::BeginPopup("##trafficopts")) {
        if (ImGui::MenuItem("Save session (HAR)...", nullptr, false, !rows_.empty())) {
            harSaveFiltered_ = false;
            harSaver_.open(FileBrowser::Mode::SaveFile);
            harSaver_.setDefaultName("apkspy-session.har");
        }
        if (ImGui::MenuItem("Save shown requests (HAR)...", nullptr, false, !shownIds_.empty())) {
            harSaveFiltered_ = true;
            harSaver_.open(FileBrowser::Mode::SaveFile);
            harSaver_.setDefaultName("apkspy-filtered.har");
        }
        if (ImGui::MenuItem("Open session / HAR file...")) harOpener_.open(FileBrowser::Mode::OpenFile);
        if (ImGui::MenuItem("Load .proto files...")) protoOpener_.open(FileBrowser::Mode::SelectFolder);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("A folder of .proto files: protobuf and gRPC bodies then show field names (pick the message type)");
        if (ImGui::MenuItem("Replay shown requests", nullptr, false, !shownIds_.empty() && !batch_.job.valid()))
            startBatchReplay(shownIds_);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Sends every request in the list again; the answers are added as new rows");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Adds the requests of a HAR file (ApkSpy, browsers, Burp, mitmproxy, Charles) to the list");
        ImGui::Separator();
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
    if (const std::string mode = modeLabel(proxy.mode()); !mode.empty()) ui::wrappedColored(kDim, "Mode: " + mode);
    pollBatchReplay();
    if (batch_.job.valid()) {
        ImGui::TextColored(kAccent, "Replaying %d / %d...", batch_.done->load(), batch_.total);
        ImGui::SameLine();
        if (ui::smallButton("Stop##batch")) batch_.cancel->store(true);
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
    std::snprintf(line, sizeof line, "%s%s%s up, %s down | %.0f ms%s%s", f.status ? "status " : "",
                  f.status ? (std::to_string(f.status) + " | ").c_str() : "", humanBytes(f.bytesUp).c_str(),
                  humanBytes(f.bytesDown).c_str(), f.durationMs, f.error.empty() ? "" : " | ", f.error.c_str());
    ui::wrappedColored(kDim, line);
    if (!f.note.empty()) ui::wrappedColored(kAccent, f.note);
    const bool http = f.transport.empty() && f.method != "PRI";  // Repeater, Comparer, Copy as: HTTP only
    if (http && ui::smallButton("Send to Repeater")) sendToRepeater(f);
    if (http && !f.tunnel && ui::flowSmallButton("Response to Comparer"))
        sendToComparer(std::to_string(f.status) + " " + f.url(), messageText(f.response));
    if (ui::flowSmallButton("Copy URL")) ImGui::SetClipboardText(f.url().c_str());
    if (http && !f.tunnel && ui::flowSmallButton("Copy as...")) ImGui::OpenPopup("##copyas");
    if (ImGui::BeginPopup("##copyas")) {
        copyAsMenu(f.id);
        ImGui::EndPopup();
    }
    if (ui::flowSmallButton("Close")) selected_ = 0;
    if (!f.transport.empty()) {
        // A raw TCP stream or UDP datagrams: the bytes each way, with content views.
        ui::wrappedColored(kDim, f.transport == "udp" ? (f.method == "DNS" ? "DNS over UDP (SOCKS5)" : "UDP datagrams (SOCKS5)")
                                                      : "Raw TCP stream - the protocol is not HTTP or TLS");
        ImGui::BeginChild("##stream");
        drawDetailWebSockets(f);
        ImGui::EndChild();
    } else if (f.tunnel) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled(
            "Encrypted HTTPS tunnel to %s:%d%s%s. ApkSpy relays the TLS bytes without decrypting them, so request "
            "and response contents are not visible - only the destination, timing and sizes. Enable HTTPS "
            "interception (Settings > Network) and install ApkSpy's CA on the device to see inside.",
            f.host.c_str(), f.port, f.sni.empty() ? "" : ", server name ", f.sni.c_str());
        ImGui::PopTextWrapPos();
    } else {
        drawDetailTls(f);
        if (ImGui::BeginTabBar("##rr")) {
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
            if (f.websocket && ImGui::BeginTabItem("WebSocket")) {
                ImGui::BeginChild("##ws");
                drawDetailWebSockets(f);
                ImGui::EndChild();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::EndChild();
}

void TrafficPanel::drawDetailTls(const TrafficProxy::Flow& f) {
    if (!f.https) return;
    char line[512];
    std::snprintf(line, sizeof line, "%s%s%s%s | %s",
                  f.tlsVersion.empty() ? "TLS" : f.tlsVersion.c_str(),
                  f.tlsCipher.empty() ? "" : " (", f.tlsCipher.c_str(), f.tlsCipher.empty() ? "" : ")",
                  f.alpn.empty() ? "no ALPN" : f.alpn.c_str());
    ui::wrappedColored(kDim, std::string("Intercepted HTTPS to ") + (f.sni.empty() ? f.host : f.sni) + " - " + line);
    if (!f.tlsError.empty()) ui::wrappedColored(kWarn, "TLS: " + f.tlsError);
}

void TrafficPanel::drawDetailWebSockets(const TrafficProxy::Flow& f) {
    TrafficProxy& proxy = devices_.traffic();
    // Frames come from the running flow; refetch while it is open.
    TrafficProxy::Flow live;
    const TrafficProxy::Flow* shown = &f;
    if (!f.complete && proxy.flow(f.id, live)) shown = &live;
    const auto& frames = shown->wsFrames;
    if (wsSelectedFlow_ != f.id) {
        wsSelectedFlow_ = f.id;
        wsSelected_ = -1;
        wsStatus_.clear();
    }

    // Send a message into the live connection.
    const bool isLive = f.websocket && proxy.webSocketLive(f.id);
    if (!f.websocket) {
        // (raw TCP / UDP flows: no sending)
    } else if (isLive) {
        ImGui::RadioButton("to the server", &wsSendToServer_, 1);
        ImGui::SameLine();
        ImGui::RadioButton("to the app", &wsSendToServer_, 0);
        ImGui::SameLine();
        ImGui::Checkbox("binary (hex)", &wsSendHex_);
        ImGui::SameLine();
        if (ImGui::Button("Send message")) {
            std::string payload = wsSendText_;
            bool ok = true;
            if (wsSendHex_) ok = codec::hexDecode(wsSendText_, payload);
            std::string error;
            if (!ok) wsStatus_ = "Not valid hex.";
            else
                wsStatus_ = proxy.injectWebSocket(f.id, wsSendToServer_ == 1, wsSendHex_ ? 2 : 1, payload, error)
                                ? "Sent " + std::to_string(payload.size()) + " bytes."
                                : "Not sent: " + error;
        }
        if (!wsStatus_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", wsStatus_.c_str());
        }
        ImGui::PushFont(Theme::monoFont());
        ui::codeBox("##wssend", wsSendText_.data(), wsSendText_.capacity() + 1, ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 3.5f),
                                  ImGuiInputTextFlags_CallbackResize,
                                  [](ImGuiInputTextCallbackData* d) {
                                      if (d->EventFlag == ImGuiInputTextFlags_CallbackResize) {
                                          auto* s = static_cast<std::string*>(d->UserData);
                                          s->resize(static_cast<size_t>(d->BufTextLen));
                                          d->Buf = s->data();
                                      }
                                      return 0;
                                  },
                                  &wsSendText_);
        ImGui::PopFont();
    } else {
        ImGui::TextDisabled("The connection is closed - messages can be sent while it is open.");
    }
    if (frames.empty()) {
        ImGui::TextDisabled("No WebSocket frames recorded (yet).");
        return;
    }
    const bool hasSel = wsSelected_ >= 0 && wsSelected_ < static_cast<int>(frames.size());
    const float tableH = hasSel ? ImGui::GetContentRegionAvail().y * 0.45f : 0.f;
    if (ImGui::BeginTable("##wsframes", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                               ImGuiTableFlags_BordersInnerV,
                          ImVec2(0, tableH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, ui::em(5.5f));
        ImGui::TableSetupColumn("Direction", ImGuiTableColumnFlags_WidthFixed, ui::em(6.f));
        ImGui::TableSetupColumn("Frame", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        ImGui::TableSetupColumn("Payload", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableHeadersRow();
        static const char* kOps[] = {"continuation", "text", "binary", "?", "?", "?", "?", "?", "close", "ping", "pong"};
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(frames.size()));
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& frame = frames[static_cast<size_t>(i)];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (ImGui::Selectable(clock(frame.at).c_str(), wsSelected_ == i, ImGuiSelectableFlags_SpanAllColumns))
                    wsSelected_ = wsSelected_ == i ? -1 : i;
                ImGui::TableNextColumn();
                ImGui::TextColored(frame.fromClient ? kAccent : kGood, "%s", frame.fromClient ? "client ->" : "<- server");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(frame.opcode >= 0 && frame.opcode <= 10 ? kOps[frame.opcode] : "?");
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", humanBytes(frame.size).c_str());
                ImGui::TableNextColumn();
                if (frame.injected) ImGui::TextColored(kAccent, "[sent by ApkSpy]"), ImGui::SameLine();
                if (frame.dropped) ImGui::TextColored(kError, "[dropped]"), ImGui::SameLine();
                if (frame.edited) ImGui::TextColored(kWarn, "[edited]"), ImGui::SameLine();
                const std::string dnsLine = shown->method == "DNS" ? contentview::dnsSummary(frame.preview) : std::string();
                if (!dnsLine.empty()) ImGui::TextUnformatted(dnsLine.c_str());
                else if (frame.opcode == 1) ImGui::TextUnformatted(json::sanitizeUtf8(frame.preview.substr(0, 200)).c_str());
                else if (frame.opcode == 2) {
                    // Binary frames (and raw TCP / UDP data): text when it is printable, else the first bytes in hex.
                    const std::string head = frame.preview.substr(0, 200);
                    bool printable = !head.empty();
                    for (unsigned char ch : head) printable &= ch >= 0x20 || ch == '\t' || ch == '\r' || ch == '\n';
                    if (printable && json::sanitizeUtf8(head) == head) ImGui::TextUnformatted(head.c_str());
                    else ImGui::TextDisabled("%s", contentview::hexDump(frame.preview.substr(0, 16)).substr(10, 48).c_str());
                }
                else ImGui::TextDisabled("%s", json::sanitizeUtf8(frame.preview.substr(0, 120)).c_str());
                ImGui::PopID();
            }
        ImGui::EndTable();
    }
    if (hasSel) {
        const auto& frame = frames[static_cast<size_t>(wsSelected_)];
        ImGui::Separator();
        ImGui::PushID("wsframe");
        std::vector<std::string> notes;
        if (frame.truncated)
            notes.push_back("payload capped: " + std::to_string(frame.preview.size()) + " of " + std::to_string(frame.size) + " bytes kept");
        if (frame.injected) notes.push_back("sent by ApkSpy");
        if (frame.dropped) notes.push_back("dropped - never delivered");
        if (f.websocket && ui::smallButton("Resend")) {
            std::string error;
            wsStatus_ = proxy.injectWebSocket(f.id, frame.fromClient, frame.opcode == 2 ? 2 : 1, frame.preview, error)
                            ? "Resent." : "Not resent: " + error;
        }
        if (f.websocket) ImGui::SameLine();
        if (f.websocket && ui::smallButton("Edit in Send box")) {
            wsSendHex_ = frame.opcode == 2;
            wsSendText_ = wsSendHex_ ? codec::hexEncode(frame.preview) : frame.preview;
            wsSendToServer_ = frame.fromClient ? 1 : 0;
        }
        ImGui::SameLine();
        if (ui::smallButton("To Comparer"))
            sendToComparer(std::string(frame.fromClient ? "WS client " : "WS server ") + clock(frame.at), frame.preview);
        ImGui::BeginChild("##wsbody");
        drawBody(frame.preview, shown->method == "DNS" ? "application/dns-message" : frame.opcode == 1 ? "text/plain" : "", notes);
        ImGui::EndChild();
        ImGui::PopID();
    }
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
