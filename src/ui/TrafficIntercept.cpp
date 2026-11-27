// Intercept of the Traffic panel, as in Burp: matching requests and responses
// (plain HTTP and decrypted HTTPS alike) wait in the proxy; here they are read,
// edited, forwarded or dropped.
#include <algorithm>
#include <unordered_set>
#include "core/TextUtils.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

namespace {

int resizeText(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<size_t>(data->BufTextLen));
        data->Buf = text->data();
    }
    return 0;
}

// Raw bytes as edited text: LF lines in the head, the body unchanged.
std::string editable(const std::string& raw) {
    const size_t headEnd = raw.find("\r\n\r\n");
    if (headEnd == std::string::npos) return raw;
    std::string head = raw.substr(0, headEnd);
    std::string out;
    for (size_t i = 0; i < head.size(); ++i)
        if (!(head[i] == '\r' && i + 1 < head.size() && head[i + 1] == '\n')) out += head[i];
    return out + "\n\n" + raw.substr(headEnd + 4);
}

}  // namespace

void TrafficPanel::applyIntercept() {
    devices_.traffic().setIntercept(interceptRequests_, interceptResponses_, interceptFilter_, interceptWs_);
}

void TrafficPanel::drawIntercept() {
    TrafficProxy& proxy = devices_.traffic();
    const bool on = interceptRequests_ || interceptResponses_ || interceptWs_;

    // Toolbar: the switch, what to hold, which URLs.
    ImGui::PushStyleColor(ImGuiCol_Button, on ? theme::vec(Col::Accent) : ImGui::GetStyleColorVec4(ImGuiCol_Button));
    ImGui::PushStyleColor(ImGuiCol_Text, on ? theme::vec(Col::TextOnAccent) : ImGui::GetStyleColorVec4(ImGuiCol_Text));
    if (ImGui::Button(on ? "Intercept is on" : "Intercept is off")) {
        if (on) interceptRequests_ = interceptResponses_ = interceptWs_ = false;
        else interceptRequests_ = true;
        applyIntercept();
    }
    ImGui::PopStyleColor(2);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip(on ? "Turn off: everything waiting goes on unchanged" : "Hold matching HTTP requests");
    ImGui::SameLine();
    if (ImGui::Checkbox("Requests", &interceptRequests_)) applyIntercept();
    ImGui::SameLine();
    if (ImGui::Checkbox("Responses", &interceptResponses_)) applyIntercept();
    ImGui::SameLine();
    if (ImGui::Checkbox("WebSocket messages", &interceptWs_)) applyIntercept();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hold each text / binary WebSocket message (up to 1 MB) in both directions");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(16.f));
    if (ImGui::InputTextWithHint("##icfilter", "only URLs containing...", interceptFilter_, sizeof interceptFilter_)) applyIntercept();
    const std::vector<TrafficProxy::Held> held = proxy.held();
    if (!held.empty()) {
        ImGui::SameLine();
        if (ui::smallButton("Forward all")) proxy.forwardAll();
    }
    if (!proxy.running())
        ui::wrappedColored(kDim, "Start capture to route the device through the proxy; intercepted messages wait here.");

    // Edits of messages no longer waiting are dropped.
    std::unordered_set<uint64_t> live;
    for (const auto& h : held) live.insert(h.id);
    for (auto it = heldEdits_.begin(); it != heldEdits_.end();) it = live.count(it->first) ? std::next(it) : heldEdits_.erase(it);
    if (held.empty()) {
        selectedHeld_ = 0;
        if (on)
            ui::emptyState("Waiting for matching traffic",
                           "Decrypted HTTPS is held here like plain HTTP; un-decrypted tunnels pass through untouched.");
        else
            ui::emptyState("Intercept is off",
                           "Turn it on to hold requests (and responses) before they go on - plain HTTP and decrypted HTTPS alike - "
                           "then edit, forward or drop them.");
        return;
    }
    if (!live.count(selectedHeld_)) selectedHeld_ = held.front().id;  // oldest first, as they arrived

    // Waiting messages | the selected one.
    ImGui::BeginChild("##heldList", ImVec2(ui::em(20.f), 0.f), ImGuiChildFlags_ResizeX | ImGuiChildFlags_Borders);
    for (const auto& h : held) {
        ImGui::PushID(static_cast<int>(h.id));
        const std::string first = h.websocket ? json::sanitizeUtf8(h.raw.substr(0, 60)) : h.raw.substr(0, h.raw.find("\r\n"));
        const std::string label = std::string(h.websocket ? "WS " : "") + (h.response ? "<- " : "-> ") + first;
        if (ImGui::Selectable(label.c_str(), selectedHeld_ == h.id)) selectedHeld_ = h.id;
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s %s", h.websocket ? (h.response ? "WebSocket message from" : "WebSocket message to")
                                                   : (h.response ? "Response from" : "Request to"),
                              h.url.c_str());
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    const TrafficProxy::Held* sel = nullptr;
    for (const auto& h : held)
        if (h.id == selectedHeld_) sel = &h;
    ImGui::BeginChild("##heldEdit", ImVec2(0.f, 0.f));
    if (sel) {
        const std::string original = editable(sel->raw);
        auto [it, fresh] = heldEdits_.try_emplace(sel->id, original);
        std::string& text = it->second;
        const bool changed = text != original;
        const auto forward = [&] {
            proxy.forward(sel->id, changed ? text : std::string());
        };
        ImGui::PushStyleColor(ImGuiCol_Button, theme::vec(Col::Accent));
        ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextOnAccent));
        if (ImGui::Button("Forward")) forward();
        ImGui::PopStyleColor(2);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Send it on%s (Ctrl+F)", changed ? ", as edited" : "");
        ImGui::SameLine();
        if (ImGui::Button("Drop")) proxy.drop(sel->id);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip(sel->response ? "The app gets no response (the connection closes)"
                                                                    : "The request never reaches the server");
        if (!sel->response && !sel->websocket) {
            ImGui::SameLine();
            if (ImGui::Button("Send to Repeater")) {
                httpclient::Target t;
                httpclient::targetFromRequest(text, t);
                newRepeaterTab(t, text);
            }
        }
        if (changed) {
            ImGui::SameLine();
            if (ui::smallButton("Undo edits")) text = original;
        }
        ImGui::SameLine();
        const char* what = sel->websocket ? (sel->response ? "WebSocket message from" : "WebSocket message to")
                                          : (sel->response ? "Response from" : "Request to");
        ImGui::TextColored(changed ? kWarn : kDim, "%s %s%s", what, sel->url.c_str(), changed ? " (edited)" : "");
        ImGui::PushFont(Theme::monoFont());
        ui::codeBox("##held", text.data(), text.capacity() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                                  ImGuiInputTextFlags_CallbackResize | ImGuiInputTextFlags_AllowTabInput, resizeText, &text);
        ImGui::PopFont();
        // Ctrl+F forwards, as in Burp.
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false) &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows))
            forward();
    }
    ImGui::EndChild();
}
