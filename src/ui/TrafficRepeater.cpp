// Repeater of the Traffic panel, as in Burp: a request in an editor, Send, the
// response beside it; every send is kept in the tab's history (< >).
#include <GLFW/glfw3.h>
#include <algorithm>
#include <cstdio>
#include "app/Icons.hpp"
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

// A response as one block of text: start line, headers, blank line, body.
std::string rawText(const TrafficProxy::Message& m) {
    std::string out = m.startLine + "\n";
    for (const auto& [name, value] : m.headers) out += name + ": " + value + "\n";
    out += "\n";
    out += json::sanitizeUtf8(m.body);
    return out;
}

const char* kNewRequest = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: ApkSpy-Repeater\nAccept: */*\n\n";

}  // namespace

TrafficPanel::RepeaterTab& TrafficPanel::newRepeaterTab(const httpclient::Target& target, std::string request) {
    auto tab = std::make_unique<RepeaterTab>();
    tab->id = repeaterNext_++;
    tab->title = std::to_string(tab->id);
    tab->target = target;
    tab->hostEdit = target.host;
    tab->request = std::move(request);
    repeater_.push_back(std::move(tab));
    repeaterSelect_ = repeater_.back()->id;
    showRepeater_ = true;
    return *repeater_.back();
}

void TrafficPanel::sendToRepeater(const TrafficProxy::Flow& f) {
    httpclient::Target t;
    if (f.tunnel) {
        // The contents of an HTTPS connection were never seen: start from a request to its host.
        t.host = f.sni.empty() ? f.host : f.sni;
        t.port = f.port;
        t.https = true;
        std::string req = kNewRequest;
        const std::string hostLine = "Host: " + t.host + (t.port == 443 ? "" : ":" + std::to_string(t.port));
        req.replace(req.find("Host: example.com"), std::string("Host: example.com").size(), hostLine);
        newRepeaterTab(t, req);
        return;
    }
    // Plain HTTP and decrypted HTTPS alike: the captured request, as sent.
    t.host = f.sni.empty() ? f.host : f.sni;
    t.port = f.port;
    t.https = f.https;
    std::string request = httpclient::editableRequest(f);
    if (f.https) {
        // The editable text keeps the original Host header; the target is the
        // interception's host so the send goes where the app went.
        httpclient::Target fromHost;
        if (httpclient::targetFromRequest(request, fromHost)) t.host = fromHost.host, t.port = fromHost.port;
    }
    newRepeaterTab(t, std::move(request));
}

void TrafficPanel::sendRepeater(RepeaterTab& tab) {
    if (tab.pending.valid()) return;
    tab.target.host = tab.hostEdit;
    while (!tab.target.host.empty() && tab.target.host.back() == ' ') tab.target.host.pop_back();
    if (tab.target.host.empty()) httpclient::targetFromRequest(tab.request, tab.target), tab.hostEdit = tab.target.host;
    httpclient::Options o;
    o.fixContentLength = tab.fixLength;
    o.ignoreCertErrors = tab.ignoreCert;
    tab.cancel = std::make_shared<std::atomic<bool>>(false);
    tab.pendingRequest = tab.request;
    tab.sentAt = std::chrono::steady_clock::now();
    tab.pending = std::async(std::launch::async, [target = tab.target, request = tab.request, o, cancel = tab.cancel] {
        httpclient::Result r = httpclient::send(target, request, o, cancel.get());
        glfwPostEmptyEvent();  // wake the UI to show it
        return r;
    });
}

void TrafficPanel::drawRepeater() {
    if (repeater_.empty()) {
        if (ui::smallButton(ui::icon(icons::ADD, "New request").c_str())) newRepeaterTab({"example.com", 80, false}, kNewRequest);
        ui::emptyState("No requests in the Repeater",
                       "Right-click a request and choose Send to Repeater (Ctrl+R) to edit it and send it again, "
                       "or start from an empty request.");
        return;
    }
    int close = -1;
    if (ImGui::BeginTabBar("##repeaterTabs", ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_FittingPolicyScroll |
                                                 ImGuiTabBarFlags_AutoSelectNewTabs)) {
        for (auto& tp : repeater_) {
            RepeaterTab& tab = *tp;
            bool open = true;
            const std::string label = tab.title + (tab.pending.valid() ? " ..." : "") + "###rep" + std::to_string(tab.id);
            const bool selected = ImGui::BeginTabItem(label.c_str(), &open, repeaterSelect_ == tab.id ? ImGuiTabItemFlags_SetSelected : 0);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tab.target.label().c_str());
            if (selected) {
                drawRepeaterTab(tab);
                ImGui::EndTabItem();
            }
            if (!open) close = tab.id;
        }
        repeaterSelect_ = -1;
        if (ImGui::TabItemButton(Theme::hasIcons() ? icons::ADD : "+", ImGuiTabItemFlags_Trailing | ImGuiTabItemFlags_NoTooltip))
            newRepeaterTab({"example.com", 80, false}, kNewRequest);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("New request");
        ImGui::EndTabBar();
    }
    if (close >= 0)
        repeater_.erase(std::remove_if(repeater_.begin(), repeater_.end(),
                                       [&](const auto& t) {
                                           if (t->id != close) return false;
                                           // A send still running is cancelled and finishes on its own.
                                           if (t->cancel) t->cancel->store(true);
                                           if (t->pending.valid()) abandoned_.push_back(std::move(t->pending));
                                           return true;
                                       }),
                        repeater_.end());
    abandoned_.erase(std::remove_if(abandoned_.begin(), abandoned_.end(),
                                    [](auto& f) { return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready; }),
                     abandoned_.end());
}

void TrafficPanel::drawRepeaterTab(RepeaterTab& tab) {
    ImGui::PushID(tab.id);
    // A finished send joins the history and is shown.
    if (tab.pending.valid() && tab.pending.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        Exchange e{tab.target, tab.pendingRequest, tab.pending.get()};
        if (e.result.error != "cancelled") {
            tab.history.push_back(std::move(e));
            tab.shown = static_cast<int>(tab.history.size()) - 1;
        }
    }
    const bool sending = tab.pending.valid();

    // Toolbar: Send, history, target, options.
    if (sending) {
        if (ImGui::Button("Cancel")) tab.cancel->store(true);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, theme::vec(Col::Accent));
        ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextOnAccent));
        if (ImGui::Button("Send")) sendRepeater(tab);
        ImGui::PopStyleColor(2);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Send the request (Ctrl+Enter)");
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(tab.shown <= 0);
    if (ImGui::ArrowButton("##prev", ImGuiDir_Left)) {
        --tab.shown;
        tab.request = tab.history[static_cast<size_t>(tab.shown)].request;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(tab.shown + 1 >= static_cast<int>(tab.history.size()));
    if (ImGui::ArrowButton("##next", ImGuiDir_Right)) {
        ++tab.shown;
        tab.request = tab.history[static_cast<size_t>(tab.shown)].request;
    }
    ImGui::EndDisabled();
    if (!tab.history.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%d/%zu", tab.shown + 1, tab.history.size());
    }
    ImGui::SameLine();
    ImGui::TextDisabled("Target");
    ImGui::SameLine();
    if (ImGui::Checkbox("HTTPS", &tab.target.https)) {
        if (tab.target.https && tab.target.port == 80) tab.target.port = 443;
        else if (!tab.target.https && tab.target.port == 443) tab.target.port = 80;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(14.f));
    ImGui::InputTextWithHint("##host", "host", tab.hostEdit.data(), tab.hostEdit.capacity() + 1, ImGuiInputTextFlags_CallbackResize,
                             resizeText, &tab.hostEdit);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(4.5f));
    ImGui::InputInt("##port", &tab.target.port, 0, 0);
    tab.target.port = std::clamp(tab.target.port, 1, 65535);
    ImGui::SameLine();
    if (ui::smallButton("From Host header")) {
        httpclient::Target t = tab.target;
        if (httpclient::targetFromRequest(tab.request, t)) tab.target = t, tab.hostEdit = t.host;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Take the host and port from the request's Host header");
    ImGui::SameLine();
    if (ui::smallButton("Options")) ImGui::OpenPopup("##repopts");
    if (ImGui::BeginPopup("##repopts")) {
        ImGui::Checkbox("Update Content-Length", &tab.fixLength);
        ImGui::Checkbox("Ignore certificate errors (HTTPS)", &tab.ignoreCert);
        ImGui::Separator();
        char title[64];
        std::snprintf(title, sizeof title, "%s", tab.title.c_str());
        ImGui::SetNextItemWidth(ui::em(10.f));
        if (ImGui::InputText("Tab name", title, sizeof title)) tab.title = title[0] ? title : std::to_string(tab.id);
        ImGui::EndPopup();
    }

    // Request | Response, side by side.
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const float half = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;
    ImGui::BeginChild("##reqCol", ImVec2(half, 0.f));
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Request");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", tab.target.label().c_str());
    ImGui::PushFont(Theme::monoFont());
    ui::codeBox("##req", tab.request.data(), tab.request.capacity() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                              ImGuiInputTextFlags_CallbackResize | ImGuiInputTextFlags_AllowTabInput, resizeText, &tab.request);
    ImGui::PopFont();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##respCol", ImVec2(0.f, 0.f));
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Response");
    const Exchange* ex = tab.shown >= 0 && tab.shown < static_cast<int>(tab.history.size()) ? &tab.history[static_cast<size_t>(tab.shown)] : nullptr;
    if (sending) {
        ImGui::SameLine();
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - tab.sentAt).count();
        ImGui::TextDisabled("sending... %.1f s", s);
    } else if (ex && !ex->result.ok) {
        ImGui::SameLine();
        ImGui::TextColored(kError, "%s", ex->result.error.c_str());
    } else if (ex) {
        const httpclient::Result& r = ex->result;
        ImGui::SameLine();
        ImGui::TextColored(statusColor(r.status), "%d", r.status);
        ImGui::SameLine();
        ImGui::TextDisabled("%.0f ms, %s", r.ms, humanBytes(r.response.bodySize).c_str());
        static const char* kViews[] = {"Raw", "Pretty", "Headers"};
        ImGui::SameLine();
        if (ui::segmented(kViews, 3, tab.view)) tab.rawFor = -1;
        std::string note;
        const std::string body = TrafficProxy::decodeBody(r.response, &note);
        ImGui::SameLine();
        if (ui::smallButton(ui::icon(icons::COPY, "Copy body").c_str())) ImGui::SetClipboardText(body.c_str());
        ImGui::SameLine();
        if (ui::smallButton("To Decoder")) workspace_.sendToDecoder(body);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Open the response body in the Decoder");
        ImGui::SameLine();
        if (ui::smallButton("To Comparer"))
            sendToComparer(tab.title + " #" + std::to_string(tab.shown + 1) + " " + std::to_string(r.status), messageText(r.response));
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Compare this response with another (send two)");
        if (!r.note.empty() || !note.empty()) ImGui::TextDisabled("(%s)", (r.note + (r.note.empty() || note.empty() ? "" : "; ") + note).c_str());
        // The read-only box selects and copies like any text field.
        if (tab.rawFor != tab.shown * 3 + tab.view) {
            tab.rawFor = tab.shown * 3 + tab.view;
            if (tab.view == 0) {
                tab.rawCache = rawText(r.response);
            } else if (tab.view == 1) {
                tab.rawCache = presentBody(body, r.response.header("content-type"));
                if (tab.rawCache.empty()) tab.rawCache = "(no body)";
            } else {
                tab.rawCache = r.response.startLine + "\n";
                for (const auto& [name, value] : r.response.headers) tab.rawCache += name + ": " + value + "\n";
            }
            std::replace(tab.rawCache.begin(), tab.rawCache.end(), '\0', '.');
        }
        ImGui::PushFont(Theme::monoFont());
        ui::codeBox("##resp", tab.rawCache.data(), tab.rawCache.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                                  ImGuiInputTextFlags_ReadOnly);
        ImGui::PopFont();
    } else if (!sending) {
        ui::emptyState("No response yet",
                       "Edit the request and press Send (Ctrl+Enter).\n"
                       "It goes out exactly as typed, over plain HTTP or verified TLS; redirects are not followed and no cookies are kept.");
    }
    ImGui::EndChild();

    // Ctrl+Enter / Ctrl+Space (Burp's key) sends from anywhere in the tab.
    const ImGuiIO& io = ImGui::GetIO();
    if (!sending && io.KeyCtrl && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false) ||
         ImGui::IsKeyPressed(ImGuiKey_Space, false)))
        sendRepeater(tab);
    ImGui::PopID();
}
