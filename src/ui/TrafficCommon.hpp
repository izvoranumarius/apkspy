#pragma once
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>
#include "app/Theme.hpp"
#include <memory>
#include "core/Settings.hpp"
#include "core/TextUtils.hpp"
#include "debug/ContentView.hpp"
#include "debug/ProtoSchema.hpp"
#include "debug/TrafficProxy.hpp"
#include "imgui.h"
#include "mcp/Json.hpp"
#include "ui/UiUtil.hpp"

// Display helpers shared by the Traffic panel's views (requests, Repeater).
namespace trafficui {

inline const ImVec4 kGood(0.45f, 0.8f, 0.45f, 1.f);
inline const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);
inline const ImVec4 kError(0.95f, 0.45f, 0.4f, 1.f);
inline const ImVec4 kAccent(0.55f, 0.75f, 0.95f, 1.f);
inline const ImVec4 kDim(0.6f, 0.6f, 0.6f, 1.f);

inline ImVec4 statusColor(int status) {
    if (status >= 500) return kError;
    if (status >= 400) return kWarn;
    if (status >= 300) return kAccent;
    if (status >= 200) return kGood;
    return kDim;
}

inline std::string clock(double unix) {
    const std::time_t t = static_cast<std::time_t>(unix);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof buf, "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>((unix - static_cast<double>(t)) * 1000.0));
    return buf;
}

inline std::string humanBytes(uint64_t n) {
    char buf[32];
    if (n < 1024) std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(n));
    else if (n < 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f KB", static_cast<double>(n) / 1024.0);
    else std::snprintf(buf, sizeof buf, "%.1f MB", static_cast<double>(n) / (1024.0 * 1024.0));
    return buf;
}

// Pretty JSON when the body parses, otherwise the text (or a hex note).
inline std::string presentBody(const std::string& body, const std::string& contentType) {
    if (body.empty()) return {};
    Json j;
    if ((contentType.find("json") != std::string::npos || body.front() == '{' || body.front() == '[') &&
        Json::parse(body, j))
        return j.dump(true);
    size_t binary = 0;
    for (size_t i = 0; i < std::min<size_t>(body.size(), 4096); ++i) {
        const unsigned char c = static_cast<unsigned char>(body[i]);
        if (c < 9 || (c > 13 && c < 32)) ++binary;
    }
    if (binary > 16) return "(" + std::to_string(body.size()) + " bytes of binary data - " + contentType + ")";
    return json::sanitizeUtf8(body);
}

// The .proto schemas loaded for the protobuf / gRPC views (shared by every pane).
inline std::shared_ptr<const protoschema::Schema>& protoSchema() {
    static std::shared_ptr<const protoschema::Schema> schema;
    return schema;
}

// A decoded body with its content view picker (as in mitmproxy). The choice
// is remembered per pane in ImGui's state storage (call inside a PushID), and
// the rendering is cached: it reruns only when the body or the view changes.
// `notes` are shown above the text (decoding notes, truncation).
inline void drawBody(const std::string& body, const std::string& contentType, const std::vector<std::string>& notes) {
    int& viewIndex = *ImGui::GetStateStorage()->GetIntRef(ImGui::GetID("##contentView"), 0);
    viewIndex = std::clamp(viewIndex, 0, contentview::kViewCount - 1);
    const auto view = static_cast<contentview::View>(viewIndex);
    // Protobuf / gRPC with a schema: the message type, chosen per pane.
    static std::unordered_map<ImGuiID, std::string> messageTypes;
    std::string& messageType = messageTypes[ImGui::GetID("##protoType")];
    const auto schema = protoSchema();
    struct Cache {
        size_t size = SIZE_MAX;
        size_t hash = 0;
        int view = -1;
        std::string type;
        std::string message;
        const void* schema = nullptr;
        contentview::Rendered result;
    };
    static std::unordered_map<ImGuiID, Cache> cache;
    if (cache.size() > 64) cache.clear();
    Cache& c = cache[ImGui::GetID("##contentCache")];
    const size_t hash = std::hash<std::string>{}(body);
    if (c.size != body.size() || c.hash != hash || c.view != viewIndex || c.type != contentType || c.message != messageType ||
        c.schema != schema.get()) {
        c.result = contentview::render(view, body, contentType, schema.get(), messageType);
        c.size = body.size();
        c.hash = hash;
        c.view = viewIndex;
        c.type = contentType;
        c.message = messageType;
        c.schema = schema.get();
    }
    if (!body.empty()) {
        ImGui::SetNextItemWidth(ui::em(11.f));
        const std::string preview = view == contentview::View::Auto
                                        ? std::string("Auto: ") + contentview::viewName(c.result.view)
                                        : std::string(contentview::viewName(view));
        if (ImGui::BeginCombo("##view", preview.c_str())) {
            for (int i = 0; i < contentview::kViewCount; ++i)
                if (ImGui::Selectable(contentview::viewName(static_cast<contentview::View>(i)), i == viewIndex)) viewIndex = i;
            ImGui::EndCombo();
        }
        if (schema && !schema->empty() && (c.result.view == contentview::View::Protobuf || c.result.view == contentview::View::Grpc ||
                                           view == contentview::View::Protobuf || view == contentview::View::Grpc)) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(ui::em(14.f));
            if (ImGui::BeginCombo("##msgtype", messageType.empty() ? "(no message type)" : messageType.c_str(), ImGuiComboFlags_HeightLarge)) {
                if (ImGui::Selectable("(no message type)", messageType.empty())) messageType.clear();
                for (const auto& name : schema->messageNames())
                    if (ImGui::Selectable(name.c_str(), name == messageType)) messageType = name;
                ImGui::EndCombo();
            }
        }
        ImGui::SameLine();
        if (ui::smallButton("Copy body")) ImGui::SetClipboardText(body.c_str());
        ImGui::SameLine();
        if (ui::smallButton("Copy view")) ImGui::SetClipboardText(c.result.text.c_str());
    }
    ImGui::PushFont(Theme::monoFont());
    ImGui::PushTextWrapPos(0.f);
    for (const auto& n : notes)
        if (!n.empty()) ImGui::TextDisabled("(%s)", n.c_str());
    if (!c.result.note.empty()) ImGui::TextDisabled("(%s)", c.result.note.c_str());
    if (body.empty()) ImGui::TextDisabled("(no body)");
    else ImGui::TextUnformatted(c.result.text.data(), c.result.text.data() + c.result.text.size());
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
}

inline void drawMessage(const char* id, const TrafficProxy::Message& m) {
    ImGui::PushID(id);
    ImGui::PushFont(Theme::monoFont());
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextColored(kAccent, "%s", m.startLine.c_str());
    for (const auto& h : m.headers) {
        ImGui::TextColored(kDim, "%s:", h.first.c_str());
        ImGui::SameLine();
        ImGui::TextUnformatted(h.second.c_str());
    }
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
    // Query parameters, cookies and JSON Web Tokens, decoded (collapsed by default).
    const bool response = m.startLine.rfind("HTTP/", 0) == 0;
    if (!response) {
        const size_t sp1 = m.startLine.find(' '), sp2 = m.startLine.rfind(' ');
        const std::string target = sp1 != std::string::npos && sp2 > sp1 ? m.startLine.substr(sp1 + 1, sp2 - sp1 - 1) : std::string();
        const size_t q = target.find('?');
        std::string fields;
        if (q != std::string::npos && contentview::formFields(target.substr(q + 1), fields) &&
            ImGui::TreeNode("##query", "Query parameters")) {
            ImGui::PushFont(Theme::monoFont());
            ImGui::TextUnformatted(fields.c_str());
            ImGui::PopFont();
            ImGui::TreePop();
        }
    }
    std::vector<contentview::Cookie> cookies;
    std::string tokens;
    for (const auto& [name, value] : m.headers) {
        if (!response && tex::asciiIEqual(name, "cookie"))
            for (auto& ck : contentview::parseCookieHeader(value)) cookies.push_back(std::move(ck));
        if (response && tex::asciiIEqual(name, "set-cookie")) cookies.push_back(contentview::parseSetCookie(value));
        if (value.find("eyJ") != std::string::npos) tokens += value + "\n";
    }
    if (!cookies.empty() && ImGui::TreeNode("##cookies", "Cookies (%zu)", cookies.size())) {
        if (ImGui::BeginTable("##cookietable", response ? 3 : 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, ui::em(10.f));
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 2.f);
            if (response) ImGui::TableSetupColumn("Attributes", ImGuiTableColumnFlags_WidthStretch, 1.f);
            ImGui::TableHeadersRow();
            for (const auto& ck : cookies) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(ck.name.c_str());
                ImGui::TableNextColumn();
                ImGui::PushTextWrapPos(0.f);
                ImGui::TextUnformatted(contentview::urlDecode(ck.value, false).c_str());
                ImGui::PopTextWrapPos();
                if (response) {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", ck.attributes.c_str());
                }
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }
    std::string jwtText;
    if (!tokens.empty() && contentview::jwt(tokens, jwtText) && ImGui::TreeNode("##jwt", "JSON Web Tokens in the headers")) {
        ImGui::PushFont(Theme::monoFont());
        ImGui::TextUnformatted(jwtText.c_str());
        ImGui::PopFont();
        ImGui::TreePop();
    }
    ImGui::Separator();
    std::string note;
    const std::string body = TrafficProxy::decodeBody(m, &note);
    std::vector<std::string> notes = {note};
    if (m.truncated)
        notes.push_back("body capped: " + std::to_string(m.body.size()) + " of " + std::to_string(m.bodySize) + " bytes kept");
    drawBody(body, m.header("content-type"), notes);
    ImGui::PopID();
}

// The proxy mode saved in the settings. False (with `error`) when a target is
// not usable; `mode` then holds what could be read.
inline bool modeFromSettings(const Settings& s, TrafficProxy::Mode& mode, std::string& error) {
    mode = TrafficProxy::Mode{};
    bool ok = true;
    if (s.getString(Settings::kTrafficMode, "regular") == "reverse") {
        std::string e;
        if (!TrafficProxy::parseReverseTarget(s.getString(Settings::kTrafficReverseTarget, ""), mode, e)) {
            error = "Reverse proxy: " + e;
            ok = false;
        }
    }
    std::string e;
    if (!TrafficProxy::parseUpstream(s.getString(Settings::kTrafficUpstream, ""), mode, e)) {
        error = "Upstream proxy: " + e;
        ok = false;
    }
    mode.upstreamAuth = s.getString(Settings::kTrafficUpstreamAuth, "");
    return ok;
}

// One line describing the active mode ("" for a plain regular proxy).
inline std::string modeLabel(const TrafficProxy::Mode& m) {
    std::string out;
    if (m.reverse())
        out = std::string("Reverse proxy to ") + (m.reverseTls ? "https://" : "http://") + m.reverseHost +
              ((m.reverseTls && m.reversePort == 443) || (!m.reverseTls && m.reversePort == 80) ? "" : ":" + std::to_string(m.reversePort));
    if (m.chained()) out += (out.empty() ? "" : ", ") + std::string("via upstream ") + m.upstreamHost + ":" + std::to_string(m.upstreamPort);
    return out;
}


// A message as text for the Comparer: start line, headers, a blank line, the body
// decoded (chunked, gzip) and pretty-printed when it is JSON.
inline std::string messageText(const TrafficProxy::Message& m) {
    std::string out = m.startLine + "\n";
    for (const auto& [name, value] : m.headers) out += name + ": " + value + "\n";
    out += "\n";
    out += presentBody(TrafficProxy::decodeBody(m, nullptr), m.header("content-type"));
    return out;
}

}  // namespace trafficui
