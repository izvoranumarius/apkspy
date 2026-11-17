#pragma once
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <string>
#include "app/Theme.hpp"
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
    ImGui::Separator();
    std::string note;
    const std::string body = TrafficProxy::decodeBody(m, &note);
    if (!note.empty()) ImGui::TextDisabled("(%s)", note.c_str());
    if (m.truncated) ImGui::TextDisabled("(body capped at %zu bytes of %llu)", TrafficProxy::kMaxBody, static_cast<unsigned long long>(m.bodySize));
    const std::string shown = presentBody(body, m.header("content-type"));
    if (shown.empty()) ImGui::TextDisabled("(no body)");
    else ImGui::TextUnformatted(shown.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PopFont();
    if (!body.empty() && ui::smallButton("Copy body")) ImGui::SetClipboardText(body.c_str());
    ImGui::PopID();
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
