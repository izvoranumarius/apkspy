// Traffic panel: Map & Replay - ignore / allow hosts, map local, map remote
// and server replay.
#include <fstream>
#include <sstream>
#include "core/Paths.hpp"
#include "debug/FlowArchive.hpp"
#include "mcp/Json.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

namespace {

std::vector<std::string> lines(const char* text) {
    std::vector<std::string> out;
    std::string line;
    for (const char* c = text;; ++c) {
        if (*c == '\n' || *c == '\0' || *c == ',') {
            while (!line.empty() && (line.back() == ' ' || line.back() == '\r')) line.pop_back();
            while (!line.empty() && line.front() == ' ') line.erase(line.begin());
            if (!line.empty()) out.push_back(line);
            line.clear();
            if (!*c) break;
        } else
            line += *c;
    }
    return out;
}

std::string joinLines(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) out += (out.empty() ? "" : "\n") + s;
    return out;
}

bool inputString(const char* id, std::string& s, const char* hint, float width) {
    char buf[1024];
    std::snprintf(buf, sizeof buf, "%s", s.c_str());
    ImGui::SetNextItemWidth(width);
    const bool changed = ImGui::InputTextWithHint(id, hint, buf, sizeof buf);
    if (changed) s = buf;
    return changed;
}

}  // namespace

void TrafficPanel::loadRouting() {
    if (routingLoaded_) return;
    routingLoaded_ = true;
    Json j;
    if (Json::parse(settings_.getString(Settings::kTrafficRouting, ""), j)) {
        for (const Json& s : j.get("ignoreHosts").items()) routing_.ignoreHosts.push_back(s.asString(""));
        for (const Json& s : j.get("allowHosts").items()) routing_.allowHosts.push_back(s.asString(""));
        for (const Json& m : j.get("mapLocal").items())
            routing_.mapLocal.push_back({m.get("enabled").asBool(true), m.get("url").asString(""), m.get("path").asString(""),
                                         m.get("type").asString("")});
        for (const Json& m : j.get("mapRemote").items())
            routing_.mapRemote.push_back({m.get("enabled").asBool(true), m.get("from").asString(""), m.get("to").asString("")});
    }
    Json c;
    if (Json::parse(settings_.getString(Settings::kTrafficConditions, ""), c)) {
        conditions_.latencyMs = static_cast<int>(c.get("latencyMs").asInt(0));
        conditions_.downKbps = static_cast<int>(c.get("downKbps").asInt(0));
        conditions_.upKbps = static_cast<int>(c.get("upKbps").asInt(0));
        conditions_.failPercent = static_cast<int>(c.get("failPercent").asInt(0));
        devices_.traffic().setConditions(conditions_);
    }
    std::snprintf(ignoreHosts_, sizeof ignoreHosts_, "%s", joinLines(routing_.ignoreHosts).c_str());
    std::snprintf(allowHosts_, sizeof allowHosts_, "%s", joinLines(routing_.allowHosts).c_str());
    devices_.traffic().setRouting(routing_);
}

void TrafficPanel::applyRouting() {
    routing_.ignoreHosts = lines(ignoreHosts_);
    routing_.allowHosts = lines(allowHosts_);
    devices_.traffic().setRouting(routing_);
    Json j = Json::object();
    Json ig = Json::array(), al = Json::array(), ml = Json::array(), mr = Json::array();
    for (const auto& s : routing_.ignoreHosts) ig.push(s);
    for (const auto& s : routing_.allowHosts) al.push(s);
    for (const auto& m : routing_.mapLocal)
        ml.push(Json::obj({{"enabled", m.enabled}, {"url", m.urlPattern}, {"path", m.localPath}, {"type", m.contentType}}));
    for (const auto& m : routing_.mapRemote) mr.push(Json::obj({{"enabled", m.enabled}, {"from", m.from}, {"to", m.to}}));
    j.set("ignoreHosts", ig);
    j.set("allowHosts", al);
    j.set("mapLocal", ml);
    j.set("mapRemote", mr);
    settings_.set(Settings::kTrafficRouting, j.dump());
}

void TrafficPanel::drawRouting() {
    TrafficProxy& proxy = devices_.traffic();
    bool changed = false;

    ImGui::SeparatorText("Hosts");
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("One pattern per line: a name covers its subdomains (googleapis.com), * and ? are wildcards. "
                        "Ignored hosts - and, when the allow list is not empty, hosts not on it - are relayed as blind "
                        "tunnels: never decrypted, so pinned or noisy services keep working.");
    ImGui::PopTextWrapPos();
    const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
    ImGui::BeginGroup();
    ImGui::TextUnformatted("Ignore");
    ImGui::InputTextMultiline("##ignore", ignoreHosts_, sizeof ignoreHosts_, ImVec2(half, ImGui::GetTextLineHeight() * 5.f));
    changed |= ImGui::IsItemDeactivatedAfterEdit();
    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();
    ImGui::TextUnformatted("Allow only (empty = all)");
    ImGui::InputTextMultiline("##allow", allowHosts_, sizeof allowHosts_, ImVec2(half, ImGui::GetTextLineHeight() * 5.f));
    changed |= ImGui::IsItemDeactivatedAfterEdit();
    ImGui::EndGroup();
    if (ui::smallButton("Ignore common Google / analytics hosts")) {
        static const char* kNoise[] = {"googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
                                       "doubleclick.net", "crashlytics.com", "app-measurement.com", "firebaseinstallations.googleapis.com",
                                       "play.googleapis.com", "android.clients.google.com"};
        std::vector<std::string> cur = lines(ignoreHosts_);
        for (const char* n : kNoise)
            if (std::find(cur.begin(), cur.end(), n) == cur.end()) cur.push_back(n);
        std::snprintf(ignoreHosts_, sizeof ignoreHosts_, "%s", joinLines(cur).c_str());
        changed = true;
    }

    ImGui::SeparatorText("Map local");
    ImGui::TextDisabled("Answer matching URLs from a local file (or a directory: the rest of the path names the file).");
    int removeLocal = -1;
    for (size_t i = 0; i < routing_.mapLocal.size(); ++i) {
        auto& m = routing_.mapLocal[i];
        ImGui::PushID(static_cast<int>(i) + 1000);
        changed |= ImGui::Checkbox("##on", &m.enabled);
        ImGui::SameLine();
        changed |= inputString("##url", m.urlPattern, "https://api.example.com/v1/config*", ui::em(18.f));
        ImGui::SameLine();
        changed |= inputString("##path", m.localPath, "C:\\mocks\\config.json", ui::em(14.f));
        ImGui::SameLine();
        if (ui::smallButton("...")) {
            mapLocalBrowseRow_ = static_cast<int>(i);
            mapLocalBrowser_.open(FileBrowser::Mode::OpenFile);
        }
        ImGui::SameLine();
        changed |= inputString("##type", m.contentType, "type (auto)", ui::em(8.f));
        ImGui::SameLine();
        if (ui::smallButton("x")) removeLocal = static_cast<int>(i);
        ImGui::PopID();
    }
    if (removeLocal >= 0) routing_.mapLocal.erase(routing_.mapLocal.begin() + removeLocal), changed = true;
    if (ui::smallButton("Add map local rule")) routing_.mapLocal.push_back({}), changed = true;
    mapLocalBrowser_.render();
    {
        std::string path;
        if (mapLocalBrowser_.takeAccepted(path) && mapLocalBrowseRow_ >= 0 &&
            mapLocalBrowseRow_ < static_cast<int>(routing_.mapLocal.size())) {
            routing_.mapLocal[static_cast<size_t>(mapLocalBrowseRow_)].localPath = path;
            changed = true;
        }
    }

    ImGui::SeparatorText("Map remote");
    ImGui::TextDisabled("Send requests whose URL starts with the first prefix to the second one instead (staging, a local mock).");
    int removeRemote = -1;
    for (size_t i = 0; i < routing_.mapRemote.size(); ++i) {
        auto& m = routing_.mapRemote[i];
        ImGui::PushID(static_cast<int>(i) + 2000);
        changed |= ImGui::Checkbox("##on", &m.enabled);
        ImGui::SameLine();
        changed |= inputString("##from", m.from, "https://api.example.com", ui::em(18.f));
        ImGui::SameLine();
        ImGui::TextUnformatted("->");
        ImGui::SameLine();
        changed |= inputString("##to", m.to, "http://127.0.0.1:8080", ui::em(18.f));
        ImGui::SameLine();
        if (ui::smallButton("x")) removeRemote = static_cast<int>(i);
        ImGui::PopID();
    }
    if (removeRemote >= 0) routing_.mapRemote.erase(routing_.mapRemote.begin() + removeRemote), changed = true;
    if (ui::smallButton("Add map remote rule")) routing_.mapRemote.push_back({}), changed = true;

    if (changed) applyRouting();

    ImGui::SeparatorText("Server replay");
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("Answer requests from recorded responses (same method and URL) without contacting the servers - to "
                        "test the app offline or against a frozen session.");
    ImGui::PopTextWrapPos();
    ImGui::Checkbox("Reuse responses", &replayOptions_.reuse);
    ImGui::SameLine();
    ImGui::Checkbox("Ignore query strings", &replayOptions_.ignoreQuery);
    ImGui::SameLine();
    ImGui::Checkbox("404 for unmatched requests", &replayOptions_.refuseUnmatched);
    if (ui::smallButton("Replay the captured requests")) {
        std::vector<uint64_t> ids;
        for (const auto& r : rows_) ids.push_back(r.id);
        std::vector<TrafficProxy::Flow> recorded = proxy.fullFlows(ids);
        const size_t n = recorded.size();
        proxy.setServerReplay(std::move(recorded), replayOptions_);
        replayStatus_ = "Replaying " + std::to_string(n) + " captured requests.";
    }
    ImGui::SameLine();
    if (ui::smallButton("Replay a HAR file...")) replayOpener_.open(FileBrowser::Mode::OpenFile);
    ImGui::SameLine();
    if (ui::smallButton("Stop replay")) {
        proxy.clearServerReplay();
        replayStatus_ = "Replay stopped.";
    }
    replayOpener_.render();
    {
        std::string path;
        if (replayOpener_.takeAccepted(path)) {
            std::ifstream in(pathutil::fromUtf8(path), std::ios::binary);
            std::stringstream ss;
            ss << in.rdbuf();
            std::vector<TrafficProxy::Flow> recorded;
            std::string error;
            if (!in || !flowarchive::fromHar(ss.str(), recorded, error)) replayStatus_ = "Could not read " + path + ": " + error;
            else {
                const size_t n = recorded.size();
                proxy.setServerReplay(std::move(recorded), replayOptions_);
                replayStatus_ = "Replaying " + std::to_string(n) + " requests from " + path;
            }
        }
    }
    if (!replayStatus_.empty()) ui::wrappedColored(kDim, replayStatus_ + "  (" + std::to_string(proxy.serverReplayLeft()) + " unused)");

    ImGui::SeparatorText("Network conditions");
    ImGui::TextDisabled("Slow the traffic down or make it fail, to see how the app copes (applies at once).");
    bool condChanged = false;
    struct Preset {
        const char* name;
        TrafficProxy::Conditions c;
    };
    static const Preset kPresets[] = {{"Off", {0, 0, 0, 0}},
                                      {"Fast 3G", {150, 1600, 750, 0}},
                                      {"Slow 3G", {400, 400, 400, 0}},
                                      {"2G / EDGE", {800, 240, 200, 0}},
                                      {"Flaky (20% fail)", {200, 2000, 1000, 20}},
                                      {"Offline-ish (90% fail)", {0, 0, 0, 90}}};
    for (const auto& p : kPresets) {
        if (&p != kPresets) ImGui::SameLine();
        if (ui::smallButton(p.name)) conditions_ = p.c, condChanged = true;
    }
    ImGui::SetNextItemWidth(ui::em(7.f));
    condChanged |= ImGui::InputInt("latency ms", &conditions_.latencyMs, 50, 200);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(7.f));
    condChanged |= ImGui::InputInt("down kbit/s", &conditions_.downKbps, 100, 1000);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(7.f));
    condChanged |= ImGui::InputInt("up kbit/s", &conditions_.upKbps, 100, 1000);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(7.f));
    condChanged |= ImGui::SliderInt("% fail", &conditions_.failPercent, 0, 100);
    if (condChanged) {
        conditions_.latencyMs = std::clamp(conditions_.latencyMs, 0, 60000);
        conditions_.downKbps = std::max(0, conditions_.downKbps);
        conditions_.upKbps = std::max(0, conditions_.upKbps);
        proxy.setConditions(conditions_);
        settings_.set(Settings::kTrafficConditions,
                      Json::obj({{"latencyMs", conditions_.latencyMs},
                                 {"downKbps", conditions_.downKbps},
                                 {"upKbps", conditions_.upKbps},
                                 {"failPercent", conditions_.failPercent}})
                          .dump());
    }
    if (conditions_.active()) ImGui::TextColored(kWarn, "Network conditions are on: traffic is slowed down or dropped on purpose.");
}
