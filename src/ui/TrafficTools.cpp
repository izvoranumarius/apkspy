// Traffic panel: filter expressions, HAR sessions and traffic scripts.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "core/Paths.hpp"
#include "debug/HttpClient.hpp"
#include "debug/FlowArchive.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxScriptLog = 2000;

long long mtimeOf(const std::string& path) {
    std::error_code ec;
    const auto t = fs::last_write_time(pathutil::fromUtf8(path), ec);
    return ec ? 0 : static_cast<long long>(t.time_since_epoch().count());
}

// One number that changes when any of the scripts is saved.
long long mtimeOf(const std::vector<std::string>& paths) {
    long long sum = 0;
    for (const auto& p : paths) sum ^= mtimeOf(p) + static_cast<long long>(std::hash<std::string>{}(p));
    return sum;
}

std::string scriptSupportDir() { return pathutil::toUtf8(pathutil::configDir() / "traffic-scripts"); }

}  // namespace

TrafficPanel::~TrafficPanel() {
    devices_.traffic().setHooks(nullptr);
    if (scriptJob_.valid()) {
        auto [host, error] = scriptJob_.get();
        if (host) host->stop();
    }
    if (script_) script_->stop();
}

// ---------------------------------------------------------------------------
// Filter expressions
// ---------------------------------------------------------------------------

void TrafficPanel::updateExpression(const std::string& text) {
    TrafficProxy& proxy = devices_.traffic();
    if (exprJob_.valid() && exprJob_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        std::vector<uint64_t> ids = exprJob_.get();
        if (exprJobFor_ == exprText_)
            for (uint64_t id : ids) exprHits_.insert(id);
    }
    if (text != exprText_) {
        exprText_ = text;
        exprHits_.clear();
        exprHead_ = 0;
        exprError_.clear();
        expr_.reset();
        if (!text.empty()) expr_ = flowfilter::Filter::parse(text, exprError_);
    }
    if (!expr_ || !expr_->needsContent() || exprJob_.valid()) return;
    // Flows still running are looked at again once they complete.
    uint64_t since = exprHead_;
    for (const auto& r : rows_)
        if (!r.complete && r.id > 0) {
            since = std::min(since, r.id - 1);
            break;
        }
    const bool open = since < exprHead_;
    if (proxy.lastId() == exprHead_ && !(open && ImGui::GetFrameCount() % 30 == 0)) return;
    exprHead_ = proxy.lastId();
    std::unordered_map<uint64_t, std::string> marks;  // (highlight = an entry, comment = its text)
    for (const auto& [id, m] : marks_) marks[id] = m.comment;
    exprJobFor_ = exprText_;
    exprJob_ = std::async(std::launch::async, [&proxy, filter = expr_, marks = std::move(marks), since] {
        flowfilter::Context ctx;
        ctx.marked = [&marks](uint64_t id) { return marks.count(id) > 0; };
        ctx.comment = [&marks](uint64_t id) {
            const auto it = marks.find(id);
            return it == marks.end() ? std::string() : it->second;
        };
        return proxy.selectFlows([&](const TrafficProxy::Flow& f) { return filter->match(f, &ctx); }, since);
    });
}

void TrafficPanel::drawFilterHelp() {
    ImGui::TextUnformatted("Filter expressions (mitmproxy syntax)");
    ImGui::TextDisabled("Plain text searches host, path, method, status and comments.");
    ImGui::TextDisabled("Text with a ~filter is an expression:");
    size_t n = 0;
    const flowfilter::Help* items = flowfilter::helpItems(n);
    if (ImGui::BeginTable("##filterhelp", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
        for (size_t i = 0; i < n; ++i) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushFont(Theme::monoFont());
            ImGui::TextColored(kAccent, "%s", items[i].syntax);
            ImGui::PopFont();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(items[i].meaning);
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    ImGui::TextDisabled("Examples (click to use):");
    static const char* kExamples[] = {"~d api & ~m POST", "~c 500 | ~e", "~t json & !~a", "~bs \"token\"",
                                      "~hq authorization", "~websocket", "!~tcp & ~s"};
    ImGui::PushFont(Theme::monoFont());
    for (const char* ex : kExamples)
        if (ImGui::Selectable(ex)) std::snprintf(filter_, sizeof filter_, "%s", ex);
    ImGui::PopFont();
}

// ---------------------------------------------------------------------------
// Sessions (HAR)
// ---------------------------------------------------------------------------

void TrafficPanel::loadProtoDir(const std::string& dir, bool report) {
    auto schema = std::make_shared<protoschema::Schema>();
    std::vector<std::string> errors;
    const size_t n = schema->addDirectory(dir, errors);
    protoSchema() = schema;
    settings_.set(Settings::kTrafficProtoDir, dir);
    if (report) {
        status_ = "Loaded " + std::to_string(n) + " .proto files (" + std::to_string(schema->messageNames().size()) +
                  " message types) from " + dir;
        if (!errors.empty()) status_ += "; " + std::to_string(errors.size()) + " failed: " + errors.front();
    }
}

void TrafficPanel::drawSessionDialogs() {
    TrafficProxy& proxy = devices_.traffic();
    if (!protoLoaded_) {
        protoLoaded_ = true;
        const std::string dir = settings_.getString(Settings::kTrafficProtoDir, "");
        if (!dir.empty()) loadProtoDir(dir, false);
    }
    protoOpener_.render();
    {
        std::string dir;
        if (protoOpener_.takeAccepted(dir)) loadProtoDir(dir, true);
    }
    harSaver_.render();
    std::string path;
    if (harSaver_.takeAccepted(path)) {
        std::vector<uint64_t> ids;
        if (harSaveFiltered_) ids = shownIds_;
        else
            for (const auto& r : rows_) ids.push_back(r.id);
        flowarchive::Marks marks;
        for (const auto& [id, m] : marks_) marks[id] = {m.color, m.comment};
        const std::string har = flowarchive::toHar(proxy.fullFlows(ids), &marks);
        std::ofstream out(pathutil::fromUtf8(path), std::ios::binary | std::ios::trunc);
        out.write(har.data(), static_cast<std::streamsize>(har.size()));
        status_ = out.good() ? "Saved " + std::to_string(ids.size()) + " requests to " + path : "Could not write " + path;
    }
    harOpener_.render();
    if (harOpener_.takeAccepted(path)) {
        std::ifstream in(pathutil::fromUtf8(path), std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        std::vector<TrafficProxy::Flow> flows;
        std::vector<flowarchive::Mark> marks;
        std::string error;
        if (!in) status_ = "Could not read " + path;
        else if (!flowarchive::fromHar(ss.str(), flows, error, &marks)) status_ = "Could not open " + path + ": " + error;
        else {
            std::vector<uint64_t> ids;
            const size_t n = proxy.importFlows(std::move(flows), &ids);
            for (size_t i = 0; i < ids.size() && i < marks.size(); ++i)
                if (marks[i].color || !marks[i].comment.empty()) marks_[ids[i]] = {marks[i].color, marks[i].comment};
            rows_.clear();  // refetched next frame
            status_ = "Opened " + std::to_string(n) + " requests from " + path;
        }
    }
}

// ---------------------------------------------------------------------------
// Batch replay and "copy as"
// ---------------------------------------------------------------------------

void TrafficPanel::startBatchReplay(const std::vector<uint64_t>& ids) {
    if (batch_.job.valid()) return;
    std::vector<TrafficProxy::Flow> flows;
    for (auto& f : devices_.traffic().fullFlows(ids))
        if (!f.tunnel && !f.request.startLine.empty() && f.method != "PRI") flows.push_back(std::move(f));
    if (flows.empty()) {
        status_ = "Nothing to replay (tunnels cannot be replayed).";
        return;
    }
    batch_.cancel = std::make_shared<std::atomic<bool>>(false);
    batch_.done = std::make_shared<std::atomic<int>>(0);
    batch_.total = static_cast<int>(flows.size());
    batch_.job = std::async(std::launch::async, [flows = std::move(flows), cancel = batch_.cancel, done = batch_.done] {
        std::vector<TrafficProxy::Flow> out;
        for (const auto& f : flows) {
            if (cancel->load()) break;
            httpclient::Target t;
            t.host = f.sni.empty() ? f.host : f.sni;
            t.port = f.port;
            t.https = f.https;
            const std::string request = httpclient::editableRequest(f);
            httpclient::Options o;
            const double started = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
            httpclient::Result r = httpclient::send(t, request, o, cancel.get());
            TrafficProxy::Flow n;
            n.startedAt = started;
            n.durationMs = r.ms;
            n.method = f.method;
            n.host = f.host;
            n.port = f.port;
            n.path = f.path;
            n.https = f.https;
            n.sni = f.sni;
            n.complete = true;
            n.note = "replayed from #" + std::to_string(f.id);
            const size_t headEnd = r.sent.find("\r\n\r\n");
            if (headEnd != std::string::npos && TrafficProxy::parseHead(r.sent.substr(0, headEnd + 2), n.request)) {
                n.request.body = r.sent.substr(headEnd + 4);
                n.request.bodySize = n.request.body.size();
            } else
                n.request = f.request;
            n.response = r.response;
            n.status = r.status;
            n.error = r.ok ? std::string() : r.error;
            n.bytesUp = n.request.bodySize;
            n.bytesDown = r.response.bodySize;
            out.push_back(std::move(n));
            ++*done;
        }
        return out;
    });
}

void TrafficPanel::pollBatchReplay() {
    if (!batch_.job.valid()) return;
    if (batch_.job.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
    std::vector<TrafficProxy::Flow> flows = batch_.job.get();
    const size_t n = devices_.traffic().importFlows(std::move(flows));
    rows_.clear();
    status_ = "Replayed " + std::to_string(n) + " of " + std::to_string(batch_.total) + " requests (marked 'replayed').";
}

void TrafficPanel::copyAsMenu(uint64_t flowId) {
    for (int i = 0; i < flowexport::kFormatCount; ++i) {
        const auto fmt = static_cast<flowexport::Format>(i);
        if (ImGui::MenuItem(flowexport::formatName(fmt))) {
            TrafficProxy::Flow full;
            if (devices_.traffic().flow(flowId, full)) ImGui::SetClipboardText(flowexport::render(fmt, full).c_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Scripts
// ---------------------------------------------------------------------------

// A script is a line of the list; a line starting with # is switched off: it stays in the list (and in the saved
// settings) but is not loaded. The toggles under the list add and remove the #.
std::vector<std::string> TrafficPanel::scriptPathList() const {
    std::vector<std::string> out;
    for (const std::string& line : scriptLines())
        if (line[0] != '#') out.push_back(line);
    return out;
}

std::vector<std::string> TrafficPanel::scriptLines() const {
    std::vector<std::string> out;
    std::string line;
    for (const char* c = scriptPaths_;; ++c) {
        if (*c == '\n' || *c == '\0') {
            while (!line.empty() && (line.back() == ' ' || line.back() == '\r' || line.back() == '"')) line.pop_back();
            while (!line.empty() && (line.front() == ' ' || line.front() == '"')) line.erase(line.begin());
            if (!line.empty()) out.push_back(line);
            line.clear();
            if (!*c) break;
        } else
            line += *c;
    }
    return out;
}

void TrafficPanel::loadScripts(std::vector<std::string> paths) {
    if (scriptJob_.valid() || paths.empty()) return;
    std::string joined;  // '|' cannot appear in a path (Windows) and keeps the settings file one line per key
    for (const auto& line : scriptLines()) joined += (joined.empty() ? "" : "|") + line;  // enabled and disabled ones
    settings_.set(Settings::kTrafficScript, joined);
    devices_.traffic().setHooks(nullptr);
    if (script_) {
        for (auto& line : script_->takeLog()) scriptLog_.push_back(std::move(line));
        script_->stop();
        script_.reset();
    }
    scriptMtime_ = mtimeOf(paths);
    const std::string python = settings_.getString(Settings::kPythonPath, "python");
    scriptLog_.push_back("[ApkSpy] loading " + std::to_string(paths.size()) + " script(s) ...");
    scriptJob_ = std::async(std::launch::async, [python, paths, dir = scriptSupportDir()] {
        auto host = std::make_shared<trafficscript::Host>();
        std::string error;
        host->start(python, paths, dir, error);
        return std::make_pair(host, error);
    });
}

void TrafficPanel::pollScript() {
    if (!scriptPaths_[0] && !settings_.getString(Settings::kTrafficScript, "").empty()) {
        std::string saved = settings_.getString(Settings::kTrafficScript, "");
        for (char& c : saved)
            if (c == '|') c = '\n';
        std::snprintf(scriptPaths_, sizeof scriptPaths_, "%s", saved.c_str());
    }
    if (scriptJob_.valid() && scriptJob_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        auto [host, error] = scriptJob_.get();
        for (auto& line : host->takeLog()) scriptLog_.push_back(std::move(line));
        if (error.empty()) {
            script_ = host;
            devices_.traffic().setHooks(host);
        } else {
            scriptLog_.push_back("[ApkSpy] " + error);
        }
    }
    if (script_) {
        for (auto& line : script_->takeLog()) scriptLog_.push_back(std::move(line));
        // Reload when a script is saved (checked about once a second).
        if (scriptAutoReload_ && ++scriptCheckFrame_ % 60 == 0 && !scriptJob_.valid()) {
            const long long now = mtimeOf(script_->scripts());
            if (now != scriptMtime_) {
                scriptLog_.push_back("[ApkSpy] a script changed - reloading");
                loadScripts(script_->scripts());
            }
        }
    }
    if (scriptLog_.size() > kMaxScriptLog)
        scriptLog_.erase(scriptLog_.begin(), scriptLog_.begin() + static_cast<ptrdiff_t>(scriptLog_.size() - kMaxScriptLog));
}

void TrafficPanel::drawScripts() {
    const bool loading = scriptJob_.valid();
    const bool active = script_ && script_->running();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("Python scripts with request / response / websocket_message / error hooks (mitmproxy-style) see "
                        "every HTTP exchange and WebSocket message and can change it, answer it or drop it. One script "
                        "per line; their hooks run in that order. They run in the Python set in Settings and reload "
                        "when saved.");
    ImGui::PopTextWrapPos();
    ImGui::PushFont(Theme::monoFont());
    ui::codeBox("##scriptpaths", scriptPaths_, sizeof scriptPaths_,
                              ImVec2(-ui::buttonWidth("Browse...") - ImGui::GetStyle().ItemSpacing.x, ImGui::GetTextLineHeight() * 3.6f));
    ImGui::PopFont();
    ImGui::SameLine();
    ImGui::BeginGroup();
    if (ImGui::Button("Browse...")) scriptOpener_.open(FileBrowser::Mode::OpenFile);
    if (ImGui::Button("New...")) {
        scriptSaver_.open(FileBrowser::Mode::SaveFile);
        scriptSaver_.setDefaultName("apkspy_script.py");
    }
    ImGui::EndGroup();
    // Per-script switches: a switched-off script stays in the list but is not loaded.
    {
        std::vector<std::string> lines = scriptLines();
        bool changed = false;
        for (size_t i = 0; i < lines.size(); ++i) {
            const bool wasOn = lines[i][0] != '#';
            bool on = wasOn;
            const std::string full = wasOn ? lines[i] : lines[i].substr(1);
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Checkbox(pathutil::toUtf8(pathutil::fromUtf8(full).filename()).c_str(), &on)) {
                lines[i] = on ? full : "#" + full;
                changed = true;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", full.c_str(), on ? "enabled: loaded with the others" : "disabled: stays in the list, not loaded");
            ImGui::PopID();
        }
        if (changed) {
            std::string text;
            for (const auto& l : lines) text += (text.empty() ? "" : "\n") + l;
            std::snprintf(scriptPaths_, sizeof scriptPaths_, "%s", text.c_str());
            const std::vector<std::string> enabled = scriptPathList();
            settings_.set(Settings::kTrafficScript, [&] {
                std::string joined;
                for (const auto& l : lines) joined += (joined.empty() ? "" : "|") + l;
                return joined;
            }());
            if (enabled.empty() && script_ && !loading) {  // everything switched off: unload
                devices_.traffic().setHooks(nullptr);
                for (auto& line : script_->takeLog()) scriptLog_.push_back(std::move(line));
                script_->stop();
                script_.reset();
                scriptLog_.push_back("[ApkSpy] all scripts switched off - unloaded");
            } else if (!enabled.empty() && (script_ || scriptJob_.valid())) {
                loadScripts(enabled);  // a loaded set follows the switches at once
            }
        }
    }
    const std::vector<std::string> paths = scriptPathList();
    ImGui::BeginDisabled(loading || paths.empty());
    if (ImGui::Button(active ? "Reload" : "Load")) loadScripts(paths);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!script_ || loading);
    if (ImGui::Button("Unload")) {
        devices_.traffic().setHooks(nullptr);
        for (auto& line : script_->takeLog()) scriptLog_.push_back(std::move(line));
        script_->stop();
        script_.reset();
        scriptLog_.push_back("[ApkSpy] script unloaded");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox("Reload on save", &scriptAutoReload_);
    ImGui::SameLine();
    if (loading) ImGui::TextColored(kWarn, "loading...");
    else if (active) {
        std::string hooks;
        const auto add = [&](bool on, const char* name) {
            if (on) hooks += (hooks.empty() ? "" : ", ") + std::string(name);
        };
        add(script_->hasRequestHook(), "request");
        add(script_->hasResponseHook(), "response");
        add(script_->hasWebSocketHook(), "websocket_message");
        add(script_->hasErrorHook(), "error");
        ImGui::TextColored(kGood, "running (%s) - %llu calls, %llu changed", hooks.empty() ? "no hooks" : hooks.c_str(),
                           static_cast<unsigned long long>(script_->calls()), static_cast<unsigned long long>(script_->changes()));
    } else if (script_)
        ImGui::TextColored(kError, "stopped - see the log");
    else
        ImGui::TextDisabled("no script loaded");

    scriptOpener_.render();
    std::string path;
    const auto addPath = [&](const std::string& added) {
        std::vector<std::string> all = scriptLines();  // switched-off scripts stay in the list
        if (std::find(all.begin(), all.end(), added) == all.end() && std::find(all.begin(), all.end(), "#" + added) == all.end()) all.push_back(added);
        std::string text;
        for (const auto& s : all) text += (text.empty() ? "" : "\n") + s;
        std::snprintf(scriptPaths_, sizeof scriptPaths_, "%s", text.c_str());
        loadScripts(scriptPathList());
    };
    if (scriptOpener_.takeAccepted(path)) addPath(path);
    scriptSaver_.render();
    if (scriptSaver_.takeAccepted(path)) {
        std::error_code ec;
        if (fs::exists(pathutil::fromUtf8(path), ec)) {
            scriptLog_.push_back("[ApkSpy] " + path + " exists - not overwritten; loading it");
        } else {
            std::ofstream out(pathutil::fromUtf8(path), std::ios::binary);
            out << trafficscript::Host::exampleScript();
            if (!out.good()) scriptLog_.push_back("[ApkSpy] could not write " + path);
        }
        // apkspy_addon.py next to the script lets editors resolve the import.
        std::string error;
        trafficscript::Host::writeSupport(pathutil::toUtf8(pathutil::fromUtf8(path).parent_path()), error);
        addPath(path);
    }

    ImGui::Separator();
    ImGui::TextUnformatted("Log");
    ImGui::SameLine();
    if (ui::smallButton("Clear##scriptlog")) scriptLog_.clear();
    ImGui::SameLine();
    if (ui::smallButton("Copy##scriptlog")) {
        std::string all;
        for (const auto& l : scriptLog_) all += l + "\n";
        ImGui::SetClipboardText(all.c_str());
    }
    ui::horizontalDivider();
    ImGui::BeginChild("##scriptlogbox", ImVec2(0, 0));
    ImGui::PushFont(Theme::monoFont());
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(scriptLog_.size()));
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const std::string& l = scriptLog_[static_cast<size_t>(i)];
            if (l.rfind("[ApkSpy]", 0) == 0) ImGui::TextColored(kDim, "%s", l.c_str());
            else if (l.find("Error") != std::string::npos || l.find("Traceback") != std::string::npos)
                ImGui::TextColored(kError, "%s", l.c_str());
            else
                ImGui::TextUnformatted(l.c_str());
        }
    ImGui::PopFont();
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.f) ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
}
