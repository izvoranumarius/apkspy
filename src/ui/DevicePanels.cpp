#include "ui/DevicePanels.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <functional>
#include "app/Theme.hpp"
#include "core/TextUtils.hpp"
#include "ui/UiUtil.hpp"

namespace {

const ImVec4 kDim(0.6f, 0.6f, 0.6f, 1.f);
const ImVec4 kGood(0.45f, 0.8f, 0.45f, 1.f);
const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);
const ImVec4 kError(0.95f, 0.45f, 0.4f, 1.f);
const ImVec4 kAccent(0.55f, 0.75f, 0.95f, 1.f);

ImVec4 levelColor(char level) {
    switch (level) {
    case 'V': return ImVec4(0.6f, 0.6f, 0.6f, 1.f);
    case 'D': return ImVec4(0.55f, 0.75f, 0.95f, 1.f);
    case 'I': return ImVec4(0.8f, 0.8f, 0.8f, 1.f);
    case 'W': return ImVec4(0.95f, 0.8f, 0.35f, 1.f);
    case 'E': return ImVec4(0.95f, 0.45f, 0.4f, 1.f);
    case 'F': return ImVec4(1.f, 0.3f, 0.6f, 1.f);
    default: return ImVec4(0.8f, 0.8f, 0.8f, 1.f);
    }
}

std::string javaClassOf(const std::string& methodRef) {
    std::string cls = methodRef.substr(0, methodRef.find("->"));
    if (cls.size() > 2 && cls.front() == 'L') cls = cls.substr(1, cls.size() - 2);
    std::replace(cls.begin(), cls.end(), '/', '.');
    return cls;
}

std::string methodNameOf(const std::string& ref) {
    const size_t arrow = ref.find("->");
    if (arrow == std::string::npos) return ref;
    return ref.substr(arrow + 2, ref.find('(', arrow) - arrow - 2);
}

// "Lcom/x/Foo;" / "I" / "[Ljava/lang/String;" at s[i] -> "Foo" / "int" / "String[]", advancing i.
std::string shortType(const std::string& s, size_t& i) {
    int dims = 0;
    while (i < s.size() && s[i] == '[') ++dims, ++i;
    std::string t;
    if (i < s.size() && s[i] == 'L') {
        const size_t end = s.find(';', i);
        const size_t stop = end == std::string::npos ? s.size() : end;
        t = s.substr(i + 1, stop - i - 1);
        t = t.substr(t.find_last_of('/') + 1);
        i = stop + 1;
    } else if (i < s.size()) {
        static const char* const names[] = {"byte", "char", "double", "float", "int", "long", "short", "boolean", "void"};
        const size_t k = std::string("BCDFIJSZV").find(s[i]);
        t = k == std::string::npos ? std::string(1, s[i]) : names[k];
        ++i;
    }
    while (dims-- > 0) t += "[]";
    return t;
}

// "Lcom/x/Foo;->bar(ILjava/lang/String;)V" -> "Foo.bar(int, String)"
std::string shortMethod(const std::string& ref) {
    const size_t arrow = ref.find("->");
    if (arrow == std::string::npos) return ref;
    std::string cls = javaClassOf(ref);
    cls = cls.substr(cls.find_last_of('.') + 1);
    const size_t open = ref.find('(', arrow);
    std::string out = cls + "." + ref.substr(arrow + 2, open == std::string::npos ? std::string::npos : open - arrow - 2);
    if (open == std::string::npos) return out;
    out += "(";
    size_t i = open + 1;
    bool first = true;
    while (i < ref.size() && ref[i] != ')') {
        if (!first) out += ", ";
        out += shortType(ref, i);
        first = false;
    }
    return out + ")";
}

}  // namespace

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

void DevicesPanel::drawContents() {
    if (firstRefresh_) {
        firstRefresh_ = false;
        devices_.refreshDevices();
    }
    if (!devices_.lastError().empty()) ui::wrappedColored(kWarn, devices_.lastError());
    const std::vector<adb::Device> devices = devices_.devices();
    const std::string selected = devices_.selected();
    if (devices.empty()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("No device. Connect a phone with USB debugging enabled or start an emulator.");
        ImGui::PopTextWrapPos();
        ImGui::BeginDisabled(devices_.refreshing());
        if (ImGui::Button(devices_.refreshing() ? "Looking..." : "Look again")) devices_.refreshDevices();
        ImGui::EndDisabled();
        return;
    }
    if (selected.empty() && devices.size() == 1 && devices.front().state == "device") {
        devices_.select(devices.front().serial);
        devices_.refreshProcesses();
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    std::string current = selected.empty() ? "(select a device)" : selected;
    for (const auto& d : devices)
        if (d.serial == selected && !d.model.empty()) current = d.model + "  [" + d.serial + "]";
    if (ImGui::BeginCombo("##device", current.c_str())) {
        for (const auto& d : devices) {
            std::string label = (d.model.empty() ? d.serial : d.model + "  [" + d.serial + "]") + "  - " + d.state;
            if (ImGui::Selectable(label.c_str(), d.serial == selected, d.state == "device" ? 0 : ImGuiSelectableFlags_Disabled)) {
                devices_.select(d.serial);
                devices_.refreshProcesses();
            }
        }
        ImGui::EndCombo();
    }
    if (selected.empty()) return;

    // Auto-refresh the process list every few seconds while visible.
    const auto now = std::chrono::steady_clock::now();
    if (now - lastAutoRefresh_ > std::chrono::seconds(5) && !devices_.refreshing()) {
        lastAutoRefresh_ = now;
        devices_.refreshProcesses();
    }

    ImGui::SetNextItemWidth(-ui::buttonWidth("...") - ImGui::GetStyle().ItemSpacing.x);
    ImGui::InputTextWithHint("##pfilter", "Filter processes...", filter_, sizeof filter_);
    ImGui::SameLine();
    if (ImGui::Button("...##procopts")) ImGui::OpenPopup("##procopts");
    if (ImGui::BeginPopup("##procopts")) {
        ImGui::Checkbox("Debuggable only", &onlyDebuggable_);
        ImGui::Checkbox("Kernel threads", &showKernel_);
        if (ImGui::MenuItem("Refresh now")) {
            devices_.refreshDevices();
            devices_.refreshProcesses();
        }
        ImGui::EndPopup();
    }

    std::vector<adb::ProcessInfo> procs = devices_.processes();
    const std::vector<int> jdwp = devices_.debuggablePids();
    // Apps first (debuggable ones on top), then native daemons, by name;
    // kernel threads are noise for app work and hidden unless asked for.
    const auto isKernel = [](const adb::ProcessInfo& p) { return p.ppid == 2 || p.pid == 2 || (!p.name.empty() && p.name[0] == '['); };
    const auto isApp = [](const adb::ProcessInfo& p) { return p.user.rfind("u0_a", 0) == 0 || p.name.find('.') != std::string::npos; };
    const auto rank = [&](const adb::ProcessInfo& p) {
        const bool dbg = std::find(jdwp.begin(), jdwp.end(), p.pid) != jdwp.end();
        return dbg ? 0 : isApp(p) ? 1 : isKernel(p) ? 3 : 2;
    };
    std::stable_sort(procs.begin(), procs.end(), [&](const adb::ProcessInfo& a, const adb::ProcessInfo& b) {
        return rank(a) != rank(b) ? rank(a) < rank(b) : a.name < b.name;
    });
    const float monitorH = devices_.monitoring() ? ui::em(9.f) : 0.f;
    // Narrow panels drop the RSS column instead of squeezing every column.
    const bool wide = ImGui::GetContentRegionAvail().x > ui::em(26.f);
    if (ImGui::BeginTable("##procs", wide ? 3 : 2,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                          ImVec2(0, -monitorH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, ui::em(3.5f));
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        if (wide) ImGui::TableSetupColumn("RSS", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        ImGui::TableHeadersRow();
        for (const auto& p : procs) {
            const bool debuggable = std::find(jdwp.begin(), jdwp.end(), p.pid) != jdwp.end();
            if (onlyDebuggable_ && !debuggable) continue;
            if (!showKernel_ && isKernel(p)) continue;
            if (filter_[0] && tex::ciFind(p.name, filter_) == std::string_view::npos) continue;
            ImGui::PushID(p.pid);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char pidText[16];
            std::snprintf(pidText, sizeof pidText, "%d", p.pid);
            ImGui::Selectable(pidText, false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick);
            const bool open = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s  (pid %d, %s)%s", p.name.c_str(), p.pid, p.user.c_str(),
                                  debuggable ? "\nJDWP debuggable - double-click to attach" : "");
            const auto showInLogcat = [&] {
                std::string err;
                if (!devices_.logcatRunning() && !devices_.startLogcat(selected, err)) workspace_.log("Logcat: " + err, "debug");
                devices_.requestLogFilter(p.pid);
                showPanel_("Logcat");
            };
            if (ImGui::BeginPopupContextItem("##procctx")) {
                if (ImGui::MenuItem("Attach debugger", nullptr, false, debuggable)) attach(selected, p.pid);
                if (ImGui::MenuItem("Monitor CPU / memory")) devices_.startMonitor(selected, p.pid);
                if (ImGui::MenuItem("Show in Logcat")) showInLogcat();
                ImGui::Separator();
                if (ImGui::MenuItem("Copy name")) ImGui::SetClipboardText(p.name.c_str());
                if (ImGui::MenuItem("Copy pid")) ImGui::SetClipboardText(pidText);
                ImGui::EndPopup();
            }
            if (open) {
                if (debuggable) attach(selected, p.pid);
                else devices_.startMonitor(selected, p.pid);
            }
            ImGui::TableNextColumn();
            if (debuggable) ImGui::TextColored(kGood, "%s", p.name.c_str());
            else ImGui::TextUnformatted(p.name.c_str());
            if (wide) {
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%.1f MB", (double)p.rssKb / 1024.0);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (devices_.monitoring()) drawMonitor();
}

void DevicesPanel::drawMonitor() {
    const std::vector<DeviceService::Sample> samples = devices_.samples();
    ImGui::Separator();
    ImGui::Text("Monitoring pid %d", devices_.monitoredPid());
    if (ui::flowSmallButton("Stop")) devices_.stopMonitor();
    if (samples.empty()) {
        ImGui::TextDisabled("waiting for samples...");
        return;
    }
    std::vector<float> cpu, mem, threads;
    float maxMem = 1.f, maxThreads = 1.f;
    for (const auto& s : samples) {
        cpu.push_back((float)s.cpuPercent);
        mem.push_back((float)s.rssKb / 1024.f);
        threads.push_back((float)s.threads);
        maxMem = std::max(maxMem, mem.back());
        maxThreads = std::max(maxThreads, threads.back());
    }
    // Three plots side by side when there is room, stacked otherwise.
    const float avail = ImGui::GetContentRegionAvail().x;
    const bool row = avail > ui::em(24.f);
    const float w = row ? (avail - 2.f * ImGui::GetStyle().ItemSpacing.x) / 3.f : avail;
    const float h = row ? ui::em(6.f) : ui::em(3.f);
    char overlay[64];
    std::snprintf(overlay, sizeof overlay, "CPU %.1f%%", cpu.back());
    ImGui::PlotLines("##cpu", cpu.data(), (int)cpu.size(), 0, overlay, 0.f, 100.f, ImVec2(w, h));
    if (row) ImGui::SameLine();
    std::snprintf(overlay, sizeof overlay, "RSS %.1f MB", mem.back());
    ImGui::PlotLines("##mem", mem.data(), (int)mem.size(), 0, overlay, 0.f, maxMem * 1.2f, ImVec2(w, h));
    if (row) ImGui::SameLine();
    std::snprintf(overlay, sizeof overlay, "%d threads", samples.back().threads);
    ImGui::PlotLines("##thr", threads.data(), (int)threads.size(), 0, overlay, 0.f, maxThreads * 1.2f, ImVec2(w, h));
}

// ---------------------------------------------------------------------------
// Debugger
// ---------------------------------------------------------------------------

// Bytecode is exact (the listing lands on the instruction); decompiled source
// is the fallback, by line number, which jadx output only approximates.
void DebuggerPanel::followFrame(const DebugSession::FrameRow& frame) {
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(frame.method, cls, name, proto)) return;
    for (Root* r : workspace_.apkRoots())
        if (auto analysis = workspace_.analysis().get(r->title)) {
            const auto defs = analysis->findMethodDefs(cls, name, proto);
            if (!defs.empty()) {
                workspace_.openMethodListing(r->title, *analysis, defs.front(), (uint32_t)frame.location.index);
                return;
            }
        }
    for (Root* r : workspace_.decompiledRoots())
        if (workspace_.openSymbol(r->title, javaClassOf(frame.method), {}, nullptr)) {
            if (frame.line > 0)
                if (Document* doc = workspace_.activeDocument()) doc->goTo(frame.line - 1);
            return;
        }
}

void DevicesPanel::attach(const std::string& serial, int pid) {
    devices_.debugger().attach(serial, pid);
    std::string error;
    // Logcat follows the attached device (it may be showing another one).
    const bool sameDevice = devices_.logcatRunning() && devices_.logcatSerial() == serial;
    if (!sameDevice && !devices_.startLogcat(serial, error)) workspace_.log("Logcat: " + error, "debug");
    devices_.requestLogFilter(pid);
    showPanel_("Debugger");
}

void DebuggerPanel::processShortcuts() {
    if (ImGui::GetIO().WantTextInput) return;
    DebugSession& d = devices_.debugger();
    const DebugSession::State state = d.state();
    if (state != DebugSession::State::Running && state != DebugSession::State::Suspended) return;
    const bool shift = ImGui::GetIO().KeyShift;
    const bool suspended = state == DebugSession::State::Suspended;
    // x64dbg-like: F9 run, F12 pause, F7 step into, F8 step over, Ctrl+F9 / Shift+F8 step out.
    if (ImGui::IsKeyPressed(ImGuiKey_F9, false) && suspended) {
        if (ImGui::GetIO().KeyCtrl) d.step(2);
        else d.resume();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F12, false) && state == DebugSession::State::Running) d.suspend();
    if (suspended) {
        if (ImGui::IsKeyPressed(ImGuiKey_F7, false)) d.step(0);
        if (ImGui::IsKeyPressed(ImGuiKey_F8, false)) d.step(shift ? 2 : 1);
    }
}

void DebuggerPanel::drawContents() {
    DebugSession& d = devices_.debugger();
    const DebugSession::Snapshot s = d.snapshot();

    // Status + toolbar (flows onto several rows in a narrow panel).
    const bool attached = s.state == DebugSession::State::Running || s.state == DebugSession::State::Suspended;
    const bool suspended = s.state == DebugSession::State::Suspended;
    const ImVec4 stateCol = suspended ? kWarn
                            : s.state == DebugSession::State::Running ? kGood
                            : s.state == DebugSession::State::Failed  ? kError
                                                                      : kDim;
    if (attached) {
        const auto keyTip = [](const char* text) {
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", text);
        };
        if (ImGui::Button(suspended ? "Resume" : "Pause")) {
            if (suspended) d.resume();
            else d.suspend();
        }
        keyTip(suspended ? "F9" : "F12");
        if (!suspended) ImGui::BeginDisabled();
        if (ui::flowButton("Step into")) d.step(0);
        keyTip("F7");
        if (ui::flowButton("Step over")) d.step(1);
        keyTip("F8");
        if (ui::flowButton("Step out")) d.step(2);
        keyTip("Ctrl+F9");
        if (!suspended) ImGui::EndDisabled();
        if (ui::flowButton("Detach")) d.detach();
        ImGui::SameLine(0.f, ui::em(1.f));
        ImGui::TextColored(stateCol, "%s", DebugSession::stateName(s.state));
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("pid %d on %s\n%s", s.pid, s.serial.c_str(), s.vm.c_str());
    } else {
        ImGui::TextDisabled("Not attached. Double-click a green process in Devices.");
    }
    if (!s.error.empty()) ui::wrappedColored(kError, s.error);

    // Threads, stack and locals in three columns with room to spare (the Debug
    // workspace), side by side when wide, stacked when narrow.
    const float availW = ImGui::GetContentRegionAvail().x;
    const bool wide = availW > ui::em(36.f);
    const bool threeColumns = availW > ui::em(40.f);
    const float bottomH = ui::em(10.f);
    if (attached) {
        // Show the code a stop landed on. Runs from here, so the Debug workspace's
        // editor catches up on a stop that happened while another one was open.
        if (!suspended) followed_.clear();
        if (suspended && s.selectedFrame >= 0 && s.selectedFrame < (int)s.frames.size()) {
            const auto& frame = s.frames[(size_t)s.selectedFrame];
            const std::string key = frame.method + "@" + std::to_string(frame.location.index);
            if (key != followed_) {
                followed_ = key;
                followFrame(frame);
            }
        }
        const float upperH = wide ? -bottomH : std::max(ui::em(8.f), (ImGui::GetContentRegionAvail().y - bottomH) * 0.3f);
        ImGui::BeginChild("##dbgThreads", ImVec2(threeColumns ? availW * 0.30f : wide ? availW * 0.38f : 0.f, upperH),
                          ImGuiChildFlags_Borders);
        ImGui::TextColored(kAccent, "Threads (%zu)", s.threads.size());
        if (ImGui::BeginTable("##thr", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, ui::em(4.f));
            ImGui::TableHeadersRow();
            for (const auto& t : s.threads) {
                ImGui::PushID((int)(t.id & 0x7fffffff));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (ImGui::Selectable(t.name.c_str(), t.id == s.currentThread, ImGuiSelectableFlags_SpanAllColumns)) d.selectThread(t.id);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s%s", t.name.c_str(), t.suspend ? "\nsuspended" : "");
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", DebugSession::threadStatusName(t.status));
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
        if (wide) ImGui::SameLine();
        ImGui::BeginChild("##dbgStack", ImVec2(threeColumns ? availW * 0.32f : 0.f, wide ? -bottomH : upperH * 2.f),
                          ImGuiChildFlags_Borders);
        ImGui::TextColored(kAccent, "Call stack");
        ImGui::BeginChild("##stack", ImVec2(0, threeColumns ? 0.f : ImGui::GetContentRegionAvail().y * 0.5f), ImGuiChildFlags_None,
                          ImGuiWindowFlags_HorizontalScrollbar);
        for (int i = 0; i < (int)s.frames.size(); ++i) {
            const auto& f = s.frames[(size_t)i];
            const std::string name = shortMethod(f.method);
            char label[1024];
            if (f.line > 0) std::snprintf(label, sizeof label, "#%d  %s : %d", i, name.c_str(), f.line);
            else std::snprintf(label, sizeof label, "#%d  %s", i, name.c_str());
            ImGui::PushID(i);
            if (ImGui::Selectable(label, i == s.selectedFrame)) d.selectFrame(i);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s  bytecode @%llx", f.method.c_str(),
                                  f.line > 0 ? ("line " + std::to_string(f.line)).c_str() : "no line info",
                                  (unsigned long long)f.location.index);
            if (ImGui::BeginPopupContextItem("##fr")) {
                if (ImGui::MenuItem("Open decompiled source")) {
                    const std::string cls = javaClassOf(f.method);
                    bool opened = false;
                    for (Root* r : workspace_.decompiledRoots())
                        if (workspace_.openSymbol(r->title, cls, {}, nullptr)) {
                            opened = true;
                            if (f.line > 0)
                                if (Document* doc = workspace_.activeDocument()) doc->goTo(f.line - 1);
                            break;
                        }
                    if (!opened) workspace_.log("No decompiled source for " + cls, "debug");
                }
                if (ImGui::MenuItem("Break at this method")) d.addBreakpoint(javaClassOf(f.method), methodNameOf(f.method));
                if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(f.method.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        if (s.frames.empty()) ImGui::TextDisabled(suspended ? "(select a thread)" : attached ? "(running)" : "(not attached)");
        ImGui::EndChild();
        if (threeColumns) {
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("##dbgLocals", ImVec2(0, -bottomH), ImGuiChildFlags_Borders);
        } else {
            ImGui::Separator();
        }
        ImGui::TextColored(kAccent, "Locals");
        if (!s.exception.empty()) {
            const std::string type = s.exceptionType.substr(s.exceptionType.find_last_of('.') + 1);
            ui::wrappedColored(kWarn, type + " in " + shortMethod(s.exceptionAt) +
                                          (s.exceptionCatch.empty() ? ", uncaught" : ", caught in " + shortMethod(s.exceptionCatch)));
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", s.exception.c_str());
        }
        if (ImGui::BeginTable("##locals", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 1.2f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 2.f);
            ImGui::TableHeadersRow();
            // Objects and arrays expand into their fields / elements, loaded on first open. The path
            // guards against reference cycles (a.parent.child == a).
            std::vector<uint64_t> path;
            std::function<void(const DebugSession::Local&, int)> row = [&](const DebugSession::Local& l, int id) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(id);
                const bool cycle = l.objectId && std::find(path.begin(), path.end(), l.objectId) != path.end();
                const bool expandable = l.objectId && !cycle && path.size() < 12;
                ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanFullWidth;
                if (!expandable) flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
                const bool open = ImGui::TreeNodeEx("##n", flags, "%s", l.name.c_str());
                if (ImGui::BeginPopupContextItem("##lctx")) {
                    if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(l.value.c_str());
                    if (l.objectId && ImGui::MenuItem("Copy object id")) ImGui::SetClipboardText(std::to_string(l.objectId).c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", l.type.c_str());
                ImGui::TableNextColumn();
                if (cycle) ImGui::TextDisabled("%s  (cycle)", l.value.c_str());
                else ImGui::TextWrapped("%s", l.value.c_str());
                if (expandable && open) {
                    auto it = s.children.find(l.objectId);
                    if (it == s.children.end()) {
                        d.expand(l.objectId);
                    } else if (it->second.empty()) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextDisabled("loading...");
                    } else {
                        path.push_back(l.objectId);
                        int childId = 0;
                        for (const auto& c : it->second) row(c, childId++);
                        path.pop_back();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            };
            int localId = 0;
            for (const auto& l : s.locals) row(l, localId++);
            ImGui::EndTable();
        }
        ImGui::EndChild();

    }

    // Breakpoints + events.
    ImGui::BeginChild("##bps", ImVec2(wide ? ImGui::GetContentRegionAvail().x * 0.55f : 0.f, wide ? 0.f : bottomH),
                      ImGuiChildFlags_Borders);
    ImGui::TextColored(kAccent, "Breakpoints");
    ImGui::SameLine();
    if (ImGui::SmallButton("Add...")) ImGui::OpenPopup("##addbp");
    if (ImGui::BeginPopup("##addbp")) {
        ImGui::SetNextItemWidth(ui::em(20.f));
        ImGui::InputTextWithHint("##bpc", "Class, e.g. com.example.Foo", bpClass_, sizeof bpClass_);
        ImGui::SetNextItemWidth(ui::em(14.f));
        ImGui::InputTextWithHint("##bpm", "Method", bpMethod_, sizeof bpMethod_);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ui::em(5.5f));
        ImGui::InputTextWithHint("##bpl", "Line", bpLine_, sizeof bpLine_, ImGuiInputTextFlags_CharsDecimal);
        ImGui::BeginDisabled(!bpClass_[0] || !bpMethod_[0]);
        if (ImGui::Button("Add breakpoint")) {
            const int line = std::atoi(bpLine_);
            d.addBreakpoint(bpClass_, bpMethod_, line > 0 ? line : -1);
            bpMethod_[0] = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
        ImGui::Separator();
        if (ImGui::Button("Break on exception")) {
            d.addExceptionBreakpoint(bpClass_, excCaught_, excUncaught_);
            ImGui::CloseCurrentPopup();
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Of the class above and its subclasses, or any exception when the class is empty");
        ImGui::SameLine();
        ImGui::Checkbox("caught", &excCaught_);
        ImGui::SameLine();
        ImGui::Checkbox("uncaught", &excUncaught_);
        if (!excCaught_ && !excUncaught_) excUncaught_ = true;
        ImGui::EndPopup();
    }
    for (const auto& b : s.breakpoints) {
        ImGui::PushID(b.id);
        if (ImGui::SmallButton("x")) d.removeBreakpoint(b.id);
        ImGui::SameLine();
        const std::string where =
            b.exception ? "exception " + (b.classDescriptor.empty() ? std::string("(any)") : javaClassOf(b.classDescriptor + "->"))
                        : javaClassOf(b.classDescriptor + "->") + "." + b.method +
                              (b.line >= 0 ? ":" + std::to_string(b.line) : std::string());
        ui::wrappedColored(b.resolved ? kGood : kDim, where + "   hits " + std::to_string(b.hits) + " - " + b.status);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (wide) ImGui::SameLine();
    ImGui::BeginChild("##events", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextColored(kAccent, "Events");
    for (const auto& e : s.events) ImGui::TextWrapped("%s", e.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.f) ImGui::SetScrollHereY(1.f);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// Logcat
// ---------------------------------------------------------------------------

void LogcatPanel::drawContents() {
    const std::string serial = devices_.selected();
    const bool running = devices_.logcatRunning();
    // "Show in Logcat" from the Devices panel narrows the view to that pid.
    if (const int requested = devices_.takeLogFilterRequest(); requested > 0)
        std::snprintf(query_, sizeof query_, "pid:%d", requested);
    if (running) {
        if (ImGui::Button("Stop")) devices_.stopLogcat();
    } else {
        if (serial.empty()) ImGui::BeginDisabled();
        if (ImGui::Button("Start")) {
            error_.clear();
            if (!devices_.startLogcat(serial, error_)) workspace_.log("Logcat: " + error_, "debug");
        }
        if (serial.empty()) ImGui::EndDisabled();
    }
    if (ui::flowButton("Clear")) {
        devices_.clearLog();
        view_.clear();
        viewHead_ = 0;
        selection_.reset();
    }
    if (ui::flowButton(paused_ ? "Continue" : "Pause")) paused_ = !paused_;
    const char* levels[] = {"V", "D", "I", "W", "E", "F"};
    ui::sameLineIfFits(ui::em(3.5f));
    ImGui::SetNextItemWidth(ui::em(3.5f));
    ImGui::Combo("##lvl", &level_, levels, 6);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Lowest level shown");
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##q", "Filter text, tag:Name, pid:1234", query_, sizeof query_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Words match the message; tag: and pid: narrow by source");
    // One box, three filters.
    pid_ = 0;
    tag_[0] = 0;
    {
        std::string words;
        std::istringstream tokens(query_);
        for (std::string token; tokens >> token;) {
            if (token.rfind("pid:", 0) == 0) pid_ = std::atoi(token.c_str() + 4);
            else if (token.rfind("tag:", 0) == 0) std::snprintf(tag_, sizeof tag_, "%s", token.c_str() + 4);
            else words += (words.empty() ? "" : " ") + token;
        }
        std::snprintf(text_, sizeof text_, "%s", words.c_str());
    }
    if (serial.empty()) {
        ImGui::TextDisabled("No device selected.");
    } else if (!error_.empty()) {
        ui::wrappedColored(kWarn, error_);
    }

    // Rebuild the filtered view when the filter changed; otherwise append
    // only what arrived since the last frame (no per-frame full copy).
    const std::string key = std::to_string(level_) + "|" + std::to_string(pid_) + "|" + tag_ + "|" + text_;
    DeviceService::LogFilter f;
    f.minLevel = levels[level_][0];
    f.pid = pid_;
    f.tag = tag_;
    f.text = text_;
    constexpr size_t kViewCap = 20000;
    if (key != viewKey_) {
        viewKey_ = key;
        view_ = devices_.logEntries(0, f, kViewCap);
        viewHead_ = devices_.logHead();
        selection_.reset();
    } else if (!paused_ && devices_.logHead() != viewHead_) {
        auto fresh = devices_.logEntries(viewHead_, f, kViewCap);
        viewHead_ = devices_.logHead();
        view_.insert(view_.end(), std::make_move_iterator(fresh.begin()), std::make_move_iterator(fresh.end()));
        if (view_.size() > kViewCap) {
            view_.erase(view_.begin(), view_.begin() + (ptrdiff_t)(view_.size() - kViewCap));
            selection_.reset();  // rows shifted
        }
    }

    ImGui::BeginChild("##log", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushFont(Theme::monoFont());
    const float rowH = ImGui::GetTextLineHeight();
    const auto rowText = [&](int i) {
        const auto& e = view_[(size_t)i];
        char head[64];
        std::snprintf(head, sizeof head, "%s %5d %5d %c ", e.time.c_str(), e.pid, e.tid, e.level);
        return std::string(head) + e.tag + ": " + e.message;
    };
    ImGuiListClipper clipper;
    clipper.Begin((int)view_.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto& e = view_[(size_t)i];
            const ImVec2 rowPos = ImGui::GetCursorPos();
            ImGui::PushID(i);
            ImGui::Selectable("##row", selection_.contains(i), ImGuiSelectableFlags_AllowOverlap, ImVec2(0, rowH));
            selection_.handleRow(i);
            ImGui::PopID();
            ImGui::SetCursorPos(rowPos);
            ImGui::TextColored(kDim, "%s %5d %5d", e.time.c_str(), e.pid, e.tid);
            ImGui::SameLine();
            ImGui::TextColored(levelColor(e.level), "%c %s: %s", e.level, e.tag.c_str(), e.message.c_str());
        }
    }
    const std::string copied = selection_.handleCommands((int)view_.size(), rowText, "##logcatCtx");
    if (!copied.empty()) ImGui::SetClipboardText(copied.c_str());
    if (autoScroll_ && !paused_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - ui::em(2.f)) ImGui::SetScrollHereY(1.f);
    ImGui::PopFont();
    ImGui::EndChild();
}
