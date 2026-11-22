#include "ui/InsightsPanel.hpp"
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include "analysis/Report.hpp"
#include "core/Paths.hpp"
#include "ui/UiUtil.hpp"

namespace {

ImVec4 severityColor(insights::Severity s) {
    switch (s) {
        case insights::Severity::High: return theme::vec(Col::Error);
        case insights::Severity::Medium: return theme::vec(Col::Warning);
        case insights::Severity::Low: return theme::vec(Col::Info);
        default: return theme::vec(Col::TextMuted);
    }
}

ImVec4 auditColor(manifestaudit::Severity s) {
    using S = manifestaudit::Severity;
    return s == S::Critical || s == S::High ? theme::vec(Col::Error)
           : s == S::Medium                 ? theme::vec(Col::Warning)
           : s == S::Low                    ? theme::vec(Col::Info)
                                            : theme::vec(Col::TextMuted);
}

void collectFiles(const TreeNode& n, std::vector<std::string>& out) {
    if (!n.isFolder() && !n.path().empty()) out.push_back(n.path());
    for (const auto& c : n.children()) collectFiles(*c, out);
}

}  // namespace

void InsightsPanel::runScan() {
    analysis_ = workspace_.analysis().get(group_);
    if (!analysis_) {
        status_ = "Bytecode analysis of this APK is not ready yet.";
        return;
    }
    const ApkAnalysis& a = *analysis_;
    insights::Inputs in;
    for (const auto& c : a.classes()) in.classes.emplace_back(a.classDescriptor(c));
    std::set<std::string> refs;
    std::set<std::string> strs;
    for (const auto& dex : a.dexes()) {
        for (uint32_t i = 0; i < dex->methodCount(); ++i) refs.insert(dex->methodSignature(i));
        for (uint32_t i = 0; i < dex->stringCount(); ++i) strs.insert(dex->string(i));
    }
    in.methodRefs.assign(refs.begin(), refs.end());
    in.strings.assign(strs.begin(), strs.end());
    Root* apk = workspace_.rootByGroup(group_, Root::Kind::Apk);
    if (apk && apk->tree) collectFiles(*apk->tree, in.files);
    result_ = insights::scan(in);
    strings_ = std::move(in.strings);
    endpoints_ = insights::endpoints(strings_);
    decoded_ = insights::decodeStrings(strings_);
    callers_.clear();
    constArgs_.clear();

    haveAudit_ = false;
    auditError_.clear();
    permUse_.clear();
    permMissing_.clear();
    if (apk)
        if (const auto* archive = dynamic_cast<const ApkArchive*>(apk->source.get())) {
            const auto res = workspace_.resources(group_);
            haveAudit_ = manifestaudit::audit(*archive, res.get(), audit_, auditError_);
        }
    netsec_ = netsec::Config{};
    netsecFile_.clear();
    if (haveAudit_ && apk)
        if (const auto* archive = dynamic_cast<const ApkArchive*>(apk->source.get())) {
            std::string ref = audit_.networkSecurityConfig;  // "@xml/name" once resources resolve it
            const size_t slash = ref.find_last_of("/");
            std::string base = slash == std::string::npos ? ref : ref.substr(slash + 1);
            if (base.size() > 4 && base.compare(base.size() - 4, 4, ".xml") == 0) base.resize(base.size() - 4);
            std::string entry;
            if (!base.empty() && base[0] != '0') {
                for (const auto& e : archive->entries())
                    if (e.path == "res/xml/" + base + ".xml") entry = e.path;
                if (entry.empty())
                    for (const auto& e : archive->entries())  // obfuscated resource paths keep the name rarely; try any xml with that name
                        if (e.path.size() > base.size() + 5 && e.path.rfind("res/", 0) == 0 &&
                            e.path.compare(e.path.size() - base.size() - 4, base.size() + 4, base + ".xml") == 0)
                            entry = e.path;
            }
            std::vector<uint8_t> bytes;
            if (!entry.empty() && archive->readEntry(entry, bytes) && AxmlDecoder::looksLikeAxml(bytes)) {
                netsec::Collector col;
                std::string err;
                if (AxmlDecoder::decodeEvents(bytes, col, err, nullptr)) {
                    netsec_ = col.result;
                    netsecFile_ = entry;
                }
            }
        }
    if (haveAudit_) {
        permUse_ = insights::permissionUsage(audit_.permissions, in.methodRefs);
        permMissing_ = insights::missingPermissions(audit_.permissions, in.methodRefs);
    }
    scanned_ = true;
    selectOverview_ = true;
    char buf[200];
    std::snprintf(buf, sizeof buf, "Scanned %zu classes, %zu referenced methods, %zu strings, %zu files.", in.classes.size(),
                  in.methodRefs.size(), strings_.size(), in.files.size());
    status_ = buf;
}

void InsightsPanel::openRef(const ApkAnalysis::CodeRef& ref) {
    if (!analysis_) return;
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(analysis_->methodSignature(ref), cls, name, proto)) return;
    const auto defs = analysis_->findMethodDefs(cls, name, proto);
    if (defs.empty()) return;
    workspace_.openMethodListing(group_, *analysis_, defs.front(), ref.pc);
    if (showPanel_) showPanel_("Editor");
}

std::string InsightsPanel::constArgs(const ApkAnalysis::XrefHit& hit, const std::string& callee) {
    const std::string key = callee + "|" + std::to_string(hit.from.dex) + ":" + std::to_string(hit.from.method) + ":" +
                            std::to_string(hit.from.pc);
    if (auto it = constArgs_.find(key); it != constArgs_.end()) return it->second;
    std::string out;
    std::string cls, name, proto;
    if (ApkAnalysis::splitMethodRef(analysis_->methodSignature(hit.from), cls, name, proto))
        for (const auto& def : analysis_->findMethodDefs(cls, name, proto)) {
            if (def.dex != hit.from.dex) continue;
            for (const auto& call : analysis_->constantArguments(def)) {
                if (call.pc != hit.from.pc || call.callee != callee) continue;
                for (const auto& [pos, value] : call.args) out += (out.empty() ? "" : ", ") + ("arg" + std::to_string(pos) + " = " + value);
            }
            break;
        }
    return constArgs_[key] = out;
}

void InsightsPanel::drawXrefs(const std::vector<ApkAnalysis::XrefHit>& hits, const std::string& callee) {
    if (hits.empty()) {
        ImGui::TextDisabled("No code uses it (only referenced).");
        return;
    }
    for (size_t i = 0; i < hits.size(); ++i) {
        ImGui::PushID(static_cast<int>(i));
        // Known constant arguments first: the caller signatures are long.
        if (!callee.empty())
            if (const std::string args = constArgs(hits[i], callee); !args.empty()) {
                ImGui::TextColored(theme::vec(Col::Info), "[%s]", args.c_str());
                ImGui::SameLine();
            }
        const std::string label = analysis_->methodSignature(hits[i].from);
        if (ImGui::Selectable(label.c_str())) openRef(hits[i].from);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Open the smali listing at this call");
        ImGui::PopID();
    }
}

void InsightsPanel::drawOverview() {
    const auto& o = result_.obfuscation;
    ImGui::Text("Obfuscation: %s", o.verdict);
    ImGui::SameLine();
    ImGui::TextDisabled("(%d of %d app classes have 1-2 character names)", o.shortNames, o.appClasses);
    int trackers = 0;
    for (const auto& s : result_.sdks) trackers += s.tracker ? 1 : 0;
    int high = 0;
    for (const auto& s : result_.secrets) high += s.severity == insights::Severity::High ? 1 : 0;
    ImGui::Text("%zu SDK(s), %d tracker(s), %zu secret(s) (%d high), %zu code-risk rule(s)", result_.sdks.size(), trackers,
                result_.secrets.size(), high, result_.rules.size());
    ImGui::Separator();
    if (result_.detections.empty()) {
        ImGui::TextDisabled("No framework or packer recognised (plain Java / Kotlin app).");
        return;
    }
    if (ImGui::BeginTable("##det", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Detected");
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, ui::em(7.f));
        ImGui::TableSetupColumn("Evidence");
        ImGui::TableHeadersRow();
        for (const auto& d : result_.detections) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (d.kind == "Packer") ImGui::TextColored(theme::vec(Col::Warning), "%s", d.name.c_str());
            else ImGui::TextUnformatted(d.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", d.kind.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.evidence.c_str());
        }
        ImGui::EndTable();
    }
    for (const auto& d : result_.detections)
        if (d.kind == "Packer") {
            ImGui::TextWrapped("A packer or protector was detected: the DEX code visible here may be a loader stub, and the real "
                               "code may only exist at run time.");
            break;
        }
}

void InsightsPanel::drawSecrets() {
    ImGui::Checkbox("Show values", &showValues_);
    if (result_.secrets.empty()) {
        ImGui::TextDisabled("No hard-coded secrets matched.");
        return;
    }
    for (size_t i = 0; i < result_.secrets.size(); ++i) {
        const auto& s = result_.secrets[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::PushStyleColor(ImGuiCol_Text, severityColor(s.severity));
        const bool open = ImGui::TreeNodeEx("##s", ImGuiTreeNodeFlags_SpanAvailWidth, "[%s] %s", insights::severityName(s.severity),
                                            s.kind.c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        const std::string shown = showValues_ ? s.value : insights::mask(s.value);
        ImGui::PushFont(Theme::monoFont());
        ImGui::TextUnformatted(shown.c_str());
        ImGui::PopFont();
        if (ImGui::BeginPopupContextItem("##ctx")) {
            if (ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(s.value.c_str());
            ImGui::EndPopup();
        }
        if (open) {
            const std::string key = "s:" + s.value;
            auto it = callers_.find(key);
            if (it == callers_.end()) {
                const std::string& full = s.stringIndex < strings_.size() ? strings_[s.stringIndex] : s.value;
                it = callers_.emplace(key, analysis_->stringUses(full, false, 50)).first;
            }
            drawXrefs(it->second);
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

void InsightsPanel::drawSdks() {
    if (result_.sdks.empty()) {
        ImGui::TextDisabled("No known SDK packages found.");
        return;
    }
    if (ImGui::BeginTable("##sdk", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("SDK");
        ImGui::TableSetupColumn("Category");
        ImGui::TableSetupColumn("Package");
        ImGui::TableSetupColumn("Classes", ImGuiTableColumnFlags_WidthFixed, ui::em(4.f));
        ImGui::TableHeadersRow();
        for (const auto& s : result_.sdks) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (s.tracker) ImGui::TextColored(theme::vec(Col::Warning), "%s", s.name.c_str());
            else ImGui::TextUnformatted(s.name.c_str());
            if (s.tracker && ImGui::IsItemHovered()) ImGui::SetTooltip("Tracker: collects usage, attribution or ad data");
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", s.category.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.prefix.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%d", s.classes);
        }
        ImGui::EndTable();
    }
}

void InsightsPanel::drawEndpoints() {
    if (endpoints_.empty()) {
        ImGui::TextDisabled("No URLs in the string constants.");
        return;
    }
    ImGui::TextDisabled("Hosts found in string constants. Cloud backends first; click a URL for the code that uses it.");
    for (size_t i = 0; i < endpoints_.size(); ++i) {
        const auto& h = endpoints_[i];
        ImGui::PushID(static_cast<int>(i));
        const bool cloud = !h.kind.empty();
        ImGui::PushStyleColor(ImGuiCol_Text, cloud ? theme::vec(Col::Info) : (h.https ? theme::vec(Col::Text) : theme::vec(Col::Warning)));
        const bool open = ImGui::TreeNodeEx("##h", ImGuiTreeNodeFlags_SpanAvailWidth, "%s  (%zu)", h.host.c_str(), h.urls.size());
        ImGui::PopStyleColor();
        if (cloud) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", h.kind.c_str());
        }
        if (!h.https) {
            ImGui::SameLine();
            ImGui::TextColored(theme::vec(Col::Warning), "cleartext only");
        }
        if (ImGui::BeginPopupContextItem("##hctx")) {
            if (ImGui::MenuItem("Copy host")) ImGui::SetClipboardText(h.host.c_str());
            ImGui::EndPopup();
        }
        if (open) {
            for (size_t k = 0; k < h.urls.size(); ++k) {
                ImGui::PushID(static_cast<int>(k));
                if (ImGui::TreeNodeEx("##u", ImGuiTreeNodeFlags_SpanAvailWidth, "%s", h.urls[k].c_str())) {
                    const std::string key = "u:" + h.urls[k];
                    auto it = callers_.find(key);
                    if (it == callers_.end()) it = callers_.emplace(key, analysis_->stringUses(h.urls[k], true, 50)).first;
                    drawXrefs(it->second);
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

void InsightsPanel::drawDecoded() {
    if (decoded_.empty()) {
        ImGui::TextDisabled("No base64 / hex / URL-encoded text constants.");
        return;
    }
    ImGui::TextDisabled("Constants that decode to readable text. Click one for the code that uses it.");
    for (size_t i = 0; i < decoded_.size(); ++i) {
        const auto& d = decoded_[i];
        ImGui::PushID(static_cast<int>(i));
        std::string shown = d.decoded.substr(0, 120);
        for (char& c : shown)
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        const bool open = ImGui::TreeNodeEx("##d", ImGuiTreeNodeFlags_SpanAvailWidth, "[%s] %s", d.method.c_str(), shown.c_str());
        if (ImGui::BeginPopupContextItem("##dctx")) {
            if (ImGui::MenuItem("Copy decoded text")) ImGui::SetClipboardText(d.decoded.c_str());
            if (ImGui::MenuItem("Copy original")) ImGui::SetClipboardText(d.original.c_str());
            ImGui::EndPopup();
        }
        if (open) {
            ImGui::TextDisabled("%s", d.original.substr(0, 200).c_str());
            const std::string key = "d:" + d.original;
            auto it = callers_.find(key);
            if (it == callers_.end()) it = callers_.emplace(key, analysis_->stringUses(d.original, false, 50)).first;
            drawXrefs(it->second);
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

void InsightsPanel::drawRules() {
    if (result_.rules.empty()) {
        ImGui::TextDisabled("No rule matched.");
        return;
    }
    for (size_t i = 0; i < result_.rules.size(); ++i) {
        const auto& h = result_.rules[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::PushStyleColor(ImGuiCol_Text, severityColor(h.severity));
        const bool open = ImGui::TreeNodeEx("##r", ImGuiTreeNodeFlags_SpanAvailWidth, "[%s] %s  (%zu)",
                                            insights::severityName(h.severity), h.title.c_str(), h.matched.size());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled("%s", h.masvs.c_str());
        if (open) {
            ImGui::TextWrapped("%s", h.detail.c_str());
            for (size_t k = 0; k < h.matched.size(); ++k) {
                const std::string& m = h.matched[k];
                ImGui::PushID(static_cast<int>(k));
                const bool isString = !m.empty() && (m[0] == '"' || m.rfind("http", 0) == 0 || m[0] == '/');
                if (ImGui::TreeNodeEx("##m", ImGuiTreeNodeFlags_SpanAvailWidth, "%s", m.c_str())) {
                    auto it = callers_.find(m);
                    if (it == callers_.end()) {
                        std::vector<ApkAnalysis::XrefHit> hits;
                        if (isString) {
                            std::string text = m;
                            if (text.size() >= 2 && text.front() == '"') text = text.substr(1, text.size() - 2);
                            hits = analysis_->stringUses(text, false, 50);
                        } else {
                            std::string cls, name, proto;
                            if (ApkAnalysis::splitMethodRef(m, cls, name, proto)) hits = analysis_->callersOf(cls, name, proto, 50);
                        }
                        it = callers_.emplace(m, std::move(hits)).first;
                    }
                    drawXrefs(it->second, isString ? std::string() : m);
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

void InsightsPanel::drawManifest() {
    if (!haveAudit_) {
        ImGui::TextDisabled("Manifest not audited%s%s", auditError_.empty() ? "" : ": ", auditError_.c_str());
        return;
    }
    const auto& a = audit_;
    ImGui::Text("%s  %s (%d)  minSdk %d  targetSdk %d", a.package.c_str(), a.versionName.c_str(), a.versionCode, a.minSdk, a.targetSdk);
    ImGui::Text("debuggable %s, allowBackup %s, cleartext %s, testOnly %s", a.debuggable ? "yes" : "no", a.allowBackup ? "yes" : "no",
                a.usesCleartext ? "yes" : "no", a.testOnly ? "yes" : "no");
    if (ui::smallButton("Copy as Markdown")) ImGui::SetClipboardText(manifestaudit::toMarkdown(a).c_str());
    if (ImGui::CollapsingHeader("Findings", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (size_t i = 0; i < a.findings.size(); ++i) {
            const auto& f = a.findings[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::PushStyleColor(ImGuiCol_Text, auditColor(f.severity));
            const bool open = ImGui::TreeNodeEx("##f", ImGuiTreeNodeFlags_SpanAvailWidth, "[%s] %s",
                                                manifestaudit::severityName(f.severity), f.title.c_str());
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextDisabled("%s", f.masvsId.c_str());
            if (open) {
                ImGui::TextWrapped("%s", f.detail.c_str());
                if (!f.location.empty()) ImGui::TextDisabled("%s", f.location.c_str());
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
    }
    int exported = 0;
    for (const auto& c : a.components) exported += c.exported ? 1 : 0;
    char header[64];
    std::snprintf(header, sizeof header, "Exported components (%d)###exp", exported);
    if (ImGui::CollapsingHeader(header)) {
        for (const auto& c : a.components) {
            if (!c.exported) continue;
            ImGui::BulletText("%s %s%s%s", manifestaudit::Component::kindName(c.kind), c.name.c_str(),
                              c.permission.empty() ? "" : "  permission: ", c.permission.c_str());
        }
    }
    {
        // Network security config: trust anchors, cleartext, pins.
        const auto lines = netsec::notes(netsec_, a.targetSdk, a.usesCleartext);
        if (ImGui::CollapsingHeader("Network security config###netsec")) {
            if (!netsecFile_.empty()) ImGui::TextDisabled("%s", netsecFile_.c_str());
            else if (!a.networkSecurityConfig.empty())
                ImGui::TextDisabled("referenced as %s (file not found in the APK)", a.networkSecurityConfig.c_str());
            for (const auto& l : lines) ImGui::BulletText("%s", l.c_str());
            for (const auto& sc : netsec_.domainConfigs) {
                for (const auto& d : sc.domains) {
                    ImGui::TextDisabled("%s%s", d.name.c_str(), d.includeSubdomains ? " (+subdomains)" : "");
                    for (const auto& p : sc.pins) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("  %s:%s", p.digest.c_str(), p.value.c_str());
                        break;
                    }
                }
            }
        }
    }
    if (!a.deepLinks.empty()) {
        char dl[48];
        std::snprintf(dl, sizeof dl, "Deep links (%zu)###deeplinks", a.deepLinks.size());
        if (ImGui::CollapsingHeader(dl)) {
            ImGui::TextDisabled("Browsable VIEW entry points. Double-click a row to copy an adb am start command.");
            const auto qualify = [&](const std::string& comp) {
                if (comp.empty()) return comp;
                if (comp[0] == '.') return a.package + comp;
                if (comp.find('.') == std::string::npos) return a.package + "." + comp;
                return comp;
            };
            for (size_t i = 0; i < a.deepLinks.size(); ++i) {
                const auto& d = a.deepLinks[i];
                ImGui::PushID(static_cast<int>(i));
                const std::string cmd = "adb shell am start -a android.intent.action.VIEW -d \"" + d.uri + "\" " + a.package + "/" +
                                        qualify(d.component);
                ImGui::PushFont(Theme::monoFont());
                if (ImGui::Selectable(d.uri.c_str())) ImGui::SetClipboardText(cmd.c_str());
                ImGui::PopFont();
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s%s\n\nClick to copy:\n%s", d.component.c_str(),
                                                              d.autoVerify ? "  (autoVerify / App Link)" : "", cmd.c_str());
                ImGui::PopID();
            }
        }
    }

    char perms[64];
    std::snprintf(perms, sizeof perms, "Dangerous permissions (%zu)###perm", a.dangerousPermissions.size());
    if (ImGui::CollapsingHeader(perms))
        for (const auto& p : a.dangerousPermissions) ImGui::BulletText("%s", p.c_str());

    const auto shortPerm = [](const std::string& p) {
        const size_t dot = p.rfind('.');
        return dot == std::string::npos ? p : p.substr(dot + 1);
    };
    char usage[64];
    std::snprintf(usage, sizeof usage, "Permission -> API usage (%zu)###permuse", permUse_.size());
    if (!permUse_.empty() && ImGui::CollapsingHeader(usage)) {
        ImGui::TextDisabled("Which guarded APIs the app actually calls for each requested permission.");
        for (const auto& u : permUse_) {
            ImGui::PushID(u.permission.c_str());
            const bool unused = u.apis.empty();
            ImGui::PushStyleColor(ImGuiCol_Text, unused ? theme::vec(Col::TextMuted) : theme::vec(Col::Text));
            const bool open = ImGui::TreeNodeEx("##p", ImGuiTreeNodeFlags_SpanAvailWidth, "%s  (%zu)", shortPerm(u.permission).c_str(),
                                                u.apis.size());
            ImGui::PopStyleColor();
            if (unused) {
                ImGui::SameLine();
                ImGui::TextDisabled("no matching call found");
            }
            if (open) {
                for (const auto& api : u.apis) ImGui::BulletText("%s", api.c_str());
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
    }
    if (!permMissing_.empty()) {
        char miss[72];
        std::snprintf(miss, sizeof miss, "Guarded APIs used WITHOUT the permission (%zu)###permmiss", permMissing_.size());
        if (ImGui::CollapsingHeader(miss)) {
            ImGui::TextColored(theme::vec(Col::Warning), "These calls need a permission the manifest does not request (library code often guards them at run time, so check the callers).");
            for (const auto& u : permMissing_) {
                ImGui::PushID(u.permission.c_str());
                if (ImGui::TreeNodeEx("##m", ImGuiTreeNodeFlags_SpanAvailWidth, "%s  (%zu)", shortPerm(u.permission).c_str(),
                                      u.apis.size())) {
                    for (const auto& api : u.apis) ImGui::BulletText("%s", api.c_str());
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
        }
    }
}

void InsightsPanel::drawRetrace() {
    ImGui::TextWrapped("Paste an obfuscated stack trace and load the build's ProGuard / R8 mapping.txt.");
    if (ui::smallButton("Load mapping.txt...")) mappingBrowser_.open(FileBrowser::Mode::OpenFile);
    ImGui::SameLine();
    if (mappingFile_.empty()) ImGui::TextDisabled("no mapping loaded");
    else {
        ImGui::TextDisabled("%s: %zu classes%s - applied to the Analysis class tree", mappingFile_.c_str(), mapping_.byObfuscated.size(),
                            mapping_.errors ? " (some lines skipped)" : "");
        ImGui::SameLine();
        if (ui::smallButton("Clear")) {
            mappingFile_.clear();
            mapping_ = mapping::Mapping{};
            workspace_.setMapping(nullptr);
        }
    }
    std::string picked;
    if (mappingBrowser_.render(), mappingBrowser_.takeAccepted(picked)) {
        std::ifstream in(pathutil::fromUtf8(picked), std::ios::binary);
        std::ostringstream s;
        s << in.rdbuf();
        mappingText_ = s.str();
        mapping_ = mapping::parse(mappingText_);
        workspace_.setMapping(std::make_shared<const mapping::Mapping>(mapping_));
        mappingFile_ = picked.substr(picked.find_last_of("/\\") + 1);
        retraced_ = mapping::retrace(mapping_, traceBuf_.data());
    }
    ImGui::PushFont(Theme::monoFont());
    const float h = std::max(ui::em(6.f), (ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing()) * 0.5f);
    if (ImGui::InputTextMultiline("##trace", traceBuf_.data(), traceBuf_.size(), ImVec2(-FLT_MIN, h)))
        retraced_ = mapping::retrace(mapping_, traceBuf_.data());
    ImGui::InputTextMultiline("##out", retraced_.data(), retraced_.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopFont();
}

void InsightsPanel::saveExport(const std::string& file) {
    std::string text;
    const std::string name = group_.empty() ? "app.apk" : group_;
    if (exportKind_ == ExportKind::Json) text = insights::toJson(result_, name);
    else if (exportKind_ == ExportKind::Sarif) text = insights::toSarif(result_, name);
    else {
        report::Options o;
        o.subtitle = name;
        text = report::toMarkdown(o, haveAudit_ ? &audit_ : nullptr);
        text += "\n## Insights\n\n```json\n" + insights::toJson(result_, name) + "```\n";
    }
    std::ofstream out(pathutil::fromUtf8(file), std::ios::binary);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    status_ = out ? "Saved " + file : "Could not write " + file;
    workspace_.log(status_);
}

void InsightsPanel::drawContents() {
    const auto apks = workspace_.apkRoots();
    if (apks.empty()) {
        ImGui::TextDisabled("Open an APK to scan it.");
        return;
    }
    bool found = false;
    for (Root* r : apks) found |= r->title == group_;
    if (!found) group_ = apks.front()->title, scanned_ = false;
    if (apks.size() > 1) {
        ImGui::SetNextItemWidth(ui::em(14.f));
        if (ImGui::BeginCombo("##apk", group_.c_str())) {
            for (Root* r : apks)
                if (ImGui::Selectable(r->title.c_str(), r->title == group_)) group_ = r->title, scanned_ = false;
            ImGui::EndCombo();
        }
        ImGui::SameLine();
    }
    const bool ready = workspace_.analysis().get(group_) != nullptr;
    ImGui::BeginDisabled(!ready);
    if (ui::smallButton(scanned_ ? "Rescan" : "Scan")) runScan();
    ImGui::EndDisabled();
    if (!ready) {
        ImGui::SameLine();
        ImGui::TextDisabled("waiting for the bytecode analysis");
    }
    if (scanned_) {
        ImGui::SameLine();
        const auto exportAs = [&](const char* label, ExportKind k, const char* name) {
            ImGui::SameLine();
            if (ui::smallButton(label)) {
                exportKind_ = k;
                exportBrowser_.open(FileBrowser::Mode::SaveFile);
                exportBrowser_.setDefaultName(name);
            }
        };
        ImGui::TextDisabled("Export:");
        exportAs("JSON", ExportKind::Json, "insights.json");
        exportAs("SARIF", ExportKind::Sarif, "insights.sarif");
        exportAs("Markdown", ExportKind::Markdown, "report.md");
    }
    std::string picked;
    if (exportBrowser_.render(), exportBrowser_.takeAccepted(picked)) saveExport(picked);
    if (!status_.empty()) ImGui::TextDisabled("%s", status_.c_str());

    if (!ImGui::BeginTabBar("##insights")) return;
    if (scanned_) {
        const ImGuiTabItemFlags ovFlags = selectOverview_ ? ImGuiTabItemFlags_SetSelected : 0;
        selectOverview_ = false;
        if (ImGui::BeginTabItem("Overview", nullptr, ovFlags)) {
            ImGui::BeginChild("##ov");
            drawOverview();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        char label[64];
        std::snprintf(label, sizeof label, "Secrets (%zu)###sec", result_.secrets.size());
        if (ImGui::BeginTabItem(label)) {
            ImGui::BeginChild("##sec");
            drawSecrets();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "SDKs (%zu)###sdk", result_.sdks.size());
        if (ImGui::BeginTabItem(label)) {
            ImGui::BeginChild("##sdk");
            drawSdks();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "Endpoints (%zu)###endpoints", endpoints_.size());
        if (ImGui::BeginTabItem(label)) {
            ImGui::BeginChild("##endpoints");
            drawEndpoints();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "Decoded (%zu)###decoded", decoded_.size());
        if (ImGui::BeginTabItem(label)) {
            ImGui::BeginChild("##decoded");
            drawDecoded();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        std::snprintf(label, sizeof label, "Code risks (%zu)###rules", result_.rules.size());
        if (ImGui::BeginTabItem(label)) {
            ImGui::BeginChild("##rules");
            drawRules();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Manifest")) {
            ImGui::BeginChild("##man");
            drawManifest();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
    }
    if (ImGui::BeginTabItem("Retrace")) {
        drawRetrace();
        ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
}
