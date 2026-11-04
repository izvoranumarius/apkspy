#include "ui/AnalysisPanel.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <set>
#include "analysis/Dalvik.hpp"
#include "app/Theme.hpp"
#include "core/ApkInfo.hpp"
#include "core/TextUtils.hpp"
#include "ui/UiUtil.hpp"

namespace {

const ImVec4 kDim(0.6f, 0.6f, 0.6f, 1.f);
const ImVec4 kAccent(0.55f, 0.75f, 0.95f, 1.f);
const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);

template <typename T>
bool ready(std::future<T>& f) {
    return f.valid() && f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::string shortName(std::string_view descriptor) {
    std::string j = DexFile::descriptorToJava(descriptor);
    const size_t dot = j.rfind('.');
    return dot == std::string::npos ? j : j.substr(dot + 1);
}

// Listing path inside the virtual root (".smali" -> smali highlighting).
std::string sanitizeForPath(std::string s) {
    for (char& c : s)
        if (c == '/' || c == '\\' || c == ':' || c == '<' || c == '>' || c == '|' || c == '?' || c == '*' || c == '"')
            c = '_';
    return s;
}

const char* kCategoryNames[] = {"All strings", "URLs", "IP addresses", "API paths", "Secrets / tokens", "E-mail"};
const ApkAnalysis::StringCategory kCategories[] = {
    ApkAnalysis::StringCategory::Any,  ApkAnalysis::StringCategory::Url,    ApkAnalysis::StringCategory::Ip,
    ApkAnalysis::StringCategory::Path, ApkAnalysis::StringCategory::Secret, ApkAnalysis::StringCategory::Email};

}  // namespace

void AnalysisPanel::resetCaches() {
    filtered_.clear();
    appliedFilter_ = "\x01";  // force a refilter
    selectedClass_ = -1;
    xrefs_.clear();
    xrefTitle_.clear();
    strings_.clear();
    stringsLoaded_ = false;
    graphValid_ = false;
    graph_.clear();
    graphBlocks_.clear();
}

void AnalysisPanel::drawContents() {
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.empty()) {
        ImGui::TextDisabled("Open an APK to analyse its bytecode.");
        return;
    }
    if (apkIdx_ >= (int)apks.size()) apkIdx_ = 0;
    Workspace::NativeViewRequest nativeReq;
    if (workspace_.takeNativeView(nativeReq)) {
        for (int i = 0; i < (int)apks.size(); ++i)
            if (apks[(size_t)i]->title == nativeReq.group && i != apkIdx_) {
                apkIdx_ = i;
                resetCaches();
            }
        requestTab_ = 4;
        symbolView_ = 5;
        if (!nativeReq.view.empty()) nativeMode_ = nativeReq.view == "graph" ? 1 : nativeReq.view == "calls" ? 2 : 0;
        pendingLib_ = nativeReq.entry;
        pendingTarget_ = nativeReq.target;
    }
    Workspace::MethodViewRequest methodReq;
    const bool methodRequested = workspace_.takeMethodView(methodReq);
    if (methodRequested)
        for (int i = 0; i < (int)apks.size(); ++i)
            if (apks[(size_t)i]->title == methodReq.group && i != apkIdx_) {
                apkIdx_ = i;
                resetCaches();
            }
    if (apks.size() > 1) {
        ImGui::SetNextItemWidth(std::min(ui::em(13.f), ImGui::GetContentRegionAvail().x));
        if (ImGui::BeginCombo("##apk", apks[(size_t)apkIdx_]->title.c_str())) {
            for (int i = 0; i < (int)apks.size(); ++i)
                if (ImGui::Selectable(apks[(size_t)i]->title.c_str(), i == apkIdx_)) {
                    apkIdx_ = i;
                    resetCaches();
                }
            ImGui::EndCombo();
        }
        ImGui::SameLine();
    }
    Root& apk = *apks[(size_t)apkIdx_];
    // Opening the workspace is the request: everything here needs the result.
    if (workspace_.analysis().status(apk.title).state == AnalysisService::State::None) workspace_.startAnalysis(apk.title);
    const AnalysisService::Status st = workspace_.analysis().status(apk.title);
    drawHeader(apk, st);

    std::shared_ptr<const ApkAnalysis> analysis = workspace_.analysis().get(apk.title);
    if (analysis.get() != cacheOwner_) {
        cacheOwner_ = analysis.get();
        resetCaches();
    }
    if (methodRequested && analysis) {
        std::string cls, name, proto;
        std::vector<ApkAnalysis::MethodDef> defs;
        if (ApkAnalysis::splitMethodRef(methodReq.method, cls, name, proto)) defs = analysis->findMethodDefs(cls, name, proto);
        if (defs.empty()) workspace_.log("No bytecode in this APK for " + methodReq.method, "analysis");
        else if (methodReq.view == "graph") showGraph(*analysis, defs.front());
        else if (methodReq.view == "calls") showCallGraph(*analysis, defs.front());
        else openMethod(*analysis, defs.front(), apk.title);
    }

    if (!ImGui::BeginTabBar("##analysisTabs", ImGuiTabBarFlags_FittingPolicyScroll)) return;
    const auto tabFlags = [&](int idx) {
        return requestTab_ == idx ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
    };
    // Results tabs exist while they have something to show.
    if (analysis && ImGui::BeginTabItem("Classes", nullptr, tabFlags(0))) {
        drawClasses(*analysis, apk);
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Native", nullptr, tabFlags(4))) {
        drawNative(apk);
        ImGui::EndTabItem();
    }
    if (analysis && ImGui::BeginTabItem("Strings", nullptr, tabFlags(2))) {
        drawStrings(*analysis, apk);
        ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Resources", nullptr, tabFlags(6))) {
        drawResources(apk);
        ImGui::EndTabItem();
    }
    if (analysis && !xrefTitle_.empty() && ImGui::BeginTabItem("Xrefs", nullptr, tabFlags(1))) {
        drawXrefs(*analysis, apk);
        ImGui::EndTabItem();
    }
    if (analysis && graphValid_ && ImGui::BeginTabItem("Graph", nullptr, tabFlags(3))) {
        drawGraph(*analysis, apk);
        ImGui::EndTabItem();
    }
    if (apks.size() > 1 && ImGui::BeginTabItem("Compare", nullptr, tabFlags(5))) {
        drawCompare(apk);
        ImGui::EndTabItem();
    }
    requestTab_ = -1;
    ImGui::EndTabBar();
}

void AnalysisPanel::drawHeader(Root& apk, const AnalysisService::Status& st) {
    switch (st.state) {
    case AnalysisService::State::None:
    case AnalysisService::State::Cancelled:
    case AnalysisService::State::Failed:
        if (ui::flowButton("Analyze again")) workspace_.startAnalysis(apk.title, true);
        if (st.state == AnalysisService::State::Failed)
            ui::wrappedColored(kWarn, "failed: " + st.error);
        else if (st.state == AnalysisService::State::Cancelled)
            ui::flowTextDisabled("cancelled");
        break;
    case AnalysisService::State::Running: {
        const float frac = st.total ? (float)st.done / (float)st.total : 0.f;
        char overlay[96];
        std::snprintf(overlay, sizeof overlay, "%s %zu / %zu", st.phase.c_str(), st.done, st.total);
        ImGui::ProgressBar(st.total ? frac : -1.f * (float)ImGui::GetTime(),
                           ImVec2(std::min(ui::em(16.f), ImGui::GetContentRegionAvail().x), 0), overlay);
        if (ui::flowButton("Cancel")) workspace_.analysis().cancel(apk.title);
        break;
    }
    case AnalysisService::State::Ready: {
        if (!st.error.empty()) ui::wrappedColored(kWarn, st.error);
        break;
    }
    }
}

// ---------------------------------------------------------------------------
// Classes / methods
// ---------------------------------------------------------------------------

void AnalysisPanel::drawClasses(const ApkAnalysis& a, Root& apk) {
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint("##classFilter", "Filter classes (package or name)...", classFilter_, sizeof classFilter_);
    if (appliedFilter_ != classFilter_) {
        appliedFilter_ = classFilter_;
        filtered_.clear();
        std::string needle = appliedFilter_;
        std::replace(needle.begin(), needle.end(), '.', '/');
        const auto& classes = a.classes();
        for (uint32_t i = 0; i < (uint32_t)classes.size(); ++i)
            if (needle.empty() || tex::ciFind(a.classDescriptor(classes[i]), needle) != std::string_view::npos)
                filtered_.push_back(i);
        if (selectedClass_ >= 0 && std::find(filtered_.begin(), filtered_.end(), (uint32_t)selectedClass_) == filtered_.end())
            selectedClass_ = -1;
    }
    const float methodsH = selectedClass_ >= 0 ? ImGui::GetContentRegionAvail().y * 0.45f : 0.f;
    ImGui::BeginChild("##classList", ImVec2(0, selectedClass_ >= 0 ? -methodsH : 0), ImGuiChildFlags_Borders);
    ImGuiListClipper clipper;
    clipper.Begin((int)filtered_.size());
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const uint32_t idx = filtered_[(size_t)row];
            const auto& c = a.classes()[idx];
            const std::string name = DexFile::descriptorToJava(a.classDescriptor(c));
            ImGui::PushID((int)idx);
            if (ImGui::Selectable(name.c_str(), selectedClass_ == (int)idx, ImGuiSelectableFlags_AllowDoubleClick)) {
                selectedClass_ = (int)idx;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) openClass(a, c, apk.title);
            }
            if (ImGui::BeginPopupContextItem("##cls")) {
                if (ImGui::MenuItem("Open smali")) openClass(a, c, apk.title);
                if (ImGui::MenuItem("Open decompiled source")) {
                    if (!workspace_.openSymbol(apk.title, name, {}, nullptr))
                        workspace_.log("No decompiled source for " + name, "analysis");
                }
                if (ImGui::MenuItem("Find type references")) {
                    xrefs_.clear();
                    xrefTitle_ = "References to " + name;
                    for (const auto& h : a.typeUses(name, 2000))
                        xrefs_.push_back({a.methodSignature(h.from), "type use", true, h.from, {}});
                    requestTab_ = 1;
                }
                if (ImGui::MenuItem("Subclasses / implementers")) {
                    xrefs_.clear();
                    xrefTitle_ = "Hierarchy of " + name;
                    for (const auto& s : a.superChain(name)) xrefs_.push_back({s, "super chain", false, {}, {}});
                    for (const auto& s : a.subclassesOf(name, 2000)) xrefs_.push_back({s, "subclass", false, {}, {}});
                    for (const auto& s : a.implementersOf(name, 2000)) xrefs_.push_back({s, "implements", false, {}, {}});
                    requestTab_ = 1;
                }
                if (ImGui::MenuItem("Copy name")) ImGui::SetClipboardText(name.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    ImGui::TextDisabled("%zu of %zu classes", filtered_.size(), a.classes().size());
    if (selectedClass_ >= 0 && selectedClass_ < (int)a.classes().size()) drawMethods(a, apk, a.classes()[(size_t)selectedClass_]);
}

void AnalysisPanel::drawMethods(const ApkAnalysis& a, Root& apk, const ApkAnalysis::ClassEntry& c) {
    const DexFile& dex = *a.dexes()[c.dex];
    const auto& def = a.classDef(c);
    ImGui::BeginChild("##methods", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextColored(kAccent, "%s", DexFile::descriptorToJava(a.classDescriptor(c)).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("extends %s  [%s]",
                        def.superclassIdx != DexFile::kNoIndex ? DexFile::descriptorToJava(dex.typeDescriptor(def.superclassIdx)).c_str() : "-",
                        dex.name().c_str());
    if (ImGui::BeginTable("##mt", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                         ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthStretch, 3.f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, ui::em(3.5f));
        ImGui::TableHeadersRow();
        int row = 0;
        for (const ApkAnalysis::MethodDef& m : a.methodsOf(c)) {
            ImGui::PushID(row++);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            std::string label = DexFile::accessFlagsToString(m.method.accessFlags, true);
            if (!label.empty()) label += ' ';
            label += std::string(dex.methodName(m.method.methodIdx)) + dex.protoDescriptor(dex.methodProto(m.method.methodIdx));
            if (ImGui::Selectable(label.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_SpanAllColumns) &&
                ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                openMethod(a, m, apk.title);
            // Same keys as the native view: Space for the graph, X for cross-references.
            if (ImGui::IsItemHovered() && !ImGui::GetIO().WantTextInput) {
                if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) showGraph(a, m);
                if (ImGui::IsKeyPressed(ImGuiKey_X, false)) showCallers(a, m);
            }
            if (ImGui::BeginPopupContextItem("##method")) {
                if (ImGui::MenuItem("Open listing")) openMethod(a, m, apk.title);
                if (ImGui::MenuItem("Control-flow graph", "Space")) showGraph(a, m);
                if (ImGui::MenuItem("Call graph")) showCallGraph(a, m);
                ImGui::Separator();
                if (ImGui::MenuItem("Callers", "X")) showCallers(a, m);
                if (ImGui::MenuItem("Callees")) showCallees(a, m);
                ImGui::EndPopup();
            }
            ImGui::TableNextColumn();
            DexFile::CodeItem code;
            if (m.method.codeOff && dex.codeItem(m.method.codeOff, code)) ImGui::Text("%u", code.insnsSize);
            else ImGui::TextDisabled("-");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

void AnalysisPanel::openClass(const ApkAnalysis& a, const ApkAnalysis::ClassEntry& c, const std::string& group) {
    const std::string desc(a.classDescriptor(c));
    workspace_.openGenerated(group, "smali/" + sanitizeForPath(desc) + ".smali", shortName(desc) + ".smali",
                             a.disassembleClass(c), 0);
}

void AnalysisPanel::openMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group,
                               uint32_t pc) {
    workspace_.openMethodListing(group, a, m, pc);
}

void AnalysisPanel::openCodeRef(const ApkAnalysis& a, const ApkAnalysis::CodeRef& r, const std::string& group) {
    const DexFile& dex = *a.dexes()[r.dex];
    for (const auto& m : a.findMethodDefs(dex.typeDescriptor(dex.methodClass(r.method)), dex.methodName(r.method),
                                          dex.protoDescriptor(dex.methodProto(r.method)))) {
        openMethod(a, m, group, r.pc);
        return;
    }
    workspace_.log("Method has no bytecode in this APK: " + a.methodSignature(r), "analysis");
}

void AnalysisPanel::showCallers(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    const DexFile& dex = *a.dexes()[m.dex];
    xrefs_.clear();
    xrefTitle_ = "Callers of " + a.methodSignature(m);
    for (const auto& h : a.callersOf(dex.typeDescriptor(dex.methodClass(m.method.methodIdx)), dex.methodName(m.method.methodIdx),
                                     dex.protoDescriptor(dex.methodProto(m.method.methodIdx)), 5000)) {
        char pc[32];
        std::snprintf(pc, sizeof pc, "call @%04x", h.from.pc);
        xrefs_.push_back({a.methodSignature(h.from), pc, true, h.from, {}});
    }
    requestTab_ = 1;
}

void AnalysisPanel::showCallees(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    xrefs_.clear();
    xrefTitle_ = "Calls made by " + a.methodSignature(m);
    for (const auto& c : a.calleesOf(m)) {
        char what[64];
        std::snprintf(what, sizeof what, "%s @%04x", c.opcode.c_str(), c.pc);
        xrefs_.push_back({c.signature, what, true, {m.dex, m.method.methodIdx, c.pc}, c.signature});
    }
    requestTab_ = 1;
}

// ---------------------------------------------------------------------------
// Xrefs
// ---------------------------------------------------------------------------

void AnalysisPanel::drawXrefs(const ApkAnalysis& a, Root& apk) {
    if (ready(xrefJob_)) {
        xrefs_ = xrefJob_.get();
        const size_t at = xrefTitle_.rfind(" (searching...)");
        if (at != std::string::npos) xrefTitle_.resize(at);
    } else if (xrefJob_.valid()) {
        ImGui::TextDisabled("%s", xrefTitle_.c_str());
        ImGui::ProgressBar(-1.f * (float)ImGui::GetTime(), ImVec2(ui::em(12.f), 0), "scanning methods");
        return;
    }
    if (xrefTitle_.empty()) {
        ImGui::TextDisabled("Use Callers / Callees on a method, a class context menu, or a string to fill this list.");
        return;
    }
    ImGui::TextColored(kAccent, "%s", xrefTitle_.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu)", xrefs_.size());
    if (ImGui::BeginTable("##xr", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                         ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 4.f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin((int)xrefs_.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const XrefRow& r = xrefs_[(size_t)i];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (ImGui::Selectable(r.from.c_str(), false, ImGuiSelectableFlags_SpanAllColumns |
                                                                 ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (!r.targetMethod.empty()) {
                        std::string cls, name, proto;
                        if (ApkAnalysis::splitMethodRef(r.targetMethod, cls, name, proto)) {
                            auto defs = a.findMethodDefs(cls, name, proto);
                            if (!defs.empty()) openMethod(a, defs.front(), apk.title);
                            else openCodeRef(a, r.ref, apk.title);  // framework callee: show the call site
                        }
                    } else if (r.hasRef) {
                        openCodeRef(a, r.ref, apk.title);
                    } else if (const auto* c = a.findClass(r.from)) {
                        openClass(a, *c, apk.title);
                    }
                }
                if (ImGui::BeginPopupContextItem("##xrctx")) {
                    if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(r.from.c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", r.what.c_str());
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

void AnalysisPanel::drawStrings(const ApkAnalysis& a, Root& apk) {
    ImGui::SetNextItemWidth(std::min(ui::em(9.f), ImGui::GetContentRegionAvail().x));
    bool refresh = ImGui::Combo("##cat", &stringCategory_, kCategoryNames, IM_ARRAYSIZE(kCategoryNames));
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-ui::buttonWidth("Search") - ImGui::GetStyle().ItemSpacing.x);
    refresh |= ImGui::InputTextWithHint("##sfilter", "Filter...", stringFilter_, sizeof stringFilter_,
                                        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    refresh |= ImGui::Button("Search");
    if (refresh || !stringsLoaded_) {
        strings_ = a.strings(stringFilter_, kCategories[stringCategory_], 20000);
        stringsLoaded_ = true;
    }
    ImGui::TextDisabled("%zu strings%s - click to list the code using one", strings_.size(),
                        strings_.size() >= 20000 ? " (capped)" : "");
    if (ImGui::BeginTable("##st", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 5.f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin((int)strings_.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& s = strings_[(size_t)i];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                std::string shown = s.value.size() > 300 ? s.value.substr(0, 300) + "..." : s.value;
                for (char& ch : shown)
                    if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
                if (ImGui::Selectable(shown.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    xrefs_.clear();
                    xrefTitle_ = "Uses of \"" + (s.value.size() > 80 ? s.value.substr(0, 80) + "..." : s.value) + "\"";
                    for (const auto& h : a.stringUses(s.value, false, 5000)) {
                        char pc[32];
                        std::snprintf(pc, sizeof pc, "const-string @%04x", h.from.pc);
                        xrefs_.push_back({a.methodSignature(h.from), pc, true, h.from, {}});
                    }
                    requestTab_ = 1;
                }
                if (ImGui::BeginPopupContextItem("##sctx")) {
                    if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(s.value.c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", ApkAnalysis::categoryName(s.category));
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    (void)apk;
}

// ---------------------------------------------------------------------------
// Control-flow graph
// ---------------------------------------------------------------------------

void AnalysisPanel::showGraph(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    graphMethod_ = m;
    graphBlocks_ = a.controlFlowGraph(m);
    graphTitle_ = a.methodSignature(m);
    graphValid_ = true;
    graphIsCalls_ = false;

    // Block text from the listing (pc-tagged lines).
    std::string listing;
    std::vector<int32_t> pcs;
    dalvik::ListingOptions opt;
    opt.showLines = false;
    dalvik::disassembleMethod(*a.dexes()[m.dex], m.method, opt, listing, &pcs);
    std::vector<std::pair<int32_t, std::string>> lines;
    size_t start = 0, li = 0;
    for (size_t i = 0; i <= listing.size(); ++i)
        if (i == listing.size() || listing[i] == '\n') {
            if (li < pcs.size() && pcs[li] >= 0) {
                std::string l = listing.substr(start, i - start);
                const size_t first = l.find_first_not_of(' ');
                lines.emplace_back(pcs[li], first == std::string::npos ? l : l.substr(first));
            }
            ++li;
            start = i + 1;
        }

    std::vector<GraphView::Block> blocks(graphBlocks_.size());
    std::vector<graphlayout::Edge> edges;
    for (uint32_t b = 0; b < (uint32_t)graphBlocks_.size(); ++b) {
        const auto& block = graphBlocks_[b];
        for (const auto& l : lines)
            if (l.first >= (int32_t)block.startPc && l.first < (int32_t)block.endPc) {
                std::string text = l.second.size() > 90 ? l.second.substr(0, 90) + "..." : l.second;
                ImU32 color = IM_COL32(212, 212, 212, 255);
                if (text.rfind("invoke", 0) == 0) color = IM_COL32(140, 190, 240, 255);
                else if (text.rfind("if-", 0) == 0 || text.rfind("goto", 0) == 0 || text.rfind("packed-", 0) == 0 || text.rfind("sparse-", 0) == 0)
                    color = IM_COL32(240, 205, 100, 255);
                else if (text.rfind("return", 0) == 0 || text.rfind("throw", 0) == 0) color = IM_COL32(240, 125, 125, 255);
                blocks[b].lines.push_back({{std::move(text), color}});
            }
        if (block.exit) blocks[b].border = IM_COL32(200, 120, 120, 255);
        const bool branch = block.successors.size() == 2;
        for (size_t k = 0; k < block.successors.size(); ++k) {
            graphlayout::Edge e;
            e.from = (int)b;
            e.to = (int)block.successors[k];
            e.kind = branch ? (k == 0 ? graphlayout::EdgeKind::Taken : graphlayout::EdgeKind::Fallthrough) : graphlayout::EdgeKind::Jump;
            edges.push_back(std::move(e));
        }
        for (uint32_t h : block.exceptional) {
            graphlayout::Edge e;
            e.from = (int)b;
            e.to = (int)h;
            e.kind = graphlayout::EdgeKind::Exception;
            edges.push_back(std::move(e));
        }
    }
    graph_.set(std::move(blocks), std::move(edges));
    requestTab_ = 3;
}

// The method, what calls it and what it calls. Double-clicking a neighbour recentres.
void AnalysisPanel::showCallGraph(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    constexpr size_t kMaxNeighbours = 40;
    const DexFile& dex = *a.dexes()[m.dex];
    const auto shortRef = [](const std::string& ref) {
        std::string cls, name, proto;
        if (!ApkAnalysis::splitMethodRef(ref, cls, name, proto)) return ref;
        return shortName(cls) + "." + name + "()";
    };
    graphMethod_ = m;
    graphTitle_ = a.methodSignature(m);
    graphValid_ = true;
    graphIsCalls_ = true;
    graphRefs_ = {graphTitle_};
    std::vector<GraphView::Block> blocks(1);
    blocks[0].lines.push_back({{shortRef(graphTitle_), IM_COL32(255, 255, 255, 255)}});
    blocks[0].border = IM_COL32(0, 150, 240, 255);
    blocks[0].fill = IM_COL32(32, 48, 66, 255);
    std::vector<graphlayout::Edge> edges;
    const auto addNode = [&](const std::string& ref, bool caller) {
        const auto seen = std::find(graphRefs_.begin(), graphRefs_.end(), ref);
        int index = (int)(seen - graphRefs_.begin());
        if (seen == graphRefs_.end()) {
            graphRefs_.push_back(ref);
            GraphView::Block block;
            block.lines.push_back({{shortRef(ref), IM_COL32(212, 212, 212, 255)}});
            blocks.push_back(std::move(block));
        }
        graphlayout::Edge e;
        e.from = caller ? index : 0;
        e.to = caller ? 0 : index;
        e.kind = graphlayout::EdgeKind::Call;
        const bool duplicate = std::any_of(edges.begin(), edges.end(), [&](const graphlayout::Edge& o) { return o.from == e.from && o.to == e.to; });
        if (!duplicate) edges.push_back(std::move(e));
    };
    size_t count = 0;
    for (const auto& h : a.callersOf(dex.typeDescriptor(dex.methodClass(m.method.methodIdx)), dex.methodName(m.method.methodIdx),
                                     dex.protoDescriptor(dex.methodProto(m.method.methodIdx)), 400)) {
        if (count++ >= kMaxNeighbours) break;
        addNode(a.methodSignature(h.from), true);
    }
    count = 0;
    for (const auto& c : a.calleesOf(m)) {
        if (count++ >= kMaxNeighbours) break;
        addNode(c.signature, false);
    }
    graph_.set(std::move(blocks), std::move(edges), true);
    requestTab_ = 3;
}

void AnalysisPanel::drawGraph(const ApkAnalysis& a, Root& apk) {
    if (!graphValid_) {
        ImGui::TextDisabled("Press CFG or Calls on a method (Classes tab) to show its graph.");
        return;
    }
    ImGui::TextColored(kAccent, "%s", graphTitle_.c_str());
    if (!graphIsCalls_) {
        ui::sameLineIfFits(ui::em(6.f));
        if (ImGui::SmallButton("Copy DOT")) ImGui::SetClipboardText(a.cfgToDot(graphMethod_, graphBlocks_).c_str());
    }
    const GraphView::Result r = graph_.draw("##graph", Theme::monoFont());
    if (!r.activated || r.block < 0) return;
    if (!graphIsCalls_) {
        if (r.block < (int)graphBlocks_.size()) openMethod(a, graphMethod_, apk.title, graphBlocks_[(size_t)r.block].startPc);
        return;
    }
    if (r.block >= (int)graphRefs_.size()) return;
    const std::string ref = graphRefs_[(size_t)r.block];
    std::string cls, name, proto;
    std::vector<ApkAnalysis::MethodDef> defs;
    if (ApkAnalysis::splitMethodRef(ref, cls, name, proto)) defs = a.findMethodDefs(cls, name, proto);
    if (defs.empty()) workspace_.log("No bytecode in this APK for " + ref, "analysis");
    else showCallGraph(a, defs.front());
}

// ---------------------------------------------------------------------------
// Native libraries
// ---------------------------------------------------------------------------

void AnalysisPanel::selectLib(Root& apk, int index) {
    selectedLib_ = index;
    elf_.reset();
    elfError_.clear();
    resetNative();
    AnalysisService* service = &workspace_.analysis();
    const std::string apkPath = apk.apkPath, entry = libs_[(size_t)index].path;
    // Parsed on a worker with its own archive handle.
    elfLoad_ = std::async(std::launch::async, [service, apkPath, entry] {
        std::string err;
        auto elf = service->loadElf(apkPath, entry, err);
        return std::make_pair(elf, err);
    });
}

void AnalysisPanel::drawNative(Root& apk) {
    if (libsGroup_ != apk.title) {
        libsGroup_ = apk.title;
        libs_.clear();
        selectedLib_ = -1;
        elf_.reset();
        resetNative();
        if (const TreeNode* lib = apk.tree ? apk.tree->findChild("lib") : nullptr)
            for (const auto& abi : lib->children())
                for (const auto& so : abi->children()) {
                    if (so->isFolder()) continue;
                    uint64_t size = 0;
                    apk.source->sizeOf(*so, size);
                    libs_.push_back({so->path(), abi->name(), size});
                }
    }
    if (libs_.empty()) {
        ImGui::TextDisabled("This APK ships no native libraries (lib/<abi>/*.so).");
        return;
    }
    if (ready(elfLoad_)) {
        auto r = elfLoad_.get();
        elf_ = std::move(r.first);
        elfError_ = std::move(r.second);
    }
    if (!pendingLib_.empty() && !elfLoad_.valid()) {
        for (int i = 0; i < (int)libs_.size(); ++i)
            if (libs_[(size_t)i].path == pendingLib_ && i != selectedLib_) selectLib(apk, i);
        pendingLib_.clear();
    }
    // Code views get the whole panel: the library list shrinks to a dropdown.
    if (selectedLib_ < 0 && !elfLoad_.valid()) {  // open on something: arm64 can be disassembled
        int first = 0;
        for (int i = (int)libs_.size() - 1; i >= 0; --i)
            if (libs_[(size_t)i].abi == "arm64-v8a") first = i;
        selectLib(apk, first);
    }
    const bool compactLibs = selectedLib_ >= 0;
    const bool sideBySide = !compactLibs && ImGui::GetContentRegionAvail().x > ui::em(34.f);
    const auto libLabel = [&](int i) {
        char label[512];
        std::snprintf(label, sizeof label, "%s  (%.0f KB)", libs_[(size_t)i].path.c_str(), (double)libs_[(size_t)i].size / 1024.0);
        return std::string(label);
    };
    if (compactLibs) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::BeginCombo("##lib", libLabel(selectedLib_).c_str())) {
            for (int i = 0; i < (int)libs_.size(); ++i)
                if (ImGui::Selectable(libLabel(i).c_str(), selectedLib_ == i) && !elfLoad_.valid() && selectedLib_ != i) selectLib(apk, i);
            ImGui::EndCombo();
        }
    } else {
    // Stacked: just tall enough for the library list (resizable).
    const float libsH = std::min(ui::em(8.f), ImGui::GetTextLineHeightWithSpacing() * ((float)libs_.size() + 0.6f) +
                                                  ImGui::GetStyle().WindowPadding.y * 2.f);
    ImGui::BeginChild("##libs", sideBySide ? ImVec2(ui::em(15.f), 0) : ImVec2(0, libsH),
                      ImGuiChildFlags_Borders | (sideBySide ? ImGuiChildFlags_ResizeX : ImGuiChildFlags_ResizeY));
    for (int i = 0; i < (int)libs_.size(); ++i)
        if (ImGui::Selectable(libLabel(i).c_str(), selectedLib_ == i) && !elfLoad_.valid() && selectedLib_ != i) selectLib(apk, i);
    ImGui::EndChild();
    if (sideBySide) ImGui::SameLine();
    }
    ImGui::BeginChild("##elf", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (elfLoad_.valid()) {
        ImGui::TextDisabled("Parsing...");
    } else if (!elfError_.empty()) {
        ImGui::TextColored(kWarn, "%s", elfError_.c_str());
    } else if (elf_) {
        const bool codeView = symbolView_ != 3 && symbolView_ != 4;  // file facts belong with the sections
        if (!codeView) {
            ImGui::TextColored(kAccent, "%s", elf_->name().c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("%s %s, %s", elf_->is64() ? "ELF64" : "ELF32", elf_->typeName().c_str(), elf_->machineName().c_str());
        }
        if (!codeView && !elf_->soname().empty()) ImGui::Text("SONAME: %s", elf_->soname().c_str());
        if (!codeView && !elf_->needed().empty()) {
            std::string needed;
            for (const auto& n : elf_->needed()) needed += (needed.empty() ? "" : ", ") + n;
            ImGui::TextWrapped("NEEDED: %s", needed.c_str());
        }
        if (!codeView && selectedLib_ >= 0 && ImGui::SmallButton("Open hex view")) {
            if (const TreeNode* node = apk.tree->findByPath(libs_[(size_t)selectedLib_].path))
                workspace_.openNode(apk, *node, -1, Workspace::OpenMode::Permanent);
        }
        ImGui::Separator();
        static const char* const kViews[] = {"Functions", "Strings", "Symbols", "Sections"};
        int view = symbolView_ == 5 ? 0 : symbolView_ == 6 ? 1 : symbolView_ <= 2 ? 2 : 3;
        if (ui::segmented(kViews, 4, view)) symbolView_ = view == 0 ? 5 : view == 1 ? 6 : view == 2 ? 0 : 3;
        if (view == 2) {
            static const char* const kSymbols[] = {"JNI", "Exports", "Imports"};
            ImGui::SameLine(0.f, ui::em(1.f));
            ui::segmented(kSymbols, 3, symbolView_);
        } else if (view == 3) {
            static const char* const kParts[] = {"Sections", "Segments"};
            int part = symbolView_ - 3;
            ImGui::SameLine(0.f, ui::em(1.f));
            if (ui::segmented(kParts, 2, part)) symbolView_ = 3 + part;
        }
        if (symbolView_ <= 4) {
            ui::sameLineIfFits(ui::em(8.f));
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputTextWithHint("##symf", "Filter...", symbolFilter_, sizeof symbolFilter_);
        }
        const std::string filter = symbolFilter_;
        if (symbolView_ == 5) {
            drawNativeCode(apk);
        } else if (symbolView_ == 6) {
            drawNativeStrings(apk);
        } else if (symbolView_ <= 2) {
            const auto syms = symbolView_ == 0 ? elf_->jniSymbols() : symbolView_ == 1 ? elf_->exports() : elf_->imports();
            std::vector<const ElfFile::Symbol*> shown;
            for (const auto* s : syms)
                if (filter.empty() || tex::ciFind(s->name, filter) != std::string_view::npos) shown.push_back(s);
            if (ImGui::BeginTable("##syms", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch, 5.f);
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, ui::em(6.f));
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, ui::em(4.f));
                ImGui::TableHeadersRow();
                ImGuiListClipper clipper;
                clipper.Begin((int)shown.size());
                while (clipper.Step())
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                        const auto* s = shown[(size_t)i];
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        const std::string dem = ElfFile::demangle(s->name);
                        ImGui::PushID(i);
                        const bool defined = s->shndx != 0 && s->value != 0;
                        if (ImGui::Selectable(dem.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) && defined &&
                            ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                            symbolView_ = 5;
                            gotoNative(s->value & ~1ull);
                        }
                        ImGui::PopID();
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("%s%s", s->name.c_str(), defined ? "\ndouble-click: disassemble" : "");
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%llx", (unsigned long long)s->value);
                        ImGui::TableNextColumn();
                        ImGui::Text("%llu", (unsigned long long)s->size);
                    }
                ImGui::EndTable();
            }
        } else if (symbolView_ == 3) {
            if (ImGui::BeginTable("##secs", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Address");
                ImGui::TableSetupColumn("Offset");
                ImGui::TableSetupColumn("Size");
                ImGui::TableHeadersRow();
                for (const auto& s : elf_->sections()) {
                    if (!filter.empty() && tex::ciFind(s.name, filter) == std::string_view::npos) continue;
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(s.name.c_str());
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", (unsigned long long)s.addr);
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", (unsigned long long)s.offset);
                    ImGui::TableNextColumn();
                    ImGui::Text("%llu", (unsigned long long)s.size);
                }
                ImGui::EndTable();
            }
        } else if (symbolView_ == 4) {
            if (ImGui::BeginTable("##segs", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Type");
                ImGui::TableSetupColumn("Flags");
                ImGui::TableSetupColumn("VAddr");
                ImGui::TableSetupColumn("Offset");
                ImGui::TableSetupColumn("FileSz / MemSz");
                ImGui::TableHeadersRow();
                for (const auto& s : elf_->segments()) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("%u", s.type);
                    ImGui::TableNextColumn();
                    ImGui::Text("%c%c%c", s.flags & 4 ? 'R' : '-', s.flags & 2 ? 'W' : '-', s.flags & 1 ? 'X' : '-');
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", (unsigned long long)s.vaddr);
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", (unsigned long long)s.offset);
                    ImGui::TableNextColumn();
                    ImGui::Text("%llu / %llu", (unsigned long long)s.filesz, (unsigned long long)s.memsz);
                }
                ImGui::EndTable();
            }
        }
    } else {
        ImGui::TextDisabled("Select a library.");
    }
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

void AnalysisPanel::drawCompare(Root& apk) {
    std::vector<Root*> apks = workspace_.apkRoots();
    if (apks.size() < 2) {
        ImGui::TextDisabled("Add a second APK (another version) to the project to compare them.");
        return;
    }
    if (compareWith_ < 0 || compareWith_ >= (int)apks.size() || apks[(size_t)compareWith_] == &apk)
        for (int i = 0; i < (int)apks.size(); ++i)
            if (apks[(size_t)i] != &apk) compareWith_ = i;
    Root& other = *apks[(size_t)compareWith_];
    ImGui::Text("Compare %s with", apk.title.c_str());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::min(ui::em(12.f), ImGui::GetContentRegionAvail().x));
    if (ImGui::BeginCombo("##other", other.title.c_str())) {
        for (int i = 0; i < (int)apks.size(); ++i)
            if (apks[(size_t)i] != &apk && ImGui::Selectable(apks[(size_t)i]->title.c_str(), i == compareWith_)) compareWith_ = i;
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    const bool running = diffJob_.valid();
    if (running) ImGui::BeginDisabled();
    if (ImGui::Button("Compare")) {
        auto* archA = dynamic_cast<ApkArchive*>(apk.source.get());
        auto* archB = dynamic_cast<ApkArchive*>(other.source.get());
        if (archA && archB) {
            // Central directories and manifests are read here (UI thread
            // owns the archives); the code diff runs on a worker.
            auto entriesA = archA->entries(), entriesB = archB->entries();
            workspace_.resources(apk.title);
            workspace_.resources(other.title);
            const ApkInfo ia = ApkInfo::extract(apk), ib = ApkInfo::extract(other);
            permAdded_.clear();
            permRemoved_.clear();
            std::set<std::string> pa(ia.permissions.begin(), ia.permissions.end()), pb(ib.permissions.begin(), ib.permissions.end());
            for (const auto& p : pb)
                if (!pa.count(p)) permAdded_.push_back(p);
            for (const auto& p : pa)
                if (!pb.count(p)) permRemoved_.push_back(p);
            diffTitle_ = apk.title + " (" + ia.versionName + ") -> " + other.title + " (" + ib.versionName + ")";
            auto anA = workspace_.analysis().get(apk.title), anB = workspace_.analysis().get(other.title);
            diffJob_ = std::async(std::launch::async, [entriesA = std::move(entriesA), entriesB = std::move(entriesB), anA, anB] {
                ApkDiff d = ApkDiff::compareEntries(entriesA, entriesB);
                if (anA && anB) d.compareCode(*anA, *anB, 20000, nullptr);
                return d;
            });
            diffValid_ = false;
        }
    }
    if (running) {
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("comparing...");
    }
    if (ready(diffJob_)) {
        diff_ = diffJob_.get();
        diffValid_ = true;
    }
    if (!workspace_.analysis().get(apk.title) || !workspace_.analysis().get(other.title))
        ImGui::TextDisabled("Tip: analyse both APKs to also compare classes and method bodies.");
    if (!diffValid_) return;
    ImGui::TextColored(kAccent, "%s", diffTitle_.c_str());
    ImGui::Text("%zu entries changed, %zu unchanged", diff_.entries.size(), diff_.entriesUnchanged);
    const auto list = [](const char* title, const std::vector<std::string>& items) {
        char header[128];
        std::snprintf(header, sizeof header, "%s (%zu)###%s", title, items.size(), title);
        if (ImGui::CollapsingHeader(header)) {
            ImGui::BeginChild(title, ImVec2(0, std::min(240.f, 20.f + 18.f * (float)items.size())), ImGuiChildFlags_Borders);
            ImGuiListClipper clipper;
            clipper.Begin((int)items.size());
            while (clipper.Step())
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) ImGui::TextUnformatted(items[(size_t)i].c_str());
            ImGui::EndChild();
        }
    };
    if (ImGui::CollapsingHeader("Archive entries")) {
        ImGui::BeginChild("##entries", ImVec2(0, 240.f), ImGuiChildFlags_Borders);
        for (const auto& e : diff_.entries) {
            const ImVec4 col = e.kind == ApkDiff::Kind::Added ? ImVec4(0.4f, 0.8f, 0.4f, 1.f)
                               : e.kind == ApkDiff::Kind::Removed ? ImVec4(0.9f, 0.45f, 0.4f, 1.f)
                                                                  : ImVec4(0.9f, 0.8f, 0.4f, 1.f);
            ImGui::TextColored(col, "%-8s", ApkDiff::kindName(e.kind));
            ImGui::SameLine();
            ImGui::Text("%s  (%llu -> %llu bytes)", e.path.c_str(), (unsigned long long)e.sizeA, (unsigned long long)e.sizeB);
        }
        ImGui::EndChild();
    }
    list("Permissions added", permAdded_);
    list("Permissions removed", permRemoved_);
    if (diff_.codeCompared) {
        list("Classes added", diff_.classesAdded);
        list("Classes removed", diff_.classesRemoved);
        list("Methods changed", diff_.methodsChanged);
        list("Methods added", diff_.methodsAdded);
        list("Methods removed", diff_.methodsRemoved);
    }
}

// ---------------------------------------------------------------------------
// Resources (resources.arsc)
// ---------------------------------------------------------------------------

void AnalysisPanel::drawResources(Root& apk) {
    std::shared_ptr<const ResourceTable> table = workspace_.resources(apk.title);
    if (!table) {
        ImGui::TextDisabled("This APK has no readable resources.arsc.");
        return;
    }
    if (table.get() != resOwner_) {
        resOwner_ = table.get();
        resTypes_ = table->types();
        resTypes_.insert(resTypes_.begin(), "(all types)");
        resType_ = 0;
        resKey_ = "\x01";
    }
    ui::wrappedColored(kDim, table->packageName() + " - " + std::to_string(table->size()) + " resources");
    ImGui::SetNextItemWidth(std::min(ui::em(9.f), ImGui::GetContentRegionAvail().x));
    if (ImGui::BeginCombo("##restype", resTypes_[(size_t)resType_].c_str())) {
        for (int i = 0; i < (int)resTypes_.size(); ++i)
            if (ImGui::Selectable(resTypes_[(size_t)i].c_str(), i == resType_)) resType_ = i;
        ImGui::EndCombo();
    }
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##resfilter", "Filter name or value...", resFilter_, sizeof resFilter_);
    const std::string key = std::to_string(resType_) + "|" + resFilter_;
    if (key != resKey_) {
        resKey_ = key;
        resItems_ = table->list(resType_ ? resTypes_[(size_t)resType_] : std::string(), resFilter_, 50000);
    }
    // Narrow panels show "type/name" + value; wide ones add id and type columns.
    const bool wideRes = ImGui::GetContentRegionAvail().x > ui::em(30.f);
    if (ImGui::BeginTable("##res", wideRes ? 4 : 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                                        ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        if (wideRes) {
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, ui::em(5.5f));
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, ui::em(5.f));
        }
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin((int)resItems_.size());
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const ResourceTable::Item& it = resItems_[(size_t)i];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                char id[16];
                std::snprintf(id, sizeof id, "0x%08X", it.id);
                const std::string first = wideRes ? std::string(id) : it.type + "/" + it.name;
                ImGui::Selectable(first.c_str(), false, ImGuiSelectableFlags_SpanAllColumns);
                if (!wideRes && ImGui::IsItemHovered()) ImGui::SetTooltip("%s  @%s/%s", id, it.type.c_str(), it.name.c_str());
                if (ImGui::BeginPopupContextItem("##resctx")) {
                    if (ImGui::MenuItem("Copy id")) ImGui::SetClipboardText(id);
                    if (ImGui::MenuItem("Copy reference")) ImGui::SetClipboardText(("@" + it.type + "/" + it.name).c_str());
                    if (!it.value.empty() && ImGui::MenuItem("Copy value")) ImGui::SetClipboardText(it.value.c_str());
                    if (auto a = workspace_.analysis().get(apk.title); a && ImGui::MenuItem("Find code using this id")) {
                        // R.<type>.<name> is compiled into a literal: list the
                        // methods that load the id as a constant.
                        // Every method is scanned: run it off the UI thread.
                        xrefs_.clear();
                        xrefTitle_ = "Code referencing @" + it.type + "/" + it.name + " (searching...)";
                        const std::string literal = std::to_string((int32_t)it.id);
                        xrefJob_ = std::async(std::launch::async, [a, literal] {
                            std::vector<XrefRow> rows;
                            for (const auto& cls : a->classes())
                                for (const auto& m : a->methodsOf(cls))
                                    for (const auto& call : a->constantArguments(m))
                                        for (const auto& arg : call.args)
                                            if (arg.second == literal && rows.size() < 2000)
                                                rows.push_back({a->methodSignature(m), "passes id to " + call.callee, true,
                                                                {m.dex, m.method.methodIdx, call.pc}, {}});
                            return rows;
                        });
                        requestTab_ = 1;
                    }
                    ImGui::EndPopup();
                }
                if (wideRes) {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", it.type.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(it.name.c_str());
                }
                ImGui::TableNextColumn();
                if (it.complex) ImGui::TextDisabled("(style / array)");
                else {
                    std::string v = it.value.size() > 200 ? it.value.substr(0, 200) + "..." : it.value;
                    for (char& c : v)
                        if (c == '\n' || c == '\r') c = ' ';
                    ImGui::TextUnformatted(v.c_str());
                    if (it.value.size() > 60 && ImGui::IsItemHovered()) {
                        ImGui::PushTextWrapPos(ui::em(30.f));
                        ImGui::SetTooltip("%s", it.value.c_str());
                        ImGui::PopTextWrapPos();
                    }
                }
                if (it.configs > 1) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(%d configs)", it.configs);
                }
                ImGui::PopID();
            }
        ImGui::EndTable();
    }
}
