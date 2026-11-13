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
#include "document/SyntaxHighlighter.hpp"
#include "ui/UiUtil.hpp"

namespace {

const ImVec4 kDim(0.6f, 0.6f, 0.6f, 1.f);
const ImVec4 kAccent(0.55f, 0.75f, 0.95f, 1.f);
const ImVec4 kWarn(0.95f, 0.65f, 0.35f, 1.f);

template <typename T>
bool ready(std::future<T>& f) {
    return f.valid() && f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::string hexAddr(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return b;
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

// "(Ljava/lang/String;I)V" pieces: "String", "int", "byte[]".
std::string prettyType(std::string_view d) {
    int dims = 0;
    while (!d.empty() && d[0] == '[') {
        ++dims;
        d.remove_prefix(1);
    }
    std::string base;
    switch (d.empty() ? 'V' : d[0]) {
    case 'Z': base = "boolean"; break;
    case 'B': base = "byte"; break;
    case 'S': base = "short"; break;
    case 'C': base = "char"; break;
    case 'I': base = "int"; break;
    case 'J': base = "long"; break;
    case 'F': base = "float"; break;
    case 'D': base = "double"; break;
    case 'V': base = "void"; break;
    default: base = shortName(d); break;
    }
    for (int i = 0; i < dims; ++i) base += "[]";
    return base;
}

// "name(String, int) : boolean" from a name and a proto descriptor.
std::string prettyMethod(std::string_view cls, std::string_view name, std::string_view proto) {
    std::string params;
    size_t i = proto.find('(') + 1;
    const size_t close = proto.find(')');
    while (i < close && i != std::string_view::npos + 1) {
        size_t j = i;
        while (j < close && proto[j] == '[') ++j;
        if (j < close && proto[j] == 'L') j = proto.find(';', j);
        if (j == std::string_view::npos || j >= close) j = close - 1;
        if (!params.empty()) params += ", ";
        params += prettyType(proto.substr(i, j - i + 1));
        i = j + 1;
    }
    std::string shown(name);
    if (name == "<init>") shown = shortName(cls);
    else if (name == "<clinit>") return "static {}";
    std::string out = shown + "(" + params + ")";
    if (name != "<init>" && close != std::string_view::npos && close + 1 < proto.size()) out += " : " + prettyType(proto.substr(close + 1));
    return out;
}

// "Lcom/a/B;->name(I)V" -> "B.name(int)".
std::string prettyRef(const std::string& ref) {
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(ref, cls, name, proto)) return ref;
    std::string m = prettyMethod(cls, name, proto);
    const size_t colon = m.find(" : ");
    if (colon != std::string::npos) m.resize(colon);
    return name == "<init>" ? "new " + m : shortName(cls) + "." + m;
}

// Small round badge before a tree row: C class, I interface, E enum, m method.
void badge(char letter, ImU32 color) {
    const float h = ImGui::GetTextLineHeight();
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 c(p.x + h * 0.5f, p.y + h * 0.5f);
    dl->AddCircleFilled(c, h * 0.42f, color);
    const char text[2] = {letter, 0};
    const ImVec2 ts = ImGui::CalcTextSize(text);
    dl->AddText(ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f), IM_COL32(255, 255, 255, 255), text);
    ImGui::Dummy(ImVec2(h, h));
    ImGui::SameLine(0.f, ImGui::GetStyle().ItemInnerSpacing.x);
}

void folderIcon() {
    const float h = ImGui::GetTextLineHeight();
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(ImVec2(p.x + h * 0.08f, p.y + h * 0.22f), ImVec2(p.x + h * 0.45f, p.y + h * 0.36f), IM_COL32(200, 170, 90, 255), 1.f);
    dl->AddRectFilled(ImVec2(p.x + h * 0.08f, p.y + h * 0.32f), ImVec2(p.x + h * 0.92f, p.y + h * 0.82f), IM_COL32(220, 185, 95, 255), 1.5f);
    ImGui::Dummy(ImVec2(h, h));
    ImGui::SameLine(0.f, ImGui::GetStyle().ItemInnerSpacing.x);
}

}  // namespace

void AnalysisPanel::resetCaches() {
    appliedFilter_ = "\x01";  // force a refilter
    packages_.clear();
    packageOpen_.clear();
    classOpen_.clear();
    classMethods_.clear();
    rows_.clear();
    rowsDirty_ = true;
    sel_ = Selection::None;
    selClass_ = UINT32_MAX;
    selCallers_.clear();
    selCallees_.clear();
    methodListing_.clear();
    refsQuery_ = false;
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
        ImGui::TextDisabled("Open an APK to analyse it.");
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
        nav_ = Nav::Native;
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
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::BeginCombo("##apk", apks[(size_t)apkIdx_]->title.c_str())) {
            for (int i = 0; i < (int)apks.size(); ++i)
                if (ImGui::Selectable(apks[(size_t)i]->title.c_str(), i == apkIdx_) && i != apkIdx_) {
                    apkIdx_ = i;
                    resetCaches();
                }
            ImGui::EndCombo();
        }
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
    current_ = analysis;
    currentGroup_ = apk.title;
    if (methodRequested && analysis) {
        std::string cls, name, proto;
        std::vector<ApkAnalysis::MethodDef> defs;
        if (ApkAnalysis::splitMethodRef(methodReq.method, cls, name, proto)) defs = analysis->findMethodDefs(cls, name, proto);
        if (defs.empty()) workspace_.log("No bytecode in this APK for " + methodReq.method, "analysis");
        else if (methodReq.view == "graph") showGraph(*analysis, defs.front());
        else if (methodReq.view == "calls") showCallGraph(*analysis, defs.front());
        else selectMethod(*analysis, defs.front(), apk.title, false), showFunction(0);
    }

    // What to browse: one row of views, the list below.
    std::vector<const char*> views = {"Classes", "Strings", "Native", "Resources"};
    if (apks.size() > 1) views.push_back("Compare");
    int view = (int)nav_;
    if (view >= (int)views.size()) view = 0;
    ImGui::PushID("nav");
    if (ui::segmented(views.data(), (int)views.size(), view)) nav_ = (Nav)view;
    ImGui::PopID();
    nav_ = (Nav)view;
    switch (nav_) {
    case Nav::Classes:
        if (analysis) drawClassTree(*analysis, apk);
        break;
    case Nav::Strings:
        if (analysis) drawStrings(*analysis, apk);
        break;
    case Nav::Native: drawNative(apk); break;
    case Nav::Resources: drawResources(apk); break;
    case Nav::Compare: drawCompare(apk); break;
    }
}

void AnalysisPanel::showQuery() {
    refsQuery_ = true;
    if (showPanel_) showPanel_("References");
}

void AnalysisPanel::showFunction(int mode) {
    functionMode_ = mode;
    if (showPanel_) showPanel_("Function");
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

void AnalysisPanel::buildPackageTree(const ApkAnalysis& a) {
    packages_.assign(1, PackageNode{});
    std::unordered_map<std::string, uint32_t> byPath;
    const auto& classes = a.classes();
    for (uint32_t i = 0; i < (uint32_t)classes.size(); ++i) {
        const std::string name = DexFile::descriptorToJava(a.classDescriptor(classes[i]));
        uint32_t node = 0;
        size_t start = 0;
        for (size_t dot = name.find('.'); dot != std::string::npos; dot = name.find('.', start)) {
            const std::string path = name.substr(0, dot);
            auto it = byPath.find(path);
            if (it == byPath.end()) {
                const uint32_t child = (uint32_t)packages_.size();
                packages_.push_back(PackageNode{name.substr(start, dot - start), {}, {}});
                packages_[node].packages.push_back(child);
                it = byPath.emplace(path, child).first;
            }
            node = it->second;
            start = dot + 1;
        }
        packages_[node].classes.push_back(i);
    }
    const auto simple = [&](uint32_t c) { return shortName(a.classDescriptor(classes[c])); };
    for (auto& p : packages_) {
        std::sort(p.packages.begin(), p.packages.end(), [&](uint32_t x, uint32_t y) { return packages_[x].name < packages_[y].name; });
        std::sort(p.classes.begin(), p.classes.end(), [&](uint32_t x, uint32_t y) { return simple(x) < simple(y); });
    }
    packageOpen_.assign(packages_.size(), 0);
    rowsDirty_ = true;
}

const std::vector<ApkAnalysis::MethodDef>& AnalysisPanel::methodsOfClass(const ApkAnalysis& a, uint32_t cls) {
    auto it = classMethods_.find(cls);
    if (it == classMethods_.end()) it = classMethods_.emplace(cls, a.methodsOf(a.classes()[cls])).first;
    return it->second;
}

void AnalysisPanel::flattenTree(const ApkAnalysis& a) {
    rowsDirty_ = false;
    rows_.clear();
    const auto& classes = a.classes();
    const auto addMethods = [&](uint32_t cls, uint8_t depth) {
        const auto& methods = methodsOfClass(a, cls);
        const DexFile& dex = *a.dexes()[classes[cls].dex];
        for (uint32_t k = 0; k < (uint32_t)methods.size(); ++k) {
            const uint32_t idx = methods[k].method.methodIdx;
            rows_.push_back({TreeRow::Method, depth, cls, k,
                             prettyMethod(dex.typeDescriptor(dex.methodClass(idx)), dex.methodName(idx),
                                          dex.protoDescriptor(dex.methodProto(idx)))});
        }
    };
    const auto addClass = [&](uint32_t cls, uint8_t depth, bool fullName) {
        const std::string_view desc = a.classDescriptor(classes[cls]);
        rows_.push_back({TreeRow::Class, depth, cls, 0, fullName ? DexFile::descriptorToJava(desc) : shortName(desc)});
        if (classOpen_.count(cls)) addMethods(cls, (uint8_t)(depth + 1));
    };
    std::string needle = classFilter_;
    if (!needle.empty()) {  // filtered: a flat list of matching classes
        std::replace(needle.begin(), needle.end(), '.', '/');
        for (uint32_t i = 0; i < (uint32_t)classes.size() && rows_.size() < 20000; ++i)
            if (tex::ciFind(a.classDescriptor(classes[i]), needle) != std::string_view::npos) addClass(i, 0, true);
        return;
    }
    // Packages with a single sub-package and no classes collapse into one row.
    std::vector<std::pair<uint32_t, uint8_t>> stack;
    const auto& root = packages_[0];
    for (auto it = root.classes.rbegin(); it != root.classes.rend(); ++it) stack.push_back({*it | 0x80000000u, 0});
    for (auto it = root.packages.rbegin(); it != root.packages.rend(); ++it) stack.push_back({*it, 0});
    while (!stack.empty()) {
        const auto [item, depth] = stack.back();
        stack.pop_back();
        if (item & 0x80000000u) {
            addClass(item & 0x7FFFFFFFu, depth, false);
            continue;
        }
        uint32_t node = item;
        std::string label = packages_[node].name;
        while (packages_[node].packages.size() == 1 && packages_[node].classes.empty()) {
            node = packages_[node].packages[0];
            label += "." + packages_[node].name;
        }
        rows_.push_back({TreeRow::Package, depth, node, 0, std::move(label)});
        if (!packageOpen_[node]) continue;
        const auto& p = packages_[node];
        for (auto it = p.classes.rbegin(); it != p.classes.rend(); ++it) stack.push_back({*it | 0x80000000u, (uint8_t)(depth + 1)});
        for (auto it = p.packages.rbegin(); it != p.packages.rend(); ++it) stack.push_back({*it, (uint8_t)(depth + 1)});
    }
}

void AnalysisPanel::drawClassTree(const ApkAnalysis& a, Root& apk) {
    if (packages_.empty()) buildPackageTree(a);
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##classFilter", "Find class (name or package)...", classFilter_, sizeof classFilter_);
    if (appliedFilter_ != classFilter_) {
        appliedFilter_ = classFilter_;
        rowsDirty_ = true;
    }
    if (rowsDirty_) flattenTree(a);
    const auto& classes = a.classes();
    const float h = ImGui::GetTextLineHeight();
    const float indent = h * 0.95f;
    ImGui::BeginChild("##tree", ImVec2(0, 0), ImGuiChildFlags_None);
    if (scrollToSelection_) {
        scrollToSelection_ = false;
        for (size_t i = 0; i < rows_.size(); ++i)
            if ((sel_ == Selection::Class && rows_[i].kind == TreeRow::Class && rows_[i].index == selClass_) ||
                (sel_ == Selection::Method && rows_[i].kind == TreeRow::Method && rows_[i].index == selClass_ &&
                 methodsOfClass(a, selClass_)[rows_[i].method].method.methodIdx == selMethod_.method.methodIdx)) {
                ImGui::SetScrollY(std::max(0.f, (float)i * ImGui::GetTextLineHeightWithSpacing() - ImGui::GetWindowHeight() * 0.3f));
                break;
            }
    }
    bool toggled = false;
    ImGuiListClipper clipper;
    clipper.Begin((int)rows_.size());
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const TreeRow& row = rows_[(size_t)r];
            ImGui::PushID(r);
            const float x0 = ImGui::GetCursorPosX() + (float)row.depth * indent;
            bool selected = false;
            if (row.kind == TreeRow::Class) selected = sel_ == Selection::Class && selClass_ == row.index;
            if (row.kind == TreeRow::Method)
                selected = sel_ == Selection::Method && selClass_ == row.index &&
                           methodsOfClass(a, row.index)[row.method].method.methodIdx == selMethod_.method.methodIdx &&
                           methodsOfClass(a, row.index)[row.method].dex == selMethod_.dex;
            const ImVec2 rowMin = ImGui::GetCursorScreenPos();
            const bool clicked = ImGui::Selectable("##row", selected, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap);
            const bool hovered = ImGui::IsItemHovered();
            const bool doubleClick = clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            const bool onArrow = hovered && ImGui::GetIO().MousePos.x < rowMin.x + (float)row.depth * indent + h;
            ImGui::SameLine(x0);
            // Expand arrow (packages and classes).
            if (row.kind != TreeRow::Method) {
                const bool open = row.kind == TreeRow::Package ? packageOpen_[row.index] != 0 : classOpen_.count(row.index) > 0;
                const ImVec2 p = ImGui::GetCursorScreenPos();
                ImGui::RenderArrow(ImGui::GetWindowDrawList(), ImVec2(p.x, p.y + h * 0.1f), ImGui::GetColorU32(ImGuiCol_TextDisabled),
                                   open ? ImGuiDir_Down : ImGuiDir_Right, 0.7f);
            }
            ImGui::Dummy(ImVec2(h * 0.85f, h));
            ImGui::SameLine(0.f, 0.f);
            if (row.kind == TreeRow::Package) {
                folderIcon();
                ImGui::TextUnformatted(row.label.c_str());
                if (clicked) {
                    packageOpen_[row.index] = !packageOpen_[row.index];
                    toggled = true;
                }
            } else if (row.kind == TreeRow::Class) {
                const uint32_t flags = a.classDef(classes[row.index]).accessFlags;
                if (flags & 0x4000) badge('E', IM_COL32(200, 130, 40, 255));
                else if (flags & 0x0200) badge('I', IM_COL32(70, 160, 90, 255));
                else badge('C', IM_COL32(50, 120, 200, 255));
                ImGui::TextUnformatted(row.label.c_str());
                if (clicked) {
                    if (onArrow || doubleClick) {
                        if (!classOpen_.erase(row.index)) classOpen_.insert(row.index);
                        toggled = true;
                    }
                    if (!onArrow) selectClass(a, row.index, apk.title, doubleClick);
                }
            } else {
                const ApkAnalysis::MethodDef& m = methodsOfClass(a, row.index)[row.method];
                const bool isStatic = (m.method.accessFlags & 0x0008) != 0;
                badge('m', isStatic ? IM_COL32(150, 90, 170, 255) : IM_COL32(180, 80, 140, 255));
                if (m.method.accessFlags & 0x0002) ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                ImGui::TextUnformatted(row.label.c_str());
                if (m.method.accessFlags & 0x0002) ImGui::PopStyleColor();
                if (clicked) selectMethod(a, m, apk.title, true, doubleClick);
                if (hovered && !ImGui::GetIO().WantTextInput) {
                    if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) showGraph(a, m);
                    if (ImGui::IsKeyPressed(ImGuiKey_X, false)) {
                        selectMethod(a, m, apk.title, false);
                        refsQuery_ = false;
                        if (showPanel_) showPanel_("References");
                    }
                }
            }
            // Context menus: the row's other actions.
            if (row.kind == TreeRow::Class && ImGui::BeginPopupContextItem("##cls")) {
                const auto& c = classes[row.index];
                const std::string name = DexFile::descriptorToJava(a.classDescriptor(c));
                if (ImGui::MenuItem("Open decompiled source")) {
                    if (!workspace_.openClassSource(apk.title, name, Workspace::OpenMode::Permanent))
                        workspace_.log("No decompiled source for " + name, "analysis");
                }
                if (ImGui::MenuItem("Open smali")) openClass(a, c, apk.title);
                ImGui::Separator();
                if (ImGui::MenuItem("Find type references")) {
                    xrefs_.clear();
                    xrefTitle_ = "References to " + name;
                    for (const auto& hit : a.typeUses(name, 2000))
                        xrefs_.push_back({a.methodSignature(hit.from), "type use", true, hit.from, {}});
                    showQuery();
                }
                if (ImGui::MenuItem("Subclasses / implementers")) {
                    xrefs_.clear();
                    xrefTitle_ = "Hierarchy of " + name;
                    for (const auto& s : a.superChain(name)) xrefs_.push_back({s, "super chain", false, {}, {}});
                    for (const auto& s : a.subclassesOf(name, 2000)) xrefs_.push_back({s, "subclass", false, {}, {}});
                    for (const auto& s : a.implementersOf(name, 2000)) xrefs_.push_back({s, "implements", false, {}, {}});
                    showQuery();
                }
                if (ImGui::MenuItem("Copy name")) ImGui::SetClipboardText(name.c_str());
                ImGui::EndPopup();
            }
            if (row.kind == TreeRow::Method && ImGui::BeginPopupContextItem("##method")) {
                const ApkAnalysis::MethodDef m = methodsOfClass(a, row.index)[row.method];
                if (ImGui::MenuItem("Smali listing")) selectMethod(a, m, apk.title, false), showFunction(0);
                if (ImGui::MenuItem("Control-flow graph", "Space")) showGraph(a, m);
                if (ImGui::MenuItem("Call graph")) showCallGraph(a, m);
                ImGui::Separator();
                if (ImGui::MenuItem("Callers and callees", "X")) {
                    selectMethod(a, m, apk.title, false);
                    refsQuery_ = false;
                    if (showPanel_) showPanel_("References");
                }
                if (ImGui::MenuItem("Open smali in editor")) openMethod(a, m, apk.title);
                if (ImGui::MenuItem("Copy signature")) ImGui::SetClipboardText(a.methodSignature(m).c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    if (toggled) rowsDirty_ = true;
}

// A class: its Java (or smali without jadx output) opens in the editor.
void AnalysisPanel::selectClass(const ApkAnalysis& a, uint32_t cls, const std::string& group, bool keep) {
    sel_ = Selection::Class;
    selClass_ = cls;
    refsQuery_ = false;
    const auto& c = a.classes()[cls];
    const std::string name = DexFile::descriptorToJava(a.classDescriptor(c));
    const auto mode = keep ? Workspace::OpenMode::Permanent : Workspace::OpenMode::Preview;
    if (!workspace_.openClassSource(group, name, mode)) openClass(a, c, group);
    if (showPanel_) showPanel_("Editor");
}

// A method: the Function and References panels follow it; the Java opens at
// the method when jadx output exists.
void AnalysisPanel::selectMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group,
                                 bool openSource, bool keep) {
    const DexFile& dex = *a.dexes()[m.dex];
    const uint32_t idx = m.method.methodIdx;
    const std::string cls(dex.typeDescriptor(dex.methodClass(idx)));
    sel_ = Selection::Method;
    selMethod_ = m;
    selClass_ = UINT32_MAX;
    if (const auto* entry = a.findClass(DexFile::descriptorToJava(cls))) {
        for (uint32_t i = 0; i < (uint32_t)a.classes().size(); ++i)
            if (a.classes()[i].dex == entry->dex && a.classes()[i].def == entry->def) {
                selClass_ = i;
                break;
            }
    }
    refsQuery_ = false;
    selCallers_ = a.callersOf(cls, dex.methodName(idx), dex.protoDescriptor(dex.methodProto(idx)), 2000);
    selCallees_ = a.calleesOf(m);
    graphValid_ = false;

    // Smali of the method, line by line with each instruction's pc.
    methodListing_.clear();
    std::string listing;
    std::vector<int32_t> pcs;
    dalvik::ListingOptions opt;
    dalvik::disassembleMethod(dex, m.method, opt, listing, &pcs);
    size_t start = 0, li = 0;
    for (size_t i = 0; i <= listing.size(); ++i)
        if (i == listing.size() || listing[i] == '\n') {
            methodListing_.push_back({listing.substr(start, i - start), li < pcs.size() ? pcs[li] : -1});
            ++li;
            start = i + 1;
        }
    listingPc_ = -1;

    if (!openSource) return;
    const std::string javaClass = DexFile::descriptorToJava(cls);
    const auto mode = keep ? Workspace::OpenMode::Permanent : Workspace::OpenMode::Preview;
    if (Document* doc = workspace_.openClassSource(group, javaClass, mode)) {
        // Jump to the declaration: the first line naming the method with a parameter list.
        std::string name(dex.methodName(idx));
        if (name == "<init>" || name == "<clinit>") name = shortName(cls);
        const auto& lines = doc->lines();
        for (size_t i = 0; i < lines.size(); ++i) {
            const std::string_view l = lines[i];
            const size_t at = l.find(name + "(");
            if (at == std::string_view::npos || l.find(';') < at || l.find("=") < at) continue;
            if (at > 0 && (std::isalnum((unsigned char)l[at - 1]) || l[at - 1] == '_' || l[at - 1] == '.')) continue;
            doc->goTo((int)i);
            break;
        }
        if (showPanel_) showPanel_("Editor");
    } else {
        showFunction(0);  // no Java: the smali listing is the code
    }
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
    showQuery();
}

void AnalysisPanel::showCallees(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    xrefs_.clear();
    xrefTitle_ = "Calls made by " + a.methodSignature(m);
    for (const auto& c : a.calleesOf(m)) {
        char what[64];
        std::snprintf(what, sizeof what, "%s @%04x", c.opcode.c_str(), c.pc);
        xrefs_.push_back({c.signature, what, true, {m.dex, m.method.methodIdx, c.pc}, c.signature});
    }
    showQuery();
}

// ---------------------------------------------------------------------------
// Xrefs
// ---------------------------------------------------------------------------

void AnalysisPanel::drawQueryResults(const ApkAnalysis& a, Root& apk) {
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
    if (ImGui::SmallButton("<")) refsQuery_ = false;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Back to the callers and callees of the selection");
    ImGui::SameLine();
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
                if (ImGui::Selectable(r.hasRef ? prettyRef(r.from).c_str() : r.from.c_str(), false,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (r.hasRef) {
                        // The method holding the use, at the instruction.
                        const DexFile& dex = *a.dexes()[r.ref.dex];
                        const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(r.ref.method)),
                                                           dex.methodName(r.ref.method), dex.protoDescriptor(dex.methodProto(r.ref.method)));
                        if (!defs.empty()) {
                            selectMethod(a, defs.front(), apk.title, false);
                            refsQuery_ = true;  // stay on the results
                            listingPc_ = (int32_t)r.ref.pc;
                            listingScroll_ = true;
                            showFunction(0);
                        }
                    } else if (const auto* c = a.findClass(r.from)) {
                        openClass(a, *c, apk.title);
                    }
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", r.from.c_str());
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
                // Control characters escaped: protobuf / R8 metadata strings start with NUL
                // and would otherwise show as blank rows.
                std::string shown;
                for (size_t k = 0; k < s.value.size() && shown.size() < 300; ++k) {
                    const unsigned char ch = (unsigned char)s.value[k];
                    if (ch >= 0x20) {
                        shown.push_back((char)ch);
                    } else {
                        char esc[8];
                        std::snprintf(esc, sizeof esc, ch == 0 ? "\\0" : ch == '\n' ? "\\n" : ch == '\t' ? "\\t" : "\\x%02X", ch);
                        shown += esc;
                    }
                }
                if (shown.size() >= 300) shown += "...";
                const bool clicked = ImGui::Selectable("##str", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap);
                ImGui::SameLine(0.f, 0.f);
                ImGui::TextUnformatted(shown.c_str());  // not a label: "##" in a string would hide text
                if (clicked) {
                    xrefs_.clear();
                    xrefTitle_ = "Uses of \"" + (shown.size() > 80 ? shown.substr(0, 80) + "..." : shown) + "\"";  // escaped: one line
                    for (const auto& h : a.stringUses(s.value, false, 5000)) {
                        char pc[32];
                        std::snprintf(pc, sizeof pc, "const-string @%04x", h.from.pc);
                        xrefs_.push_back({a.methodSignature(h.from), pc, true, h.from, {}});
                    }
                    showQuery();
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
    if (sel_ != Selection::Method || selMethod_.dex != m.dex || selMethod_.method.methodIdx != m.method.methodIdx)
        selectMethod(a, m, currentGroup_, false);
    if (showPanel_) showPanel_("Function");
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
    functionMode_ = 1;
}

// The method, what calls it and what it calls. Double-clicking a neighbour recentres.
void AnalysisPanel::showCallGraph(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    constexpr size_t kMaxNeighbours = 40;
    if (sel_ != Selection::Method || selMethod_.dex != m.dex || selMethod_.method.methodIdx != m.method.methodIdx)
        selectMethod(a, m, currentGroup_, false);
    if (showPanel_) showPanel_("Function");
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
    functionMode_ = 2;
}

void AnalysisPanel::drawGraph(const ApkAnalysis& a, Root& apk) {
    if (!graphValid_) {
        ImGui::TextDisabled("Press CFG or Calls on a method (Classes tab) to show its graph.");
        return;
    }
    // The method is named in the Function header above.
    if (!graphIsCalls_) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Copy DOT")) ImGui::SetClipboardText(a.cfgToDot(graphMethod_, graphBlocks_).c_str());
    }
    const GraphView::Result r = graph_.draw("##graph", Theme::monoFont());
    if (!r.activated || r.block < 0) return;
    if (!graphIsCalls_) {
        if (r.block < (int)graphBlocks_.size()) {  // the block's code in the listing
            functionMode_ = 0;
            listingPc_ = (int32_t)graphBlocks_[(size_t)r.block].startPc;
            listingScroll_ = true;
        }
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
// Function and References panels
// ---------------------------------------------------------------------------

void AnalysisPanel::drawFunctionView() {
    if (sel_ == Selection::Native && native_) {
        drawNativeListing(*native_);
        nativeComment_.draw(workspace_.annotations());
        return;
    }
    auto analysis = current_.lock();
    Root* apk = workspace_.rootByGroup(currentGroup_, Root::Kind::Apk);
    if (sel_ != Selection::Method || !analysis || !apk) {
        ImGui::TextDisabled("Select a method in Classes, or a function in Native.");
        return;
    }
    drawMethodView(*analysis, *apk);
}

void AnalysisPanel::drawMethodView(const ApkAnalysis& a, Root& apk) {
    ui::wrappedColored(kAccent, prettyRef(a.methodSignature(selMethod_)));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", a.methodSignature(selMethod_).c_str());
    static const char* const kModes[] = {"Smali", "Graph", "Calls"};
    int mode = functionMode_;
    ImGui::PushID("fmode");
    if (ui::segmented(kModes, 3, mode)) functionMode_ = mode;
    ImGui::PopID();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput &&
        ImGui::IsKeyPressed(ImGuiKey_Space, false))
        functionMode_ = functionMode_ == 0 ? 1 : 0;
    if (functionMode_ != 0) {
        if (functionMode_ == 2) ImGui::SameLine(), ImGui::TextDisabled("callers left, callees right");
        // Build the graph the mode asks for when it is not the one on screen.
        const bool same = graphValid_ && graphMethod_.dex == selMethod_.dex &&
                          graphMethod_.method.methodIdx == selMethod_.method.methodIdx && graphIsCalls_ == (functionMode_ == 2);
        if (!same) {
            const int keep = functionMode_;
            if (keep == 1) showGraph(a, selMethod_);
            else showCallGraph(a, selMethod_);
            functionMode_ = keep;
        }
        drawGraph(a, apk);
        return;
    }
    drawMethodListing(a, apk);
}

void AnalysisPanel::drawMethodListing(const ApkAnalysis& a, Root& apk) {
    ImGui::PushFont(Theme::monoFont());
    ImGui::BeginChild("##smali", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    const float lh = ImGui::GetTextLineHeightWithSpacing();
    if (listingScroll_) {
        listingScroll_ = false;
        for (size_t i = 0; i < methodListing_.size(); ++i)
            if (methodListing_[i].pc == listingPc_) {
                ImGui::SetScrollY(std::max(0.f, (float)i * lh - ImGui::GetWindowHeight() * 0.3f));
                break;
            }
    }
    std::vector<Span> spans;
    ImGuiListClipper clipper;
    clipper.Begin((int)methodListing_.size(), lh);
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ListingLine& l = methodListing_[(size_t)i];
            ImGui::PushID(i);
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            const bool focus = l.pc >= 0 && l.pc == listingPc_;
            if (ImGui::Selectable("##l", focus, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(0, ImGui::GetTextLineHeight()))) {
                listingPc_ = l.pc;
                // Double-click a call: go to the called method when the APK defines it.
                const size_t arrow = l.text.find("->");
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && arrow != std::string::npos) {
                    size_t begin = l.text.rfind(' ', arrow);
                    begin = begin == std::string::npos ? 0 : begin + 1;
                    const std::string ref = l.text.substr(begin);
                    std::string cls, name, proto;
                    if (ApkAnalysis::splitMethodRef(ref, cls, name, proto)) {
                        const auto defs = a.findMethodDefs(cls, name, proto);
                        if (!defs.empty()) selectMethod(a, defs.front(), apk.title, false);
                        else workspace_.log("Not in this APK: " + ref, "analysis");
                    }
                }
            }
            // Smali colouring, drawn over the row.
            bool inBlock = false;
            SyntaxHighlighter::tokenize(l.text, Language::Smali, inBlock, spans);
            float x = pos.x;
            for (const Span& s : spans) {
                const char* b = l.text.data() + s.begin;
                const char* e = l.text.data() + s.end;
                ImGui::GetWindowDrawList()->AddText(ImVec2(x, pos.y), s.color, b, e);
                x += ImGui::CalcTextSize(b, e).x;
            }
            ImGui::PopID();
        }
    ImGui::EndChild();
    ImGui::PopFont();
}

void AnalysisPanel::drawReferences() {
    auto analysis = current_.lock();
    Root* apk = workspace_.rootByGroup(currentGroup_, Root::Kind::Apk);
    if (refsQuery_ && analysis && apk) {
        drawQueryResults(*analysis, *apk);
        return;
    }
    // Two lists side by side: what calls the selection, what it calls.
    const auto twoColumns = [&](const char* left, size_t nLeft, const char* right, size_t nRight,
                                const std::function<void(size_t)>& drawLeft, const std::function<void(size_t)>& drawRight) {
        if (!ImGui::BeginTable("##refs", 2, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY))
            return;
        char l[64], r[64];
        std::snprintf(l, sizeof l, "%s (%zu)", left, nLeft);
        std::snprintf(r, sizeof r, "%s (%zu)", right, nRight);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(l);
        ImGui::TableSetupColumn(r);
        ImGui::TableHeadersRow();
        const size_t rows = std::max(nLeft, nRight);
        ImGuiListClipper clipper;
        clipper.Begin((int)rows);
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableNextColumn();
                if ((size_t)i < nLeft) drawLeft((size_t)i);
                ImGui::TableNextColumn();
                if ((size_t)i < nRight) drawRight((size_t)i);
                ImGui::PopID();
            }
        ImGui::EndTable();
    };
    if (sel_ == Selection::Native && native_) {
        const NativeCode& nc = *native_;
        const NativeCode::Function* f = funcAddr_ != UINT64_MAX ? nc.functionAt(funcAddr_) : nullptr;
        if (!f) return;
        if (nativeCalleesOf_ != f->addr) {
            nativeCalleesOf_ = f->addr;
            nativeCallees_.clear();
            for (const auto& r : nc.refsFrom(*f, 2000))
                if (r.kind == NativeCode::RefKind::Call || r.kind == NativeCode::RefKind::Jump) nativeCallees_.push_back(r);
        }
        twoColumns("Called by", funcCallers_.size(), "Calls", nativeCallees_.size(),
                   [&](size_t i) {
                       const auto& r = funcCallers_[i];
                       const std::string from = nc.symbolize(r.from);
                       if (ImGui::Selectable((from.empty() ? hexAddr(r.from) : from).c_str(), false, ImGuiSelectableFlags_None)) gotoNative(r.from);
                   },
                   [&](size_t i) {
                       const auto& r = nativeCallees_[i];
                       const NativeCode::Function* to = nc.functionAt(r.target);
                       const std::string name = to ? NativeCode::displayName(*to) : hexAddr(r.target);
                       ImGui::PushID("callee");
                       if (ImGui::Selectable(name.c_str()) && to) gotoNative(to->addr);
                       ImGui::PopID();
                   });
        return;
    }
    if (sel_ != Selection::Method || !analysis || !apk) {
        ImGui::TextDisabled("Select a method to see what calls it and what it calls.");
        return;
    }
    const ApkAnalysis& a = *analysis;
    twoColumns("Called by", selCallers_.size(), "Calls", selCallees_.size(),
               [&](size_t i) {
                   const auto& h = selCallers_[i];
                   const std::string sig = a.methodSignature(h.from);
                   if (ImGui::Selectable(prettyRef(sig).c_str())) {
                       const DexFile& dex = *a.dexes()[h.from.dex];
                       const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(h.from.method)), dex.methodName(h.from.method),
                                                          dex.protoDescriptor(dex.methodProto(h.from.method)));
                       if (!defs.empty()) {
                           selectMethod(a, defs.front(), apk->title, true);
                           listingPc_ = (int32_t)h.from.pc;
                           listingScroll_ = true;
                       }
                   }
                   if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\ncall at %04x", sig.c_str(), h.from.pc);
               },
               [&](size_t i) {
                   const auto& c = selCallees_[i];
                   const std::string label = prettyRef(c.signature);
                   ImGui::PushID("callee");
                   std::string cls, name, proto;
                   std::vector<ApkAnalysis::MethodDef> defs;
                   if (ApkAnalysis::splitMethodRef(c.signature, cls, name, proto)) defs = a.findMethodDefs(cls, name, proto);
                   if (defs.empty()) ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                   if (ImGui::Selectable(label.c_str())) {
                       if (!defs.empty()) selectMethod(a, defs.front(), apk->title, true);
                       else {
                           listingPc_ = (int32_t)c.pc;  // framework method: show the call site
                           listingScroll_ = true;
                           showFunction(0);
                       }
                   }
                   if (defs.empty()) ImGui::PopStyleColor();
                   if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s at %04x%s", c.signature.c_str(), c.opcode.c_str(), c.pc,
                                                                 defs.empty() ? "\n(not in this APK)" : "");
                   ImGui::PopID();
               });
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
    const bool compactLibs = true;  // the navigator is narrow: a dropdown
    const bool sideBySide = false;
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
    ImGui::BeginChild("##elf", ImVec2(0, 0));
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
        ImGui::PushID("views");
        if (ui::segmented(kViews, 4, view)) symbolView_ = view == 0 ? 5 : view == 1 ? 6 : view == 2 ? 0 : 3;
        ImGui::PopID();
        ImGui::PushID("parts");  // "Sections" is a label in both rows
        if (view == 2) {
            static const char* const kSymbols[] = {"JNI", "Exports", "Imports"};
            ui::segmented(kSymbols, 3, symbolView_);  // own row: the navigator is narrow
        } else if (view == 3) {
            static const char* const kParts[] = {"Sections", "Segments"};
            int part = symbolView_ - 3;
            if (ui::segmented(kParts, 2, part)) symbolView_ = 3 + part;
        }
        ImGui::PopID();
        if (symbolView_ <= 4) {
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
                        showQuery();
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
