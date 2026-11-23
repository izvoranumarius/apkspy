#include "ui/AnalysisPanel.hpp"
#include "app/Icons.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <set>
#include "analysis/Dalvik.hpp"
#include "app/Theme.hpp"
#include "core/ApkInfo.hpp"
#include "edit/Edits.hpp"
#include "core/TextUtils.hpp"
#include "document/SyntaxHighlighter.hpp"
#include "ui/AbiUi.hpp"
#include "ui/UiUtil.hpp"

namespace {

ImVec4 kDim() { return theme::vec(Col::TextMuted); }
ImVec4 kAccent() { return theme::vec(Col::Info); }
ImVec4 kWarn() { return theme::vec(Col::Warning); }

template <typename T>
bool ready(std::future<T>& f) {
    return f.valid() && f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::string hexAddr(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string shortName(std::string_view descriptor) {
    std::string const j = DexFile::descriptorToJava(descriptor);
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

void AnalysisPanel::resetCaches(bool keepNative) {
    appliedFilter_ = "\x01";  // force a refilter
    packages_.clear();
    packageOpen_.clear();
    classOpen_.clear();
    classMethods_.clear();
    rows_.clear();
    rowsDirty_ = true;
    if (!(keepNative && sel_ == Selection::Native)) sel_ = Selection::None;
    selClass_ = UINT32_MAX;
    selCallers_.clear();
    selCallees_.clear();
    methodListing_.clear();
    listingSel_.reset();
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
        ui::emptyState("No APK open", "Add an APK to the project to browse its classes, strings, native code and resources.");
        return;
    }
    if (apkIdx_ >= static_cast<int>(apks.size())) apkIdx_ = 0;
    Workspace::NativeViewRequest nativeReq;
    if (workspace_.takeNativeView(nativeReq)) {
        for (int i = 0; i < static_cast<int>(apks.size()); ++i)
            if (apks[static_cast<size_t>(i)]->title == nativeReq.group && i != apkIdx_) {
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
        for (int i = 0; i < static_cast<int>(apks.size()); ++i)
            if (apks[static_cast<size_t>(i)]->title == methodReq.group && i != apkIdx_) {
                apkIdx_ = i;
                resetCaches();
            }
    if (apks.size() > 1) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::BeginCombo("##apk", apks[static_cast<size_t>(apkIdx_)]->title.c_str())) {
            for (int i = 0; i < static_cast<int>(apks.size()); ++i)
                if (ImGui::Selectable(apks[static_cast<size_t>(i)]->title.c_str(), i == apkIdx_) && i != apkIdx_) {
                    apkIdx_ = i;
                    resetCaches();
                }
            ImGui::EndCombo();
        }
    }
    Root& apk = *apks[static_cast<size_t>(apkIdx_)];
    // Opening the workspace is the request: everything here needs the result.
    if (workspace_.analysis().status(apk.title).state == AnalysisService::State::None) workspace_.startAnalysis(apk.title);
    const AnalysisService::Status st = workspace_.analysis().status(apk.title);
    drawHeader(apk, st);

    std::shared_ptr<const ApkAnalysis> const analysis = workspace_.analysis().get(apk.title);
    if (analysis.get() != cacheOwner_) {
        cacheOwner_ = analysis.get();
        // The bytecode analysis finished or was replaced: a native function on screen does not depend on it.
        resetCaches(true);
    }
    current_ = analysis;
    currentGroup_ = apk.title;
    if (analysis) syncFromEditor(*analysis);
    if (methodRequested && analysis && methodReq.view == "class") {
        // A class (descriptor or Java name): its source in the Editor.
        const ApkAnalysis::ClassEntry* entry = analysis->findClass(methodReq.method);
        uint32_t index = UINT32_MAX;
        if (entry)
            for (uint32_t i = 0; i < static_cast<uint32_t>(analysis->classes().size()); ++i)
                if (analysis->classes()[i].dex == entry->dex && analysis->classes()[i].def == entry->def) index = i;
        if (index == UINT32_MAX) workspace_.log("No bytecode in this APK for " + methodReq.method, "analysis");
        else selectClass(*analysis, index, apk.title, false);
    } else if (methodRequested && analysis) {
        std::string cls, name, proto;
        std::vector<ApkAnalysis::MethodDef> defs;
        if (ApkAnalysis::splitMethodRef(methodReq.method, cls, name, proto)) defs = analysis->findMethodDefs(cls, name, proto);
        if (defs.empty()) workspace_.log("No bytecode in this APK for " + methodReq.method, "analysis");
        else if (methodReq.view == "graph") showGraph(*analysis, defs.front());
        else if (methodReq.view == "calls") showCallGraph(*analysis, defs.front());
        // "source": open the code (Java, or the smali listing) without bringing the Function panel forward.
        else if (methodReq.view == "source") selectMethod(*analysis, defs.front(), apk.title, true, false, false);
        else selectMethod(*analysis, defs.front(), apk.title, false), showFunction(0);
    }

    // What to browse: one row of views, the list below.
    std::vector<const char*> views = {"Classes", "Strings", "Native", "Resources"};
    if (apks.size() > 1) views.push_back("Compare");
    int view = static_cast<int>(nav_);
    if (view >= static_cast<int>(views.size())) view = 0;
    ImGui::PushID("nav");
    if (ui::segmented(views.data(), static_cast<int>(views.size()), view)) nav_ = static_cast<Nav>(view);
    ImGui::PopID();
    nav_ = static_cast<Nav>(view);
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
    present("Function");
}

void AnalysisPanel::drawHeader(Root& apk, const AnalysisService::Status& st) {
    switch (st.state) {
    case AnalysisService::State::None:
    case AnalysisService::State::Cancelled:
    case AnalysisService::State::Failed:
        if (ui::flowButton("Analyze again")) workspace_.startAnalysis(apk.title, true);
        if (st.state == AnalysisService::State::Failed)
            ui::wrappedColored(kWarn(), "failed: " + st.error);
        else if (st.state == AnalysisService::State::Cancelled)
            ui::flowTextDisabled("cancelled");
        break;
    case AnalysisService::State::Running: {
        const float frac = st.total ? static_cast<float>(st.done) / static_cast<float>(st.total) : 0.f;
        char overlay[96];
        std::snprintf(overlay, sizeof overlay, "%s %zu / %zu", st.phase.c_str(), st.done, st.total);
        ImGui::ProgressBar(st.total ? frac : -1.f * static_cast<float>(ImGui::GetTime()),
                           ImVec2(std::min(ui::em(16.f), ImGui::GetContentRegionAvail().x), 0), overlay);
        if (ui::flowButton("Cancel")) workspace_.analysis().cancel(apk.title);
        break;
    }
    case AnalysisService::State::Ready: {
        if (!st.error.empty()) ui::wrappedColored(kWarn(), st.error);
        break;
    }
    }
}

// ---------------------------------------------------------------------------
// Classes / methods
// ---------------------------------------------------------------------------

static const char* const kDefaultHideLibs =
    "android.\nandroidx.\nkotlin.\nkotlinx.\ncom.google.\ncom.android.\njava.\njavax.\nokhttp3.\nokio.\nretrofit2.\n"
    "io.reactivex.\ndagger.\ncom.squareup.\ncom.facebook.\ncom.bumptech.\n";

void AnalysisPanel::setSettings(Settings* settings) {
    settings_ = settings;
    excludesLoaded_ = false;
}

void AnalysisPanel::loadExcludes() {
    excludesLoaded_ = true;
    std::string list = kDefaultHideLibs;
    if (settings_) {
        hideLibs_ = settings_->getBool(Settings::kHideLibs, false);
        const std::string saved = settings_->getString(Settings::kHideLibsList, "");
        if (!saved.empty()) {
            list.clear();
            for (char ch : saved) list += ch == '|' ? '\n' : ch;  // stored on one line
        }
    }
    std::snprintf(excludeBuf_, sizeof excludeBuf_, "%s", list.c_str());
    saveExcludes();
}

void AnalysisPanel::saveExcludes() {
    excluded_.clear();
    std::string line, joined;
    const std::string buf = excludeBuf_;
    for (size_t i = 0; i <= buf.size(); ++i) {
        if (i == buf.size() || buf[i] == '\n' || buf[i] == '\r') {
            size_t a = line.find_first_not_of(" \t"), b = line.find_last_not_of(" \t");
            if (a != std::string::npos) {
                const std::string p = line.substr(a, b - a + 1);
                excluded_.push_back(p);
                joined += (joined.empty() ? "" : "|") + p;
            }
            line.clear();
        } else {
            line += buf[i];
        }
    }
    if (settings_) {
        settings_->set(Settings::kHideLibs, hideLibs_);
        settings_->set(Settings::kHideLibsList, joined);
    }
}

bool AnalysisPanel::isExcluded(std::string_view javaName) const {
    if (!hideLibs_) return false;
    for (const std::string& p : excluded_)
        if (javaName.substr(0, p.size()) == p) return true;
    return false;
}

void AnalysisPanel::buildPackageTree(const ApkAnalysis& a) {
    packages_.assign(1, PackageNode{});
    std::unordered_map<std::string, uint32_t> byPath;
    const auto& classes = a.classes();
    for (uint32_t i = 0; i < static_cast<uint32_t>(classes.size()); ++i) {
        const std::string name = DexFile::descriptorToJava(a.classDescriptor(classes[i]));
        if (isExcluded(name)) continue;
        uint32_t node = 0;
        size_t start = 0;
        for (size_t dot = name.find('.'); dot != std::string::npos; dot = name.find('.', start)) {
            const std::string path = name.substr(0, dot);
            auto it = byPath.find(path);
            if (it == byPath.end()) {
                const uint32_t child = static_cast<uint32_t>(packages_.size());
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
        for (uint32_t k = 0; k < static_cast<uint32_t>(methods.size()); ++k) {
            const uint32_t idx = methods[k].method.methodIdx;
            rows_.push_back({TreeRow::Method, depth, cls, k,
                             prettyMethod(dex.typeDescriptor(dex.methodClass(idx)), dex.methodName(idx),
                                          dex.protoDescriptor(dex.methodProto(idx)))});
        }
    };
    const auto addClass = [&](uint32_t cls, uint8_t depth, bool fullName) {
        const std::string_view desc = a.classDescriptor(classes[cls]);
        std::string label = fullName ? DexFile::descriptorToJava(desc) : shortName(desc);
        if (const mapping::Mapping* map = workspace_.mapping()) {
            // An applied mapping.txt: show the original name next to the obfuscated one.
            const std::string java = DexFile::descriptorToJava(desc);
            const std::string original = map->originalClass(java);
            if (original != java) label += "  -> " + (fullName ? original : original.substr(original.rfind('.') + 1));
        }
        rows_.push_back({TreeRow::Class, depth, cls, 0, std::move(label)});
        if (classOpen_.count(cls)) addMethods(cls, static_cast<uint8_t>(depth + 1));
    };
    std::string needle = classFilter_;
    if (!needle.empty()) {  // filtered: a flat list of matching classes
        std::replace(needle.begin(), needle.end(), '.', '/');
        {
            const mapping::Mapping* map = workspace_.mapping();
            const std::string raw = classFilter_;
            for (uint32_t i = 0; i < static_cast<uint32_t>(classes.size()) && rows_.size() < 20000; ++i) {
                const std::string java = DexFile::descriptorToJava(a.classDescriptor(classes[i]));
                bool match = tex::ciFind(a.classDescriptor(classes[i]), needle) != std::string_view::npos;
                if (!match && map) match = tex::ciFind(map->originalClass(java), raw) != std::string_view::npos;
                if (match && !(hideLibs_ && isExcluded(java))) addClass(i, 0, true);
            }
        }
        return;
    }
    // Packages with a single sub-package and no classes collapse into one row.
    std::vector<std::pair<uint32_t, uint8_t>> stack;
    const auto& root = packages_[0];
    for (auto it = root.classes.rbegin(); it != root.classes.rend(); ++it) stack.push_back({*it | 0x80000000u, uint8_t{0}});
    for (auto it = root.packages.rbegin(); it != root.packages.rend(); ++it) stack.push_back({*it, uint8_t{0}});
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
        for (auto it = p.classes.rbegin(); it != p.classes.rend(); ++it) stack.push_back({*it | 0x80000000u, static_cast<uint8_t>(depth + 1)});
        for (auto it = p.packages.rbegin(); it != p.packages.rend(); ++it) stack.push_back({*it, static_cast<uint8_t>(depth + 1)});
    }
}

void AnalysisPanel::drawClassTree(const ApkAnalysis& a, Root& apk) {
    if (!excludesLoaded_) loadExcludes();
    if (mappingSeen_ != workspace_.mappingVersion()) {
        mappingSeen_ = workspace_.mappingVersion();
        rowsDirty_ = true;
    }
    if (packages_.empty()) buildPackageTree(a);
    if (ImGui::Checkbox("Hide libs", &hideLibs_)) {
        saveExcludes();
        buildPackageTree(a);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hide library packages from the class tree (edit the list with the ... button)");
    ImGui::SameLine();
    if (ui::smallButton("...##hidelibs")) ImGui::OpenPopup("##hidelibspopup");
    if (ImGui::BeginPopup("##hidelibspopup")) {
        ImGui::TextDisabled("Package prefixes to hide, one per line (e.g. androidx. or com.google.)");
        ui::codeBox("##hidelist", excludeBuf_, sizeof excludeBuf_, ImVec2(ui::em(24.f), ui::em(10.f)));
        if (ImGui::Button("Apply")) {
            saveExcludes();
            buildPackageTree(a);
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::SameLine();
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
                ImGui::SetScrollY(std::max(0.f, static_cast<float>(i) * ImGui::GetTextLineHeightWithSpacing() - ImGui::GetWindowHeight() * 0.3f));
                break;
            }
    }
    bool toggled = false;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows_.size()));
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const TreeRow& row = rows_[static_cast<size_t>(r)];
            ImGui::PushID(r);
            const float x0 = ImGui::GetCursorPosX() + static_cast<float>(row.depth) * indent;
            bool selected = false;
            if (row.kind == TreeRow::Class) selected = sel_ == Selection::Class && selClass_ == row.index;
            if (row.kind == TreeRow::Method)
                selected = sel_ == Selection::Method && selClass_ == row.index &&
                           methodsOfClass(a, row.index)[row.method].method.methodIdx == selMethod_.method.methodIdx &&
                           methodsOfClass(a, row.index)[row.method].dex == selMethod_.dex;
            const ImVec2 rowMin = ImGui::GetCursorScreenPos();
            const bool clicked = ImGui::Selectable("##row", selected, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap);
            const bool hovered = ImGui::IsItemHovered();
            const bool mouseOver = ImGui::IsItemHovered(ImGuiHoveredFlags_NoNavOverride);  // the mouse, not the keyboard cursor
            const bool doubleClick = clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            const bool onArrow = hovered && ImGui::GetIO().MousePos.x < rowMin.x + static_cast<float>(row.depth) * indent + h;
            // Keyboard, as in any tree: Right opens the focused package / class, Left closes it.
            if (row.kind != TreeRow::Method && ImGui::IsItemFocused() && !ImGui::GetIO().WantTextInput) {
                const bool isOpen = row.kind == TreeRow::Package ? packageOpen_[row.index] != 0 : classOpen_.count(row.index) > 0;
                const bool wantOpen = ImGui::IsKeyPressed(ImGuiKey_RightArrow, false), wantClose = ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false);
                if ((wantOpen && !isOpen) || (wantClose && isOpen)) {
                    if (row.kind == TreeRow::Package) packageOpen_[row.index] = !isOpen;
                    else if (isOpen) classOpen_.erase(row.index);
                    else classOpen_.insert(row.index);
                    toggled = true;
                }
            }
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
                    if (!onArrow) {
                        browsing_ = !doubleClick;
                        selectClass(a, row.index, apk.title, doubleClick);
                        browsing_ = false;
                    }
                }
            } else {
                const ApkAnalysis::MethodDef& m = methodsOfClass(a, row.index)[row.method];
                const bool isStatic = (m.method.accessFlags & 0x0008) != 0;
                badge('m', isStatic ? IM_COL32(150, 90, 170, 255) : IM_COL32(180, 80, 140, 255));
                if (m.method.accessFlags & 0x0002) ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                ImGui::TextUnformatted(row.label.c_str());
                if (m.method.accessFlags & 0x0002) ImGui::PopStyleColor();
                if (clicked) {
                    browsing_ = !doubleClick;
                    selectMethod(a, m, apk.title, true, doubleClick);
                    browsing_ = false;
                }
                if (hovered && !ImGui::GetIO().WantTextInput) {
                    // Space over a method shows its graph - with the mouse only: for the
                    // keyboard Space is "activate", which already selected the row.
                    if (mouseOver && ImGui::IsKeyPressed(ImGuiKey_Space, false)) showGraph(a, m);
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
    selClassUses_ = a.typeUses(name, 2000);
    selClassSubs_ = a.subclassesOf(name, 500);
    for (std::string& s : a.implementersOf(name, 500)) selClassSubs_.push_back(std::move(s));
    const auto mode = keep ? Workspace::OpenMode::Permanent : Workspace::OpenMode::Preview;
    if (!workspace_.openClassSource(group, name, mode)) openBuiltInJava(a, c, group);
    present("Function");  // the class view
    present("Editor");    // its Java (or smali) beside it
}

// A method: the Function and References panels follow it; the Java opens at
// the method when jadx output exists.
void AnalysisPanel::selectMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group,
                                 bool openSource, bool keep, bool focusFunction) {
    const DexFile& dex = *a.dexes()[m.dex];
    const uint32_t idx = m.method.methodIdx;
    const std::string cls(dex.typeDescriptor(dex.methodClass(idx)));
    sel_ = Selection::Method;
    selMethod_ = m;
    selClass_ = UINT32_MAX;
    syncPcs_.clear();
    if (const auto* entry = a.findClass(DexFile::descriptorToJava(cls))) {
        for (uint32_t i = 0; i < static_cast<uint32_t>(a.classes().size()); ++i)
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
    listingSel_.reset();
    std::string listing;
    std::vector<int32_t> pcs;
    dalvik::ListingOptions const opt;
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
        // Jump to the declaration: the parsed method with the same parameter types
        // (overloads included); failing that, the first line naming it with a parameter list.
        const int decl = javaFile(*doc)->findMethod(javaClass, dex.methodName(idx),
                                                    sourcemap::paramSimpleTypes(dex.protoDescriptor(dex.methodProto(idx))));
        std::string name(dex.methodName(idx));
        if (name == "<init>" || name == "<clinit>") name = shortName(cls);
        const auto& lines = doc->lines();
        if (decl >= 0) doc->goTo(decl);
        for (size_t i = 0; decl < 0 && i < lines.size(); ++i) {
            const std::string_view l = lines[i];
            const size_t at = l.find(name + "(");
            if (at == std::string_view::npos || l.find(';') < at || l.find('=') < at) continue;
            if (at > 0 && (std::isalnum(static_cast<unsigned char>(l[at - 1])) || l[at - 1] == '_' || l[at - 1] == '.')) continue;
            doc->goTo(static_cast<int>(i));
            break;
        }
        // The listing stays in front: the Decompiler panel shows the method next to it,
        // jadx's Java waits in the Editor tab.
        if (focusFunction) {
            present("Function");
            if (showPanel_) showPanel_("reveal:Editor");  // the Java at the method, beside the listing
        } else {
            present("Editor");
        }
    } else if (focusFunction) {
        // No jadx Java: the smali listing is the code, and the built-in
        // decompiler beside it shows the same method as Java (instead of the
        // class's smali again in the Editor).
        showFunction(0);
        if (showPanel_) showPanel_("reveal:Decompiler");
    } else {
        openMethod(a, m, group);  // the smali listing in the Editor
        if (showPanel_) showPanel_("Editor");
    }
}

// ---------------------------------------------------------------------------
// Java <-> smali synchronisation
// ---------------------------------------------------------------------------

const sourcemap::JavaFile* AnalysisPanel::javaFile(const Document& doc) {
    if (!javaFile_ || javaDoc_ != &doc || javaRevision_ != doc.textRevision() || javaLines_ != doc.lineCount()) {
        std::vector<std::string_view> lines;
        lines.reserve(doc.lineCount());
        for (size_t i = 0; i < doc.lineCount(); ++i) lines.push_back(doc.line(i));
        javaFile_ = std::make_unique<sourcemap::JavaFile>(lines);
        javaDoc_ = &doc;
        javaRevision_ = doc.textRevision();
        javaLines_ = doc.lineCount();
    }
    return javaFile_.get();
}

static bool isJavaSource(const Document& doc) {
    const std::string& t = doc.title();
    return doc.rootKind() == RootKind::Decompiled && t.size() > 5 && t.compare(t.size() - 5, 5, ".java") == 0;
}

void AnalysisPanel::syncFromEditor(const ApkAnalysis& a) {
    const Workspace::EditorCursor& cur = workspace_.editorCursor();
    if (cur.serial == cursorSerial_) return;
    cursorSerial_ = cur.serial;
    if (!syncJava_ || !cur.doc) return;
    // The click may be on a document closed since: only use one that is still open.
    const Document* doc = nullptr;
    for (const auto& d : workspace_.documents())
        if (d.get() == cur.doc) doc = d.get();
    if (!doc || !isJavaSource(*doc) || doc->rootGroup() != currentGroup_) return;
    sourcemap::Target t;
    if (!sourcemap::javaToBytecode(a, *javaFile(*doc), cur.line, t)) return;
    const bool same = sel_ == Selection::Method && selMethod_.dex == t.method.dex && selMethod_.method.methodIdx == t.method.method.methodIdx;
    if (!same) selectMethod(a, t.method, currentGroup_, false);  // the editor stays where the user is
    syncPcs_ = t.pcs;
    syncExact_ = t.exact;
    if (!t.pcs.empty()) {
        listingPc_ = static_cast<int32_t>(t.pcs.front());
        listingScroll_ = true;
    }
}

Document* AnalysisPanel::openJavaFor(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) const {
    const DexFile& dex = *a.dexes()[m.dex];
    std::string rel = DexFile::descriptorToJava(dex.typeDescriptor(dex.methodClass(m.method.methodIdx)));
    rel = rel.substr(0, rel.find('$'));  // inner classes live in the outer class's file
    std::replace(rel.begin(), rel.end(), '.', '/');
    rel = "/" + rel + ".java";
    for (const auto& d : workspace_.documents()) {
        if (!isJavaSource(*d) || d->rootGroup() != currentGroup_ || !d->node()) continue;
        std::string path = d->node()->path();
        std::replace(path.begin(), path.end(), '\\', '/');
        if (path.size() >= rel.size() && path.compare(path.size() - rel.size(), rel.size(), rel) == 0) return d.get();
    }
    return nullptr;
}

void AnalysisPanel::syncToJava(const ApkAnalysis& a, uint32_t pc) {
    if (!syncJava_ || sel_ != Selection::Method) return;
    // Only a Java file already open moves: an instruction click never opens tabs.
    Document* doc = openJavaFor(a, selMethod_);
    if (!doc) return;
    const int line = sourcemap::bytecodeToJava(a, *javaFile(*doc), selMethod_, pc);
    if (line >= 0) doc->goTo(line);
}

void AnalysisPanel::openClass(const ApkAnalysis& a, const ApkAnalysis::ClassEntry& c, const std::string& group) {
    const std::string desc(a.classDescriptor(c));
    workspace_.openGenerated(group, "smali/" + sanitizeForPath(desc) + ".smali", shortName(desc) + ".smali",
                             a.disassembleClass(c, workspace_.listingOptions(group)), 0);
}

void AnalysisPanel::openBuiltInJava(const ApkAnalysis& a, const ApkAnalysis::ClassEntry& c, const std::string& group) {
    const std::string desc(a.classDescriptor(c));
    const std::string java = DexFile::descriptorToJava(desc);
    const DexFile& dex = *a.dexes()[c.dex];
    const DexFile::ClassDef& def = a.classDef(c);
    std::string out = "// Built-in decompiler: jadx output is not available for this APK.\n"
                      "// Set up jadx in File > Settings > JADX for complete Java (inner classes, generics, lambdas).\n";
    if (const size_t dot = java.rfind('.'); dot != std::string::npos) out += "package " + java.substr(0, dot) + ";\n";
    out += "\n";
    // Java modifiers only (no dex-level words like synthetic / bridge / constructor).
    enum class Of { Class, Field, Method };
    const auto javaMods = [](uint32_t f, Of of) {
        std::string m;
        const auto add = [&](uint32_t bit, const char* word) {
            if (f & bit) m += std::string(word) + " ";
        };
        add(0x0001, "public");
        add(0x0002, "private");
        add(0x0004, "protected");
        add(0x0008, "static");
        add(0x0010, "final");
        if (of == Of::Field) {
            add(0x0040, "volatile");
            add(0x0080, "transient");
        }
        if (of == Of::Method) {
            add(0x0020, "synchronized");
            add(0x0100, "native");
        }
        if (!(of == Of::Class && (f & 0x0200))) add(0x0400, "abstract");  // interfaces are abstract anyway
        return m;
    };
    // Declaration.
    const bool isInterface = (def.accessFlags & 0x0200) != 0;
    std::string decl = javaMods(def.accessFlags, Of::Class);
    decl += (def.accessFlags & 0x2000) ? "@interface " : isInterface ? "interface " : (def.accessFlags & 0x4000) ? "enum " : "class ";
    decl += shortName(desc);
    if (def.superclassIdx != DexFile::kNoIndex) {
        const std::string_view super = dex.typeDescriptor(def.superclassIdx);
        if (super != "Ljava/lang/Object;" && super != "Ljava/lang/Enum;") decl += " extends " + prettyType(super);
    }
    const std::vector<uint32_t> ifaces = dex.interfaces(def);
    for (size_t i = 0; i < ifaces.size(); ++i)
        decl += (i ? ", " : isInterface ? " extends " : " implements ") + prettyType(dex.typeDescriptor(ifaces[i]));
    out += decl + " {\n";
    // Fields.
    DexFile::ClassData data;
    dex.classData(def, data);
    for (const DexFile::EncodedField& f : data.fields) {
        out += "    " + javaMods(f.accessFlags, Of::Field) + prettyType(dex.typeDescriptor(dex.fieldType(f.fieldIdx))) + " " +
               std::string(dex.fieldName(f.fieldIdx)) + ";\n";
    }
    // Methods, each as the Decompiler panel shows it.
    for (const ApkAnalysis::MethodDef& m : a.methodsOf(c)) {
        out += "\n";
        const uint32_t idx = m.method.methodIdx;
        if (!m.method.codeOff) {  // abstract / native: the declaration alone, Java order "R name(A)"
            std::string sig = prettyMethod(desc, dex.methodName(idx), dex.protoDescriptor(dex.methodProto(idx)));
            if (const size_t colon = sig.rfind(" : "); colon != std::string::npos) sig = sig.substr(colon + 3) + " " + sig.substr(0, colon);
            out += "    " + javaMods(m.method.accessFlags, Of::Method) + sig + ";\n";
            continue;
        }
        const decompiler::Output d = decompiler::decompileMethod(a, m);
        if (!d.error.empty() || d.lines.empty()) {
            out += "    // " + prettyMethod(desc, dex.methodName(idx), dex.protoDescriptor(dex.methodProto(idx))) + ": " +
                   (d.error.empty() ? std::string("no output") : d.error) + "\n";
            continue;
        }
        for (size_t i = 0; i < d.lines.size(); ++i) {
            const decompiler::Line& l = d.lines[i];
            if (i == 0 && l.text == "// " + java) continue;  // the panel's class banner
            out += std::string(static_cast<size_t>(l.indent + 1) * 4, ' ') + l.text + "\n";
        }
    }
    out += "}\n";
    workspace_.openGenerated(group, "java/" + sanitizeForPath(desc) + ".java", shortName(desc) + ".java", std::move(out), 0);
}

void AnalysisPanel::openMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group,
                               uint32_t pc) {
    workspace_.openMethodListing(group, a, m, pc);
}

void AnalysisPanel::openCodeRef(const ApkAnalysis& a, const ApkAnalysis::CodeRef& r, const std::string& group) {
    const DexFile& dex = *a.dexes()[r.dex];
    const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(r.method)), dex.methodName(r.method),
                                       dex.protoDescriptor(dex.methodProto(r.method)));
    if (!defs.empty()) {
        openMethod(a, defs.front(), group, r.pc);
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
        ImGui::ProgressBar(-1.f * static_cast<float>(ImGui::GetTime()), ImVec2(ui::em(12.f), 0), "scanning methods");
        return;
    }
    if (xrefTitle_.empty()) {
        ImGui::TextDisabled("Use Callers / Callees on a method, a class context menu, or a string to fill this list.");
        return;
    }
    if (ui::smallButton("<")) refsQuery_ = false;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Back to the callers and callees of the selection");
    ImGui::SameLine();
    ImGui::TextColored(kAccent(), "%s", xrefTitle_.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu)", xrefs_.size());
    if (xrefs_.empty() && xrefTitle_.rfind("Uses of \"", 0) == 0) {
        ImGui::TextWrapped("No code loads this string with const-string. It is still in the dex string table "
                           "because something else names it: a class, method or field name, a type descriptor, "
                           "an annotation value, a static field initial value or debug info.");
        return;
    }
    if (ImGui::BeginTable("##xr", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                         ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Location", ImGuiTableColumnFlags_WidthStretch, 4.f);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(xrefs_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const XrefRow& r = xrefs_[static_cast<size_t>(i)];
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
                            listingPc_ = static_cast<int32_t>(r.ref.pc);
                            listingScroll_ = true;
                            showFunction(0);
                        }
                    } else if (const auto* c = a.findClass(r.from)) {
                        openClass(a, *c, apk.title);
                    }
                }
                ui::copyHovered(r.from);
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

void AnalysisPanel::drawStrings(const ApkAnalysis& a, Root& /*apk*/) {
    ImGui::SetNextItemWidth(std::min(ui::em(9.f), ImGui::GetContentRegionAvail().x));
    bool refresh = ImGui::Combo("##cat", &stringCategory_, kCategoryNames, IM_ARRAYSIZE(kCategoryNames));
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-ui::buttonWidth("Search") - ImGui::GetStyle().ItemSpacing.x);
    refresh |= ImGui::InputTextWithHint("##sfilter", "Filter...", stringFilter_, sizeof stringFilter_,
                                        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    refresh |= ImGui::Button("Search");
    refresh |= ui::flowCheckbox("Used by code", &stringsCodeOnly_);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Only strings some code loads (const-string).\nOff: everything in the dex string tables, including\n"
                          "class and member names.");
    refresh |= ui::flowCheckbox("Text only", &stringsReadable_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hide binary data (strings with control characters, such as protobuf schemas)");
    if (refresh || !stringsLoaded_) {
        strings_ = a.strings(stringFilter_, kCategories[stringCategory_], 20000, stringsCodeOnly_, stringsReadable_);
        stringsLoaded_ = true;
    }
    {
        char count[96];
        if (strings_.size() >= 20000) std::snprintf(count, sizeof count, "20000+ strings: filter to narrow. Click one for the code using it.");
        else std::snprintf(count, sizeof count, "%zu strings. Click one for the code using it.", strings_.size());
        ui::wrappedColored(theme::vec(Col::TextMuted), count);
    }
    if (ImGui::BeginTable("##st", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 5.f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(strings_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& s = strings_[static_cast<size_t>(i)];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                // Control characters escaped: protobuf / R8 metadata strings start with NUL
                // and would otherwise show as blank rows.
                std::string shown;
                for (size_t k = 0; k < s.value.size() && shown.size() < 300; ++k) {
                    const unsigned char ch = static_cast<unsigned char>(s.value[k]);
                    if (ch >= 0x20) {
                        shown.push_back(static_cast<char>(ch));
                    } else {
                        char esc[8];
                        std::snprintf(esc, sizeof esc, ch == 0 ? "\\0" : ch == '\n' ? "\\n" : ch == '\t' ? "\\t" : "\\x%02X", ch);
                        shown += esc;
                    }
                }
                if (shown.size() >= 300) shown += "...";
                const bool clicked = ImGui::Selectable("##str", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap);
                ui::copyHovered(s.value);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) ui::encodedStringTooltip(s.value);
                ImGui::SameLine(0.f, 0.f);
                ImGui::TextUnformatted(shown.c_str());  // not a label: "##" in a string would hide text
                if (clicked) {
                    xrefs_.clear();
                    xrefTitle_ = "Uses of \"" + (shown.size() > 80 ? shown.substr(0, 80) + "..." : shown) + "\"";  // escaped: one line
                    // URL rows hold a token cut out of a longer constant: find the constants containing it.
                    const bool isUrlToken = kCategories[stringCategory_] == ApkAnalysis::StringCategory::Url;
                    for (const auto& h : a.stringUses(s.value, isUrlToken, 5000)) {
                        char pc[32];
                        std::snprintf(pc, sizeof pc, "const-string @%04x", h.from.pc);
                        xrefs_.push_back({a.methodSignature(h.from), pc, true, h.from, {}});
                    }
                    showQuery();
                }
                if (ImGui::BeginPopupContextItem("##sctx")) {
                    if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(s.value.c_str());
                    if (ImGui::MenuItem("Send to Decoder")) workspace_.sendToDecoder(s.value);
                    ImGui::EndPopup();
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", ApkAnalysis::categoryName(s.category));
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
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
                std::string const l = listing.substr(start, i - start);
                const size_t first = l.find_first_not_of(' ');
                lines.emplace_back(pcs[li], first == std::string::npos ? l : l.substr(first));
            }
            ++li;
            start = i + 1;
        }

    std::vector<GraphView::Block> blocks(graphBlocks_.size());
    std::vector<graphlayout::Edge> edges;
    for (uint32_t b = 0; b < static_cast<uint32_t>(graphBlocks_.size()); ++b) {
        const auto& block = graphBlocks_[b];
        for (const auto& l : lines)
            if (l.first >= static_cast<int32_t>(block.startPc) && l.first < static_cast<int32_t>(block.endPc)) {
                std::string text = l.second.size() > 90 ? l.second.substr(0, 90) + "..." : l.second;
                Col color = Col::Text;
                if (text.rfind("invoke", 0) == 0) color = Col::Blue;
                else if (text.rfind("if-", 0) == 0 || text.rfind("goto", 0) == 0 || text.rfind("packed-", 0) == 0 || text.rfind("sparse-", 0) == 0)
                    color = Col::Yellow;
                else if (text.rfind("return", 0) == 0 || text.rfind("throw", 0) == 0) color = Col::Red;
                blocks[b].lines.push_back({{std::move(text), color}});
            }
        if (block.exit) blocks[b].border = Col::Red;
        const bool branch = block.successors.size() == 2;
        for (size_t k = 0; k < block.successors.size(); ++k) {
            graphlayout::Edge e;
            e.from = static_cast<int>(b);
            e.to = static_cast<int>(block.successors[k]);
            e.kind = branch ? (k == 0 ? graphlayout::EdgeKind::Taken : graphlayout::EdgeKind::Fallthrough) : graphlayout::EdgeKind::Jump;
            edges.push_back(std::move(e));
        }
        for (uint32_t const h : block.exceptional) {
            graphlayout::Edge e;
            e.from = static_cast<int>(b);
            e.to = static_cast<int>(h);
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
    blocks[0].lines.push_back({{shortRef(graphTitle_), Col::Text}});
    blocks[0].border = Col::Accent;
    blocks[0].fill = Col::RowSelected;
    std::vector<graphlayout::Edge> edges;
    const auto addNode = [&](const std::string& ref, bool caller) {
        const auto seen = std::find(graphRefs_.begin(), graphRefs_.end(), ref);
        int const index = static_cast<int>(seen - graphRefs_.begin());
        if (seen == graphRefs_.end()) {
            graphRefs_.push_back(ref);
            GraphView::Block block;
            block.lines.push_back({{shortRef(ref), Col::Text}});
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

void AnalysisPanel::drawGraph(const ApkAnalysis& a, Root& /*apk*/) {
    if (!graphValid_) {
        ui::emptyState("No graph", "Press CFG or Calls on a method in the Classes tab to draw its graph.");
        return;
    }
    // The method is named in the Function header above.
    if (!graphIsCalls_) {
        // An action, not a view: kept apart from the Smali / Graph / Calls switch.
        ImGui::SameLine(0.f, ui::em(1.2f));
        if (ui::smallButton(ui::icon(icons::COPY, "Copy DOT").c_str()))
            ImGui::SetClipboardText(a.cfgToDot(graphMethod_, graphBlocks_).c_str());
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Copy the graph in Graphviz DOT format");
    }
    const GraphView::Result r = graph_.draw("##graph", Theme::monoFont());
    if (!r.activated || r.block < 0) return;
    if (!graphIsCalls_) {
        if (r.block < static_cast<int>(graphBlocks_.size())) {  // the block's code in the listing
            functionMode_ = 0;
            listingPc_ = static_cast<int32_t>(graphBlocks_[static_cast<size_t>(r.block)].startPc);
            listingScroll_ = true;
        }
        return;
    }
    if (r.block >= static_cast<int>(graphRefs_.size())) return;
    const std::string ref = graphRefs_[static_cast<size_t>(r.block)];
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
    if (sel_ == Selection::Class && analysis && apk && selClass_ < analysis->classes().size()) {
        drawClassView(*analysis, *apk);
        return;
    }
    if (sel_ != Selection::Method || !analysis || !apk) {
        ui::emptyState("Nothing selected", "Select a class or a method in Classes, or a function in Native.");
        return;
    }
    drawMethodView(*analysis, *apk);
}

void AnalysisPanel::drawClassView(const ApkAnalysis& a, Root& apk) {
    const ApkAnalysis::ClassEntry& entry = a.classes()[selClass_];
    const DexFile& dex = *a.dexes()[entry.dex];
    const DexFile::ClassDef& def = a.classDef(entry);
    const std::string_view desc = a.classDescriptor(entry);
    const auto modifiers = [](uint32_t f, bool forClass) {
        std::string m;
        const auto add = [&](uint32_t bit, const char* word) {
            if (f & bit) (m += m.empty() ? "" : " ") += word;
        };
        add(0x0001, "public");
        add(0x0002, "private");
        add(0x0004, "protected");
        add(0x0008, "static");
        add(0x0010, "final");
        if (!forClass) {
            add(0x0020, "synchronized");
            add(0x0100, "native");
        }
        if (!(forClass && (f & 0x0200))) add(0x0400, "abstract");
        return m;
    };

    // Declaration: name, then "public final class extends X implements Y, Z".
    ImGui::AlignTextToFramePadding();  // the title shares its row with the Smali button
    ImGui::PushStyleColor(ImGuiCol_Text, kAccent());
    ImGui::TextUnformatted(DexFile::descriptorToJava(desc).c_str());
    ImGui::PopStyleColor();
    {
        const char* smaliLabel = "Smali";
        const float w = ui::smallButtonWidth(smaliLabel);
        ImGui::SameLine(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowContentRegionMax().x - w));
        if (ui::smallButton(smaliLabel)) {
            openClass(a, entry, apk.title);
            if (showPanel_) showPanel_("Editor");
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("The whole class as smali, in the Editor");
    }
    const uint32_t flags = def.accessFlags;
    std::string decl = modifiers(flags, true);
    (decl += decl.empty() ? "" : " ") += (flags & 0x2000) ? "@interface" : (flags & 0x4000) ? "enum" : (flags & 0x0200) ? "interface" : "class";
    if (def.superclassIdx != DexFile::kNoIndex) {
        const std::string_view super = dex.typeDescriptor(def.superclassIdx);
        if (super != "Ljava/lang/Object;" && super != "Ljava/lang/Enum;") decl += "  extends " + DexFile::descriptorToJava(super);
    }
    const std::vector<uint32_t> ifaces = dex.interfaces(def);
    for (size_t i = 0; i < ifaces.size(); ++i)
        decl += (i ? ", " : "  implements ") + DexFile::descriptorToJava(dex.typeDescriptor(ifaces[i]));
    ui::wrappedColored(theme::vec(Col::TextMuted), decl);

    DexFile::ClassData data;
    dex.classData(def, data);
    const auto& methods = methodsOfClass(a, selClass_);
    {
        std::string facts = "classes" + (entry.dex ? std::to_string(entry.dex + 1) : std::string()) + ".dex";
        if (def.sourceFileIdx != DexFile::kNoIndex) facts += "  \xc2\xb7  " + dex.string(def.sourceFileIdx);
        facts += "  \xc2\xb7  " + std::to_string(data.fields.size()) + " fields, " + std::to_string(methods.size()) + " methods";
        ImGui::TextDisabled("%s", facts.c_str());
    }
    ui::toolbarSeparator();

    ImGui::BeginChild("##classBody", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    const ImGuiTableFlags tableFlags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoPadOuterX;
    if (!data.fields.empty()) {
        char heading[32];
        std::snprintf(heading, sizeof heading, "Fields  %zu", data.fields.size());
        ui::sectionHeader(heading);
        if (ImGui::BeginTable("##fields", 3, tableFlags)) {
            ImGui::TableSetupColumn("mods", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("type", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch);
            for (const DexFile::EncodedField& f : data.fields) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", modifiers(f.accessFlags, false).c_str());
                ImGui::TableNextColumn();
                ImGui::PushStyleColor(ImGuiCol_Text, theme::syntax(SyntaxToken::Type));
                ImGui::TextUnformatted(prettyType(dex.typeDescriptor(dex.fieldType(f.fieldIdx))).c_str());
                ImGui::PopStyleColor();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(std::string(dex.fieldName(f.fieldIdx)).c_str());
            }
            ImGui::EndTable();
        }
    }

    char heading[32];
    std::snprintf(heading, sizeof heading, "Methods  %zu", methods.size());
    ui::sectionHeader(heading);
    if (methods.empty()) ImGui::TextDisabled("No methods.");
    else if (ImGui::BeginTable("##methods", 3, tableFlags)) {
        ImGui::TableSetupColumn("mods", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("signature", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed);
        for (size_t k = 0; k < methods.size(); ++k) {
            const ApkAnalysis::MethodDef& m = methods[k];
            const uint32_t idx = m.method.methodIdx;
            ImGui::PushID(static_cast<int>(k));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            // The whole row is the click target; the cells are drawn over it.
            const bool clicked = ImGui::Selectable("##m", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                                                                     ImGuiSelectableFlags_AllowDoubleClick);
            const bool doubleClick = clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\nClick: listing    Double-click: keep the Java tab open", dex.methodSignature(idx).c_str());
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextDisabled("%s", modifiers(m.method.accessFlags, false).c_str());
            ImGui::TableNextColumn();
            const bool hidden = (m.method.accessFlags & 0x0002) != 0;
            if (hidden) ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(Col::TextMuted));
            ImGui::TextUnformatted(prettyMethod(desc, dex.methodName(idx), dex.protoDescriptor(dex.methodProto(idx))).c_str());
            if (hidden) ImGui::PopStyleColor();
            ImGui::TableNextColumn();
            DexFile::CodeItem code;
            if (m.method.codeOff && dex.codeItem(m.method.codeOff, code)) ImGui::TextDisabled("%u B", code.insnsSize * 2u);
            else ImGui::TextDisabled("%s", (m.method.accessFlags & 0x0100) ? "native" : "abstract");
            ImGui::PopID();
            if (clicked) {
                const ApkAnalysis::MethodDef target = m;  // selectMethod refreshes the per-class cache
                selectMethod(a, target, apk.title, true, doubleClick);
                break;
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

void AnalysisPanel::drawMethodView(const ApkAnalysis& a, Root& apk) {
    // Breadcrumb: the class (back to its member list) > the method.
    if (selClass_ < a.classes().size()) {
        const std::string cls = shortName(a.classDescriptor(a.classes()[selClass_]));
        ImGui::PushID("crumb");
        if (ImGui::TextLink(cls.c_str())) sel_ = Selection::Class;
        ImGui::PopID();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Back to the class: its fields and methods");
        ImGui::SameLine(0.f, ui::em(0.4f));
        ImGui::TextDisabled(">");
        ImGui::SameLine(0.f, ui::em(0.4f));
        const DexFile& dex = *a.dexes()[selMethod_.dex];
        const uint32_t idx = selMethod_.method.methodIdx;
        ImGui::PushStyleColor(ImGuiCol_Text, kAccent());
        ImGui::TextUnformatted(prettyMethod(dex.typeDescriptor(dex.methodClass(idx)), dex.methodName(idx),
                                            dex.protoDescriptor(dex.methodProto(idx))).c_str());
        ImGui::PopStyleColor();
    } else {
        ui::wrappedColored(kAccent(), prettyRef(a.methodSignature(selMethod_)));
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", a.methodSignature(selMethod_).c_str());
    static const char* const kModes[] = {"Smali", "Graph", "Calls"};
    int mode = functionMode_;
    ImGui::PushID("fmode");
    if (ui::segmented(kModes, 3, mode)) functionMode_ = mode;
    ImGui::PopID();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput &&
        ImGui::IsKeyPressed(ImGuiKey_Space, false))
        functionMode_ = functionMode_ == 0 ? 1 : 0;
    if (functionMode_ == 0) {
        ImGui::SameLine(0.f, ui::em(1.f));
        ImGui::Checkbox("Java sync", &syncJava_);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Click a line of jadx's Java (Editor) to select its method and highlight its instructions here;\n"
                              "click an instruction to move the highlight in the open Java file.");
        if (!syncPcs_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled(syncExact_ ? "%zu instructions (debug lines)" : "%zu instructions (matched by calls)", syncPcs_.size());
        }
    }
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
                ImGui::SetScrollY(std::max(0.f, static_cast<float>(i) * lh - ImGui::GetWindowHeight() * 0.3f));
                break;
            }
    }
    std::vector<Span> spans;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(methodListing_.size()), lh);
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const ListingLine& l = methodListing_[static_cast<size_t>(i)];
            ImGui::PushID(i);
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            const bool focus = l.pc >= 0 && l.pc == listingPc_;
            // Instructions of the Java line clicked in the editor.
            if (l.pc >= 0 && std::find(syncPcs_.begin(), syncPcs_.end(), static_cast<uint32_t>(l.pc)) != syncPcs_.end())
                ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + ImGui::GetContentRegionAvail().x, pos.y + ImGui::GetTextLineHeight()),
                                                          theme::u32(Col::FindMatch, 0.55f));
            if (ImGui::Selectable("##l", focus, ImGuiSelectableFlags_AllowDoubleClick, ImVec2(0, ImGui::GetTextLineHeight()))) {
                listingPc_ = l.pc;
                if (l.pc >= 0) syncToJava(a, static_cast<uint32_t>(l.pc));
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
            listingSel_.row(i, l.text, pos, lh);
            if (ImGui::IsItemHovered()) ui::literalTooltip(l.text, pos.x, ImGui::GetIO().MousePos.x);
            if (ImGui::BeginPopupContextItem("##lctx")) {
                const ui::TextSelect::LineFn text = [this](int k) { return methodListing_[static_cast<size_t>(k)].text; };
                if (std::string lit; ui::literalForMenu(l.text, std::string::npos, lit) && ImGui::MenuItem("Send string to Decoder"))
                    workspace_.sendToDecoder(lit);
                if (ImGui::MenuItem("Copy line")) ImGui::SetClipboardText(l.text.c_str());
                listingSel_.menuItems(static_cast<int>(methodListing_.size()), text,
                                      [this](std::string s) { workspace_.sendToDecoder(std::move(s)); });
                ImGui::EndPopup();
            }
            // Smali colouring, drawn over the row.
            bool inBlock = false;
            SyntaxHighlighter::tokenize(l.text, Language::Smali, inBlock, spans);
            float x = pos.x;
            for (const Span& s : spans) {
                const char* b = l.text.data() + s.begin;
                const char* e = l.text.data() + s.end;
                ImGui::GetWindowDrawList()->AddText(ImVec2(x, pos.y), theme::syntax(s.token), b, e);
                x += ImGui::CalcTextSize(b, e).x;
            }
            ImGui::PopID();
        }
    listingSel_.finish(static_cast<int>(methodListing_.size()), [this](int k) { return methodListing_[static_cast<size_t>(k)].text; }, lh);
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
    // Two lists side by side: what calls the selection, what it calls. A click only records
    // where to go: navigating replaces the lists being drawn, so it happens after them.
    std::function<void()> go;
    // Each entry's text, for Ctrl+C and its context menu (set by the draw functions below).
    std::string entryText;
    const auto copyMenu = [&](const char* id) {
        ui::copyHovered(entryText);
        if (ImGui::BeginPopupContextItem(id)) {
            if (ImGui::MenuItem("Copy", "Ctrl+C")) ImGui::SetClipboardText(entryText.c_str());
            ImGui::EndPopup();
        }
    };
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
        clipper.Begin(static_cast<int>(rows));
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableNextColumn();
                if (static_cast<size_t>(i) < nLeft) drawLeft(static_cast<size_t>(i)), copyMenu("##lcopy");
                ImGui::TableNextColumn();
                if (static_cast<size_t>(i) < nRight) drawRight(static_cast<size_t>(i)), copyMenu("##rcopy");
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
                       entryText = from.empty() ? hexAddr(r.from) : from;
                       if (ImGui::Selectable(entryText.c_str(), false, ImGuiSelectableFlags_None)) {
                           const uint64_t at = r.from;
                           go = [this, at] { gotoNative(at); };
                       }
                   },
                   [&](size_t i) {
                       const auto& r = nativeCallees_[i];
                       const NativeCode::Function* to = nc.functionAt(r.target);
                       const std::string name = to ? NativeCode::displayName(*to) : hexAddr(r.target);
                       entryText = name;
                       ImGui::PushID("callee");
                       if (ImGui::Selectable(name.c_str()) && to) {
                           const uint64_t at = to->addr;
                           go = [this, at] { gotoNative(at); };
                       }
                       ImGui::PopID();
                   });
        if (go) go();
        return;
    }
    if (sel_ == Selection::Class && analysis && apk && selClass_ < analysis->classes().size()) {
        const ApkAnalysis& a = *analysis;
        twoColumns("Used by", selClassUses_.size(), "Subclasses & implementers", selClassSubs_.size(),
                   [&](size_t i) {
                       const auto& h = selClassUses_[i];
                       const std::string sig = a.methodSignature(h.from);
                       entryText = sig;
                       if (ImGui::Selectable(prettyRef(sig).c_str())) {
                           const DexFile& dex = *a.dexes()[h.from.dex];
                           const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(h.from.method)), dex.methodName(h.from.method),
                                                              dex.protoDescriptor(dex.methodProto(h.from.method)));
                           if (!defs.empty()) {
                               const ApkAnalysis::MethodDef target = defs.front();
                               const int32_t pc = static_cast<int32_t>(h.from.pc);
                               go = [this, &a, apk, target, pc] {
                                   selectMethod(a, target, apk->title, true);
                                   listingPc_ = pc;
                                   listingScroll_ = true;
                               };
                           }
                       }
                       if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\nuses the type at %04x", sig.c_str(), h.from.pc);
                   },
                   [&](size_t i) {
                       const std::string& name = selClassSubs_[i];
                       entryText = name;
                       ImGui::PushID("sub");
                       if (ImGui::Selectable(name.c_str())) {
                           if (const ApkAnalysis::ClassEntry* e = a.findClass(name)) {
                               const auto& all = a.classes();
                               for (uint32_t k = 0; k < static_cast<uint32_t>(all.size()); ++k)
                                   if (all[k].dex == e->dex && all[k].def == e->def) {
                                       go = [this, &a, apk, k] { selectClass(a, k, apk->title, false); };
                                       break;
                                   }
                           }
                       }
                       ImGui::PopID();
                   });
        if (go) go();
        return;
    }
    if (sel_ != Selection::Method || !analysis || !apk) {
        ui::emptyState("Nothing selected", "Select a class to see where it is used, or a method to see what calls it and what it calls.");
        return;
    }
    const ApkAnalysis& a = *analysis;
    twoColumns("Called by", selCallers_.size(), "Calls", selCallees_.size(),
               [&](size_t i) {
                   const auto& h = selCallers_[i];
                   const std::string sig = a.methodSignature(h.from);
                   entryText = sig;
                   if (ImGui::Selectable(prettyRef(sig).c_str())) {
                       const DexFile& dex = *a.dexes()[h.from.dex];
                       const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(h.from.method)), dex.methodName(h.from.method),
                                                          dex.protoDescriptor(dex.methodProto(h.from.method)));
                       if (!defs.empty()) {
                           const ApkAnalysis::MethodDef target = defs.front();
                           const int32_t pc = static_cast<int32_t>(h.from.pc);
                           go = [this, &a, apk, target, pc] {
                               selectMethod(a, target, apk->title, true);
                               listingPc_ = pc;
                               listingScroll_ = true;
                           };
                       }
                   }
                   if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\ncall at %04x", sig.c_str(), h.from.pc);
               },
               [&](size_t i) {
                   const auto& c = selCallees_[i];
                   const std::string label = prettyRef(c.signature);
                   entryText = c.signature;
                   ImGui::PushID("callee");
                   std::string cls, name, proto;
                   std::vector<ApkAnalysis::MethodDef> defs;
                   if (ApkAnalysis::splitMethodRef(c.signature, cls, name, proto)) defs = a.findMethodDefs(cls, name, proto);
                   if (defs.empty()) ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                   if (ImGui::Selectable(label.c_str())) {
                       if (!defs.empty()) {
                           const ApkAnalysis::MethodDef target = defs.front();
                           go = [this, &a, apk, target] { selectMethod(a, target, apk->title, true); };
                       } else {
                           listingPc_ = static_cast<int32_t>(c.pc);  // framework method: show the call site
                           listingScroll_ = true;
                           showFunction(0);
                       }
                   }
                   if (defs.empty()) ImGui::PopStyleColor();
                   if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s at %04x%s", c.signature.c_str(), c.opcode.c_str(), c.pc,
                                                                 defs.empty() ? "\n(not in this APK)" : "");
                   ImGui::PopID();
               });
    if (go) go();
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
    const std::string apkPath = apk.apkPath, entry = libs_[static_cast<size_t>(index)].path;
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
        // What each library's ELF header says it is (the directory name is only a convention).
        libInventory_ = workspace_.analysis().nativeInventory(apk.apkPath);
        for (LibRow& row : libs_)
            for (const abi::NativeLib& l : libInventory_->libs)
                if (l.path == row.path) {
                    row.arch = l.validElf ? std::string(l.elf.id == abi::Id::Unknown ? abi::machineName(l.ident.machine).c_str() : l.elf.arch) : std::string("not an ELF file");
                    row.mismatch = l.mismatch();
                    row.disassemblable = l.effective().disassemblable;
                }
    }
    if (libs_.empty()) {
        ui::emptyState("No native libraries", "This APK ships no lib/<abi>/*.so files: all of its code is Dalvik bytecode.");
        return;
    }
    if (ready(elfLoad_)) {
        auto r = elfLoad_.get();
        elf_ = std::move(r.first);
        elfError_ = std::move(r.second);
    }
    if (!pendingLib_.empty() && !elfLoad_.valid()) {
        for (int i = 0; i < static_cast<int>(libs_.size()); ++i)
            if (libs_[static_cast<size_t>(i)].path == pendingLib_ && i != selectedLib_) selectLib(apk, i);
        pendingLib_.clear();
    }
    // Code views get the whole panel: the library list shrinks to a dropdown.
    if (selectedLib_ < 0 && !elfLoad_.valid()) {
        // Open on the library the connected device would load, else the first one ApkSpy can disassemble
        // (arm64-v8a, armeabi-v7a, x86_64, x86 in that order).
        const Workspace::DeviceAbiState& device = workspace_.deviceAbis();
        const std::string chosen = !device.label.empty() && device.abis.known() && libInventory_ ? abi::check(*libInventory_, device.abis).chosen : std::string();
        int first = -1, bestRank = 99;
        for (int i = 0; i < static_cast<int>(libs_.size()); ++i) {
            const LibRow& row = libs_[static_cast<size_t>(i)];
            static const char* const kOrder[] = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"};
            int rank = row.disassemblable ? 10 : 50;
            for (int k = 0; k < 4; ++k)
                if (row.abi == kOrder[k]) rank += k;
            if (!chosen.empty() && row.abi == chosen) rank -= 8;
            if (rank < bestRank) bestRank = rank, first = i;
        }
        selectLib(apk, first < 0 ? 0 : first);
    }
    const bool compactLibs = true;  // the navigator is narrow: a dropdown
    const bool sideBySide = false;
    const auto libLabel = [&](int i) {
        char label[512];
        const LibRow& row = libs_[static_cast<size_t>(i)];
        std::snprintf(label, sizeof label, "%s  (%s%s, %.0f KB)", row.path.c_str(), row.arch.empty() ? "?" : row.arch.c_str(),
                      row.mismatch ? ", not what the directory says" : "", static_cast<double>(row.size) / 1024.0);
        return std::string(label);
    };
    if (libInventory_) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("%s", abiui::shipsLine(*libInventory_).c_str());
        ImGui::PopTextWrapPos();
        if (!workspace_.deviceAbis().label.empty()) abiui::drawDeviceCompat(*libInventory_, workspace_.deviceAbis());
    }
    if (compactLibs) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::BeginCombo("##lib", libLabel(selectedLib_).c_str())) {
            for (int i = 0; i < static_cast<int>(libs_.size()); ++i)
                if (ImGui::Selectable(libLabel(i).c_str(), selectedLib_ == i) && !elfLoad_.valid() && selectedLib_ != i) selectLib(apk, i);
            ImGui::EndCombo();
        }
    } else {
    // Stacked: just tall enough for the library list (resizable).
    const float libsH = std::min(ui::em(8.f), ImGui::GetTextLineHeightWithSpacing() * (static_cast<float>(libs_.size()) + 0.6f) +
                                                  ImGui::GetStyle().WindowPadding.y * 2.f);
    ImGui::BeginChild("##libs", sideBySide ? ImVec2(ui::em(15.f), 0) : ImVec2(0, libsH),
                      ImGuiChildFlags_Borders | (sideBySide ? ImGuiChildFlags_ResizeX : ImGuiChildFlags_ResizeY));
    for (int i = 0; i < static_cast<int>(libs_.size()); ++i)
        if (ImGui::Selectable(libLabel(i).c_str(), selectedLib_ == i) && !elfLoad_.valid() && selectedLib_ != i) selectLib(apk, i);
    ImGui::EndChild();
    if (sideBySide) ImGui::SameLine();
    }
    ImGui::BeginChild("##elf", ImVec2(0, 0));
    if (elfLoad_.valid()) {
        ImGui::TextDisabled("Parsing...");
    } else if (!elfError_.empty()) {
        ImGui::TextColored(kWarn(), "%s", elfError_.c_str());
    } else if (elf_) {
        const bool codeView = symbolView_ != 3 && symbolView_ != 4;  // file facts belong with the sections
        if (!codeView) {
            ImGui::TextColored(kAccent(), "%s", elf_->name().c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("%s %s, %s", elf_->is64() ? "ELF64" : "ELF32", elf_->typeName().c_str(), elf_->machineName().c_str());
        }
        if (!codeView && !elf_->soname().empty()) ImGui::Text("SONAME: %s", elf_->soname().c_str());
        if (!codeView && !elf_->needed().empty()) {
            std::string needed;
            for (const auto& n : elf_->needed()) needed += (needed.empty() ? "" : ", ") + n;
            ImGui::TextWrapped("NEEDED: %s", needed.c_str());
        }
        if (!codeView && selectedLib_ >= 0 && ui::smallButton("Open hex view")) {
            if (const TreeNode* node = apk.tree->findByPath(libs_[static_cast<size_t>(selectedLib_)].path))
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
            if (symbolView_ == 0) {
                // Natives bound at run time with RegisterNatives (no Java_* export to find them by).
                if (jniRegsFor_ != elf_.get()) {
                    jniRegs_ = elf_->jniRegistrations();
                    jniRegsFor_ = elf_.get();
                }
                if (!jniRegs_.empty()) {
                    char header[64];
                    std::snprintf(header, sizeof header, "Registered natives (%zu)###regnatives", jniRegs_.size());
                    if (ui::collapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen)) {
                        if (ImGui::BeginTable("##regs", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                                              ImVec2(0, std::min(ui::em(14.f), ImGui::GetTextLineHeightWithSpacing() * (jniRegs_.size() + 2.f))))) {
                            ImGui::TableSetupScrollFreeze(0, 1);
                            ImGui::TableSetupColumn("Java method", ImGuiTableColumnFlags_WidthStretch, 2.f);
                            ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthStretch, 3.f);
                            ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, ui::em(6.f));
                            ImGui::TableHeadersRow();
                            for (size_t i = 0; i < jniRegs_.size(); ++i) {
                                const auto& r = jniRegs_[i];
                                if (!filter.empty() && tex::ciFind(r.name, filter) == std::string_view::npos &&
                                    tex::ciFind(r.signature, filter) == std::string_view::npos)
                                    continue;
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                ImGui::PushID(static_cast<int>(i));
                                if (ImGui::Selectable(r.name.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_SpanAllColumns) &&
                                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                                    symbolView_ = 5;
                                    gotoNative(r.fnAddr);
                                }
                                if (ImGui::IsItemHovered()) ImGui::SetTooltip("double-click: disassemble the native implementation");
                                ImGui::PopID();
                                ImGui::TableNextColumn();
                                ImGui::TextDisabled("%s", r.signature.c_str());
                                ImGui::TableNextColumn();
                                ImGui::Text("0x%llx", static_cast<unsigned long long>(r.fnAddr));
                            }
                            ImGui::EndTable();
                        }
                    }
                }
            }
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
                clipper.Begin(static_cast<int>(shown.size()));
                while (clipper.Step())
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                        const auto* s = shown[static_cast<size_t>(i)];
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
                        ui::copyHovered(dem);
                        if (ImGui::BeginPopupContextItem("##symctx")) {
                            if (ImGui::MenuItem("Copy name", "Ctrl+C")) ImGui::SetClipboardText(dem.c_str());
                            if (dem != s->name && ImGui::MenuItem("Copy mangled name")) ImGui::SetClipboardText(s->name.c_str());
                            char addr[32];
                            std::snprintf(addr, sizeof addr, "0x%llx", static_cast<unsigned long long>(s->value));
                            if (ImGui::MenuItem("Copy address")) ImGui::SetClipboardText(addr);
                            ImGui::EndPopup();
                        }
                        ImGui::PopID();
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("%s%s", s->name.c_str(), defined ? "\ndouble-click: disassemble" : "");
                        ImGui::TableNextColumn();
                        ImGui::Text("0x%llx", static_cast<unsigned long long>(s->value));
                        ImGui::TableNextColumn();
                        ImGui::Text("%llu", static_cast<unsigned long long>(s->size));
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
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(s.addr));
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(s.offset));
                    ImGui::TableNextColumn();
                    ImGui::Text("%llu", static_cast<unsigned long long>(s.size));
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
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(s.vaddr));
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%llx", static_cast<unsigned long long>(s.offset));
                    ImGui::TableNextColumn();
                    ImGui::Text("%llu / %llu", static_cast<unsigned long long>(s.filesz), static_cast<unsigned long long>(s.memsz));
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

// Opens a unified diff of one method between two APKs (the same normalised
// listing the version diff compares: no offsets, no line numbers).
void AnalysisPanel::openMethodDiff(Root& a, Root& b, const std::string& signature) {
    auto anA = workspace_.analysis().get(a.title), anB = workspace_.analysis().get(b.title);
    std::string cls, name, proto;
    if (!anA || !anB || !ApkAnalysis::splitMethodRef(signature, cls, name, proto)) return;
    const auto listing = [&](const ApkAnalysis& an) {
        std::string text;
        dalvik::ListingOptions opt;
        opt.showOffsets = false;
        opt.showLines = false;
        for (const auto& def : an.findMethodDefs(cls, name, proto)) dalvik::disassembleMethod(*an.dexes()[def.dex], def.method, opt, text);
        return text;
    };
    const std::string left = listing(*anA), right = listing(*anB);
    std::string text = "# " + signature + "\n# --- " + a.title + "   +++ " + b.title + "\n\n";
    const std::string d = edits::unifiedDiff(a.title + " -> " + b.title, left, right, 4);
    text += d.empty() ? "(no textual difference once offsets and line numbers are ignored)\n" : d;
    std::string path = "diff/" + signature + ".diff";
    for (char& c : path)
        if (c == '\\' || c == ':' || c == '<' || c == '>' || c == '|' || c == '?' || c == '*' || c == '"') c = '_';
    workspace_.openGenerated(a.title, path, shortName(cls) + "." + name + ".diff", std::move(text), 0);
}

void AnalysisPanel::drawCompare(Root& /*apk*/) {
    // The comparison has its own panel: sections, filters and side-by-side code.
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("Compare two versions of the app: manifest, permissions, classes, methods side by side, "
                        "resources, native libraries, bundled libraries and endpoints.");
    ImGui::PopTextWrapPos();
    if (ui::flowButton("Open the Diff panel") && showPanel_) showPanel_("Diff");
}

// ---------------------------------------------------------------------------
// Resources (resources.arsc)
// ---------------------------------------------------------------------------

void AnalysisPanel::drawResources(Root& apk) {
    std::shared_ptr<const ResourceTable> const table = workspace_.resources(apk.title);
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
    ui::wrappedColored(kDim(), table->packageName() + " - " + std::to_string(table->size()) + " resources");
    ImGui::SetNextItemWidth(std::min(ui::em(9.f), ImGui::GetContentRegionAvail().x));
    if (ImGui::BeginCombo("##restype", resTypes_[static_cast<size_t>(resType_)].c_str())) {
        for (int i = 0; i < static_cast<int>(resTypes_.size()); ++i)
            if (ImGui::Selectable(resTypes_[static_cast<size_t>(i)].c_str(), i == resType_)) resType_ = i;
        ImGui::EndCombo();
    }
    ui::sameLineIfFits(ui::em(10.f));
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##resfilter", "Filter name or value...", resFilter_, sizeof resFilter_);
    const std::string key = std::to_string(resType_) + "|" + resFilter_;
    if (key != resKey_) {
        resKey_ = key;
        resItems_ = table->list(resType_ ? resTypes_[static_cast<size_t>(resType_)] : std::string(), resFilter_, 50000);
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
        clipper.Begin(static_cast<int>(resItems_.size()));
        while (clipper.Step())
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const ResourceTable::Item& it = resItems_[static_cast<size_t>(i)];
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
                        const std::string literal = std::to_string(static_cast<int32_t>(it.id));
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
