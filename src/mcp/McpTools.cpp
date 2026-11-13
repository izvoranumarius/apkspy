#include "mcp/McpTools.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <set>
#include <thread>
#include "analysis/ApkDiff.hpp"
#include "analysis/Dalvik.hpp"
#include "core/ApkInfo.hpp"
#include "core/AxmlDecoder.hpp"
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"
#include "core/Workspace.hpp"
#include "debug/DeviceService.hpp"

namespace fs = std::filesystem;

namespace {

using schema::boolean;
using schema::integer;
using schema::str;
using schema::strEnum;

constexpr size_t kMaxReadBytes = 4u << 20;

// ---- argument helpers -------------------------------------------------------

std::string argStr(const Json& a, const char* k, const std::string& def = {}) { return a.get(k).asString(def); }
int64_t argInt(const Json& a, const char* k, int64_t def) { return a.get(k).isNumber() ? a.get(k).asInt() : def; }
bool argBool(const Json& a, const char* k, bool def) { return a.get(k).isBool() ? a.get(k).asBool() : def; }

Json apkArg() { return str("APK group name as listed by list_apks (optional when the project has one APK)"); }

// Resolves the "apk" argument to the APK root of the workspace.
Root* resolveApk(Workspace& ws, const Json& args, std::string& error) {
    const std::string group = argStr(args, "apk");
    const std::vector<Root*> apks = ws.apkRoots();
    if (apks.empty()) {
        error = "No APK is open. Open a project or add an APK in ApkSpy first.";
        return nullptr;
    }
    if (group.empty()) {
        if (apks.size() == 1) return apks.front();
        error = "Several APKs are open; pass \"apk\" (one of:";
        for (Root* r : apks) error += " " + r->title;
        error += ")";
        return nullptr;
    }
    for (Root* r : apks)
        if (r->title == group) return r;
    error = "Unknown APK group '" + group + "'";
    return nullptr;
}

std::string sourcesDirOf(const Root& dec) { return pathutil::toUtf8(pathutil::fromUtf8(dec.outDir) / "sources"); }

// Path shown to clients: zip entry path (APK) or path relative to the jadx
// sources directory with '/' separators (decompiled).
std::string displayPath(const Root& root, const std::string& nodePath) {
    if (root.kind == Root::Kind::Apk) return nodePath;
    const std::string base = sourcesDirOf(root);
    std::string rel = nodePath;
    if (rel.size() > base.size() && rel.compare(0, base.size(), base) == 0) rel = rel.substr(base.size() + 1);
    std::replace(rel.begin(), rel.end(), '\\', '/');
    return rel;
}

// Finds a node by the client-facing path. Only nodes that exist in the
// project tree can be reached - no raw filesystem access.
const TreeNode* findNode(const Root& root, std::string path) {
    if (!root.tree) return nullptr;
    while (!path.empty() && path.front() == '/') path.erase(path.begin());
    if (path.empty()) return root.tree.get();
    if (root.kind == Root::Kind::Apk) {
        if (const TreeNode* n = root.tree->findByPath(path)) return n;
        return root.tree->findByPath(path + "/");  // folder entries end with '/'
    }
    if (path.find("..") != std::string::npos) return nullptr;
    fs::path p = pathutil::fromUtf8(sourcesDirOf(root)) / pathutil::fromUtf8(path);
    p.make_preferred();
    return root.tree->findByPath(pathutil::toUtf8(p));
}

Root* rootFor(Workspace& ws, Root& apk, const std::string& which, std::string& error) {
    if (which.empty() || which == "apk") return &apk;
    Root* dec = ws.rootByGroup(apk.title, Root::Kind::Decompiled);
    if (!dec || dec->title != apk.title) {
        error = "No decompiled output for " + apk.title;
        return nullptr;
    }
    return dec;
}

const char* kindName(NodeKind k) {
    switch (k) {
    case NodeKind::Folder: return "folder";
    case NodeKind::Java: return "java";
    case NodeKind::Kotlin: return "kotlin";
    case NodeKind::Xml: return "xml";
    case NodeKind::Json: return "json";
    case NodeKind::Smali: return "smali";
    case NodeKind::Groovy: return "groovy";
    case NodeKind::Yaml: return "yaml";
    case NodeKind::Web: return "web";
    case NodeKind::Text: return "text";
    case NodeKind::Image: return "image";
    case NodeKind::Dex: return "dex";
    case NodeKind::Native: return "native";
    case NodeKind::Binary: return "binary";
    }
    return "binary";
}

std::string hexDump(const uint8_t* data, size_t len, uint64_t baseOffset) {
    std::string out;
    char buf[96];
    for (size_t row = 0; row < len; row += 16) {
        int n = std::snprintf(buf, sizeof buf, "%08llx  ", (unsigned long long)(baseOffset + row));
        out.append(buf, (size_t)n);
        for (size_t k = 0; k < 16; ++k) {
            if (row + k < len) n = std::snprintf(buf, sizeof buf, "%02x ", data[row + k]);
            else n = std::snprintf(buf, sizeof buf, "   ");
            out.append(buf, (size_t)n);
            if (k == 7) out.push_back(' ');
        }
        out += " |";
        for (size_t k = 0; k < 16 && row + k < len; ++k) {
            const uint8_t c = data[row + k];
            out.push_back(c >= 32 && c < 127 ? (char)c : '.');
        }
        out += "|\n";
    }
    return out;
}

bool looksText(const std::vector<uint8_t>& b) {
    const size_t n = std::min<size_t>(b.size(), 8192);
    for (size_t i = 0; i < n; ++i)
        if (b[i] == 0) return false;
    return true;
}

// Text view of file bytes: decoded AXML, text, or a hex dump of the head.
Json renderContent(const std::vector<uint8_t>& bytes, int64_t startLine, int64_t maxLines,
                   const ResourceTable* resources = nullptr) {
    std::string text;
    std::string format;
    if (AxmlDecoder::looksLikeAxml(bytes)) {
        std::string err;
        if (AxmlDecoder::decode(bytes, text, err, resources)) format = "xml (decoded from binary XML)";
    }
    if (format.empty() && looksText(bytes)) {
        text.assign((const char*)bytes.data(), bytes.size());
        format = "text";
    }
    if (format.empty()) {
        const size_t n = std::min<size_t>(bytes.size(), 4096);
        return Json::obj({{"format", "binary"},
                          {"size", (unsigned long long)bytes.size()},
                          {"hexdump", hexDump(bytes.data(), n, 0)},
                          {"note", n < bytes.size() ? "first 4096 bytes shown; use hexdump for other ranges" : ""}});
    }
    // Line window.
    std::vector<std::string_view> lines;
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i)
        if (i == text.size() || text[i] == '\n') {
            std::string_view l(text.data() + start, i - start);
            if (!l.empty() && l.back() == '\r') l.remove_suffix(1);
            lines.push_back(l);
            start = i + 1;
        }
    const int64_t total = (int64_t)lines.size();
    const int64_t first = std::clamp<int64_t>(startLine, 1, std::max<int64_t>(total, 1));
    const int64_t last = std::min<int64_t>(total, first + maxLines - 1);
    std::string window;
    for (int64_t i = first; i <= last; ++i) {
        window.append(lines[(size_t)(i - 1)]);
        window.push_back('\n');
    }
    return Json::obj({{"format", format},
                      {"total_lines", (long long)total},
                      {"start_line", (long long)first},
                      {"end_line", (long long)last},
                      {"truncated", last < total},
                      {"content", json::sanitizeUtf8(window)}});
}

Json analysisStateJson(const AnalysisService::Status& st) {
    const char* names[] = {"not_started", "running", "ready", "failed", "cancelled"};
    Json j = Json::obj({{"state", names[(int)st.state]}});
    if (st.total) j.set("progress", Json::obj({{"done", (unsigned long long)st.done}, {"total", (unsigned long long)st.total}}));
    if (!st.phase.empty()) j.set("phase", st.phase);
    if (!st.error.empty()) j.set("message", st.error);
    return j;
}

// Fetches the ready analysis of an APK, or explains how to get one.
std::shared_ptr<const ApkAnalysis> requireAnalysis(Workspace& ws, Root& apk, std::string& error) {
    auto a = ws.analysis().get(apk.title);
    if (a) return a;
    const AnalysisService::Status st = ws.analysis().status(apk.title);
    if (st.state == AnalysisService::State::Running)
        error = "Bytecode analysis of " + apk.title + " is still running (" + std::to_string(st.done) + "/" +
                std::to_string(st.total) + " classes). Call run_analysis with wait=true.";
    else
        error = "Bytecode analysis of " + apk.title + " is not available - call run_analysis first" +
                (st.error.empty() ? std::string() : " (last error: " + st.error + ")");
    return nullptr;
}

Json xrefJson(const ApkAnalysis& a, const ApkAnalysis::XrefHit& h) {
    static const char* kinds[] = {"call", "field_read", "field_write", "string", "type"};
    Json j = Json::obj({{"from", a.methodSignature(h.from)},
                        {"pc", (unsigned long long)h.from.pc},
                        {"kind", kinds[(int)h.kind]},
                        {"target", json::sanitizeUtf8(h.target)},
                        {"dex", a.dexes()[h.from.dex]->name()}});
    // Source line when debug info is present.
    const DexFile& dex = *a.dexes()[h.from.dex];
    const auto defs = a.findMethodDefs(dex.typeDescriptor(dex.methodClass(h.from.method)), dex.methodName(h.from.method),
                                       dex.protoDescriptor(dex.methodProto(h.from.method)));
    if (!defs.empty()) {
        const auto& m = defs.front();
        DexFile::CodeItem code;
        if (m.method.codeOff && dex.codeItem(m.method.codeOff, code)) {
            const int line = dex.lineForPc(code, h.from.pc);
            if (line >= 0) j.set("line", line);
        }
    }
    return j;
}

// Resolves "method" args: "Lcom/a/B;->name(I)V", "com.a.B.name" or class+name.
bool resolveMethodArg(const ApkAnalysis& a, const Json& args, std::vector<ApkAnalysis::MethodDef>& out,
                      std::string& cls, std::string& name, std::string& proto, std::string& error) {
    const std::string ref = argStr(args, "method");
    if (!ApkAnalysis::splitMethodRef(ref, cls, name, proto)) {
        error = "method must look like Lcom/example/Foo;->bar(I)V or com.example.Foo.bar";
        return false;
    }
    out = a.findMethodDefs(cls, name, proto);
    if (out.empty()) {
        error = "no method " + name + proto + " defined in " + DexFile::descriptorToJava(cls) +
                " (framework methods have no bytecode in the APK)";
        return false;
    }
    return true;
}

Json methodJson(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    const DexFile& dex = *a.dexes()[m.dex];
    Json j = Json::obj({{"signature", a.methodSignature(m)},
                        {"name", std::string(dex.methodName(m.method.methodIdx))},
                        {"proto", dex.protoDescriptor(dex.methodProto(m.method.methodIdx))},
                        {"access", DexFile::accessFlagsToString(m.method.accessFlags, true)}});
    DexFile::CodeItem code;
    if (m.method.codeOff && dex.codeItem(m.method.codeOff, code)) {
        j.set("registers", (int)code.registers);
        j.set("code_units", (unsigned long long)code.insnsSize);
    } else {
        j.set("code_units", 0);
    }
    return j;
}

std::string javaToRelSourcePath(const std::string& javaName) {
    // com.a.B$Inner -> com/a/B.java (jadx emits inner classes in the outer file)
    std::string outer = javaName.substr(0, javaName.find('$'));
    std::replace(outer.begin(), outer.end(), '.', '/');
    return outer + ".java";
}

Json deviceJson(const adb::Device& d) {
    return Json::obj({{"serial", d.serial}, {"state", d.state}, {"model", d.model}, {"product", d.product},
                      {"emulator", d.emulator()}});
}

// Picks the device: explicit serial, else the selected one, else the only one.
std::string resolveSerial(DeviceService& dev, const Json& args, std::string& error) {
    std::string serial = argStr(args, "serial");
    if (!serial.empty()) {
        if (!adb::validSerial(serial)) {
            error = "invalid serial";
            return {};
        }
        return serial;
    }
    serial = dev.selected();
    if (!serial.empty()) return serial;
    std::vector<adb::Device> list = dev.adb().devices(error);
    std::vector<adb::Device> online;
    for (auto& d : list)
        if (d.state == "device") online.push_back(d);
    if (online.size() == 1) return online.front().serial;
    if (online.empty()) error = error.empty() ? "no device connected (adb devices is empty)" : error;
    else error = "several devices connected; pass \"serial\"";
    return {};
}

// pid from "pid" or "package" args.
int resolvePid(DeviceService& dev, const std::string& serial, const Json& args, std::string& error) {
    const int64_t pid = argInt(args, "pid", 0);
    if (pid > 0) return (int)pid;
    const std::string pkg = argStr(args, "package");
    if (pkg.empty()) {
        error = "pass \"pid\" or \"package\"";
        return 0;
    }
    if (!adb::validPackage(pkg)) {
        error = "invalid package name";
        return 0;
    }
    return dev.adb().pidOf(serial, pkg, error);
}

Json debugSnapshotJson(const DebugSession::Snapshot& s) {
    Json threads = Json::array();
    for (const auto& t : s.threads)
        threads.push(Json::obj({{"id", (unsigned long long)t.id},
                                {"name", json::sanitizeUtf8(t.name)},
                                {"status", DebugSession::threadStatusName(t.status)},
                                {"suspended", t.suspend != 0}}));
    Json frames = Json::array();
    for (size_t i = 0; i < s.frames.size(); ++i) {
        const auto& f = s.frames[i];
        Json fj = Json::obj({{"index", (unsigned long long)i}, {"method", f.method}, {"bytecode_index", (unsigned long long)f.location.index}});
        if (f.line >= 0) fj.set("line", f.line);
        frames.push(std::move(fj));
    }
    Json locals = Json::array();
    for (const auto& l : s.locals) {
        Json lj = Json::obj({{"name", l.name}, {"type", l.type}, {"value", json::sanitizeUtf8(l.value)}});
        if (l.objectId) lj.set("object_id", (unsigned long long)l.objectId);  // expandable with debugger_inspect
        locals.push(std::move(lj));
    }
    Json bps = Json::array();
    for (const auto& b : s.breakpoints) {
        Json bj = Json::obj({{"id", b.id},
                             {"class", b.classDescriptor.empty() ? std::string("*") : DexFile::descriptorToJava(b.classDescriptor)},
                             {"method", b.method},
                             {"resolved", b.resolved},
                             {"hits", b.hits},
                             {"status", b.status}});
        if (b.line >= 0) bj.set("line", b.line);
        if (b.exception) {
            bj.set("kind", "exception");
            bj.set("caught", b.caught);
            bj.set("uncaught", b.uncaught);
        }
        bps.push(std::move(bj));
    }
    Json events = Json::array();
    const size_t from = s.events.size() > 30 ? s.events.size() - 30 : 0;
    for (size_t i = from; i < s.events.size(); ++i) events.push(s.events[i]);
    Json j = Json::obj({{"state", DebugSession::stateName(s.state)},
                        {"serial", s.serial},
                        {"pid", s.pid},
                        {"vm", s.vm},
                        {"current_thread", (unsigned long long)s.currentThread},
                        {"selected_frame", s.selectedFrame},
                        {"threads", std::move(threads)},
                        {"frames", std::move(frames)},
                        {"locals", std::move(locals)},
                        {"breakpoints", std::move(bps)},
                        {"recent_events", std::move(events)}});
    if (!s.exception.empty()) j.set("exception", json::sanitizeUtf8(s.exception));
    if (!s.error.empty()) j.set("error", s.error);
    return j;
}

}  // namespace

std::string apkSpyMcpInstructions() {
    return "ApkSpy is an Android APK reverse-engineering workbench. Tools operate on the APKs of the currently "
           "open ApkSpy project. Typical flow: list_apks -> apk_info / get_manifest -> run_analysis (bytecode "
           "index; needed for classes, methods, xrefs, call graphs, CFGs and strings) -> list_classes / "
           "get_class / get_method / xrefs / call_graph. decompile_class returns jadx Java source when jadx "
           "output exists. Paths: root=\"apk\" uses zip entry paths (e.g. res/layout/main.xml), "
           "root=\"decompiled\" uses paths relative to the jadx sources directory (e.g. com/example/Main.java). "
           "Method references use smali syntax: Lcom/example/Foo;->bar(Ljava/lang/String;)V (or "
           "com.example.Foo.bar for all overloads). Device tools (device_list, logcat_read, process_stats, "
           "debugger_*) need adb and a connected device/emulator; the debugger works on debuggable apps.";
}

void registerApkSpyTools(McpServer& server, const McpToolEnv& env) {
    Workspace& ws = *env.workspace;
    DeviceService* devices = env.devices;

    // ------------------------------------------------------------------ project
    server.addTool({"list_apks", "List APKs",
                    "Lists the APKs in the open project with their decompilation and analysis state.",
                    schema::object({}), true, false, [&ws](const Json&, McpToolContext&) -> McpToolOutcome {
                        Json list = Json::array();
                        for (Root* r : ws.apkRoots()) {
                            const Root* dec = ws.rootByGroup(r->title, Root::Kind::Decompiled);
                            std::string decState = "none";
                            if (dec && dec->title == r->title) {
                                if (ws.isGroupDecompiling(r->title)) decState = "running";
                                else if (dec->tree && !dec->tree->children().empty()) decState = "available";
                                else decState = "pending";
                            }
                            std::error_code ec;
                            const auto size = fs::file_size(pathutil::fromUtf8(r->apkPath), ec);
                            list.push(Json::obj({{"apk", r->title},
                                                 {"path", r->apkPath},
                                                 {"size", ec ? 0ull : (unsigned long long)size},
                                                 {"decompiled", decState},
                                                 {"analysis", analysisStateJson(ws.analysis().status(r->title))}}));
                        }
                        return McpToolResult::ok(Json::obj({{"apks", std::move(list)}}));
                    }});

    server.addTool({"apk_info", "APK overview",
                    "Package name, version, SDK levels, debuggable/allowBackup flags, permissions, components "
                    "(activities, services, receivers, providers with exported flags and intent filters) and "
                    "signing certificates.",
                    schema::object({{"apk", apkArg()}}), true, false,
                    [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        ws.resources(apk->title);  // resolves the label and @ref ids
                        const ApkInfo info = ApkInfo::extract(*apk);
                        if (!info.ok) return McpToolResult::error("AndroidManifest.xml could not be decoded");
                        Json perms = Json::array();
                        for (const auto& p : info.permissions) perms.push(p);
                        Json comps = Json::array();
                        for (const auto& c : info.components) {
                            Json actions = Json::array(), cats = Json::array();
                            for (const auto& a : c.actions) actions.push(a);
                            for (const auto& k : c.categories) cats.push(k);
                            comps.push(Json::obj({{"type", c.type}, {"name", c.name}, {"exported", c.exported},
                                                  {"actions", std::move(actions)}, {"categories", std::move(cats)}}));
                        }
                        Json sigs = Json::array();
                        for (const auto& s : info.signatures)
                            sigs.push(Json::obj({{"scheme", s.scheme}, {"sha256", s.certSha256},
                                                 {"subject", s.subject}, {"issuer", s.issuer}}));
                        return McpToolResult::ok(Json::obj({{"apk", apk->title},
                                                            {"package", info.packageName},
                                                            {"version_name", info.versionName},
                                                            {"version_code", info.versionCode},
                                                            {"min_sdk", info.minSdk},
                                                            {"target_sdk", info.targetSdk},
                                                            {"label", info.appLabel},
                                                            {"label_ref", info.appLabelRef},
                                                            {"debuggable", info.debuggable},
                                                            {"allow_backup", info.allowBackup},
                                                            {"permissions", std::move(perms)},
                                                            {"components", std::move(comps)},
                                                            {"signatures", std::move(sigs)}}));
                    }});

    server.addTool({"get_manifest", "AndroidManifest.xml", "Returns the decoded AndroidManifest.xml as text.",
                    schema::object({{"apk", apkArg()}}), true, false,
                    [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        const TreeNode* node = apk->tree ? apk->tree->findChild("AndroidManifest.xml") : nullptr;
                        std::vector<uint8_t> bytes;
                        if (!node || !apk->source->read(*node, bytes))
                            return McpToolResult::error("AndroidManifest.xml not found");
                        std::string xml;
                        if (!AxmlDecoder::decode(bytes, xml, err, ws.resources(apk->title).get()))
                            return McpToolResult::error("decode failed: " + err);
                        McpToolResult r;
                        r.text = json::sanitizeUtf8(xml);
                        return r;
                    }});

    server.addTool({"list_resources", "Resources (resources.arsc)",
                    "Resources of the APK: id, type, name and the value of the default configuration "
                    "(strings, colors, dimensions, references). Filter by type and name/value text.",
                    schema::object({{"apk", apkArg()},
                                    {"type", str("Resource type, e.g. string, color, layout, drawable (optional)")},
                                    {"filter", str("Substring of the name or value")},
                                    {"limit", integer("Max (default 300)", 1, 20000)}}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        auto table = ws.resources(apk->title);
                        if (!table) return McpToolResult::error("the APK has no readable resources.arsc");
                        Json list = Json::array();
                        for (const auto& it : table->list(argStr(args, "type"), argStr(args, "filter"), (size_t)argInt(args, "limit", 300))) {
                            char id[16];
                            std::snprintf(id, sizeof id, "0x%08X", it.id);
                            Json j = Json::obj({{"id", id}, {"type", it.type}, {"name", it.name}});
                            if (it.complex) j.set("complex", true);
                            else j.set("value", json::sanitizeUtf8(it.value));
                            if (it.configs > 1) j.set("configs", it.configs);
                            list.push(std::move(j));
                        }
                        Json types = Json::array();
                        for (const auto& t : table->types()) types.push(t);
                        return McpToolResult::ok(Json::obj({{"package", table->packageName()},
                                                            {"total", (unsigned long long)table->size()},
                                                            {"types", std::move(types)},
                                                            {"resources", std::move(list)}}));
                    }});

    server.addTool({"resolve_resource", "Resolve resource",
                    "Resolves a resource id (0x7F0E0023, or the decimal literal found in code) or a reference "
                    "(@string/app_name) to its type, name and value.",
                    schema::object({{"apk", apkArg()}, {"resource", str("Id (hex or decimal) or @type/name")}}, {"resource"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        auto table = ws.resources(apk->title);
                        if (!table) return McpToolResult::error("the APK has no readable resources.arsc");
                        const std::string spec = argStr(args, "resource");
                        uint32_t id = 0;
                        if (spec.find('/') != std::string::npos) id = table->find(spec);
                        else id = (uint32_t)std::strtoll(spec.c_str(), nullptr, spec.rfind("0x", 0) == 0 || spec.rfind("0X", 0) == 0 ? 16 : 10);
                        ResourceTable::Item it;
                        if (!id || !table->lookup(id, it)) return McpToolResult::error("unknown resource " + spec);
                        char hex[16];
                        std::snprintf(hex, sizeof hex, "0x%08X", it.id);
                        return McpToolResult::ok(Json::obj({{"id", hex}, {"decimal", (long long)(int32_t)it.id},
                                                            {"reference", "@" + it.type + "/" + it.name},
                                                            {"value", json::sanitizeUtf8(it.value)},
                                                            {"complex", it.complex}, {"configs", it.configs}}));
                    }});

    server.addTool({"list_files", "List files",
                    "Lists a directory of the APK archive (root=apk) or of the jadx output (root=decompiled).",
                    schema::object({{"apk", apkArg()},
                                    {"root", strEnum("Which tree to browse", {"apk", "decompiled"})},
                                    {"path", str("Folder path ('' = top level)")},
                                    {"recursive", boolean("List the whole subtree (default false)")},
                                    {"offset", integer("Entries to skip", 0, 100000000)},
                                    {"limit", integer("Maximum entries (default 500)", 1, 5000)}}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Root* root = rootFor(ws, *apk, argStr(args, "root", "apk"), err);
                        if (!root) return McpToolResult::error(err);
                        const TreeNode* folder = findNode(*root, argStr(args, "path"));
                        if (!folder) return McpToolResult::error("path not found");
                        if (!folder->isFolder()) return McpToolResult::error("not a folder");
                        const bool recursive = argBool(args, "recursive", false);
                        const size_t offset = (size_t)argInt(args, "offset", 0);
                        const size_t limit = (size_t)argInt(args, "limit", 500);
                        Json entries = Json::array();
                        size_t index = 0, total = 0;
                        std::vector<const TreeNode*> stack{folder};
                        while (!stack.empty()) {
                            const TreeNode* cur = stack.back();
                            stack.pop_back();
                            const auto& kids = cur->children();
                            for (auto it = kids.rbegin(); it != kids.rend(); ++it)
                                if (recursive && (*it)->isFolder()) stack.push_back(it->get());
                            for (const auto& c : kids) {
                                if (recursive && c->isFolder()) continue;
                                ++total;
                                if (index++ < offset || entries.size() >= limit) continue;
                                Json e = Json::obj({{"path", displayPath(*root, c->path())},
                                                    {"type", c->isFolder() ? "folder" : "file"},
                                                    {"kind", kindName(c->kind())}});
                                uint64_t size = 0;
                                if (!c->isFolder() && root->source->sizeOf(*c, size)) e.set("size", (unsigned long long)size);
                                entries.push(std::move(e));
                            }
                        }
                        return McpToolResult::ok(Json::obj({{"root", root->kind == Root::Kind::Apk ? "apk" : "decompiled"},
                                                            {"total", (unsigned long long)total},
                                                            {"offset", (unsigned long long)offset},
                                                            {"entries", std::move(entries)}}));
                    }});

    server.addTool({"read_file", "Read file",
                    "Reads a file from the APK (binary XML is decoded) or from the jadx output. Text is returned "
                    "as a line window; binary files as a hex dump of the head.",
                    schema::object({{"apk", apkArg()},
                                    {"root", strEnum("Tree", {"apk", "decompiled"})},
                                    {"path", str("File path")},
                                    {"start_line", integer("First line (1-based, default 1)", 1, 100000000)},
                                    {"max_lines", integer("Lines to return (default 400)", 1, 5000)}},
                                   {"path"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Root* root = rootFor(ws, *apk, argStr(args, "root", "apk"), err);
                        if (!root) return McpToolResult::error(err);
                        const TreeNode* node = findNode(*root, argStr(args, "path"));
                        if (!node || node->isFolder()) return McpToolResult::error("file not found");
                        uint64_t size = 0;
                        if (root->source->sizeOf(*node, size) && size > kMaxReadBytes)
                            return McpToolResult::error("file is larger than 4 MB; use hexdump for byte ranges");
                        const int64_t start = argInt(args, "start_line", 1), maxLines = argInt(args, "max_lines", 400);
                        const std::string shown = displayPath(*root, node->path());
                        if (root->kind == Root::Kind::Decompiled) {
                            // Disk files are read off the UI thread.
                            const std::string diskPath = node->path();
                            return McpToolOutcome::later([diskPath, shown, start, maxLines](McpToolContext&) {
                                std::vector<uint8_t> bytes;
                                if (!DiskSource::readFile(diskPath, bytes)) return McpToolResult::error("read failed");
                                Json j = renderContent(bytes, start, maxLines);
                                j.set("path", shown);
                                return McpToolResult::ok(std::move(j));
                            });
                        }
                        std::vector<uint8_t> bytes;
                        if (!root->source->read(*node, bytes)) return McpToolResult::error("read failed");
                        Json j = renderContent(bytes, start, maxLines, ws.resources(apk->title).get());
                        j.set("path", shown);
                        return McpToolResult::ok(std::move(j));
                    }});

    server.addTool({"hexdump", "Hex dump", "Hex dump of a byte range of any APK entry (max 64 KiB per call).",
                    schema::object({{"apk", apkArg()},
                                    {"path", str("Zip entry path")},
                                    {"offset", integer("Start offset", 0, 1ll << 40)},
                                    {"length", integer("Bytes (default 512)", 1, 65536)}},
                                   {"path"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        const TreeNode* node = findNode(*apk, argStr(args, "path"));
                        if (!node || node->isFolder()) return McpToolResult::error("entry not found");
                        const std::string apkPath = apk->apkPath, entry = node->path();
                        const uint64_t offset = (uint64_t)argInt(args, "offset", 0);
                        const size_t length = (size_t)argInt(args, "length", 512);
                        return McpToolOutcome::later([apkPath, entry, offset, length](McpToolContext&) {
                            ApkArchive archive;  // private handle: safe off the UI thread
                            std::vector<uint8_t> bytes;
                            if (!archive.open(apkPath) || !archive.readEntry(entry, bytes, 256ull << 20))
                                return McpToolResult::error("cannot read entry");
                            if (offset >= bytes.size()) return McpToolResult::error("offset beyond end of entry");
                            const size_t n = (size_t)std::min<uint64_t>(length, bytes.size() - offset);
                            McpToolResult r;
                            r.text = entry + " (" + std::to_string(bytes.size()) + " bytes)\n" +
                                     hexDump(bytes.data() + offset, n, offset);
                            return r;
                        });
                    }});

    server.addTool({"search_code", "Search decompiled code",
                    "Searches the jadx output: full text, file names, class / method / field declarations.",
                    schema::object({{"apk", apkArg()},
                                    {"query", str("Text to find (case-insensitive)")},
                                    {"mode", strEnum("Search mode (default text)", {"text", "filenames", "classes", "methods", "fields"})},
                                    {"limit", integer("Maximum hits (default 200)", 1, 2000)}},
                                   {"query"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Root* dec = rootFor(ws, *apk, "decompiled", err);
                        if (!dec || !dec->tree || dec->tree->children().empty())
                            return McpToolResult::error("no decompiled sources yet (jadx output missing)");
                        const std::string modeName = argStr(args, "mode", "text");
                        SearchService::Mode mode = SearchService::Mode::Text;
                        if (modeName == "filenames") mode = SearchService::Mode::Filenames;
                        else if (modeName == "classes") mode = SearchService::Mode::Classes;
                        else if (modeName == "methods") mode = SearchService::Mode::Methods;
                        else if (modeName == "fields") mode = SearchService::Mode::Fields;
                        // Snapshot the file list on the owner thread; scan it
                        // off-thread straight from disk.
                        struct FileRef {
                            std::string disk, shown;
                            NodeKind kind;
                        };
                        std::vector<FileRef> files;
                        std::vector<const TreeNode*> stack{dec->tree.get()};
                        while (!stack.empty()) {
                            const TreeNode* n = stack.back();
                            stack.pop_back();
                            for (const auto& c : n->children()) {
                                if (c->isFolder()) stack.push_back(c.get());
                                else files.push_back({c->path(), displayPath(*dec, c->path()), c->kind()});
                            }
                        }
                        const std::string query = tex::asciiLower(argStr(args, "query"));
                        const size_t limit = (size_t)argInt(args, "limit", 200);
                        return McpToolOutcome::later([files = std::move(files), query, mode, limit](McpToolContext& ctx) {
                            Json hits = Json::array();
                            size_t scanned = 0, skipped = 0;
                            std::vector<uint8_t> buf;
                            for (const FileRef& f : files) {
                                if (ctx.cancelled() || hits.size() >= limit) break;
                                if (ctx.progress && scanned % 500 == 0)
                                    ctx.progress((double)scanned, (double)files.size(), "searching");
                                ++scanned;
                                const std::string_view name(f.shown);
                                if (mode == SearchService::Mode::Filenames) {
                                    if (tex::ciFind(name.substr(name.find_last_of('/') + 1), query) != std::string_view::npos)
                                        hits.push(Json::obj({{"path", f.shown}}));
                                    continue;
                                }
                                if (f.kind != NodeKind::Java && f.kind != NodeKind::Kotlin && f.kind != NodeKind::Xml &&
                                    f.kind != NodeKind::Text && f.kind != NodeKind::Json && f.kind != NodeKind::Smali)
                                    continue;
                                std::error_code ec;
                                if (fs::file_size(pathutil::fromUtf8(f.disk), ec) > kMaxReadBytes) {
                                    ++skipped;
                                    continue;
                                }
                                if (!DiskSource::readFile(f.disk, buf)) continue;
                                const std::string_view text((const char*)buf.data(), buf.size());
                                size_t pos = 0;
                                int lineNo = 1;
                                while (pos <= text.size() && hits.size() < limit) {
                                    size_t end = text.find('\n', pos);
                                    if (end == std::string_view::npos) end = text.size();
                                    std::string_view line = text.substr(pos, end - pos);
                                    if (SearchService::lineMatches(mode, line, query)) {
                                        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
                                        if (line.size() > 300) line = line.substr(0, 300);
                                        hits.push(Json::obj({{"path", f.shown}, {"line", lineNo},
                                                             {"text", json::sanitizeUtf8(line)}}));
                                    }
                                    pos = end + 1;
                                    ++lineNo;
                                }
                            }
                            return McpToolResult::ok(Json::obj({{"hits", std::move(hits)},
                                                                {"files_scanned", (unsigned long long)scanned},
                                                                {"files_skipped_large", (unsigned long long)skipped},
                                                                {"limit_reached", hits.size() >= limit}}));
                        });
                    }});

    server.addTool({"decompile_class", "Decompiled Java source",
                    "Returns the jadx Java source of a class (com.example.Foo or Lcom/example/Foo;).",
                    schema::object({{"apk", apkArg()},
                                    {"class", str("Class name")},
                                    {"start_line", integer("First line (default 1)", 1, 100000000)},
                                    {"max_lines", integer("Lines (default 1000)", 1, 5000)}},
                                   {"class"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Root* dec = rootFor(ws, *apk, "decompiled", err);
                        if (!dec) return McpToolResult::error(err);
                        std::string cls = argStr(args, "class");
                        if (!cls.empty() && cls.front() == 'L' && cls.back() == ';') cls = DexFile::descriptorToJava(cls);
                        std::string disk = ws.symbols().resolve(apk->title, cls);
                        const TreeNode* node = disk.empty() ? findNode(*dec, javaToRelSourcePath(cls)) : dec->tree->findByPath(disk);
                        if (!node || node->isFolder())
                            return McpToolResult::error("no decompiled source for " + cls +
                                                        " (is jadx output available? try search_code mode=classes)");
                        const std::string path = node->path(), shown = displayPath(*dec, path);
                        const int64_t start = argInt(args, "start_line", 1), maxLines = argInt(args, "max_lines", 1000);
                        return McpToolOutcome::later([path, shown, start, maxLines](McpToolContext&) {
                            std::vector<uint8_t> bytes;
                            if (!DiskSource::readFile(path, bytes)) return McpToolResult::error("read failed");
                            Json j = renderContent(bytes, start, maxLines);
                            j.set("path", shown);
                            return McpToolResult::ok(std::move(j));
                        });
                    }});

    // ----------------------------------------------------------------- analysis
    server.addTool({"run_analysis", "Run bytecode analysis",
                    "Parses every classes*.dex and builds the cross-reference index (required by the class, "
                    "method, xref, call graph, CFG and string tools). Long-running: reports progress and can be "
                    "cancelled.",
                    schema::object({{"apk", apkArg()},
                                    {"wait", boolean("Wait for completion (default true)")},
                                    {"force", boolean("Re-run even if a result exists")},
                                    {"timeout_seconds", integer("Max wait (default 300)", 1, 3600)}}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        ws.startAnalysis(apk->title, argBool(args, "force", false));
                        AnalysisService* service = &ws.analysis();
                        const std::string group = apk->title;
                        if (!argBool(args, "wait", true))
                            return McpToolResult::ok(analysisStateJson(service->status(group)));
                        const int64_t timeout = argInt(args, "timeout_seconds", 300);
                        return McpToolOutcome::later([service, group, timeout](McpToolContext& ctx) {
                            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
                            for (;;) {
                                const AnalysisService::Status st = service->status(group);
                                if (st.state != AnalysisService::State::Running) {
                                    Json j = analysisStateJson(st);
                                    if (auto a = service->get(group)) {
                                        const auto& s = a->stats();
                                        Json dexes = Json::array();
                                        for (const auto& d : a->dexes()) dexes.push(d->name());
                                        j.set("stats", Json::obj({{"dex_files", std::move(dexes)},
                                                                  {"classes", (unsigned long long)s.classes},
                                                                  {"methods", (unsigned long long)s.methods},
                                                                  {"methods_with_code", (unsigned long long)s.methodsWithCode},
                                                                  {"instructions", (unsigned long long)s.instructions},
                                                                  {"xrefs", (unsigned long long)s.xrefs}}));
                                    }
                                    return st.state == AnalysisService::State::Failed ? McpToolResult::error(j.dump(true))
                                                                                      : McpToolResult::ok(std::move(j));
                                }
                                if (ctx.cancelled()) {
                                    service->cancel(group);
                                    return McpToolResult::error("cancelled");
                                }
                                if (std::chrono::steady_clock::now() > deadline)
                                    return McpToolResult::ok(analysisStateJson(st));  // still running
                                if (ctx.progress) ctx.progress((double)st.done, (double)st.total, st.phase);
                                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                            }
                        });
                    }});

    // Helper: run a query against the ready analysis off the owner thread.
    auto analysisTool = [&server, &ws](std::string name, std::string title, std::string description, Json schemaJson,
                                       std::function<McpToolResult(const ApkAnalysis&, const Json&, McpToolContext&)> body) {
        server.addTool({std::move(name), std::move(title), std::move(description), std::move(schemaJson), true, false,
                        [&ws, body](const Json& args, McpToolContext&) -> McpToolOutcome {
                            std::string err;
                            Root* apk = resolveApk(ws, args, err);
                            if (!apk) return McpToolResult::error(err);
                            auto a = requireAnalysis(ws, *apk, err);
                            if (!a) return McpToolResult::error(err);
                            return McpToolOutcome::later(
                                [a, args, body](McpToolContext& ctx) { return body(*a, args, ctx); });
                        }});
    };

    analysisTool("dex_info", "DEX files", "DEX files of the APK with version and table sizes, plus analysis statistics.",
                 schema::object({{"apk", apkArg()}}), [](const ApkAnalysis& a, const Json&, McpToolContext&) {
                     Json list = Json::array();
                     for (const auto& d : a.dexes())
                         list.push(Json::obj({{"name", d->name()}, {"version", d->version()},
                                              {"size", (unsigned long long)d->sizeBytes()},
                                              {"strings", d->stringCount()}, {"types", d->typeCount()},
                                              {"methods", d->methodCount()}, {"fields", d->fieldCount()},
                                              {"classes", (unsigned long long)d->classes().size()}}));
                     const auto& s = a.stats();
                     return McpToolResult::ok(Json::obj({{"dex_files", std::move(list)},
                                                         {"classes", (unsigned long long)s.classes},
                                                         {"methods", (unsigned long long)s.methods},
                                                         {"code_bytes", (unsigned long long)s.codeBytes},
                                                         {"xrefs", (unsigned long long)s.xrefs}}));
                 });

    analysisTool("list_classes", "List classes", "Classes defined in the APK's bytecode, filtered by name.",
                 schema::object({{"apk", apkArg()},
                                 {"filter", str("Substring of the class name (package or simple name)")},
                                 {"offset", integer("Skip", 0, 100000000)},
                                 {"limit", integer("Max (default 500)", 1, 5000)}}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const size_t offset = (size_t)argInt(args, "offset", 0), limit = (size_t)argInt(args, "limit", 500);
                     auto all = a.searchClasses(argStr(args, "filter"), offset + limit);
                     Json list = Json::array();
                     for (size_t i = offset; i < all.size(); ++i) {
                         const auto& def = a.classDef(*all[i]);
                         list.push(Json::obj({{"class", DexFile::descriptorToJava(a.classDescriptor(*all[i]))},
                                              {"access", DexFile::accessFlagsToString(def.accessFlags, false)}}));
                     }
                     return McpToolResult::ok(Json::obj({{"classes", std::move(list)}, {"offset", (unsigned long long)offset},
                                                         {"has_more", all.size() >= offset + limit}}));
                 });

    analysisTool("get_class", "Class details",
                 "Superclass chain, interfaces, fields, methods (with access flags and sizes), subclasses and the "
                 "decompiled source path of a class.",
                 schema::object({{"apk", apkArg()}, {"class", str("com.example.Foo or Lcom/example/Foo;")},
                                 {"smali", boolean("Include the full smali disassembly of the class")}},
                                {"class"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const std::string cls = argStr(args, "class");
                     const ApkAnalysis::ClassEntry* c = a.findClass(cls);
                     if (!c) return McpToolResult::error("class not found in the APK bytecode: " + cls);
                     const DexFile& dex = *a.dexes()[c->dex];
                     const auto& def = a.classDef(*c);
                     Json itfs = Json::array();
                     for (uint32_t t : dex.interfaces(def)) itfs.push(DexFile::descriptorToJava(dex.typeDescriptor(t)));
                     Json chain = Json::array();
                     for (auto& s : a.superChain(cls)) chain.push(s);
                     Json fields = Json::array();
                     DexFile::ClassData data;
                     dex.classData(def, data);
                     for (const auto& f : data.fields)
                         fields.push(Json::obj({{"name", std::string(dex.fieldName(f.fieldIdx))},
                                                {"type", DexFile::descriptorToJava(dex.typeDescriptor(dex.fieldType(f.fieldIdx)))},
                                                {"access", DexFile::accessFlagsToString(f.accessFlags, false)}}));
                     Json methods = Json::array();
                     for (const auto& m : a.methodsOf(*c)) methods.push(methodJson(a, m));
                     Json subs = Json::array();
                     for (auto& s : a.subclassesOf(cls, 200)) subs.push(s);
                     Json j = Json::obj({{"class", DexFile::descriptorToJava(a.classDescriptor(*c))},
                                         {"descriptor", std::string(a.classDescriptor(*c))},
                                         {"dex", dex.name()},
                                         {"access", DexFile::accessFlagsToString(def.accessFlags, false)},
                                         {"super_chain", std::move(chain)},
                                         {"interfaces", std::move(itfs)},
                                         {"fields", std::move(fields)},
                                         {"methods", std::move(methods)},
                                         {"direct_subclasses", std::move(subs)},
                                         {"decompiled_path", javaToRelSourcePath(DexFile::descriptorToJava(a.classDescriptor(*c)))}});
                     if (def.sourceFileIdx != DexFile::kNoIndex) j.set("source_file", dex.string(def.sourceFileIdx));
                     if (argBool(args, "smali", false)) j.set("smali", json::sanitizeUtf8(a.disassembleClass(*c)));
                     return McpToolResult::ok(std::move(j));
                 });

    analysisTool("get_method", "Method disassembly",
                 "Smali disassembly of a method plus its callees and constant arguments passed to calls "
                 "(lightweight data flow).",
                 schema::object({{"apk", apkArg()}, {"method", str("Lcom/a/B;->name(I)V or com.a.B.name")}}, {"method"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     std::vector<ApkAnalysis::MethodDef> defs;
                     std::string cls, name, proto, err;
                     if (!resolveMethodArg(a, args, defs, cls, name, proto, err)) return McpToolResult::error(err);
                     Json list = Json::array();
                     for (const auto& m : defs) {
                         Json j = methodJson(a, m);
                         j.set("smali", json::sanitizeUtf8(a.disassemble(m)));
                         Json callees = Json::array();
                         for (const auto& c : a.calleesOf(m))
                             callees.push(Json::obj({{"pc", c.pc}, {"op", c.opcode}, {"target", c.signature}}));
                         j.set("callees", std::move(callees));
                         Json consts = Json::array();
                         for (const auto& c : a.constantArguments(m)) {
                             Json argsJ = Json::array();
                             for (const auto& p : c.args)
                                 argsJ.push(Json::obj({{"position", p.first}, {"value", json::sanitizeUtf8(p.second)}}));
                             consts.push(Json::obj({{"pc", c.pc}, {"callee", c.callee}, {"constant_args", std::move(argsJ)}}));
                         }
                         j.set("constant_arguments", std::move(consts));
                         list.push(std::move(j));
                     }
                     return McpToolResult::ok(Json::obj({{"methods", std::move(list)}}));
                 });

    analysisTool("xrefs", "Cross-references",
                 "Who calls a method, reads/writes a field, uses a string constant or references a type.",
                 schema::object({{"apk", apkArg()},
                                 {"kind", strEnum("What to look up", {"method", "field", "string", "type"})},
                                 {"target", str("method: Lcom/a/B;->m(I)V | field: Lcom/a/B;->f | string: text | type: com.a.B")},
                                 {"substring", boolean("string kind: match substrings (default false)")},
                                 {"limit", integer("Max results (default 200)", 1, 5000)}},
                                {"kind", "target"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const std::string kind = argStr(args, "kind"), target = argStr(args, "target");
                     const size_t limit = (size_t)argInt(args, "limit", 200);
                     std::vector<ApkAnalysis::XrefHit> hits;
                     if (kind == "method") {
                         std::string cls, name, proto;
                         if (!ApkAnalysis::splitMethodRef(target, cls, name, proto))
                             return McpToolResult::error("target must look like Lcom/a/B;->m(I)V");
                         hits = a.callersOf(cls, name, proto, limit);
                     } else if (kind == "field") {
                         const size_t arrow = target.find("->");
                         if (arrow == std::string::npos) return McpToolResult::error("target must look like Lcom/a/B;->field");
                         std::string field = target.substr(arrow + 2);
                         field = field.substr(0, field.find(':'));
                         hits = a.fieldAccesses(target.substr(0, arrow), field, limit);
                     } else if (kind == "string") {
                         hits = a.stringUses(target, argBool(args, "substring", false), limit);
                     } else {
                         hits = a.typeUses(target, limit);
                     }
                     Json list = Json::array();
                     for (const auto& h : hits) list.push(xrefJson(a, h));
                     return McpToolResult::ok(Json::obj({{"count", (unsigned long long)hits.size()},
                                                         {"truncated", hits.size() >= limit},
                                                         {"xrefs", std::move(list)}}));
                 });

    analysisTool("call_graph", "Call graph",
                 "Callers (incoming) or callees (outgoing) of a method, expanded breadth-first up to `depth`.",
                 schema::object({{"apk", apkArg()},
                                 {"method", str("Lcom/a/B;->m(I)V or com.a.B.m")},
                                 {"direction", strEnum("Edge direction (default callees)", {"callers", "callees"})},
                                 {"depth", integer("Levels (default 2)", 1, 5)},
                                 {"limit", integer("Max edges (default 300)", 1, 5000)}},
                                {"method"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext& ctx) {
                     std::vector<ApkAnalysis::MethodDef> defs;
                     std::string cls, name, proto, err;
                     if (!resolveMethodArg(a, args, defs, cls, name, proto, err)) return McpToolResult::error(err);
                     const bool callers = argStr(args, "direction", "callees") == "callers";
                     const int depth = (int)argInt(args, "depth", 2);
                     const size_t limit = (size_t)argInt(args, "limit", 300);
                     Json edges = Json::array();
                     std::set<std::string> seen;
                     std::vector<std::string> frontier;
                     for (const auto& d : defs) frontier.push_back(a.methodSignature(d));
                     for (const auto& f : frontier) seen.insert(f);
                     for (int level = 1; level <= depth && !frontier.empty() && edges.size() < limit; ++level) {
                         std::vector<std::string> next;
                         for (const std::string& sig : frontier) {
                             if (ctx.cancelled() || edges.size() >= limit) break;
                             std::string c, n, p;
                             if (!ApkAnalysis::splitMethodRef(sig, c, n, p)) continue;
                             std::vector<std::string> neighbours;
                             if (callers) {
                                 for (const auto& h : a.callersOf(c, n, p, limit)) neighbours.push_back(a.methodSignature(h.from));
                             } else {
                                 for (const auto& m : a.findMethodDefs(c, n, p))
                                     for (const auto& callee : a.calleesOf(m)) neighbours.push_back(callee.signature);
                             }
                             std::sort(neighbours.begin(), neighbours.end());
                             neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
                             for (const std::string& nb : neighbours) {
                                 if (edges.size() >= limit) break;
                                 edges.push(Json::obj({{"from", callers ? nb : sig}, {"to", callers ? sig : nb}, {"depth", level}}));
                                 if (seen.insert(nb).second) next.push_back(nb);
                             }
                         }
                         frontier = std::move(next);
                     }
                     return McpToolResult::ok(Json::obj({{"direction", callers ? "callers" : "callees"},
                                                         {"edges", std::move(edges)},
                                                         {"nodes", (unsigned long long)seen.size()}}));
                 });

    analysisTool("control_flow_graph", "Control-flow graph",
                 "Basic blocks and edges (normal + exception) of a method, as JSON or Graphviz DOT.",
                 schema::object({{"apk", apkArg()}, {"method", str("Lcom/a/B;->m(I)V")},
                                 {"format", strEnum("Output (default json)", {"json", "dot"})}},
                                {"method"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     std::vector<ApkAnalysis::MethodDef> defs;
                     std::string cls, name, proto, err;
                     if (!resolveMethodArg(a, args, defs, cls, name, proto, err)) return McpToolResult::error(err);
                     const auto& m = defs.front();
                     const auto blocks = a.controlFlowGraph(m);
                     if (argStr(args, "format", "json") == "dot") {
                         McpToolResult r;
                         r.text = a.cfgToDot(m, blocks);
                         return r;
                     }
                     Json bj = Json::array();
                     for (size_t i = 0; i < blocks.size(); ++i) {
                         Json succ = Json::array(), exc = Json::array();
                         for (auto s : blocks[i].successors) succ.push(s);
                         for (auto s : blocks[i].exceptional) exc.push(s);
                         bj.push(Json::obj({{"id", (unsigned long long)i}, {"start_pc", blocks[i].startPc},
                                            {"end_pc", blocks[i].endPc}, {"successors", std::move(succ)},
                                            {"exception_handlers", std::move(exc)}, {"exit", blocks[i].exit}}));
                     }
                     return McpToolResult::ok(Json::obj({{"method", a.methodSignature(m)}, {"blocks", std::move(bj)}}));
                 });

    analysisTool("class_hierarchy", "Class hierarchy", "Superclass chain, direct subclasses and implementers of a type.",
                 schema::object({{"apk", apkArg()}, {"class", str("com.example.Foo")}}, {"class"}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const std::string cls = argStr(args, "class");
                     Json chain = Json::array(), subs = Json::array(), impls = Json::array();
                     for (auto& s : a.superChain(cls)) chain.push(s);
                     for (auto& s : a.subclassesOf(cls, 500)) subs.push(s);
                     for (auto& s : a.implementersOf(cls, 500)) impls.push(s);
                     return McpToolResult::ok(Json::obj({{"class", cls}, {"super_chain", std::move(chain)},
                                                         {"subclasses", std::move(subs)}, {"implementers", std::move(impls)}}));
                 });

    analysisTool("search_strings", "Search strings",
                 "Searches the DEX string tables. category filters with heuristics: url, ip, path (API "
                 "endpoints), secret (key/token-like), email.",
                 schema::object({{"apk", apkArg()},
                                 {"query", str("Substring filter (optional)")},
                                 {"category", strEnum("Category (default any)", {"any", "url", "ip", "path", "secret", "email"})},
                                 {"with_xrefs", boolean("Add up to 5 using methods per string (default false)")},
                                 {"limit", integer("Max (default 300)", 1, 5000)}}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const std::string cat = argStr(args, "category", "any");
                     ApkAnalysis::StringCategory c = ApkAnalysis::StringCategory::Any;
                     if (cat == "url") c = ApkAnalysis::StringCategory::Url;
                     else if (cat == "ip") c = ApkAnalysis::StringCategory::Ip;
                     else if (cat == "path") c = ApkAnalysis::StringCategory::Path;
                     else if (cat == "secret") c = ApkAnalysis::StringCategory::Secret;
                     else if (cat == "email") c = ApkAnalysis::StringCategory::Email;
                     const bool withXrefs = argBool(args, "with_xrefs", false);
                     const auto hits = a.strings(argStr(args, "query"), c, (size_t)argInt(args, "limit", 300));
                     Json list = Json::array();
                     for (const auto& h : hits) {
                         Json j = Json::obj({{"value", json::sanitizeUtf8(h.value)}, {"category", ApkAnalysis::categoryName(h.category)}});
                         if (withXrefs) {
                             Json used = Json::array();
                             for (const auto& x : a.stringUsesAt(h.dex, h.index, 5)) used.push(a.methodSignature(x.from));
                             j.set("used_by", std::move(used));
                         }
                         list.push(std::move(j));
                     }
                     return McpToolResult::ok(Json::obj({{"count", (unsigned long long)hits.size()}, {"strings", std::move(list)}}));
                 });

    analysisTool("find_endpoints", "Network endpoints",
                 "Aggregates URLs, IP addresses and API-like paths from the bytecode with the methods using them.",
                 schema::object({{"apk", apkArg()}, {"limit", integer("Max per category (default 200)", 1, 2000)}}),
                 [](const ApkAnalysis& a, const Json& args, McpToolContext&) {
                     const size_t limit = (size_t)argInt(args, "limit", 200);
                     Json out = Json::object();
                     for (auto c : {ApkAnalysis::StringCategory::Url, ApkAnalysis::StringCategory::Ip,
                                    ApkAnalysis::StringCategory::Path}) {
                         Json list = Json::array();
                         for (const auto& h : a.strings({}, c, limit)) {
                             Json used = Json::array();
                             for (const auto& x : a.stringUsesAt(h.dex, h.index, 3)) used.push(a.methodSignature(x.from));
                             list.push(Json::obj({{"value", json::sanitizeUtf8(h.value)}, {"used_by", std::move(used)}}));
                         }
                         out.set(std::string(ApkAnalysis::categoryName(c)) + "s", std::move(list));
                     }
                     return McpToolResult::ok(std::move(out));
                 });

    // ------------------------------------------------------------------ native
    server.addTool({"list_native_libs", "Native libraries", "Native libraries (lib/<abi>/*.so) shipped in the APK.",
                    schema::object({{"apk", apkArg()}}), true, false,
                    [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Json list = Json::array();
                        const TreeNode* lib = apk->tree ? apk->tree->findChild("lib") : nullptr;
                        if (lib)
                            for (const auto& abi : lib->children())
                                for (const auto& so : abi->children()) {
                                    if (so->isFolder()) continue;
                                    uint64_t size = 0;
                                    apk->source->sizeOf(*so, size);
                                    list.push(Json::obj({{"path", so->path()}, {"abi", abi->name()}, {"size", (unsigned long long)size}}));
                                }
                        return McpToolResult::ok(Json::obj({{"libraries", std::move(list)}}));
                    }});

    server.addTool({"inspect_native_lib", "Inspect native library",
                    "ELF header, sections, segments, DT_NEEDED, exports, imports and JNI entry points of a .so.",
                    schema::object({{"apk", apkArg()},
                                    {"path", str("Entry path, e.g. lib/arm64-v8a/libfoo.so")},
                                    {"symbol_filter", str("Only symbols containing this text")},
                                    {"include_strings", boolean("Include printable strings from .rodata (default false)")},
                                    {"limit", integer("Max symbols per list (default 300)", 1, 20000)}},
                                   {"path"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        const TreeNode* node = findNode(*apk, argStr(args, "path"));
                        if (!node || node->isFolder()) return McpToolResult::error("entry not found");
                        AnalysisService* service = &ws.analysis();
                        const std::string apkPath = apk->apkPath, entry = node->path();
                        return McpToolOutcome::later([service, apkPath, entry, args](McpToolContext&) {
                            std::string e;
                            auto elf = service->loadElf(apkPath, entry, e);
                            if (!elf) return McpToolResult::error(e);
                            const std::string filter = argStr(args, "symbol_filter");
                            const size_t limit = (size_t)argInt(args, "limit", 300);
                            const auto symList = [&](const std::vector<const ElfFile::Symbol*>& syms) {
                                Json l = Json::array();
                                for (const auto* s : syms) {
                                    if (l.size() >= limit) break;
                                    if (!filter.empty() && tex::ciFind(s->name, filter) == std::string_view::npos) continue;
                                    Json j = Json::obj({{"name", json::sanitizeUtf8(s->name)}, {"value", (unsigned long long)s->value},
                                                        {"size", (unsigned long long)s->size}});
                                    const std::string dem = ElfFile::demangle(s->name);
                                    if (dem != s->name) j.set("demangled", json::sanitizeUtf8(dem));
                                    l.push(std::move(j));
                                }
                                return l;
                            };
                            Json sections = Json::array();
                            for (const auto& s : elf->sections())
                                sections.push(Json::obj({{"name", s.name}, {"type", s.type}, {"addr", (unsigned long long)s.addr},
                                                         {"offset", (unsigned long long)s.offset}, {"size", (unsigned long long)s.size}}));
                            Json segs = Json::array();
                            for (const auto& s : elf->segments()) {
                                std::string flags = std::string(s.flags & 4 ? "R" : "-") + (s.flags & 2 ? "W" : "-") + (s.flags & 1 ? "X" : "-");
                                segs.push(Json::obj({{"type", s.type}, {"flags", flags}, {"vaddr", (unsigned long long)s.vaddr},
                                                     {"offset", (unsigned long long)s.offset}, {"filesz", (unsigned long long)s.filesz},
                                                     {"memsz", (unsigned long long)s.memsz}}));
                            }
                            Json needed = Json::array();
                            for (const auto& n : elf->needed()) needed.push(n);
                            Json warnings = Json::array();
                            for (const auto& w : elf->warnings()) warnings.push(w);
                            Json j = Json::obj({{"path", entry},
                                                {"class", elf->is64() ? "ELF64" : "ELF32"},
                                                {"machine", elf->machineName()},
                                                {"type", elf->typeName()},
                                                {"soname", elf->soname()},
                                                {"needed", std::move(needed)},
                                                {"sections", std::move(sections)},
                                                {"segments", std::move(segs)},
                                                {"jni", symList(elf->jniSymbols())},
                                                {"exports", symList(elf->exports())},
                                                {"imports", symList(elf->imports())},
                                                {"warnings", std::move(warnings)}});
                            if (argBool(args, "include_strings", false)) {
                                Json strs = Json::array();
                                for (const auto& s : elf->strings(6, limit))
                                    strs.push(Json::obj({{"offset", (unsigned long long)s.offset}, {"value", s.value}}));
                                j.set("strings", std::move(strs));
                            }
                            return McpToolResult::ok(std::move(j));
                        });
                    }});

    // ----------------------------------------------------------------- native code (AArch64)
    // Resolves apk + path on the owner thread, then builds / reuses the code analysis in the continuation.
    const auto nativeTool = [&server, &ws](std::string name, std::string title, std::string description, Json props,
                                           std::vector<std::string> required,
                                           std::function<McpToolResult(const NativeCode&, const Json&)> body) {
        props.set("apk", apkArg());
        props.set("path", str("Library entry, e.g. lib/arm64-v8a/libfoo.so (see list_native_libs)"));
        required.insert(required.begin(), "path");
        Json req = Json::array();
        for (const auto& r : required) req.push(Json(r));
        Json schemaJson = Json::obj({{"type", "object"}});
        schemaJson.set("properties", std::move(props));
        schemaJson.set("required", std::move(req));
        schemaJson.set("additionalProperties", false);
        server.addTool({std::move(name), std::move(title), std::move(description), std::move(schemaJson), true, false,
                        [&ws, body](const Json& args, McpToolContext&) -> McpToolOutcome {
                            std::string err;
                            Root* apk = resolveApk(ws, args, err);
                            if (!apk) return McpToolResult::error(err);
                            const TreeNode* node = findNode(*apk, argStr(args, "path"));
                            if (!node || node->isFolder()) return McpToolResult::error("entry not found");
                            AnalysisService* service = &ws.analysis();
                            const std::string apkPath = apk->apkPath, entry = node->path();
                            return McpToolOutcome::later([service, apkPath, entry, args, body](McpToolContext& ctx) {
                                std::string e;
                                if (ctx.progress) ctx.progress(0, 1, "disassembling " + entry);
                                auto code = service->loadNative(apkPath, entry, ctx.cancel, e);
                                if (!code) return McpToolResult::error(e);
                                return body(*code, args);
                            });
                        }});
    };
    const auto hexStr = [](uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
        return std::string(b);
    };
    const auto parseAddr = [](const std::string& s, uint64_t& out) {
        if (s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
        char* end = nullptr;
        out = std::strtoull(s.c_str() + 2, &end, 16);
        return end && *end == 0;
    };
    const auto refKind = [](NativeCode::RefKind k) {
        return k == NativeCode::RefKind::Call ? "call" : k == NativeCode::RefKind::Jump ? "jump"
               : k == NativeCode::RefKind::Read ? "read" : "address";
    };

    nativeTool("native_functions", "Native functions",
               "Functions of an arm64 native library: symbols, PLT import stubs (name@plt) and unnamed call "
               "targets (sub_<addr>), with address, size and whether they are exported / JNI entry points.",
               Json::obj({{"filter", str("Only names containing this text (raw or demangled)")},
                          {"exported_only", boolean("Only exported functions")},
                          {"limit", integer("Max functions (default 300)", 1, 50000)}}),
               {}, [hexStr](const NativeCode& nc, const Json& args) {
                   const std::string filter = argStr(args, "filter");
                   const bool exportedOnly = argBool(args, "exported_only", false);
                   const size_t limit = (size_t)argInt(args, "limit", 300);
                   Json list = Json::array();
                   size_t matched = 0;
                   for (const auto& f : nc.functions()) {
                       if (exportedOnly && !f.exported) continue;
                       const std::string dem = NativeCode::displayName(f);
                       if (!filter.empty() && tex::ciFind(f.name, filter) == std::string_view::npos &&
                           tex::ciFind(dem, filter) == std::string_view::npos)
                           continue;
                       if (++matched > limit) continue;
                       Json j = Json::obj({{"name", json::sanitizeUtf8(f.name)}, {"address", hexStr(f.addr)},
                                           {"size", (unsigned long long)f.size},
                                           {"kind", f.kind == NativeCode::FunctionKind::Plt ? "import_stub"
                                                    : f.kind == NativeCode::FunctionKind::Discovered ? "discovered"
                                                                                                     : "symbol"}});
                       if (dem != f.name) j.set("demangled", json::sanitizeUtf8(dem));
                       if (f.exported) j.set("exported", true);
                       list.push(std::move(j));
                   }
                   return McpToolResult::ok(Json::obj({{"total_functions", (unsigned long long)nc.functions().size()},
                                                       {"matched", (unsigned long long)matched},
                                                       {"instructions", (unsigned long long)nc.instructionCount()},
                                                       {"functions", std::move(list)}}));
               });

    nativeTool("disassemble_native", "Disassemble native code",
               "AArch64 disassembly of a function (by name, demangled name or 0x address) or of an address "
               "range. Call targets are named (imports as name@plt) and adrp+add/ldr pairs are resolved to the "
               "string literal, GOT slot or symbol they address.",
               Json::obj({{"function", str("Function name or 0x address inside it")},
                          {"address", str("Start address (0x...) instead of a function")},
                          {"count", integer("Max instructions (default 400)", 1, 20000)}}),
               {}, [hexStr, parseAddr](const NativeCode& nc, const Json& args) {
                   const size_t count = (size_t)argInt(args, "count", 400);
                   std::vector<NativeCode::Line> lines;
                   Json head = Json::object();
                   const std::string fn = argStr(args, "function"), at = argStr(args, "address");
                   if (!fn.empty()) {
                       const NativeCode::Function* f = nc.findFunction(fn);
                       if (!f) return McpToolResult::error("no function matches '" + fn + "' (see native_functions)");
                       lines = nc.disassembleFunction(*f, count);
                       head = Json::obj({{"function", json::sanitizeUtf8(NativeCode::displayName(*f))},
                                         {"address", hexStr(f->addr)}, {"size", (unsigned long long)f->size}});
                   } else {
                       uint64_t a = 0;
                       if (!parseAddr(at, a)) return McpToolResult::error("give function or address (0x...)");
                       lines = nc.disassemble(a, UINT64_MAX, count);
                       if (lines.empty()) return McpToolResult::error("no code at " + at);
                       if (const auto* f = nc.functionAt(a)) head.set("function", json::sanitizeUtf8(nc.symbolize(a)));
                       head.set("address", hexStr(a));
                   }
                   std::string text;
                   for (const auto& l : lines) {
                       char row[64];
                       std::snprintf(row, sizeof row, "%08llx  %-8s ", (unsigned long long)l.insn.addr, l.insn.mnemonic.c_str());
                       text += row + l.insn.operands;
                       if (!l.targetName.empty()) text += " <" + l.targetName + ">";
                       if (!l.comment.empty()) text += "    ; " + l.comment;
                       text += "\n";
                   }
                   head.set("instructions", (unsigned long long)lines.size());
                   head.set("listing", json::sanitizeUtf8(text));
                   return McpToolResult::ok(std::move(head));
               });

    nativeTool("native_xrefs", "Native cross-references",
               "References in an arm64 library: who calls / jumps to / takes the address of a function or "
               "address (direction 'to'), or what a function calls and references (direction 'from').",
               Json::obj({{"target", str("Function name or 0x address")},
                          {"direction", strEnum("to (default) or from", {"to", "from"})},
                          {"limit", integer("Max references (default 300)", 1, 20000)}}),
               {"target"}, [hexStr, parseAddr, refKind](const NativeCode& nc, const Json& args) {
                   const std::string target = argStr(args, "target");
                   const size_t limit = (size_t)argInt(args, "limit", 300);
                   uint64_t addr = 0;
                   const NativeCode::Function* f = nullptr;
                   if (parseAddr(target, addr)) {
                       f = nc.functionAt(addr);
                   } else {
                       f = nc.findFunction(target);
                       if (!f) return McpToolResult::error("no function matches '" + target + "'");
                       addr = f->addr;
                   }
                   Json list = Json::array();
                   if (argStr(args, "direction") == "from") {
                       if (!f) return McpToolResult::error("no function at " + target);
                       for (const auto& r : nc.refsFrom(*f, limit)) {
                           Json j = Json::obj({{"kind", refKind(r.kind)}, {"at", hexStr(r.from)}, {"target", hexStr(r.target)}});
                           if (std::string s = nc.symbolize(r.target); !s.empty()) j.set("target_name", json::sanitizeUtf8(s));
                           if (r.kind == NativeCode::RefKind::Data)
                               if (std::string str = nc.cStringAt(r.target); !str.empty()) j.set("string", json::sanitizeUtf8(str));
                           list.push(std::move(j));
                       }
                   } else {
                       for (const auto& r : nc.refsTo(addr, limit)) {
                           Json j = Json::obj({{"kind", refKind(r.kind)}, {"from", hexStr(r.from)}});
                           if (std::string s = nc.symbolize(r.from); !s.empty()) j.set("from_function", json::sanitizeUtf8(s));
                           list.push(std::move(j));
                       }
                   }
                   Json out = Json::obj({{"target", hexStr(addr)}, {"references", std::move(list)}});
                   if (f) out.set("function", json::sanitizeUtf8(NativeCode::displayName(*f)));
                   return McpToolResult::ok(std::move(out));
               });

    nativeTool("native_cfg", "Native control-flow graph",
               "Basic blocks of an arm64 function with their successors (taken / fallthrough), for reasoning about "
               "its structure. Indirect jumps (branch tables) end a block without successors.",
               Json::obj({{"function", str("Function name or 0x address inside it")},
                          {"max_instructions", integer("Max instructions (default 20000)", 1, 200000)}}),
               {"function"}, [hexStr](const NativeCode& nc, const Json& args) {
                   const std::string fn = argStr(args, "function");
                   const NativeCode::Function* f = nc.findFunction(fn);
                   if (!f) return McpToolResult::error("no function matches '" + fn + "' (see native_functions)");
                   const auto cfg = nc.controlFlow(*f, (size_t)argInt(args, "max_instructions", 20000));
                   Json blocks = Json::array();
                   for (size_t i = 0; i < cfg.blocks.size(); ++i) {
                       const auto& b = cfg.blocks[i];
                       Json successors = Json::array();
                       for (size_t k = 0; k < b.successors.size(); ++k) {
                           const int to = b.successors[k];
                           Json edge = Json::obj({{"block", to}, {"address", hexStr(cfg.lines[cfg.blocks[(size_t)to].firstLine].insn.addr)}});
                           if (b.conditional) edge.set("kind", k == 0 ? "taken" : "fallthrough");
                           successors.push(std::move(edge));
                       }
                       Json j = Json::obj({{"block", (int)i},
                                           {"address", hexStr(cfg.lines[b.firstLine].insn.addr)},
                                           {"instructions", (unsigned long long)b.lineCount},
                                           {"successors", std::move(successors)}});
                       if (b.exit) j.set("exit", true);
                       blocks.push(std::move(j));
                   }
                   return McpToolResult::ok(Json::obj({{"function", json::sanitizeUtf8(NativeCode::displayName(*f))},
                                                       {"address", hexStr(f->addr)},
                                                       {"blocks", std::move(blocks)}}));
               });

    nativeTool("native_strings", "Native string references",
               "String literals that arm64 code actually references (through adrp + add / ldr), each with the "
               "function that uses it - more precise than scanning .rodata.",
               Json::obj({{"filter", str("Only strings containing this text")},
                          {"limit", integer("Max results (default 300)", 1, 20000)}}),
               {}, [hexStr](const NativeCode& nc, const Json& args) {
                   Json list = Json::array();
                   for (const auto& s : nc.stringRefs(argStr(args, "filter"), (size_t)argInt(args, "limit", 300))) {
                       Json j = Json::obj({{"string", json::sanitizeUtf8(s.text)}, {"address", hexStr(s.addr)},
                                           {"used_at", hexStr(s.from)}});
                       if (std::string fn = nc.symbolize(s.from); !fn.empty()) j.set("function", json::sanitizeUtf8(fn));
                       list.push(std::move(j));
                   }
                   return McpToolResult::ok(Json::obj({{"strings", std::move(list)}}));
               });

    // ----------------------------------------------------------------- annotations
    const auto annotationJson = [&ws, hexStr](const Annotation& a) {
        Json j = Json::obj({{"id", a.id},
                            {"kind", a.kind == Annotation::Kind::Comment ? "comment" : "bookmark"},
                            {"apk", a.group},
                            {"text", json::sanitizeUtf8(a.text)}});
        if (a.target == Annotation::Target::Native) {
            j.set("path", a.path);
            j.set("address", hexStr(a.addr));
        } else {
            const Root* root = ws.rootByGroup(a.group, a.root);
            j.set("path", root ? displayPath(*root, a.path) : a.path);
            j.set("root", a.root == RootKind::Decompiled ? "decompiled" : "apk");
            j.set("line", a.line + 1);
        }
        if (!a.context.empty()) j.set("context", json::sanitizeUtf8(a.context));
        return j;
    };

    server.addTool({"list_annotations", "List bookmarks and comments",
                    "The user's bookmarks and comments (on file lines and native addresses), which are also a good "
                    "summary of what is already known about the APK.",
                    schema::object({{"apk", str("Only this APK group")},
                                    {"kind", strEnum("Only this kind", {"bookmark", "comment"})},
                                    {"filter", str("Only annotations whose text, context or path contains this")},
                                    {"limit", integer("Max results (default 500)", 1, 100000)}}),
                    true, false, [&ws, annotationJson](const Json& args, McpToolContext&) -> McpToolOutcome {
                        const std::string group = argStr(args, "apk"), kind = argStr(args, "kind"), filter = argStr(args, "filter");
                        const size_t limit = (size_t)argInt(args, "limit", 500);
                        Json list = Json::array();
                        for (const Annotation& a : ws.annotations().all()) {
                            if (list.size() >= limit) break;
                            if (!group.empty() && a.group != group) continue;
                            if (!kind.empty() && (kind == "comment") != (a.kind == Annotation::Kind::Comment)) continue;
                            if (!filter.empty() && tex::ciFind(a.text, filter) == std::string_view::npos &&
                                tex::ciFind(a.context, filter) == std::string_view::npos &&
                                tex::ciFind(a.path, filter) == std::string_view::npos)
                                continue;
                            list.push(annotationJson(a));
                        }
                        return McpToolResult::ok(Json::obj({{"total", (unsigned long long)ws.annotations().all().size()},
                                                            {"annotations", std::move(list)}}));
                    }});

    server.addTool({"add_annotation", "Add bookmark or comment",
                    "Leaves a bookmark or comment for the user on a file line (path + line) or a native library "
                    "address (path + address). The same kind at the same place is replaced. Saved with the project.",
                    schema::object({{"apk", apkArg()},
                                    {"kind", strEnum("Kind", {"bookmark", "comment"})},
                                    {"path", str("File path, or library entry when address is given")},
                                    {"root", strEnum("Tree of a file (default apk)", {"apk", "decompiled"})},
                                    {"line", integer("1-based line of a file (default 1)", 1, 100000000)},
                                    {"address", str("Native address, 0x...")},
                                    {"text", str("Comment text / bookmark label")}},
                                   {"kind", "path"}),
                    false, false, [&ws, annotationJson, parseAddr](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Root* apk = resolveApk(ws, args, err);
                        if (!apk) return McpToolResult::error(err);
                        Annotation a;
                        a.kind = argStr(args, "kind") == "comment" ? Annotation::Kind::Comment : Annotation::Kind::Bookmark;
                        a.text = argStr(args, "text");
                        a.group = apk->title;
                        if (a.kind == Annotation::Kind::Comment && a.text.empty()) return McpToolResult::error("a comment needs text");
                        const bool native = args.has("address");
                        Root* root = native ? apk : rootFor(ws, *apk, argStr(args, "root", "apk"), err);
                        if (!root) return McpToolResult::error(err);
                        const TreeNode* node = findNode(*root, argStr(args, "path"));
                        if (!node || node->isFolder()) return McpToolResult::error("file not found");
                        a.path = node->path();
                        if (native) {
                            a.target = Annotation::Target::Native;
                            if (!parseAddr(argStr(args, "address"), a.addr)) return McpToolResult::error("address must be 0x...");
                        } else {
                            a.root = root->kind;
                            a.line = (int)argInt(args, "line", 1) - 1;
                        }
                        const int id = ws.annotations().set(std::move(a));
                        if (!id) return McpToolResult::error("annotation rejected (limit reached)");
                        return McpToolResult::ok(annotationJson(*ws.annotations().find(id)));
                    }});

    server.addTool({"remove_annotation", "Remove bookmark or comment", "Deletes an annotation by the id from list_annotations.",
                    schema::object({{"id", integer("Annotation id", 1, 1 << 30)}}, {"id"}), false, false,
                    [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        if (!ws.annotations().remove((int)argInt(args, "id", 0))) return McpToolResult::error("no such annotation");
                        return McpToolResult::ok(Json::obj({{"removed", true}}));
                    }});

    // ----------------------------------------------------------------- compare
    server.addTool({"compare_apks", "Compare APKs",
                    "Compares two APKs of the project: archive entries, manifest facts and (when both analyses "
                    "are ready) added/removed classes and changed method bodies.",
                    schema::object({{"apk_a", str("Old APK group")}, {"apk_b", str("New APK group")},
                                    {"limit", integer("Max items per list (default 300)", 1, 5000)}},
                                   {"apk_a", "apk_b"}),
                    true, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                        std::string err;
                        Json ja = Json::obj({{"apk", args.get("apk_a")}}), jb = Json::obj({{"apk", args.get("apk_b")}});
                        Root* a = resolveApk(ws, ja, err);
                        Root* b = a ? resolveApk(ws, jb, err) : nullptr;
                        if (!a || !b) return McpToolResult::error(err);
                        auto* archA = dynamic_cast<ApkArchive*>(a->source.get());
                        auto* archB = dynamic_cast<ApkArchive*>(b->source.get());
                        if (!archA || !archB) return McpToolResult::error("not APK archives");
                        ApkDiff diff = ApkDiff::compareEntries(archA->entries(), archB->entries());
                        ws.resources(a->title);
                        ws.resources(b->title);
                        const ApkInfo ia = ApkInfo::extract(*a), ib = ApkInfo::extract(*b);
                        auto anA = ws.analysis().get(a->title), anB = ws.analysis().get(b->title);
                        const size_t limit = (size_t)argInt(args, "limit", 300);
                        return McpToolOutcome::later([diff = std::move(diff), ia, ib, anA, anB, limit](McpToolContext& ctx) mutable {
                            if (anA && anB) diff.compareCode(*anA, *anB, limit, ctx.cancel);
                            Json entries = Json::array();
                            for (const auto& e : diff.entries) {
                                if (entries.size() >= limit) break;
                                entries.push(Json::obj({{"path", e.path}, {"change", ApkDiff::kindName(e.kind)},
                                                        {"size_a", (unsigned long long)e.sizeA}, {"size_b", (unsigned long long)e.sizeB}}));
                            }
                            std::set<std::string> pa(ia.permissions.begin(), ia.permissions.end());
                            std::set<std::string> pb(ib.permissions.begin(), ib.permissions.end());
                            Json permAdded = Json::array(), permRemoved = Json::array();
                            for (const auto& p : pb)
                                if (!pa.count(p)) permAdded.push(p);
                            for (const auto& p : pa)
                                if (!pb.count(p)) permRemoved.push(p);
                            const auto list = [](const std::vector<std::string>& v) {
                                Json l = Json::array();
                                for (const auto& s : v) l.push(s);
                                return l;
                            };
                            Json j = Json::obj({{"version_a", ia.versionName + " (" + ia.versionCode + ")"},
                                                {"version_b", ib.versionName + " (" + ib.versionCode + ")"},
                                                {"entries_changed", (unsigned long long)diff.entries.size()},
                                                {"entries_unchanged", (unsigned long long)diff.entriesUnchanged},
                                                {"entries", std::move(entries)},
                                                {"permissions_added", std::move(permAdded)},
                                                {"permissions_removed", std::move(permRemoved)}});
                            if (diff.codeCompared) {
                                j.set("classes_added", list(diff.classesAdded));
                                j.set("classes_removed", list(diff.classesRemoved));
                                j.set("methods_added", list(diff.methodsAdded));
                                j.set("methods_removed", list(diff.methodsRemoved));
                                j.set("methods_changed", list(diff.methodsChanged));
                                j.set("code_lists_truncated", diff.truncated);
                            } else {
                                j.set("code_comparison", "skipped - run run_analysis on both APKs first");
                            }
                            return McpToolResult::ok(std::move(j));
                        });
                    }});

    // --------------------------------------------------------------- UI bridge
    if (env.gui && env.showPanel) {
        auto showPanel = env.showPanel;
        server.addTool({"show_panel", "Show panel",
                        "Brings an ApkSpy panel to the front for the user, switching workspace if needed: Explorer, Overview, Editor, Analysis, "
                        "Debugger, Devices, Output, Search, Logcat, Traffic, Bookmarks or Script.",
                        schema::object({{"panel", str("Panel title")}}, {"panel"}), false, false,
                        [showPanel](const Json& args, McpToolContext&) -> McpToolOutcome {
                            const std::string panel = argStr(args, "panel");
                            if (!showPanel(panel)) return McpToolResult::error("unknown panel: " + panel);
                            return McpToolResult::ok(Json::obj({{"shown", panel}}));
                        }});
    }
    if (env.gui) {
        server.addTool({"open_in_editor", "Open in ApkSpy",
                        "Opens a file in the ApkSpy editor (optionally at a 1-based line) so the user sees what "
                        "you are looking at.",
                        schema::object({{"apk", apkArg()}, {"root", strEnum("Tree", {"apk", "decompiled"})},
                                        {"path", str("File path")}, {"line", integer("1-based line", 1, 100000000)}},
                                       {"path"}),
                        false, false, [&ws](const Json& args, McpToolContext&) -> McpToolOutcome {
                            std::string err;
                            Root* apk = resolveApk(ws, args, err);
                            if (!apk) return McpToolResult::error(err);
                            Root* root = rootFor(ws, *apk, argStr(args, "root", "apk"), err);
                            if (!root) return McpToolResult::error(err);
                            const TreeNode* node = findNode(*root, argStr(args, "path"));
                            if (!node || node->isFolder()) return McpToolResult::error("file not found");
                            NavLocation origin;
                            const NavLocation* originPtr = nullptr;
                            if (Document* d = ws.activeDocument()) {
                                origin = ws.locationOf(*d);
                                originPtr = &origin;
                            }
                            ws.navigateTo(*root, *node, (int)argInt(args, "line", 1) - 1, originPtr);
                            return McpToolResult::ok(Json::obj({{"opened", displayPath(*root, node->path())}}));
                        }});
    }

    if (env.gui) {
        server.addTool({"show_method", "Show a method in ApkSpy",
                        "Opens a bytecode method for the user: its smali listing, control-flow graph or call graph. "
                        "Needs run_analysis first.",
                        schema::object({{"apk", apkArg()},
                                        {"method", str("Method, e.g. Lcom/a/B;->name(I)V or com.a.B.name")},
                                        {"view", strEnum("What to show (default listing)", {"listing", "graph", "calls"})}},
                                       {"method"}),
                        false, false, [&ws, showPanel = env.showPanel](const Json& args, McpToolContext&) -> McpToolOutcome {
                            std::string err;
                            Root* apk = resolveApk(ws, args, err);
                            if (!apk) return McpToolResult::error(err);
                            auto analysis = ws.analysis().get(apk->title);
                            if (!analysis) return McpToolResult::error("run run_analysis first");
                            const std::string method = argStr(args, "method");
                            std::string cls, name, proto;
                            if (!ApkAnalysis::splitMethodRef(method, cls, name, proto) || analysis->findMethodDefs(cls, name, proto).empty())
                                return McpToolResult::error("no bytecode for " + method);
                            ws.requestMethodView({apk->title, method, argStr(args, "view", "listing")});
                            if (showPanel) showPanel("Analysis");
                            return McpToolResult::ok(Json::obj({{"shown", method}}));
                        }});
        server.addTool({"show_native", "Show native code in ApkSpy",
                        "Opens the Analysis panel's native view on a function or address of an arm64 library so "
                        "the user sees the disassembly you are discussing.",
                        schema::object({{"apk", apkArg()},
                                        {"path", str("Library entry, e.g. lib/arm64-v8a/libfoo.so")},
                                        {"target", str("Function name or 0x address")},
                                        {"view", strEnum("What to show (default: keep the current view)", {"listing", "graph", "calls"})}},
                                       {"path", "target"}),
                        false, false, [&ws, showPanel = env.showPanel](const Json& args, McpToolContext&) -> McpToolOutcome {
                            std::string err;
                            Root* apk = resolveApk(ws, args, err);
                            if (!apk) return McpToolResult::error(err);
                            const TreeNode* node = findNode(*apk, argStr(args, "path"));
                            if (!node || node->isFolder()) return McpToolResult::error("entry not found");
                            ws.requestNativeView({apk->title, node->path(), argStr(args, "target"), argStr(args, "view")});
                            if (showPanel) showPanel("Analysis");
                            return McpToolResult::ok(Json::obj({{"shown", node->path()}, {"target", argStr(args, "target")}}));
                        }});
    }

    // ----------------------------------------------------------------- devices
    if (!devices) return;
    DeviceService& dev = *devices;

    server.addTool({"device_list", "Devices", "Connected Android devices and emulators (adb devices -l).",
                    schema::object({}), true, true, [&dev](const Json&, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev](McpToolContext&) {
                            std::string err;
                            auto list = dev.adb().devices(err);
                            if (!err.empty() && list.empty()) return McpToolResult::error(err);
                            Json l = Json::array();
                            for (const auto& d : list) l.push(deviceJson(d));
                            return McpToolResult::ok(Json::obj({{"devices", std::move(l)}, {"selected", dev.selected()}}));
                        });
                    }});

    server.addTool({"device_info", "Device properties", "Model, Android version, ABI and build flags of a device.",
                    schema::object({{"serial", str("Device serial (optional)")}}), true, true,
                    [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            Json props = Json::object();
                            for (const auto& kv : dev.adb().properties(serial, err)) props.set(kv.first, kv.second);
                            return McpToolResult::ok(Json::obj({{"serial", serial}, {"properties", std::move(props)}}));
                        });
                    }});

    server.addTool({"device_processes", "Processes", "Processes on the device (marks JDWP-debuggable ones).",
                    schema::object({{"serial", str("Device serial (optional)")}, {"filter", str("Name substring")},
                                    {"limit", integer("Max (default 300)", 1, 5000)}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            auto procs = dev.adb().processes(serial, err);
                            std::string jerr;
                            const auto jdwp = dev.adb().jdwpPids(serial, 1200, jerr);
                            const std::string filter = argStr(args, "filter");
                            const size_t limit = (size_t)argInt(args, "limit", 300);
                            Json l = Json::array();
                            for (const auto& p : procs) {
                                if (l.size() >= limit) break;
                                if (!filter.empty() && tex::ciFind(p.name, filter) == std::string_view::npos) continue;
                                l.push(Json::obj({{"pid", p.pid}, {"ppid", p.ppid}, {"user", p.user}, {"name", p.name},
                                                  {"rss_kb", (unsigned long long)p.rssKb},
                                                  {"debuggable", std::find(jdwp.begin(), jdwp.end(), p.pid) != jdwp.end()}}));
                            }
                            if (procs.empty() && !err.empty()) return McpToolResult::error(err);
                            return McpToolResult::ok(Json::obj({{"serial", serial}, {"processes", std::move(l)}}));
                        });
                    }});

    server.addTool({"logcat_read", "Read Logcat",
                    "Reads buffered Logcat lines (starts streaming the device log on first use). Use `since` with "
                    "the returned `head` to poll for new lines only.",
                    schema::object({{"serial", str("Device serial (optional)")},
                                    {"since", integer("Only entries after this sequence number", 0, 1ll << 50)},
                                    {"min_level", strEnum("Minimum level", {"V", "D", "I", "W", "E", "F"})},
                                    {"pid", integer("Only this pid", 1, 1 << 30)},
                                    {"package", str("Only this app (resolved to its pid)")},
                                    {"tag", str("Tag substring")},
                                    {"text", str("Message substring")},
                                    {"max_lines", integer("Max lines (default 300)", 1, 5000)}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            if (!dev.logcatRunning()) {
                                dev.select(serial);
                                if (!dev.startLogcat(serial, err)) return McpToolResult::error(err);
                                std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // let the backlog arrive
                            }
                            DeviceService::LogFilter f;
                            const std::string lvl = argStr(args, "min_level", "V");
                            f.minLevel = lvl.empty() ? 'V' : lvl[0];
                            f.pid = (int)argInt(args, "pid", 0);
                            if (!f.pid && !argStr(args, "package").empty()) {
                                f.pid = resolvePid(dev, serial, args, err);
                                if (!f.pid) return McpToolResult::error(err);
                            }
                            f.tag = argStr(args, "tag");
                            f.text = argStr(args, "text");
                            const auto entries = dev.logEntries((uint64_t)argInt(args, "since", 0), f,
                                                                (size_t)argInt(args, "max_lines", 300));
                            Json l = Json::array();
                            for (const auto& e : entries)
                                l.push(Json::obj({{"seq", (unsigned long long)e.seq}, {"time", e.time}, {"pid", e.pid},
                                                  {"tid", e.tid}, {"level", std::string(1, e.level)},
                                                  {"tag", json::sanitizeUtf8(e.tag)}, {"message", json::sanitizeUtf8(e.message)}}));
                            return McpToolResult::ok(Json::obj({{"head", (unsigned long long)dev.logHead()}, {"lines", std::move(l)}}));
                        });
                    }});

    server.addTool({"process_stats", "Process CPU / memory",
                    "CPU usage (sampled over ~1 s), RSS, thread count and dumpsys meminfo summary of a process.",
                    schema::object({{"serial", str("Device serial (optional)")}, {"pid", integer("Process id", 1, 1 << 30)},
                                    {"package", str("Package name (alternative to pid)")},
                                    {"meminfo", boolean("Include dumpsys meminfo (slower, default true)")}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            const int pid = resolvePid(dev, serial, args, err);
                            if (!pid) return McpToolResult::error(err);
                            const adb::ProcStat a = dev.adb().procStat(serial, pid, err);
                            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                            const adb::ProcStat b = dev.adb().procStat(serial, pid, err);
                            if (!a.ok || !b.ok) return McpToolResult::error("cannot read /proc for pid " + std::to_string(pid) + ": " + err);
                            const double cpu = b.cpuTotalJiffies > a.cpuTotalJiffies
                                                   ? 100.0 * (double)(b.procJiffies - a.procJiffies) /
                                                         (double)(b.cpuTotalJiffies - a.cpuTotalJiffies)
                                                   : 0.0;
                            Json j = Json::obj({{"pid", pid}, {"cpu_percent_of_device", cpu}, {"rss_kb", (unsigned long long)b.rssKb},
                                                {"vm_size_kb", (unsigned long long)b.vmSizeKb}, {"threads", b.threads}});
                            if (argBool(args, "meminfo", true)) {
                                const adb::MemInfo m = dev.adb().memInfo(serial, pid, err);
                                if (m.ok)
                                    j.set("meminfo", Json::obj({{"total_pss_kb", (unsigned long long)m.totalPssKb},
                                                                {"java_heap_kb", (unsigned long long)m.javaHeapKb},
                                                                {"native_heap_kb", (unsigned long long)m.nativeHeapKb},
                                                                {"code_kb", (unsigned long long)m.codeKb},
                                                                {"graphics_kb", (unsigned long long)m.graphicsKb}}));
                            }
                            return McpToolResult::ok(std::move(j));
                        });
                    }});

    server.addTool({"process_threads", "Process threads", "Native threads of a process (ps -T) with their state.",
                    schema::object({{"serial", str("Device serial (optional)")}, {"pid", integer("Process id", 1, 1 << 30)},
                                    {"package", str("Package name")}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            const int pid = resolvePid(dev, serial, args, err);
                            if (!pid) return McpToolResult::error(err);
                            Json l = Json::array();
                            for (const auto& t : dev.adb().threads(serial, pid, err))
                                l.push(Json::obj({{"tid", t.tid}, {"name", t.name}, {"state", t.state}}));
                            return McpToolResult::ok(Json::obj({{"pid", pid}, {"threads", std::move(l)}}));
                        });
                    }});

    server.addTool({"process_backtrace", "Native + Java backtrace",
                    "Dumps all thread stacks of a process through debuggerd (debuggable app or rooted device).",
                    schema::object({{"serial", str("Device serial (optional)")}, {"pid", integer("Process id", 1, 1 << 30)},
                                    {"package", str("Package name")}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            const int pid = resolvePid(dev, serial, args, err);
                            if (!pid) return McpToolResult::error(err);
                            std::string out = dev.adb().backtrace(serial, pid, err);
                            if (out.empty()) return McpToolResult::error(err.empty() ? "no output" : err);
                            McpToolResult r;
                            r.text = json::sanitizeUtf8(out);
                            return r;
                        });
                    }});

    server.addTool({"debugger_state", "Debugger state",
                    "Live JDWP debugger state: attach state, threads, current stack frames, local variables of the "
                    "selected frame, breakpoints and recent events.",
                    schema::object({}), true, true, [&dev](const Json&, McpToolContext&) -> McpToolOutcome {
                        return McpToolResult::ok(debugSnapshotJson(dev.debugger().snapshot()));
                    }});

    server.addTool({"debugger_attach", "Attach debugger",
                    "Attaches the JDWP debugger to a debuggable app process (by pid or package).",
                    schema::object({{"serial", str("Device serial (optional)")}, {"pid", integer("Process id", 1, 1 << 30)},
                                    {"package", str("Package name")}}),
                    false, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            std::string err;
                            const std::string serial = resolveSerial(dev, args, err);
                            if (serial.empty()) return McpToolResult::error(err);
                            const int pid = resolvePid(dev, serial, args, err);
                            if (!pid) return McpToolResult::error(err);
                            dev.debugger().attach(serial, pid);
                            dev.debugger().waitIdle(20000);
                            const auto snap = dev.debugger().snapshot();
                            if (snap.state == DebugSession::State::Failed) return McpToolResult::error(snap.error);
                            return McpToolResult::ok(debugSnapshotJson(snap));
                        });
                    }});

    server.addTool({"debugger_control", "Debugger control",
                    "Execution control of the attached process: suspend, resume, step_into, step_over, step_out, "
                    "refresh_threads, detach.",
                    schema::object({{"action", strEnum("Action", {"suspend", "resume", "step_into", "step_over", "step_out",
                                                                  "refresh_threads", "detach"})}},
                                   {"action"}),
                    false, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            DebugSession& d = dev.debugger();
                            const std::string action = argStr(args, "action");
                            if (action != "detach" && d.state() == DebugSession::State::Detached)
                                return McpToolResult::error("debugger is not attached (use debugger_attach)");
                            if (action == "suspend") d.suspend();
                            else if (action == "resume") d.resume();
                            else if (action == "step_into") d.step(0);
                            else if (action == "step_over") d.step(1);
                            else if (action == "step_out") d.step(2);
                            else if (action == "refresh_threads") d.refreshThreads();
                            else d.detach();
                            d.waitIdle(15000);
                            if (action.rfind("step", 0) == 0) {
                                // Give the step a moment to land on the next line.
                                for (int i = 0; i < 20 && d.state() == DebugSession::State::Running; ++i)
                                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                d.waitIdle(5000);
                            }
                            return McpToolResult::ok(debugSnapshotJson(d.snapshot()));
                        });
                    }});

    server.addTool({"debugger_select", "Select thread / frame",
                    "Selects a thread (loads its stack) and/or a frame (loads its local variables).",
                    schema::object({{"thread_id", integer("Thread id from debugger_state", 0, 1ll << 53)},
                                    {"frame", integer("Frame index", 0, 4096)}}),
                    true, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            DebugSession& d = dev.debugger();
                            if (args.has("thread_id")) d.selectThread((DebugSession::Id)argInt(args, "thread_id", 0));
                            if (args.has("frame")) d.selectFrame((int)argInt(args, "frame", 0));
                            d.waitIdle(15000);
                            return McpToolResult::ok(debugSnapshotJson(d.snapshot()));
                        });
                    }});

    server.addTool({"debugger_inspect", "Inspect object",
                    "Instance fields (along the class chain) of an object, or the first 200 elements of an array, "
                    "from a suspended app. Use the object_id of a local (debugger_state) or of a previous inspect.",
                    schema::object({{"object_id", integer("Object id", 1, 1ll << 53)}}, {"object_id"}), true, true,
                    [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            DebugSession& d = dev.debugger();
                            if (d.state() != DebugSession::State::Suspended)
                                return McpToolResult::error("the app must be suspended (breakpoint, exception or suspend)");
                            const uint64_t id = (uint64_t)argInt(args, "object_id", 0);
                            d.expand(id);
                            d.waitIdle(15000);
                            const auto snap = d.snapshot();
                            auto it = snap.children.find(id);
                            if (it == snap.children.end()) return McpToolResult::error("object not available");
                            Json fields = Json::array();
                            for (const auto& l : it->second) {
                                Json lj = Json::obj({{"name", l.name}, {"type", l.type}, {"value", json::sanitizeUtf8(l.value)}});
                                if (l.objectId) lj.set("object_id", (unsigned long long)l.objectId);
                                fields.push(std::move(lj));
                            }
                            return McpToolResult::ok(Json::obj({{"object_id", (unsigned long long)id}, {"fields", std::move(fields)}}));
                        });
                    }});

    server.addTool({"debugger_breakpoint", "Breakpoints",
                    "Adds (class + method, optional source line) or removes (id) a breakpoint; add_exception stops "
                    "when an exception of a class (or any, when class is omitted) is thrown. Breakpoints on classes "
                    "that are not loaded yet are armed when the class loads.",
                    schema::object({{"action", strEnum("add, add_exception or remove", {"add", "add_exception", "remove"})},
                                    {"class", str("com.example.Foo (exception class for add_exception; optional)")},
                                    {"method", str("Method name (all overloads)")},
                                    {"line", integer("Source line (optional; default = method entry)", 1, 10000000)},
                                    {"caught", boolean("add_exception: stop on caught exceptions (default true)")},
                                    {"uncaught", boolean("add_exception: stop on uncaught exceptions (default true)")},
                                    {"id", integer("Breakpoint id (remove)", 1, 1 << 30)}},
                                   {"action"}),
                    false, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            DebugSession& d = dev.debugger();
                            if (argStr(args, "action") == "add_exception") {
                                const bool caught = argBool(args, "caught", true), uncaught = argBool(args, "uncaught", true);
                                if (!caught && !uncaught) return McpToolResult::error("caught and uncaught cannot both be false");
                                d.addExceptionBreakpoint(argStr(args, "class"), caught, uncaught);
                            } else if (argStr(args, "action") == "add") {
                                const std::string cls = argStr(args, "class"), method = argStr(args, "method");
                                if (cls.empty() || method.empty()) return McpToolResult::error("add needs class and method");
                                d.addBreakpoint(cls, method, args.has("line") ? (int)argInt(args, "line", -1) : -1);
                            } else {
                                if (!args.has("id")) return McpToolResult::error("remove needs id");
                                d.removeBreakpoint((int)argInt(args, "id", 0));
                            }
                            d.waitIdle(15000);
                            return McpToolResult::ok(debugSnapshotJson(d.snapshot()));
                        });
                    }});

    // ----------------------------------------------------------------- traffic
    const auto flowSummary = [](const TrafficProxy::Flow& f) {
        Json j = Json::obj({{"id", (unsigned long long)f.id},
                            {"time", f.startedAt},
                            {"method", f.method},
                            {"url", json::sanitizeUtf8(f.url())},
                            {"host", f.host},
                            {"status", f.status},
                            {"tunnel", f.tunnel},
                            {"complete", f.complete},
                            {"bytes_up", (unsigned long long)f.bytesUp},
                            {"bytes_down", (unsigned long long)f.bytesDown},
                            {"duration_ms", f.durationMs}});
        if (!f.sni.empty()) j.set("sni", f.sni);
        if (!f.tunnel) j.set("content_type", f.contentType());
        if (!f.error.empty()) j.set("error", f.error);
        return j;
    };

    server.addTool({"traffic_status", "Traffic sniffer status",
                    "State of the network sniffer: proxy port, routed device, number of captured requests.",
                    schema::object({}), true, false, [&dev](const Json&, McpToolContext&) -> McpToolOutcome {
                        TrafficProxy& t = dev.traffic();
                        return McpToolResult::ok(Json::obj({{"running", t.running()},
                                                            {"port", t.port()},
                                                            {"routed_device", t.routedSerial()},
                                                            {"captured", (unsigned long long)t.lastId()},
                                                            {"note", "plain HTTP is captured fully; HTTPS appears as "
                                                                     "encrypted CONNECT tunnels (host, SNI, sizes)"}}));
                    }});

    server.addTool({"traffic_control", "Traffic sniffer control",
                    "start / stop the proxy, route the device through it (adb reverse + global http_proxy) or "
                    "restore the device's proxy setting.",
                    schema::object({{"action", strEnum("Action", {"start", "stop", "route_device", "restore_device"})},
                                    {"port", integer("Proxy port for start (default 8899)", 1024, 65535)},
                                    {"serial", str("Device serial (optional)")}},
                                   {"action"}),
                    false, true, [&dev](const Json& args, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([&dev, args](McpToolContext&) {
                            TrafficProxy& t = dev.traffic();
                            const std::string action = argStr(args, "action");
                            std::string err;
                            if (action == "start") {
                                if (!t.running() && !t.start((int)argInt(args, "port", 8899), err)) return McpToolResult::error(err);
                            } else if (action == "stop") {
                                dev.stopTraffic();
                            } else {
                                const std::string serial = resolveSerial(dev, args, err);
                                if (serial.empty()) return McpToolResult::error(err);
                                const bool ok = action == "route_device" ? t.routeDevice(dev.adb(), serial, err)
                                                                         : t.restoreDevice(dev.adb(), serial, err);
                                if (!ok) return McpToolResult::error(err);
                            }
                            return McpToolResult::ok(Json::obj({{"running", t.running()}, {"port", t.port()},
                                                                {"routed_device", t.routedSerial()}}));
                        });
                    }});

    server.addTool({"traffic_list", "Captured requests",
                    "Captured network requests (newest last). Filter by text (host / path / method), host or "
                    "status; use since_id to poll for new requests.",
                    schema::object({{"filter", str("Substring of method, host or path")},
                                    {"host", str("Exact host")},
                                    {"status", integer("HTTP status", 0, 999)},
                                    {"include_tunnels", boolean("Include HTTPS CONNECT tunnels (default true)")},
                                    {"since_id", integer("Only requests with a higher id", 0, 1ll << 50)},
                                    {"limit", integer("Max (default 200)", 1, 5000)}}),
                    true, false, [&dev, flowSummary](const Json& args, McpToolContext&) -> McpToolOutcome {
                        const auto flows = dev.traffic().flows((uint64_t)argInt(args, "since_id", 0));
                        const std::string filter = argStr(args, "filter"), host = argStr(args, "host");
                        const int64_t status = argInt(args, "status", -1);
                        const bool tunnels = argBool(args, "include_tunnels", true);
                        const size_t limit = (size_t)argInt(args, "limit", 200);
                        Json list = Json::array();
                        for (auto it = flows.rbegin(); it != flows.rend() && list.size() < limit; ++it) {
                            const auto& f = *it;
                            if (!tunnels && f.tunnel) continue;
                            if (!host.empty() && f.host != host && f.sni != host) continue;
                            if (status >= 0 && f.status != status) continue;
                            if (!filter.empty() && tex::ciFind(f.method + " " + f.host + " " + f.sni + " " + f.path, filter) ==
                                                       std::string_view::npos)
                                continue;
                            list.push(flowSummary(f));
                        }
                        Json ordered = Json::array();
                        for (size_t i = list.size(); i-- > 0;) ordered.push(list[i]);
                        return McpToolResult::ok(Json::obj({{"requests", std::move(ordered)},
                                                            {"last_id", (unsigned long long)dev.traffic().lastId()}}));
                    }});

    server.addTool({"traffic_get", "Request details",
                    "Full request and response of a captured flow: headers and decoded bodies (chunked / gzip), "
                    "plus a ready-to-run curl command.",
                    schema::object({{"id", integer("Request id from traffic_list", 1, 1ll << 50)},
                                    {"max_body_bytes", integer("Body bytes to return (default 65536)", 0, 2 << 20)}},
                                   {"id"}),
                    true, false, [&dev, flowSummary](const Json& args, McpToolContext&) -> McpToolOutcome {
                        TrafficProxy::Flow f;
                        if (!dev.traffic().flow((uint64_t)argInt(args, "id", 0), f)) return McpToolResult::error("no such request");
                        const size_t maxBody = (size_t)argInt(args, "max_body_bytes", 65536);
                        const auto message = [maxBody](const TrafficProxy::Message& m) {
                            Json headers = Json::array();
                            for (const auto& h : m.headers)
                                headers.push(Json::obj({{"name", h.first}, {"value", json::sanitizeUtf8(h.second)}}));
                            std::string note;
                            std::string body = TrafficProxy::decodeBody(m, &note);
                            const bool cut = body.size() > maxBody;
                            if (cut) body.resize(maxBody);
                            Json j = Json::obj({{"start_line", json::sanitizeUtf8(m.startLine)},
                                                {"headers", std::move(headers)},
                                                {"body", json::sanitizeUtf8(body)},
                                                {"body_size", (unsigned long long)m.bodySize},
                                                {"body_truncated", cut || m.truncated}});
                            if (!note.empty()) j.set("body_note", note);
                            return j;
                        };
                        Json j = flowSummary(f);
                        if (f.tunnel) {
                            j.set("note", "encrypted HTTPS tunnel: contents are not visible to the proxy");
                        } else {
                            j.set("request", message(f.request));
                            j.set("response", message(f.response));
                            j.set("curl", json::sanitizeUtf8(TrafficProxy::curl(f)));
                        }
                        return McpToolResult::ok(std::move(j));
                    }});

    server.addTool({"traffic_endpoints", "API endpoint map",
                    "Captured traffic grouped by host + method + path template (numeric / UUID / token segments "
                    "become {id}), with hit counts and status codes.",
                    schema::object({}), true, false, [&dev](const Json&, McpToolContext&) -> McpToolOutcome {
                        Json list = Json::array();
                        for (const auto& e : dev.traffic().endpoints()) {
                            Json st = Json::array();
                            for (int s : e.statuses) st.push(s);
                            list.push(Json::obj({{"method", e.method}, {"host", e.host}, {"path", e.pathTemplate},
                                                 {"tunnel", e.tunnel}, {"hits", e.count}, {"statuses", std::move(st)},
                                                 {"bytes", (unsigned long long)e.bytes},
                                                 {"last_request_id", (unsigned long long)e.lastFlow}}));
                        }
                        return McpToolResult::ok(Json::obj({{"endpoints", std::move(list)}}));
                    }});
}
