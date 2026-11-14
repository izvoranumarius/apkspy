#include "analysis/ApkDiff.hpp"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <unordered_map>
#include "analysis/BehaviorGraph.hpp"
#include "analysis/Dalvik.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/LibraryCatalog.hpp"
#include "core/TextDiff.hpp"

namespace {

uint64_t fnv1a(std::string_view s, uint64_t h = 1469598103934665603ull) {
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

bool isHex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

// Instruction lines of a listing (not directives, labels, comments or blank lines).
bool isInstruction(std::string_view line) {
    const size_t start = line.find_first_not_of(" \t");
    if (start == std::string_view::npos) return false;
    const char c = line[start];
    return c != '.' && c != ':' && c != '#';
}

std::string_view opcodeOf(std::string_view line) {
    const size_t start = line.find_first_not_of(" \t");
    if (start == std::string_view::npos) return {};
    const size_t end = line.find_first_of(" \t", start);
    return line.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
}

// The listing with every register (v12, p0) replaced: equal keys mean the
// bodies differ only in register allocation.
std::string registerFree(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        const bool boundary = i == 0 || !(std::isalnum(static_cast<unsigned char>(text[i - 1])) || text[i - 1] == '_' || text[i - 1] == '$');
        if ((c == 'v' || c == 'p') && boundary && i + 1 < text.size() && std::isdigit(static_cast<unsigned char>(text[i + 1]))) {
            size_t j = i + 1;
            while (j < text.size() && std::isdigit(static_cast<unsigned char>(text[j]))) ++j;
            if (j == text.size() || !(std::isalnum(static_cast<unsigned char>(text[j])) || text[j] == '_')) {
                out += 'r';
                i = j - 1;
                continue;
            }
        }
        out += c;
    }
    return out;
}

// Quoted operand of const-string lines.
std::vector<std::string> constStrings(const std::vector<std::string_view>& lines) {
    std::vector<std::string> out;
    for (std::string_view l : lines) {
        const std::string_view op = opcodeOf(l);
        if (op != "const-string" && op != "const-string/jumbo") continue;
        const size_t q = l.find('"');
        if (q != std::string_view::npos && l.size() > q + 1 && l.back() == '"') out.emplace_back(l.substr(q + 1, l.size() - q - 2));
    }
    return out;
}

template <typename T>
void setDiff(const std::vector<T>& a, const std::vector<T>& b, std::vector<T>& added, std::vector<T>& removed, size_t limit) {
    const std::set<T> sa(a.begin(), a.end()), sb(b.begin(), b.end());
    for (const T& x : sb)
        if (!sa.count(x) && added.size() < limit) added.push_back(x);
    for (const T& x : sa)
        if (!sb.count(x) && removed.size() < limit) removed.push_back(x);
}

// "Lcom/a/B;->name(I)V" -> "B.name()"
std::string shortCall(const std::string& sig) {
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(sig, cls, name, proto)) return sig;
    std::string_view c = cls;
    if (c.size() >= 2 && c.front() == 'L' && c.back() == ';') c = c.substr(1, c.size() - 2);
    const size_t slash = c.rfind('/');
    if (slash != std::string_view::npos) c = c.substr(slash + 1);
    return std::string(c) + "." + name + "()";
}

const ApkAnalysis::MethodDef* findDef(const ApkAnalysis& a, const std::string& sig, ApkAnalysis::MethodDef& storage) {
    std::string cls, name, proto;
    if (!ApkAnalysis::splitMethodRef(sig, cls, name, proto)) return nullptr;
    const auto defs = a.findMethodDefs(cls, name, proto);
    if (defs.empty()) return nullptr;
    storage = defs.front();
    return &storage;
}

// Signature of a class's code shape: what an obfuscator keeps when it renames.
// 0 when the class is too small to identify reliably.
uint64_t classShape(const ApkAnalysis& a, const ApkAnalysis::ClassEntry& c) {
    std::vector<uint64_t> methods;
    size_t instructions = 0;
    for (const ApkAnalysis::MethodDef& m : a.methodsOf(c)) {
        if (!m.method.codeOff) {
            methods.push_back(0x9e3779b97f4a7c15ull ^ m.method.accessFlags);
            continue;
        }
        const std::string text = ApkDiff::normalizedListing(a, m);
        uint64_t h = fnv1a(std::to_string(m.method.accessFlags));
        for (std::string_view line : textdiff::splitLines(text))
            if (isInstruction(line)) {
                h = fnv1a(opcodeOf(line), h);
                ++instructions;
            }
        methods.push_back(h);
    }
    if (methods.size() < 2 && instructions < 12) return 0;
    std::sort(methods.begin(), methods.end());
    uint64_t h = 1469598103934665603ull ^ methods.size();
    for (uint64_t m : methods) h = (h ^ m) * 1099511628211ull;
    return h;
}

std::string yesNo(bool v) { return v ? "yes" : "no"; }

std::string joined(const std::vector<std::string>& v) {
    std::string out;
    for (const std::string& s : v) out += (out.empty() ? "" : ", ") + s;
    return out;
}

std::vector<std::string> entryPaths(const std::vector<ApkArchive::Entry>& entries) {
    std::vector<std::string> out;
    out.reserve(entries.size());
    for (const ApkArchive::Entry& e : entries) out.push_back(e.path);
    return out;
}

std::vector<std::string> exportNames(ApkArchive* arch, const std::string& path) {
    std::vector<std::string> names;
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    if (!arch || !arch->readEntry(path, *bytes, 512ull * 1024 * 1024)) return names;
    std::string err;
    auto elf = ElfFile::parse(bytes, path, err);
    if (!elf) return names;
    for (const ElfFile::Symbol* s : elf->exports()) names.push_back(s->name);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

}  // namespace

std::string ApkDiff::normalizedListing(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m) {
    dalvik::ListingOptions opt;
    opt.showOffsets = false;  // offsets shift with unrelated edits
    opt.showLines = false;    // so do line numbers
    std::string text;
    dalvik::disassembleMethod(*a.dexes()[m.dex], m.method, opt, text);
    // Branch labels are named after their pc: renumber them in order of appearance.
    std::unordered_map<std::string, std::string> labels;
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size();) {
        if (text[i] == ':' && i + 2 < text.size() && text[i + 1] == 'L' && isHex(text[i + 2])) {
            size_t j = i + 2;
            while (j < text.size() && isHex(text[j])) ++j;
            const std::string label = text.substr(i, j - i);
            auto it = labels.find(label);
            if (it == labels.end()) it = labels.emplace(label, ":L" + std::to_string(labels.size())).first;
            out += it->second;
            i = j;
            continue;
        }
        out += text[i++];
    }
    return out;
}

const char* ApkDiff::kindName(Kind k) {
    switch (k) {
    case Kind::Added: return "added";
    case Kind::Removed: return "removed";
    case Kind::Changed: return "changed";
    }
    return "?";
}

ApkDiff ApkDiff::compareEntries(const std::vector<ApkArchive::Entry>& a, const std::vector<ApkArchive::Entry>& b) {
    ApkDiff d;
    std::map<std::string, const ApkArchive::Entry*> mapA, mapB;
    for (const auto& e : a) mapA[e.path] = &e;
    for (const auto& e : b) mapB[e.path] = &e;
    for (const auto& kv : mapA) {
        auto it = mapB.find(kv.first);
        if (it == mapB.end()) {
            d.entries.push_back({kv.first, Kind::Removed, kv.second->size, 0});
        } else if (it->second->crc32 != kv.second->crc32 || it->second->size != kv.second->size) {
            d.entries.push_back({kv.first, Kind::Changed, kv.second->size, it->second->size});
        } else {
            ++d.entriesUnchanged;
        }
    }
    for (const auto& kv : mapB)
        if (!mapA.count(kv.first)) d.entries.push_back({kv.first, Kind::Added, 0, kv.second->size});
    std::sort(d.entries.begin(), d.entries.end(),
              [](const EntryChange& x, const EntryChange& y) { return x.path < y.path; });
    return d;
}

void ApkDiff::compareCode(const ApkAnalysis& a, const ApkAnalysis& b, size_t limit, const std::atomic<bool>* cancel) {
    codeCompared = true;
    const auto push = [&](std::vector<std::string>& list, std::string v) {
        if (list.size() < limit) list.push_back(std::move(v));
        else truncated = true;
    };
    const auto hashes = [](const ApkAnalysis& an, const ApkAnalysis::ClassEntry& c) {
        std::unordered_map<std::string, uint64_t> out;
        for (const ApkAnalysis::MethodDef& m : an.methodsOf(c)) out[an.methodSignature(m)] = fnv1a(normalizedListing(an, m));
        return out;
    };
    // Both class tables are sorted by descriptor: merge-walk them.
    const auto& ca = a.classes();
    const auto& cb = b.classes();
    size_t i = 0, j = 0;
    while (i < ca.size() || j < cb.size()) {
        if (cancel && cancel->load()) return;
        const std::string_view da = i < ca.size() ? a.classDescriptor(ca[i]) : std::string_view();
        const std::string_view db = j < cb.size() ? b.classDescriptor(cb[j]) : std::string_view();
        if (j >= cb.size() || (i < ca.size() && da < db)) {
            push(classesRemoved, DexFile::descriptorToJava(da));
            ++i;
        } else if (i >= ca.size() || db < da) {
            push(classesAdded, DexFile::descriptorToJava(db));
            ++j;
        } else {
            const auto ha = hashes(a, ca[i]);
            const auto hb = hashes(b, cb[j]);
            for (const auto& kv : ha) {
                auto it = hb.find(kv.first);
                if (it == hb.end()) push(methodsRemoved, kv.first);
                else if (it->second != kv.second) push(methodsChanged, kv.first);
            }
            for (const auto& kv : hb)
                if (!ha.count(kv.first)) push(methodsAdded, kv.first);
            ++i;
            ++j;
        }
    }
    std::sort(methodsAdded.begin(), methodsAdded.end());
    std::sort(methodsRemoved.begin(), methodsRemoved.end());
    std::sort(methodsChanged.begin(), methodsChanged.end());
}

ApkDiff ApkDiff::compare(const Side& sa, const Side& sb, const Options& opt, const std::atomic<bool>* cancel) {
    const auto stopped = [&] { return cancel && cancel->load(); };
    ApkDiff d = compareEntries(sa.entries, sb.entries);
    const size_t limit = opt.limit;

    // Manifest -----------------------------------------------------------------
    const ApkInfo& ia = sa.info;
    const ApkInfo& ib = sb.info;
    const auto field = [&](const char* name, const std::string& x, const std::string& y) {
        if (x != y) d.manifest.push_back({name, x, y});
    };
    field("package", ia.packageName, ib.packageName);
    field("versionName", ia.versionName, ib.versionName);
    field("versionCode", ia.versionCode, ib.versionCode);
    field("minSdk", ia.minSdk, ib.minSdk);
    field("targetSdk", ia.targetSdk, ib.targetSdk);
    field("label", ia.appLabel, ib.appLabel);
    field("debuggable", yesNo(ia.debuggable), yesNo(ib.debuggable));
    field("allowBackup", yesNo(ia.allowBackup), yesNo(ib.allowBackup));
    field("signing scheme", ia.signatures.empty() ? "" : ia.signatures[0].scheme, ib.signatures.empty() ? "" : ib.signatures[0].scheme);
    field("certificate SHA-256", ia.signatures.empty() ? "" : ia.signatures[0].certSha256, ib.signatures.empty() ? "" : ib.signatures[0].certSha256);
    setDiff(ia.permissions, ib.permissions, d.permissionsAdded, d.permissionsRemoved, limit);
    {
        std::map<std::string, const ApkComponent*> ca, cb;
        for (const ApkComponent& c : ia.components) ca[behavior::componentClass(ia.packageName, c.name)] = &c;
        for (const ApkComponent& c : ib.components) cb[behavior::componentClass(ib.packageName, c.name)] = &c;
        for (const auto& [name, c] : ca) {
            auto it = cb.find(name);
            if (it == cb.end()) {
                d.components.push_back({name, c->type, Kind::Removed, c->exported ? "was exported" : ""});
                continue;
            }
            std::vector<std::string> what;
            if (c->exported != it->second->exported) what.push_back("exported: " + yesNo(c->exported) + " -> " + yesNo(it->second->exported));
            if (c->type != it->second->type) what.push_back("type: " + c->type + " -> " + it->second->type);
            std::vector<std::string> actAdded, actRemoved;
            setDiff(c->actions, it->second->actions, actAdded, actRemoved, 64);
            if (!actAdded.empty()) what.push_back("actions added: " + joined(actAdded));
            if (!actRemoved.empty()) what.push_back("actions removed: " + joined(actRemoved));
            std::vector<std::string> catAdded, catRemoved;
            setDiff(c->categories, it->second->categories, catAdded, catRemoved, 64);
            if (!catAdded.empty()) what.push_back("categories added: " + joined(catAdded));
            if (!catRemoved.empty()) what.push_back("categories removed: " + joined(catRemoved));
            if (!what.empty()) d.components.push_back({name, it->second->type, Kind::Changed, joined(what)});
        }
        for (const auto& [name, c] : cb)
            if (!ca.count(name)) d.components.push_back({name, c->type, Kind::Added, c->exported ? "exported" : ""});
    }
    if (stopped()) return d;

    // Resources ------------------------------------------------------------------
    if (sa.resources && sb.resources) {
        d.resourcesCompared = true;
        std::map<std::string, ResourceTable::Item> ra, rb;
        for (auto& it : sa.resources->list("", "", SIZE_MAX)) ra.emplace(it.type + "/" + it.name, std::move(it));
        for (auto& it : sb.resources->list("", "", SIZE_MAX)) rb.emplace(it.type + "/" + it.name, std::move(it));
        const auto shown = [](const ResourceTable::Item& it) { return it.complex ? std::string("(complex)") : it.value; };
        for (const auto& [name, item] : ra) {
            auto it = rb.find(name);
            if (it == rb.end()) {
                if (d.resources.size() < limit) d.resources.push_back({name, Kind::Removed, shown(item), ""});
            } else if (item.value != it->second.value || item.complex != it->second.complex || item.configs != it->second.configs) {
                std::string va = shown(item), vb = shown(it->second);
                if (va == vb) va += " (" + std::to_string(item.configs) + " configs)", vb += " (" + std::to_string(it->second.configs) + " configs)";
                if (d.resources.size() < limit) d.resources.push_back({name, Kind::Changed, va, vb});
            } else {
                ++d.resourcesUnchanged;
            }
        }
        for (const auto& [name, item] : rb)
            if (!ra.count(name) && d.resources.size() < limit) d.resources.push_back({name, Kind::Added, "", shown(item)});
    }
    if (stopped()) return d;

    // Native libraries and version files (private archives) -------------------------
    ApkArchive archA, archB;
    const bool openA = !sa.apkPath.empty() && archA.open(sa.apkPath);
    const bool openB = !sb.apkPath.empty() && archB.open(sb.apkPath);
    for (const EntryChange& e : d.entries) {
        if (stopped()) return d;
        if (e.path.rfind("lib/", 0) != 0 || e.path.size() < 4 || e.path.compare(e.path.size() - 3, 3, ".so") != 0) continue;
        NativeChange n{e.path, e.kind, e.sizeA, e.sizeB, {}, {}};
        if (opt.nativeSymbols) {
            const std::vector<std::string> ea = e.kind != Kind::Added && openA ? exportNames(&archA, e.path) : std::vector<std::string>();
            const std::vector<std::string> eb = e.kind != Kind::Removed && openB ? exportNames(&archB, e.path) : std::vector<std::string>();
            setDiff(ea, eb, n.exportsAdded, n.exportsRemoved, 2000);
        }
        d.natives.push_back(std::move(n));
    }
    const std::vector<std::string> pathsA = entryPaths(sa.entries), pathsB = entryPaths(sb.entries);
    const auto filesA = libcatalog::readVersionFiles(sa.apkPath, pathsA);
    const auto filesB = libcatalog::readVersionFiles(sb.apkPath, pathsB);
    if (stopped()) return d;

    // Code ---------------------------------------------------------------------------
    const ApkAnalysis* anA = sa.analysis.get();
    const ApkAnalysis* anB = sb.analysis.get();
    if (anA && anB) {
        d.compareCode(*anA, *anB, limit, cancel);
        if (stopped()) return d;

        // Renamed classes: removed on one side, added on the other, same code shape.
        std::unordered_map<uint64_t, std::vector<size_t>> shapesA, shapesB;
        for (size_t i = 0; i < d.classesRemoved.size(); ++i)
            if (const auto* c = anA->findClass(d.classesRemoved[i]))
                if (const uint64_t s = classShape(*anA, *c)) shapesA[s].push_back(i);
        if (stopped()) return d;
        for (size_t i = 0; i < d.classesAdded.size(); ++i)
            if (const auto* c = anB->findClass(d.classesAdded[i]))
                if (const uint64_t s = classShape(*anB, *c)) shapesB[s].push_back(i);
        std::set<size_t> renamedA, renamedB;
        for (const auto& [shape, ia2] : shapesA) {
            auto it = shapesB.find(shape);
            if (ia2.size() != 1 || it == shapesB.end() || it->second.size() != 1) continue;  // ambiguous
            d.classesRenamed.push_back({d.classesRemoved[ia2[0]], d.classesAdded[it->second[0]]});
            renamedA.insert(ia2[0]);
            renamedB.insert(it->second[0]);
        }
        std::sort(d.classesRenamed.begin(), d.classesRenamed.end(), [](const ClassRename& x, const ClassRename& y) { return x.from < y.from; });
        const auto dropIndices = [](std::vector<std::string>& v, const std::set<size_t>& drop) {
            std::vector<std::string> kept;
            for (size_t i = 0; i < v.size(); ++i)
                if (!drop.count(i)) kept.push_back(std::move(v[i]));
            v = std::move(kept);
        };
        dropIndices(d.classesRemoved, renamedA);
        dropIndices(d.classesAdded, renamedB);

        // What changed in each method; bodies that differ only in registers are cosmetic.
        std::vector<std::string> meaningful;
        for (const std::string& sig : d.methodsChanged) {
            if (stopped()) return d;
            ApkAnalysis::MethodDef ma, mb;
            const ApkAnalysis::MethodDef* pa = findDef(*anA, sig, ma);
            const ApkAnalysis::MethodDef* pb = findDef(*anB, sig, mb);
            if (!pa || !pb) continue;
            const std::string la = normalizedListing(*anA, *pa), lb = normalizedListing(*anB, *pb);
            if (registerFree(la) == registerFree(lb)) {
                ++d.methodsCosmetic;
                continue;
            }
            MethodChange mc;
            mc.signature = sig;
            const auto linesA = textdiff::splitLines(la), linesB = textdiff::splitLines(lb);
            for (const textdiff::Edit& e : textdiff::diff(linesA, linesB, 600)) {
                if (e.op == textdiff::Op::Delete && isInstruction(linesA[static_cast<size_t>(e.a)])) ++mc.removed;
                if (e.op == textdiff::Op::Insert && isInstruction(linesB[static_cast<size_t>(e.b)])) ++mc.added;
            }
            std::vector<std::string> callsA, callsB;
            for (const auto& c : anA->calleesOf(*pa)) callsA.push_back(c.signature);
            for (const auto& c : anB->calleesOf(*pb)) callsB.push_back(c.signature);
            setDiff(callsA, callsB, mc.callsAdded, mc.callsRemoved, 50);
            setDiff(constStrings(linesA), constStrings(linesB), mc.stringsAdded, mc.stringsRemoved, 50);
            mc.summary = "+" + std::to_string(mc.added) + " -" + std::to_string(mc.removed);
            if (!mc.callsAdded.empty()) {
                mc.summary += "; calls ";
                for (size_t k = 0; k < mc.callsAdded.size() && k < 3; ++k) mc.summary += (k ? ", " : "") + shortCall(mc.callsAdded[k]);
                if (mc.callsAdded.size() > 3) mc.summary += " +" + std::to_string(mc.callsAdded.size() - 3);
            }
            if (!mc.callsRemoved.empty()) mc.summary += "; drops " + std::to_string(mc.callsRemoved.size()) + " call(s)";
            if (!mc.stringsAdded.empty()) mc.summary += "; new string \"" + mc.stringsAdded.front().substr(0, 48) + "\"";
            meaningful.push_back(sig);
            d.methodDetails.push_back(std::move(mc));
        }
        d.methodsChanged = std::move(meaningful);

        // Network endpoints.
        std::vector<std::string> urlsA, urlsB;
        for (const auto& h : anA->strings({}, ApkAnalysis::StringCategory::Url, 50000)) urlsA.push_back(h.value);
        for (const auto& h : anB->strings({}, ApkAnalysis::StringCategory::Url, 50000)) urlsB.push_back(h.value);
        setDiff(urlsA, urlsB, d.endpointsAdded, d.endpointsRemoved, limit);
    }

    // Bundled libraries -----------------------------------------------------------
    {
        const auto la = libcatalog::detect(anA && anB ? anA : nullptr, filesA, pathsA);
        const auto lb = libcatalog::detect(anA && anB ? anB : nullptr, filesB, pathsB);
        const auto key = [](const libcatalog::Detection& x) { return x.lib ? std::string(x.lib->id) : x.maven; };
        const auto name = [](const libcatalog::Detection& x) { return x.lib ? std::string(x.lib->name) : x.maven; };
        std::map<std::string, const libcatalog::Detection*> ma, mb;
        for (const auto& x : la) ma[key(x)] = &x;
        for (const auto& x : lb) mb[key(x)] = &x;
        for (const auto& [k, x] : ma) {
            auto it = mb.find(k);
            if (it == mb.end()) {
                d.libraries.push_back({name(*x), Kind::Removed, x->version, "", x->classes, 0});
                continue;
            }
            const auto* y = it->second;
            const bool versionChanged = !x->version.empty() && !y->version.empty() && x->version != y->version;
            const size_t lo = std::min(x->classes, y->classes), hi = std::max(x->classes, y->classes);
            const bool sizeChanged = hi > 0 && (hi - lo) * 10 > hi;  // more than 10% of the classes
            if (versionChanged || sizeChanged) d.libraries.push_back({name(*x), Kind::Changed, x->version, y->version, x->classes, y->classes});
        }
        for (const auto& [k, y] : mb)
            if (!ma.count(k)) d.libraries.push_back({name(*y), Kind::Added, "", y->version, 0, y->classes});
    }
    return d;
}
