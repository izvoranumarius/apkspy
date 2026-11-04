#include "analysis/ApkDiff.hpp"
#include <algorithm>
#include <map>
#include <unordered_map>
#include "analysis/Dalvik.hpp"

namespace {

uint64_t fnv1a(std::string_view s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

// signature -> body hash for every method of a class.
std::unordered_map<std::string, uint64_t> methodHashes(const ApkAnalysis& an, const ApkAnalysis::ClassEntry& c) {
    std::unordered_map<std::string, uint64_t> out;
    dalvik::ListingOptions opt;
    opt.showOffsets = false;  // offsets shift with unrelated edits
    opt.showLines = false;    // so do line numbers
    std::string text;
    for (const ApkAnalysis::MethodDef& m : an.methodsOf(c)) {
        text.clear();
        dalvik::disassembleMethod(*an.dexes()[m.dex], m.method, opt, text);
        out[an.methodSignature(m)] = fnv1a(text);
    }
    return out;
}

}  // namespace

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
            const auto ha = methodHashes(a, ca[i]);
            const auto hb = methodHashes(b, cb[j]);
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
