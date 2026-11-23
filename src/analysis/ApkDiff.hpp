#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "core/ApkArchive.hpp"
#include "core/ApkInfo.hpp"
#include "core/ResourceTable.hpp"

// Version comparison of two APKs.
//
// Archive entries are compared by CRC/size (no decompression). With both
// bytecode analyses, classes and method bodies too: bodies by a hash of their
// normalised disassembly (references by name, offsets and branch labels
// renumbered), so index renumbering between builds is not a change. On top of
// that, compare() adds the manifest, permissions and components, resources,
// native libraries (exported symbols), bundled libraries with versions,
// network endpoints, classes renamed by an obfuscator (same code under a new
// name) and, per changed method, what changed: instructions added and
// removed, calls and strings that appeared or disappeared, or nothing but
// register allocation (cosmetic).
struct ApkDiff {
    enum class Kind { Added, Removed, Changed };

    struct EntryChange {
        std::string path;
        Kind kind;
        uint64_t sizeA = 0;
        uint64_t sizeB = 0;
    };
    std::vector<EntryChange> entries;
    size_t entriesUnchanged = 0;

    std::vector<std::string> classesAdded;
    std::vector<std::string> classesRemoved;
    std::vector<std::string> methodsAdded;
    std::vector<std::string> methodsRemoved;
    std::vector<std::string> methodsChanged;  // meaningful changes only when compare() ran
    bool codeCompared = false;
    bool truncated = false;

    // --- compare() --------------------------------------------------------
    struct FieldChange {
        std::string field, a, b;
    };
    std::vector<FieldChange> manifest;  // versions, SDKs, flags, label, signing certificate
    std::vector<std::string> permissionsAdded, permissionsRemoved;
    struct ComponentChange {
        std::string name, type;
        Kind kind;
        std::string detail;  // what changed: "exported: no -> yes", intent filters...
    };
    std::vector<ComponentChange> components;

    struct ClassRename {
        std::string from, to;  // Java names
    };
    std::vector<ClassRename> classesRenamed;

    struct MethodChange {
        std::string signature;
        int added = 0, removed = 0;  // instruction lines
        std::vector<std::string> callsAdded, callsRemoved;
        std::vector<std::string> stringsAdded, stringsRemoved;
        std::string summary;  // one line: what is new
    };
    std::vector<MethodChange> methodDetails;  // one per methodsChanged entry (same order)
    size_t methodsCosmetic = 0;               // bodies differing only in registers / ordering of labels

    struct ResourceChange {
        std::string name;  // "string/app_name"
        Kind kind;
        std::string a, b;
    };
    std::vector<ResourceChange> resources;
    size_t resourcesUnchanged = 0;
    bool resourcesCompared = false;

    struct NativeChange {
        std::string path;
        Kind kind;
        uint64_t sizeA = 0, sizeB = 0;
        std::vector<std::string> exportsAdded, exportsRemoved;
    };
    std::vector<NativeChange> natives;

    struct LibraryChange {
        std::string name;    // display name or Maven coordinates
        Kind kind;
        std::string versionA, versionB;
        size_t classesA = 0, classesB = 0;
    };
    std::vector<LibraryChange> libraries;

    std::vector<std::string> endpointsAdded, endpointsRemoved;  // URLs

    // Everything compare() needs from one APK. The archive listing, manifest
    // and resources are read on the thread owning the workspace; apkPath is
    // reopened privately for library bytes, so compare() runs on any thread.
    struct Side {
        std::string apkPath;
        std::vector<ApkArchive::Entry> entries;
        ApkInfo info;
        std::shared_ptr<const ResourceTable> resources;
        std::shared_ptr<const ApkAnalysis> analysis;
    };
    struct Options {
        size_t limit = 20000;       // cap of every list
        bool nativeSymbols = true;  // parse changed .so files for their exports
    };
    static ApkDiff compare(const Side& a, const Side& b, const Options& opt, const std::atomic<bool>* cancel = nullptr);

    static const char* kindName(Kind k);

    static ApkDiff compareEntries(const std::vector<ApkArchive::Entry>& a, const std::vector<ApkArchive::Entry>& b);
    // Adds the class/method comparison. `limit` caps every list.
    void compareCode(const ApkAnalysis& a, const ApkAnalysis& b, size_t limit, const std::atomic<bool>* cancel);

    // Normalised listing of a method as compared (offsets and line numbers
    // dropped, branch labels renumbered in order of appearance). Shared by
    // the side-by-side view so it shows exactly what the diff compared.
    static std::string normalizedListing(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
};
