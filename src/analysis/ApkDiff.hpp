#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "core/ApkArchive.hpp"

// Version comparison of two APKs: archive entries (by CRC/size, no
// decompression) and - when both bytecode analyses are available - classes
// and method bodies. Method bodies are compared by a hash of their
// normalised disassembly (references rendered by name), so pure index
// renumbering between builds does not show up as a change.
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
    std::vector<std::string> methodsChanged;
    bool codeCompared = false;
    bool truncated = false;

    static const char* kindName(Kind k);

    static ApkDiff compareEntries(const std::vector<ApkArchive::Entry>& a, const std::vector<ApkArchive::Entry>& b);
    // Adds the class/method comparison. `limit` caps every list.
    void compareCode(const ApkAnalysis& a, const ApkAnalysis& b, size_t limit, const std::atomic<bool>* cancel);
};
