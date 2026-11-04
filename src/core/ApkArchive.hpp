#pragma once
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>
#include <miniz.h>
#include "core/ContentSource.hpp"

// A zip-backed APK. `path` is UTF-8 on every platform; on Windows the file is
// opened with wide-char APIs so non-ASCII paths work.
class ApkArchive : public ContentSource {
public:
    ApkArchive();
    ~ApkArchive() override;
    ApkArchive(const ApkArchive&) = delete;
    ApkArchive& operator=(const ApkArchive&) = delete;

    bool open(const std::string& path);
    void close();
    const std::string& name() const { return name_; }
    std::unique_ptr<TreeNode> buildTree() const;
    bool read(const TreeNode& node, std::vector<uint8_t>& out) const override;
    bool sizeOf(const TreeNode& node, uint64_t& out) const override;

    // Reads one entry by its zip path; entries whose declared size exceeds
    // `maxSize` are refused before anything is allocated (zip bombs).
    bool readEntry(const std::string& entryPath, std::vector<uint8_t>& out,
                   uint64_t maxSize = kDefaultMaxEntry) const;
    static constexpr uint64_t kDefaultMaxEntry = 1024ull * 1024 * 1024;  // 1 GiB

    // Central-directory listing (no decompression): used by analysis and the
    // APK comparison.
    struct Entry {
        std::string path;
        uint64_t size = 0;
        uint64_t compressedSize = 0;
        uint32_t crc32 = 0;
        uint16_t method = 0;
    };
    std::vector<Entry> entries() const;

private:
    mutable mz_zip_archive zip_;
    bool opened_ = false;
    std::string name_;
    std::FILE* file_ = nullptr;  // kept open for the archive's lifetime
};
