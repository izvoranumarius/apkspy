#pragma once
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
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

private:
    mutable mz_zip_archive zip_;
    bool opened_ = false;
    std::string name_;
    std::FILE* file_ = nullptr;  // kept open for the archive's lifetime
};
