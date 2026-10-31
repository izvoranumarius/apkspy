#pragma once
#include <memory>
#include <string>
#include <miniz.h>
#include "core/ContentSource.hpp"

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

private:
    mutable mz_zip_archive zip_;
    bool opened_ = false;
    std::string name_;
};
