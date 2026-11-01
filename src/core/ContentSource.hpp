#pragma once
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include "core/TreeNode.hpp"
#include "core/Paths.hpp"

class ContentSource {
public:
    virtual ~ContentSource() = default;
    virtual bool read(const TreeNode& node, std::vector<uint8_t>& out) const = 0;
    // Content size without reading it - lets callers skip oversized files
    // before loading them. Returns false when the size is unknown.
    virtual bool sizeOf(const TreeNode& node, uint64_t& out) const {
        (void)node;
        out = 0;
        return false;
    }
};

class DiskSource : public ContentSource {
public:
    bool read(const TreeNode& node, std::vector<uint8_t>& out) const override {
        std::ifstream in(pathutil::fromUtf8(node.path()), std::ios::binary);
        if (!in) return false;
        out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        return true;
    }
    bool sizeOf(const TreeNode& node, uint64_t& out) const override {
        std::error_code ec;
        uintmax_t size = std::filesystem::file_size(pathutil::fromUtf8(node.path()), ec);
        if (ec) return false;
        out = (uint64_t)size;
        return true;
    }
};
