#pragma once
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include "core/TreeNode.hpp"

class ContentSource {
public:
    virtual ~ContentSource() = default;
    virtual bool read(const TreeNode& node, std::vector<uint8_t>& out) const = 0;
};

class DiskSource : public ContentSource {
public:
    bool read(const TreeNode& node, std::vector<uint8_t>& out) const override {
        std::ifstream in(node.path(), std::ios::binary);
        if (!in) return false;
        out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        return true;
    }
};
