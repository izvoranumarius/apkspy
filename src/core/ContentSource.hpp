#pragma once
#include <cstdint>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <mutex>
#include <string>
#include <unordered_map>
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
    // Reads a whole file with ONE sized read into `out` (its capacity is
    // reused, so callers scanning many files can keep one buffer). The old
    // istreambuf_iterator loop read byte by byte and grew the vector
    // geometrically - up to 2x the file size at peak, and very slow in Debug.
    static bool readFile(const std::string& utf8Path, std::vector<uint8_t>& out) {
        std::ifstream in(pathutil::fromUtf8(utf8Path), std::ios::binary | std::ios::ate);
        if (!in) return false;
        const std::streamoff size = in.tellg();
        if (size < 0) return false;
        in.seekg(0, std::ios::beg);
        out.resize((size_t)size);
        if (size > 0 && !in.read(reinterpret_cast<char*>(out.data()), size)) {
            out.resize((size_t)std::max<std::streamsize>(0, in.gcount()));
            return false;
        }
        return true;
    }

    bool read(const TreeNode& node, std::vector<uint8_t>& out) const override {
        return readFile(node.path(), out);
    }
    bool sizeOf(const TreeNode& node, uint64_t& out) const override {
        std::error_code ec;
        uintmax_t size = std::filesystem::file_size(pathutil::fromUtf8(node.path()), ec);
        if (ec) return false;
        out = (uint64_t)size;
        return true;
    }
};

// In-memory content for generated documents (virtual root). Thread-safe.
class MemorySource : public ContentSource {
public:
    void put(const std::string& path, std::string text) {
        std::lock_guard<std::mutex> lock(mutex_);
        content_[path] = std::move(text);
    }
    void erase(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        content_.erase(path);
    }
    bool read(const TreeNode& node, std::vector<uint8_t>& out) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = content_.find(node.path());
        if (it == content_.end()) return false;
        out.assign(it->second.begin(), it->second.end());
        return true;
    }
    bool sizeOf(const TreeNode& node, uint64_t& out) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = content_.find(node.path());
        if (it == content_.end()) return false;
        out = it->second.size();
        return true;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> content_;
};
