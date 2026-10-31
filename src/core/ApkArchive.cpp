#include "core/ApkArchive.hpp"
#include <filesystem>

ApkArchive::ApkArchive() { mz_zip_zero_struct(&zip_); }

ApkArchive::~ApkArchive() { close(); }

bool ApkArchive::open(const std::string& path) {
    close();
    mz_zip_zero_struct(&zip_);
    if (!mz_zip_reader_init_file(&zip_, path.c_str(), 0)) return false;
    opened_ = true;
    name_ = std::filesystem::path(path).filename().string();
    return true;
}

void ApkArchive::close() {
    if (!opened_) return;
    mz_zip_reader_end(&zip_);
    opened_ = false;
}

std::unique_ptr<TreeNode> ApkArchive::buildTree() const {
    auto root = std::make_unique<TreeNode>(name_, "", NodeKind::Folder);
    if (!opened_) return root;
    mz_uint count = mz_zip_reader_get_num_files(&zip_);
    for (mz_uint i = 0; i < count; ++i) {
        char buf[1024];
        if (!mz_zip_reader_get_filename(&zip_, i, buf, sizeof buf)) continue;
        std::string full(buf);
        bool isDir = mz_zip_reader_is_file_a_directory(&zip_, i);
        TreeNode* cur = root.get();
        size_t start = 0;
        while (start < full.size()) {
            size_t slash = full.find('/', start);
            bool last = slash == std::string::npos;
            std::string part = full.substr(start, last ? std::string::npos : slash - start);
            start = last ? full.size() : slash + 1;
            if (part.empty()) continue;
            bool folder = !last || isDir;
            TreeNode* next = cur->findChild(part);
            if (!next) {
                std::string path = folder ? full.substr(0, start) : full;
                NodeKind kind = folder ? NodeKind::Folder : TreeNode::classify(part);
                next = cur->addChild(std::make_unique<TreeNode>(part, path, kind));
            }
            cur = next;
        }
    }
    root->sortRecursive();
    return root;
}

bool ApkArchive::read(const TreeNode& node, std::vector<uint8_t>& out) const {
    if (!opened_ || node.isFolder()) return false;
    size_t size = 0;
    void* data = mz_zip_reader_extract_file_to_heap(&zip_, node.path().c_str(), &size, 0);
    if (!data) return false;
    out.assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + size);
    mz_free(data);
    return true;
}
