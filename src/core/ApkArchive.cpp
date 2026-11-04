#include "core/ApkArchive.hpp"
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string_view>
#include <unordered_map>
#include "core/Paths.hpp"

#ifdef _WIN32
extern "C" std::FILE* _wfopen(const wchar_t* path, const wchar_t* mode);  // <cstdio> on MSVC
#endif

namespace fs = std::filesystem;

ApkArchive::ApkArchive() { mz_zip_zero_struct(&zip_); }

ApkArchive::~ApkArchive() { close(); }

bool ApkArchive::open(const std::string& path) {
    close();
    mz_zip_zero_struct(&zip_);
    // Open the file ourselves (UTF-8 -> native wide chars on Windows) and
    // hand miniz the FILE*; mz_zip_reader_init_file would use fopen, which
    // mangles non-ANSI paths on Windows.
    fs::path native = pathutil::fromUtf8(path);
#ifdef _WIN32
    const std::wstring wide = native.wstring();
    file_ = _wfopen(wide.c_str(), L"rb");
#else
    file_ = std::fopen(path.c_str(), "rb");
#endif
    if (!file_) return false;
    if (!mz_zip_reader_init_cfile(&zip_, file_, 0, 0)) {
        std::fclose(file_);
        file_ = nullptr;
        return false;
    }
    opened_ = true;
    name_ = pathutil::toUtf8(native.filename());
    return true;
}

void ApkArchive::close() {
    if (opened_) {
        mz_zip_reader_end(&zip_);
        opened_ = false;
    }
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
}

std::unique_ptr<TreeNode> ApkArchive::buildTree() const {
    auto root = std::make_unique<TreeNode>(name_, "", NodeKind::Folder);
    if (!opened_) return root;
    mz_uint count = mz_zip_reader_get_num_files(&zip_);
    // Index of each folder's children by name: inserting thousands of zip
    // entries with a linear findChild per path component is O(n^2). Keys
    // are views of the nodes' own names (stable: nodes live on the heap), so
    // building the index copies no strings.
    std::unordered_map<const TreeNode*, std::unordered_map<std::string_view, TreeNode*>> folders;
    auto childIndex = [&](TreeNode* folder) -> std::unordered_map<std::string_view, TreeNode*>& {
        auto& map = folders[folder];
        if (map.empty())
            for (const auto& c : folder->children()) map.emplace(c->name(), c.get());
        return map;
    };
    mz_zip_archive_file_stat stat{};
    for (mz_uint i = 0; i < count; ++i) {
        if (!mz_zip_reader_file_stat(&zip_, i, &stat)) continue;
        std::string full(stat.m_filename);
        bool isDir = stat.m_is_directory != 0;
        TreeNode* cur = root.get();
        size_t start = 0;
        while (start < full.size()) {
            size_t slash = full.find('/', start);
            bool last = slash == std::string::npos;
            std::string part = full.substr(start, last ? std::string::npos : slash - start);
            start = last ? full.size() : slash + 1;
            if (part.empty()) continue;
            bool folder = !last || isDir;
            auto& map = childIndex(cur);
            TreeNode* next = nullptr;
            if (auto found = map.find(part); found != map.end()) next = found->second;
            if (!next) {
                std::string path = folder ? full.substr(0, start) : full;
                NodeKind kind = folder ? NodeKind::Folder : TreeNode::classify(part);
                next = cur->addChild(std::make_unique<TreeNode>(std::move(part), std::move(path), kind));
                map.emplace(next->name(), next);
            }
            cur = next;
        }
    }
    root->sortRecursive();
    return root;
}

bool ApkArchive::read(const TreeNode& node, std::vector<uint8_t>& out) const {
    if (!opened_ || node.isFolder()) return false;
    return readEntry(node.path(), out);
}

bool ApkArchive::readEntry(const std::string& entryPath, std::vector<uint8_t>& out, uint64_t maxSize) const {
    if (!opened_) return false;
    mz_uint32 index = 0;
    if (!mz_zip_reader_locate_file_v2(&zip_, entryPath.c_str(), nullptr, 0, &index)) return false;
    mz_zip_archive_file_stat stat{};
    if (!mz_zip_reader_file_stat(&zip_, index, &stat) || stat.m_is_directory) return false;
    // The declared size comes from the (untrusted) central directory: cap it
    // before allocating, and let miniz verify the real size/CRC.
    if (stat.m_uncomp_size > maxSize || stat.m_uncomp_size > (uint64_t)SIZE_MAX) return false;
    // Decompress straight into the caller's buffer: one allocation sized
    // from the central directory instead of extract-to-heap + a copy (which
    // doubled the peak for every large entry such as classes.dex).
    out.resize((size_t)stat.m_uncomp_size);
    if (stat.m_uncomp_size == 0) return true;
    if (!mz_zip_reader_extract_to_mem(&zip_, index, out.data(), out.size(), 0)) {
        out.clear();
        return false;
    }
    return true;
}

std::vector<ApkArchive::Entry> ApkArchive::entries() const {
    std::vector<Entry> out;
    if (!opened_) return out;
    const mz_uint count = mz_zip_reader_get_num_files(&zip_);
    out.reserve(count);
    mz_zip_archive_file_stat stat{};
    for (mz_uint i = 0; i < count; ++i) {
        if (!mz_zip_reader_file_stat(&zip_, i, &stat) || stat.m_is_directory) continue;
        out.push_back({stat.m_filename, stat.m_uncomp_size, stat.m_comp_size, stat.m_crc32,
                       stat.m_method});
    }
    return out;
}

bool ApkArchive::sizeOf(const TreeNode& node, uint64_t& out) const {
    if (!opened_ || node.isFolder()) return false;
    mz_uint32 index = 0;
    if (!mz_zip_reader_locate_file_v2(&zip_, node.path().c_str(), nullptr, 0, &index)) return false;
    mz_zip_archive_file_stat stat{};
    if (!mz_zip_reader_file_stat(&zip_, index, &stat)) return false;
    out = stat.m_uncomp_size;
    return true;
}
