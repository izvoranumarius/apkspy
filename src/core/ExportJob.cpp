#include "core/ExportJob.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>
#include "core/AxmlDecoder.hpp"
#include "core/Paths.hpp"
#include "core/SafePath.hpp"

namespace fs = std::filesystem;

void ExportJob::start(std::string destDir, std::vector<Item> items, bool decoded) {
    items_ = std::move(items);
    next_ = 0;
    done_ = 0;
    failed_ = 0;
    decoded_ = decoded;
    cancelRequested_ = false;
    destDir_ = pathutil::normalize(destDir);
    currentName_.clear();
    lastError_.clear();
    state_ = items_.empty() ? State::Done : State::Running;
}

void ExportJob::cancel() {
    if (state_ == State::Running) cancelRequested_ = true;
}

void ExportJob::pump() {
    if (state_ != State::Running) return;
    if (cancelRequested_) {
        items_.clear();
        next_ = 0;
        state_ = State::Cancelled;
        return;
    }
    const Item item = items_[next_++];
    currentName_ = item.node ? item.node->name() : std::string();
    writeOne(item);
    ++done_;
    if (next_ >= items_.size()) {
        items_.clear();
        next_ = 0;
        state_ = State::Done;
    }
}

void ExportJob::writeOne(const Item& item) {
    if (!item.node || !item.source) {
        ++failed_;
        lastError_ = "invalid item";
        return;
    }
    // The name comes from archive content: sanitise it (ground rule 5). A
    // rejected name counts as a failed item, never as a silent skip.
    std::string rel;
    if (!safepath::relativePath(item.relativePath, rel)) {
        ++failed_;
        lastError_ = "unsafe name: " + item.relativePath;
        return;
    }
    const fs::path dest = pathutil::fromUtf8(destDir_) / pathutil::fromUtf8(rel);
    // Defence in depth: the sanitiser guarantees containment, this check
    // makes it verifiable.
    const fs::path normalizedDest = dest.lexically_normal();
    const fs::path normalizedBase = pathutil::fromUtf8(destDir_).lexically_normal();
    if (normalizedDest.string().rfind(normalizedBase.string(), 0) != 0) {
        ++failed_;
        lastError_ = "path escaped the destination: " + rel;
        return;
    }
    std::vector<uint8_t> bytes;
    if (!item.source->read(*item.node, bytes)) {
        ++failed_;
        lastError_ = "read failed: " + item.node->path();
        return;
    }
    std::error_code ec;
    fs::create_directories(normalizedDest.parent_path(), ec);
    if (ec) {
        ++failed_;
        lastError_ = "cannot create " + pathutil::toUtf8(normalizedDest.parent_path());
        return;
    }
    // Decoded export: compiled Android XML becomes readable XML text; other
    // entries are written as-is (they are text or binary as-is).
    std::string text;
    if (decoded_ && AxmlDecoder::looksLikeAxml(bytes)) {
        std::string error;
        if (AxmlDecoder::decode(bytes, text, error)) {
            std::ofstream out(normalizedDest, std::ios::binary);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (!out) {
                ++failed_;
                lastError_ = "write failed: " + rel;
            }
            return;
        }
        // fall through: undecodable AXML is written raw
    }
    std::ofstream out(normalizedDest, std::ios::binary);
    if (!out) {
        ++failed_;
        lastError_ = "cannot open " + rel;
        return;
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        ++failed_;
        lastError_ = "write failed: " + rel;
    }
}
