#include "core/SymbolIndex.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"

namespace fs = std::filesystem;

namespace {

constexpr uint64_t kMaxScanBytes = 256 * 1024;  // declarations live at the top of a file

bool isIdentStart(unsigned char c) { return std::isalpha(c) || c == '_' || c == '$'; }
bool isIdentPart(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$'; }

// Pulls the next identifier out of `text` starting at (and advancing) `pos`.
bool nextIdentifier(const std::string& text, size_t& pos, std::string& out) {
    while (pos < text.size() && !isIdentStart((unsigned char)text[pos])) ++pos;
    if (pos >= text.size()) return false;
    size_t start = pos;
    while (pos < text.size() && isIdentPart((unsigned char)text[pos])) ++pos;
    out.assign(text, start, pos - start);
    return true;
}

// "package com.example.sub;" -> "com.example.sub". Rough but sufficient for
// navigation: the value is only used to build fully qualified keys.
std::string packageOf(const std::string& text) {
    size_t pk = text.find("package");
    while (pk != std::string::npos && pk > 0 && isIdentPart((unsigned char)text[pk - 1]))
        pk = text.find("package", pk + 1);
    if (pk == std::string::npos) return {};
    size_t q = pk + 7;
    while (q < text.size() && (text[q] == ' ' || text[q] == '\t' || text[q] == '\r' || text[q] == '\n')) ++q;
    std::string qualified;
    while (q < text.size() && (isIdentPart((unsigned char)text[q]) || text[q] == '.'))
        qualified += text[q++];
    const size_t end = qualified.find_last_not_of('.');
    return end == std::string::npos ? std::string() : qualified.substr(0, end + 1);
}

}  // namespace

SymbolIndex::~SymbolIndex() {
    stop_ = true;
    if (worker_.joinable()) worker_.join();
}

void SymbolIndex::purgeGroup(const std::string& group) {
    std::lock_guard<std::mutex> lock(mutex_);
    tables_.erase(group);
    for (auto it = queue_.begin(); it != queue_.end();)
        it = it->group == group ? queue_.erase(it) : it + 1;
}

bool SymbolIndex::building(const std::string& group) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const Request& r : queue_)
        if (r.group == group) return true;
    // Conservative: a running worker may still be working on this group.
    return workerActive_.load();
}

// UI thread only (worker start / queue push are not otherwise synchronised).
void SymbolIndex::ensureIndex(const std::string& group, uint64_t epoch, std::vector<File> files,
                              std::shared_ptr<ContentSource> source) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tables_.find(group);
        if (it != tables_.end() && it->second && it->second->epoch == epoch) return;
        queue_.push_back({group, epoch, std::move(files), std::move(source)});
    }
    if (!workerActive_.load()) {
        stop_ = false;
        if (worker_.joinable()) worker_.join();
        workerActive_ = true;
        worker_ = std::thread(&SymbolIndex::workerLoop, this);
    }
}

std::shared_ptr<const SymbolIndex::Table> SymbolIndex::buildTable(const Request& req,
                                                                  const std::atomic<bool>& stop) {
    auto table = std::make_shared<Table>();
    table->epoch = req.epoch;
    const auto addName = [&](const std::string& name, const std::string& path, const std::string& pkg) {
        if (name.empty()) return;
        table->byName[name].push_back(path);
        if (!pkg.empty()) table->byQualifiedName[pkg + '.' + name] = path;
    };

    for (const File& f : req.files) {
        if (stop.load()) break;
        // Bound the read: class declarations live at the top of a file.
        std::error_code ec;
        uint64_t size = (uint64_t)fs::file_size(pathutil::fromUtf8(f.path), ec);
        if (ec || size == 0) continue;
        std::ifstream in(pathutil::fromUtf8(f.path), std::ios::binary);
        if (!in) continue;
        size_t toRead = (size_t)std::min<uint64_t>(size, kMaxScanBytes);
        std::string text(toRead, '\0');
        in.read(text.data(), (std::streamsize)toRead);
        text.resize((size_t)std::max<size_t>(0, (size_t)in.gcount()));
        if (text.empty()) continue;

        const std::string pkg = packageOf(text);

        // File stems: Foo.java registers "Foo"; Foo$Bar.java registers both
        // "Foo$Bar" and the nested simple name "Bar" (code references use the
        // simple name, the manifest uses the $ or dotted binary name).
        const std::string fileName = pathutil::toUtf8(fs::path(pathutil::fromUtf8(f.path)).filename());
        const size_t dot = fileName.find_last_of('.');
        const std::string stem = dot == std::string::npos ? fileName : fileName.substr(0, dot);
        std::string nested = stem;
        const size_t dollar = stem.rfind('$');
        if (dollar != std::string::npos) nested = stem.substr(dollar + 1);
        addName(stem, f.path, pkg);
        if (nested != stem) addName(nested, f.path, pkg);

        // Declared types: class/interface/enum/record plus Kotlin's object.
        // The scan is identifier-based, so a "class" inside a comment or
        // string can register a bogus name - harmless for navigation (the
        // entry points at a file that mentions the identifier), and cheap.
        std::string ident;
        size_t p = 0;
        while (nextIdentifier(text, p, ident)) {
            const bool declKeyword = ident == "class" || ident == "interface" || ident == "enum" ||
                                     ident == "record" || (f.kotlin && ident == "object");
            if (!declKeyword) continue;
            std::string name;
            if (!nextIdentifier(text, p, name)) break;
            addName(name, f.path, pkg);
        }
    }
    // Deterministic candidate order.
    for (auto& kv : table->byName) std::sort(kv.second.begin(), kv.second.end());
    return table;
}

void SymbolIndex::workerLoop() {
    for (;;) {
        Request req;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_.load() || queue_.empty()) break;
            req = std::move(queue_.front());
            queue_.pop_front();
        }
        auto table = buildTable(req, stop_);
        std::lock_guard<std::mutex> lock(mutex_);
        // Never let an older result overwrite a newer table.
        auto it = tables_.find(req.group);
        if (it == tables_.end() || !it->second || it->second->epoch <= table->epoch)
            tables_[req.group] = std::move(table);
    }
    workerActive_ = false;
}

std::string SymbolIndex::resolve(const std::string& group, const std::string& identifier,
                                 const std::string& hintDir) const {
    std::shared_ptr<const Table> table;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tables_.find(group);
        if (it == tables_.end()) return {};
        table = it->second;
    }
    if (!table || identifier.empty()) return {};

    // 1) Fully qualified names win (manifest component names, imports).
    if (identifier.find('.') != std::string::npos) {
        auto it = table->byQualifiedName.find(identifier);
        if (it != table->byQualifiedName.end()) return it->second;
    }

    // 2) Short name ("Foo", or "Bar" from Foo$Bar.java). Prefer a file from
    //    the same package as the file the user clicked in.
    auto it = table->byName.find(identifier);
    if (it == table->byName.end() || it->second.empty()) return {};
    if (!hintDir.empty()) {
        for (const std::string& path : it->second) {
            const std::string dir = pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).parent_path());
            if (dir == hintDir) return path;
        }
    }
    return it->second.front();
}
