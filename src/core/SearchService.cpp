#include "core/SearchService.hpp"
#include <algorithm>
#include "core/TextUtils.hpp"

namespace {
constexpr size_t kMaxHits = 3000;
constexpr size_t kMaxFileSize = 4 * 1024 * 1024;
constexpr size_t kMaxHitText = 300;  // stored line excerpts are capped

bool isCodeFile(NodeKind k) {
    return k == NodeKind::Java || k == NodeKind::Kotlin || k == NodeKind::Smali;
}

bool isTextLike(NodeKind k) {
    return k == NodeKind::Java || k == NodeKind::Kotlin || k == NodeKind::Xml || k == NodeKind::Text ||
           k == NodeKind::Json || k == NodeKind::Smali || k == NodeKind::Groovy || k == NodeKind::Yaml ||
           k == NodeKind::Web;
}
}  // namespace

SearchService::~SearchService() { stop(); }

void SearchService::stop() {
    stop_ = true;
    if (worker_.joinable()) worker_.join();
    stop_ = false;
    // Drop hits as well: they point into trees that may be gone (e.g. after
    // removing an APK from the project), so stale results must not survive.
    std::lock_guard<std::mutex> lock(mutex_);
    hits_.clear();
}

void SearchService::start(const TreeNode* root, const ContentSource* source, std::string query, Mode mode,
                          std::string group) {
    stop();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        hits_.clear();
    }
    truncated_ = false;
    skipped_ = 0;
    if (!root || query.empty()) return;
    if (mode != Mode::Filenames && !source) return;
    mode_ = mode;
    group_ = std::move(group);
    std::string lowered = tex::asciiLower(std::move(query));
    running_ = true;
    worker_ = std::thread(&SearchService::run, this, root, source, std::move(lowered));
}

void SearchService::run(const TreeNode* root, const ContentSource* source, std::string query) {
    if (mode_ == Mode::Filenames) scanFileNames(*root, query);
    else scan(*root, *source, query);
    std::vector<uint8_t>().swap(readBuffer_);  // give the scan buffer back
    running_ = false;
}

bool SearchService::addHit(const TreeNode& node, int line, const char* begin, const char* end) {
    size_t len = static_cast<size_t>(end - begin);
    std::string text(begin, len > kMaxHitText ? kMaxHitText : len);
    if (len > kMaxHitText) text += "...";
    std::lock_guard<std::mutex> lock(mutex_);
    if (hits_.size() >= kMaxHits) {
        truncated_ = true;
        stop_ = true;
        return false;
    }
    hits_.push_back({&node, line, std::move(text)});
    return true;
}

void SearchService::scanFileNames(const TreeNode& node, const std::string& query) {
    if (stop_) return;
    if (!node.isFolder() && tex::ciFind(node.name(), query) != std::string_view::npos) {
        if (!addHit(node, 0, node.path().data(), node.path().data() + node.path().size())) return;
    }
    for (const auto& c : node.children()) scanFileNames(*c, query);
}

bool SearchService::lineMatches(Mode mode, std::string_view line, std::string_view query) {
    // True when the query appears somewhere in the line directly followed
    // by `c` (used for "name(" method detection).
    const auto followedBy = [&](char c) {
        size_t p = 0;
        while (true) {
            size_t rel = tex::ciFind(line.substr(p), query);
            if (rel == std::string_view::npos) return false;
            size_t atEnd = p + rel + query.size();
            if (atEnd < line.size() && line[atEnd] == c) return true;
            p = p + rel + query.size();
        }
    };
    // Case-insensitive keyword scans happen in place. (Classes/Fields used to
    // bind a string_view to a temporary lowered copy of the line - a
    // dangling view, plus one heap allocation per scanned line.)
    const auto has = [&](const char* kw) { return tex::ciFind(line, kw) != std::string_view::npos; };
    switch (mode) {
    case Mode::Text: return tex::ciFind(line, query) != std::string_view::npos;
    case Mode::Classes: {
        const bool decl = has("class ") || has("interface ") || has("enum ") || has("record ") || has("object ");
        return decl && tex::ciContainsWord(line, query);
    }
    case Mode::Methods: return tex::ciContainsWord(line, query) && followedBy('(');
    case Mode::Fields: {
        const bool decl = has("private ") || has("public ") || has("protected ") || has("val ") || has("var ") ||
                          has("static ");
        const bool initializer = line.find('=') != std::string_view::npos || line.find(';') != std::string_view::npos;
        return decl && initializer && !followedBy('(') && tex::ciContainsWord(line, query);
    }
    default: return false;
    }
}

void SearchService::scan(const TreeNode& node, const ContentSource& source, const std::string& query) {
    if (stop_) return;
    if (node.isFolder()) {
        for (const auto& c : node.children()) scan(*c, source, query);
        return;
    }
    NodeKind k = node.kind();

    // Class searches also match source file names (Foo.java declares Foo).
    if (mode_ == Mode::Classes && isCodeFile(k) && tex::ciFind(node.name(), query) != std::string_view::npos) {
        if (!addHit(node, 0, node.path().data(), node.path().data() + node.path().size())) return;
    }
    if (!isTextLike(k)) return;

    // Check the size BEFORE reading: a huge file must not be pulled into
    // memory just to be skipped afterwards.
    uint64_t fileSize = 0;
    if (source.sizeOf(node, fileSize) && fileSize > kMaxFileSize) {
        skipped_++;
        return;
    }
    // One read buffer for the whole scan (capacity kept across files)
    // instead of a fresh multi-megabyte allocation per file.
    std::vector<uint8_t>& bytes = readBuffer_;
    if (!source.read(node, bytes)) return;
    if (bytes.size() > kMaxFileSize) {
        skipped_++;
        return;
    }

    // Case-insensitive matching happens in place on each line - no lowered
    // copies of every line are allocated.
    const char* data = reinterpret_cast<const char*>(bytes.data());
    const size_t total = bytes.size();
    size_t pos = 0;
    int lineNo = 0;
    while (pos <= total && !stop_) {
        size_t end = pos;
        while (end < total && data[end] != '\n') ++end;
        const char* lineBegin = data + pos;
        const size_t lineLen = end - pos;
        std::string_view line(lineBegin, lineLen);
        const bool match = lineMatches(mode_, line, query);
        if (match) {
            const char* b = lineBegin;
            const char* e = lineBegin + lineLen;
            while (b < e && (*b == ' ' || *b == '\t' || *b == '\r')) ++b;
            while (e > b && (e[-1] == '\r')) --e;
            if (!addHit(node, lineNo, b, e)) return;
        }
        pos = end + 1;
        ++lineNo;
    }
}
