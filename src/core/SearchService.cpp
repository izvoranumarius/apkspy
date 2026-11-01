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
    running_ = false;
}

bool SearchService::addHit(const TreeNode& node, int line, const char* begin, const char* end) {
    size_t len = (size_t)(end - begin);
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
    std::vector<uint8_t> bytes;
    if (!source.read(node, bytes)) return;
    if (bytes.size() > kMaxFileSize) {
        skipped_++;
        return;
    }

    // Case-insensitive matching happens in place on each line - no lowered
    // copies of every line are allocated.
    const char* data = (const char*)bytes.data();
    const size_t total = bytes.size();
    size_t pos = 0;
    int lineNo = 0;
    while (pos <= total && !stop_) {
        size_t end = pos;
        while (end < total && data[end] != '\n') ++end;
        const char* lineBegin = data + pos;
        const size_t lineLen = end - pos;
        std::string_view line(lineBegin, lineLen);
        // True when the query appears somewhere in the line directly
        // followed by `c` (used for "name(" method detection).
        auto followedBy = [&](char c) {
            size_t p = 0;
            while (true) {
                size_t rel = tex::ciFind(line.substr(p), query);
                if (rel == std::string_view::npos) return false;
                size_t atEnd = p + rel + query.size();
                if (atEnd < line.size() && line[atEnd] == c) return true;
                p = p + rel + query.size();
            }
        };
        bool match = false;
        switch (mode_) {
        case Mode::Text:
            match = tex::ciFind(line, query) != std::string_view::npos;
            break;
        case Mode::Classes: {
            std::string_view low = tex::asciiLower(line);  // keyword scan needs a lowered copy
            bool decl = low.find("class ") != std::string_view::npos ||
                        low.find("interface ") != std::string_view::npos ||
                        low.find("enum ") != std::string_view::npos ||
                        low.find("record ") != std::string_view::npos ||
                        low.find("object ") != std::string_view::npos;
            match = decl && tex::ciContainsWord(line, query);
            break;
        }
        case Mode::Methods:
            match = tex::ciContainsWord(line, query) && followedBy('(');
            break;
        case Mode::Fields: {
            std::string_view low = tex::asciiLower(line);
            bool decl = low.find("private ") != std::string_view::npos ||
                        low.find("public ") != std::string_view::npos ||
                        low.find("protected ") != std::string_view::npos ||
                        low.find("val ") != std::string_view::npos || low.find("var ") != std::string_view::npos ||
                        low.find("static ") != std::string_view::npos;
            bool initializer = line.find('=') != std::string_view::npos || line.find(';') != std::string_view::npos;
            match = decl && initializer && !followedBy('(') && tex::ciContainsWord(line, query);
            break;
        }
        default:
            break;
        }
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
