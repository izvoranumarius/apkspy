#include "core/SearchService.hpp"
#include <algorithm>
#include <cctype>

namespace {
constexpr size_t kMaxHits = 3000;
constexpr size_t kMaxFileSize = 4 * 1024 * 1024;

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

bool isIdentChar(unsigned char c) { return std::isalnum(c) || c == '_' || c == '$'; }

// True when `query` occurs in `line` as a standalone identifier.
bool containsWord(const std::string& lineLower, const std::string& queryLower) {
    size_t pos = 0;
    while ((pos = lineLower.find(queryLower, pos)) != std::string::npos) {
        bool leftOk = pos == 0 || !isIdentChar((unsigned char)lineLower[pos - 1]);
        size_t end = pos + queryLower.size();
        bool rightOk = end >= lineLower.size() || !isIdentChar((unsigned char)lineLower[end]);
        if (leftOk && rightOk) return true;
        pos = end;
    }
    return false;
}

bool isCodeFile(NodeKind k) {
    return k == NodeKind::Java || k == NodeKind::Kotlin || k == NodeKind::Smali;
}

bool isTextLike(NodeKind k) {
    return k == NodeKind::Java || k == NodeKind::Kotlin || k == NodeKind::Xml || k == NodeKind::Text ||
           k == NodeKind::Json || k == NodeKind::Smali || k == NodeKind::Groovy || k == NodeKind::Yaml ||
           k == NodeKind::Web;
}
}

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

void SearchService::start(const TreeNode* root, const ContentSource* source, std::string query, Mode mode) {
    stop();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        hits_.clear();
    }
    if (!root || query.empty()) return;
    if (mode != Mode::Filenames && !source) return;
    mode_ = mode;
    running_ = true;
    worker_ = std::thread(&SearchService::run, this, root, source, lower(std::move(query)));
}

void SearchService::run(const TreeNode* root, const ContentSource* source, std::string query) {
    if (mode_ == Mode::Filenames) scanFileNames(*root, query);
    else scan(*root, *source, query);
    running_ = false;
}

bool SearchService::addHit(const TreeNode& node, int line, std::string text) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (hits_.size() >= kMaxHits) {
        stop_ = true;
        return false;
    }
    hits_.push_back({&node, node.name(), line, std::move(text)});
    return true;
}

void SearchService::scanFileNames(const TreeNode& node, const std::string& query) {
    if (stop_) return;
    if (!node.isFolder() && lower(node.name()).find(query) != std::string::npos) {
        if (!addHit(node, 0, node.path())) return;
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

    if (mode_ == Mode::Filenames) return;  // handled above

    // Class searches also match source file names (Foo.java declares Foo).
    if (mode_ == Mode::Classes && isCodeFile(k) && lower(node.name()).find(query) != std::string::npos) {
        if (!addHit(node, 0, node.path())) return;
    }
    if (!isTextLike(k)) return;

    std::vector<uint8_t> bytes;
    if (!source.read(node, bytes) || bytes.size() > kMaxFileSize) return;
    std::string content(bytes.begin(), bytes.end());
    size_t pos = 0;
    int lineNo = 0;
    while (pos <= content.size() && !stop_) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos) end = content.size();
        std::string line = content.substr(pos, end - pos);
        std::string lineLower = lower(line);
        bool match = false;
        switch (mode_) {
        case Mode::Text:
            match = lineLower.find(query) != std::string::npos;
            break;
        case Mode::Classes: {
            bool decl = lineLower.find("class ") != std::string::npos ||
                        lineLower.find("interface ") != std::string::npos ||
                        lineLower.find("enum ") != std::string::npos ||
                        lineLower.find("record ") != std::string::npos ||
                        lineLower.find("object ") != std::string::npos;
            match = decl && containsWord(lineLower, query);
            break;
        }
        case Mode::Methods:
            match = containsWord(lineLower, query) && lineLower.find(query + "(") != std::string::npos;
            break;
        case Mode::Fields: {
            bool decl = lineLower.find("private ") != std::string::npos ||
                        lineLower.find("public ") != std::string::npos ||
                        lineLower.find("protected ") != std::string::npos ||
                        lineLower.find("val ") != std::string::npos || lineLower.find("var ") != std::string::npos ||
                        lineLower.find("static ") != std::string::npos;
            bool initializer = line.find('=') != std::string::npos || line.find(';') != std::string::npos;
            match = decl && initializer && containsWord(lineLower, query) &&
                    lineLower.find(query + "(") == std::string::npos;
            break;
        }
        default:
            break;
        }
        if (match) {
            size_t first = line.find_first_not_of(" \t\r");
            std::string trimmed = first == std::string::npos ? std::string() : line.substr(first);
            while (!trimmed.empty() && trimmed.back() == '\r') trimmed.pop_back();
            if (!addHit(node, lineNo, std::move(trimmed))) return;
        }
        pos = end + 1;
        ++lineNo;
    }
}
