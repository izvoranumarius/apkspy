#include "document/Document.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include "core/AxmlDecoder.hpp"
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"
#include "image/ImageDecoder.hpp"

namespace {
constexpr size_t kMaxTextSize = 8 * 1024 * 1024;

bool looksLikeText(const std::vector<uint8_t>& bytes) {
    size_t n = std::min<size_t>(bytes.size(), 4096);
    for (size_t i = 0; i < n; ++i)
        if (bytes[i] == 0) return false;
    return true;
}

// Splits text into lines (dropping \r) - the single line-splitting helper for
// the whole document, used for both file bytes and the edit buffer.
std::vector<std::string> splitTextLines(std::string_view text) {
    std::vector<std::string> lines;
    std::string current;
    for (char b : text) {
        if (b == '\n') {
            lines.push_back(std::move(current));
            current.clear();
        } else if (b != '\r') {
            current.push_back(b);
        }
    }
    lines.push_back(std::move(current));
    return lines;
}

// Byte offset of each line's start inside `text` (which uses \n only).
std::vector<size_t> lineOffsetsOf(std::string_view text) {
    std::vector<size_t> offsets;
    offsets.push_back(0);
    for (size_t i = 0; i < text.size(); ++i)
        if (text[i] == '\n') offsets.push_back(i + 1);
    return offsets;
}
}  // namespace

std::atomic<uint64_t> Document::sEditSerial_{1};

Document::Document(std::string title, const TreeNode* node, std::vector<uint8_t> bytes, RootKind rootKind)
    : title_(std::move(title)), node_(node), bytes_(std::move(bytes)), rootKind_(rootKind) {
    NodeKind kind = node_->kind();
    bool imageCandidate = kind == NodeKind::Image ||
                          (kind == NodeKind::Binary && !ImageDecoder::sniffFormat(bytes_).empty());
    if (imageCandidate) {
        loadImage();
        return;
    }
    bool binaryKind = kind == NodeKind::Dex || kind == NodeKind::Native;

    // Binary XML inside an APK (AndroidManifest.xml, res/**/*.xml) is compiled
    // AXML - decode it into readable, highlighted text instead of hex.
    if (!binaryKind && AxmlDecoder::looksLikeAxml(bytes_)) {
        std::string xml, error;
        if (AxmlDecoder::decode(bytes_, xml, error)) {
            mode_ = Mode::Code;
            language_ = Language::Xml;
            lines_ = splitTextLines(xml);
            computeBlockStates();
            note_ = "Decoded from binary XML";
            bytes_.clear();
            bytes_.shrink_to_fit();
            return;
        }
        note_ = "Could not decode binary XML: " + error;
    }

    bool text = !binaryKind && bytes_.size() <= kMaxTextSize && looksLikeText(bytes_);
    if (!text) return;
    mode_ = Mode::Code;
    if (kind == NodeKind::Java) language_ = Language::Java;
    else if (kind == NodeKind::Kotlin) language_ = Language::Kotlin;
    else if (kind == NodeKind::Xml) language_ = Language::Xml;
    else if (kind == NodeKind::Json) language_ = Language::Json;
    else if (kind == NodeKind::Smali) language_ = Language::Smali;
    else if (kind == NodeKind::Groovy) language_ = Language::Groovy;
    else if (kind == NodeKind::Yaml) language_ = Language::Yaml;
    else if (kind == NodeKind::Web) {
        std::string ext = tex::asciiLower(node_->name().substr(node_->name().find_last_of('.') + 1));
        if (ext == "css") language_ = Language::Css;
        else if (ext == "js" || ext == "mjs") language_ = Language::JavaScript;
        else language_ = Language::Xml;  // html/htm
    }
    splitLines();
    computeBlockStates();
    bytes_.clear();
    bytes_.shrink_to_fit();
}

bool Document::loadImage() {
    DecodedImage image;
    std::string error;
    if (!ImageDecoder::decode(bytes_, image, error)) {
        note_ = "Cannot display image: " + error;
        return false;
    }
    if (image.width > Texture::maxSize() || image.height > Texture::maxSize()) {
        note_ = "Image is larger than the maximum GPU texture size";
        return false;
    }
    texture_ = std::make_unique<Texture>(image.rgba.data(), image.width, image.height);
    imageFormat_ = image.format;
    mode_ = Mode::Image;
    return true;
}

const std::vector<std::string>& Document::lines() const {
    if (cachesDirty_) refreshEditCaches();
    return lines_;
}

const std::vector<size_t>& Document::lineOffsets() const {
    if (cachesDirty_) refreshEditCaches();
    return lineOffsets_;
}

bool Document::blockStateAt(size_t line) const {
    if (cachesDirty_) refreshEditCaches();
    return line < blockStates_.size() && blockStates_[line];
}

void Document::splitLines() {
    lines_ = splitTextLines(std::string_view((const char*)bytes_.data(), bytes_.size()));
}

void Document::computeBlockStates() const {
    bool inBlock = false;
    std::vector<Span> scratch;
    blockStates_.clear();
    blockStates_.reserve(lines_.size());
    for (const auto& line : lines_) {
        blockStates_.push_back(inBlock);
        SyntaxHighlighter::tokenize(line, language_, inBlock, scratch);
    }
}

void Document::refreshEditCaches() const {
    cachesDirty_ = false;
    lines_ = splitTextLines(editBuffer_);
    lineOffsets_ = lineOffsetsOf(editBuffer_);
    computeBlockStates();
}

void Document::beginEdit() {
    if (!canEdit() || editing_) return;
    if (editBuffer_.empty()) {
        size_t total = 0;
        for (const auto& line : lines_) total += line.size() + 1;
        editBuffer_.reserve(total + 1);
        for (size_t i = 0; i < lines_.size(); ++i) {
            if (i) editBuffer_.push_back('\n');
            editBuffer_.append(lines_[i]);
        }
    }
    editing_ = true;
    ++textRevision_;  // lines() now reflects the (identical) edit buffer snapshot
}

void Document::markDirty() {
    dirty_ = true;
    cachesDirty_ = true;  // re-parse lazily on the next lines()/blockStateAt()
    bumpEditSerial();
    ++textRevision_;
}

void Document::cancelEdit() {
    editing_ = false;
    wantsEdit_ = false;
    dirty_ = false;
    editBuffer_.clear();
    editBuffer_.shrink_to_fit();
    cachesDirty_ = true;
    bumpEditSerial();
    ++textRevision_;
}

bool Document::save() {
    if (!canEdit()) return false;
    std::ofstream out(pathutil::fromUtf8(node_->path()), std::ios::binary);
    if (!out) return false;
    out.write(editBuffer_.data(), (std::streamsize)editBuffer_.size());
    out.close();
    if (!out) return false;
    lines_ = splitTextLines(editBuffer_);
    lineOffsets_ = lineOffsetsOf(editBuffer_);
    computeBlockStates();
    cachesDirty_ = false;
    dirty_ = false;
    editing_ = false;
    editBuffer_.clear();
    editBuffer_.shrink_to_fit();
    bumpEditSerial();
    ++textRevision_;
    return true;
}
