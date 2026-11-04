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

// Start offset of each line inside `text` ('\n' separated) - the single
// line-indexing helper for the whole document (file text and edit buffer).
void lineOffsetsOf(std::string_view text, std::vector<uint32_t>& offsets) {
    offsets.clear();
    offsets.push_back(0);
    for (size_t i = 0; i < text.size(); ++i)
        if (text[i] == '\n') offsets.push_back((uint32_t)(i + 1));
    offsets.shrink_to_fit();
}
}  // namespace

std::atomic<uint64_t> Document::sEditSerial_{1};

Document::Document(std::string title, const TreeNode* node, std::vector<uint8_t> bytes, RootKind rootKind,
                   const ResourceTable* resources)
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
        if (AxmlDecoder::decode(bytes_, xml, error, resources)) {
            mode_ = Mode::Code;
            language_ = Language::Xml;
            setText(std::move(xml));
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
    } else if (node_->name().size() > 3 &&
               tex::asciiLower(node_->name().substr(node_->name().size() - 3)) == ".py") {
        language_ = Language::Python;
    }
    setText(std::string((const char*)bytes_.data(), bytes_.size()));
    bytes_.clear();
    bytes_.shrink_to_fit();
}

Document::Document(std::string title, const TreeNode* node, std::string text, Language language,
                   RootKind rootKind)
    : title_(std::move(title)), node_(node), rootKind_(rootKind) {
    mode_ = Mode::Code;
    language_ = language;
    setText(std::move(text));
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

void Document::setText(std::string text) {
    // Line endings are normalised to '\n' once, in place (no second copy).
    text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
    text.shrink_to_fit();
    text_ = std::move(text);
    lineOffsetsOf(text_, lineOffsets_);
    computeBlockStates();
}

std::string_view Document::text() const {
    return usesEditBuffer() ? std::string_view(editBuffer_) : std::string_view(text_);
}

size_t Document::lineCount() const {
    if (cachesDirty_) refreshEditCaches();
    return lineOffsets_.size();
}

std::string_view Document::line(size_t i) const {
    if (cachesDirty_) refreshEditCaches();
    if (i >= lineOffsets_.size()) return {};
    const std::string_view all = text();
    const size_t begin = std::min<size_t>(lineOffsets_[i], all.size());
    size_t end = i + 1 < lineOffsets_.size() ? (size_t)lineOffsets_[i + 1] - 1 : all.size();
    end = std::max(begin, std::min(end, all.size()));
    if (end > begin && all[end - 1] == '\r') --end;  // CRLF pasted into the edit buffer
    return all.substr(begin, end - begin);
}

const std::vector<uint32_t>& Document::lineOffsets() const {
    if (cachesDirty_) refreshEditCaches();
    return lineOffsets_;
}

bool Document::blockStateAt(size_t line) const {
    if (cachesDirty_) refreshEditCaches();
    return line < blockStates_.size() && blockStates_[line];
}

void Document::computeBlockStates() const {
    bool inBlock = false;
    std::vector<Span> scratch;
    const std::string_view all = text();
    const size_t n = lineOffsets_.size();
    blockStates_.assign(n, 0);
    for (size_t i = 0; i < n; ++i) {
        blockStates_[i] = inBlock;
        const size_t begin = lineOffsets_[i];
        const size_t end = i + 1 < n ? (size_t)lineOffsets_[i + 1] - 1 : all.size();
        SyntaxHighlighter::tokenize(all.substr(begin, end - begin), language_, inBlock, scratch);
    }
}

void Document::refreshEditCaches() const {
    cachesDirty_ = false;
    lineOffsetsOf(text(), lineOffsets_);
    computeBlockStates();
}

void Document::beginEdit() {
    if (!canEdit() || editing_) return;
    // Unsaved edits survive a trip back to the viewer; otherwise start from
    // the read-only text (already '\n'-joined, so this is one copy).
    if (!dirty_) editBuffer_ = text_;
    editing_ = true;
    ++textRevision_;  // line() now reads the (identical) edit buffer snapshot
}

void Document::markDirty() {
    dirty_ = true;
    cachesDirty_ = true;  // re-index lazily on the next line()/blockStateAt()
    bumpEditSerial();
    ++textRevision_;
}

void Document::cancelEdit() {
    editing_ = false;
    wantsEdit_ = false;
    dirty_ = false;
    // Release the edit copy; the views fall back to the untouched read-only
    // text on the next access.
    std::string().swap(editBuffer_);
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
    dirty_ = false;
    editing_ = false;
    // The saved buffer becomes the read-only text (moved, not copied).
    std::string saved;
    saved.swap(editBuffer_);
    setText(std::move(saved));
    cachesDirty_ = false;
    bumpEditSerial();
    ++textRevision_;
    return true;
}
