#include "document/Document.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include "core/AxmlDecoder.hpp"
#include "image/ImageDecoder.hpp"

namespace {
constexpr size_t kMaxTextSize = 8 * 1024 * 1024;

bool looksLikeText(const std::vector<uint8_t>& bytes) {
    size_t n = std::min<size_t>(bytes.size(), 4096);
    for (size_t i = 0; i < n; ++i)
        if (bytes[i] == 0) return false;
    return true;
}
}

Document::Document(std::string title, const TreeNode* node, std::vector<uint8_t> bytes, bool fromDisk)
    : title_(std::move(title)), node_(node), bytes_(std::move(bytes)), fromDisk_(fromDisk) {
    NodeKind kind = node_->kind();
    bool imageCandidate = kind == NodeKind::Image ||
                          (kind == NodeKind::Binary && !ImageDecoder::sniffFormat(bytes_).empty());
    if (imageCandidate) {
        loadImage();
        return;
    }
    bool binaryKind = kind == NodeKind::Dex || kind == NodeKind::Native;

    // Binary XML inside an APK (AndroidManifest.xml, res/**/*.xml) is compiled
    // AXML - decode it into readable, editable-looking text instead of hex.
    if (!binaryKind && AxmlDecoder::looksLikeAxml(bytes_)) {
        std::string xml, error;
        if (AxmlDecoder::decode(bytes_, xml, error)) {
            mode_ = Mode::Code;
            language_ = Language::Xml;
            splitLinesFromText(xml);
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
        const std::string& name = node_->name();
        size_t dot = name.find_last_of('.');
        std::string ext = dot == std::string::npos ? std::string() : name.substr(dot + 1);
        for (char& c : ext) c = (char)std::tolower((unsigned char)c);
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

void Document::splitLines() {
    std::string current;
    for (uint8_t b : bytes_) {
        if (b == '\n') {
            lines_.push_back(std::move(current));
            current.clear();
        } else if (b != '\r') {
            current.push_back((char)b);
        }
    }
    lines_.push_back(std::move(current));
}

void Document::splitLinesFromText(const std::string& text) {
    lines_.clear();
    lineOffsets_.clear();
    lineOffsets_.push_back(0);
    std::string current;
    size_t i = 0;
    for (char b : text) {
        if (b == '\n') {
            lines_.push_back(std::move(current));
            current.clear();
            lineOffsets_.push_back(i + 1);
        } else if (b != '\r') {
            current.push_back(b);
        }
        ++i;
    }
    lines_.push_back(std::move(current));
}

void Document::computeBlockStates() {
    bool inBlock = false;
    std::vector<Span> scratch;
    blockStates_.reserve(lines_.size());
    for (const auto& line : lines_) {
        blockStates_.push_back(inBlock);
        SyntaxHighlighter::tokenize(line, language_, inBlock, scratch);
    }
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
        // Byte offsets matching the freshly built buffer (lines_ joined with
        // '\n'); kept in sync by markDirty()/save() from here on.
        lineOffsets_.clear();
        size_t offset = 0;
        for (const auto& line : lines_) {
            lineOffsets_.push_back(offset);
            offset += line.size() + 1;
        }
    }
    editing_ = true;
}

void Document::markDirty() {
    dirty_ = true;
    if (editing_) {
        splitLinesFromText(editBuffer_);
        computeBlockStates();
    }
}

void Document::cancelEdit() {
    editing_ = false;
    dirty_ = false;
    editBuffer_.clear();
    editBuffer_.shrink_to_fit();
}

bool Document::save() {
    if (!canEdit()) return false;
    std::ofstream out(node_->path(), std::ios::binary);
    if (!out) return false;
    out.write(editBuffer_.data(), (std::streamsize)editBuffer_.size());
    out.close();
    if (!out) return false;
    splitLinesFromText(editBuffer_);
    computeBlockStates();
    dirty_ = false;
    editing_ = false;
    editBuffer_.clear();
    editBuffer_.shrink_to_fit();
    return true;
}
