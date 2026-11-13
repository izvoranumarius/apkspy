#include "document/Document.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include "core/ApkInfo.hpp"
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
std::string extensionOf(const std::string& name) {
    const size_t dot = name.find_last_of('.');
    return dot == std::string::npos ? std::string() : tex::asciiLower(name.substr(dot + 1));
}

bool startsWith(const std::vector<uint8_t>& b, const char* magic, size_t len, size_t at = 0) {
    return b.size() >= at + len && std::equal(magic, magic + len, b.begin() + (ptrdiff_t)at,
                                               [](char m, uint8_t v) { return (uint8_t)m == v; });
}

// Played by the audio view: by extension, or by content for files without one.
bool looksLikeAudio(const std::string& ext, const std::vector<uint8_t>& b) {
    if (ext == "ogg" || ext == "oga" || ext == "mp3" || ext == "wav" || ext == "flac" || ext == "opus" ||
        ext == "amr" || ext == "mid" || ext == "midi")
        return true;
    return startsWith(b, "OggS", 4) || startsWith(b, "fLaC", 4) || startsWith(b, "ID3", 3) ||
           (startsWith(b, "RIFF", 4) && startsWith(b, "WAVE", 4, 8));
}

// Played by the media player (Media Foundation): video, and AAC / M4A audio.
bool looksLikeVideo(const std::string& ext, const std::vector<uint8_t>& b) {
    if (ext == "mp4" || ext == "m4v" || ext == "mov" || ext == "3gp" || ext == "3g2" || ext == "webm" || ext == "mkv" ||
        ext == "wmv" || ext == "avi" || ext == "m4a" || ext == "aac")
        return true;
    return startsWith(b, "ftyp", 4, 4) || startsWith(b, "\x1A\x45\xDF\xA3", 4);
}

bool looksLikeFont(const std::string& ext, const std::vector<uint8_t>& b) {
    if (ext == "ttf" || ext == "otf" || ext == "ttc") return true;
    return startsWith(b, "\x00\x01\x00\x00", 4) || startsWith(b, "OTTO", 4) || startsWith(b, "ttcf", 4);
}

std::string fingerprint(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        if (i) out.push_back(':');
        out.push_back((char)std::toupper((unsigned char)hex[i]));
        out.push_back((char)std::toupper((unsigned char)hex[i + 1]));
    }
    return out;
}

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
    const std::string ext = extensionOf(node_->name());
    if (kind == NodeKind::Binary && looksLikeVideo(ext, bytes_)) {
        mode_ = Mode::Video;
        return;
    }
    if (kind == NodeKind::Binary && looksLikeAudio(ext, bytes_)) {
        mode_ = Mode::Audio;
        return;
    }
    if (kind == NodeKind::Binary && looksLikeFont(ext, bytes_)) {
        mode_ = Mode::Font;
        return;
    }
    // META-INF/*.RSA / .DSA / .EC: the v1 signature block, shown as its certificate.
    if (kind == NodeKind::Binary && (ext == "rsa" || ext == "dsa" || ext == "ec")) {
        ApkSigningInfo cert;
        if (ApkInfo::describeSignatureBlock(bytes_, cert)) {
            std::string text = "Signature block (PKCS#7), APK signature scheme v1 (JAR signing)\n\n";
            text += "Subject     CN=" + (cert.subject.empty() ? std::string("(none)") : cert.subject) + "\n";
            text += "Issuer      CN=" + (cert.issuer.empty() ? std::string("(none)") : cert.issuer) + "\n";
            text += "SHA-256     " + fingerprint(cert.certSha256) + "\n";
            mode_ = Mode::Code;
            note_ = "Decoded from the signature block";
            setText(std::move(text));
            return;
        }
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
