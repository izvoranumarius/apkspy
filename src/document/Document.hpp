#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "document/SyntaxHighlighter.hpp"
#include "image/Texture.hpp"
#include "core/TreeNode.hpp"

struct ImageView {
    bool fit = true;
    float zoom = 1.f;
    float lastScale = 1.f;
    bool checker = true;
    bool showHex = false;
    bool hasPendingScroll = false;
    ImVec2 pendingScroll = ImVec2(0.f, 0.f);
};

class Document {
public:
    enum class Mode { Code, Hex, Image };

    Document(std::string title, const TreeNode* node, std::vector<uint8_t> bytes, bool fromDisk = false);

    const std::string& title() const { return title_; }
    const TreeNode* node() const { return node_; }
    Mode mode() const { return mode_; }
    Language language() const { return language_; }
    const std::vector<uint8_t>& bytes() const { return bytes_; }
    const std::vector<std::string>& lines() const { return lines_; }
    // Byte offset of each line's start inside editBuffer(); used to place the
    // caret in the syntax-highlighted editor.
    const std::vector<size_t>& lineOffsets() const { return lineOffsets_; }
    bool blockStateAt(size_t line) const { return line < blockStates_.size() && blockStates_[line]; }
    const std::string& note() const { return note_; }
    bool fromDisk() const { return fromDisk_; }
    // 0 = APK root, 1 = decompiled root; used for session restore.
    int rootKind() const { return rootKind_; }
    void setRootKind(int kind) { rootKind_ = kind; }
    // Group (APK) this document belongs to; ties documents to their APK in
    // multi-APK projects (session restore, Remove from Project).
    const std::string& rootGroup() const { return rootGroup_; }
    void setRootGroup(std::string group) { rootGroup_ = std::move(group); }

    Texture* texture() const { return texture_.get(); }
    const std::string& imageFormat() const { return imageFormat_; }
    ImageView& imageView() { return imageView_; }

    // --- Tab state -------------------------------------------------------
    // A preview tab is opened by a single click in the explorer and is
    // replaced when another file is previewed. Double-clicking promotes it
    // to a permanent tab that stays open until the user closes it.
    bool isPreview() const { return preview_; }
    void promote() { preview_ = false; }
    void setPreview(bool preview) { preview_ = preview; }

    // --- Editing ----------------------------------------------------------
    bool canEdit() const { return mode_ == Mode::Code && fromDisk_ && !node_->path().empty(); }
    bool isEditing() const { return editing_; }
    bool isDirty() const { return dirty_; }
    void beginEdit();
    std::string& editBuffer() { return editBuffer_; }
    // Marks the buffer changed and refreshes the line/block caches so the
    // syntax-highlighted editor keeps its colours in sync while typing.
    void markDirty();
    // Writes the edited text back to disk; returns false if impossible.
    bool save();
    void cancelEdit();

    void goTo(int line) {
        goTo_ = line;
        highlight_ = line;
    }
    int takeGoTo() {
        int l = goTo_;
        goTo_ = -1;
        return l;
    }
    int highlight() const { return highlight_; }

private:
    bool loadImage();
    void splitLines();
    void splitLinesFromText(const std::string& text);
    void computeBlockStates();

    std::string title_;
    const TreeNode* node_;
    std::vector<uint8_t> bytes_;
    bool fromDisk_ = false;
    int rootKind_ = 0;
    std::string rootGroup_;
    Mode mode_ = Mode::Hex;
    Language language_ = Language::Plain;
    std::vector<std::string> lines_;
    std::vector<size_t> lineOffsets_;
    std::vector<char> blockStates_;
    std::string note_;
    std::unique_ptr<Texture> texture_;
    std::string imageFormat_;
    ImageView imageView_;
    int goTo_ = -1;
    int highlight_ = -1;

    bool preview_ = true;
    bool editing_ = false;
    bool dirty_ = false;
    std::string editBuffer_;
};
