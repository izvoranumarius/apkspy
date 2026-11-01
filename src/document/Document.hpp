#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "document/SyntaxHighlighter.hpp"
#include "image/Texture.hpp"
#include "core/TreeNode.hpp"
#include "core/RootKind.hpp"

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

    Document(std::string title, const TreeNode* node, std::vector<uint8_t> bytes,
             RootKind rootKind = RootKind::Apk);

    const std::string& title() const { return title_; }
    const TreeNode* node() const { return node_; }
    Mode mode() const { return mode_; }
    Language language() const { return language_; }
    const std::vector<uint8_t>& bytes() const { return bytes_; }
    const std::vector<std::string>& lines() const;
    // Byte offset of each line's start inside editBuffer(); used to place the
    // caret in the syntax-highlighted editor.
    const std::vector<size_t>& lineOffsets() const;
    bool blockStateAt(size_t line) const;
    const std::string& note() const { return note_; }
    RootKind rootKind() const { return rootKind_; }
    void setRootKind(RootKind kind) { rootKind_ = kind; }
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
    void promote() { preview_ = false; bumpEditSerial(); }
    void setPreview(bool preview) { preview_ = preview; bumpEditSerial(); }

    // Bumped by every change that affects the "unsaved" comparison in the
    // title bar (edits, saves, promote/cancel); lets the UI skip its
    // per-frame deep check when nothing happened.
    static uint64_t editSerial() { return sEditSerial_.load(); }

    // --- Editing ----------------------------------------------------------
    // Only files on disk (decompiled output) can be modified; APK entries
    // stay read-only.
    bool canEdit() const { return mode_ == Mode::Code && rootKind_ == RootKind::Decompiled && !node_->path().empty(); }
    // The viewer is read-only by default; the editor's Edit toggle switches
    // this document into editing mode (and back, keeping any unsaved edits).
    bool wantsEdit() const { return wantsEdit_; }
    void setWantsEdit(bool want) { wantsEdit_ = want; }
    // Back to the read-only view without discarding unsaved edits.
    void stopEditingView() { editing_ = false; }
    bool isEditing() const { return editing_; }
    bool isDirty() const { return dirty_; }
    void beginEdit();
    std::string& editBuffer() { return editBuffer_; }
    // Marks the buffer changed; the line/block caches are re-built lazily on
    // the next access, so a burst of keystrokes costs one re-parse.
    void markDirty();
    // Writes the edited text back to disk; returns false if impossible.
    bool save();
    // Discards the edits and leaves editing mode ("Don't Save").
    void cancelEdit();

    // Jumps to a 0-BASED line number (-1 = clear). The highlight band is
    // drawn on that line by both the read-only viewer and the editor.
    // SearchHit::line and textsearch::Match::line use the same 0-based
    // convention; 1-based line numbers exist only in the UI (Ctrl+G, the
    // gutter and the Search panel add 1 for display).
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

    // Bumped by every change that alters which text lines() returns (edits,
    // entering/leaving edit mode, save). The editor's find bar compares this
    // against its own snapshot instead of re-hashing the text per frame.
    uint32_t textRevision() const { return textRevision_; }

    // Top visible line (0-based, -1 = never drawn). Plain UI view state kept
    // on the document so Back/Forward can return to the exact view position;
    // EditorPanel refreshes it every frame.
    int viewLine() const { return viewLine_; }
    void setViewLine(int line) { viewLine_ = line; }

private:
    bool loadImage();
    void splitLines();
    void computeBlockStates() const;
    void refreshEditCaches() const;  // lines + offsets + block states from editBuffer_
    static void bumpEditSerial() { sEditSerial_.fetch_add(1); }

    std::string title_;
    const TreeNode* node_;
    std::vector<uint8_t> bytes_;
    RootKind rootKind_ = RootKind::Apk;
    std::string rootGroup_;
    Mode mode_ = Mode::Hex;
    Language language_ = Language::Plain;
    mutable std::vector<std::string> lines_;
    mutable std::vector<size_t> lineOffsets_;
    mutable std::vector<char> blockStates_;
    mutable bool cachesDirty_ = false;  // edit buffer changed, caches are stale
    std::string note_;
    std::unique_ptr<Texture> texture_;
    std::string imageFormat_;
    ImageView imageView_;
    int goTo_ = -1;
    int highlight_ = -1;
    int viewLine_ = -1;  // top visible line, maintained by the editor panel

    bool preview_ = true;
    bool wantsEdit_ = false;
    bool editing_ = false;
    bool dirty_ = false;
    std::string editBuffer_;
    uint32_t textRevision_ = 0;

    static std::atomic<uint64_t> sEditSerial_;
};
