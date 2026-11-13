#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Hex viewer for one file: address, hex and text columns with a data
// inspector. Click and drag (or Shift+click, Shift+arrows) to select a range;
// Ctrl+C copies it as hex and the context menu offers other formats.
class HexView {
public:
    void draw(const std::vector<uint8_t>& bytes);

    // What a file is, from its first bytes ("DEX 035", "ELF 64-bit", ...);
    // empty when nothing is recognised. Exposed for the tests.
    static std::string describeFormat(const uint8_t* data, size_t size);

private:
    void drawToolbar(const std::vector<uint8_t>& bytes);
    void drawBody(const std::vector<uint8_t>& bytes);
    void drawInspector(const std::vector<uint8_t>& bytes);
    void handleKeys(const std::vector<uint8_t>& bytes, int visibleRows);
    void contextMenu(const std::vector<uint8_t>& bytes);
    void find(const std::vector<uint8_t>& bytes, bool backward);
    void select(int64_t anchor, int64_t cursor, bool scroll);
    int64_t selBegin() const { return cursor_ < anchor_ ? cursor_ : anchor_; }
    int64_t selEnd() const { return cursor_ < anchor_ ? anchor_ : cursor_; }  // inclusive

    int64_t anchor_ = -1;  // selection: anchor_..cursor_ (inclusive), -1 = none
    int64_t cursor_ = -1;
    bool dragging_ = false;
    bool scrollToCursor_ = false;
    int bytesPerRow_ = 16;
    bool bigEndian_ = false;
    bool findText_ = false;
    char gotoBuf_[32] = {};
    char findBuf_[128] = {};
    std::string status_;
    std::string format_;
    bool formatKnown_ = false;
};
