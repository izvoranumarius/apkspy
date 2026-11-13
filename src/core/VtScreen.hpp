#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

// A terminal screen fed with the output of a pseudo-console: printable text,
// line wrapping, scrolling into a scrollback, cursor movement, erasing,
// insert/delete, scroll regions, the alternate screen and SGR colours
// (16, 256 and 24-bit). Enough for shells, adb shell, Python and other REPLs;
// no mouse reporting or double-width characters.
class VtScreen {
public:
    struct Cell {
        char32_t ch = U' ';
        uint32_t fg = kDefault;  // 0xRRGGBB, or kDefault
        uint32_t bg = kDefault;
        uint8_t flags = 0;       // kBold | kInverse | kUnderline
    };
    static constexpr uint32_t kDefault = 0xFF000000u;
    static constexpr uint8_t kBold = 1, kInverse = 2, kUnderline = 4;
    using Line = std::vector<Cell>;

    VtScreen(int cols = 80, int rows = 24, size_t scrollback = 5000);

    void feed(std::string_view bytes);
    void resize(int cols, int rows);

    int cols() const { return cols_; }
    int rows() const { return rows_; }
    int cursorX() const { return cx_; }
    int cursorY() const { return cy_; }
    bool cursorVisible() const { return cursorVisible_; }
    bool altScreen() const { return alt_; }
    const std::string& title() const { return title_; }

    // Scrollback (oldest first) followed by the screen rows.
    size_t lineCount() const { return (alt_ ? 0 : scrollback_.size()) + (size_t)rows_; }
    const Line& line(size_t i) const;
    std::string lineText(size_t i) const;  // UTF-8, trailing spaces trimmed

    // Replies the terminal owes the program (cursor position reports).
    void setReply(std::function<void(const std::string&)> reply) { reply_ = std::move(reply); }
    // Bumped by every change, so the UI can skip work when nothing changed.
    uint64_t version() const { return version_; }

    static uint32_t paletteColor(int index);  // xterm 256-colour palette

private:
    void put(char32_t ch);
    void newline();
    void scrollUp(int top, int bottom, int n);
    void scrollDown(int top, int bottom, int n);
    void csi(char final);
    void sgr();
    void clearRow(Line& row, int from, int to);
    int param(size_t i, int def) const;

    int cols_, rows_;
    size_t maxScrollback_;
    std::vector<Line> screen_;
    std::vector<Line> mainScreen_;  // kept while the alternate screen is up
    std::deque<Line> scrollback_;
    int cx_ = 0, cy_ = 0;
    int savedX_ = 0, savedY_ = 0;
    int mainX_ = 0, mainY_ = 0;
    bool pendingWrap_ = false;
    bool cursorVisible_ = true;
    bool alt_ = false;
    int top_ = 0, bottom_ = 0;  // scroll region (inclusive)
    Cell pen_;
    std::string title_;
    uint64_t version_ = 0;

    // Parser state.
    enum class State { Text, Esc, Csi, Osc, OscEsc, Charset } state_ = State::Text;
    std::string params_;
    bool privateMode_ = false;
    std::string osc_;
    uint32_t utf8Code_ = 0;
    int utf8Left_ = 0;
    std::function<void(const std::string&)> reply_;
};
