#include "core/VtScreen.hpp"
#include <algorithm>
#include <cstdlib>

namespace {

void appendUtf8(std::string& out, char32_t c) {
    if (c < 0x80) {
        out.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (c >> 6)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (c >> 12)));
        out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (c >> 18)));
        out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
}

}  // namespace

VtScreen::VtScreen(int cols, int rows, size_t scrollback)
    : cols_(std::max(1, cols)), rows_(std::max(1, rows)), maxScrollback_(scrollback) {
    screen_.assign(static_cast<size_t>(rows_), Line(static_cast<size_t>(cols_)));
    bottom_ = rows_ - 1;
}

uint32_t VtScreen::paletteColor(int i) {
    if (i < 16) return kIndexed | static_cast<uint32_t>(std::max(0, i));  // resolved by the theme
    if (i < 232) {  // 6x6x6 cube
        const int v = i - 16;
        const auto level = [](int x) { return x == 0 ? 0 : 55 + x * 40; };
        return static_cast<uint32_t>(level(v / 36) << 16 | level((v / 6) % 6) << 8 | level(v % 6));
    }
    const int g = 8 + (std::min(i, 255) - 232) * 10;  // grey ramp
    return static_cast<uint32_t>(g << 16 | g << 8 | g);
}

const VtScreen::Line& VtScreen::line(size_t i) const {
    const size_t back = alt_ ? 0 : scrollback_.size();
    if (i < back) return scrollback_[i];
    return screen_[std::min(i - back, screen_.size() - 1)];
}

std::string VtScreen::lineText(size_t i) const {
    const Line& l = line(i);
    std::string out;
    size_t end = l.size();
    while (end > 0 && l[end - 1].ch == U' ') --end;
    for (size_t k = 0; k < end; ++k) appendUtf8(out, l[k].ch);
    return out;
}

void VtScreen::resize(int cols, int rows) {
    cols = std::max(1, cols);
    rows = std::max(1, rows);
    if (cols == cols_ && rows == rows_) return;
    for (auto& l : screen_) l.resize(static_cast<size_t>(cols));
    for (auto& l : mainScreen_) l.resize(static_cast<size_t>(cols));
    // Shrinking keeps the rows around the cursor: the top ones go to scrollback.
    while (static_cast<int>(screen_.size()) > rows) {
        if (cy_ >= rows) {  // the cursor would fall off: the top row scrolls away
            if (!alt_) scrollback_.push_back(std::move(screen_.front()));
            screen_.erase(screen_.begin());
            --cy_;
        } else {
            screen_.pop_back();  // empty space below the cursor
        }
    }
    while (static_cast<int>(screen_.size()) < rows) screen_.emplace_back(static_cast<size_t>(cols));
    while (scrollback_.size() > maxScrollback_) scrollback_.pop_front();
    cols_ = cols;
    rows_ = rows;
    top_ = 0;
    bottom_ = rows_ - 1;
    cx_ = std::min(cx_, cols_ - 1);
    cy_ = std::min(cy_, rows_ - 1);
    pendingWrap_ = false;
    ++version_;
}

void VtScreen::clearRow(Line& row, int from, int to) {
    Cell blank;
    blank.bg = pen_.bg;
    for (int x = std::max(0, from); x < std::min(to, static_cast<int>(row.size())); ++x) row[static_cast<size_t>(x)] = blank;
}

void VtScreen::scrollUp(int top, int bottom, int n) {
    for (int k = 0; k < n; ++k) {
        if (top == 0 && !alt_) {
            scrollback_.push_back(screen_[static_cast<size_t>(top)]);
            if (scrollback_.size() > maxScrollback_) scrollback_.pop_front();
        }
        screen_.erase(screen_.begin() + top);
        screen_.insert(screen_.begin() + bottom, Line(static_cast<size_t>(cols_)));
        clearRow(screen_[static_cast<size_t>(bottom)], 0, cols_);
    }
}

void VtScreen::scrollDown(int top, int bottom, int n) {
    for (int k = 0; k < n; ++k) {
        screen_.erase(screen_.begin() + bottom);
        screen_.insert(screen_.begin() + top, Line(static_cast<size_t>(cols_)));
        clearRow(screen_[static_cast<size_t>(top)], 0, cols_);
    }
}

void VtScreen::newline() {
    if (cy_ == bottom_) scrollUp(top_, bottom_, 1);
    else if (cy_ < rows_ - 1) ++cy_;
}

void VtScreen::put(char32_t ch) {
    if (pendingWrap_) {
        pendingWrap_ = false;
        cx_ = 0;
        newline();
    }
    Cell c = pen_;
    c.ch = ch;
    screen_[static_cast<size_t>(cy_)][static_cast<size_t>(cx_)] = c;
    if (cx_ == cols_ - 1) pendingWrap_ = true;
    else ++cx_;
}

int VtScreen::param(size_t i, int def) const {
    size_t start = 0;
    for (size_t k = 0; k < i; ++k) {
        start = params_.find(';', start);
        if (start == std::string::npos) return def;
        ++start;
    }
    if (start >= params_.size() || params_[start] == ';') return def;
    return std::atoi(params_.c_str() + start);
}

void VtScreen::sgr() {
    std::vector<int> p;
    if (params_.empty()) p.push_back(0);
    size_t start = 0;
    while (start <= params_.size() && !params_.empty()) {
        const size_t end = params_.find_first_of(";:", start);
        p.push_back(std::atoi(params_.substr(start, end == std::string::npos ? std::string::npos : end - start).c_str()));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    for (size_t i = 0; i < p.size(); ++i) {
        const int v = p[i];
        if (v == 0) pen_ = Cell{};
        else if (v == 1) pen_.flags |= kBold;
        else if (v == 4) pen_.flags |= kUnderline;
        else if (v == 7) pen_.flags |= kInverse;
        else if (v == 22) pen_.flags &= static_cast<uint8_t>(~kBold);
        else if (v == 24) pen_.flags &= static_cast<uint8_t>(~kUnderline);
        else if (v == 27) pen_.flags &= static_cast<uint8_t>(~kInverse);
        else if (v >= 30 && v <= 37) pen_.fg = paletteColor(v - 30);
        else if (v == 39) pen_.fg = kDefault;
        else if (v >= 40 && v <= 47) pen_.bg = paletteColor(v - 40);
        else if (v == 49) pen_.bg = kDefault;
        else if (v >= 90 && v <= 97) pen_.fg = paletteColor(v - 90 + 8);
        else if (v >= 100 && v <= 107) pen_.bg = paletteColor(v - 100 + 8);
        else if ((v == 38 || v == 48) && i + 1 < p.size()) {
            uint32_t color = kDefault;
            if (p[i + 1] == 5 && i + 2 < p.size()) {
                color = paletteColor(p[i + 2]);
                i += 2;
            } else if (p[i + 1] == 2 && i + 4 < p.size()) {
                color = static_cast<uint32_t>((p[i + 2] & 255) << 16 | (p[i + 3] & 255) << 8 | (p[i + 4] & 255));
                i += 4;
            }
            (v == 38 ? pen_.fg : pen_.bg) = color;
        }
    }
}

void VtScreen::csi(char f) {
    const int n = std::max(1, param(0, 1));
    pendingWrap_ = false;
    if (privateMode_) {
        if (f == 'h' || f == 'l') {
            const bool on = f == 'h';
            const int mode = param(0, 0);
            if (mode == 25) cursorVisible_ = on;
            if ((mode == 1049 || mode == 47 || mode == 1047) && on != alt_) {
                if (on) {
                    mainScreen_ = screen_;
                    mainX_ = cx_;
                    mainY_ = cy_;
                    for (auto& l : screen_) clearRow(l, 0, cols_);
                    alt_ = true;
                } else {
                    screen_ = mainScreen_;
                    screen_.resize(static_cast<size_t>(rows_), Line(static_cast<size_t>(cols_)));
                    cx_ = std::min(mainX_, cols_ - 1);
                    cy_ = std::min(mainY_, rows_ - 1);
                    alt_ = false;
                }
            }
        }
        return;
    }
    switch (f) {
    case 'A': cy_ = std::max(top_ <= cy_ ? top_ : 0, cy_ - n); break;
    case 'B': cy_ = std::min(cy_ <= bottom_ ? bottom_ : rows_ - 1, cy_ + n); break;
    case 'C': cx_ = std::min(cols_ - 1, cx_ + n); break;
    case 'D': cx_ = std::max(0, cx_ - n); break;
    case 'E': cx_ = 0, cy_ = std::min(rows_ - 1, cy_ + n); break;
    case 'F': cx_ = 0, cy_ = std::max(0, cy_ - n); break;
    case 'G': case '`': cx_ = std::clamp(n - 1, 0, cols_ - 1); break;
    case 'd': cy_ = std::clamp(n - 1, 0, rows_ - 1); break;
    case 'H': case 'f':
        cy_ = std::clamp(param(0, 1) - 1, 0, rows_ - 1);
        cx_ = std::clamp(param(1, 1) - 1, 0, cols_ - 1);
        break;
    case 'J': {
        const int mode = param(0, 0);
        if (mode == 0) {
            clearRow(screen_[static_cast<size_t>(cy_)], cx_, cols_);
            for (int y = cy_ + 1; y < rows_; ++y) clearRow(screen_[static_cast<size_t>(y)], 0, cols_);
        } else if (mode == 1) {
            clearRow(screen_[static_cast<size_t>(cy_)], 0, cx_ + 1);
            for (int y = 0; y < cy_; ++y) clearRow(screen_[static_cast<size_t>(y)], 0, cols_);
        } else {
            for (auto& l : screen_) clearRow(l, 0, cols_);
            if (mode == 3) scrollback_.clear();
        }
        break;
    }
    case 'K': {
        const int mode = param(0, 0);
        if (mode == 0) clearRow(screen_[static_cast<size_t>(cy_)], cx_, cols_);
        else if (mode == 1) clearRow(screen_[static_cast<size_t>(cy_)], 0, cx_ + 1);
        else clearRow(screen_[static_cast<size_t>(cy_)], 0, cols_);
        break;
    }
    case 'X': clearRow(screen_[static_cast<size_t>(cy_)], cx_, cx_ + n); break;
    case 'P': {
        Line& l = screen_[static_cast<size_t>(cy_)];
        const int k = std::min(n, cols_ - cx_);
        l.erase(l.begin() + cx_, l.begin() + cx_ + k);
        l.insert(l.end(), static_cast<size_t>(k), Cell{});
        break;
    }
    case '@': {
        Line& l = screen_[static_cast<size_t>(cy_)];
        const int k = std::min(n, cols_ - cx_);
        l.insert(l.begin() + cx_, static_cast<size_t>(k), Cell{});
        l.resize(static_cast<size_t>(cols_));
        break;
    }
    case 'L': if (cy_ >= top_ && cy_ <= bottom_) scrollDown(cy_, bottom_, std::min(n, bottom_ - cy_ + 1)); break;
    case 'M': if (cy_ >= top_ && cy_ <= bottom_) scrollUp(cy_, bottom_, std::min(n, bottom_ - cy_ + 1)); break;
    case 'S': scrollUp(top_, bottom_, n); break;
    case 'T': scrollDown(top_, bottom_, n); break;
    case 'm': sgr(); break;
    case 'r': {
        const int t = std::clamp(param(0, 1) - 1, 0, rows_ - 1), b = std::clamp(param(1, rows_) - 1, 0, rows_ - 1);
        if (t < b) {
            top_ = t;
            bottom_ = b;
            cx_ = 0;
            cy_ = 0;
        }
        break;
    }
    case 's': savedX_ = cx_, savedY_ = cy_; break;
    case 'u': cx_ = savedX_, cy_ = savedY_; break;
    case 'n':
        if (param(0, 0) == 6 && reply_) reply_("\x1b[" + std::to_string(cy_ + 1) + ";" + std::to_string(cx_ + 1) + "R");
        break;
    default: break;
    }
}

void VtScreen::feed(std::string_view bytes) {
    for (const char raw : bytes) {
        const unsigned char b = static_cast<unsigned char>(raw);
        switch (state_) {
        case State::Text: {
            if (utf8Left_ > 0) {
                if ((b & 0xC0) == 0x80) {
                    utf8Code_ = (utf8Code_ << 6) | (b & 0x3F);
                    if (--utf8Left_ == 0) put(utf8Code_);
                    continue;
                }
                utf8Left_ = 0;  // broken sequence: start over with this byte
            }
            if (b == 0x1B) state_ = State::Esc;
            else if (b == '\r') cx_ = 0, pendingWrap_ = false;
            else if (b == '\n' || b == 0x0B || b == 0x0C) pendingWrap_ = false, newline();
            else if (b == '\b') cx_ = std::max(0, cx_ - 1), pendingWrap_ = false;
            else if (b == '\t') cx_ = std::min(cols_ - 1, (cx_ / 8 + 1) * 8);
            else if (b == 0x07 || b < 0x20) {}
            else if (b < 0x80) put(b);
            else if ((b & 0xE0) == 0xC0) utf8Code_ = b & 0x1F, utf8Left_ = 1;
            else if ((b & 0xF0) == 0xE0) utf8Code_ = b & 0x0F, utf8Left_ = 2;
            else if ((b & 0xF8) == 0xF0) utf8Code_ = b & 0x07, utf8Left_ = 3;
            break;
        }
        case State::Esc:
            state_ = State::Text;
            if (b == '[') {
                state_ = State::Csi;
                params_.clear();
                privateMode_ = false;
            } else if (b == ']') {
                state_ = State::Osc;
                osc_.clear();
            } else if (b == '(' || b == ')') {
                state_ = State::Charset;
            } else if (b == '7') {
                savedX_ = cx_, savedY_ = cy_;
            } else if (b == '8') {
                cx_ = savedX_, cy_ = savedY_;
            } else if (b == 'M') {  // reverse index
                if (cy_ == top_) scrollDown(top_, bottom_, 1);
                else cy_ = std::max(0, cy_ - 1);
            } else if (b == 'D') {
                newline();
            } else if (b == 'E') {
                cx_ = 0;
                newline();
            } else if (b == 'c') {  // full reset
                pen_ = Cell{};
                for (auto& l : screen_) clearRow(l, 0, cols_);
                cx_ = cy_ = 0;
            }
            break;
        case State::Charset: state_ = State::Text; break;
        case State::Csi:
            if (b == '?' || b == '>' || b == '=') privateMode_ = true;
            else if ((b >= '0' && b <= '9') || b == ';' || b == ':') params_.push_back(static_cast<char>(b));
            else if (b >= 0x40 && b <= 0x7E) {
                state_ = State::Text;
                csi(static_cast<char>(b));
            } else if (b == 0x1B) {
                state_ = State::Esc;
            }
            break;
        case State::Osc:
            if (b == 0x07) {
                state_ = State::Text;
                if (osc_.rfind("0;", 0) == 0 || osc_.rfind("2;", 0) == 0) title_ = osc_.substr(2);
            } else if (b == 0x1B) {
                state_ = State::OscEsc;
            } else if (osc_.size() < 4096) {
                osc_.push_back(static_cast<char>(b));
            }
            break;
        case State::OscEsc:  // ESC \ ends an OSC string
            state_ = State::Text;
            if (osc_.rfind("0;", 0) == 0 || osc_.rfind("2;", 0) == 0) title_ = osc_.substr(2);
            break;
        }
    }
    ++version_;
}
