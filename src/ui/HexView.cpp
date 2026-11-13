#include "ui/HexView.hpp"
#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include "app/Theme.hpp"
#include "imgui.h"
#include "ui/UiUtil.hpp"

namespace {

constexpr size_t kMaxCopy = 4u << 20;  // bytes copied at most in one go

// Byte colours, as in most hex editors: zero dim, text bright, control and
// high bytes in between, 0xFF marked.
ImU32 byteColor(uint8_t b) {
    if (b == 0x00) return IM_COL32(95, 95, 100, 255);
    if (b == 0xFF) return IM_COL32(220, 150, 110, 255);
    if (b >= 0x20 && b < 0x7F) return IM_COL32(215, 215, 215, 255);
    if (b == '\t' || b == '\n' || b == '\r') return IM_COL32(110, 190, 200, 255);
    return IM_COL32(150, 160, 190, 255);
}

// "DE AD be ef" / "deadbeef" -> bytes; false on bad input.
bool parseHex(const char* text, std::vector<uint8_t>& out) {
    out.clear();
    int nibble = -1;
    for (const char* p = text; *p; ++p) {
        const char c = *p;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c == ' ' || c == ',') continue;
        else return false;
        if (nibble < 0) {
            nibble = v;
        } else {
            out.push_back((uint8_t)(nibble << 4 | v));
            nibble = -1;
        }
    }
    return nibble < 0 && !out.empty();
}

// "1f00" / "0x1f00" are hex, "#1234" decimal, "+20" / "-20" relative (hex).
bool parseOffset(const char* text, int64_t current, int64_t& out) {
    while (*text == ' ') ++text;
    int sign = 0;
    if (*text == '+' || *text == '-') sign = *text++ == '+' ? 1 : -1;
    int base = 16;
    if (*text == '#') {
        base = 10;
        ++text;
    } else if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
    }
    if (!*text) return false;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(text, &end, base);
    if (end == text || *end) return false;
    out = sign == 0 ? (int64_t)v : std::max<int64_t>(0, current) + sign * (int64_t)v;
    return true;
}

}  // namespace

std::string HexView::describeFormat(const uint8_t* d, size_t n) {
    const auto starts = [&](const char* magic, size_t len, size_t at = 0) {
        return n >= at + len && std::memcmp(d + at, magic, len) == 0;
    };
    char buf[96];
    if (starts("dex\n", 4) && n >= 7) {
        std::snprintf(buf, sizeof buf, "DEX %.3s", (const char*)d + 4);
        return buf;
    }
    if (starts("\x7F" "ELF", 4) && n >= 20) {
        const char* bits = d[4] == 2 ? "64-bit" : "32-bit";
        const unsigned machine = d[5] == 2 ? (unsigned)(d[18] << 8 | d[19]) : (unsigned)(d[18] | d[19] << 8);
        const char* arch = machine == 183 ? "AArch64" : machine == 40 ? "ARM" : machine == 62 ? "x86-64" : machine == 3 ? "x86" : "";
        std::snprintf(buf, sizeof buf, "ELF %s %s", bits, arch);
        return buf;
    }
    if (starts("PK\x03\x04", 4) || starts("PK\x05\x06", 4)) return "ZIP archive";
    if (starts("\x89PNG", 4)) return "PNG image";
    if (starts("\xFF\xD8\xFF", 3)) return "JPEG image";
    if (starts("GIF8", 4)) return "GIF image";
    if (starts("RIFF", 4) && starts("WEBP", 4, 8)) return "WebP image";
    if (starts("RIFF", 4) && starts("WAVE", 4, 8)) return "WAV audio";
    if (starts("OggS", 4)) return "Ogg audio";
    if (starts("fLaC", 4)) return "FLAC audio";
    if (starts("ID3", 3) || (n >= 2 && d[0] == 0xFF && (d[1] & 0xE0) == 0xE0)) return "MP3 audio";
    if (starts("ftyp", 4, 4)) return starts("M4A ", 4, 8) ? "M4A audio" : "MP4 video";
    if (starts("\x1A\x45\xDF\xA3", 4)) return "WebM / Matroska video";
    if (starts("RIFF", 4) && starts("AVI ", 4, 8)) return "AVI video";
    if (starts("\x30\x26\xB2\x75", 4)) return "WMV / ASF media";
    if (starts("\x1F\x8B", 2)) return "gzip";
    if (starts("SQLite format 3", 15)) return "SQLite 3 database";
    if (starts("\x00\x01\x00\x00", 4) || starts("OTTO", 4) || starts("true", 4)) return "TrueType / OpenType font";
    if (starts("ttcf", 4)) return "Font collection";
    if (starts("\x03\x00\x08\x00", 4)) return "Android binary XML";
    if (starts("\x02\x00\x0C\x00", 4)) return "Android resource table";
    if (starts("UnityFS", 7)) return "Unity asset bundle";
    if (starts("\xCA\xFE\xBA\xBE", 4)) return "Java class";
    if (starts("dey\n", 4)) return "Optimized DEX";
    if (starts("\x30\x82", 2)) return "DER (ASN.1)";
    if (starts("-----BEGIN", 10)) return "PEM";
    return {};
}

void HexView::select(int64_t anchor, int64_t cursor, bool scroll) {
    anchor_ = anchor;
    cursor_ = cursor;
    scrollToCursor_ = scroll;
}

void HexView::draw(const std::vector<uint8_t>& bytes) {
    if (!formatKnown_) {
        formatKnown_ = true;
        format_ = describeFormat(bytes.data(), bytes.size());
    }
    if (cursor_ >= (int64_t)bytes.size()) select(-1, -1, false);
    drawToolbar(bytes);
    const float inspectorW = ui::em(16.f);
    const bool inspector = ImGui::GetContentRegionAvail().x > inspectorW + ui::em(30.f);
    ImGui::BeginChild("##hexarea", ImVec2(inspector ? -inspectorW : 0.f, 0.f));
    drawBody(bytes);
    ImGui::EndChild();
    if (inspector) {
        ImGui::SameLine();
        drawInspector(bytes);
    }
}

void HexView::drawToolbar(const std::vector<uint8_t>& bytes) {
    ImGui::SetNextItemWidth(ui::em(7.f));
    if (ImGui::InputTextWithHint("##goto", "Go to...", gotoBuf_, sizeof gotoBuf_, ImGuiInputTextFlags_EnterReturnsTrue)) {
        int64_t off = 0;
        if (!parseOffset(gotoBuf_, cursor_, off)) status_ = "Offsets are hex (1f00 or 0x1f00), #1234 is decimal, +20 is relative";
        else if (off >= (int64_t)bytes.size()) status_ = "Past the end of the file";
        else {
            select(off, off, true);
            status_.clear();
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hex offset (1f00 or 0x1f00), decimal (#1234) or relative (+20, -20)");
    ImGui::SameLine();
    static const char* const kModes[] = {"Hex", "Text"};
    int mode = findText_ ? 1 : 0;
    ImGui::PushID("findmode");
    if (ui::segmented(kModes, 2, mode)) findText_ = mode == 1;
    ImGui::PopID();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(13.f));
    const bool enter = ImGui::InputTextWithHint("##find", findText_ ? "Find text..." : "Find bytes, e.g. 64 65 78",
                                                findBuf_, sizeof findBuf_, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter) find(bytes, ImGui::GetIO().KeyShift);
    ImGui::SameLine(0.f, 2.f);
    if (ImGui::SmallButton("<##prev")) find(bytes, true);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous match (Shift+Enter)");
    ImGui::SameLine(0.f, 2.f);
    if (ImGui::SmallButton(">##next")) find(bytes, false);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next match (Enter)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(4.5f));
    static const int kWidths[] = {8, 16, 32};
    char label[16];
    std::snprintf(label, sizeof label, "%d / row", bytesPerRow_);
    if (ImGui::BeginCombo("##bpr", label, ImGuiComboFlags_NoArrowButton)) {
        for (int w : kWidths) {
            std::snprintf(label, sizeof label, "%d / row", w);
            if (ImGui::Selectable(label, w == bytesPerRow_)) {
                bytesPerRow_ = w;
                scrollToCursor_ = true;
            }
        }
        ImGui::EndCombo();
    }
    std::string info;
    if (!status_.empty()) {
        info = status_;
    } else {
        char b[128];
        if (anchor_ >= 0 && selEnd() > selBegin())
            std::snprintf(b, sizeof b, "%" PRId64 " bytes selected", selEnd() - selBegin() + 1);
        else
            std::snprintf(b, sizeof b, "%zu bytes", bytes.size());
        info = format_.empty() ? std::string(b) : format_ + "   " + b;
    }
    ui::sameLineIfFits(ImGui::CalcTextSize(info.c_str()).x);
    if (!status_.empty()) ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.35f, 1.f), "%s", info.c_str());
    else ImGui::TextDisabled("%s", info.c_str());
}

void HexView::find(const std::vector<uint8_t>& bytes, bool backward) {
    if (!findBuf_[0]) return;
    std::vector<uint8_t> pattern;
    if (findText_) pattern.assign(findBuf_, findBuf_ + std::strlen(findBuf_));
    else if (!parseHex(findBuf_, pattern)) {
        status_ = "Type hex bytes, like 64 65 78";
        return;
    }
    const int64_t size = (int64_t)bytes.size();
    const int64_t here = cursor_ < 0 ? (backward ? size : -1) : selBegin();
    auto hit = bytes.end();
    bool wrapped = false;
    if (!backward) {
        hit = std::search(bytes.begin() + std::min(here + 1, size), bytes.end(), pattern.begin(), pattern.end());
        if (hit == bytes.end()) {
            hit = std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end());
            wrapped = true;
        }
    } else {
        const auto limit = bytes.begin() + std::clamp<int64_t>(here + (int64_t)pattern.size() - 1, 0, size);
        hit = std::find_end(bytes.begin(), limit, pattern.begin(), pattern.end());
        if (hit == limit) {
            hit = std::find_end(bytes.begin(), bytes.end(), pattern.begin(), pattern.end());
            wrapped = true;
        }
    }
    if (hit == bytes.end() || pattern.empty()) {
        status_ = "Not found";
        return;
    }
    const int64_t at = hit - bytes.begin();
    select(at, at + (int64_t)pattern.size() - 1, true);
    status_ = wrapped ? "Wrapped around" : "";
}

void HexView::drawBody(const std::vector<uint8_t>& bytes) {
    ImGui::PushFont(Theme::monoFont());
    const float charW = ImGui::CalcTextSize("0").x;
    const float lineH = ImGui::GetTextLineHeightWithSpacing();
    const int bpr = bytesPerRow_;
    const auto hexCol = [&](int k) { return 10.f + 3.f * (float)k + (float)(k / 8); };
    const float asciiCol = hexCol(bpr) + 1.f;
    const float rowChars = asciiCol + (float)bpr;

    // Column header, outside the scrolling area.
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 p = ImGui::GetCursorScreenPos();
        char h[4];
        for (int k = 0; k < bpr; ++k) {
            std::snprintf(h, sizeof h, "%02X", k);
            dl->AddText(ImVec2(p.x + hexCol(k) * charW, p.y), IM_COL32(110, 140, 180, 255), h);
        }
        dl->AddText(p, IM_COL32(110, 140, 180, 255), "Offset");
        ImGui::Dummy(ImVec2(rowChars * charW, ImGui::GetTextLineHeight()));
        ImGui::Separator();
    }

    ImGui::BeginChild("##hexbody", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoNavInputs);  // arrows move the cursor, not nav
    const int64_t size = (int64_t)bytes.size();
    const int64_t rows = (size + bpr - 1) / bpr;
    const int visibleRows = std::max(1, (int)(ImGui::GetWindowHeight() / lineH) - 1);
    if (ImGui::IsWindowFocused()) handleKeys(bytes, visibleRows);
    if (scrollToCursor_ && cursor_ >= 0) {
        scrollToCursor_ = false;
        const float y = (float)(cursor_ / bpr) * lineH;
        if (y < ImGui::GetScrollY() || y + lineH > ImGui::GetScrollY() + ImGui::GetWindowHeight())
            ImGui::SetScrollY(std::max(0.f, y - ImGui::GetWindowHeight() * 0.33f));
    }
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const int64_t s0 = anchor_ >= 0 ? selBegin() : -1, s1 = anchor_ >= 0 ? selEnd() : -2;

    // Mouse: what byte is under the pointer (hex or text column).
    int64_t hover = -1;
    if (ImGui::IsWindowHovered()) {
        const ImVec2 m = ImGui::GetIO().MousePos;
        const int64_t row = (int64_t)std::floor((m.y - origin.y) / lineH);
        const float col = (m.x - origin.x) / charW;
        int k = -1;
        for (int i = 0; i < bpr && k < 0; ++i)
            if (col >= hexCol(i) - 0.5f && col < hexCol(i) + 2.5f) k = i;
        if (k < 0 && col >= asciiCol && col < asciiCol + (float)bpr) k = (int)(col - asciiCol);
        if (row >= 0 && k >= 0 && row * bpr + k < size) hover = row * bpr + k;
    }
    if (hover >= 0 && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        if (ImGui::GetIO().KeyShift && anchor_ >= 0) select(anchor_, hover, false);
        else select(hover, hover, false);
        dragging_ = true;
    }
    if (dragging_ && ImGui::IsMouseDown(ImGuiMouseButton_Left) && hover >= 0) cursor_ = hover;
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) dragging_ = false;

    ImGuiListClipper clipper;
    clipper.Begin((int)std::min<int64_t>(rows, INT32_MAX), lineH);
    char text[24];
    while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
            const int64_t base = (int64_t)r * bpr;
            const float y = origin.y + (float)r * lineH;
            std::snprintf(text, sizeof text, "%08" PRIX64, (uint64_t)base);
            dl->AddText(ImVec2(origin.x, y), IM_COL32(110, 140, 180, 255), text);
            for (int k = 0; k < bpr && base + k < size; ++k) {
                const int64_t at = base + k;
                const uint8_t b = bytes[(size_t)at];
                const float hx = origin.x + hexCol(k) * charW, ax = origin.x + (asciiCol + (float)k) * charW;
                const bool selected = at >= s0 && at <= s1;
                if (selected || at == hover) {
                    const ImU32 bg = selected ? IM_COL32(0, 122, 204, 150) : IM_COL32(255, 255, 255, 28);
                    const bool joinNext = selected && at + 1 <= s1 && k + 1 < bpr;  // one band across a selection
                    dl->AddRectFilled(ImVec2(hx - charW * 0.5f, y), ImVec2(hx + charW * (joinNext ? 2.5f + (float)((k + 1) % 8 == 0) : 2.5f), y + lineH), bg);
                    dl->AddRectFilled(ImVec2(ax, y), ImVec2(ax + charW, y + lineH), bg);
                }
                if (at == cursor_) dl->AddRect(ImVec2(hx - charW * 0.5f, y), ImVec2(hx + charW * 2.5f, y + lineH), IM_COL32(255, 255, 255, 140));
                static const char kDigits[] = "0123456789ABCDEF";
                const char pair[2] = {kDigits[b >> 4], kDigits[b & 15]};
                dl->AddText(ImVec2(hx, y), byteColor(b), pair, pair + 2);
                const char c = b >= 0x20 && b < 0x7F ? (char)b : '.';
                dl->AddText(ImVec2(ax, y), b >= 0x20 && b < 0x7F ? IM_COL32(200, 200, 200, 255) : IM_COL32(90, 90, 95, 255), &c, &c + 1);
            }
            ImGui::Dummy(ImVec2(rowChars * charW, lineH));
        }
    }
    clipper.End();
    contextMenu(bytes);
    ImGui::EndChild();
    ImGui::PopFont();
}

void HexView::handleKeys(const std::vector<uint8_t>& bytes, int visibleRows) {
    const int64_t size = (int64_t)bytes.size();
    if (size == 0) return;
    const ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) {
        select(0, size - 1, false);
        return;
    }
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false) && anchor_ >= 0) {
        std::string out;
        static const char kDigits[] = "0123456789ABCDEF";
        for (int64_t i = selBegin(); i <= selEnd() && (size_t)(i - selBegin()) < kMaxCopy; ++i) {
            if (i > selBegin()) out.push_back(' ');
            out.push_back(kDigits[bytes[(size_t)i] >> 4]);
            out.push_back(kDigits[bytes[(size_t)i] & 15]);
        }
        ImGui::SetClipboardText(out.c_str());
        return;
    }
    int64_t step = 0;
    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) step = -1;
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow)) step = 1;
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) step = -bytesPerRow_;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) step = bytesPerRow_;
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) step = -(int64_t)bytesPerRow_ * visibleRows;
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) step = (int64_t)bytesPerRow_ * visibleRows;
    int64_t target = -1;
    const int64_t at = std::max<int64_t>(0, cursor_);
    if (step != 0) target = std::clamp<int64_t>(at + step, 0, size - 1);
    if (ImGui::IsKeyPressed(ImGuiKey_Home)) target = io.KeyCtrl ? 0 : at - at % bytesPerRow_;
    if (ImGui::IsKeyPressed(ImGuiKey_End)) target = io.KeyCtrl ? size - 1 : std::min(size - 1, at - at % bytesPerRow_ + bytesPerRow_ - 1);
    if (target < 0) return;
    select(io.KeyShift && anchor_ >= 0 ? anchor_ : target, target, true);
}

void HexView::contextMenu(const std::vector<uint8_t>& bytes) {
    if (!ImGui::BeginPopupContextWindow("##hexctx")) return;
    const bool any = anchor_ >= 0;
    const int64_t b = selBegin(), e = selEnd();
    const size_t n = any ? (size_t)std::min<int64_t>(e - b + 1, (int64_t)kMaxCopy) : 0;
    const uint8_t* p = any ? bytes.data() + b : nullptr;
    static const char kDigits[] = "0123456789ABCDEF";
    if (ImGui::MenuItem("Copy as hex", "Ctrl+C", false, any)) {
        std::string out;
        for (size_t i = 0; i < n; ++i) {
            if (i) out.push_back(' ');
            out.push_back(kDigits[p[i] >> 4]);
            out.push_back(kDigits[p[i] & 15]);
        }
        ImGui::SetClipboardText(out.c_str());
    }
    if (ImGui::MenuItem("Copy as text", nullptr, false, any)) {
        std::string out;
        for (size_t i = 0; i < n; ++i) out.push_back(p[i] >= 0x20 && p[i] < 0x7F ? (char)p[i] : '.');
        ImGui::SetClipboardText(out.c_str());
    }
    if (ImGui::MenuItem("Copy as C array", nullptr, false, any)) {
        std::string out = "const unsigned char data[" + std::to_string(n) + "] = {";
        for (size_t i = 0; i < n; ++i) {
            out += i % 12 == 0 ? "\n    " : " ";
            out += "0x";
            out.push_back(kDigits[p[i] >> 4]);
            out.push_back(kDigits[p[i] & 15]);
            if (i + 1 < n) out.push_back(',');
        }
        out += "\n};\n";
        ImGui::SetClipboardText(out.c_str());
    }
    if (ImGui::MenuItem("Copy offset", nullptr, false, any)) {
        char o[32];
        std::snprintf(o, sizeof o, "0x%" PRIX64, (uint64_t)b);
        ImGui::SetClipboardText(o);
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Select all", "Ctrl+A", false, !bytes.empty())) select(0, (int64_t)bytes.size() - 1, false);
    ImGui::EndPopup();
}

void HexView::drawInspector(const std::vector<uint8_t>& bytes) {
    ImGui::BeginChild("##inspector", ImVec2(0, 0), ImGuiChildFlags_Borders);
    static const char* const kEndian[] = {"Little endian", "Big endian"};
    int endian = bigEndian_ ? 1 : 0;
    ImGui::PushID("endian");
    if (ui::segmented(kEndian, 2, endian)) bigEndian_ = endian == 1;
    ImGui::PopID();
    if (cursor_ < 0 || cursor_ >= (int64_t)bytes.size()) {
        ImGui::TextDisabled("Click a byte.");
        ImGui::EndChild();
        return;
    }
    const size_t off = (size_t)selBegin();
    const size_t avail = bytes.size() - off;
    const auto read = [&](size_t n) {
        uint64_t v = 0;
        for (size_t i = 0; i < n && i < avail; ++i) {
            const uint64_t b = bytes[off + i];
            v |= bigEndian_ ? b << (8 * (n - 1 - i)) : b << (8 * i);
        }
        return v;
    };
    ImGui::PushFont(Theme::monoFont());
    const auto row = [](const char* name, const char* value) {
        ImGui::TextDisabled("%-8s", name);
        ImGui::SameLine();
        ImGui::TextUnformatted(value);
    };
    char v[96];
    std::snprintf(v, sizeof v, "0x%zX (%zu)", off, off);
    row("offset", v);
    if (selEnd() > selBegin()) {
        std::snprintf(v, sizeof v, "%" PRId64 " bytes", selEnd() - selBegin() + 1);
        row("length", v);
    }
    ImGui::Separator();
    const uint8_t b0 = bytes[off];
    char bits[9];
    for (int i = 0; i < 8; ++i) bits[i] = (b0 >> (7 - i)) & 1 ? '1' : '0';
    bits[8] = 0;
    row("binary", bits);
    std::snprintf(v, sizeof v, "%d", (int)(int8_t)b0);
    row("int8", v);
    std::snprintf(v, sizeof v, "%u", (unsigned)b0);
    row("uint8", v);
    if (avail >= 2) {
        std::snprintf(v, sizeof v, "%d", (int)(int16_t)read(2));
        row("int16", v);
        std::snprintf(v, sizeof v, "%u", (unsigned)(uint16_t)read(2));
        row("uint16", v);
    }
    if (avail >= 4) {
        const uint32_t u = (uint32_t)read(4);
        float f;
        std::memcpy(&f, &u, 4);
        std::snprintf(v, sizeof v, "%d", (int32_t)u);
        row("int32", v);
        std::snprintf(v, sizeof v, "%u", u);
        row("uint32", v);
        std::snprintf(v, sizeof v, "%g", f);
        row("float", v);
        // Plausible Unix times only (2000 to 2040), so random data stays quiet.
        if (u >= 946684800u && u <= 2208988800u) {
            const std::time_t t = (std::time_t)u;
            std::tm tm{};
#ifdef _WIN32
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            std::strftime(v, sizeof v, "%Y-%m-%d %H:%M:%S UTC", &tm);
            row("time32", v);
        }
    }
    if (avail >= 8) {
        const uint64_t u = read(8);
        double d;
        std::memcpy(&d, &u, 8);
        std::snprintf(v, sizeof v, "%" PRId64, (int64_t)u);
        row("int64", v);
        std::snprintf(v, sizeof v, "%" PRIu64, u);
        row("uint64", v);
        std::snprintf(v, sizeof v, "%g", d);
        row("double", v);
    }
    {
        uint64_t u = 0;
        int shift = 0;
        size_t i = 0;
        for (; i < 10 && i < avail; ++i) {
            u |= (uint64_t)(bytes[off + i] & 0x7F) << shift;
            shift += 7;
            if (!(bytes[off + i] & 0x80)) break;
        }
        std::snprintf(v, sizeof v, "%" PRIu64 " (%zu b)", u, std::min(i + 1, avail));
        row("uleb128", v);
    }
    ImGui::Separator();
    std::string utf8;
    for (size_t i = 0; i < 64 && i < avail && bytes[off + i] >= 0x20 && bytes[off + i] < 0x7F; ++i) utf8.push_back((char)bytes[off + i]);
    ImGui::TextDisabled("ascii");
    ImGui::TextWrapped("\"%s\"", utf8.c_str());
    std::string utf16;
    for (size_t i = 0; i + 1 < avail && utf16.size() < 64; i += 2) {
        const unsigned c = bigEndian_ ? (unsigned)(bytes[off + i] << 8 | bytes[off + i + 1]) : (unsigned)(bytes[off + i] | bytes[off + i + 1] << 8);
        if (c < 0x20 || c >= 0x7F) break;
        utf16.push_back((char)c);
    }
    if (!utf16.empty()) {
        ImGui::TextDisabled("utf-16");
        ImGui::TextWrapped("\"%s\"", utf16.c_str());
    }
    ImGui::PopFont();
    ImGui::EndChild();
}
