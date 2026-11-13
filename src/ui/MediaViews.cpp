#include "ui/MediaViews.hpp"
#include "app/Theme.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include "image/Texture.hpp"
#include "imgui.h"
#include "imgui_internal.h"
#include "ui/UiUtil.hpp"

// imgui_draw.cpp compiles its own static copy; this one is private to this file.
// Being static, the stb_truetype functions this file does not call are
// reported as removed (C4505) at the end of the translation unit, where a
// push/pop around the include no longer applies, so it is disabled here.
#ifdef _MSC_VER
#pragma warning(disable : 4505)
#pragma warning(push, 0)
#endif
#define STBTT_STATIC
#define STB_TRUETYPE_IMPLEMENTATION
#include "imstb_truetype.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace {

std::string clock(double seconds) {
    if (seconds < 0) seconds = 0;
    const int total = static_cast<int>(seconds);
    char b[32];
    std::snprintf(b, sizeof b, "%d:%02d.%d", total / 60, total % 60, static_cast<int>((seconds - total) * 10));
    return b;
}

// Hex / back toggle shared by the media views.
bool hexToggle(bool& showHex) {
    ui::sameLineIfFits(ui::em(4.f));
    if (ui::smallButton(showHex ? "Back" : "Hex")) showHex = !showHex;
    return showHex;
}

// Name table strings are UTF-16BE for the Windows platform: keep the ASCII part.
std::string nameString(const stbtt_fontinfo& font, int nameId) {
    int len = 0;
    const char* s = stbtt_GetFontNameString(&font, &len, STBTT_PLATFORM_ID_MICROSOFT, STBTT_MS_EID_UNICODE_BMP,
                                            STBTT_MS_LANG_ENGLISH, nameId);
    std::string out;
    if (s) {
        for (int i = 0; i + 1 < len; i += 2)
            if (s[i] == 0 && static_cast<unsigned char>(s[i + 1]) >= 0x20 && static_cast<unsigned char>(s[i + 1]) < 0x7F) out.push_back(s[i + 1]);
        return out;
    }
    s = stbtt_GetFontNameString(&font, &len, STBTT_PLATFORM_ID_MAC, 0, 0, nameId);
    if (s) out.assign(s, static_cast<size_t>(len));
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

void AudioView::draw(const std::vector<uint8_t>& bytes) {
    if (!opened_) {
        opened_ = true;
        format_ = HexView::describeFormat(bytes.data(), bytes.size());
        if (player_.open(bytes, error_)) player_.setVolume(volume_);
    }
    ImGui::TextUnformatted(format_.empty() ? "Audio" : format_.c_str());
    if (player_.isOpen()) {
        ImGui::SameLine();
        const double d = player_.duration();
        ImGui::TextDisabled("%s, %d Hz, %s", d > 0 ? clock(d).c_str() : "length unknown", player_.sampleRate(),
                            player_.channels() == 1 ? "mono" : player_.channels() == 2 ? "stereo" : "multichannel");
    }
    if (hexToggle(showHex_)) {
        ImGui::Separator();
        hex_.draw(bytes);
        return;
    }
    ImGui::Separator();
    if (!player_.isOpen()) {
        ImGui::TextColored(theme::vec(Col::Warning), "%s", error_.c_str());
        ImGui::TextDisabled("Use Hex to inspect the file, or export it.");
        return;
    }
    if (!player_.deviceError().empty()) ImGui::TextColored(theme::vec(Col::Warning), "%s", player_.deviceError().c_str());

    // Transport. The controls stay out of keyboard navigation so Space always
    // means play / pause (nav would otherwise claim it for the clicked button).
    ImGui::PushItemFlag(ImGuiItemFlags_NoNav, true);
    const bool playing = player_.playing();
    if (ImGui::Button(playing ? "Pause" : "Play", ImVec2(ui::em(5.f), 0)) ||
        (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
         ImGui::IsKeyPressed(ImGuiKey_Space, ImGuiInputFlags_None, ImGuiKeyOwner_Any) && !ImGui::GetIO().WantTextInput)) {
        if (playing) player_.pause();
        else player_.play();
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Space");
    ImGui::SameLine();
    if (ImGui::Button("Stop")) {
        player_.pause();
        player_.seek(0);
    }
    ImGui::SameLine();
    ImGui::Text("%s / %s", clock(player_.position()).c_str(), clock(player_.duration()).c_str());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ui::em(8.f));
    int percent = static_cast<int>(std::lround(volume_ * 100.f));
    if (ImGui::SliderInt("##vol", &percent, 0, 100, "Volume %d%%")) {
        volume_ = static_cast<float>(percent) / 100.f;
        player_.setVolume(volume_);
    }

    // Waveform: click or drag to seek.
    const ImVec2 size(ImGui::GetContentRegionAvail().x, std::min(ImGui::GetContentRegionAvail().y, ui::em(9.f)));
    if (size.x < 10.f || size.y < 10.f) {
        ImGui::PopItemFlag();
        return;
    }
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##wave", size);
    ImGui::PopItemFlag();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + size.x, p.y + size.y), theme::u32(Col::EditorBackground));
    const float mid = p.y + size.y * 0.5f;
    const std::vector<float> peaks = player_.peaks();
    if (peaks.empty()) {
        dl->AddText(ImVec2(p.x + 8.f, mid - ImGui::GetTextLineHeight() * 0.5f), theme::u32(Col::TextMuted), "Reading waveform...");
    } else {
        const int columns = std::max(1, static_cast<int>(size.x));
        for (int x = 0; x < columns; ++x) {
            const float v = peaks[static_cast<size_t>(x) * peaks.size() / static_cast<size_t>(columns)];
            const float h = std::max(1.f, v * size.y * 0.48f);
            dl->AddLine(ImVec2(p.x + static_cast<float>(x) + 0.5f, mid - h), ImVec2(p.x + static_cast<float>(x) + 0.5f, mid + h), theme::u32(Col::Accent));
        }
    }
    const double d = player_.duration();
    if (d > 0) {
        const float x = p.x + static_cast<float>(player_.position() / d) * size.x;
        dl->AddLine(ImVec2(x, p.y), ImVec2(x, p.y + size.y), theme::u32(Col::Text, 0.9f), 1.5f);
        if (ImGui::IsItemActive()) {
            const float t = std::clamp((ImGui::GetIO().MousePos.x - p.x) / size.x, 0.f, 1.f);
            player_.seek(t * d);
        }
        if (ImGui::IsItemHovered()) {
            const float t = std::clamp((ImGui::GetIO().MousePos.x - p.x) / size.x, 0.f, 1.f);
            ImGui::SetTooltip("%s", clock(t * d).c_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Video
// ---------------------------------------------------------------------------

VideoView::VideoView() = default;
VideoView::~VideoView() = default;

void VideoView::draw(const std::vector<uint8_t>& bytes) {
    if (!opened_) {
        opened_ = true;
        format_ = HexView::describeFormat(bytes.data(), bytes.size());
        if (player_.open(bytes, error_)) player_.setVolume(volume_);
    }
    ImGui::TextUnformatted(format_.empty() ? "Media" : format_.c_str());
    if (player_.isOpen()) {
        ImGui::SameLine();
        const double d = player_.duration();
        std::string info = d > 0 ? clock(d) : std::string("length unknown");
        if (player_.hasVideo()) info += ", " + std::to_string(player_.width()) + " x " + std::to_string(player_.height());
        info += player_.hasAudio() ? (player_.hasVideo() ? ", with sound" : ", audio only") : ", no sound";
        ImGui::TextDisabled("%s", info.c_str());
    }
    if (hexToggle(showHex_)) {
        ImGui::Separator();
        hex_.draw(bytes);
        return;
    }
    ImGui::Separator();
    if (!player_.isOpen()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextColored(theme::vec(Col::Warning), "%s", error_.c_str());
        ImGui::PopTextWrapPos();
        ImGui::TextDisabled("Use Hex to inspect the file, or export it.");
        return;
    }

    // Transport, kept out of keyboard navigation so Space is always play / pause.
    ImGui::PushItemFlag(ImGuiItemFlags_NoNav, true);
    const bool playing = player_.playing();
    if (ImGui::Button(playing ? "Pause" : "Play", ImVec2(ui::em(5.f), 0)) ||
        (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
         ImGui::IsKeyPressed(ImGuiKey_Space, ImGuiInputFlags_None, ImGuiKeyOwner_Any) && !ImGui::GetIO().WantTextInput)) {
        if (playing) player_.pause();
        else player_.play();
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Space");
    ImGui::SameLine();
    if (ImGui::Button("Stop")) {
        player_.pause();
        player_.seek(0);
    }
    ImGui::SameLine();
    const double d = player_.duration();
    ImGui::Text("%s / %s", clock(player_.position()).c_str(), clock(d).c_str());
    if (player_.hasAudio()) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ui::em(8.f));
        int percent = static_cast<int>(std::lround(volume_ * 100.f));
        if (ImGui::SliderInt("##vol", &percent, 0, 100, "Volume %d%%")) {
            volume_ = static_cast<float>(percent) / 100.f;
            player_.setVolume(volume_);
        }
    }
    // Seek bar.
    const float barH = ImGui::GetFontSize() * 0.6f;
    const ImVec2 bp = ImGui::GetCursorScreenPos();
    const float barW = ImGui::GetContentRegionAvail().x;
    ImGui::InvisibleButton("##seek", ImVec2(barW, barH + 6.f));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float y = bp.y + 3.f;
    dl->AddRectFilled(ImVec2(bp.x, y), ImVec2(bp.x + barW, y + barH), theme::u32(Col::Control), barH * 0.5f);
    if (d > 0) {
        const float t = static_cast<float>(std::clamp(player_.position() / d, 0.0, 1.0));
        dl->AddRectFilled(ImVec2(bp.x, y), ImVec2(bp.x + barW * t, y + barH), theme::u32(Col::Accent), barH * 0.5f);
        if (ImGui::IsItemActive()) player_.seek(std::clamp((ImGui::GetIO().MousePos.x - bp.x) / barW, 0.f, 1.f) * d);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", clock(std::clamp((ImGui::GetIO().MousePos.x - bp.x) / barW, 0.f, 1.f) * d).c_str());
    }
    ImGui::PopItemFlag();

    // Picture, scaled to fit and centred.
    if (!player_.hasVideo()) {
        ImGui::TextDisabled("This file has no picture.");
        return;
    }
    if (player_.takeFrame(frame_)) {
        if (!texture_) texture_ = std::make_unique<Texture>(frame_.data(), player_.width(), player_.height());
        else texture_->update(frame_.data());
    }
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    if (!texture_ || avail.x < 8.f || avail.y < 8.f) return;
    const float scale = std::min(avail.x / static_cast<float>(texture_->width()), avail.y / static_cast<float>(texture_->height()));
    const ImVec2 size(static_cast<float>(texture_->width()) * scale, static_cast<float>(texture_->height()) * scale);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    dl->AddRectFilled(p, ImVec2(p.x + avail.x, p.y + avail.y), IM_COL32(0, 0, 0, 255));
    ImGui::SetCursorScreenPos(ImVec2(p.x + (avail.x - size.x) * 0.5f, p.y + (avail.y - size.y) * 0.5f));
    ImGui::Image(static_cast<ImTextureID>(static_cast<intptr_t>(texture_->id())), size);
    // Clicking the picture plays or pauses, as in most players.
    if (ImGui::IsItemClicked()) {
        if (player_.playing()) player_.pause();
        else player_.play();
    }
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

FontView::FontView() = default;
FontView::~FontView() = default;

void FontView::render(const std::vector<uint8_t>& bytes) {
    rendered_ = true;
    stbtt_fontinfo font;
    const int offset = stbtt_GetFontOffsetForIndex(bytes.data(), 0);
    if (offset < 0 || !stbtt_InitFont(&font, bytes.data(), offset)) {
        error_ = "This font could not be read";
        return;
    }
    family_ = nameString(font, 1);
    fullName_ = nameString(font, 4);
    glyphs_ = font.numGlyphs;

    // Sample lines at several sizes, then a grid of the first glyphs (icon
    // fonts have no letters, but their glyphs still show).
    static const char* const kSample = "The quick brown fox jumps over the lazy dog 0123456789";
    static const float kSizes[] = {14.f, 20.f, 28.f, 40.f, 56.f};
    const int width = 1400;
    const int gridCell = 40, gridCols = width / gridCell;
    const int gridGlyphs = std::min(glyphs_, gridCols * 8);
    int height = 0;
    for (float s : kSizes) height += static_cast<int>(s * 1.35f);
    height += 12 + (gridGlyphs + gridCols - 1) / gridCols * gridCell;
    std::vector<uint8_t> alpha(static_cast<size_t>(width) * static_cast<size_t>(height), 0);

    int y = 0;
    for (float px : kSizes) {
        const float scale = stbtt_ScaleForPixelHeight(&font, px);
        int ascent = 0, descent = 0, gap = 0;
        stbtt_GetFontVMetrics(&font, &ascent, &descent, &gap);
        const int baseline = y + static_cast<int>(std::lround(ascent * scale));
        float x = 4.f;
        for (const char* c = kSample; *c; ++c) {
            int advance = 0, lsb = 0;
            stbtt_GetCodepointHMetrics(&font, *c, &advance, &lsb);
            int x0, y0, x1, y1;
            stbtt_GetCodepointBitmapBox(&font, *c, scale, scale, &x0, &y0, &x1, &y1);
            const int gx = static_cast<int>(x) + x0, gy = baseline + y0;
            const int gw = x1 - x0, gh = y1 - y0;
            if (gx >= 0 && gy >= 0 && gx + gw < width && gy + gh < height && gw > 0 && gh > 0)
                stbtt_MakeCodepointBitmap(&font, &alpha[static_cast<size_t>(gy) * width + static_cast<size_t>(gx)], gw, gh, width, scale, scale, *c);
            x += advance * scale;
            if (c[1]) x += scale * stbtt_GetCodepointKernAdvance(&font, c[0], c[1]);
            if (x > width - px) break;
        }
        y += static_cast<int>(px * 1.35f);
    }
    y += 12;
    const float gridScale = stbtt_ScaleForPixelHeight(&font, gridCell * 0.7f);
    for (int g = 0; g < gridGlyphs; ++g) {
        int x0, y0, x1, y1;
        stbtt_GetGlyphBitmapBox(&font, g, gridScale, gridScale, &x0, &y0, &x1, &y1);
        const int gw = std::min(x1 - x0, gridCell - 2), gh = std::min(y1 - y0, gridCell - 2);
        const int cx = (g % gridCols) * gridCell + (gridCell - gw) / 2;
        const int cy = y + (g / gridCols) * gridCell + (gridCell - gh) / 2;
        if (gw > 0 && gh > 0 && cx + gw < width && cy + gh < height)
            stbtt_MakeGlyphBitmap(&font, &alpha[static_cast<size_t>(cy) * width + static_cast<size_t>(cx)], gw, gh, width, gridScale, gridScale, g);
    }
    std::vector<uint8_t> rgba(static_cast<size_t>(width) * static_cast<size_t>(height) * 4);
    for (size_t i = 0; i < alpha.size(); ++i) {
        rgba[i * 4 + 0] = 230;
        rgba[i * 4 + 1] = 230;
        rgba[i * 4 + 2] = 230;
        rgba[i * 4 + 3] = alpha[i];
    }
    texture_ = std::make_unique<Texture>(rgba.data(), width, height);
}

void FontView::draw(const std::vector<uint8_t>& bytes) {
    if (!rendered_) render(bytes);
    if (!error_.empty()) {
        ImGui::TextColored(theme::vec(Col::Warning), "%s", error_.c_str());
    } else {
        ImGui::TextUnformatted(fullName_.empty() ? (family_.empty() ? "Font" : family_.c_str()) : fullName_.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%d glyphs", glyphs_);
    }
    if (hexToggle(showHex_)) {
        ImGui::Separator();
        hex_.draw(bytes);
        return;
    }
    ImGui::Separator();
    if (!texture_) return;
    ImGui::BeginChild("##font", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::Image(static_cast<ImTextureID>(static_cast<intptr_t>(texture_->id())), ImVec2(static_cast<float>(texture_->width()), static_cast<float>(texture_->height())));
    ImGui::EndChild();
}
