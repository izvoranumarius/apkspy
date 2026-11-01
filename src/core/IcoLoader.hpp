#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Minimal ICO (Windows icon) decoder for the app's own assets
// (assets/favicon.ico -> window/taskbar icon and title-bar icon).
//
// - Pure byte-level decoding: no OS calls, no image library, fully
//   headless-testable. PNG-compressed frames are inflated with the miniz
//   copy already vendored under include/miniz (no new dependency).
// - Supported frames: PNG payloads and classic BMP payloads
//   (1/4/8/24/32 bpp, BI_RGB and BI_BITFIELDS, BITMAPINFOHEADER and the
//   old 12-byte BITMAPCOREHEADER). Anything else is skipped with a reason.
// - Output is always straight-alpha RGBA8, top-down, ready for GLFWimage
//   and Texture.
namespace ico {

struct Image {
    int width = 0;
    int height = 0;
    std::vector<uint8_t> rgba;  // width*height*4 bytes
};

// Decodes every usable frame of an ICO buffer, in file order.
// Returns false when the buffer is not an ICO or no frame could be decoded;
// 'error' then says why. Individual frames that fail are skipped (their
// reason is appended to 'error') so one bad frame cannot sink the file.
bool decode(const std::vector<uint8_t>& bytes, std::vector<Image>& out, std::string& error);

// Picks the frame whose width is closest to 'side'; equally distant frames
// resolve to the smaller one. Returns nullptr for an empty list.
const Image* bestFrame(const std::vector<Image>& frames, int side);

}  // namespace ico
