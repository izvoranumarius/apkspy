#include "image/ImageDecoder.hpp"
#include <cstring>
#include <string>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#include "stb/stb_image.h"

#include "src/webp/decode.h"

namespace {
// Images come from untrusted APKs: bound the pixel dimensions before
// decoding so a crafted header cannot allocate gigabytes.
constexpr int kMaxImageDim = 16384;
bool dimensionsOk(int w, int h) { return w > 0 && h > 0 && w <= kMaxImageDim && h <= kMaxImageDim; }
}  // namespace

std::string ImageDecoder::sniffFormat(const std::vector<uint8_t>& b) {
    if (b.size() >= 12 && std::memcmp(b.data(), "RIFF", 4) == 0 && std::memcmp(b.data() + 8, "WEBP", 4) == 0) return "WEBP";
    if (b.size() >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') return "PNG";
    if (b.size() >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "JPEG";
    if (b.size() >= 6 && std::memcmp(b.data(), "GIF8", 4) == 0) return "GIF";
    if (b.size() >= 26 && b[0] == 'B' && b[1] == 'M') return "BMP";
    if (b.size() >= 4 && std::memcmp(b.data(), "8BPS", 4) == 0) return "PSD";
    return std::string();
}

bool ImageDecoder::decode(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error) {
    if (bytes.empty()) {
        error = "File is empty";
        return false;
    }
    out.format = sniffFormat(bytes);
    bool ok = out.format == "WEBP" ? decodeWebp(bytes, out, error) : decodeStb(bytes, out, error);
    if (ok && out.format.empty()) out.format = "Image";
    return ok;
}

bool ImageDecoder::decodeWebp(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error) {
    WebPBitstreamFeatures features;
    if (WebPGetFeatures(bytes.data(), bytes.size(), &features) != VP8_STATUS_OK) {
        error = "Invalid WebP data";
        return false;
    }
    if (features.has_animation) {
        error = "Animated WebP is not supported";
        return false;
    }
    if (!dimensionsOk(features.width, features.height)) {
        error = "Image dimensions are out of range";
        return false;
    }
    int w = 0, h = 0;
    uint8_t* pixels = WebPDecodeRGBA(bytes.data(), bytes.size(), &w, &h);
    if (!pixels) {
        error = "WebP decoding failed";
        return false;
    }
    out.width = w;
    out.height = h;
    out.rgba.assign(pixels, pixels + (size_t)w * (size_t)h * 4);
    WebPFree(pixels);
    return true;
}

bool ImageDecoder::decodeStb(const std::vector<uint8_t>& bytes, DecodedImage& out, std::string& error) {
    int w = 0, h = 0, channels = 0;
    // Probe the header first: decoding a crafted image with huge dimensions
    // would allocate width * height * 4 bytes before anything can stop it.
    if (!stbi_info_from_memory(bytes.data(), (int)bytes.size(), &w, &h, &channels)) {
        const char* reason = stbi_failure_reason();
        error = reason ? std::string("Decoding failed (") + reason + ")" : std::string("Unsupported image format");
        return false;
    }
    if (!dimensionsOk(w, h)) {
        error = "Image dimensions are out of range";
        return false;
    }
    stbi_uc* pixels = stbi_load_from_memory(bytes.data(), (int)bytes.size(), &w, &h, &channels, 4);
    if (!pixels) {
        const char* reason = stbi_failure_reason();
        error = reason ? std::string("Decoding failed (") + reason + ")" : std::string("Unsupported image format");
        return false;
    }
    out.width = w;
    out.height = h;
    out.rgba.assign(pixels, pixels + (size_t)w * (size_t)h * 4);
    stbi_image_free(pixels);
    return true;
}
