#include "core/IcoLoader.hpp"
#include <algorithm>
#include <cstring>
#include <miniz.h>

// ICO layout references: the ICONDIR / ICONDIRENTRY structs and the two
// payload flavours (BITMAPINFOHEADER+"XOR/AND" bitmaps, or embedded PNG).
// All integers are little-endian; PNG chunk payloads inside ICO are the
// usual big-endian PNG. Every read is bounds-checked against the payload
// size so a truncated or hostile file cannot read out of range.

namespace {

constexpr int kMaxDim = 16384;          // same guard as ImageDecoder
constexpr size_t kMaxFrameBytes = 256u * 1024 * 1024;
constexpr size_t kMaxFrames = 64;       // far more than any sane .ico

uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint32_t rdBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

// ---------------------------------------------------------------- PNG frames

// Expands a raw (defiltered) scanline of any supported PNG colour type to
// RGBA8. 'scale' lifts 1/2/4-bit samples and 16-bit samples to 8 bits.
void expandPngRow(const uint8_t* row, int width, int colorType, int bitDepth, const uint8_t* palette,
                  const uint8_t* trns, int trnsCount, uint8_t* out) {
    auto scale = [&](unsigned v) -> uint8_t {
        switch (bitDepth) {
        case 1: return static_cast<uint8_t>(v ? 255 : 0);
        case 2: return static_cast<uint8_t>(v * 85);
        case 4: return static_cast<uint8_t>(v * 17);
        case 16: return static_cast<uint8_t>(v >> 8);
        default: return static_cast<uint8_t>(v);
        }
    };
    // Reads the n-th sample of the row for sub-byte depths (MSB first).
    auto sample = [&](int i) -> unsigned {
        if (bitDepth == 8) return row[i];
        if (bitDepth == 16) return static_cast<unsigned>(row[i * 2] << 8 | row[i * 2 + 1]);
        const int perByte = 8 / bitDepth;
        const int shift = 8 - bitDepth * (i % perByte + 1);
        return ((row[i / perByte] >> shift) & ((1u << bitDepth) - 1));
    };
    for (int x = 0; x < width; ++x) {
        uint8_t* o = out + static_cast<size_t>(x) * 4;
        switch (colorType) {
        case 0: {  // grayscale
            const uint8_t g = scale(sample(x));
            o[0] = o[1] = o[2] = g;
            o[3] = 255;
            break;
        }
        case 2: {  // RGB
            const int s = x * 3;
            o[0] = scale(sample(s));
            o[1] = scale(sample(s + 1));
            o[2] = scale(sample(s + 2));
            o[3] = 255;
            break;
        }
        case 3: {  // palette
            const unsigned idx = sample(x);
            const uint8_t* e = palette + static_cast<size_t>(idx) * 3;
            o[0] = e[0];
            o[1] = e[1];
            o[2] = e[2];
            o[3] = (trns && idx < static_cast<unsigned>(trnsCount)) ? trns[idx] : 255;
            break;
        }
        case 4: {  // gray + alpha
            const int s = x * 2;
            const uint8_t g = scale(sample(s));
            o[0] = o[1] = o[2] = g;
            o[3] = scale(sample(s + 1));
            break;
        }
        default: {  // 6 = RGBA
            const int s = x * 4;
            o[0] = scale(sample(s));
            o[1] = scale(sample(s + 1));
            o[2] = scale(sample(s + 2));
            o[3] = scale(sample(s + 3));
            break;
        }
        }
    }
}

int paeth(int a, int b, int c) {
    const int p = a + b - c;
    const int pa = std::abs(p - a), pb = std::abs(p - b), pc = std::abs(p - c);
    if (pa <= pb && pa <= pc) return a;
    return pb <= pc ? b : c;
}

bool decodePngFrame(const uint8_t* d, size_t n, ico::Image& out, std::string& err) {
    static const uint8_t kSig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    if (n < 8 + 12 + 13 || std::memcmp(d, kSig, 8) != 0) {
        err = "frame is not a PNG stream";
        return false;
    }
    size_t pos = 8;
    bool haveHeader = false;
    int width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
    std::vector<uint8_t> palette, trns, idat;
    // Chunk walk: 4-byte length, 4-byte type, data, CRC (not verified - the
    // file is the app's own asset and miniz validates the zlib stream).
    while (pos + 8 <= n) {
        const uint32_t len = rdBE32(d + pos);
        const uint8_t* type = d + pos + 4;
        if (len > n || pos + 8 + len + 4 > n) break;  // truncated tail: keep what we have
        const uint8_t* data = d + pos + 8;
        if (!haveHeader && std::memcmp(type, "IHDR", 4) == 0 && len == 13) {
            width = static_cast<int>(rdBE32(data));
            height = static_cast<int>(rdBE32(data + 4));
            bitDepth = data[8];
            colorType = data[9];
            interlace = data[12];
            haveHeader = true;
        } else if (std::memcmp(type, "PLTE", 4) == 0) {
            palette.assign(data, data + len);
        } else if (std::memcmp(type, "tRNS", 4) == 0) {
            trns.assign(data, data + len);
        } else if (std::memcmp(type, "IDAT", 4) == 0) {
            idat.insert(idat.end(), data, data + len);
        } else if (std::memcmp(type, "IEND", 4) == 0) {
            break;
        }
        pos += 8 + len + 4;
    }
    if (!haveHeader || width <= 0 || height <= 0 || width > kMaxDim || height > kMaxDim) {
        err = "frame has a bad PNG header";
        return false;
    }
    if (interlace != 0) {
        err = "interlaced PNG frames are not supported";
        return false;
    }
    // Colour type / bit depth pairs allowed by the PNG spec, indexed by
    // [colorType][bitDepth] (rows 1 and 5 are unused colour types).
    static const bool kDepthOk[8][17] = {
        /*0 gray    */ {false, true, true, true, true, false, false, false, true, false, false, false, false, false,
                        false, false, true},
        /*1 invalid */ {},
        /*2 rgb     */ {false, false, false, false, false, false, false, false, true, false, false, false, false,
                        false, false, false, true},
        /*3 palette */ {false, true, true, true, true, false, false, false, false, false, false, false, false, false,
                        false, false, false},
        /*4 gray+a  */ {false, false, false, false, false, false, false, false, true, false, false, false, false,
                        false, false, false, true},
        /*5 invalid */ {},
        /*6 rgba    */ {false, false, false, false, false, false, false, false, true, false, false, false, false,
                        false, false, false, true},
    };
    if ((colorType != 0 && colorType != 2 && colorType != 3 && colorType != 4 && colorType != 6) ||
        bitDepth < 1 || bitDepth > 16 || !kDepthOk[colorType][bitDepth]) {
        err = "unsupported PNG colour type / bit depth";
        return false;
    }
    if (colorType == 3 && (palette.empty() || palette.size() % 3 != 0)) {
        err = "palette PNG frame without a palette";
        return false;
    }
    const int bitsPerPixel = (colorType == 0 ? 1 : colorType == 3 ? 1 : colorType == 2 ? 3 : colorType == 4 ? 2 : 4) *
                             bitDepth;
    const size_t rowBytes = (static_cast<size_t>(width) * bitsPerPixel + 7) / 8;
    const size_t rawSize = (rowBytes + 1) * static_cast<size_t>(height);
    if (idat.empty() || idat.size() > kMaxFrameBytes) {
        err = "PNG frame has no image data";
        return false;
    }
    std::vector<uint8_t> raw(rawSize);
    mz_ulong rawLen = static_cast<mz_ulong>(rawSize);
    if (mz_uncompress(raw.data(), &rawLen, idat.data(), static_cast<mz_ulong>(idat.size())) != MZ_OK || rawLen != rawSize) {
        err = "PNG frame data is corrupt";
        return false;
    }
    // Defilter into 'recon', then expand straight to RGBA.
    std::vector<uint8_t> recon(rawSize);
    const uint8_t byt = static_cast<uint8_t>(std::max(1, bitsPerPixel / 8));
    for (int y = 0; y < height; ++y) {
        const uint8_t* src = raw.data() + static_cast<size_t>(y) * (rowBytes + 1);
        const int f = src[0];
        const uint8_t* cur = src + 1;
        uint8_t* dst = recon.data() + static_cast<size_t>(y) * rowBytes;
        const uint8_t* prev = y ? recon.data() + static_cast<size_t>(y - 1) * rowBytes : nullptr;
        for (size_t i = 0; i < rowBytes; ++i) {
            const int a = i >= byt ? dst[i - byt] : 0;
            const int b = prev ? prev[i] : 0;
            const int c = (prev && i >= byt) ? prev[i - byt] : 0;
            int v = cur[i];
            switch (f) {
            case 1: v += a; break;
            case 2: v += b; break;
            case 3: v += (a + b) / 2; break;
            case 4: v += paeth(a, b, c); break;
            default: break;  // 0 = None
            }
            dst[i] = static_cast<uint8_t>(v);
        }
    }
    out.width = width;
    out.height = height;
    out.rgba.assign(static_cast<size_t>(width) * height * 4, 0);
    for (int y = 0; y < height; ++y)
        expandPngRow(recon.data() + static_cast<size_t>(y) * rowBytes, width, colorType, bitDepth, palette.data(), trns.data(),
                     static_cast<int>(trns.size()), out.rgba.data() + static_cast<size_t>(y) * width * 4);
    return true;
}

// ---------------------------------------------------------------- BMP frames

// Channel value from a BI_BITFIELDS colour mask (mask must be contiguous).
uint8_t extractMask(uint32_t v, uint32_t mask) {
    if (!mask) return 255;
    int shift = 0;
    while (!(mask & 1u)) {
        mask >>= 1;
        ++shift;
    }
    int bits = 0;
    while (mask & 1u) {
        mask >>= 1;
        ++bits;
    }
    const uint32_t val = (v >> shift) & ((1u << bits) - 1);
    return bits >= 8 ? static_cast<uint8_t>(val >> (bits - 8)) : static_cast<uint8_t>(val << (8 - bits));
}

bool decodeBmpFrame(const uint8_t* d, size_t n, ico::Image& out, std::string& err) {
    if (n < 4) {
        err = "BMP frame is too small";
        return false;
    }
    const uint32_t headerSize = rd32(d);
    int width = 0, height = 0, bpp = 0;
    uint32_t compression = 0, clrUsed = 0;
    bool core = false;
    if (headerSize == 12) {  // BITMAPCOREHEADER (Win 2.x era icons)
        if (n < 12) {
            err = "BMP frame is too small";
            return false;
        }
        width = rd16(d + 4);
        height = rd16(d + 6);
        bpp = rd16(d + 10);
        core = true;
    } else if (headerSize >= 40 && n >= 40) {  // BITMAPINFOHEADER and later
        width = static_cast<int>(rd32(d + 4));
        height = static_cast<int>(rd32(d + 8));
        bpp = rd16(d + 14);
        compression = rd32(d + 16);
        clrUsed = rd32(d + 32);
    } else {
        err = "unsupported BMP header";
        return false;
    }
    // In ICO payloads biHeight counts XOR rows + AND rows, i.e. 2*H.
    if (width <= 0 || height <= 0 || height % 2 != 0 || width > kMaxDim || height > 2 * kMaxDim) {
        err = "BMP frame has bad dimensions";
        return false;
    }
    const int h = height / 2;
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 24 && bpp != 32) {
        err = "unsupported BMP bit depth";
        return false;
    }
    if (compression != 0 && !(compression == 3 && bpp == 32)) {
        err = "unsupported BMP compression";
        return false;
    }
    uint32_t maskR = 0x00FF0000, maskG = 0x0000FF00, maskB = 0x000000FF, maskA = 0xFF000000;
    size_t paletteOffset = core ? 12 : headerSize;
    if (compression == 3) {  // BI_BITFIELDS: masks follow the header
        const size_t maskPos = headerSize >= 52 ? 40 : headerSize;
        if (maskPos + 12 > n) {
            err = "BMP frame is missing its colour masks";
            return false;
        }
        maskR = rd32(d + maskPos);
        maskG = rd32(d + maskPos + 4);
        maskB = rd32(d + maskPos + 8);
        maskA = 0;
        if (headerSize >= 56 && n >= 56) maskA = rd32(d + maskPos + 12);  // V4+ header keeps it inline
        paletteOffset = headerSize >= 52 ? headerSize : headerSize + 12;
    }
    // Palette (indexed depths only): 4-byte BGRA quads, 3-byte RGBTRIPLE for
    // the 12-byte core header.
    size_t paletteBytes = 0;
    if (bpp <= 8) {
        const size_t count = clrUsed ? clrUsed : static_cast<size_t>(1) << bpp;
        paletteBytes = count * (core ? 3 : 4);
        if (count > 256) {
            err = "BMP palette is too large";
            return false;
        }
    }
    if (paletteOffset + paletteBytes > n) {
        err = "BMP frame is truncated in its palette";
        return false;
    }
    auto rowBytes = [&](int w) -> size_t {
        switch (bpp) {
        case 32: return static_cast<size_t>(w) * 4;
        case 24: return (static_cast<size_t>(w) * 3 + 3) & ~static_cast<size_t>(3);
        case 8: return (static_cast<size_t>(w) + 3) & ~static_cast<size_t>(3);
        case 4: return ((static_cast<size_t>(w) + 1) / 2 + 3) & ~static_cast<size_t>(3);
        default: return ((static_cast<size_t>(w) + 7) / 8 + 3) & ~static_cast<size_t>(3);  // 1 bpp
        }
    };
    const size_t xorSize = rowBytes(width) * static_cast<size_t>(h);
    const size_t andStride = ((static_cast<size_t>(width) + 31) / 32) * 4;
    const size_t andSize = andStride * static_cast<size_t>(h);
    if (paletteOffset + paletteBytes + xorSize > n) {
        err = "BMP frame is truncated in its pixel data";
        return false;
    }
    const bool haveMask = paletteOffset + paletteBytes + xorSize + andSize <= n;
    const uint8_t* xorData = d + paletteOffset + paletteBytes;
    const uint8_t* andData = haveMask ? xorData + xorSize : nullptr;
    // AND mask bit (1 = transparent) for pixel x on BMP row y.
    auto maskBit = [&](int y, int x) -> bool {
        if (!andData) return false;
        const uint8_t byte = andData[static_cast<size_t>(y) * andStride + static_cast<size_t>(x) / 8];
        return (byte >> (7 - x % 8)) & 1;
    };
    bool anyAlpha = false;
    std::vector<uint8_t> tmp(static_cast<size_t>(width) * h * 4, 0);  // top-down RGBA, assembled below
    auto paletteEntry = [&](size_t i) -> const uint8_t* {
        return core ? d + paletteOffset + i * 3 : d + paletteOffset + i * 4;
    };
    for (int y = 0; y < h; ++y) {
        const uint8_t* row = xorData + static_cast<size_t>(y) * rowBytes(width);
        uint8_t* dst = tmp.data() + static_cast<size_t>(h - 1 - y) * width * 4;  // BMP rows are bottom-up
        for (int x = 0; x < width; ++x) {
            uint8_t* o = dst + static_cast<size_t>(x) * 4;
            switch (bpp) {
            case 32: {
                const uint32_t v = rd32(row + static_cast<size_t>(x) * 4);
                o[0] = extractMask(v, maskR);
                o[1] = extractMask(v, maskG);
                o[2] = extractMask(v, maskB);
                o[3] = maskA ? extractMask(v, maskA) : 255;
                if (o[3]) anyAlpha = true;
                break;
            }
            case 24: {
                const uint8_t* p = row + static_cast<size_t>(x) * 3;
                o[0] = p[2];
                o[1] = p[1];
                o[2] = p[0];
                o[3] = 255;
                break;
            }
            case 8: {
                const uint8_t* e = paletteEntry(row[x]);
                o[0] = e[2];
                o[1] = e[1];
                o[2] = e[0];
                o[3] = 255;
                break;
            }
            case 4: {
                const uint8_t idx = (x % 2) ? (row[x / 2] & 0x0F) : (row[x / 2] >> 4);
                const uint8_t* e = paletteEntry(idx);
                o[0] = e[2];
                o[1] = e[1];
                o[2] = e[0];
                o[3] = 255;
                break;
            }
            default: {  // 1 bpp
                const uint8_t idx = (row[x / 8] >> (7 - x % 8)) & 1;
                const uint8_t* e = paletteEntry(idx);
                o[0] = e[2];
                o[1] = e[1];
                o[2] = e[0];
                o[3] = 255;
                break;
            }
            }
            if (bpp < 32) o[3] = maskBit(y, x) ? 0 : 255;
        }
    }
    // A 32-bit frame whose alpha channel is all zero (legacy encoders) gets
    // its transparency from the AND mask instead. Mask rows are in the same
    // bottom-up order as the XOR rows, so flip while copying.
    if (bpp == 32 && !anyAlpha)
        for (int y = 0; y < h; ++y)
            for (int x = 0; x < width; ++x)
                tmp[(static_cast<size_t>(h - 1 - y) * width + x) * 4 + 3] = maskBit(y, x) ? 0 : 255;
    out.width = width;
    out.height = h;
    out.rgba = std::move(tmp);
    return true;
}

}  // namespace

namespace ico {

bool decode(const std::vector<uint8_t>& bytes, std::vector<Image>& out, std::string& error) {
    out.clear();
    error.clear();
    if (bytes.size() < 6) {
        error = "not an ICO file (too small)";
        return false;
    }
    const uint16_t type = rd16(bytes.data() + 2);
    const uint16_t count = rd16(bytes.data() + 4);
    if (type != 1 && type != 2) {
        error = "not an ICO file (bad type)";
        return false;
    }
    if (count == 0) {
        error = "ICO file has no frames";
        return false;
    }
    if (static_cast<size_t>(count) * 16 + 6 > bytes.size()) {
        error = "ICO directory is truncated";
        return false;
    }
    int skipped = 0;
    std::string skipReasons;
    const size_t frames = std::min<size_t>(count, kMaxFrames);
    for (size_t i = 0; i < frames; ++i) {
        const uint8_t* e = bytes.data() + 6 + i * 16;
        const uint32_t size = rd32(e + 8);
        const uint32_t offset = rd32(e + 12);
        if (size < 8 || size > kMaxFrameBytes || static_cast<uint64_t>(offset) + size > bytes.size()) {
            ++skipped;
            skipReasons += " frame " + std::to_string(i) + " is out of bounds;";
            continue;
        }
        const uint8_t* d = bytes.data() + offset;
        Image img;
        std::string err;
        const bool png = size >= 8 && d[0] == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G';
        const bool ok = png ? decodePngFrame(d, size, img, err) : decodeBmpFrame(d, size, img, err);
        if (!ok || img.rgba.size() != static_cast<size_t>(img.width) * img.height * 4) {
            ++skipped;
            skipReasons += " frame " + std::to_string(i) + ": " + err + ";";
            continue;
        }
        out.push_back(std::move(img));
    }
    if (out.empty()) {
        error = "no usable frame (" + skipReasons + ")";
        return false;
    }
    if (skipped) error = skipReasons;  // informational; frames below still used
    return true;
}

const Image* bestFrame(const std::vector<Image>& frames, int side) {
    const Image* best = nullptr;
    int bestDist = 0;
    for (const Image& f : frames) {
        if (f.width <= 0) continue;
        const int dist = std::abs(f.width - side);
        if (!best || dist < bestDist || (dist == bestDist && f.width < best->width)) {
            best = &f;
            bestDist = dist;
        }
    }
    return best;
}

}  // namespace ico
