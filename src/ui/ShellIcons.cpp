#include "ui/ShellIcons.hpp"

// Single shared instance on every platform (defined outside the _WIN32 guard).
ShellIcons& ShellIcons::instance() {
    static ShellIcons s;
    return s;
}

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#include <cctype>
#include <utility>
#include <vector>

namespace {
std::string extOf(const std::string& name) {
    size_t dot = name.find_last_of('.');
    if (dot == std::string::npos) return {};
    std::string ext = name.substr(dot);  // includes the dot
    for (char& c : ext) c = (char)std::tolower((unsigned char)c);
    return ext;
}

// Decodes an HICON into a top-down RGBA pixel buffer.
bool hiconToRgba(HICON icon, std::vector<uint8_t>& px, int& w, int& h) {
    ICONINFO ii{};
    if (!GetIconInfo(icon, &ii)) return false;
    bool ok = false;
    BITMAP bm{};
    if (ii.hbmColor && GetObject(ii.hbmColor, sizeof bm, &bm) && bm.bmWidth > 0 && bm.bmHeight > 0) {
        w = bm.bmWidth;
        h = bm.bmHeight;
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;  // negative = top-down rows
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        px.assign((size_t)w * h * 4, 0);
        HDC dc = GetDC(nullptr);
        if (GetDIBits(dc, ii.hbmColor, 0, h, px.data(), &bi, DIB_RGB_COLORS) == h) {
            ok = true;
            // GetDIBits yields BGRA - swap into RGBA.
            for (size_t i = 0; i < px.size(); i += 4) std::swap(px[i], px[i + 2]);
            bool hasAlpha = false;
            for (size_t i = 3; i < px.size(); i += 4)
                if (px[i]) { hasAlpha = true; break; }
            if (!hasAlpha && ii.hbmMask) {
                // Legacy 16/24-bit icons keep transparency in the 1bpp mask.
                const int stride = ((w + 31) / 32) * 4;
                std::vector<uint8_t> mask((size_t)stride * h, 0);
                BITMAPINFO mb{};
                mb.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                mb.bmiHeader.biWidth = w;
                mb.bmiHeader.biHeight = -h;
                mb.bmiHeader.biPlanes = 1;
                mb.bmiHeader.biBitCount = 1;
                mb.bmiHeader.biCompression = BI_RGB;
                if (GetDIBits(dc, ii.hbmMask, 0, h, mask.data(), &mb, DIB_RGB_COLORS) == h)
                    for (int y = 0; y < h; ++y)
                        for (int x = 0; x < w; ++x)
                            px[((size_t)y * w + x) * 4 + 3] =
                                (mask[(size_t)y * stride + x / 8] & (0x80 >> (x % 8))) ? 0 : 255;
            }
        }
        ReleaseDC(nullptr, dc);
    }
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);
    return ok;
}
}  // namespace

ImTextureID ShellIcons::textureFor(const std::string& key, const wchar_t* probeName, unsigned fileAttrs) {
    auto it = cache_.find(key);
    if (it != cache_.end()) return it->second ? (ImTextureID)(uintptr_t)it->second->id() : 0;

    SHFILEINFOW sfi{};
    std::unique_ptr<Texture> tex;
    // SHGFI_USEFILEATTRIBUTES: icon is resolved from the extension without
    // the probe file existing on disk.
    if (SHGetFileInfoW(probeName, fileAttrs, &sfi, sizeof sfi,
                       SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES) &&
        sfi.hIcon) {
        std::vector<uint8_t> px;
        int w = 0, h = 0;
        if (hiconToRgba(sfi.hIcon, px, w, h) && w > 0 && h > 0)
            tex = std::make_unique<Texture>(px.data(), w, h);
        DestroyIcon(sfi.hIcon);
    }
    cache_[key] = std::move(tex);  // failures are cached too (as null)
    return cache_[key] ? (ImTextureID)(uintptr_t)cache_[key]->id() : 0;
}

ImTextureID ShellIcons::iconFor(const TreeNode& node, bool apkRoot) {
    if (apkRoot) {
        if (!apk_) apk_ = textureFor(".apk", L"probe.apk", FILE_ATTRIBUTE_NORMAL);
        if (apk_) return apk_;
    }
    if (node.isFolder()) {
        if (!folder_) folder_ = textureFor("<folder>", L"probe", FILE_ATTRIBUTE_DIRECTORY);
        return folder_;
    }
    std::string ext = extOf(node.name());
    if (ext.empty()) {
        if (!generic_) generic_ = textureFor("<file>", L"probe", FILE_ATTRIBUTE_NORMAL);
        return generic_;
    }
    const std::wstring probe = L"probe" + std::wstring(ext.begin(), ext.end());
    return textureFor(ext, probe.c_str(), FILE_ATTRIBUTE_NORMAL);
}

#else  // non-Windows: no shell icons, explorer falls back to drawn icons

ImTextureID ShellIcons::iconFor(const TreeNode& node, bool apkRoot) {
    (void)node;
    (void)apkRoot;
    return 0;
}

#endif
