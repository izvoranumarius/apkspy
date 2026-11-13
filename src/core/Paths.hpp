#pragma once
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

// Path helpers shared by the whole app.
//
// Internal storage rule: every path kept in a std::string is UTF-8, on every
// platform. At the OS boundary the string is converted to the native encoding
// (wide chars on Windows) via fromUtf8(); everything coming out of the OS
// (directory listings, GLFW drops) is converted back via toUtf8().
namespace pathutil {

// UTF-8 -> fs::path (native-wide on Windows, byte string elsewhere).
// Since C++20 UTF-8 text is typed char8_t; the char <-> char8_t copies are
// byte-for-byte reinterpretations, not conversions.
inline std::filesystem::path fromUtf8(const std::string& s) {
#ifdef _WIN32
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
#else
    return std::filesystem::path(s);
#endif
}

// fs::path -> UTF-8 std::string.
inline std::string toUtf8(const std::filesystem::path& p) {
#ifdef _WIN32
    const std::u8string u8 = p.u8string();
    return std::string(u8.begin(), u8.end());
#else
    return p.string();
#endif
}

// Absolute + lexically_normal form of a UTF-8 path (never throws).
inline std::string normalize(const std::string& utf8) {
    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(fromUtf8(utf8), ec);
    if (ec) return utf8;
    return toUtf8(abs.lexically_normal());
}

// Per-user configuration directory (created on first use):
//   Windows: %APPDATA%\ApkSpy
//   Linux:   $XDG_CONFIG_HOME/apkspy or ~/.config/apkspy
//   macOS:   ~/Library/Application Support/ApkSpy
// Falls back to the temp directory when no home can be found.
inline std::filesystem::path configDir() {
    namespace fs = std::filesystem;
    fs::path dir;
#ifdef _WIN32
    if (const char* appdata = std::getenv("APPDATA")) dir = fromUtf8(appdata) / "ApkSpy";
    else if (const char* home = std::getenv("USERPROFILE"))
        dir = fromUtf8(home) / "AppData" / "Roaming" / "ApkSpy";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) dir = fromUtf8(home) / "Library" / "Application Support" / "ApkSpy";
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
        if (*xdg) dir = fromUtf8(xdg) / "apkspy";
    }
    if (dir.empty()) {
        if (const char* home = std::getenv("HOME")) dir = fromUtf8(home) / ".config" / "apkspy";
    }
#endif
    if (dir.empty()) dir = fs::temp_directory_path() / "apkspy";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

// Full path of a config file (e.g. "apkspy.settings").
inline std::string configFile(const char* name) { return toUtf8(configDir() / name); }

// Directory containing the running executable (UTF-8, no trailing slash).
// Empty when the platform lookup fails; assetsFile() then relies on the
// working directory. Implemented in Paths.cpp (needs one OS call each).
std::string exeDir();

// Locates "assets/<relativeName>" next to the solution/project folder:
//   <exeDir>/assets, <exeDir>/../assets, <exeDir>/../../assets (the exe
// lives in build/ or x64/Debug at dev time), then ./assets relative to the
// working directory. Returns an absolute UTF-8 path, or "" when the file
// does not exist. Missing assets are never an error: the caller keeps its
// built-in fallback.
std::string assetsFile(const char* relativeName);

}  // namespace pathutil
