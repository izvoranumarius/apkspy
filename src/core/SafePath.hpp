#pragma once
#include <string>
#include <string_view>

// Path sanitiser for names that come from archive content (M5). Every file
// ApkSpy writes whose name originates inside an APK (zip entry names, folder
// entry names) MUST pass through this module first (ground rule 5): zip
// entries can contain "..", absolute paths, drive letters and Windows device
// names, and a naive join would let a crafted APK write outside the
// destination directory (zip-slip).
namespace safepath {

// True when the segment is a Windows reserved device name (CON, PRN, AUX,
// NUL, COM1-9, LPT1-9), case-insensitively, also with an extension.
inline bool isReservedDevice(std::string_view stem) {
    auto equals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i], cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    };
    static const char* kReserved[] = {"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4",
                                      "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3",
                                      "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
    for (const char* r : kReserved)
        if (equals(stem, r)) return true;
    return false;
}

// Sanitises ONE path segment in place. Rules:
//  - control characters and '\\'/':' become '_' (separators / drive letters),
//  - a bare "." or ".." segment (and dots-only names) become "_",
//  - Windows reserved device names get a '_' prefix,
//  - trailing dots and spaces are stripped (Windows ignores them, which
//    enables name-collision tricks).
// Returns false when nothing usable remains (empty input).
inline bool segment(std::string_view name, std::string& out) {
    out.clear();
    if (name.empty()) return false;
    for (char c : name) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F || c == '\\' || c == ':') out += '_';
        else out += c;
    }
    // Dots-only segments ("." / ".." / "...") must never survive: they are
    // the zip-slip vehicle.
    bool onlyDots = true;
    for (char c : out)
        if (c != '.') { onlyDots = false; break; }
    if (onlyDots) {
        out.assign(out.size(), '_');
        return true;
    }
    // Windows reserved device names (CON, NUL, COM1, ... also with extension).
    const size_t dot = out.find('.');
    const std::string_view stem = dot == std::string::npos ? std::string_view(out) : std::string_view(out).substr(0, dot);
    if (isReservedDevice(stem)) out.insert(out.begin(), '_');
    // Trailing dots/spaces are invisible on Windows - strip them.
    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) out.pop_back();
    return !out.empty();
}

// Sanitises a full archive-entry path into a safe RELATIVE path (segments
// joined with '/'). Absolute paths lose their root, ".." segments become "_"
// and empty segments are dropped, so the result can never escape the
// destination directory. Returns false when no safe segment remains or the
// path is absurdly deep.
inline bool relativePath(std::string_view archivePath, std::string& out) {
    out.clear();
    if (archivePath.empty()) return false;
    size_t depth = 0;
    size_t start = 0;
    std::string seg;
    while (start <= archivePath.size()) {
        size_t slash = archivePath.find('/', start);
        const bool last = slash == std::string_view::npos;
        const std::string_view part = archivePath.substr(start, last ? std::string_view::npos : slash - start);
        start = last ? archivePath.size() + 1 : slash + 1;
        if (part.empty()) continue;
        if (!segment(part, seg)) continue;
        if (depth > 0) out += '/';
        out += seg;
        if (++depth > 64) return false;  // absurd nesting: refuse
        if (last) break;
    }
    return depth > 0 && out.size() <= 1024;
}

}  // namespace safepath
