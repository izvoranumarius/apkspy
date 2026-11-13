#include "core/Paths.hpp"
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif

namespace pathutil {

std::string exeDir() {
    namespace fs = std::filesystem;
    std::error_code ec;
#ifdef _WIN32
    std::wstring exe(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size()));
    if (n == 0 || n >= exe.size()) return {};
    exe.resize(n);
    return toUtf8(fs::path(exe).parent_path());
#elif defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) return {};
    std::vector<char> buf(size);
    if (_NSGetExecutablePath(buf.data(), &size) != 0) return {};
    return toUtf8(fs::path(buf.data()).parent_path());
#else
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(buf)) return {};
    buf[n] = '\0';
    return toUtf8(fs::path(buf).parent_path());
#endif
}

std::string assetsFile(const char* relativeName) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const std::string dir = exeDir();
    std::vector<std::string> bases;
    if (!dir.empty()) {
        bases.push_back(dir);           // <exe>/assets            (installed next to the exe)
        bases.push_back(dir + "/..");   // <exe>/../assets          (exe in build/ or x64/Debug)
        bases.push_back(dir + "/../..");  // <exe>/../../assets      (exe in x64/Debug of a nested solution)
    }
    bases.push_back(".");  // last resort: the working directory
    for (const std::string& base : bases) {
        const fs::path candidate = fs::path(base) / "assets" / fromUtf8(relativeName);
        if (fs::is_regular_file(candidate, ec)) return toUtf8(fs::weakly_canonical(candidate, ec));
    }
    return {};
}

}  // namespace pathutil
