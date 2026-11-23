#include "app/SystemTheme.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace systemtheme {

int prefersDark() {
#ifdef _WIN32
    DWORD value = 1, size = sizeof value;
    const LSTATUS rc = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                                    L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &value, &size);
    if (rc != ERROR_SUCCESS) return -1;
    return value == 0 ? 1 : 0;  // AppsUseLightTheme = 0 means dark
#else
    return -1;
#endif
}

const char* presetFor(int dark) {
    if (dark < 0) return "";
    return dark ? "dark-modern" : "light";
}

}  // namespace systemtheme
