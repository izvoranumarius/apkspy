#pragma once
// Owning wrappers for Win32 handles (C++ Core Guidelines R.1): the handle is
// released when its owner goes out of scope, on every path, including early
// returns and exceptions. Use .get() to pass it to an API, .release() to hand
// ownership on and .reset() to close it early.
//
// Windows only. Include it after the file's own <windows.h> (and its
// WIN32_LEAN_AND_MEAN / NOMINMAX choices); it does not configure them.
#ifndef _WIN32
#error "core/UniqueHandle.hpp is Windows-only"
#endif
#include <memory>
#include <windows.h>

struct HandleCloser {
    void operator()(HANDLE h) const noexcept { CloseHandle(h); }
};
// A kernel handle closed with CloseHandle. Empty is nullptr.
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

// Takes ownership of a handle from an API that reports failure as
// INVALID_HANDLE_VALUE (CreateFile) rather than nullptr.
inline UniqueHandle adoptFileHandle(HANDLE h) noexcept {
    return UniqueHandle(h == INVALID_HANDLE_VALUE ? nullptr : h);
}

struct LocalFreer {
    void operator()(void* p) const noexcept { LocalFree(p); }
};
// Memory the OS allocated with LocalAlloc (CommandLineToArgvW, FormatMessage).
template <typename T>
using UniqueLocal = std::unique_ptr<T, LocalFreer>;
