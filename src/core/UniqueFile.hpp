#pragma once
// An owning std::FILE* (C++ Core Guidelines R.1): fclose runs when the owner
// goes out of scope, on every path. Use .get() to pass it to stdio calls.
#include <cstdio>
#include <memory>

struct FileCloser {
    void operator()(std::FILE* f) const noexcept { std::fclose(f); }
};
using UniqueFile = std::unique_ptr<std::FILE, FileCloser>;
