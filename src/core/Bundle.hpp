#pragma once
#include <string>
#include <vector>

// App bundles that wrap APKs: .xapk, .apks and .apkm are zip files holding a
// base APK and split APKs (config / feature splits). ApkSpy analyses APKs, so
// opening a bundle extracts the inner APKs and adds the useful ones.
//
// Entry names come from archive content, so they pass through the SafePath
// module: nothing is ever written outside the destination directory.
namespace bundle {

// True for a bundle file name (by extension, case-insensitive).
bool isBundle(const std::string& path);

struct Extracted {
    std::string path;   // the extracted APK
    std::string label;  // "base" or the split's name ("split_config.arm64_v8a")
    bool base = false;
    bool hasCode = false;    // contains classes*.dex
    bool hasNative = false;  // contains lib/**/*.so
};

struct Result {
    std::vector<Extracted> apks;  // base first, then the splits that carry code or native libraries
    int skipped = 0;              // splits left out (resources / config only)
    std::string error;
    bool ok() const { return error.empty() && !apks.empty(); }
};

// Extracts the inner APKs of `bundlePath` under `destRoot`/<stem>_<size>/ and
// returns the ones worth analysing. The extracted files are named
// "<stem>.apk" (base) and "<stem>-<split>.apk" so they get readable group
// names in the project. A previous extraction of the same bundle is reused.
Result extract(const std::string& bundlePath, const std::string& destRoot);

}  // namespace bundle
