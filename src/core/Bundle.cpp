#include "core/Bundle.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include "core/ApkArchive.hpp"
#include "core/Paths.hpp"
#include "core/ProtoXml.hpp"
#include "core/SafePath.hpp"

namespace bundle {

namespace fs = std::filesystem;

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool endsWith(const std::string& s, const char* suffix) {
    const std::string suf = suffix;
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

std::string stemOf(const std::string& path) {
    const std::string name = pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).stem());
    return name.empty() ? "bundle" : name;
}

// "dir/split_config.arm64_v8a.apk" -> "split_config.arm64_v8a"
std::string splitLabel(const std::string& entry) {
    const size_t slash = entry.find_last_of('/');
    std::string n = slash == std::string::npos ? entry : entry.substr(slash + 1);
    if (endsWith(lower(n), ".apk")) n.resize(n.size() - 4);
    return n;
}

}  // namespace

bool isBundle(const std::string& path) {
    const std::string ext = lower(pathutil::toUtf8(fs::path(pathutil::fromUtf8(path)).extension()));
    return ext == ".xapk" || ext == ".apks" || ext == ".apkm" || ext == ".aab";
}

// An Android App Bundle holds modules (base/, feature folders) instead of APKs. Each module becomes an APK: its
// protobuf manifest converted to binary XML, dex/*.dex as classes*.dex, lib/, assets/, root/ and res/ as they are.
// resources.pb (the proto resource table) becomes a resources.arsc with the default-configuration values of simple entries.
static Result extractAab(ApkArchive& zip, const std::string& bundlePath, const fs::path& dir, const std::string& safeStem) {
    Result res;
    std::vector<std::string> modules;
    for (const auto& e : zip.entries()) {
        const size_t slash = e.path.find('/');
        if (slash == std::string::npos) continue;
        if (e.path.compare(slash, std::string::npos, "/manifest/AndroidManifest.xml") != 0) continue;
        modules.push_back(e.path.substr(0, slash));
    }
    if (modules.empty()) {
        res.error = "no module manifest inside " + bundlePath;
        return res;
    }
    std::stable_sort(modules.begin(), modules.end(), [](const std::string& a, const std::string& b) { return (a == "base") > (b == "base"); });
    std::error_code ec;
    const auto entries = zip.entries();
    for (const std::string& module : modules) {
        const bool isBase = module == "base";
        std::vector<uint8_t> pb, axml;
        std::string err;
        if (!zip.readEntry(module + "/manifest/AndroidManifest.xml", pb) || !protoxml::toBinaryXml(pb, axml, err)) {
            if (isBase) {
                res.error = "cannot convert the manifest of the base module: " + err;
                return res;
            }
            continue;
        }
        std::string safeLabel;
        if (!safepath::segment(module, safeLabel)) safeLabel = "module";
        const fs::path out = dir / (isBase ? safeStem + ".apk" : safeStem + "-" + safeLabel + ".apk");
        mz_zip_archive w{};
        if (!mz_zip_writer_init_file(&w, pathutil::toUtf8(out).c_str(), 0)) continue;
        Extracted ex;
        ex.path = pathutil::toUtf8(out);
        ex.label = isBase ? "base" : module;
        ex.base = isBase;
        mz_zip_writer_add_mem(&w, "AndroidManifest.xml", axml.data(), axml.size(), MZ_DEFAULT_LEVEL);
        {   // the proto resource table as a resources.arsc, so resource names and values resolve
            std::vector<uint8_t> table, arsc;
            std::string tableError;
            if (zip.readEntry(module + "/resources.pb", table) && protoxml::toArsc(table, arsc, tableError))
                mz_zip_writer_add_mem(&w, "resources.arsc", arsc.data(), arsc.size(), MZ_DEFAULT_LEVEL);
        }
        const std::string prefix = module + "/";
        for (const auto& e : entries) {
            if (e.path.rfind(prefix, 0) != 0 || e.path.back() == '/') continue;
            const std::string rel = e.path.substr(prefix.size());
            std::string target;
            if (rel.rfind("dex/", 0) == 0 && endsWith(rel, ".dex")) target = rel.substr(4), ex.hasCode = true;
            else if (rel.rfind("lib/", 0) == 0 || rel.rfind("assets/", 0) == 0 || rel.rfind("res/", 0) == 0) target = rel;
            else if (rel.rfind("root/", 0) == 0) target = rel.substr(5);
            else continue;
            if (rel.rfind("lib/", 0) == 0 && endsWith(rel, ".so")) ex.hasNative = true;
            std::string safe;
            if (!safepath::relativePath(target, safe)) continue;
            std::vector<uint8_t> bytes;
            if (!zip.readEntry(e.path, bytes)) continue;
            mz_zip_writer_add_mem(&w, safe.c_str(), bytes.data(), bytes.size(), MZ_DEFAULT_LEVEL);
        }
        const bool ok = mz_zip_writer_finalize_archive(&w);
        mz_zip_writer_end(&w);
        if (!ok) continue;
        if (ex.base || ex.hasCode || ex.hasNative) res.apks.push_back(std::move(ex));
        else {
            ++res.skipped;
            fs::remove(out, ec);
        }
    }
    if (res.apks.empty()) res.error = "no usable module inside " + bundlePath;
    return res;
}

Result extract(const std::string& bundlePath, const std::string& destRoot) {
    Result res;
    ApkArchive zip;
    if (!zip.open(bundlePath)) {
        res.error = "cannot open " + bundlePath;
        return res;
    }
    std::error_code ec;
    const uintmax_t size = fs::file_size(pathutil::fromUtf8(bundlePath), ec);
    const std::string stem = stemOf(bundlePath);
    // Directory per bundle: the stem is sanitised like any archive-derived name.
    std::string safeStem;
    if (!safepath::segment(stem, safeStem)) safeStem = "bundle";
    const fs::path dir = pathutil::fromUtf8(destRoot) / (safeStem + "_" + std::to_string(size));
    fs::create_directories(dir, ec);
    if (ec) {
        res.error = "cannot create " + pathutil::toUtf8(dir);
        return res;
    }

    if (lower(pathutil::toUtf8(fs::path(pathutil::fromUtf8(bundlePath)).extension())) == ".aab") return extractAab(zip, bundlePath, dir, safeStem);

    // Inner APKs (anywhere in the bundle). base.apk (or the entry without a
    // "split"/"config" in its name) is the base.
    std::vector<std::string> inner;
    for (const auto& e : zip.entries())
        if (endsWith(lower(e.path), ".apk")) inner.push_back(e.path);
    if (inner.empty()) {
        res.error = "no APK inside " + bundlePath;
        return res;
    }
    // Exactly one base: an entry literally named base.apk, else the first one
    // that does not look like a split, else the first entry.
    const auto looksSplit = [](const std::string& entry) {
        const std::string l = lower(splitLabel(entry));
        return l.find("split") != std::string::npos || l.find("config.") != std::string::npos;
    };
    size_t baseIndex = inner.size();
    for (size_t k = 0; k < inner.size() && baseIndex == inner.size(); ++k)
        if (lower(splitLabel(inner[k])) == "base") baseIndex = k;
    for (size_t k = 0; k < inner.size() && baseIndex == inner.size(); ++k)
        if (!looksSplit(inner[k])) baseIndex = k;
    if (baseIndex == inner.size()) baseIndex = 0;
    std::rotate(inner.begin(), inner.begin() + static_cast<std::ptrdiff_t>(baseIndex), inner.begin() + static_cast<std::ptrdiff_t>(baseIndex) + 1);

    for (size_t k = 0; k < inner.size(); ++k) {
        const std::string& entry = inner[k];
        const bool isBase = k == 0;
        std::string label = isBase ? "base" : splitLabel(entry);
        std::string safeLabel;
        if (!safepath::segment(label, safeLabel)) safeLabel = "split";
        const std::string fileName = isBase ? safeStem + ".apk" : safeStem + "-" + safeLabel + ".apk";
        const fs::path out = dir / fileName;

        std::vector<uint8_t> bytes;
        if (!zip.readEntry(entry, bytes)) continue;
        // Reuse a previous extraction of identical size.
        if (!(fs::exists(out, ec) && fs::file_size(out, ec) == bytes.size())) {
            std::ofstream f(out, std::ios::binary | std::ios::trunc);
            if (!f) continue;
            f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            f.close();
            if (!f) continue;
        }

        Extracted ex;
        ex.path = pathutil::toUtf8(out);
        ex.label = label;
        ex.base = isBase;
        ApkArchive inside;
        if (inside.open(ex.path))
            for (const auto& e : inside.entries()) {
                if (e.path.rfind("classes", 0) == 0 && endsWith(e.path, ".dex")) ex.hasCode = true;
                if (e.path.rfind("lib/", 0) == 0 && endsWith(e.path, ".so")) ex.hasNative = true;
            }
        if (ex.base || ex.hasCode || ex.hasNative) res.apks.push_back(std::move(ex));
        else {
            ++res.skipped;
            fs::remove(out, ec);  // resources / config only: nothing for ApkSpy to show
        }
    }
    if (res.apks.empty()) res.error = "no usable APK inside " + bundlePath;
    return res;
}

}  // namespace bundle
