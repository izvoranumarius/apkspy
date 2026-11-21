#include "core/ApkRepack.hpp"
#include <map>
#include "core/ApkArchive.hpp"

namespace repack {

Result run(const Options& options, std::function<void(const std::string&)> onLog,
           const std::function<bool()>& cancelled) {
    Result res;
    const auto log = [&](const std::string& line) {
        res.log += line + "\n";
        if (onLog) onLog(line);
    };

    ApkArchive in;
    if (!in.open(options.sourceApk)) {
        res.error = "cannot open " + options.sourceApk;
        return res;
    }
    std::map<std::string, std::string> replaced;
    for (const auto& r : options.replacements) replaced[r.entryPath] = r.bytes;

    log("Reading " + std::to_string(in.entries().size()) + " entries");

    // miniz writer: one archive, entries added in order.
    mz_zip_archive out{};
    if (!mz_zip_writer_init_file(&out, options.outputApk.c_str(), 0)) {
        res.error = "cannot create " + options.outputApk;
        return res;
    }
    bool ok = true;
    for (const auto& e : in.entries()) {
        if (cancelled && cancelled()) {
            res.error = "cancelled";
            ok = false;
            break;
        }
        std::vector<uint8_t> data;
        auto it = replaced.find(e.path);
        if (it != replaced.end()) {
            data.assign(it->second.begin(), it->second.end());
            ++res.replaced;
        } else if (!in.readEntry(e.path, data)) {
            log("skip unreadable entry " + e.path);
            continue;
        }
        // resources.arsc must be 4-byte aligned; .so files stored uncompressed.
        // (The bundled miniz has no alignment flag: STORE keeps offsets
        // deterministic, and zipalign is a post step when available.)
        const bool isArsc = e.path == "resources.arsc";
        const bool isSo = e.path.size() > 3 && e.path.compare(e.path.size() - 3, 3, ".so") == 0;
        const mz_uint flags = (isArsc || isSo) ? MZ_ZIP_FLAG_COMPRESSED_DATA : 0;
        const mz_uint method = (isArsc || isSo) ? MZ_NO_COMPRESSION : MZ_DEFAULT_COMPRESSION;
        if (!mz_zip_writer_add_mem(&out, e.path.c_str(), data.data(), data.size(), method | flags)) {
            log("failed to add " + e.path);
            ok = false;
            break;
        }
        ++res.entries;
    }
    // Replacements for entries that did not exist in the source are added too.
    for (const auto& [path, bytes] : replaced) {
        bool exists = false;
        for (const auto& e : in.entries())
            if (e.path == path) {
                exists = true;
                break;
            }
        if (exists) continue;
        if (!mz_zip_writer_add_mem(&out, path.c_str(), bytes.data(), bytes.size(), MZ_DEFAULT_COMPRESSION)) {
            log("failed to add " + path);
            ok = false;
            break;
        }
        ++res.entries;
        ++res.replaced;
    }
    if (ok && !mz_zip_writer_finalize_archive(&out)) {
        res.error = "cannot finalize archive";
        ok = false;
    }
    mz_zip_writer_end(&out);

    if (!ok) {
        if (res.error.empty()) res.error = "repack failed";
        return res;
    }
    log("Wrote " + std::to_string(res.entries) + " entries (" + std::to_string(res.replaced) +
        " replaced) - output is UNSIGNED");
    // Signing (v1 JAR signature) needs a key + crypto; it is reported as not
    // done rather than silently producing an uninstallable APK.
    if (!options.keystorePath.empty())
        log("re-signing requested, but v1/v2 signing is not implemented yet - output stays unsigned");
    res.ok = true;
    return res;
}

}  // namespace repack
