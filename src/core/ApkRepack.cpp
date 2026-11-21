#include "core/ApkRepack.hpp"
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include "core/ApkArchive.hpp"
#include "core/Paths.hpp"
#include "core/Process.hpp"

namespace repack {

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

#ifdef _WIN32
constexpr const char* kExe = ".exe";
constexpr const char* kBat = ".bat";
#else
constexpr const char* kExe = "";
constexpr const char* kBat = "";
#endif

bool fileExists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec);
}

}  // namespace

Tools Tools::fromAdb(const std::string& adbPath) {
    Tools t;
    // keytool: JAVA_HOME/bin/keytool, else PATH.
    if (const char* jh = std::getenv("JAVA_HOME"); jh && *jh) {
        const fs::path k = pathutil::fromUtf8(jh) / "bin" / ("keytool" + std::string(kExe));
        if (fileExists(k)) t.keytool = pathutil::toUtf8(k);
    }
    if (adbPath.empty() || adbPath == "adb") return t;
    const fs::path sdk = pathutil::fromUtf8(adbPath).parent_path().parent_path();
    const fs::path bt = sdk / "build-tools";
    if (!fileExists(bt)) return t;
    // Newest build-tools version (lexicographic on the version dir name is a
    // good-enough ordering for "34.0.0" style names).
    fs::path best;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(bt, ec))
        if (e.is_directory(ec) && (best.empty() || e.path().filename().string() > best.filename().string())) best = e.path();
    if (best.empty()) return t;
    const fs::path za = best / ("zipalign" + std::string(kExe));
    const fs::path as = best / ("apksigner" + std::string(kBat));
    if (fileExists(za)) t.zipalign = pathutil::toUtf8(za);
    if (fileExists(as)) t.apksigner = pathutil::toUtf8(as);
    return t;
}

std::string debugKeystorePath() {
    const char* home =
#ifdef _WIN32
        std::getenv("USERPROFILE");
#else
        std::getenv("HOME");
#endif
    if (!home || !*home) return "debug.keystore";
    return pathutil::toUtf8(pathutil::fromUtf8(home) / ".android" / "debug.keystore");
}

bool ensureDebugKeystore(const Tools& tools, const std::string& path, std::string& error) {
    if (fileExists(pathutil::fromUtf8(path))) return true;
    std::error_code ec;
    fs::create_directories(pathutil::fromUtf8(path).parent_path(), ec);
    // The Android SDK's own debug key: CN=Android Debug, 2048-bit RSA, 30y.
    const proc::RunResult r = proc::run({tools.keytool, "-genkeypair", "-v", "-keystore", path, "-storepass", "android",
                                         "-keypass", "android", "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
                                         "-validity", "10950", "-dname", "CN=Android Debug,O=Android,C=US"},
                                        60000);
    if (!r.started) {
        error = "keytool not found (install a JDK or set JAVA_HOME)";
        return false;
    }
    if (!fileExists(pathutil::fromUtf8(path))) {
        error = trim(r.output).empty() ? "keytool failed to create the debug keystore" : trim(r.output);
        return false;
    }
    return true;
}

std::vector<std::string> assembleArgv(const std::string& smali, const std::string& dir, const std::string& outDex) {
    const bool isJar = smali.size() > 4 && smali.compare(smali.size() - 4, 4, ".jar") == 0;
    if (isJar) return {"java", "-jar", smali, "a", dir, "-o", outDex};
    return {smali, "a", dir, "-o", outDex};
}

std::vector<std::string> signArgv(const Tools& tools, const Options& opts, const std::string& in, const std::string& out) {
    const std::string ks = opts.keystorePath.empty() ? debugKeystorePath() : opts.keystorePath;
    const std::string storePass = opts.keystorePath.empty() ? "android" : opts.keystorePassword;
    const std::string alias = opts.keyAlias.empty() ? (opts.keystorePath.empty() ? "androiddebugkey" : "") : opts.keyAlias;
    const std::string keyPass = !opts.keyPassword.empty() ? opts.keyPassword : storePass;
    std::vector<std::string> argv = {tools.apksigner, "sign", "--ks", ks, "--ks-pass", "pass:" + storePass};
    if (!alias.empty()) {
        argv.push_back("--ks-key-alias");
        argv.push_back(alias);
    }
    if (!keyPass.empty()) {
        argv.push_back("--key-pass");
        argv.push_back("pass:" + keyPass);
    }
    argv.push_back("--out");
    argv.push_back(out);
    argv.push_back(in);
    return argv;
}

namespace {

std::string readWhole(const std::string& path, bool& ok) {
    std::ifstream in(pathutil::fromUtf8(path), std::ios::binary);
    if (!in) {
        ok = false;
        return {};
    }
    std::ostringstream s;
    s << in.rdbuf();
    ok = true;
    return s.str();
}

// The zip-rebuild step: source entries (replacements spliced in) into `dest`.
bool rebuild(const std::string& sourceApk, const std::vector<Replacement>& replacements,
             const std::function<void(const std::string&)>& log, const std::function<bool()>& cancelled,
             const std::string& dest, Result& res) {
    ApkArchive in;
    if (!in.open(sourceApk)) {
        res.error = "cannot open " + sourceApk;
        return false;
    }
    std::map<std::string, std::string> replaced;
    for (const auto& r : replacements) replaced[r.entryPath] = r.bytes;
    log("Reading " + std::to_string(in.entries().size()) + " entries");

    mz_zip_archive out{};
    if (!mz_zip_writer_init_file(&out, dest.c_str(), 0)) {
        res.error = "cannot create " + dest;
        return false;
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
        // resources.arsc and .so are stored uncompressed (alignment + mmap).
        const bool isArsc = e.path == "resources.arsc";
        const bool isSo = e.path.size() > 3 && e.path.compare(e.path.size() - 3, 3, ".so") == 0;
        const mz_uint method = (isArsc || isSo) ? MZ_NO_COMPRESSION : MZ_DEFAULT_COMPRESSION;
        if (!mz_zip_writer_add_mem(&out, e.path.c_str(), data.data(), data.size(), method)) {
            log("failed to add " + e.path);
            ok = false;
            break;
        }
        ++res.entries;
    }
    for (const auto& [path, bytes] : replaced) {
        bool present = false;
        for (const auto& e : in.entries())
            if (e.path == path) {
                present = true;
                break;
            }
        if (present) continue;
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
    return ok;
}

}  // namespace

Result run(const Options& options, const Tools& tools, std::function<void(const std::string&)> onLog,
           const std::function<bool()>& cancelled) {
    Result res;
    res.outputApk = options.outputApk;
    const auto log = [&](const std::string& line) {
        res.log += line + "\n";
        if (onLog) onLog(line);
    };
    std::error_code ec;

    // Assemble smali folders into dex replacements first.
    std::vector<Replacement> reps = options.replacements;
    int asmIndex = 0;
    for (const auto& asmb : options.assemblies) {
        const std::string outDex = options.outputApk + ".asm" + std::to_string(asmIndex++) + ".dex";
        log("Assembling " + asmb.smaliDir + " -> " + asmb.entryPath);
        const proc::RunResult r = proc::run(assembleArgv(tools.smali, asmb.smaliDir, outDex), 180000);
        if (!r.started) {
            res.error = "smali assembler not found (" + tools.smali + "); set its path or install smali";
            return res;
        }
        if (r.exitCode != 0 || !fileExists(pathutil::fromUtf8(outDex))) {
            res.error = "smali assembly failed: " + trim(r.output);
            fs::remove(pathutil::fromUtf8(outDex), ec);
            return res;
        }
        bool ok = false;
        std::string bytes = readWhole(outDex, ok);
        fs::remove(pathutil::fromUtf8(outDex), ec);
        if (!ok) {
            res.error = "cannot read assembled dex";
            return res;
        }
        reps.push_back({asmb.entryPath, std::move(bytes)});
    }

    const std::string rebuilt = options.outputApk + ".rebuilt.apk";
    if (!rebuild(options.sourceApk, reps, log, cancelled, rebuilt, res)) {
        if (res.error.empty()) res.error = "repack failed";
        fs::remove(pathutil::fromUtf8(rebuilt), ec);
        return res;
    }
    log("Rebuilt " + std::to_string(res.entries) + " entries (" + std::to_string(res.replaced) + " replaced)");

    std::string current = rebuilt;  // the file to carry to the next step

    // zipalign.
    if (options.align) {
        const bool haveZa = proc::run({tools.zipalign, "--help"}, 8000).started || tools.zipalign != "zipalign";
        if (!haveZa && tools.zipalign == "zipalign") {
            log("zipalign not found - skipping alignment (apksigner still aligns on sign)");
        } else {
            const std::string aligned = options.outputApk + ".aligned.apk";
            fs::remove(pathutil::fromUtf8(aligned), ec);
            const proc::RunResult r = proc::run({tools.zipalign, "-p", "-f", "4", current, aligned}, 120000);
            if (r.started && r.exitCode == 0 && fileExists(pathutil::fromUtf8(aligned))) {
                fs::remove(pathutil::fromUtf8(current), ec);
                current = aligned;
                res.aligned = true;
                log("Aligned (zipalign -p 4)");
            } else {
                log("zipalign failed - continuing unaligned: " + trim(r.output));
            }
        }
    }

    // apksigner (also aligns with v2+; a debug keystore is created if needed).
    if (options.sign) {
        std::string keystore = options.keystorePath.empty() ? debugKeystorePath() : options.keystorePath;
        std::string err;
        bool keyOk = true;
        if (options.keystorePath.empty()) keyOk = ensureDebugKeystore(tools, keystore, err);
        if (!keyOk) {
            log("cannot sign: " + err);
            // leave the rebuilt/aligned file as the (unsigned) output
            fs::rename(pathutil::fromUtf8(current), pathutil::fromUtf8(options.outputApk), ec);
            if (ec) fs::copy_file(pathutil::fromUtf8(current), pathutil::fromUtf8(options.outputApk),
                                  fs::copy_options::overwrite_existing, ec);
            res.error = "unsigned (" + err + ")";
            res.ok = true;  // a rebuilt, unsigned APK was still produced
            return res;
        }
        fs::remove(pathutil::fromUtf8(options.outputApk), ec);
        const proc::RunResult r = proc::run(signArgv(tools, options, current, options.outputApk), 180000);
        if (!r.started) {
            log("apksigner not found - output left unsigned");
            fs::rename(pathutil::fromUtf8(current), pathutil::fromUtf8(options.outputApk), ec);
            res.error = "apksigner not found (install Android SDK build-tools)";
            res.ok = true;
            return res;
        }
        if (r.exitCode != 0 || !fileExists(pathutil::fromUtf8(options.outputApk))) {
            res.error = trim(r.output).empty() ? "apksigner failed" : trim(r.output);
            fs::remove(pathutil::fromUtf8(current), ec);
            return res;
        }
        fs::remove(pathutil::fromUtf8(current), ec);  // apksigner wrote a fresh --out
        res.signedOutput = true;
        log("Signed with " + (options.keystorePath.empty() ? std::string("the debug keystore") : keystore));
    } else {
        fs::rename(pathutil::fromUtf8(current), pathutil::fromUtf8(options.outputApk), ec);
    }

    log("Wrote " + options.outputApk);
    res.ok = true;
    return res;
}

}  // namespace repack
