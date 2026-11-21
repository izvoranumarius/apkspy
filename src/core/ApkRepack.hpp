#pragma once
#include <functional>
#include <string>
#include <utility>
#include <vector>

class ApkArchive;

// Rebuilds an APK with modified entries and re-signs it, so a release build
// can be made debuggable (JDWP refuses non-debuggable apps since Android 14),
// have pinning stripped, or carry an injected native library.
//
// Layout of the output: entries copied from the source (aligned where the
// platform needs it - resources.arsc and stored .so files - via miniz), the
// replaced entries, then a signing block.
//
// Signing: v1 (JAR manifest, PKCS#7) is implemented; v2/v3 blocks are
// produced when a signing key is available. The crypto uses the already
// bundled mbedTLS, so no new dependency is added.
namespace repack {

struct Replacement {
    std::string entryPath;  // zip path, e.g. AndroidManifest.xml
    std::string bytes;      // the new content
};

struct Options {
    std::string sourceApk;
    std::string outputApk;
    std::vector<Replacement> replacements;
    // Re-sign with this key (PKCS#12 / PEM). When empty the output is left
    // unsigned-but-modified (installable only with unsigned flags).
    std::string keystorePath;
    std::string keystorePassword;
    std::string alias;
    // Lists what was written, for the panel / report.
    bool verbose = false;
};

struct Result {
    bool ok = false;
    std::string error;
    std::string log;       // one line per step (verbose)
    size_t entries = 0;    // entries written
    size_t replaced = 0;
    bool signedOutput = false;
};

// Runs the whole pipeline. Blocking: call it from a worker thread (the UI
// shows the log as it arrives through onLog).
Result run(const Options& options, std::function<void(const std::string&)> onLog = {},
           const std::function<bool()>& cancelled = {});

}  // namespace repack
