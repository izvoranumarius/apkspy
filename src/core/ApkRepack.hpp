#pragma once
#include <functional>
#include <string>
#include <utility>
#include <vector>

// Rebuilds an APK with modified entries and re-signs it, so an edited app can
// be installed on a device: patch smali/resources, re-pack, align and sign.
//
// The pipeline is: rebuild the zip (bundled miniz, resources.arsc and .so
// kept uncompressed) -> zipalign -> apksigner. Alignment and signing use the
// Android SDK build-tools (zipalign, apksigner) and the JDK's keytool, found
// next to a known adb or on PATH; when they are missing the output is left
// rebuilt-but-unsigned and the log says so (nothing crashes).
namespace repack {

struct Replacement {
    std::string entryPath;  // zip path, e.g. AndroidManifest.xml or smali as compiled dex
    std::string bytes;      // the new content
};

// A folder of smali assembled (by the external smali tool) into a dex entry.
struct SmaliAssembly {
    std::string smaliDir;   // folder of .smali files (a baksmali-style tree)
    std::string entryPath;  // target zip entry, e.g. "classes.dex"
};

// External tools. Derive them from the SDK that holds a known adb, or leave
// the PATH defaults.
struct Tools {
    std::string zipalign = "zipalign";
    std::string apksigner = "apksigner";  // a .bat on Windows
    std::string keytool = "keytool";      // from the JDK
    // The smali assembler: a wrapper on PATH, or a path to smali.jar (run
    // through java). Only needed when Options::assemblies is non-empty.
    std::string smali = "smali";
    // <sdk>/platform-tools/adb -> <sdk>/build-tools/<newest>/{zipalign,apksigner}.
    static Tools fromAdb(const std::string& adbPath);
};

struct Options {
    std::string sourceApk;
    std::string outputApk;
    std::vector<Replacement> replacements;
    // Smali folders assembled into dex entries before the rebuild (each
    // becomes a replacement). Needs Tools::smali.
    std::vector<SmaliAssembly> assemblies;
    // Signing key (a Java keystore). When empty, a debug keystore is used or
    // created (the standard android / androiddebugkey / android), so the
    // output is always installable.
    std::string keystorePath;
    std::string keystorePassword;
    std::string keyAlias;
    std::string keyPassword;   // defaults to the store password when empty
    bool align = true;         // run zipalign before signing
    bool sign = true;          // run apksigner
};

struct Result {
    bool ok = false;
    std::string error;
    std::string log;        // one line per step
    std::string outputApk;  // the final file written
    size_t entries = 0;
    size_t replaced = 0;
    bool aligned = false;
    bool signedOutput = false;
};

// Default debug keystore path (~/.android/debug.keystore) and its fixed
// credentials, matching the Android SDK's own debug key.
std::string debugKeystorePath();

// Ensures `path` exists as a debug keystore, creating it with keytool when
// missing. False (with error) only when it is missing and cannot be created.
bool ensureDebugKeystore(const Tools& tools, const std::string& path, std::string& error);

// apksigner argv for `in` -> `out` (pure, for testing/preview).
std::vector<std::string> signArgv(const Tools& tools, const Options& opts, const std::string& in, const std::string& out);

// smali-assembler argv for `dir` -> `outDex` (pure). A `smali` ending in
// ".jar" is run through java; otherwise it is the smali wrapper executable.
std::vector<std::string> assembleArgv(const std::string& smali, const std::string& dir, const std::string& outDex);

// Runs the whole pipeline. Blocking: call it from a worker thread (the UI
// shows the log as it arrives through onLog).
Result run(const Options& options, const Tools& tools, std::function<void(const std::string&)> onLog = {},
           const std::function<bool()>& cancelled = {});

}  // namespace repack
