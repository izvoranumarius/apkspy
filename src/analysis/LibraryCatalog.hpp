#pragma once
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class ApkAnalysis;

// Known third-party libraries and frameworks, identified by the package
// prefixes of their classes. One table serves the behavior graph (calls into
// a library are a boundary, not code to walk) and Dependency Intelligence
// (what the app bundles, under which license).
namespace libcatalog {

struct Library {
    const char* id;        // stable key: "okhttp3", "firebase-messaging"
    const char* name;      // display name
    const char* category;  // "Networking", "Analytics", "Ads", "UI", ...
    const char* license;   // SPDX id when known ("Apache-2.0"), "" otherwise
    const char* url;       // project page
    std::vector<const char*> prefixes;  // descriptor prefixes: "Lokhttp3/"
    // Maven coordinates ("com.squareup.okhttp3:okhttp") used to match
    // META-INF/*.version files and vulnerability records; "" when none.
    const char* maven;
    // Native libraries that identify it (lib/<abi>/libflutter.so).
    std::vector<const char*> natives = {};
};

// Every library in the table (stable order).
const std::vector<Library>& all();
// The library a class descriptor belongs to (longest prefix wins), or nullptr.
const Library* forClass(std::string_view descriptor);
// The library with this id or Maven coordinate, or nullptr.
const Library* byId(std::string_view id);
// True for platform and runtime classes that are never bundled app code
// (java/, javax/, android/, dalvik/, kotlin/ ...) - also when not in the table.
bool isPlatformClass(std::string_view descriptor);

// A library found in an APK.
struct Detection {
    const Library* lib = nullptr;  // nullptr: known only from a version file
    std::string maven;             // coordinates ("group:artifact") when known
    size_t classes = 0;            // bundled classes attributed to it
    std::string version;           // from META-INF version files, "" when unknown
    std::string versionSource;     // the file the version came from
    std::vector<std::string> nativeLibs;  // lib/<abi>/*.so entries attributed to it
};

// Entries that carry library versions: META-INF/<group>_<artifact>.version
// (Gradle writes one per AndroidX / Kotlin / Firebase artifact) and
// META-INF/maven/<group>/<artifact>/pom.properties (plain Maven jars).
bool isVersionFile(std::string_view entryPath);
// Reads those entries through a private archive (any thread).
std::vector<std::pair<std::string, std::string>> readVersionFiles(const std::string& apkPath,
                                                                  const std::vector<std::string>& entryPaths);
// The library a native library file name belongs to ("libflutter.so"), or nullptr.
const Library* forNativeLibrary(std::string_view fileName);
// Libraries in `a` (nullptr = versions only), by class prefix, by version
// file and by native library. `versionFiles` holds (entry path, contents);
// `nativeEntries` the lib/<abi>/*.so paths. Sorted by name.
std::vector<Detection> detect(const ApkAnalysis* a, const std::vector<std::pair<std::string, std::string>>& versionFiles,
                              const std::vector<std::string>& nativeEntries = {});

}  // namespace libcatalog
