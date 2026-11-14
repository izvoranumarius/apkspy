#pragma once
#include <string_view>
#include <vector>

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

}  // namespace libcatalog
