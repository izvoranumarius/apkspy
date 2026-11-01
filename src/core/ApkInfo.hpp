#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "core/RootKind.hpp"

struct Root;  // full definition in Workspace.hpp (included by the .cpp)

class Root;

// Structured facts about one APK (M4), extracted from the binary manifest
// and the signing data. Built by ApkInfo::extract on the UI thread: it reads
// through the APK root's ContentSource, which only the UI thread may use
// (ApkArchive is not thread-safe).
struct ApkComponent {
    std::string type;                   // activity / service / receiver / provider / activity-alias
    std::string name;                   // android:name as written in the manifest
    bool exported = false;              // android:exported
    std::vector<std::string> actions;    // intent-filter actions
    std::vector<std::string> categories; // intent-filter categories
};

struct ApkSigningInfo {
    std::string scheme;      // "v2", "v3" or "v1 (JAR)"
    std::string certSha256;  // lowercase hex SHA-256 of the first certificate
    std::string subject;     // certificate subject CN ("" when absent)
    std::string issuer;      // certificate issuer CN ("" when absent)
};

struct ApkInfo {
    bool ok = false;  // manifest decoded
    std::string packageName;
    std::string versionName;
    std::string versionCode;
    std::string minSdk;
    std::string targetSdk;
    std::string appLabel;   // android:label of <application> (may be a @ref/... resource id)
    std::string appIcon;    // android:icon (resource reference)
    bool debuggable = false;
    bool allowBackup = false;
    std::vector<std::string> permissions;  // uses-permission android:name values
    std::vector<ApkComponent> components;
    std::vector<ApkSigningInfo> signatures;
    std::string manifestPath;  // zip entry path of AndroidManifest.xml

    // Reads the manifest and the signing data of one APK root. UI thread
    // only (see class comment). Never throws; failures leave the fields empty.
    static ApkInfo extract(Root& apkRoot);

    // Fingerprint + subject/issuer CN of one raw X.509 certificate DER.
    // Exposed for the headless tests.
    static ApkSigningInfo describeCertificate(const uint8_t* der, size_t len, const char* scheme);

    // Parses an APK Signing Block (v2 0x7109871a / v3 0xf05368c0) out of raw
    // APK file bytes. `bufferOffset` is the absolute file offset of
    // buffer[0] (0 = whole file), so a tail read works as well as a full
    // read. Exposed for the headless tests; extract() uses it internally.
    static bool parseSigningBlock(const std::vector<uint8_t>& buffer, uint64_t bufferOffset,
                                  std::vector<ApkSigningInfo>& out);
};
