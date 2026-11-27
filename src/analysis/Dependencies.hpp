#pragma once
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/LibraryCatalog.hpp"
#include "analysis/VulnDb.hpp"

// Dependency Intelligence: the libraries and frameworks an APK bundles
// (LibraryCatalog: class prefixes, META-INF version files, native
// libraries), their versions and licenses, and the known vulnerabilities of
// those versions (VulnDb). Plain data, built on a worker.
namespace deps {

enum class LicenseKind : uint8_t { Permissive, WeakCopyleft, Copyleft, Proprietary, Unknown };
LicenseKind licenseKind(std::string_view spdx);
const char* licenseKindName(LicenseKind k);

struct Dependency {
    std::string name;      // display name, or Maven coordinates for uncatalogued artifacts
    std::string id;        // catalogue id ("" when uncatalogued)
    std::string maven;
    std::string category;  // "Networking", "Ads"... ("Library" when uncatalogued)
    std::string license;   // SPDX id, "Proprietary" or ""
    LicenseKind licenseKind = LicenseKind::Unknown;
    std::string url;
    std::string version;   // "" = unknown
    std::string versionSource;
    size_t classes = 0;
    std::vector<std::string> prefixes;    // package prefixes (Java form: "okhttp3.")
    std::vector<std::string> nativeLibs;
    std::vector<vulndb::Vulnerability> vulnerabilities;  // affecting this version
    size_t advisoriesAnyVersion = 0;  // version unknown: advisories that affect some version
};

struct Report {
    std::vector<Dependency> dependencies;  // most vulnerable first, then by size
    std::vector<std::string> unidentifiedNative;  // lib/<abi>/*.so nobody claims (unique file names)
    size_t totalClasses = 0;
    size_t libraryClasses = 0;
    std::string databaseNote;  // which vulnerability data was used
};

// `entryPaths`: every archive entry (version files and native libraries are
// taken from it); the version files are read through a private archive.
Report analyze(const ApkAnalysis* a, const std::string& apkPath, const std::vector<std::string>& entryPaths,
               const vulndb::Database& db, const std::string& databaseNote = {});

// Worst severity among a dependency's vulnerabilities (0 none .. 4 critical).
int worstSeverity(const Dependency& d);

}  // namespace deps
