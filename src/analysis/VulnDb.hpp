#pragma once
#include <string>
#include <string_view>
#include <vector>

// Known vulnerabilities of bundled libraries, by Maven coordinates and
// version range (OSV semantics: introduced <= v < fixed, or v <= last
// affected). A curated database ships with ApkSpy; "Update" runs a small
// Python script that asks OSV.dev (osv.dev, which aggregates the GitHub
// Security Advisories and NVD for Maven) about the libraries found in the
// APK and merges the answers into vulndb.json in the config directory, which
// is loaded instead of the built-in data from then on.
namespace vulndb {

struct Range {
    std::string introduced;    // "0" = from the first version
    std::string fixed;         // "" = no fixed version
    std::string lastAffected;  // alternative upper bound (inclusive)
};

struct Vulnerability {
    std::string id;       // CVE-2022-25647, GHSA-...
    std::string package;  // Maven coordinates: com.google.code.gson:gson
    std::string severity; // Critical, High, Medium, Low
    std::string summary;
    std::string url;
    std::vector<Range> ranges;
};

class Database {
public:
    // The curated data compiled into ApkSpy.
    static Database builtin();
    // Parses a database file (format "apkspy-vulndb-1"); false with a reason on error.
    bool loadText(std::string_view json, std::string& error);
    bool loadFile(const std::string& path, std::string& error);
    std::string toJson() const;

    // Advisories of a package affecting `version`; with an empty version,
    // every advisory of the package (the caller says the version is unknown).
    std::vector<const Vulnerability*> affecting(std::string_view package, std::string_view version) const;
    // Adds or replaces (same id and package) advisories.
    void merge(const Database& other);

    const std::vector<Vulnerability>& all() const { return vulns_; }
    const std::string& updated() const { return updated_; }
    const std::string& source() const { return source_; }

private:
    std::vector<Vulnerability> vulns_;
    std::string updated_;
    std::string source_;
};

// Maven-style version ordering: numeric parts compare as numbers, and
// alpha < beta < milestone < rc < snapshot < release < sp. <0, 0, >0.
int compareVersions(std::string_view a, std::string_view b);
bool inRange(std::string_view version, const Range& r);

// Where the updated database lives (config dir / vulndb.json).
std::string userDatabasePath();
// The database to use: the user's file when present and valid, else the built-in one.
Database loadPreferred(std::string* note = nullptr);

// Python source of the updater: `updater.py <packages.json> <vulndb.json>`.
// packages.json is [{"package": "g:a", "version": "1.2"}, ...].
const char* updaterScript();

}  // namespace vulndb
