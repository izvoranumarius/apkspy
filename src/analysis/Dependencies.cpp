#include "analysis/Dependencies.hpp"
#include <algorithm>
#include <set>

namespace deps {

LicenseKind licenseKind(std::string_view s) {
    if (s.empty()) return LicenseKind::Unknown;
    if (s.find("Proprietary") != std::string_view::npos) return LicenseKind::Proprietary;
    if (s.find("classpath-exception") != std::string_view::npos || s.find("LGPL") != std::string_view::npos ||
        s.find("MPL") != std::string_view::npos || s.find("EPL") != std::string_view::npos)
        return LicenseKind::WeakCopyleft;
    if (s.find("GPL") != std::string_view::npos) return LicenseKind::Copyleft;
    return LicenseKind::Permissive;
}

const char* licenseKindName(LicenseKind k) {
    switch (k) {
    case LicenseKind::Permissive: return "Permissive";
    case LicenseKind::WeakCopyleft: return "Weak copyleft";
    case LicenseKind::Copyleft: return "Copyleft";
    case LicenseKind::Proprietary: return "Proprietary";
    case LicenseKind::Unknown: return "Unknown";
    }
    return "?";
}

namespace {
int severityRank(const std::string& s) {
    if (s == "Critical") return 4;
    if (s == "High") return 3;
    if (s == "Medium") return 2;
    if (s == "Low") return 1;
    return 0;
}
}  // namespace

int worstSeverity(const Dependency& d) {
    int worst = 0;
    for (const auto& v : d.vulnerabilities) worst = std::max(worst, severityRank(v.severity));
    return worst;
}

Report analyze(const ApkAnalysis* a, const std::string& apkPath, const std::vector<std::string>& entryPaths, const vulndb::Database& db,
               const std::string& databaseNote) {
    Report r;
    r.databaseNote = databaseNote;
    std::vector<std::string> natives;
    for (const std::string& p : entryPaths)
        if (p.rfind("lib/", 0) == 0 && p.size() > 3 && p.compare(p.size() - 3, 3, ".so") == 0) natives.push_back(p);
    const auto versionFiles = libcatalog::readVersionFiles(apkPath, entryPaths);
    const std::vector<libcatalog::Detection> found = libcatalog::detect(a, versionFiles, natives);
    if (a) r.totalClasses = a->classes().size();
    std::set<std::string> claimed;
    for (const libcatalog::Detection& d : found) {
        Dependency dep;
        if (d.lib) {
            dep.name = d.lib->name;
            dep.id = d.lib->id;
            dep.category = d.lib->category;
            dep.license = d.lib->license;
            dep.url = d.lib->url;
            for (const char* p : d.lib->prefixes) {
                std::string pkg(p);  // "Lokhttp3/" -> "okhttp3."
                if (!pkg.empty() && pkg[0] == 'L') pkg.erase(0, 1);
                std::replace(pkg.begin(), pkg.end(), '/', '.');
                dep.prefixes.push_back(std::move(pkg));
            }
        } else {
            dep.name = d.maven;
            dep.category = "Library";
        }
        dep.maven = d.maven;
        dep.licenseKind = licenseKind(dep.license);
        dep.version = d.version;
        dep.versionSource = d.versionSource;
        dep.classes = d.classes;
        dep.nativeLibs = d.nativeLibs;
        for (const std::string& n : d.nativeLibs) claimed.insert(n.substr(n.find_last_of('/') + 1));
        r.libraryClasses += d.classes;
        if (!dep.maven.empty()) {
            if (!dep.version.empty())
                for (const vulndb::Vulnerability* v : db.affecting(dep.maven, dep.version)) dep.vulnerabilities.push_back(*v);
            else
                dep.advisoriesAnyVersion = db.affecting(dep.maven, {}).size();
        }
        r.dependencies.push_back(std::move(dep));
    }
    std::set<std::string> unclaimed;
    for (const std::string& n : natives) {
        const std::string file = n.substr(n.find_last_of('/') + 1);
        if (!claimed.count(file)) unclaimed.insert(file);
    }
    r.unidentifiedNative.assign(unclaimed.begin(), unclaimed.end());
    std::stable_sort(r.dependencies.begin(), r.dependencies.end(), [](const Dependency& x, const Dependency& y) {
        const int sx = worstSeverity(x), sy = worstSeverity(y);
        if (sx != sy) return sx > sy;
        if (x.vulnerabilities.size() != y.vulnerabilities.size()) return x.vulnerabilities.size() > y.vulnerabilities.size();
        return x.classes > y.classes;
    });
    return r;
}

}  // namespace deps
