#include "analysis/VulnDb.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "core/Paths.hpp"
#include "mcp/Json.hpp"

namespace vulndb {
namespace {

// Curated advisories for libraries Android apps commonly bundle. Each entry
// follows the corresponding OSV / GitHub Security Advisory record; Update
// replaces and extends this with live data.
constexpr const char* kBuiltin = R"JSON({
  "format": "apkspy-vulndb-1",
  "updated": "built-in",
  "source": "Curated from OSV.dev / GitHub Security Advisories. Use Update to fetch current data.",
  "vulnerabilities": [
    {"id": "CVE-2021-44228", "package": "org.apache.logging.log4j:log4j-core", "severity": "Critical",
     "summary": "Remote code execution through JNDI lookups in logged data (Log4Shell)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
     "ranges": [{"introduced": "2.0-beta9", "fixed": "2.3.1"}, {"introduced": "2.4", "fixed": "2.12.2"}, {"introduced": "2.13.0", "fixed": "2.15.0"}]},
    {"id": "CVE-2021-45046", "package": "org.apache.logging.log4j:log4j-core", "severity": "Critical",
     "summary": "Incomplete fix of Log4Shell: code execution in non-default configurations",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
     "ranges": [{"introduced": "2.0-beta9", "fixed": "2.3.1"}, {"introduced": "2.4", "fixed": "2.12.2"}, {"introduced": "2.13.0", "fixed": "2.16.0"}]},
    {"id": "CVE-2019-17571", "package": "log4j:log4j", "severity": "Critical",
     "summary": "SocketServer deserializes untrusted data (remote code execution); Log4j 1.x is end of life",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-17571",
     "ranges": [{"introduced": "1.2", "last_affected": "1.2.17"}]},
    {"id": "CVE-2022-42889", "package": "org.apache.commons:commons-text", "severity": "Critical",
     "summary": "Remote code execution through variable interpolation in StringSubstitutor (Text4Shell)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-42889",
     "ranges": [{"introduced": "1.5", "fixed": "1.10.0"}]},
    {"id": "CVE-2015-7501", "package": "commons-collections:commons-collections", "severity": "Critical",
     "summary": "Remote code execution when deserializing untrusted data (InvokerTransformer)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-7501",
     "ranges": [{"introduced": "0", "fixed": "3.2.2"}]},
    {"id": "CVE-2022-1471", "package": "org.yaml:snakeyaml", "severity": "High",
     "summary": "Remote code execution: the default Constructor instantiates arbitrary types from untrusted YAML",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-1471",
     "ranges": [{"introduced": "0", "fixed": "2.0"}]},
    {"id": "CVE-2022-25857", "package": "org.yaml:snakeyaml", "severity": "High",
     "summary": "Denial of service through deeply nested collections",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25857",
     "ranges": [{"introduced": "0", "fixed": "1.31"}]},
    {"id": "CVE-2022-25845", "package": "com.alibaba:fastjson", "severity": "Critical",
     "summary": "AutoType check bypass leading to remote code execution when parsing untrusted JSON",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25845",
     "ranges": [{"introduced": "0", "fixed": "1.2.83"}]},
    {"id": "CVE-2022-25647", "package": "com.google.code.gson:gson", "severity": "High",
     "summary": "Deserializing untrusted data can exhaust memory (denial of service)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25647",
     "ranges": [{"introduced": "0", "fixed": "2.8.9"}]},
    {"id": "CVE-2020-36518", "package": "com.fasterxml.jackson.core:jackson-databind", "severity": "High",
     "summary": "Stack overflow through deeply nested objects (denial of service)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-36518",
     "ranges": [{"introduced": "0", "fixed": "2.12.6.1"}, {"introduced": "2.13.0", "fixed": "2.13.2.1"}]},
    {"id": "CVE-2021-39144", "package": "com.thoughtworks.xstream:xstream", "severity": "High",
     "summary": "Remote code execution when unmarshalling untrusted XML",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-39144",
     "ranges": [{"introduced": "0", "fixed": "1.4.18"}]},
    {"id": "CVE-2020-28052", "package": "org.bouncycastle:bcprov-jdk15on", "severity": "Critical",
     "summary": "OpenBSDBCrypt.checkPassword accepts some wrong passwords",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28052",
     "ranges": [{"introduced": "1.65", "fixed": "1.67"}]},
    {"id": "CVE-2021-37714", "package": "org.jsoup:jsoup", "severity": "High",
     "summary": "Crafted input makes the parser loop or use excessive memory (denial of service)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-37714",
     "ranges": [{"introduced": "0", "fixed": "1.14.2"}]},
    {"id": "CVE-2022-36033", "package": "org.jsoup:jsoup", "severity": "Medium",
     "summary": "Cross-site scripting: the HTML cleaner can keep javascript: URLs",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-36033",
     "ranges": [{"introduced": "0", "fixed": "1.15.3"}]},
    {"id": "CVE-2020-13956", "package": "org.apache.httpcomponents:httpclient", "severity": "Medium",
     "summary": "A malformed authority in a request URI can send the request to the wrong host",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-13956",
     "ranges": [{"introduced": "0", "fixed": "4.5.13"}]},
    {"id": "CVE-2018-1000850", "package": "com.squareup.retrofit2:retrofit", "severity": "High",
     "summary": "Path traversal through @Path parameters in RequestBuilder",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-1000850",
     "ranges": [{"introduced": "2.0.0", "fixed": "2.5.0"}]},
    {"id": "CVE-2018-10237", "package": "com.google.guava:guava", "severity": "Medium",
     "summary": "Unbounded memory allocation when deserializing AtomicDoubleArray or CompoundOrdering",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-10237",
     "ranges": [{"introduced": "11.0", "fixed": "24.1.1"}]},
    {"id": "CVE-2023-2976", "package": "com.google.guava:guava", "severity": "High",
     "summary": "FileBackedOutputStream creates temporary files readable by other users",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-2976",
     "ranges": [{"introduced": "1.0", "fixed": "32.0.0"}]},
    {"id": "CVE-2020-8908", "package": "com.google.guava:guava", "severity": "Low",
     "summary": "Files.createTempDir creates directories readable by other users",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8908",
     "ranges": [{"introduced": "0", "fixed": "32.0.0"}]},
    {"id": "CVE-2022-3171", "package": "com.google.protobuf:protobuf-javalite", "severity": "High",
     "summary": "Crafted messages cause long garbage collection pauses while parsing (denial of service)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-3171",
     "ranges": [{"introduced": "0", "fixed": "3.16.3"}, {"introduced": "3.17.0", "fixed": "3.19.6"}, {"introduced": "3.20.0", "fixed": "3.20.3"}, {"introduced": "3.21.0", "fixed": "3.21.7"}]},
    {"id": "CVE-2022-3171", "package": "com.google.protobuf:protobuf-java", "severity": "High",
     "summary": "Crafted messages cause long garbage collection pauses while parsing (denial of service)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-3171",
     "ranges": [{"introduced": "0", "fixed": "3.16.3"}, {"introduced": "3.17.0", "fixed": "3.19.6"}, {"introduced": "3.20.0", "fixed": "3.20.3"}, {"introduced": "3.21.0", "fixed": "3.21.7"}]},
    {"id": "CVE-2023-3635", "package": "com.squareup.okio:okio", "severity": "Medium",
     "summary": "GzipSource throws on a crafted header (denial of service when reading untrusted data)",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-3635",
     "ranges": [{"introduced": "0", "fixed": "1.17.6"}, {"introduced": "2.0.0", "fixed": "3.4.0"}]},
    {"id": "CVE-2021-29425", "package": "commons-io:commons-io", "severity": "Medium",
     "summary": "Path traversal in FileNameUtils.normalize",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-29425",
     "ranges": [{"introduced": "0", "fixed": "2.7"}]}
  ]
})JSON";

// One item of a version: a number, or a qualifier ranked like Maven does.
struct Item {
    bool number = true;
    unsigned long long n = 0;
    int rank = 0;      // qualifiers: alpha 1, beta 2, milestone 3, rc 4, (other) 5, snapshot 6, release 7, sp 8
    std::string text;  // unknown qualifiers compare by text
};

int qualifierRank(const std::string& q) {
    if (q == "alpha" || q == "a") return 1;
    if (q == "beta" || q == "b") return 2;
    if (q == "milestone" || q == "m") return 3;
    if (q == "rc" || q == "cr") return 4;
    if (q == "snapshot") return 6;
    if (q.empty() || q == "ga" || q == "final" || q == "release") return 7;
    if (q == "sp") return 8;
    return 5;
}

std::vector<Item> items(std::string_view v) {
    std::vector<Item> out;
    std::string cur;
    bool digits = false;
    const auto flush = [&] {
        if (cur.empty()) return;
        Item it;
        if (digits) {
            it.n = std::strtoull(cur.c_str(), nullptr, 10);
        } else {
            it.number = false;
            std::transform(cur.begin(), cur.end(), cur.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            it.rank = qualifierRank(cur);
            it.text = cur;
        }
        out.push_back(std::move(it));
        cur.clear();
    };
    for (char c : v) {
        if (c == '.' || c == '-' || c == '_' || c == '+') {
            flush();
            continue;
        }
        const bool d = std::isdigit(static_cast<unsigned char>(c)) != 0;
        if (!cur.empty() && d != digits) flush();
        digits = d;
        cur += c;
    }
    flush();
    // Trailing zeros and release markers do not change the version: 1.0 == 1.0.0 == 1.0-final.
    while (!out.empty() && ((out.back().number && out.back().n == 0) || (!out.back().number && out.back().rank == 7))) out.pop_back();
    return out;
}

int compareItem(const Item* a, const Item* b) {
    // A missing item is a release (0 for numbers).
    static const Item kRelease{false, 0, 7, ""};
    static const Item kZero{true, 0, 0, ""};
    if (!a) a = b && b->number ? &kZero : &kRelease;
    if (!b) b = a->number ? &kZero : &kRelease;
    if (a->number && b->number) return a->n < b->n ? -1 : a->n > b->n ? 1 : 0;
    if (a->number != b->number) {
        // 1.0.1 > 1.0-rc1: a number beats a qualifier, except sp (service pack) which follows releases.
        const Item& q = a->number ? *b : *a;
        const int numberWins = q.rank >= 8 ? -1 : 1;
        return a->number ? numberWins : -numberWins;
    }
    if (a->rank != b->rank) return a->rank < b->rank ? -1 : 1;
    return a->text < b->text ? -1 : a->text > b->text ? 1 : 0;
}

}  // namespace

int compareVersions(std::string_view a, std::string_view b) {
    const std::vector<Item> x = items(a), y = items(b);
    for (size_t i = 0; i < std::max(x.size(), y.size()); ++i) {
        const int c = compareItem(i < x.size() ? &x[i] : nullptr, i < y.size() ? &y[i] : nullptr);
        if (c) return c;
    }
    return 0;
}

bool inRange(std::string_view v, const Range& r) {
    if (!r.introduced.empty() && r.introduced != "0" && compareVersions(v, r.introduced) < 0) return false;
    if (!r.fixed.empty()) return compareVersions(v, r.fixed) < 0;
    if (!r.lastAffected.empty()) return compareVersions(v, r.lastAffected) <= 0;
    return true;
}

Database Database::builtin() {
    Database db;
    std::string error;
    db.loadText(kBuiltin, error);
    return db;
}

bool Database::loadText(std::string_view text, std::string& error) {
    Json root;
    if (!Json::parse(text, root, &error)) return false;
    if (root.get("format").asString("") != "apkspy-vulndb-1") {
        error = "not an ApkSpy vulnerability database (format apkspy-vulndb-1)";
        return false;
    }
    vulns_.clear();
    updated_ = root.get("updated").asString("");
    source_ = root.get("source").asString("");
    const Json& list = root.get("vulnerabilities");
    for (size_t i = 0; i < list.size(); ++i) {
        const Json& v = list[i];
        Vulnerability out;
        out.id = v.get("id").asString("");
        out.package = v.get("package").asString("");
        out.severity = v.get("severity").asString("Medium");
        out.summary = v.get("summary").asString("");
        out.url = v.get("url").asString("");
        const Json& ranges = v.get("ranges");
        for (size_t k = 0; k < ranges.size(); ++k)
            out.ranges.push_back({ranges[k].get("introduced").asString("0"), ranges[k].get("fixed").asString(""),
                                  ranges[k].get("last_affected").asString("")});
        if (!out.id.empty() && !out.package.empty()) vulns_.push_back(std::move(out));
    }
    return true;
}

bool Database::loadFile(const std::string& path, std::string& error) {
    std::ifstream in(pathutil::fromUtf8(path), std::ios::binary);
    if (!in) {
        error = "cannot read " + path;
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return loadText(ss.str(), error);
}

std::string Database::toJson() const {
    Json list = Json::array();
    for (const Vulnerability& v : vulns_) {
        Json ranges = Json::array();
        for (const Range& r : v.ranges) {
            Json j = Json::obj({{"introduced", r.introduced}});
            if (!r.fixed.empty()) j.set("fixed", r.fixed);
            if (!r.lastAffected.empty()) j.set("last_affected", r.lastAffected);
            ranges.push(std::move(j));
        }
        list.push(Json::obj({{"id", v.id}, {"package", v.package}, {"severity", v.severity}, {"summary", v.summary}, {"url", v.url},
                             {"ranges", std::move(ranges)}}));
    }
    return Json::obj({{"format", "apkspy-vulndb-1"}, {"updated", updated_}, {"source", source_}, {"vulnerabilities", std::move(list)}}).dump();
}

std::vector<const Vulnerability*> Database::affecting(std::string_view package, std::string_view version) const {
    std::vector<const Vulnerability*> out;
    for (const Vulnerability& v : vulns_) {
        if (v.package != package) continue;
        if (version.empty() || std::any_of(v.ranges.begin(), v.ranges.end(), [&](const Range& r) { return inRange(version, r); }))
            out.push_back(&v);
    }
    return out;
}

void Database::merge(const Database& other) {
    for (const Vulnerability& v : other.vulns_) {
        auto it = std::find_if(vulns_.begin(), vulns_.end(), [&](const Vulnerability& x) { return x.id == v.id && x.package == v.package; });
        if (it != vulns_.end()) *it = v;
        else vulns_.push_back(v);
    }
    if (!other.updated_.empty()) updated_ = other.updated_;
    if (!other.source_.empty()) source_ = other.source_;
}

std::string userDatabasePath() { return pathutil::configFile("vulndb.json"); }

Database loadPreferred(std::string* note) {
    std::error_code ec;
    const std::string path = userDatabasePath();
    if (std::filesystem::exists(pathutil::fromUtf8(path), ec)) {
        Database db;
        std::string error;
        if (db.loadFile(path, error)) {
            // The user's file extends the built-in data; its entries win.
            Database merged = Database::builtin();
            merged.merge(db);
            if (note) *note = "updated " + db.updated();
            return merged;
        }
        if (note) *note = "vulndb.json ignored: " + error;
        return Database::builtin();
    }
    if (note) *note = "built-in data (run Update for current advisories)";
    return Database::builtin();
}

const char* updaterScript() {
    return R"PY(# ApkSpy vulnerability database updater (generated - safe to delete).
# Asks OSV.dev about each library and merges the advisories into the database.
import json, sys, time, urllib.request, urllib.error
from datetime import date

API = "https://api.osv.dev/v1"

def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)

def severity_of(v, affected):
    for src in (affected.get("database_specific") or {}, v.get("database_specific") or {}):
        s = str(src.get("severity", "")).upper()
        if s in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
            return {"MODERATE": "Medium", "MEDIUM": "Medium"}.get(s, s.capitalize())
    return "Medium"

def main():
    packages = json.load(open(sys.argv[1], encoding="utf-8"))
    out_path = sys.argv[2]
    try:
        db = json.load(open(out_path, encoding="utf-8"))
    except (OSError, ValueError):
        db = {"vulnerabilities": []}
    queries = []
    for p in packages:
        q = {"package": {"ecosystem": "Maven", "name": p["package"]}}
        if p.get("version"):
            q["version"] = p["version"]
        queries.append(q)
    print(f"Querying OSV.dev for {len(queries)} libraries...", flush=True)
    ids = {}
    for start in range(0, len(queries), 100):
        batch = queries[start:start + 100]
        res = post(API + "/querybatch", {"queries": batch})
        for q, r in zip(batch, res.get("results", [])):
            for v in r.get("vulns", []) or []:
                ids.setdefault(v["id"], set()).add(q["package"]["name"])
    print(f"{len(ids)} advisories to fetch", flush=True)
    found = {}  # (id, package) -> record; OSV lists one "affected" block per range
    for i, (vid, names) in enumerate(sorted(ids.items())):
        try:
            v = get(f"{API}/vulns/{vid}")
        except urllib.error.URLError as e:
            print(f"  {vid}: {e}", flush=True)
            continue
        aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        shown = aliases[0] if aliases else vid
        refs = v.get("references") or []
        url = refs[0]["url"] if refs else f"https://osv.dev/vulnerability/{vid}"
        for a in v.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("ecosystem") != "Maven" or pkg.get("name") not in names:
                continue
            ranges = []
            for r in a.get("ranges", []):
                if r.get("type") != "ECOSYSTEM":
                    continue
                cur = {}
                for ev in r.get("events", []):
                    if "introduced" in ev:
                        if cur:
                            ranges.append(cur)
                        cur = {"introduced": ev["introduced"]}
                    elif "fixed" in ev:
                        cur["fixed"] = ev["fixed"]
                        ranges.append(cur)
                        cur = {}
                    elif "last_affected" in ev:
                        cur["last_affected"] = ev["last_affected"]
                        ranges.append(cur)
                        cur = {}
                if cur:
                    ranges.append(cur)
            if not ranges:
                continue
            key = (shown, pkg["name"])
            if key in found:
                found[key]["ranges"].extend(r for r in ranges if r not in found[key]["ranges"])
            else:
                found[key] = {"id": shown, "package": pkg["name"], "severity": severity_of(v, a),
                              "summary": (v.get("summary") or v.get("details", "")[:200]).strip(), "url": url, "ranges": ranges}
        print(f"  [{i + 1}/{len(ids)}] {shown}", flush=True)
        time.sleep(0.05)
    merged = {(x["id"], x["package"]): x for x in db.get("vulnerabilities", [])}
    for key, x in found.items():
        merged[key] = x
    db = {"format": "apkspy-vulndb-1", "updated": date.today().isoformat(),
          "source": "OSV.dev (GitHub Security Advisories, NVD)", "vulnerabilities": list(merged.values())}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=1)
    print(f"Wrote {len(db['vulnerabilities'])} advisories to {out_path}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as e:
        print(f"Network error: {e}. Is the machine online?", flush=True)
        sys.exit(2)
)PY";
}

}  // namespace vulndb
