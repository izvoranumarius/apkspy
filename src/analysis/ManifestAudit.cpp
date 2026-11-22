#include "analysis/ManifestAudit.hpp"
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <utility>
#include "core/ApkArchive.hpp"
#include "core/AxmlDecoder.hpp"
#include "core/ResourceTable.hpp"

namespace manifestaudit {
namespace {

// Protection levels of the platform permissions commonly seen in manifests.
// A curated set, not a dump: the audited app may target any SDK, and an
// unknown name is simply not classified (never guessed).
const std::set<std::string>& dangerousPermissions() {
    static const std::set<std::string> k = {
        "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
        "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "ADD_VOICEMAIL", "USE_SIP", "ANSWER_PHONE_CALLS", "BODY_SENSORS", "SEND_SMS",
        "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION", "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS", "BLUETOOTH_CONNECT",
        "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES",
    };
    return k;
}

std::string shortPermission(const std::string& p) {
    const size_t dot = p.rfind('.');
    return dot == std::string::npos ? p : p.substr(dot + 1);
}

int toInt(const std::string& s) {
    try {
        return std::stoi(s);
    } catch (...) {
        return 0;
    }
}

bool toBool(const std::string& s) { return s == "true"; }

// Collects the manifest with a Visitor. Elements nest, so a small stack of
// open tags tracks the component we are inside (application > activity...).
class ManifestCollector : public AxmlDecoder::Visitor {
public:
    explicit ManifestCollector(Audit& a) : audit_(a) {}

    void startElement(const std::string& name, const std::vector<AxmlDecoder::Attr>& attrs) override {
        std::map<std::string, std::string> m;
        for (const auto& at : attrs) m[at.name] = at.value;
        auto get = [&m](const char* key) {
            auto it = m.find(key);
            return it == m.end() ? std::string() : it->second;
        };

        if (name == "manifest") {
            audit_.package = get("package");
            audit_.versionCode = toInt(get("android:versionCode"));
            audit_.versionName = get("android:versionName");
        } else if (name == "uses-sdk") {
            audit_.minSdk = toInt(get("android:minSdkVersion"));
            audit_.targetSdk = toInt(get("android:targetSdkVersion"));
        } else if (name == "uses-permission" || name == "uses-permission-sdk-23") {
            const std::string p = get("android:name");
            if (!p.empty()) audit_.permissions.push_back(p);
        } else if (name == "application") {
            audit_.appLabel = get("android:label");
            audit_.allowBackup = toBool(get("android:allowBackup"));
            audit_.debuggable = toBool(get("android:debuggable"));
            audit_.testOnly = toBool(get("android:testOnly"));
            audit_.usesCleartext = toBool(get("android:usesCleartextTraffic"));
            audit_.networkSecurityConfig = get("android:networkSecurityConfig");
        } else if (name == "activity" || name == "activity-alias" || name == "service" ||
                   name == "receiver" || name == "provider") {
            Component c;
            if (name == "service") c.kind = Component::Kind::Service;
            else if (name == "receiver") c.kind = Component::Kind::Receiver;
            else if (name == "provider") c.kind = Component::Kind::Provider;
            c.name = get("android:name");
            c.exported = toBool(get("android:exported"));
            c.permission = get("android:permission");
            audit_.components.push_back(std::move(c));
            openComponent_ = static_cast<int>(audit_.components.size()) - 1;
            declaredExported_ = m.count("android:exported") > 0;
            hasFilter_ = false;
        } else if (name == "intent-filter" && openComponent_ >= 0) {
            inIntentFilter_ = true;
            hasFilter_ = true;
            filterView_ = filterBrowsable_ = false;
            filterAutoVerify_ = toBool(get("android:autoVerify"));
            filterData_.clear();
        } else if (name == "action" && inIntentFilter_ && openComponent_ >= 0) {
            const std::string a = get("android:name");
            audit_.components[static_cast<size_t>(openComponent_)].intentActions.push_back(a);
            if (a == "android.intent.action.VIEW") filterView_ = true;
        } else if (name == "category" && inIntentFilter_) {
            if (get("android:name") == "android.intent.category.BROWSABLE") filterBrowsable_ = true;
        } else if (name == "data" && inIntentFilter_) {
            filterData_.push_back({get("android:scheme"), get("android:host"), get("android:port"),
                                   [&] {
                                       const std::string p = get("android:path");
                                       if (!p.empty()) return p;
                                       const std::string pp = get("android:pathPrefix");
                                       if (!pp.empty()) return pp;
                                       return get("android:pathPattern");
                                   }()});
        }
    }

    void endElement(const std::string& name) override {
        if (name == "intent-filter") {
            inIntentFilter_ = false;
            // A browsable VIEW filter with a URI scheme is a deep link.
            if (filterView_ && filterBrowsable_ && openComponent_ >= 0) {
                const std::string comp = audit_.components[static_cast<size_t>(openComponent_)].name;
                for (const Data& d : filterData_) {
                    if (d.scheme.empty()) continue;
                    std::string uri = d.scheme + "://";
                    uri += d.host.empty() ? "" : d.host;
                    if (!d.port.empty()) uri += ":" + d.port;
                    uri += d.path;
                    audit_.deepLinks.push_back({comp, uri, filterAutoVerify_});
                }
            }
        }
        if (!(name == "activity" || name == "activity-alias" || name == "service" ||
              name == "receiver" || name == "provider"))
            return;
        // android:exported is authoritative from targetSdk 31; before that a
        // component with an intent filter was implicitly exported - exactly
        // the trap the audit should flag.
        if (openComponent_ >= 0 && !declaredExported_ && hasFilter_ && audit_.targetSdk < 31)
            audit_.components[static_cast<size_t>(openComponent_)].exported = true;
        openComponent_ = -1;
        hasFilter_ = false;
        declaredExported_ = false;
    }

private:
    Audit& audit_;
    int openComponent_ = -1;
    bool inIntentFilter_ = false;
    bool hasFilter_ = false;
    bool declaredExported_ = false;
    // Deep-link detection, reset per intent-filter.
    bool filterView_ = false;
    bool filterBrowsable_ = false;
    bool filterAutoVerify_ = false;
    struct Data {
        std::string scheme, host, port, path;
    };
    std::vector<Data> filterData_;
};

void addFinding(Audit& a, Severity sev, std::string masvs, std::string title, std::string detail,
                std::string location) {
    a.findings.push_back(Finding{sev, std::move(masvs), std::move(title), std::move(detail), std::move(location)});
}

void evaluate(Audit& a) {
    // Deduplicate permissions (manifest can repeat them).
    std::sort(a.permissions.begin(), a.permissions.end());
    a.permissions.erase(std::unique(a.permissions.begin(), a.permissions.end()), a.permissions.end());
    for (const auto& p : a.permissions)
        if (isDangerousPermission(p)) a.dangerousPermissions.push_back(p);

    if (a.debuggable)
        addFinding(a, Severity::High, "MASVS-RESILIENCE-2", "Application is debuggable",
                   "android:debuggable=\"true\" lets any process attach a debugger and dump memory.",
                   "application@android:debuggable");
    if (a.allowBackup)
        addFinding(a, Severity::Medium, "MASVS-STORAGE-1", "Backups allowed",
                   "android:allowBackup=\"true\" lets adb backup extract the app's private data.",
                   "application@android:allowBackup");
    if (a.usesCleartext)
        addFinding(a, Severity::Medium, "MASVS-NETWORK-1", "Cleartext traffic allowed",
                   "android:usesCleartextTraffic=\"true\" permits plain HTTP for all hosts.",
                   "application@android:usesCleartextTraffic");
    if (a.networkSecurityConfig.empty() && a.targetSdk >= 28)
        addFinding(a, Severity::Low, "MASVS-NETWORK-2", "No network security config",
                   "No pinning / trust restrictions are declared; user CAs are trusted only where "
                   "the platform default allows it.",
                   "application@android:networkSecurityConfig");
    if (a.testOnly)
        addFinding(a, Severity::Info, "MASVS-RESILIENCE-2", "Test-only build",
                   "android:testOnly=\"true\" marks this as a test artifact.", "application@android:testOnly");

    for (const auto& c : a.components) {
        const std::string where = std::string(Component::kindName(c.kind)) + " " + c.name;
        if (c.exported && c.permission.empty())
            addFinding(a, Severity::High, "MASVS-PLATFORM-1", "Exported component without permission",
                       where + " is exported and any app can start it.", where);
        else if (c.exported)
            addFinding(a, Severity::Low, "MASVS-PLATFORM-1", "Exported component",
                       where + " is exported (guarded by \"" + c.permission + "\").", where);
    }
}

}  // namespace

const char* severityName(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

const char* Component::kindName(Kind k) {
    switch (k) {
        case Kind::Activity: return "activity";
        case Kind::Service: return "service";
        case Kind::Receiver: return "receiver";
        case Kind::Provider: return "provider";
    }
    return "component";
}

bool isDangerousPermission(const std::string& name) {
    if (name.rfind("android.permission.", 0) != 0) return false;
    return dangerousPermissions().count(shortPermission(name)) > 0;
}

bool audit(const ApkArchive& apk, const ResourceTable* resources, Audit& out, std::string& error) {
    out = Audit{};
    std::vector<uint8_t> manifest;
    if (!apk.readEntry("AndroidManifest.xml", manifest)) {
        error = "AndroidManifest.xml not found";
        return false;
    }
    if (!AxmlDecoder::looksLikeAxml(manifest)) {
        error = "AndroidManifest.xml is not binary XML";
        return false;
    }
    ManifestCollector collector(out);
    if (!AxmlDecoder::decodeEvents(manifest, collector, error, resources)) return false;
    // The label may be a reference; the collector stored the raw value.
    if (resources && out.appLabel.rfind("@", 0) == 0) {
        const uint32_t id = resources->find(out.appLabel.substr(1));
        if (id) out.appLabel = resources->value(id);
    }
    evaluate(out);
    return true;
}

std::string toJson(const Audit& a) {
    // Hand-rolled (the MCP Json type lives in mcp/, which analysis must not
    // depend on): valid JSON with escaped strings.
    auto q = [](const std::string& s) {
        std::string o = "\"";
        for (char c : s) {
            switch (c) {
                case '"': o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n"; break;
                case '\r': o += "\\r"; break;
                case '\t': o += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned char>(c));
                        o += buf;
                    } else {
                        o += c;
                    }
            }
        }
        return o + "\"";
    };
    auto arr = [&](const std::vector<std::string>& v) {
        std::string o = "[";
        for (size_t i = 0; i < v.size(); ++i) o += (i ? "," : "") + q(v[i]);
        return o + "]";
    };

    std::string o = "{";
    o += "\"package\":" + q(a.package) + ",\"appLabel\":" + q(a.appLabel);
    o += ",\"versionCode\":" + std::to_string(a.versionCode) + ",\"versionName\":" + q(a.versionName);
    o += ",\"minSdk\":" + std::to_string(a.minSdk) + ",\"targetSdk\":" + std::to_string(a.targetSdk);
    o += ",\"debuggable\":" + std::string(a.debuggable ? "true" : "false");
    o += ",\"allowBackup\":" + std::string(a.allowBackup ? "true" : "false");
    o += ",\"usesCleartext\":" + std::string(a.usesCleartext ? "true" : "false");
    o += ",\"permissions\":" + arr(a.permissions);
    o += ",\"dangerousPermissions\":" + arr(a.dangerousPermissions);
    o += ",\"components\":[";
    for (size_t i = 0; i < a.components.size(); ++i) {
        const auto& c = a.components[i];
        o += (i ? "," : "") + std::string("{\"kind\":") + q(Component::kindName(c.kind)) +
             ",\"name\":" + q(c.name) + ",\"exported\":" + (c.exported ? "true" : "false") +
             ",\"permission\":" + q(c.permission) + "}";
    }
    o += "],\"findings\":[";
    for (size_t i = 0; i < a.findings.size(); ++i) {
        const auto& f = a.findings[i];
        o += (i ? "," : "") + std::string("{\"severity\":") + q(severityName(f.severity)) +
             ",\"masvs\":" + q(f.masvsId) + ",\"title\":" + q(f.title) + ",\"detail\":" + q(f.detail) +
             ",\"location\":" + q(f.location) + "}";
    }
    return o + "]}";
}

std::string toMarkdown(const Audit& a) {
    std::string o = "# Security audit: " + (a.appLabel.empty() ? a.package : a.appLabel) + "\n\n";
    o += "| | |\n|---|---|\n";
    o += "| Package | `" + a.package + "` |\n";
    o += "| Version | " + a.versionName + " (" + std::to_string(a.versionCode) + ") |\n";
    o += "| SDK | min " + std::to_string(a.minSdk) + " / target " + std::to_string(a.targetSdk) + " |\n";
    o += "| Debuggable | " + std::string(a.debuggable ? "yes" : "no") + " |\n";
    o += "| Backup allowed | " + std::string(a.allowBackup ? "yes" : "no") + " |\n";
    o += "| Cleartext | " + std::string(a.usesCleartext ? "allowed" : "blocked") + " |\n\n";

    o += "## Findings\n\n";
    if (a.findings.empty()) o += "No findings.\n";
    for (const auto& f : a.findings)
        o += "- **" + std::string(severityName(f.severity)) + "** (" + f.masvsId + ") " + f.title + " — " +
             f.detail + " `" + f.location + "`\n";

    o += "\n## Components\n\n| Kind | Name | Exported | Permission |\n|---|---|---|---|\n";
    for (const auto& c : a.components)
        o += std::string("| ") + Component::kindName(c.kind) + " | `" + c.name + "` | " +
             (c.exported ? "yes" : "no") + " | " + (c.permission.empty() ? "—" : c.permission) + " |\n";

    o += "\n## Permissions\n\n";
    for (const auto& p : a.permissions) {
        bool danger = std::find(a.dangerousPermissions.begin(), a.dangerousPermissions.end(), p) !=
                      a.dangerousPermissions.end();
        o += "- `" + p + "`" + (danger ? " **dangerous**" : "") + "\n";
    }
    return o;
}

}  // namespace manifestaudit
