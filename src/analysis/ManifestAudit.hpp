#pragma once
#include <cstdint>
#include <string>
#include <vector>

class ApkArchive;
class ResourceTable;

// Static security assessment of AndroidManifest.xml: exposes the app's
// attack surface (components, permissions, dangerous flags) and a list of
// findings mapped to OWASP MASVS.
//
// Everything is derived from the decoded AXML and resources.arsc, so it
// works on any APK - no jadx, no analysis pass, no device. Malformed
// manifests yield whatever parsed (the AXML walker is bounds-checked).
namespace manifestaudit {

enum class Severity { Info, Low, Medium, High, Critical };
const char* severityName(Severity s);

struct Component {
    enum class Kind { Activity, Service, Receiver, Provider };
    static const char* kindName(Kind k);
    Kind kind = Kind::Activity;
    std::string name;        // fully qualified ("com.a.B")
    bool exported = false;
    std::string permission;  // caller permission, "" = none
    std::vector<std::string> intentActions;
};

struct Finding {
    Severity severity = Severity::Info;
    std::string masvsId;  // "MASVS-PLATFORM-1", "MASVS-NETWORK-1", ...
    std::string title;
    std::string detail;
    std::string location;  // manifest attribute or component, for jumping
};

struct Audit {
    std::string package;
    std::string appLabel;
    int versionCode = 0;
    std::string versionName;
    int minSdk = 0;
    int targetSdk = 0;
    std::vector<std::string> permissions;           // requested
    std::vector<std::string> dangerousPermissions; // requested and dangerous
    std::vector<Component> components;
    bool usesCleartext = false;
    bool allowBackup = false;
    bool debuggable = false;
    bool testOnly = false;
    std::string networkSecurityConfig;
    std::vector<Finding> findings;
};

// Audits one APK. `resources` (optional) resolves the app label and other
// references; pass the same table the viewer uses when you have it.
// Returns false when AndroidManifest.xml cannot be read or decoded.
bool audit(const ApkArchive& apk, const ResourceTable* resources, Audit& out, std::string& error);

// Android's permission protection levels, as known for the platform
// permissions (best effort: only names in the table are classified).
bool isDangerousPermission(const std::string& name);

// The audit as JSON (ready for MCP and for report export).
std::string toJson(const Audit& audit);
// The audit as Markdown: summary, attack surface tables, findings by severity.
std::string toMarkdown(const Audit& audit);

}  // namespace manifestaudit
