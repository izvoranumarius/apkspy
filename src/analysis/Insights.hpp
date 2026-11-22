#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Static triage of an APK: hard-coded secrets, third-party SDKs (trackers),
// app frameworks, packers / protectors (detection only), code-risk rules and
// an obfuscation estimate - plus JSON and SARIF export of the findings.
//
// Pure functions over plain inputs (class descriptors, referenced method
// signatures, string constants, archive entry names) so they work on any
// source of those and are testable without an APK. Nothing is executed,
// nothing is modified, nothing touches the network.
namespace insights {

enum class Severity { Info, Low, Medium, High };
const char* severityName(Severity s);

// What the scanners look at. ApkSpy fills it from ApkAnalysis + the APK tree.
struct Inputs {
    std::vector<std::string> classes;     // defined classes, descriptors ("Lcom/a/B;")
    std::vector<std::string> methodRefs;  // referenced methods ("Lx/Y;->name(proto)ret")
    std::vector<std::string> strings;     // string constants
    std::vector<std::string> files;       // archive entry names ("lib/arm64-v8a/libflutter.so")
};

// --- Secrets ----------------------------------------------------------------
struct Secret {
    std::string kind;     // "AWS access key ID", "Google API key", ...
    std::string value;    // the matched token
    size_t stringIndex = 0;  // Inputs::strings index it came from
    Severity severity = Severity::High;
};
std::vector<Secret> findSecrets(const std::vector<std::string>& strings);
// "AKIA****WXYZ": first 4 and last 4 characters kept.
std::string mask(std::string_view secret);

// --- SDKs / trackers --------------------------------------------------------
struct Sdk {
    std::string name;      // "Firebase Analytics"
    std::string category;  // "Analytics", "Advertising", "Crash reporting", ...
    bool tracker = false;  // collects usage / ad data
    std::string prefix;    // matched package ("Lcom/google/firebase/analytics/")
    int classes = 0;       // defined classes under the prefix
};
std::vector<Sdk> detectSdks(const std::vector<std::string>& classes);

// --- Frameworks and packers -------------------------------------------------
struct Detection {
    std::string name;      // "Flutter", "React Native (Hermes)", "Jiagu (Qihoo 360)"
    std::string kind;      // "Framework" or "Packer"
    std::string evidence;  // file or class that matched
};
std::vector<Detection> detectFrameworks(const Inputs& in);

// --- Code-risk rules --------------------------------------------------------
struct RuleHit {
    std::string id;     // "webview-js-interface"
    Severity severity = Severity::Medium;
    std::string title;
    std::string masvs;  // "MASVS-PLATFORM-2"
    std::string detail;
    std::vector<std::string> matched;  // referenced signatures / strings that triggered it
};
// Rules over referenced APIs and constants. Library code is not excluded:
// the app layer resolves each matched signature to its callers.
std::vector<RuleHit> runRules(const Inputs& in);

// --- Obfuscation ------------------------------------------------------------
struct Obfuscation {
    int appClasses = 0;   // classes outside well-known library packages
    int shortNames = 0;   // of those, simple names of 1-2 characters ("a", "b0")
    double ratio = 0.0;   // shortNames / appClasses
    const char* verdict = "none";  // "none", "light", "heavy"
};
Obfuscation estimateObfuscation(const std::vector<std::string>& classes);

// --- Endpoints --------------------------------------------------------------
// URLs found in string constants, grouped by host. Cloud backends (Firebase,
// App Engine, AWS, Supabase, ...) are classified so they sort first.
struct EndpointHost {
    std::string host;
    std::string kind;  // "Firebase Realtime Database", "AWS", ... or empty for a plain host
    bool https = true;  // false when only http:// was seen
    std::vector<std::string> urls;  // unique, sorted
};
std::vector<EndpointHost> endpoints(const std::vector<std::string>& strings);

// --- Encoded strings --------------------------------------------------------
// String constants that are base64, hex or URL-encoded text: apps hide URLs,
// keys and messages this way. Only readable results are reported (mostly
// printable text, at least 6 bytes), so random-looking identifiers are skipped.
struct DecodedString {
    std::string original;
    std::string decoded;
    std::string method;  // "base64", "hex" or "url"
};
std::vector<DecodedString> decodeStrings(const std::vector<std::string>& strings, size_t limit = 500);

// --- Permission -> API usage ------------------------------------------------
// Which guarded APIs an app actually calls for each dangerous permission it
// requests - the gap between what it asks for and what it uses.
struct PermissionUse {
    std::string permission;          // "android.permission.ACCESS_FINE_LOCATION"
    std::vector<std::string> apis;   // referenced guarded method signatures
};
// For each requested permission that has a known API set, the referenced
// guarded APIs (empty apis = requested but no matching call seen).
std::vector<PermissionUse> permissionUsage(const std::vector<std::string>& requestedPermissions,
                                           const std::vector<std::string>& methodRefs);
// Guarded APIs used WITHOUT the matching permission requested (possible
// crash-at-runtime, or a permission added at runtime elsewhere).
std::vector<PermissionUse> missingPermissions(const std::vector<std::string>& requestedPermissions,
                                              const std::vector<std::string>& methodRefs);

// --- Everything together ----------------------------------------------------
struct Result {
    std::vector<Secret> secrets;
    std::vector<Sdk> sdks;
    std::vector<Detection> detections;
    std::vector<RuleHit> rules;
    Obfuscation obfuscation;
};
Result scan(const Inputs& in);

// JSON object (secrets masked). Stable key order.
std::string toJson(const Result& r, std::string_view apkName);
// SARIF 2.1.0 log: one rule per finding kind, one result per finding
// (secrets masked). Locations are logical (class / method signatures).
std::string toSarif(const Result& r, std::string_view apkName);

}  // namespace insights
