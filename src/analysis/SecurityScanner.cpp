#include "analysis/SecurityScanner.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <unordered_map>
#include "analysis/BehaviorGraph.hpp"
#include "analysis/Dalvik.hpp"
#include "analysis/LibraryCatalog.hpp"
#include "core/AxmlDecoder.hpp"

namespace security {
namespace {

const std::vector<Rule> kRules = {
    {"secret-private-key", "Secrets", "Private key in the APK",
     "A private key is shipped inside the app. Anyone can extract it and impersonate the app or decrypt what it protects.",
     "Remove the key from the APK. Keep private keys on a server, or generate them on the device in the Android Keystore.",
     "CWE-321", "MASVS-CRYPTO"},
    {"secret-api-key", "Secrets", "Hardcoded credential",
     "A token or key with a recognisable format is embedded in the app. Extracting strings from an APK is trivial, so the "
     "credential must be considered public.",
     "Revoke the credential. Proxy the calls through your backend, or use short-lived tokens issued after authentication. "
     "Keys that must ship (Google API keys) should be restricted to the app's package and signature.",
     "CWE-798", "MASVS-STORAGE"},
    {"secret-generic", "Secrets", "Possible hardcoded secret",
     "A string that looks like a key, token or password is embedded in the app's code or resources.",
     "Check whether the value is sensitive; if it is, move it out of the APK.", "CWE-798", "MASVS-STORAGE"},
    {"bundled-keystore", "Secrets", "Key store bundled in the APK",
     "A key store or key file ships inside the app. Its password is usually in the code too.",
     "Do not ship key stores. Provision keys at runtime into the Android Keystore.", "CWE-321", "MASVS-CRYPTO"},
    {"manifest-debuggable", "Manifest", "Debuggable application",
     "android:debuggable=\"true\" lets anyone attach a debugger, read memory and run code as the app on any device.",
     "Never ship a debuggable build: remove the attribute and let the build type set it.", "CWE-489", "MASVS-RESILIENCE"},
    {"manifest-test-only", "Manifest", "Test-only application",
     "android:testOnly=\"true\" marks a build meant for testing; it can only be installed with adb and must not be released.",
     "Build the release from the release build type.", "CWE-489", "MASVS-CODE"},
    {"manifest-allow-backup", "Manifest", "Application data can be backed up",
     "With allowBackup (the default when the attribute is missing), the app's private files, databases and preferences can "
     "be extracted with adb backup or cloud backups.",
     "Set android:allowBackup=\"false\", or limit what is backed up with fullBackupContent / dataExtractionRules.",
     "CWE-530", "MASVS-STORAGE"},
    {"manifest-cleartext", "Network", "Cleartext traffic allowed",
     "The app allows unencrypted HTTP; traffic can be read and modified by anyone on the network path.",
     "Use HTTPS everywhere and remove usesCleartextTraffic, or allow cleartext only for specific domains in a network "
     "security configuration.",
     "CWE-319", "MASVS-NETWORK"},
    {"nsc-cleartext", "Network", "Network security configuration permits cleartext",
     "The network security configuration permits unencrypted HTTP (cleartextTrafficPermitted=\"true\").",
     "Remove cleartextTrafficPermitted or restrict it to the domains that cannot use HTTPS.", "CWE-319", "MASVS-NETWORK"},
    {"nsc-user-certs", "Network", "User-installed CAs are trusted",
     "The network security configuration trusts user-installed certificates outside debug-overrides, so a proxy CA "
     "installed on the device can intercept the app's TLS traffic.",
     "Trust only system certificates in release builds; keep user CAs in <debug-overrides>.", "CWE-295", "MASVS-NETWORK"},
    {"manifest-old-target", "Manifest", "Outdated target SDK",
     "The app targets an old API level and opts out of platform security changes (scoped storage, cleartext defaults, "
     "background restrictions, explicit exports).",
     "Target a current API level.", "CWE-1104", "MASVS-CODE"},
    {"component-exported", "Components", "Exported component without permission",
     "Other apps can start, bind or send to this component. Any data or action it exposes is reachable from any installed app.",
     "Set android:exported=\"false\" if no other app needs it; otherwise protect it with a signature-level permission and "
     "validate every input.",
     "CWE-926", "MASVS-PLATFORM"},
    {"component-weak-permission", "Components", "Component protected by a weak permission",
     "The component is protected by a permission with protectionLevel normal or dangerous, which any app can request.",
     "Use protectionLevel=\"signature\" for permissions that guard components.", "CWE-732", "MASVS-PLATFORM"},
    {"provider-grant-uri", "Components", "Provider grants URI permissions",
     "grantUriPermissions lets the app hand out temporary access to the provider's data; a wrong URI in a granting Intent "
     "leaks files.",
     "Restrict grants with <grant-uri-permission> path patterns and check the URIs the app grants.", "CWE-284", "MASVS-PLATFORM"},
    {"crypto-ecb", "Cryptography", "ECB cipher mode",
     "ECB encrypts identical blocks to identical ciphertext and leaks patterns of the plaintext. Cipher.getInstance(\"AES\") "
     "also means AES/ECB.",
     "Use AES/GCM/NoPadding with a random 12-byte IV per message.", "CWE-327", "MASVS-CRYPTO"},
    {"crypto-weak-cipher", "Cryptography", "Weak cipher",
     "DES, 3DES, RC4, RC2 and Blowfish are broken or have too small a block or key size.",
     "Use AES-GCM or ChaCha20-Poly1305.", "CWE-327", "MASVS-CRYPTO"},
    {"crypto-weak-hash", "Cryptography", "Weak hash function",
     "MD5 and SHA-1 are not collision resistant. They must not protect integrity, signatures or passwords (fine for "
     "non-security checksums).",
     "Use SHA-256 or better; for passwords use a slow KDF (PBKDF2, scrypt, Argon2).", "CWE-328", "MASVS-CRYPTO"},
    {"crypto-hardcoded-key", "Cryptography", "Hardcoded encryption key",
     "A key is built from a constant string, so it is identical in every installation and readable from the APK.",
     "Generate keys at runtime in the Android Keystore, or derive them from user input with a KDF.", "CWE-321", "MASVS-CRYPTO"},
    {"crypto-static-iv", "Cryptography", "Constant initialisation vector",
     "The IV is built from a constant: the same plaintext always encrypts the same way, and with CTR / GCM a reused IV breaks "
     "confidentiality entirely.",
     "Generate a random IV for every encryption and store it with the ciphertext.", "CWE-329", "MASVS-CRYPTO"},
    {"crypto-static-seed", "Cryptography", "SecureRandom with a fixed seed",
     "Seeding SecureRandom with a constant can make its output predictable.",
     "Do not call setSeed with a constant; let SecureRandom seed itself.", "CWE-337", "MASVS-CRYPTO"},
    {"tls-trust-all", "Network", "TLS certificates not validated",
     "A TrustManager accepts every certificate (empty checkServerTrusted) or an insecure socket factory is used: any "
     "man-in-the-middle can read and modify the traffic.",
     "Remove the custom TrustManager and use the platform's validation; pin certificates with a network security "
     "configuration if needed.",
     "CWE-295", "MASVS-NETWORK"},
    {"tls-hostname-all", "Network", "TLS host names not verified",
     "A HostnameVerifier accepts every host (or ALLOW_ALL_HOSTNAME_VERIFIER is used): a certificate for any domain is accepted.",
     "Use the default HostnameVerifier.", "CWE-297", "MASVS-NETWORK"},
    {"webview-ssl-proceed", "WebView", "WebView ignores TLS errors",
     "onReceivedSslError calls handler.proceed(): the WebView loads pages over invalid certificates.",
     "Call handler.cancel() (the default) and fix the server certificate.", "CWE-295", "MASVS-NETWORK"},
    {"webview-js-interface", "WebView", "JavaScript bridge into the app",
     "addJavascriptInterface exposes Java methods to every page the WebView loads; injected or third-party script can call "
     "them (and on API < 17, any public method, leading to code execution).",
     "Only load trusted HTTPS content in WebViews with a bridge, annotate exposed methods with @JavascriptInterface and "
     "validate their input.",
     "CWE-749", "MASVS-PLATFORM"},
    {"webview-js-enabled", "WebView", "JavaScript enabled in a WebView",
     "JavaScript is enabled, which widens the impact of loading untrusted content.",
     "Enable JavaScript only for WebViews that need it and load only trusted content.", "CWE-79", "MASVS-PLATFORM"},
    {"webview-file-access", "WebView", "WebView file access",
     "File URLs can read local files; with access from file URLs, a malicious HTML file can read the app's private data and "
     "send it anywhere.",
     "Disable setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs; use WebViewAssetLoader for local content.",
     "CWE-200", "MASVS-PLATFORM"},
    {"webview-debugging", "WebView", "WebView debugging enabled",
     "setWebContentsDebuggingEnabled(true) lets anyone with USB access inspect and script the app's WebViews through Chrome "
     "DevTools.",
     "Enable it only in debug builds.", "CWE-489", "MASVS-RESILIENCE"},
    {"webview-mixed-content", "WebView", "Mixed content allowed",
     "MIXED_CONTENT_ALWAYS_ALLOW loads HTTP resources into HTTPS pages, where they can be tampered with.",
     "Use MIXED_CONTENT_NEVER_ALLOW.", "CWE-319", "MASVS-NETWORK"},
    {"storage-world-readable", "Storage", "World-readable or writable file",
     "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE let every app read or modify the file (refused on API 24+, still a sign of "
     "data meant to be private being shared).",
     "Use MODE_PRIVATE and share data through a ContentProvider or FileProvider.", "CWE-276", "MASVS-STORAGE"},
    {"storage-external", "Storage", "External storage",
     "Files on shared external storage can be read and changed by other apps.",
     "Keep sensitive data in internal storage; validate anything read back from external storage.", "CWE-922", "MASVS-STORAGE"},
    {"sql-injection", "Code", "SQL built from strings",
     "A raw SQL statement is assembled at runtime; if any part comes from input, it can be injected.",
     "Use query parameters (selectionArgs / bindArgs) instead of concatenation.", "CWE-89", "MASVS-CODE"},
    {"log-sensitive", "Code", "Sensitive data in logs",
     "A log message mentions passwords, tokens or keys. Logs are readable over adb and by crash reporters.",
     "Do not log secrets; strip debug logging from release builds.", "CWE-532", "MASVS-STORAGE"},
    {"exec-command", "Code", "Command execution",
     "The app runs shell commands. With input in the command, this can execute arbitrary commands as the app.",
     "Avoid Runtime.exec; never build commands from input.", "CWE-78", "MASVS-CODE"},
    {"dynamic-code-loading", "Code", "Dynamic code loading",
     "Code is loaded at runtime from files or memory. If the code can be replaced (external storage, downloads), an "
     "attacker can run code in the app.",
     "Load code only from the APK or verified, app-private locations.", "CWE-94", "MASVS-CODE"},
    {"pending-intent-mutable", "Components", "Mutable PendingIntent",
     "A PendingIntent is created without FLAG_IMMUTABLE; the app that receives it may fill in the Intent and redirect it.",
     "Pass FLAG_IMMUTABLE unless the receiver must change the Intent.", "CWE-927", "MASVS-PLATFORM"},
    {"cleartext-url", "Network", "Cleartext URL",
     "The code contains http:// URLs: requests to them travel unencrypted.", "Use https:// URLs.", "CWE-319", "MASVS-NETWORK"},
};

bool isAlnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool isB64Url(char c) { return isAlnum(c) || c == '-' || c == '_'; }

// Length of the run starting at `p` whose characters satisfy `ok`.
template <typename F>
size_t runLength(std::string_view s, size_t p, F ok) {
    size_t n = 0;
    while (p + n < s.size() && ok(s[p + n])) ++n;
    return n;
}

std::string lower(std::string_view s) {
    std::string o(s);
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return o;
}

std::string upper(std::string_view s) {
    std::string o(s);
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return o;
}

// "abcd1234efgh" -> "abcd…efgh": evidence shows enough to recognise a secret, not all of it.
std::string mask(const std::string& s) {
    if (s.size() <= 12) return s;
    return s.substr(0, 8) + "..." + s.substr(s.size() - 4);
}

std::string quoteShort(const std::string& s, size_t n = 120) { return "\"" + (s.size() > n ? s.substr(0, n) + "..." : s) + "\""; }

// Hosts of http:// URLs that are XML namespaces or local, not traffic.
bool ignorableHost(const std::string& host) {
    static constexpr std::string_view kHosts[] = {
        "localhost", "127.0.0.1", "10.0.2.2", "0.0.0.0", "schemas.android.com", "www.w3.org", "w3.org", "ns.adobe.com",
        "xmlpull.org", "www.xmlpull.org", "schemas.xmlsoap.org", "schemas.microsoft.com", "www.apple.com", "json-schema.org",
        "purl.org", "xml.org", "www.xml.org", "apache.org", "www.apache.org", "java.sun.com", "xml.apache.org", "example.com",
        "www.example.com", "www.google.com", "plus.google.com", "javax.xml.XMLConstants", "relaxng.org", "www.wapforum.org",
        "www.opengis.net", "openid.net", "ns.google.com", "xmlns.jcp.org", "www.slf4j.org", "exslt.org"};
    return std::find(std::begin(kHosts), std::end(kHosts), host) != std::end(kHosts);
}

class Scanner {
public:
    Scanner(const Input& in, const std::atomic<bool>* cancel, std::atomic<size_t>* progress)
        : in_(in), cancel_(cancel), progress_(progress), targetSdk_(std::atoi(in.info.targetSdk.c_str())) {}

    Report run() {
        manifest();
        networkConfig();
        if (stopped()) return finish();
        resources();
        files();
        if (in_.analysis && !stopped()) {
            report_.bytecodeScanned = true;
            strings();
            if (!stopped()) bytecode();
            if (!stopped()) classes();
        }
        return finish();
    }

private:
    bool stopped() const { return cancel_ && cancel_->load(); }

    void add(const char* ruleId, Severity sev, int confidence, std::string evidence, Location loc, std::string library = {},
             std::string title = {}) {
        const Rule* r = rule(ruleId);
        Finding f;
        f.rule = ruleId;
        f.title = title.empty() ? (r ? r->title : ruleId) : std::move(title);
        f.severity = sev;
        f.confidence = confidence;
        f.evidence = std::move(evidence);
        f.location = std::move(loc);
        f.library = std::move(library);
        const std::string key = f.rule + "|" + f.location.ref + "|" + std::to_string(f.location.pc) + "|" + f.evidence;
        if (seen_.insert(key).second) report_.findings.push_back(std::move(f));
    }

    std::string libraryOf(std::string_view descriptor) const {
        const libcatalog::Library* lib = libcatalog::forClass(descriptor);
        return lib ? lib->name : "";
    }

    // --- manifest -----------------------------------------------------------
    void manifest() {
        const ApkInfo& m = in_.info;
        const int target = std::atoi(m.targetSdk.c_str());
        const Location app{Location::Kind::Manifest, "application", 0, -1};
        if (m.debuggable) add("manifest-debuggable", Severity::High, 100, "android:debuggable=\"true\"", app);
        if (m.testOnly) add("manifest-test-only", Severity::Medium, 100, "android:testOnly=\"true\"", app);
        if (m.allowBackupSet && m.allowBackup)
            add("manifest-allow-backup", Severity::Medium, 90, "android:allowBackup=\"true\"", app);
        else if (!m.allowBackupSet && m.ok)
            add("manifest-allow-backup", Severity::Low, 70, "android:allowBackup is not set (it defaults to true)", app);
        if (m.usesCleartextTraffic == "true")
            add("manifest-cleartext", Severity::Medium, 95, "android:usesCleartextTraffic=\"true\"", app);
        else if (m.usesCleartextTraffic.empty() && m.networkSecurityConfig.empty() && target > 0 && target < 28)
            add("manifest-cleartext", Severity::Low, 80, "targetSdk " + m.targetSdk + " < 28 without a network security configuration: cleartext is allowed by default",
                app);
        if (target > 0 && target < 29)
            add("manifest-old-target", Severity::Low, 100, "targetSdkVersion " + m.targetSdk, {Location::Kind::Manifest, "uses-sdk", 0, -1});

        std::map<std::string, std::string> protection;  // declared permission -> level
        for (const ApkPermissionDecl& p : m.declaredPermissions) protection[p.name] = p.protectionLevel;
        for (const ApkComponent& c : m.components) {
            const std::string cls = behavior::componentClass(m.packageName, c.name);
            const std::string library = libraryOf(DexFile::javaToDescriptor(cls));
            const Location loc{Location::Kind::Manifest, c.name, 0, -1};
            const bool launcher = std::find(c.categories.begin(), c.categories.end(), "android.intent.category.LAUNCHER") != c.categories.end();
            // Platform defaults: a component with an intent filter is exported below API 31;
            // providers are exported by default below API 17.
            bool exported = c.exported;
            if (!c.exportedSet) exported = c.type == "provider" ? (target > 0 && target < 17) : (c.hasIntentFilter && (target == 0 || target < 31));
            const bool isProvider = c.type == "provider";
            const bool guarded = !c.permission.empty() || (isProvider && (!c.readPermission.empty() || !c.writePermission.empty()));
            if (exported && !guarded && !launcher) {
                Severity sev = isProvider ? Severity::High : c.type == "activity" || c.type == "activity-alias" ? Severity::Low : Severity::Medium;
                int conf = c.exportedSet ? 90 : 75;
                // Receivers of system broadcasts only (BOOT_COMPLETED...) are a lesser concern.
                const bool systemOnly = !c.actions.empty() && std::all_of(c.actions.begin(), c.actions.end(), [](const std::string& a) {
                    return a.rfind("android.intent.action.", 0) == 0 || a.rfind("android.net.", 0) == 0;
                });
                if (c.type == "receiver" && systemOnly) sev = Severity::Low, conf = 50;
                std::string ev = c.type + " " + cls + (c.exportedSet ? " (android:exported=\"true\")" : " (exported by its intent filter)");
                if (!c.actions.empty()) ev += "; actions: " + c.actions.front() + (c.actions.size() > 1 ? " +" + std::to_string(c.actions.size() - 1) : "");
                if (isProvider && !c.authorities.empty()) ev += "; authorities: " + c.authorities;
                add("component-exported", sev, conf, ev, loc, library);
            }
            for (const std::string* p : {&c.permission, &c.readPermission, &c.writePermission}) {
                auto it = protection.find(*p);
                if (exported && it != protection.end() && (it->second.rfind("normal", 0) == 0 || it->second.rfind("dangerous", 0) == 0))
                    add("component-weak-permission", Severity::Low, 85, cls + " is guarded by " + *p + " (protectionLevel " + it->second + ")", loc, library);
            }
            if (isProvider && c.grantUriPermissions)
                add("provider-grant-uri", Severity::Low, 70, cls + " (android:grantUriPermissions=\"true\")", loc, library);
        }
    }

    // --- network security configuration -----------------------------------------
    void networkConfig() {
        const std::string& x = in_.networkSecurityConfig;
        if (x.empty()) return;
        const Location loc{Location::Kind::File, in_.networkSecurityConfigPath, 0, -1};
        // Walk the tags, knowing whether we are inside <debug-overrides> or a <domain-config>.
        int debugDepth = 0;
        std::vector<std::string> domains;
        bool inDomainConfig = false, domainCleartext = false;
        const auto attr = [](std::string_view tag, std::string_view name) -> std::string {
            const size_t p = tag.find(std::string(name) + "=\"");
            if (p == std::string_view::npos) return {};
            const size_t s = p + name.size() + 2, e = tag.find('"', s);
            return e == std::string_view::npos ? std::string() : std::string(tag.substr(s, e - s));
        };
        for (size_t i = x.find('<'); i != std::string::npos; i = x.find('<', i + 1)) {
            const size_t end = x.find('>', i);
            if (end == std::string::npos) break;
            const std::string_view tag(x.data() + i, end - i + 1);
            const bool closing = tag.size() > 1 && tag[1] == '/';
            const bool selfClosing = tag.size() > 2 && tag[tag.size() - 2] == '/';
            const size_t nameStart = closing ? 2 : 1;
            const size_t nameEnd = tag.find_first_of(" />\n\t", nameStart);
            const std::string name(tag.substr(nameStart, nameEnd - nameStart));
            if (name == "debug-overrides") debugDepth += closing ? -1 : (selfClosing ? 0 : 1);
            if (name == "base-config" && !closing && attr(tag, "cleartextTrafficPermitted") == "true")
                add("nsc-cleartext", Severity::Medium, 95, "<base-config cleartextTrafficPermitted=\"true\">", loc);
            if (name == "domain-config") {
                if (!closing) {
                    inDomainConfig = true;
                    domainCleartext = attr(tag, "cleartextTrafficPermitted") == "true";
                    domains.clear();
                } else {
                    if (domainCleartext && !domains.empty()) {
                        std::string list;
                        for (const std::string& d : domains) list += (list.empty() ? "" : ", ") + d;
                        add("nsc-cleartext", Severity::Low, 90, "cleartext allowed for " + list, loc);
                    }
                    inDomainConfig = false;
                }
            }
            if (name == "domain" && !closing && inDomainConfig) {
                const size_t textStart = end + 1, textEnd = x.find('<', textStart);
                if (textEnd != std::string::npos) {
                    std::string d = x.substr(textStart, textEnd - textStart);
                    d.erase(std::remove_if(d.begin(), d.end(), [](unsigned char c) { return std::isspace(c); }), d.end());
                    if (!d.empty()) domains.push_back(d);
                }
            }
            if (name == "certificates" && !closing && attr(tag, "src") == "user" && debugDepth <= 0)
                add("nsc-user-certs", Severity::Medium, 95, "<certificates src=\"user\"/> outside <debug-overrides>", loc);
        }
    }

    // --- resources and files ---------------------------------------------------
    void resources() {
        if (!in_.resources) return;
        static constexpr std::string_view kNames[] = {"secret", "password", "passwd", "api_key", "apikey", "private_key",
                                                      "client_secret", "access_token", "auth_token", "token"};
        for (const ResourceTable::Item& it : in_.resources->list("string", "", SIZE_MAX)) {
            if (stopped()) return;
            const Location loc{Location::Kind::Resource, "string/" + it.name, 0, -1};
            SecretMatch m;
            if (findSecret(it.value, m)) {
                add(m.kind == "private key" ? "secret-private-key" : "secret-api-key", m.severity, m.confidence,
                    m.kind + " in @string/" + it.name + ": " + mask(m.token), loc, {}, "Hardcoded " + m.kind);
                continue;
            }
            const std::string name = lower(it.name);
            const bool sensitiveName = std::any_of(std::begin(kNames), std::end(kNames), [&](std::string_view k) { return name.find(k) != std::string::npos; });
            if (sensitiveName && it.value.size() >= 8 && it.value.find(' ') == std::string::npos && it.value.find('@') != 0 &&
                name.find("hint") == std::string::npos && name.find("label") == std::string::npos && name.find("title") == std::string::npos)
                add("secret-generic", Severity::Medium, 50, "@string/" + it.name + " = " + mask(it.value), loc);
        }
    }

    void files() {
        ApkArchive arch;
        const bool open = !in_.apkPath.empty() && arch.open(in_.apkPath);
        static constexpr std::string_view kTextExt[] = {".json", ".properties", ".xml", ".txt", ".cfg", ".conf", ".ini", ".yml",
                                                        ".yaml", ".js", ".html", ".htm", ".env", ".plist", ".pem", ".key", ".config"};
        static constexpr std::string_view kKeyStores[] = {".jks", ".keystore", ".bks", ".p12", ".pfx"};
        const auto endsWith = [](const std::string& s, std::string_view e) {
            return s.size() >= e.size() && lower(std::string_view(s).substr(s.size() - e.size())) == e;
        };
        uint64_t budget = 16ull * 1024 * 1024;
        std::vector<uint8_t> bytes;
        for (const ApkArchive::Entry& e : in_.entries) {
            if (stopped()) return;
            if (std::any_of(std::begin(kKeyStores), std::end(kKeyStores), [&](std::string_view x) { return endsWith(e.path, x); }))
                add("bundled-keystore", Severity::Medium, 85, e.path + " (" + std::to_string(e.size) + " bytes)", {Location::Kind::File, e.path, 0, -1});
            const bool text = std::any_of(std::begin(kTextExt), std::end(kTextExt), [&](std::string_view x) { return endsWith(e.path, x); });
            const bool where = e.path.rfind("assets/", 0) == 0 || e.path.rfind("res/raw/", 0) == 0 || e.path.find('/') == std::string::npos;
            if (!open || !text || !where || e.size > 512 * 1024 || e.size > budget) continue;
            if (!arch.readEntry(e.path, bytes, 512 * 1024) || AxmlDecoder::looksLikeAxml(bytes)) continue;
            budget -= e.size;
            ++report_.filesScanned;
            const std::string content(bytes.begin(), bytes.end());
            int line = 0;
            for (size_t s = 0; s <= content.size(); ++line) {
                size_t nl = content.find('\n', s);
                if (nl == std::string::npos) nl = content.size();
                SecretMatch m;
                if (findSecret(std::string_view(content).substr(s, nl - s), m))
                    add(m.kind == "private key" ? "secret-private-key" : "secret-api-key", m.severity, m.confidence,
                        m.kind + " in " + e.path + ": " + mask(m.token), {Location::Kind::File, e.path, 0, line}, {}, "Hardcoded " + m.kind);
                s = nl + 1;
            }
        }
    }

    // --- bytecode -----------------------------------------------------------------
    Location firstUse(uint16_t dex, uint32_t index, std::string& library) {
        const auto uses = in_.analysis->stringUsesAt(dex, index, 1);
        if (uses.empty()) return {};
        const DexFile& d = *in_.analysis->dexes()[uses[0].from.dex];
        library = libraryOf(d.typeDescriptor(d.methodClass(uses[0].from.method)));
        return {Location::Kind::Method, in_.analysis->methodSignature(uses[0].from), uses[0].from.pc, -1};
    }

    void strings() {
        const ApkAnalysis& a = *in_.analysis;
        std::map<std::string, std::pair<size_t, std::pair<uint16_t, uint32_t>>> cleartextHosts;  // host -> (count, first string)
        size_t generic = 0;
        for (uint16_t di = 0; di < a.dexes().size(); ++di) {
            const DexFile& dex = *a.dexes()[di];
            for (uint32_t i = 0; i < dex.stringCount(); ++i) {
                if ((i & 4095) == 0 && stopped()) return;
                const std::string_view s = dex.stringView(i);
                ++report_.stringsScanned;
                if (s.size() < 8) continue;
                SecretMatch m;
                if (findSecret(s, m)) {
                    std::string library;
                    const Location loc = firstUse(di, i, library);
                    add(m.kind == "private key" ? "secret-private-key" : "secret-api-key", m.severity, m.confidence, m.kind + ": " + mask(m.token),
                        loc, library, "Hardcoded " + m.kind);
                    continue;
                }
                if (s.find("http://") != std::string_view::npos) {
                    for (const std::string& url : ApkAnalysis::extractUrls(s)) {
                        if (url.rfind("http://", 0) != 0) continue;
                        const std::string host = behavior::urlHost(url);
                        if (host.empty() || ignorableHost(host)) continue;
                        auto& entry = cleartextHosts[host];
                        if (entry.first++ == 0) entry.second = {di, i};
                    }
                    continue;
                }
                if (generic < 100 && s.size() >= 16 && s.size() <= 128 && ApkAnalysis::classify(s) == ApkAnalysis::StringCategory::Secret) {
                    std::string library;
                    const Location loc = firstUse(di, i, library);
                    if (loc.kind == Location::Kind::None || !library.empty()) continue;  // unused or library code
                    ++generic;
                    add("secret-generic", Severity::Low, 25, "\"" + mask(std::string(s)) + "\"", loc, library);
                }
            }
        }
        size_t n = 0;
        for (const auto& [host, info] : cleartextHosts) {
            if (n++ >= 200) break;
            std::string library;
            const Location loc = firstUse(info.second.first, info.second.second, library);
            if (loc.kind == Location::Kind::None) continue;  // never used by code
            add("cleartext-url", Severity::Low, 60, "http://" + host + " (" + std::to_string(info.first) + " URL" + (info.first > 1 ? "s" : "") + ")",
                loc, library);
        }
    }

    // Arguments known to be constant at a call: (position, rendered value).
    using Args = std::vector<std::pair<int, std::string>>;
    static const std::string* arg(const Args& args, int pos) {
        for (const auto& [p, v] : args)
            if (p == pos) return &v;
        return nullptr;
    }
    static std::string unquote(const std::string& v) { return v.size() >= 2 && v.front() == '"' && v.back() == '"' ? v.substr(1, v.size() - 2) : v; }
    static bool isTrue(const std::string* v) { return v && (*v == "1" || *v == "true"); }
    static bool literal(const std::string* v, long long& out) {
        if (!v || v->empty() || v->front() == '"') return false;
        char* end = nullptr;
        out = std::strtoll(v->c_str(), &end, 0);
        return end && *end == '\0';
    }

    void bytecode() {
        const ApkAnalysis& a = *in_.analysis;
        const int minSdk = std::atoi(in_.info.minSdk.c_str());
        const auto& classes = a.classes();
        for (size_t ci = 0; ci < classes.size(); ++ci) {
            if ((ci & 255) == 0) {
                if (stopped()) return;
                if (progress_) progress_->store(ci * 100 / std::max<size_t>(classes.size(), 1));
            }
            const std::string_view clsDesc = a.classDescriptor(classes[ci]);
            const std::string library = libraryOf(clsDesc);
            for (const ApkAnalysis::MethodDef& m : a.methodsOf(classes[ci])) {
                const DexFile& dex = *a.dexes()[m.dex];
                DexFile::CodeItem code;
                if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) continue;
                ++report_.methodsScanned;
                struct Call {
                    uint32_t pc;
                    std::string cls, name, proto;
                };
                std::vector<Call> calls;
                bool usesStringBuilder = false, hasKeySpec = false, hasIvSpec = false;
                for (uint32_t pc = 0; pc < code.insnsSize;) {
                    const dalvik::Insn in = dalvik::decode(code, pc);
                    pc += std::max<uint32_t>(in.size, 1);
                    if (!in.valid || in.payload || in.index == DexFile::kNoIndex) continue;
                    const dalvik::OpInfo& info = dalvik::opInfo(in.opcode);
                    if (info.ref == dalvik::RefKind::Field) {
                        const std::string f = dex.fieldSignature(in.index);
                        if (f.rfind("Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER", 0) == 0)
                            add("tls-hostname-all", Severity::High, 90, "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
                                {Location::Kind::Method, a.methodSignature(m), in.pc, -1}, library);
                        continue;
                    }
                    if (info.ref == dalvik::RefKind::Type && in.opcode == 0x22) {  // new-instance
                        const std::string_view t = dex.typeDescriptor(in.index);
                        if (t == "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;")
                            add("tls-hostname-all", Severity::High, 90, "new AllowAllHostnameVerifier()", {Location::Kind::Method, a.methodSignature(m), in.pc, -1},
                                library);
                        continue;
                    }
                    if (info.ref != dalvik::RefKind::Method || info.flow != dalvik::Flow::Invoke) continue;
                    Call c{in.pc, std::string(dex.typeDescriptor(dex.methodClass(in.index))), std::string(dex.methodName(in.index)),
                           dex.protoDescriptor(dex.methodProto(in.index))};
                    if (c.cls == "Ljava/lang/StringBuilder;" && c.name == "append") usesStringBuilder = true;
                    if (c.cls == "Ljavax/crypto/spec/SecretKeySpec;" && c.name == "<init>") hasKeySpec = true;
                    if (c.cls == "Ljavax/crypto/spec/IvParameterSpec;" && c.name == "<init>") hasIvSpec = true;
                    calls.push_back(std::move(c));
                }
                if (calls.empty()) continue;
                // Only methods with an interesting call pay for the constant propagation.
                const auto interesting = [](const Call& c) {
                    static const std::set<std::string> kNames = {
                        "getInstance", "setSeed", "setJavaScriptEnabled", "addJavascriptInterface", "setAllowFileAccess",
                        "setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setWebContentsDebuggingEnabled",
                        "setMixedContentMode", "proceed", "getSharedPreferences", "openFileOutput", "openOrCreateDatabase", "getDir",
                        "getExternalStorageDirectory", "getExternalStoragePublicDirectory", "rawQuery", "execSQL", "d", "v", "i", "w", "e",
                        "wtf", "exec", "getActivity", "getService", "getBroadcast", "getActivities", "getForegroundService", "getBytes",
                        "<init>", "getInsecure"};
                    return kNames.count(c.name) > 0;
                };
                if (std::none_of(calls.begin(), calls.end(), interesting)) continue;
                std::unordered_map<uint32_t, Args> consts;
                for (auto& cc : a.constantArguments(m)) consts[cc.pc] = std::move(cc.args);
                const std::string sig = a.methodSignature(m);
                const auto at = [&](uint32_t pc) { return Location{Location::Kind::Method, sig, pc, -1}; };
                const Args none;
                std::string keyString, ivString;  // constants turned into bytes (String.getBytes)
                for (const Call& c : calls) {
                    auto it = consts.find(c.pc);
                    const Args& args = it == consts.end() ? none : it->second;
                    if (c.cls == "Ljava/lang/String;" && c.name == "getBytes") {
                        if (const std::string* v = arg(args, 0); v && v->front() == '"') (keyString.empty() ? keyString : ivString) = unquote(*v);
                        continue;
                    }
                    callRule(c.cls, c.name, c.proto, args, at(c.pc), library, minSdk, usesStringBuilder);
                }
                if (hasKeySpec && !keyString.empty())
                    add("crypto-hardcoded-key", Severity::High, 60, "key bytes from the constant " + quoteShort(mask(keyString)), at(calls.front().pc), library);
                if (hasIvSpec && (!ivString.empty() || (!hasKeySpec && !keyString.empty())))
                    add("crypto-static-iv", Severity::Medium, 55, "IV bytes from a constant string", at(calls.front().pc), library);
            }
        }
    }

    void callRule(const std::string& cls, const std::string& name, const std::string& proto, const Args& args, const Location& loc,
                  const std::string& library, int minSdk, bool stringBuilder) {
        if (cls == "Ljavax/crypto/Cipher;" && name == "getInstance") {
            const std::string* v = arg(args, 0);
            if (!v || v->front() != '"') return;
            const std::string t = upper(unquote(*v));
            static constexpr std::string_view kWeak[] = {"DES", "DESEDE", "TRIPLEDES", "RC4", "ARCFOUR", "RC2", "BLOWFISH"};
            const std::string algo = t.substr(0, t.find('/'));
            if (std::find(std::begin(kWeak), std::end(kWeak), algo) != std::end(kWeak))
                add("crypto-weak-cipher", Severity::High, 90, "Cipher.getInstance(\"" + unquote(*v) + "\")", loc, library);
            else if (algo != "RSA" && (t.find("/ECB") != std::string::npos || t == "AES"))
                add("crypto-ecb", Severity::High, t == "AES" ? 75 : 90, "Cipher.getInstance(\"" + unquote(*v) + "\")", loc, library);
            return;
        }
        if (cls == "Ljava/security/MessageDigest;" && name == "getInstance") {
            const std::string* v = arg(args, 0);
            if (!v) return;
            const std::string t = upper(unquote(*v));
            if (t == "MD5" || t == "MD2" || t == "MD4" || t == "SHA-1" || t == "SHA1" || t == "SHA")
                add("crypto-weak-hash", Severity::Medium, 50, "MessageDigest.getInstance(\"" + unquote(*v) + "\")", loc, library);
            return;
        }
        if (cls == "Ljava/security/SecureRandom;" && name == "setSeed") {
            long long seed = 0;
            if (literal(arg(args, 1), seed)) add("crypto-static-seed", Severity::Medium, 60, "SecureRandom.setSeed(" + std::to_string(seed) + ")", loc, library);
            return;
        }
        if (cls == "Landroid/net/SSLCertificateSocketFactory;" && name == "getInsecure") {
            add("tls-trust-all", Severity::High, 90, "SSLCertificateSocketFactory.getInsecure()", loc, library);
            return;
        }
        if (cls == "Landroid/webkit/SslErrorHandler;" && name == "proceed") {
            add("webview-ssl-proceed", Severity::High, 85, "SslErrorHandler.proceed()", loc, library);
            return;
        }
        if (name == "addJavascriptInterface") {
            add("webview-js-interface", minSdk > 0 && minSdk < 17 ? Severity::High : Severity::Medium, 80,
                "WebView.addJavascriptInterface()" + std::string(minSdk > 0 && minSdk < 17 ? " with minSdk < 17" : ""), loc, library);
            return;
        }
        if (cls == "Landroid/webkit/WebSettings;") {
            const std::string* v = arg(args, 1);
            if (name == "setJavaScriptEnabled" && isTrue(v)) add("webview-js-enabled", Severity::Info, 90, "setJavaScriptEnabled(true)", loc, library);
            else if ((name == "setAllowFileAccessFromFileURLs" || name == "setAllowUniversalAccessFromFileURLs") && isTrue(v))
                add("webview-file-access", Severity::High, 90, name + "(true)", loc, library);
            else if (name == "setAllowFileAccess" && isTrue(v))
                add("webview-file-access", Severity::Low, 80, "setAllowFileAccess(true)", loc, library);
            else if (name == "setMixedContentMode" && v && *v == "0")
                add("webview-mixed-content", Severity::Medium, 90, "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)", loc, library);
            return;
        }
        if (cls == "Landroid/webkit/WebView;" && name == "setWebContentsDebuggingEnabled") {
            if (isTrue(arg(args, 0))) add("webview-debugging", Severity::Medium, 90, "WebView.setWebContentsDebuggingEnabled(true)", loc, library);
            return;
        }
        // Context.getSharedPreferences / openFileOutput / openOrCreateDatabase / getDir (name, mode): the receiver is any Context subclass.
        if ((name == "getSharedPreferences" || name == "openFileOutput" || name == "openOrCreateDatabase" || name == "getDir") &&
            proto.rfind("(Ljava/lang/String;I", 0) == 0) {
            long long mode = 0;
            if (literal(arg(args, 2), mode) && (mode & 3) != 0)
                add("storage-world-readable", Severity::High, 90,
                    name + "(..., " + std::string((mode & 1) ? "MODE_WORLD_READABLE" : "") + ((mode & 3) == 3 ? " | " : "") +
                        ((mode & 2) ? "MODE_WORLD_WRITEABLE" : "") + ")",
                    loc, library);
            return;
        }
        if (cls == "Landroid/os/Environment;" && (name == "getExternalStorageDirectory" || name == "getExternalStoragePublicDirectory")) {
            add("storage-external", Severity::Low, 60, "Environment." + name + "()", loc, library);
            return;
        }
        if ((cls == "Landroid/database/sqlite/SQLiteDatabase;" || cls.rfind("Lnet/sqlcipher/", 0) == 0 || cls.rfind("Lnet/zetetic/", 0) == 0) &&
            (name == "rawQuery" || name == "execSQL")) {
            const std::string* v = arg(args, 1);
            if (!v && stringBuilder) add("sql-injection", Severity::Medium, 40, "SQLiteDatabase." + name + "() with SQL built at runtime", loc, library);
            return;
        }
        if (cls == "Landroid/util/Log;") {
            // Phrasing that carries a value ("password: ", "token="), not names that merely mention one
            // (signInWithEmailAndPassword, TOKEN_SUCCESS).
            static constexpr std::string_view kWords[] = {"password:", "password=", "password is", "passwd=", "pwd=", "secret:", "secret=",
                                                          "token:", "token=", "token is", "api_key=", "apikey=", "private key:", "credit card"};
            for (const auto& [pos, v] : args) {
                if (v.empty() || v.front() != '"') continue;
                const std::string l = lower(v);
                for (std::string_view w : kWords)
                    if (l.find(w) != std::string::npos) {
                        add("log-sensitive", Severity::Low, 50, "Log." + name + "(" + quoteShort(unquote(v), 80) + ")", loc, library);
                        return;
                    }
            }
            return;
        }
        if ((cls == "Ljava/lang/Runtime;" && name == "exec") || (cls == "Ljava/lang/ProcessBuilder;" && name == "<init>")) {
            const std::string* v = arg(args, 1);
            std::string ev = cls == "Ljava/lang/Runtime;" ? "Runtime.exec(" : "new ProcessBuilder(";
            ev += v && v->front() == '"' ? quoteShort(unquote(*v), 80) + ")" : "...)";
            const bool su = v && (unquote(*v) == "su" || unquote(*v).rfind("su ", 0) == 0);
            add("exec-command", Severity::Medium, su ? 90 : 70, ev, loc, library);
            return;
        }
        if (name == "<init>" && (cls == "Ldalvik/system/DexClassLoader;" || cls == "Ldalvik/system/InMemoryDexClassLoader;" ||
                                 cls == "Ldalvik/system/PathClassLoader;")) {
            const std::string simple = cls.substr(cls.rfind('/') + 1, cls.size() - cls.rfind('/') - 2);
            add("dynamic-code-loading", Severity::Medium, cls == "Ldalvik/system/PathClassLoader;" ? 50 : 75, "new " + simple + "(...)", loc, library);
            return;
        }
        if (cls == "Landroid/app/PendingIntent;" &&
            (name == "getActivity" || name == "getService" || name == "getBroadcast" || name == "getActivities" || name == "getForegroundService")) {
            long long flags = 0;
            constexpr long long kImmutable = 0x04000000, kMutable = 0x02000000;
            if (literal(arg(args, 3), flags) && !(flags & kImmutable) && !(flags & kMutable)) {
                char hex[16];
                std::snprintf(hex, sizeof hex, "%llx", static_cast<unsigned long long>(flags));
                // Apps targeting 31+ must choose: without either flag the call throws on Android 12+.
                const bool throws = targetSdk_ >= 31;
                add("pending-intent-mutable", throws ? Severity::Medium : Severity::Low, throws ? 80 : 60,
                    "PendingIntent." + name + "(..., flags=0x" + hex + ")" +
                        (throws ? " - throws IllegalArgumentException on Android 12+ (targetSdk " + std::to_string(targetSdk_) + ")" : ""),
                    loc, library);
            }
            return;
        }
    }

    // --- classes (TrustManager / HostnameVerifier) ---------------------------------------
    // Opcodes of a method body, nops and payloads left out.
    std::vector<uint8_t> opcodes(const ApkAnalysis::MethodDef& m, std::vector<dalvik::Insn>* insns = nullptr) const {
        std::vector<uint8_t> out;
        const DexFile& dex = *in_.analysis->dexes()[m.dex];
        DexFile::CodeItem code;
        if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) return out;
        for (uint32_t pc = 0; pc < code.insnsSize;) {
            const dalvik::Insn in = dalvik::decode(code, pc);
            pc += std::max<uint32_t>(in.size, 1);
            if (!in.valid || in.payload || in.opcode == 0x00) continue;
            out.push_back(in.opcode);
            if (insns) insns->push_back(in);
        }
        return out;
    }

    void classes() {
        const ApkAnalysis& a = *in_.analysis;
        for (const ApkAnalysis::ClassEntry& c : a.classes()) {
            const DexFile& dex = *a.dexes()[c.dex];
            const DexFile::ClassDef& def = a.classDef(c);
            bool trustManager = false, hostnameVerifier = false;
            for (uint32_t t : dex.interfaces(def)) {
                const std::string_view d = dex.typeDescriptor(t);
                trustManager = trustManager || d == "Ljavax/net/ssl/X509TrustManager;";
                hostnameVerifier = hostnameVerifier || d == "Ljavax/net/ssl/HostnameVerifier;";
            }
            if (!trustManager && def.superclassIdx != DexFile::kNoIndex &&
                dex.typeDescriptor(def.superclassIdx) == "Ljavax/net/ssl/X509ExtendedTrustManager;")
                trustManager = true;
            if (!trustManager && !hostnameVerifier) continue;
            const std::string_view desc = a.classDescriptor(c);
            const std::string library = libraryOf(desc);
            for (const ApkAnalysis::MethodDef& m : a.methodsOf(c)) {
                const std::string_view name = dex.methodName(m.method.methodIdx);
                if (trustManager && name == "checkServerTrusted") {
                    const std::vector<uint8_t> ops = opcodes(m);
                    if (ops.size() == 1 && ops[0] == 0x0e)  // return-void: every chain accepted
                        add("tls-trust-all", Severity::Critical, 85, std::string(DexFile::descriptorToJava(desc)) + ".checkServerTrusted() is empty",
                            {Location::Kind::Method, a.methodSignature(m), 0, -1}, library);
                }
                if (hostnameVerifier && name == "verify") {
                    std::vector<dalvik::Insn> insns;
                    const std::vector<uint8_t> ops = opcodes(m, &insns);
                    // const/4 vA, #1 ; return vA
                    if (ops.size() == 2 && ops[0] == 0x12 && insns[0].hasLiteral && insns[0].literal == 1 && ops[1] == 0x0f)
                        add("tls-hostname-all", Severity::High, 90, std::string(DexFile::descriptorToJava(desc)) + ".verify() always returns true",
                            {Location::Kind::Method, a.methodSignature(m), 0, -1}, library);
                }
            }
        }
    }

    Report finish() {
        std::stable_sort(report_.findings.begin(), report_.findings.end(), [](const Finding& x, const Finding& y) {
            if (x.severity != y.severity) return x.severity > y.severity;
            if (x.library.empty() != y.library.empty()) return x.library.empty();  // app code first
            if (x.confidence != y.confidence) return x.confidence > y.confidence;
            return x.title < y.title;
        });
        if (progress_) progress_->store(100);
        return std::move(report_);
    }

    const Input& in_;
    const std::atomic<bool>* cancel_;
    std::atomic<size_t>* progress_;
    int targetSdk_ = 0;
    Report report_;
    std::set<std::string> seen_;
};

void jsonString(std::string& out, std::string_view s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", c);
                out += b;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

const char* locationKind(Location::Kind k) {
    switch (k) {
    case Location::Kind::Method: return "method";
    case Location::Kind::Class: return "class";
    case Location::Kind::Manifest: return "manifest";
    case Location::Kind::Resource: return "resource";
    case Location::Kind::File: return "file";
    default: return "none";
    }
}

std::string locationText(const Location& l) {
    switch (l.kind) {
    case Location::Kind::Method: {
        char pc[32];
        std::snprintf(pc, sizeof pc, " @ %04x", l.pc);
        return l.ref + pc;
    }
    case Location::Kind::File: return l.line >= 0 ? l.ref + ":" + std::to_string(l.line + 1) : l.ref;
    case Location::Kind::Manifest: return "AndroidManifest.xml: " + l.ref;
    case Location::Kind::Resource: return "@" + l.ref;
    default: return l.ref;
    }
}

}  // namespace

const char* severityName(Severity s) {
    switch (s) {
    case Severity::Info: return "Info";
    case Severity::Low: return "Low";
    case Severity::Medium: return "Medium";
    case Severity::High: return "High";
    case Severity::Critical: return "Critical";
    }
    return "?";
}

const std::vector<Rule>& rules() { return kRules; }

const Rule* rule(const std::string& id) {
    for (const Rule& r : kRules)
        if (id == r.id) return &r;
    return nullptr;
}

bool findSecret(std::string_view s, SecretMatch& out) {
    const auto found = [&](const char* kind, size_t at, size_t len, Severity sev, int conf) {
        out = {kind, std::string(s.substr(at, len)), sev, conf};
        return true;
    };
    // Private keys (PEM).
    if (const size_t p = s.find("-----BEGIN "); p != std::string_view::npos) {
        const size_t e = s.find("PRIVATE KEY-----", p);
        if (e != std::string_view::npos && e - p < 40) return found("private key", p, e + 16 - p, Severity::Critical, 95);
    }
    for (size_t i = 0; i + 8 <= s.size(); ++i) {
        const bool boundary = i == 0 || !isB64Url(s[i - 1]);
        if (!boundary) continue;
        const std::string_view rest = s.substr(i);
        const auto starts = [&](std::string_view p) { return rest.substr(0, p.size()) == p; };
        if (starts("AKIA") || starts("ASIA")) {
            const size_t n = runLength(s, i + 4, [](char c) { return std::isupper(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)); });
            if (n == 16) return found("AWS access key ID", i, 20, Severity::High, 90);
        }
        if (starts("AIza")) {
            const size_t n = runLength(s, i + 4, isB64Url);
            if (n == 35) return found("Google API key", i, 39, Severity::Medium, 90);
        }
        if (starts("sk_live_") || starts("rk_live_")) {
            const size_t n = runLength(s, i + 8, isAlnum);
            if (n >= 24) return found(starts("sk") ? "Stripe secret key" : "Stripe restricted key", i, 8 + n, starts("sk") ? Severity::Critical : Severity::High, 95);
        }
        if (starts("xox") && rest.size() > 5 && std::string_view("abposr").find(rest[3]) != std::string_view::npos && rest[4] == '-') {
            const size_t n = runLength(s, i + 5, [](char c) { return isAlnum(c) || c == '-'; });
            if (n >= 20) return found("Slack token", i, 5 + n, Severity::High, 90);
        }
        if (starts("ghp_") || starts("gho_") || starts("ghs_") || starts("ghu_")) {
            const size_t n = runLength(s, i + 4, isAlnum);
            if (n == 36) return found("GitHub token", i, 40, Severity::High, 95);
        }
        if (starts("github_pat_")) {
            const size_t n = runLength(s, i + 11, isB64Url);
            if (n >= 70) return found("GitHub token", i, 11 + n, Severity::High, 95);
        }
        if (starts("SG.")) {
            const size_t a = runLength(s, i + 3, isB64Url);
            if (a == 22 && i + 3 + a < s.size() && s[i + 3 + a] == '.') {
                const size_t b = runLength(s, i + 4 + a, isB64Url);
                if (b == 43) return found("SendGrid API key", i, 4 + a + b, Severity::High, 95);
            }
        }
        if (starts("key-")) {
            const size_t n = runLength(s, i + 4, isAlnum);
            if (n == 32) return found("Mailgun API key", i, 36, Severity::High, 70);
        }
        if (starts("AAAA")) {  // Firebase Cloud Messaging server key: AAAA<7>:<140>
            const size_t a = runLength(s, i + 4, isB64Url);
            if (a == 7 && i + 11 < s.size() && s[i + 11] == ':') {
                const size_t b = runLength(s, i + 12, isB64Url);
                if (b >= 130) return found("Firebase Cloud Messaging server key", i, 12 + b, Severity::High, 90);
            }
        }
        if (starts("eyJ")) {  // JWT: three base64url segments
            const size_t a = runLength(s, i, isB64Url);
            if (a >= 10 && i + a < s.size() && s[i + a] == '.') {
                const size_t b = runLength(s, i + a + 1, isB64Url);
                if (b >= 10 && rest.substr(a + 1 + b, 1) == "." && s.substr(i + a + 1, 3) == "eyJ") {
                    const size_t c = runLength(s, i + a + 2 + b, isB64Url);
                    if (c >= 10) return found("JSON Web Token", i, a + b + c + 2, Severity::Medium, 75);
                }
            }
        }
        if (starts("SK") && runLength(s, i + 2, [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }) == 32 &&
            (i + 34 == s.size() || !isAlnum(s[i + 34])))
            return found("Twilio API key", i, 34, Severity::High, 60);
    }
    return false;
}

Report scan(const Input& in, const std::atomic<bool>* cancel, std::atomic<size_t>* progress) {
    return Scanner(in, cancel, progress).run();
}

std::string toMarkdown(const Report& r, const ApkInfo& info) {
    std::string out = "# Security report: " + (info.appLabel.empty() ? info.packageName : info.appLabel) + "\n\n";
    out += "- Package: `" + info.packageName + "` " + info.versionName + " (" + info.versionCode + ")\n";
    out += "- SDK: min " + info.minSdk + ", target " + info.targetSdk + "\n";
    out += "- Scanned: " + std::to_string(r.methodsScanned) + " methods, " + std::to_string(r.stringsScanned) + " strings, " +
           std::to_string(r.filesScanned) + " files\n\n";
    out += "| Severity | Findings |\n| --- | --- |\n";
    for (int s = static_cast<int>(Severity::Critical); s >= 0; --s) {
        const auto n = std::count_if(r.findings.begin(), r.findings.end(), [&](const Finding& f) { return static_cast<int>(f.severity) == s; });
        out += "| " + std::string(severityName(static_cast<Severity>(s))) + " | " + std::to_string(n) + " |\n";
    }
    std::string lastRule;
    for (const Finding& f : r.findings) {
        const Rule* ru = rule(f.rule);
        out += "\n## [" + std::string(severityName(f.severity)) + "] " + f.title + "\n\n";
        if (ru) out += std::string(ru->description) + "\n\n";
        out += "- Evidence: `" + f.evidence + "`\n";
        out += "- Location: `" + locationText(f.location) + "`\n";
        if (!f.library.empty()) out += "- Library: " + f.library + "\n";
        out += "- Confidence: " + std::to_string(f.confidence) + "%\n";
        if (ru) {
            out += "- " + std::string(ru->cwe) + ", " + ru->masvs + "\n";
            out += "- Fix: " + std::string(ru->recommendation) + "\n";
        }
    }
    return out;
}

std::string toJson(const Report& r, const ApkInfo& info) {
    std::string out = "{\n  \"package\": ";
    jsonString(out, info.packageName);
    out += ",\n  \"version\": ";
    jsonString(out, info.versionName);
    out += ",\n  \"methods_scanned\": " + std::to_string(r.methodsScanned) + ",\n  \"findings\": [";
    for (size_t i = 0; i < r.findings.size(); ++i) {
        const Finding& f = r.findings[i];
        const Rule* ru = rule(f.rule);
        out += i ? ",\n    {" : "\n    {";
        out += "\"rule\": ";
        jsonString(out, f.rule);
        out += ", \"title\": ";
        jsonString(out, f.title);
        out += ", \"severity\": ";
        jsonString(out, severityName(f.severity));
        out += ", \"confidence\": " + std::to_string(f.confidence) + ", \"category\": ";
        jsonString(out, ru ? ru->category : "");
        out += ", \"cwe\": ";
        jsonString(out, ru ? ru->cwe : "");
        out += ", \"masvs\": ";
        jsonString(out, ru ? ru->masvs : "");
        out += ", \"evidence\": ";
        jsonString(out, f.evidence);
        out += ", \"location\": {\"kind\": ";
        jsonString(out, locationKind(f.location.kind));
        out += ", \"ref\": ";
        jsonString(out, f.location.ref);
        if (f.location.kind == Location::Kind::Method) out += ", \"pc\": " + std::to_string(f.location.pc);
        if (f.location.line >= 0) out += ", \"line\": " + std::to_string(f.location.line + 1);
        out += "}, \"library\": ";
        jsonString(out, f.library);
        out += "}";
    }
    out += "\n  ]\n}\n";
    return out;
}

}  // namespace security
