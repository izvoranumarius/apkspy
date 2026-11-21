// Tests for src/analysis/Insights.hpp (secrets, SDKs, frameworks, rules,
// obfuscation, JSON/SARIF) and src/analysis/Mapping.hpp (mapping.txt +
// retrace). Pure in-memory fixtures.
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>
#include "analysis/Insights.hpp"
#include "analysis/Mapping.hpp"

static int failures = 0;
static int passes = 0;
#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (cond) {                                               \
            ++passes;                                             \
        } else {                                                  \
            std::printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
            ++failures;                                           \
        }                                                         \
    } while (0)

namespace {

bool contains(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

template <class V, class P>
bool any(const V& v, P p) {
    return std::any_of(v.begin(), v.end(), p);
}

void testSecrets() {
    const std::vector<std::string> s = {
        "AKIAIOSFODNN7EXAMPLE",                                 // AWS
        "key=AIzaSyA-1234567890abcdefghijklmnopqrstu",          // Google API key (35 after AIza)
        "https://my-app-default-rtdb.firebaseio.com/users",     // Firebase
        "ghp_" "0123456789abcdefghijABCDEFGHIJ012345",          // GitHub (36); split literal so it isn't a live-looking token on disk
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",             // private key
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc_DEF-123",  // JWT
        "SK" "0123456789abcdef0123456789abcdef",                // Twilio (split literal)
        "sk_live_" "51H8abcdefghijklmnopqrstuvwx",              // Stripe (split literal)
        "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawZ",        // Telegram (33 after AA)
        "XAKIAIOSFODNN7EXAMPLE",                                // no boundary: ignored
        "AKIAIOSFODNN7EXAMPLE1",                                // too long: ignored
        "plain text with AIza but short",
        "AKIAIOSFODNN7EXAMPLE",                                 // duplicate: reported once
    };
    const auto r = insights::findSecrets(s);
    const auto has = [&](const char* kind) { return any(r, [&](const insights::Secret& x) { return x.kind == kind; }); };
    CHECK(has("AWS access key ID"), "AWS key");
    CHECK(has("Google API key"), "Google API key");
    CHECK(has("Firebase Realtime Database URL") &&
              any(r, [](const insights::Secret& x) { return x.value == "my-app-default-rtdb.firebaseio.com"; }),
          "Firebase host extracted");
    CHECK(has("GitHub token") && has("Private key") && has("JSON Web Token"), "GitHub, private key, JWT");
    CHECK(has("Twilio API key") && has("Stripe secret key") && has("Telegram bot token"), "Twilio, Stripe, Telegram");
    CHECK(std::count_if(r.begin(), r.end(), [](const insights::Secret& x) { return x.kind == "AWS access key ID"; }) == 1,
          "boundaries respected, duplicates merged");
    CHECK(r.size() == 9, "exact number of findings");
    CHECK(insights::mask("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE" && insights::mask("short") == "*****", "masking");
}

void testSdksAndFrameworks() {
    insights::Inputs in;
    in.classes = {"Lcom/google/firebase/analytics/FirebaseAnalytics;", "Lcom/appsflyer/AppsFlyerLib;", "Lcom/appsflyer/a;",
                  "Lokhttp3/OkHttpClient;", "Lio/flutter/embedding/engine/FlutterEngine;", "Lkotlin/Unit;",
                  "Lcom/app/Main;"};
    in.files = {"AndroidManifest.xml", "classes.dex", "classes2.dex", "lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so",
                "lib/arm64-v8a/libjiagu_a64.so", "assets/index.android.bundle", "lib/arm64-v8a/libhermes.so"};
    const auto sdks = insights::detectSdks(in.classes);
    CHECK(sdks.size() == 3 && sdks[0].tracker && sdks.back().name == "OkHttp", "SDKs found, trackers first");
    CHECK(any(sdks, [](const insights::Sdk& s) { return s.name == "AppsFlyer" && s.classes == 2; }), "class count per SDK");
    const auto d = insights::detectFrameworks(in);
    const auto has = [&](const char* n) { return any(d, [&](const insights::Detection& x) { return x.name == n; }); };
    CHECK(has("Flutter") && has("Flutter (Dart AOT snapshot)") && has("React Native (Hermes engine)") &&
              has("React Native (JS bundle)"),
          "frameworks from files");
    CHECK(has("Jiagu (Qihoo 360)") && d.front().kind == "Packer", "packer detected and listed first");
    CHECK(has("Kotlin") && has("Multidex"), "language and packaging");
    CHECK(std::count_if(d.begin(), d.end(), [](const insights::Detection& x) { return x.name == "Flutter"; }) == 1,
          "file + class evidence: one entry");
}

void testRules() {
    insights::Inputs in;
    in.methodRefs = {"Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V",
                     "Landroid/webkit/SslErrorHandler;->proceed()V",
                     "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                     "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;",
                     "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
                     "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"};
    in.strings = {"AES/ECB/PKCS5Padding", "DESede", "MD5", "http://api.example.com/v1", "http://schemas.android.com/apk/res/android",
                  "/system/xbin/su"};
    const auto r = insights::runRules(in);
    const auto find = [&](const char* id) -> const insights::RuleHit* {
        for (const auto& h : r)
            if (h.id == id) return &h;
        return nullptr;
    };
    CHECK(find("webview-js-interface") && find("webview-ssl-proceed") && find("dynamic-code") && find("logging"), "API rules");
    CHECK(find("cipher-ecb") && find("cipher-weak") && find("weak-hash"), "constant-based crypto rules");
    CHECK(find("cleartext-url") && find("cleartext-url")->matched.size() == 1, "cleartext URL, schema URLs ignored");
    CHECK(find("root-checks") != nullptr, "root check markers");
    CHECK(!find("webview-js-enabled") && !find("raw-sql"), "no rule without its API");
    CHECK(r.front().severity == insights::Severity::High && r.back().severity == insights::Severity::Info, "ordered by severity");

    insights::Inputs none;
    none.strings = {"AES/ECB/PKCS5Padding"};
    CHECK(insights::runRules(none).empty(), "constants alone trigger nothing");
}

void testObfuscation() {
    std::vector<std::string> cls = {"Lcom/app/a;", "Lcom/app/b;", "Lcom/app/c$a;", "Lcom/app/MainActivity;",
                                    "Landroidx/core/a;", "Lkotlin/a;"};
    const auto o = insights::estimateObfuscation(cls);
    CHECK(o.appClasses == 4 && o.shortNames == 3 && std::string(o.verdict) == "heavy", "short names outside libraries");
    CHECK(std::string(insights::estimateObfuscation({"Lcom/app/MainActivity;", "Lcom/app/Settings;"}).verdict) == "none",
          "readable names");
}

void testExport() {
    insights::Inputs in;
    in.strings = {"AKIAIOSFODNN7EXAMPLE", "a \"quoted\"\nline"};
    in.methodRefs = {"Landroid/webkit/SslErrorHandler;->proceed()V"};
    in.files = {"lib/x86/libjiagu.so"};
    const auto r = insights::scan(in);
    const std::string j = insights::toJson(r, "app.apk");
    CHECK(contains(j, "\"apk\": \"app.apk\"") && contains(j, "AKIA************MPLE") && !contains(j, "AKIAIOSFODNN7EXAMPLE"),
          "JSON masks secrets");
    CHECK(contains(j, "\"id\": \"webview-ssl-proceed\"") && contains(j, "\"kind\": \"Packer\""), "JSON contents");
    const std::string s = insights::toSarif(r, "app.apk");
    CHECK(contains(s, "\"version\": \"2.1.0\"") && contains(s, "\"ruleId\": \"secret/aws-access-key-id\"") &&
              contains(s, "\"level\": \"error\"") && contains(s, "\"ruleId\": \"packer\"") && !contains(s, "IOSFODNN7"),
          "SARIF rules, levels, masking");
    int depth = 0;
    bool balanced = true, inStr = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (inStr) {
            if (c == '\\') ++i;
            else if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') inStr = true;
        else if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') balanced &= --depth >= 0;
    }
    CHECK(balanced && depth == 0 && !inStr, "SARIF is balanced JSON");
}

void testMapping() {
    const char* text =
        "# compiler: R8\n"
        "com.example.app.MainActivity -> a.a:\n"
        "    java.lang.String TAG -> a\n"
        "    1:4:void onCreate(android.os.Bundle):20:23 -> onCreate\n"
        "    5:5:void helper():40 -> b\n"
        "    6:6:void other():50 -> b\n"
        "    void load() -> c\n"
        "com.example.app.net.Client -> a.b:\n"
        "    3:3:java.lang.String fetch(java.lang.String):88:88 -> a\n"
        "garbage line\n";
    const auto m = mapping::parse(text);
    CHECK(m.byObfuscated.size() == 2 && m.errors == 1, "classes parsed, bad line counted");
    CHECK(m.originalClass("a.a") == "com.example.app.MainActivity" && m.originalClass("zz") == "zz", "class lookup");
    CHECK(m.originalClass("a.a$1") == "com.example.app.MainActivity$1", "inner class of a mapped class");
    CHECK(m.originalMethod("a.a", "b", 5) == "helper" && m.originalMethod("a.a", "b", 6) == "other", "line range picks the method");
    CHECK(m.originalMethod("a.a", "b", 0) == "helper|other", "ambiguous without a line");
    CHECK(m.originalLine("a.a", "onCreate", 3) == 22 && m.originalLine("a.a", "b", 5) == 40, "line mapping");
    CHECK(m.originalToObfuscated.at("com.example.app.net.Client") == "a.b", "reverse map");

    const std::string trace =
        "java.lang.IllegalStateException: boom\n"
        "\tat a.b.a(SourceFile:3)\n"
        "\tat a.a.onCreate(SourceFile:2)\n"
        "\tat android.app.Activity.performCreate(Activity.java:8000)\n"
        "Caused by: a.b: inner\n";
    const std::string out = mapping::retrace(m, trace);
    CHECK(contains(out, "\tat com.example.app.net.Client.fetch(Client.java:88)\n"), "frame retraced");
    CHECK(contains(out, "\tat com.example.app.MainActivity.onCreate(MainActivity.java:21)\n"), "line mapped in range");
    CHECK(contains(out, "\tat android.app.Activity.performCreate(Activity.java:8000)\n"), "unmapped frame untouched");
    CHECK(contains(out, "Caused by: com.example.app.net.Client: inner") && contains(out, "java.lang.IllegalStateException: boom"),
          "class names in messages");
}

void testPermissions() {
    const std::vector<std::string> perms = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA",
                                            "android.permission.INTERNET"};
    const std::vector<std::string> refs = {
        "Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;",
        "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",  // READ_PHONE_STATE, NOT requested
        "Ljava/lang/String;->length()I"};
    const auto used = insights::permissionUsage(perms, refs);
    const auto find = [&](const std::vector<insights::PermissionUse>& v, const char* p) -> const insights::PermissionUse* {
        for (const auto& u : v)
            if (u.permission == p) return &u;
        return nullptr;
    };
    const auto* loc = find(used, "android.permission.ACCESS_FINE_LOCATION");
    CHECK(loc && loc->apis.size() == 1, "location permission: one API used");
    const auto* cam = find(used, "android.permission.CAMERA");
    CHECK(cam && cam->apis.empty(), "camera requested but unused");
    CHECK(!find(used, "android.permission.READ_PHONE_STATE"), "non-requested permission not in usage view");

    const auto missing = insights::missingPermissions(perms, refs);
    const auto* phone = find(missing, "android.permission.READ_PHONE_STATE");
    CHECK(phone && phone->apis.size() == 1, "getDeviceId flagged: READ_PHONE_STATE used without the permission");
    CHECK(!find(missing, "android.permission.ACCESS_FINE_LOCATION"), "requested permission not in missing view");
}

}  // namespace

int main() {
    std::printf("insights tests\n");
    testSecrets();
    testSdksAndFrameworks();
    testRules();
    testObfuscation();
    testExport();
    testMapping();
    testPermissions();
    std::printf("%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
