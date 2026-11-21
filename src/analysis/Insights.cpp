#include "analysis/Insights.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>

namespace insights {

const char* severityName(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
    }
    return "info";
}

namespace {

bool isAlnum(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool isWordish(char c) { return isAlnum(c) || c == '_' || c == '-'; }
bool isLowerHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
bool isUpperAlnum(char c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }
bool isLowerAlnum(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }

bool startsWith(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }
bool endsWith(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0; }
bool contains(std::string_view s, std::string_view p) { return s.find(p) != std::string_view::npos; }

// Counts characters of `pred` starting at `pos`, up to `max`.
template <class Pred>
size_t run(std::string_view s, size_t pos, size_t max, Pred pred) {
    size_t n = 0;
    while (pos + n < s.size() && n < max && pred(s[pos + n])) ++n;
    return n;
}

struct Pattern {
    const char* kind;
    const char* prefix;
    bool (*body)(char);
    size_t minLen, maxLen;    // body length range
    bool boundaryBefore;      // previous char must not be alphanumeric
    Severity severity;
};

bool wordChar(char c) { return isWordish(c); }
bool alnumChar(char c) { return isAlnum(c); }
bool githubPat(char c) { return isAlnum(c) || c == '_'; }

const Pattern kPatterns[] = {
    {"AWS access key ID", "AKIA", isUpperAlnum, 16, 16, true, Severity::High},
    {"AWS temporary access key ID", "ASIA", isUpperAlnum, 16, 16, true, Severity::High},
    {"Google API key", "AIza", wordChar, 35, 35, true, Severity::Medium},
    {"GitHub token", "ghp_", alnumChar, 36, 36, true, Severity::High},
    {"GitHub OAuth token", "gho_", alnumChar, 36, 36, true, Severity::High},
    {"GitHub app token", "ghs_", alnumChar, 36, 36, true, Severity::High},
    {"GitHub fine-grained token", "github_pat_", githubPat, 70, 100, true, Severity::High},
    {"Slack bot token", "xoxb-", wordChar, 10, 120, true, Severity::High},
    {"Slack user token", "xoxp-", wordChar, 10, 120, true, Severity::High},
    {"Slack app token", "xapp-", wordChar, 10, 120, true, Severity::High},
    {"Stripe secret key", "sk_live_", alnumChar, 20, 120, true, Severity::High},
    {"Stripe restricted key", "rk_live_", alnumChar, 20, 120, true, Severity::High},
    {"Stripe publishable key", "pk_live_", alnumChar, 20, 120, true, Severity::Low},
    {"Square access token", "sq0atp-", wordChar, 22, 22, true, Severity::High},
    {"Square OAuth secret", "sq0csp-", wordChar, 43, 43, true, Severity::High},
    {"Mailgun API key", "key-", isLowerAlnum, 32, 32, true, Severity::Medium},
    {"OpenAI API key", "sk-proj-", wordChar, 40, 200, true, Severity::High},
    {"Anthropic API key", "sk-ant-", wordChar, 40, 200, true, Severity::High},
    {"Facebook access token", "EAACEdEose0cBA", alnumChar, 20, 300, true, Severity::High},
    {"Slack webhook", "https://hooks.slack.com/services/", [](char c) { return isAlnum(c) || c == '/' || c == '_'; }, 20, 120, false,
     Severity::Medium},
    {"Discord webhook", "https://discord.com/api/webhooks/", [](char c) { return isWordish(c) || c == '/'; }, 20, 140, false,
     Severity::Medium},
};

void add(std::vector<Secret>& out, std::set<std::pair<std::string, std::string>>& seen, const char* kind, std::string value,
         size_t index, Severity sev) {
    if (!seen.insert({kind, value}).second) return;
    out.push_back({kind, std::move(value), index, sev});
}

void scanString(std::string_view s, size_t index, std::vector<Secret>& out, std::set<std::pair<std::string, std::string>>& seen) {
    for (const Pattern& p : kPatterns) {
        const std::string_view prefix = p.prefix;
        for (size_t pos = s.find(prefix); pos != std::string_view::npos; pos = s.find(prefix, pos + 1)) {
            if (p.boundaryBefore && pos > 0 && isAlnum(s[pos - 1])) continue;
            const size_t n = run(s, pos + prefix.size(), p.maxLen + 1, p.body);
            if (n < p.minLen || n > p.maxLen) continue;
            const size_t end = pos + prefix.size() + n;
            // Fixed-length tokens must end there.
            if (p.minLen == p.maxLen && end < s.size() && isAlnum(s[end])) continue;
            add(out, seen, p.kind, std::string(s.substr(pos, end - pos)), index, p.severity);
        }
    }
    // Twilio API key: "SK" + 32 lowercase hex, standalone.
    for (size_t pos = s.find("SK"); pos != std::string_view::npos; pos = s.find("SK", pos + 1)) {
        if (pos > 0 && isAlnum(s[pos - 1])) continue;
        const size_t n = run(s, pos + 2, 33, isLowerHex);
        if (n == 32 && (pos + 34 == s.size() || !isAlnum(s[pos + 34])))
            add(out, seen, "Twilio API key", std::string(s.substr(pos, 34)), index, Severity::High);
    }
    // SendGrid: SG.<22>.<43>
    for (size_t pos = s.find("SG."); pos != std::string_view::npos; pos = s.find("SG.", pos + 1)) {
        const size_t a = run(s, pos + 3, 23, wordChar);
        if (a != 22 || pos + 25 >= s.size() || s[pos + 25] != '.') continue;
        const size_t b = run(s, pos + 26, 44, wordChar);
        if (b == 43) add(out, seen, "SendGrid API key", std::string(s.substr(pos, 69)), index, Severity::High);
    }
    // Private keys.
    if (const size_t b = s.find("-----BEGIN "); b != std::string_view::npos) {
        const size_t e = s.find("PRIVATE KEY-----", b);
        if (e != std::string_view::npos && e - b < 40)
            add(out, seen, "Private key", std::string(s.substr(b, e + 16 - b)), index, Severity::High);
    }
    // JWT: eyJ<header>.eyJ<payload>.<signature>
    for (size_t pos = s.find("eyJ"); pos != std::string_view::npos; pos = s.find("eyJ", pos + 1)) {
        if (pos > 0 && isWordish(s[pos - 1])) continue;
        const size_t h = run(s, pos, 2000, wordChar);
        const size_t dot1 = pos + h;
        if (h < 10 || dot1 >= s.size() || s[dot1] != '.' || !startsWith(s.substr(dot1 + 1), "eyJ")) continue;
        const size_t p = run(s, dot1 + 1, 4000, wordChar);
        const size_t dot2 = dot1 + 1 + p;
        if (p < 10 || dot2 >= s.size() || s[dot2] != '.') continue;
        const size_t sig = run(s, dot2 + 1, 2000, wordChar);
        add(out, seen, "JSON Web Token", std::string(s.substr(pos, dot2 + 1 + sig - pos)), index, Severity::Medium);
        pos = dot2 + sig;
    }
    // Hosts: Firebase Realtime Database, Google OAuth client IDs.
    const auto host = [&](std::string_view suffix, const char* kind, Severity sev) {
        for (size_t pos = s.find(suffix); pos != std::string_view::npos; pos = s.find(suffix, pos + 1)) {
            size_t b = pos;
            while (b > 0 && (isLowerAlnum(s[b - 1]) || s[b - 1] == '-' || s[b - 1] == '.')) --b;
            if (b == pos) continue;
            add(out, seen, kind, std::string(s.substr(b, pos + suffix.size() - b)), index, sev);
        }
    };
    host(".firebaseio.com", "Firebase Realtime Database URL", Severity::Low);
    host(".apps.googleusercontent.com", "Google OAuth client ID", Severity::Info);
    // Google service-account JSON embedded in the app.
    if (contains(s, "\"type\"") && contains(s, "service_account") && contains(s, "private_key"))
        add(out, seen, "Google service account JSON", std::string(s.substr(0, std::min<size_t>(s.size(), 80))), index, Severity::High);
    // Telegram bot token: <8-10 digits>:AA<33 word chars>
    for (size_t pos = s.find(":AA"); pos != std::string_view::npos; pos = s.find(":AA", pos + 1)) {
        size_t b = pos;
        while (b > 0 && std::isdigit(static_cast<unsigned char>(s[b - 1]))) --b;
        const size_t digits = pos - b;
        const size_t n = run(s, pos + 3, 34, wordChar);
        if (digits >= 8 && digits <= 10 && n == 33 && (b == 0 || !isAlnum(s[b - 1])))
            add(out, seen, "Telegram bot token", std::string(s.substr(b, pos + 36 - b)), index, Severity::High);
    }
}

struct SdkDef {
    const char* prefix;
    const char* name;
    const char* category;
    bool tracker;
};

const SdkDef kSdks[] = {
    {"Lcom/google/firebase/analytics/", "Firebase Analytics", "Analytics", true},
    {"Lcom/google/android/gms/measurement/", "Google Analytics for Firebase (measurement)", "Analytics", true},
    {"Lcom/google/firebase/crashlytics/", "Firebase Crashlytics", "Crash reporting", true},
    {"Lcom/crashlytics/", "Crashlytics (legacy)", "Crash reporting", true},
    {"Lcom/google/firebase/perf/", "Firebase Performance Monitoring", "Analytics", true},
    {"Lcom/google/firebase/messaging/", "Firebase Cloud Messaging", "Push", false},
    {"Lcom/google/firebase/auth/", "Firebase Authentication", "Identity", false},
    {"Lcom/google/firebase/firestore/", "Cloud Firestore", "Backend", false},
    {"Lcom/google/firebase/database/", "Firebase Realtime Database", "Backend", false},
    {"Lcom/google/firebase/remoteconfig/", "Firebase Remote Config", "Backend", false},
    {"Lcom/google/firebase/storage/", "Firebase Storage", "Backend", false},
    {"Lcom/google/android/gms/ads/", "Google AdMob", "Advertising", true},
    {"Lcom/google/ads/", "Google Ads", "Advertising", true},
    {"Lcom/google/android/gms/analytics/", "Google Analytics", "Analytics", true},
    {"Lcom/google/android/gms/maps/", "Google Maps", "Maps", false},
    {"Lcom/google/android/gms/auth/", "Google Sign-In", "Identity", false},
    {"Lcom/google/android/gms/safetynet/", "SafetyNet", "Security", false},
    {"Lcom/google/android/play/core/integrity/", "Play Integrity", "Security", false},
    {"Lcom/google/android/recaptcha/", "reCAPTCHA", "Security", false},
    {"Lcom/facebook/appevents/", "Facebook Analytics (App Events)", "Analytics", true},
    {"Lcom/facebook/ads/", "Facebook Audience Network", "Advertising", true},
    {"Lcom/facebook/login/", "Facebook Login", "Identity", false},
    {"Lcom/appsflyer/", "AppsFlyer", "Attribution", true},
    {"Lcom/adjust/sdk/", "Adjust", "Attribution", true},
    {"Lio/branch/", "Branch", "Attribution", true},
    {"Lcom/kochava/", "Kochava", "Attribution", true},
    {"Lcom/singular/sdk/", "Singular", "Attribution", true},
    {"Lcom/mixpanel/", "Mixpanel", "Analytics", true},
    {"Lcom/amplitude/", "Amplitude", "Analytics", true},
    {"Lcom/segment/analytics/", "Segment", "Analytics", true},
    {"Lcom/flurry/", "Flurry", "Analytics", true},
    {"Lcom/yandex/metrica/", "AppMetrica (Yandex)", "Analytics", true},
    {"Lcom/heapanalytics/", "Heap", "Analytics", true},
    {"Lcom/smartlook/", "Smartlook", "Session replay", true},
    {"Lcom/uxcam/", "UXCam", "Session replay", true},
    {"Lio/sentry/", "Sentry", "Crash reporting", true},
    {"Lcom/bugsnag/", "Bugsnag", "Crash reporting", true},
    {"Lcom/instabug/", "Instabug", "Crash reporting", true},
    {"Lcom/microsoft/appcenter/", "Visual Studio App Center", "Crash reporting", true},
    {"Lcom/newrelic/", "New Relic", "Performance", true},
    {"Lcom/datadog/", "Datadog", "Performance", true},
    {"Lcom/applovin/", "AppLovin", "Advertising", true},
    {"Lcom/unity3d/ads/", "Unity Ads", "Advertising", true},
    {"Lcom/ironsource/", "ironSource", "Advertising", true},
    {"Lcom/vungle/", "Vungle (Liftoff)", "Advertising", true},
    {"Lcom/chartboost/", "Chartboost", "Advertising", true},
    {"Lcom/inmobi/", "InMobi", "Advertising", true},
    {"Lcom/mbridge/", "Mintegral", "Advertising", true},
    {"Lcom/bytedance/sdk/openadsdk/", "Pangle", "Advertising", true},
    {"Lcom/startapp/", "Start.io", "Advertising", true},
    {"Lcom/tiktok/", "TikTok Business SDK", "Attribution", true},
    {"Lcom/onesignal/", "OneSignal", "Push", true},
    {"Lcom/braze/", "Braze", "Engagement", true},
    {"Lcom/appboy/", "Braze (Appboy)", "Engagement", true},
    {"Lcom/clevertap/", "CleverTap", "Engagement", true},
    {"Lcom/huawei/hms/", "Huawei Mobile Services", "Platform", false},
    {"Lcom/stripe/android/", "Stripe", "Payments", false},
    {"Lcom/paypal/", "PayPal", "Payments", false},
    {"Lcom/braintreepayments/", "Braintree", "Payments", false},
    {"Lcom/auth0/", "Auth0", "Identity", false},
    {"Lcom/snapchat/kit/", "Snap Kit", "Identity", false},
    {"Lokhttp3/", "OkHttp", "Networking", false},
    {"Lretrofit2/", "Retrofit", "Networking", false},
    {"Lcom/android/volley/", "Volley", "Networking", false},
    {"Lio/ktor/", "Ktor", "Networking", false},
    {"Lcom/bumptech/glide/", "Glide", "Images", false},
    {"Lcom/squareup/picasso/", "Picasso", "Images", false},
    {"Lcoil/", "Coil", "Images", false},
    {"Lcom/google/gson/", "Gson", "Serialization", false},
    {"Lcom/squareup/moshi/", "Moshi", "Serialization", false},
    {"Lio/reactivex/", "RxJava", "Concurrency", false},
    {"Lio/realm/", "Realm", "Database", false},
    {"Lnet/sqlcipher/", "SQLCipher", "Security", false},
    {"Lnet/zetetic/database/sqlcipher/", "SQLCipher", "Security", false},
    {"Lorg/bouncycastle/", "Bouncy Castle", "Security", false},
    {"Ldagger/", "Dagger / Hilt", "Dependency injection", false},
    {"Lorg/koin/", "Koin", "Dependency injection", false},
};

// Packages whose classes are libraries (for the obfuscation estimate).
const char* const kLibraryPrefixes[] = {"Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/", "Lcom/google/",
                                        "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lio/reactivex/", "Lcom/facebook/", "Lorg/",
                                        "Lcom/squareup/", "Ldagger/", "Lcom/bumptech/", "Lio/flutter/", "Lcom/android/",
                                        "Ldalvik/", "Lj$/", "Lcoil/", "Lio/ktor/"};

bool isLibrary(std::string_view d) {
    for (const char* p : kLibraryPrefixes)
        if (startsWith(d, p)) return true;
    for (const SdkDef& s : kSdks)
        if (startsWith(d, s.prefix)) return true;
    return false;
}

std::string fileName(std::string_view path) {
    const size_t s = path.find_last_of('/');
    return std::string(s == std::string_view::npos ? path : path.substr(s + 1));
}

struct FileRule {
    const char* match;  // file name (exact) or path prefix ending in '/' or suffix starting with '*'
    const char* name;
    const char* kind;
};

const FileRule kFileRules[] = {
    {"libflutter.so", "Flutter", "Framework"},
    {"libapp.so", "Flutter (Dart AOT snapshot)", "Framework"},
    {"assets/index.android.bundle", "React Native (JS bundle)", "Framework"},
    {"libhermes.so", "React Native (Hermes engine)", "Framework"},
    {"libreactnativejni.so", "React Native", "Framework"},
    {"libmonodroid.so", "Xamarin / .NET for Android", "Framework"},
    {"libxamarin-app.so", "Xamarin / .NET for Android", "Framework"},
    {"libmonosgen-2.0.so", ".NET (Mono runtime)", "Framework"},
    {"libunity.so", "Unity", "Framework"},
    {"libil2cpp.so", "Unity (IL2CPP)", "Framework"},
    {"global-metadata.dat", "Unity IL2CPP metadata", "Framework"},
    {"libUE4.so", "Unreal Engine 4", "Framework"},
    {"libUnreal.so", "Unreal Engine", "Framework"},
    {"libgodot_android.so", "Godot", "Framework"},
    {"libcocos2dcpp.so", "Cocos2d-x", "Framework"},
    {"libcocos2djs.so", "Cocos2d-x (JS)", "Framework"},
    {"libcocos.so", "Cocos Creator", "Framework"},
    {"libNativeScript.so", "NativeScript", "Framework"},
    {"libQt5Core_arm64-v8a.so", "Qt 5", "Framework"},
    {"libQt6Core_arm64-v8a.so", "Qt 6", "Framework"},
    {"libcorona.so", "Solar2D (Corona)", "Framework"},
    {"assets/www/cordova.js", "Apache Cordova", "Framework"},
    {"assets/public/capacitor.config.json", "Capacitor (Ionic)", "Framework"},
    {"libjiagu.so", "Jiagu (Qihoo 360)", "Packer"},
    {"libjiagu_x86.so", "Jiagu (Qihoo 360)", "Packer"},
    {"libjiagu_a64.so", "Jiagu (Qihoo 360)", "Packer"},
    {"libDexHelper.so", "SecNeo / Bangcle DexHelper", "Packer"},
    {"libDexHelper-x86.so", "SecNeo / Bangcle DexHelper", "Packer"},
    {"libsecexe.so", "Bangcle", "Packer"},
    {"libsecmain.so", "Bangcle", "Packer"},
    {"libshella.so", "Tencent Legu", "Packer"},
    {"libshellx.so", "Tencent Legu", "Packer"},
    {"libtup.so", "Tencent Legu", "Packer"},
    {"libexec.so", "Ijiami", "Packer"},
    {"libexecmain.so", "Ijiami", "Packer"},
    {"libmobisec.so", "Alibaba security", "Packer"},
    {"libsgmain.so", "Alibaba security guard", "Packer"},
    {"libbaiduprotect.so", "Baidu protection", "Packer"},
    {"libnqshield.so", "NQ Shield", "Packer"},
    {"libcovault-appsec.so", "AppSealing", "Packer"},
};

struct ClassRule {
    const char* prefix;
    const char* name;
    const char* kind;
};

const ClassRule kClassRules[] = {
    {"Lio/flutter/", "Flutter", "Framework"},
    {"Lcom/facebook/react/", "React Native", "Framework"},
    {"Lcom/facebook/hermes/", "React Native (Hermes engine)", "Framework"},
    {"Lmono/android/", "Xamarin / .NET for Android", "Framework"},
    {"Lcom/unity3d/player/", "Unity", "Framework"},
    {"Lorg/apache/cordova/", "Apache Cordova", "Framework"},
    {"Lcom/getcapacitor/", "Capacitor (Ionic)", "Framework"},
    {"Lorg/godotengine/", "Godot", "Framework"},
    {"Lorg/qtproject/", "Qt", "Framework"},
    {"Lanywheresoftware/b4a/", "B4A", "Framework"},
    {"Lio/dcloud/", "uni-app (DCloud)", "Framework"},
    {"Lkotlin/", "Kotlin", "Language"},
    {"Landroidx/compose/", "Jetpack Compose", "UI toolkit"},
    {"Lorg/jetbrains/compose/", "Compose Multiplatform", "UI toolkit"},
    {"Lcom/guardsquare/dexguard/", "DexGuard runtime", "Packer"},
    {"Lcom/stub/StubApp;", "Jiagu stub application", "Packer"},
    {"Lcom/secneo/", "SecNeo / Bangcle", "Packer"},
    {"Lcom/tencent/StubShell/", "Tencent Legu", "Packer"},
};

struct Api {
    const char* id;
    Severity severity;
    const char* title;
    const char* masvs;
    const char* detail;
    std::vector<const char*> refs;  // "Lclass;->name(" prefixes
};

const std::vector<Api>& apis() {
    static const std::vector<Api> k = {
        {"webview-js-interface", Severity::Medium, "WebView JavaScript bridge", "MASVS-PLATFORM-2",
         "addJavascriptInterface exposes Java objects to page JavaScript; any page the WebView loads can call them.",
         {"Landroid/webkit/WebView;->addJavascriptInterface("}},
        {"webview-file-access", Severity::High, "WebView file:// cross-origin access", "MASVS-PLATFORM-2",
         "Allowing file URLs to read other origins lets a local page exfiltrate app files.",
         {"Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(", "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs("}},
        {"webview-ssl-proceed", Severity::High, "WebView ignores TLS errors", "MASVS-NETWORK-1",
         "SslErrorHandler.proceed() continues loading after a certificate error.",
         {"Landroid/webkit/SslErrorHandler;->proceed("}},
        {"webview-js-enabled", Severity::Low, "JavaScript enabled in a WebView", "MASVS-PLATFORM-2",
         "Review which content the WebView loads.", {"Landroid/webkit/WebSettings;->setJavaScriptEnabled("}},
        {"webview-debugging", Severity::Low, "WebView remote debugging switch", "MASVS-RESILIENCE-2",
         "setWebContentsDebuggingEnabled(true) in release builds exposes WebView contents over DevTools.",
         {"Landroid/webkit/WebView;->setWebContentsDebuggingEnabled("}},
        {"hostname-verifier", Severity::Medium, "Custom hostname verification", "MASVS-NETWORK-1",
         "Replacing the hostname verifier is a common way TLS validation gets disabled; check the implementation.",
         {"Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(", "Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier("}},
        {"custom-trust", Severity::Info, "Custom TLS trust setup", "MASVS-NETWORK-1",
         "SSLContext.init with custom trust managers; check they still validate certificates.",
         {"Ljavax/net/ssl/SSLContext;->init("}},
        {"dynamic-code", Severity::Medium, "Dynamic code loading", "MASVS-CODE-4",
         "Code loaded at run time is not visible to static analysis and may come from writable storage.",
         {"Ldalvik/system/DexClassLoader;-><init>(", "Ldalvik/system/InMemoryDexClassLoader;-><init>(",
          "Ldalvik/system/PathClassLoader;-><init>("}},
        {"runtime-exec", Severity::Low, "Shell command execution", "MASVS-CODE-4", "Runtime.exec / ProcessBuilder start processes.",
         {"Ljava/lang/Runtime;->exec(", "Ljava/lang/ProcessBuilder;->start("}},
        {"raw-sql", Severity::Low, "Raw SQL queries", "MASVS-CODE-4",
         "rawQuery / execSQL with concatenated input is open to SQL injection; prefer bound arguments.",
         {"Landroid/database/sqlite/SQLiteDatabase;->rawQuery(", "Landroid/database/sqlite/SQLiteDatabase;->execSQL("}},
        {"external-storage", Severity::Low, "External storage", "MASVS-STORAGE-1",
         "Files on shared external storage are readable by other apps.",
         {"Landroid/os/Environment;->getExternalStorageDirectory(", "Landroid/os/Environment;->getExternalStoragePublicDirectory("}},
        {"clipboard", Severity::Low, "Clipboard writes", "MASVS-STORAGE-2", "Data put on the clipboard is visible to other apps.",
         {"Landroid/content/ClipboardManager;->setPrimaryClip("}},
        {"securerandom-seed", Severity::Low, "SecureRandom with a fixed seed", "MASVS-CRYPTO-1",
         "setSeed on SecureRandom can make output predictable on some providers.", {"Ljava/security/SecureRandom;->setSeed("}},
        {"insecure-random", Severity::Info, "java.util.Random", "MASVS-CRYPTO-1",
         "Not suitable for keys, tokens or nonces.", {"Ljava/util/Random;-><init>("}},
        {"logging", Severity::Info, "Debug logging", "MASVS-STORAGE-2", "Log output can leak data to logcat.",
         {"Landroid/util/Log;->d(", "Landroid/util/Log;->v(", "Landroid/util/Log;->i("}},
        {"native-load", Severity::Info, "Native libraries loaded", "MASVS-CODE-4", "System.loadLibrary / load.",
         {"Ljava/lang/System;->loadLibrary(", "Ljava/lang/System;->load("}},
        {"reflection", Severity::Info, "Reflection", "MASVS-RESILIENCE-3", "Reflective calls hide call targets from static analysis.",
         {"Ljava/lang/reflect/Method;->invoke("}},
        {"broadcast", Severity::Info, "Implicit broadcasts", "MASVS-PLATFORM-1",
         "sendBroadcast without a permission reaches any registered receiver.", {"Landroid/content/Context;->sendBroadcast("}},
    };
    return k;
}

bool refMatches(const std::vector<std::string>& refs, const char* prefix, std::vector<std::string>& matched) {
    bool any = false;
    for (const std::string& r : refs)
        if (startsWith(r, prefix)) {
            matched.push_back(r);
            any = true;
        }
    return any;
}

void jsonEscape(std::string& out, std::string_view s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    out += b;
                } else {
                    out += c;
                }
        }
    }
}

std::string q(std::string_view s) {
    std::string out = "\"";
    jsonEscape(out, s);
    out += '"';
    return out;
}

}  // namespace

namespace {

// Dangerous permission -> guarded API signature prefixes. A referenced method
// whose signature starts with one of these needs that permission.
struct PermApi {
    const char* permission;
    std::vector<const char*> prefixes;
};

const std::vector<PermApi>& permApis() {
    static const std::vector<PermApi> k = {
        {"android.permission.ACCESS_FINE_LOCATION",
         {"Landroid/location/LocationManager;->getLastKnownLocation", "Landroid/location/LocationManager;->requestLocationUpdates",
          "Landroid/location/LocationManager;->getCurrentLocation", "Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation",
          "Lcom/google/android/gms/location/FusedLocationProviderClient;->requestLocationUpdates"}},
        {"android.permission.ACCESS_COARSE_LOCATION",
         {"Landroid/location/LocationManager;->getLastKnownLocation", "Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation"}},
        {"android.permission.CAMERA",
         {"Landroid/hardware/Camera;->open", "Landroid/hardware/camera2/CameraManager;->openCamera", "Landroidx/camera/"}},
        {"android.permission.RECORD_AUDIO",
         {"Landroid/media/AudioRecord;-><init>", "Landroid/media/MediaRecorder;->start", "Landroid/media/AudioRecord;->startRecording"}},
        {"android.permission.READ_CONTACTS", {"Landroid/provider/ContactsContract", "Landroid/provider/ContactsContract$"}},
        {"android.permission.READ_SMS", {"Landroid/provider/Telephony$Sms", "Landroid/telephony/SmsManager;->getAllMessagesFromIcc"}},
        {"android.permission.SEND_SMS", {"Landroid/telephony/SmsManager;->sendTextMessage", "Landroid/telephony/SmsManager;->sendMultipartTextMessage"}},
        {"android.permission.READ_PHONE_STATE",
         {"Landroid/telephony/TelephonyManager;->getDeviceId", "Landroid/telephony/TelephonyManager;->getImei",
          "Landroid/telephony/TelephonyManager;->getSubscriberId", "Landroid/telephony/TelephonyManager;->getLine1Number",
          "Landroid/telephony/TelephonyManager;->getSimSerialNumber"}},
        {"android.permission.READ_EXTERNAL_STORAGE", {"Landroid/os/Environment;->getExternalStorageDirectory"}},
        {"android.permission.READ_CALENDAR", {"Landroid/provider/CalendarContract"}},
        {"android.permission.GET_ACCOUNTS", {"Landroid/accounts/AccountManager;->getAccounts", "Landroid/accounts/AccountManager;->getAccountsByType"}},
        {"android.permission.READ_CALL_LOG", {"Landroid/provider/CallLog"}},
        {"android.permission.CALL_PHONE", {"Landroid/telephony/TelephonyManager;->endCall"}},
        {"android.permission.BLUETOOTH_CONNECT", {"Landroid/bluetooth/BluetoothDevice;->connectGatt", "Landroid/bluetooth/BluetoothSocket;->connect"}},
        {"android.permission.BLUETOOTH_SCAN", {"Landroid/bluetooth/BluetoothAdapter;->startDiscovery", "Landroid/bluetooth/le/BluetoothLeScanner;->startScan"}},
        {"android.permission.BODY_SENSORS", {"Landroid/hardware/SensorManager;->registerListener"}},
        {"android.permission.NFC", {"Landroid/nfc/NfcAdapter;", "Landroid/nfc/tech/"}},
        {"android.permission.READ_PHONE_NUMBERS", {"Landroid/telephony/TelephonyManager;->getLine1Number"}},
        {"android.permission.ACTIVITY_RECOGNITION", {"Lcom/google/android/gms/location/ActivityRecognitionClient;"}},
    };
    return k;
}

std::vector<PermissionUse> permissionCross(const std::vector<std::string>& perms, const std::vector<std::string>& methodRefs,
                                           bool requested) {
    std::set<std::string> have(perms.begin(), perms.end());
    std::vector<PermissionUse> out;
    for (const PermApi& pa : permApis()) {
        const bool asked = have.count(pa.permission) != 0;
        if (asked != requested) continue;  // requested-view vs missing-view
        PermissionUse use{pa.permission, {}};
        std::set<std::string> seen;
        for (const std::string& r : methodRefs)
            for (const char* pre : pa.prefixes)
                if (r.rfind(pre, 0) == 0 && seen.insert(r).second) use.apis.push_back(r);
        if (requested || !use.apis.empty()) out.push_back(std::move(use));
    }
    return out;
}

}  // namespace

std::vector<PermissionUse> permissionUsage(const std::vector<std::string>& perms, const std::vector<std::string>& methodRefs) {
    return permissionCross(perms, methodRefs, true);
}

std::vector<PermissionUse> missingPermissions(const std::vector<std::string>& perms, const std::vector<std::string>& methodRefs) {
    return permissionCross(perms, methodRefs, false);
}

std::string mask(std::string_view secret) {
    if (secret.size() <= 8) return std::string(secret.size(), '*');
    return std::string(secret.substr(0, 4)) + std::string(std::min<size_t>(secret.size() - 8, 12), '*') +
           std::string(secret.substr(secret.size() - 4));
}

std::vector<Secret> findSecrets(const std::vector<std::string>& strings) {
    std::vector<Secret> out;
    std::set<std::pair<std::string, std::string>> seen;
    for (size_t i = 0; i < strings.size(); ++i) scanString(strings[i], i, out, seen);
    return out;
}

std::vector<Sdk> detectSdks(const std::vector<std::string>& classes) {
    std::vector<Sdk> out;
    for (const SdkDef& d : kSdks) {
        int n = 0;
        for (const std::string& c : classes)
            if (startsWith(c, d.prefix)) ++n;
        if (n) out.push_back({d.name, d.category, d.tracker, d.prefix, n});
    }
    // Same name from two prefixes (SQLCipher): keep one, summed.
    std::vector<Sdk> merged;
    for (Sdk& s : out) {
        auto it = std::find_if(merged.begin(), merged.end(), [&](const Sdk& m) { return m.name == s.name; });
        if (it == merged.end()) merged.push_back(std::move(s));
        else it->classes += s.classes;
    }
    std::stable_sort(merged.begin(), merged.end(), [](const Sdk& a, const Sdk& b) { return a.tracker > b.tracker; });
    return merged;
}

std::vector<Detection> detectFrameworks(const Inputs& in) {
    std::vector<Detection> out;
    std::set<std::string> names;
    const auto push = [&](const char* name, const char* kind, std::string evidence) {
        if (names.insert(name).second) out.push_back({name, kind, std::move(evidence)});
    };
    for (const std::string& f : in.files) {
        const std::string base = fileName(f);
        for (const FileRule& r : kFileRules) {
            const std::string_view m = r.match;
            if (contains(m, "/") ? f == m : base == m) push(r.name, r.kind, f);
        }
        if (startsWith(f, "assemblies/") && endsWith(f, ".dll")) push("Xamarin / .NET for Android", "Framework", f);
        if (startsWith(f, "assets/bin/Data/Managed/") && endsWith(f, ".dll")) push("Unity (Mono)", "Framework", f);
        if (startsWith(f, "lib/") && startsWith(base, "libQt") && endsWith(base, ".so")) push("Qt", "Framework", f);
        if (f == "classes2.dex") push("Multidex", "Packaging", f);
    }
    for (const ClassRule& r : kClassRules)
        for (const std::string& c : in.classes)
            if (startsWith(c, r.prefix)) {
                push(r.name, r.kind, c);
                break;
            }
    std::stable_sort(out.begin(), out.end(), [](const Detection& a, const Detection& b) {
        const auto rank = [](const std::string& k) { return k == "Packer" ? 0 : k == "Framework" ? 1 : 2; };
        return rank(a.kind) < rank(b.kind);
    });
    return out;
}

std::vector<RuleHit> runRules(const Inputs& in) {
    std::vector<RuleHit> out;
    for (const Api& a : apis()) {
        RuleHit h{a.id, a.severity, a.title, a.masvs, a.detail, {}};
        bool any = false;
        for (const char* r : a.refs) any |= refMatches(in.methodRefs, r, h.matched);
        if (any) out.push_back(std::move(h));
    }
    // Constant-based crypto rules (needs both the API and the constant).
    std::vector<std::string> cipher, digest;
    const bool usesCipher = refMatches(in.methodRefs, "Ljavax/crypto/Cipher;->getInstance(", cipher);
    const bool usesDigest = refMatches(in.methodRefs, "Ljava/security/MessageDigest;->getInstance(", digest);
    if (usesCipher) {
        RuleHit ecb{"cipher-ecb", Severity::Medium, "ECB mode / default cipher mode", "MASVS-CRYPTO-1",
                    "ECB leaks plaintext patterns; \"AES\" alone defaults to AES/ECB/PKCS5Padding.", cipher};
        RuleHit weak{"cipher-weak", Severity::Medium, "Weak cipher (DES / 3DES / RC4 / Blowfish)", "MASVS-CRYPTO-1",
                     "Use AES-GCM or ChaCha20-Poly1305.", cipher};
        bool isEcb = false, isWeak = false;
        for (const std::string& s : in.strings) {
            if (s.size() > 40) continue;
            if (contains(s, "/ECB/") || s == "AES" || s == "DES") {
                isEcb = true;
                ecb.matched.push_back("\"" + s + "\"");
            }
            if (startsWith(s, "DES") || startsWith(s, "RC4") || startsWith(s, "ARCFOUR") || startsWith(s, "Blowfish")) {
                isWeak = true;
                weak.matched.push_back("\"" + s + "\"");
            }
        }
        if (isEcb) out.push_back(std::move(ecb));
        if (isWeak) out.push_back(std::move(weak));
    }
    if (usesDigest) {
        RuleHit h{"weak-hash", Severity::Low, "Weak hash (MD5 / SHA-1)", "MASVS-CRYPTO-1",
                  "Fine for checksums, not for passwords or signatures.", digest};
        bool any = false;
        for (const std::string& s : in.strings)
            if (s == "MD5" || s == "SHA-1" || s == "SHA1" || s == "md5" || s == "sha1") {
                any = true;
                h.matched.push_back("\"" + s + "\"");
            }
        if (any) out.push_back(std::move(h));
    }
    // Cleartext endpoints.
    {
        RuleHit h{"cleartext-url", Severity::Low, "Cleartext HTTP URLs", "MASVS-NETWORK-1",
                  "http:// endpoints are readable and modifiable on the network.", {}};
        for (const std::string& s : in.strings) {
            if (!startsWith(s, "http://") || s.size() < 12) continue;
            if (contains(s, "schemas.android.com") || contains(s, "www.w3.org") || contains(s, "localhost") ||
                contains(s, "127.0.0.1") || contains(s, "ns.adobe.com") || contains(s, "xml.org") || contains(s, "apache.org"))
                continue;
            if (h.matched.size() < 200) h.matched.push_back(s);
        }
        if (!h.matched.empty()) out.push_back(std::move(h));
    }
    // Root / emulator checks present in the app (informational).
    {
        RuleHit h{"root-checks", Severity::Info, "Root / emulator detection strings", "MASVS-RESILIENCE-1",
                  "The app looks for root or emulator artefacts.", {}};
        static const char* const kMarkers[] = {"/system/xbin/su", "/system/bin/su", "/sbin/su", "com.topjohnwu.magisk",
                                               "eu.chainfire.supersu", "com.noshufou.android.su", "test-keys", "goldfish",
                                               "ro.kernel.qemu"};
        for (const std::string& s : in.strings)
            for (const char* m : kMarkers)
                if (s == m) h.matched.push_back(s);
        if (!h.matched.empty()) out.push_back(std::move(h));
    }
    std::stable_sort(out.begin(), out.end(), [](const RuleHit& a, const RuleHit& b) { return a.severity > b.severity; });
    return out;
}

Obfuscation estimateObfuscation(const std::vector<std::string>& classes) {
    Obfuscation o;
    for (const std::string& c : classes) {
        if (c.size() < 3 || c.front() != 'L' || c.back() != ';' || isLibrary(c)) continue;
        ++o.appClasses;
        const size_t slash = c.find_last_of('/');
        std::string_view simple = std::string_view(c).substr(slash == std::string::npos ? 1 : slash + 1);
        simple.remove_suffix(1);
        const size_t dollar = simple.find('$');
        if (dollar != std::string_view::npos) simple = simple.substr(0, dollar);
        if (!simple.empty() && simple.size() <= 2) ++o.shortNames;
    }
    o.ratio = o.appClasses ? static_cast<double>(o.shortNames) / o.appClasses : 0.0;
    o.verdict = o.appClasses == 0 ? "none" : o.ratio >= 0.5 ? "heavy" : o.ratio >= 0.15 ? "light" : "none";
    return o;
}

Result scan(const Inputs& in) {
    Result r;
    r.secrets = findSecrets(in.strings);
    r.sdks = detectSdks(in.classes);
    r.detections = detectFrameworks(in);
    r.rules = runRules(in);
    r.obfuscation = estimateObfuscation(in.classes);
    return r;
}

std::string toJson(const Result& r, std::string_view apkName) {
    std::string o = "{\n  \"apk\": " + q(apkName) + ",\n";
    char buf[128];
    std::snprintf(buf, sizeof buf, "  \"obfuscation\": {\"appClasses\": %d, \"shortNames\": %d, \"ratio\": %.3f, \"verdict\": \"%s\"},\n",
                  r.obfuscation.appClasses, r.obfuscation.shortNames, r.obfuscation.ratio, r.obfuscation.verdict);
    o += buf;
    o += "  \"detections\": [";
    for (size_t i = 0; i < r.detections.size(); ++i) {
        const auto& d = r.detections[i];
        o += (i ? ",\n    " : "\n    ");
        o += "{\"name\": " + q(d.name) + ", \"kind\": " + q(d.kind) + ", \"evidence\": " + q(d.evidence) + "}";
    }
    o += r.detections.empty() ? "],\n" : "\n  ],\n";
    o += "  \"sdks\": [";
    for (size_t i = 0; i < r.sdks.size(); ++i) {
        const auto& s = r.sdks[i];
        o += (i ? ",\n    " : "\n    ");
        o += "{\"name\": " + q(s.name) + ", \"category\": " + q(s.category) + ", \"tracker\": " + (s.tracker ? "true" : "false") +
             ", \"package\": " + q(s.prefix) + ", \"classes\": " + std::to_string(s.classes) + "}";
    }
    o += r.sdks.empty() ? "],\n" : "\n  ],\n";
    o += "  \"secrets\": [";
    for (size_t i = 0; i < r.secrets.size(); ++i) {
        const auto& s = r.secrets[i];
        o += (i ? ",\n    " : "\n    ");
        o += "{\"kind\": " + q(s.kind) + ", \"severity\": " + q(severityName(s.severity)) + ", \"value\": " + q(mask(s.value)) + "}";
    }
    o += r.secrets.empty() ? "],\n" : "\n  ],\n";
    o += "  \"rules\": [";
    for (size_t i = 0; i < r.rules.size(); ++i) {
        const auto& h = r.rules[i];
        o += (i ? ",\n    " : "\n    ");
        o += "{\"id\": " + q(h.id) + ", \"severity\": " + q(severityName(h.severity)) + ", \"title\": " + q(h.title) +
             ", \"masvs\": " + q(h.masvs) + ", \"matched\": [";
        for (size_t k = 0; k < h.matched.size(); ++k) o += (k ? ", " : "") + q(h.matched[k]);
        o += "]}";
    }
    o += r.rules.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return o;
}

std::string toSarif(const Result& r, std::string_view apkName) {
    struct Item {
        std::string ruleId, level, text, location;
    };
    const auto level = [](Severity s) {
        return s == Severity::High ? "error" : s == Severity::Medium ? "warning" : "note";
    };
    std::vector<Item> items;
    std::vector<std::pair<std::string, std::string>> rules;  // id, description
    const auto rule = [&](const std::string& id, const std::string& desc) {
        if (std::none_of(rules.begin(), rules.end(), [&](const auto& p) { return p.first == id; })) rules.push_back({id, desc});
    };
    for (const Secret& s : r.secrets) {
        std::string id = "secret/";
        for (char c : s.kind) id += std::isalnum(static_cast<unsigned char>(c)) ? static_cast<char>(std::tolower(static_cast<unsigned char>(c))) : '-';
        rule(id, "Hard-coded " + s.kind);
        items.push_back({id, level(s.severity), s.kind + ": " + mask(s.value), "string constant"});
    }
    for (const RuleHit& h : r.rules) {
        rule(h.id, h.title + " (" + h.masvs + ")");
        const size_t n = std::min<size_t>(h.matched.size(), 20);
        if (n == 0) items.push_back({h.id, level(h.severity), h.detail, ""});
        for (size_t k = 0; k < n; ++k) items.push_back({h.id, level(h.severity), h.title + ": " + h.detail, h.matched[k]});
    }
    for (const Detection& d : r.detections)
        if (d.kind == "Packer") {
            rule("packer", "Packer / protector detected");
            items.push_back({"packer", "note", d.name + " detected", d.evidence});
        }

    std::string o = "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [{\n";
    o += "    \"tool\": {\"driver\": {\"name\": \"ApkSpy\", \"informationUri\": \"https://github.com/izvoranumarius/apkspy\", \"rules\": [";
    for (size_t i = 0; i < rules.size(); ++i)
        o += (i ? ",\n      " : "\n      ") + std::string("{\"id\": ") + q(rules[i].first) + ", \"shortDescription\": {\"text\": " +
             q(rules[i].second) + "}}";
    o += rules.empty() ? "]}},\n" : "\n    ]}},\n";
    o += "    \"artifacts\": [{\"location\": {\"uri\": " + q(apkName) + "}}],\n";
    o += "    \"results\": [";
    for (size_t i = 0; i < items.size(); ++i) {
        const Item& it = items[i];
        o += (i ? ",\n      " : "\n      ");
        o += "{\"ruleId\": " + q(it.ruleId) + ", \"level\": " + q(it.level) + ", \"message\": {\"text\": " + q(it.text) +
             "}, \"locations\": [{\"physicalLocation\": {\"artifactLocation\": {\"uri\": " + q(apkName) + "}}";
        if (!it.location.empty()) o += ", \"logicalLocations\": [{\"fullyQualifiedName\": " + q(it.location) + "}]";
        o += "}]}";
    }
    o += items.empty() ? "]\n  }]\n}\n" : "\n    ]\n  }]\n}\n";
    return o;
}

}  // namespace insights
