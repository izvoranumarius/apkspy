#pragma once
// Tests for the analysis features (behavior graph, diff, security scanner,
// dependencies, ...). Included by apkspy_platform_test.cpp after its CHECK
// macro; every fixture is built in memory with TestDex.
#include <memory>
#include "TestDex.hpp"
#include "analysis/ApkDiff.hpp"
#include "analysis/BehaviorGraph.hpp"
#include "analysis/Dependencies.hpp"
#include "analysis/SecurityScanner.hpp"
#include "analysis/VulnDb.hpp"
#include "analysis/SourceMap.hpp"
#include "core/TextDiff.hpp"
#include "analysis/Jni.hpp"
#include "analysis/LibraryCatalog.hpp"

namespace fixtures {

using T = TestDex;

// A small app:
//  MainActivity (launcher) onCreate -> login() [cleartext URL, SharedPreferences "session"]
//                                   -> new MainActivity$1 (Runnable): run() reads the location,
//                                      loads libcrypto.so and calls the native Native.decrypt()
//  SyncService (exported) onStartCommand -> OkHttp newCall (library code, not walked)
//  Unused.sendSms: SmsManager, reached by nothing
inline std::shared_ptr<ApkAnalysis> behaviorApp() {
    T d;
    d.addClass("Lcom/app/MainActivity;", "Landroid/app/Activity;");
    d.addClass("Lcom/app/MainActivity$1;", "Ljava/lang/Object;", {"Ljava/lang/Runnable;"});
    d.addClass("Lcom/app/Net;");
    d.addClass("Lcom/app/Native;");
    d.addClass("Lcom/app/SyncService;", "Landroid/app/Service;");
    d.addClass("Lcom/app/Unused;");
    d.addClass("Lokhttp3/OkHttpClient;");
    // MainActivity: regs = ins + 6, so `this` is v6 (v7 the Bundle).
    d.addMethod("Lcom/app/MainActivity;", "onCreate", "(Landroid/os/Bundle;)V", 0x1,
                {T::invokeDirect("Lcom/app/MainActivity;->login()V", {6}),
                 T::newInstance(0, "Lcom/app/MainActivity$1;"),
                 T::invokeDirect("Lcom/app/MainActivity$1;-><init>()V", {0}),
                 T::returnVoid()});
    d.addMethod("Lcom/app/MainActivity;", "login", "()V", 0x2,
                {T::constString(0, "http://api.example.com/login"),
                 T::invokeStatic("Lcom/app/Net;->post(Ljava/lang/String;)V", {0}),
                 T::constString(1, "session"),
                 T::const4(2, 0),
                 T::invokeVirtual("Lcom/app/MainActivity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;", {6, 1, 2}),
                 T::returnVoid()});
    d.addMethod("Lcom/app/Net;", "post", "(Ljava/lang/String;)V", 0x9,
                {T::newInstance(0, "Ljava/net/URL;"),
                 T::invokeDirect("Ljava/net/URL;-><init>(Ljava/lang/String;)V", {0, 6}),
                 T::invokeVirtual("Ljava/net/URL;->openConnection()Ljava/net/URLConnection;", {0}),
                 T::returnVoid()});
    d.addMethod("Lcom/app/MainActivity$1;", "<init>", "()V", 0x10001,
                {T::invokeDirect("Ljava/lang/Object;-><init>()V", {6}), T::returnVoid()});
    d.addMethod("Lcom/app/MainActivity$1;", "run", "()V", 0x1,
                {T::constString(0, "gps"),
                 T::invokeVirtual("Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;", {1, 0}),
                 T::constString(0, "crypto"),
                 T::invokeStatic("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", {0}),
                 T::invokeStatic("Lcom/app/Native;->decrypt()V"),
                 T::returnVoid()});
    d.addMethod("Lcom/app/Native;", "decrypt", "()V", 0x109, {});
    d.addMethod("Lcom/app/SyncService;", "onStartCommand", "(Landroid/content/Intent;II)I", 0x1,
                {T::invokeVirtual("Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;", {0, 1}),
                 T::returnVoid()});
    d.addMethod("Lokhttp3/OkHttpClient;", "newCall", "(Lokhttp3/Request;)Lokhttp3/Call;", 0x1,
                {T::invokeDirect("Ljava/net/Socket;-><init>()V", {0}), T::returnVoid()});
    d.addMethod("Lcom/app/Unused;", "sendSms", "()V", 0x9,
                {T::invokeVirtual("Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V", {0, 1, 2, 3, 4}),
                 T::returnVoid()});
    auto bytes = std::make_shared<std::vector<uint8_t>>(d.build());
    std::string err;
    auto dex = DexFile::parse(bytes, "classes.dex", err);
    if (!dex) {
        std::printf("  fixture dex failed to parse: %s\n", err.c_str());
        return nullptr;
    }
    std::atomic<bool> stop{false};
    return ApkAnalysis::build({dex}, stop);
}

inline behavior::Input behaviorManifest() {
    behavior::Input in;
    in.packageName = "com.app";
    ApkComponent main;
    main.type = "activity";
    main.name = ".MainActivity";
    main.exported = true;
    main.actions = {"android.intent.action.MAIN"};
    main.categories = {"android.intent.category.LAUNCHER"};
    ApkComponent sync;
    sync.type = "service";
    sync.name = "com.app.SyncService";
    sync.exported = true;
    in.components = {main, sync};
    in.declaredPermissions = {"android.permission.INTERNET", "android.permission.CAMERA"};
    return in;
}

}  // namespace fixtures

static void testBehaviorGraph() {
    std::printf("== behavior graph ==\n");
    CHECK(jni::shortName("Lcom/foo/Bar;", "baz") == "Java_com_foo_Bar_baz", "jni short name");
    CHECK(jni::shortName("Lcom/my_app/A$B;", "do_it") == "Java_com_my_1app_A_00024B_do_1it", "jni name escapes _ and $");
    CHECK(jni::longName("Lp/C;", "f", "(ILjava/lang/String;)V") == "Java_p_C_f__ILjava_lang_String_2", "jni long name");
    CHECK(behavior::urlHost("https://user:pw@API.Example.com:8443/v1?q=1") == "api.example.com", "url host: credentials, port, case");
    CHECK(behavior::urlHost("http://%s/path").empty() && behavior::urlHost("ftp://x.org").empty(), "placeholders and other schemes are no host");
    CHECK(behavior::componentClass("com.app", ".Main") == "com.app.Main" && behavior::componentClass("com.app", "Main") == "com.app.Main" &&
              behavior::componentClass("com.app", "org.x.Svc") == "org.x.Svc",
          "manifest component names");
    const auto* ok = libcatalog::forClass("Lokhttp3/internal/Util;");
    CHECK(ok && std::string(ok->id) == "okhttp3", "library catalog: okhttp");
    const auto* hilt = libcatalog::forClass("Ldagger/hilt/android/HiltAndroidApp;");
    CHECK(hilt && std::string(hilt->id) == "hilt", "library catalog: longest prefix wins (hilt over dagger)");
    CHECK(libcatalog::isPlatformClass("Landroid/app/Activity;") && !libcatalog::isPlatformClass("Landroid/support/v4/app/Fragment;"),
          "platform classes");

    {
        using behavior::permissionSatisfied;
        const std::vector<std::string> coarse = {"android.permission.ACCESS_COARSE_LOCATION"};
        CHECK(permissionSatisfied("android.permission.ACCESS_FINE_LOCATION", coarse, 34), "coarse location covers location APIs");
        CHECK(permissionSatisfied("android.permission.POST_NOTIFICATIONS", {}, 32) &&
                  !permissionSatisfied("android.permission.POST_NOTIFICATIONS", {}, 33) &&
                  !permissionSatisfied("android.permission.POST_NOTIFICATIONS", {}, 0),
              "POST_NOTIFICATIONS only needed from target SDK 33 (unknown target: needed)");
        CHECK(!permissionSatisfied("android.permission.CAMERA", coarse, 34), "unrelated permission is not covered");
    }
    auto a = fixtures::behaviorApp();
    CHECK(a != nullptr, "behavior fixture analysed");
    if (!a) return;
    using behavior::NodeKind;
    const behavior::Graph g = behavior::build(*a, fixtures::behaviorManifest());
    CHECK(g.componentsResolved == 2 && g.count(NodeKind::Component) == 2, "both components resolved");
    const int main = g.find(NodeKind::Component, "Lcom/app/MainActivity;");
    const int sync = g.find(NodeKind::Component, "Lcom/app/SyncService;");
    CHECK(main >= 0 && !g.nodes[static_cast<size_t>(main)].flagged, "launcher activity is not flagged");
    CHECK(sync >= 0 && g.nodes[static_cast<size_t>(sync)].flagged, "exported service is flagged");
    const int host = g.find(NodeKind::Endpoint, "api.example.com");
    CHECK(host >= 0 && g.nodes[static_cast<size_t>(host)].flagged, "cleartext endpoint found and flagged");
    if (host >= 0) {
        const auto& ev = g.nodes[static_cast<size_t>(host)].evidence;
        CHECK(std::find(ev.begin(), ev.end(), "http://api.example.com/login") != ev.end(), "endpoint evidence holds the URL");
    }
    const int prefs = g.find(NodeKind::Storage, "SharedPreferences:session");
    CHECK(prefs >= 0, "SharedPreferences named by its constant argument (receiver is the Activity)");
    const int loc = g.find(NodeKind::Permission, "android.permission.ACCESS_FINE_LOCATION");
    CHECK(loc >= 0 && g.nodes[static_cast<size_t>(loc)].flagged, "location reached through a callback, flagged as undeclared");
    const int internet = g.find(NodeKind::Permission, "android.permission.INTERNET");
    CHECK(internet >= 0 && !g.nodes[static_cast<size_t>(internet)].flagged, "declared INTERNET used by URL.openConnection");
    const int camera = g.find(NodeKind::Permission, "android.permission.CAMERA");
    CHECK(camera >= 0 && g.nodes[static_cast<size_t>(camera)].detail.find("no use") != std::string::npos, "declared but unused permission");
    CHECK(g.find(NodeKind::Native, "Java_com_app_Native_decrypt") >= 0, "native method mapped to its JNI symbol");
    CHECK(g.find(NodeKind::Native, "lib:libcrypto.so") >= 0, "System.loadLibrary names the library");
    CHECK(g.find(NodeKind::Permission, "android.permission.SEND_SMS") < 0, "unreachable code contributes nothing");
    CHECK(g.find(NodeKind::Endpoint, "(dynamic)") >= 0, "OkHttp call without a constant URL is a dynamic endpoint");
    bool libraryWalked = false;
    for (const auto& n : g.nodes)
        if (n.kind == NodeKind::Method && n.key.rfind("Lokhttp3/", 0) == 0) libraryWalked = true;
    CHECK(!libraryWalked, "library code is a boundary, not walked");
    const int onCreate = g.find(NodeKind::Method, "Lcom/app/MainActivity;->onCreate(Landroid/os/Bundle;)V");
    const int run = g.find(NodeKind::Method, "Lcom/app/MainActivity$1;->run()V");
    bool callback = false, entry = false;
    for (const auto& e : g.edges) {
        if (static_cast<int>(e.from) == onCreate && static_cast<int>(e.to) == run && e.kind == behavior::EdgeKind::Callback) callback = true;
        if (static_cast<int>(e.from) == main && static_cast<int>(e.to) == onCreate && e.kind == behavior::EdgeKind::Entry) entry = true;
    }
    CHECK(callback, "new Runnable() links onCreate to run() as a callback");
    CHECK(entry, "component -> lifecycle method entry edge");
    if (main >= 0 && loc >= 0) {
        const auto reach = behavior::reachableCapabilities(g, static_cast<uint32_t>(main));
        const auto it = std::find_if(reach.begin(), reach.end(), [&](const behavior::Reach& r) { return static_cast<int>(r.node) == loc; });
        CHECK(it != reach.end() && it->path.size() == 4 && static_cast<int>(it->path[1]) == onCreate && static_cast<int>(it->path[2]) == run,
              "shortest path: MainActivity -> onCreate -> run -> location");
        bool sorted = true;
        for (size_t i = 1; i < reach.size(); ++i) sorted = sorted && reach[i - 1].path.size() <= reach[i].path.size();
        CHECK(sorted && reach.size() >= 5, "capabilities come shortest path first");
    }

    std::atomic<bool> cancel{true};
    const behavior::Graph none = behavior::build(*a, fixtures::behaviorManifest(), {}, &cancel);
    CHECK(none.nodes.empty(), "cancelled build returns nothing");
}

namespace fixtures {

inline std::shared_ptr<ApkAnalysis> analyse(const TestDex& d) {
    auto bytes = std::make_shared<std::vector<uint8_t>>(d.build());
    std::string err;
    auto dex = DexFile::parse(bytes, "classes.dex", err);
    if (!dex) {
        std::printf("  fixture dex failed to parse: %s\n", err.c_str());
        return nullptr;
    }
    std::atomic<bool> stop{false};
    return ApkAnalysis::build({dex}, stop);
}

// Two versions of one app. v2: Main.run() switches to an https endpoint and
// starts encrypting; Main.cosmetic() only uses another register; the helper
// com.app.a is renamed to com.app.b by the obfuscator (same code); Gone is
// deleted, New and OkHttp appear.
inline std::pair<std::shared_ptr<ApkAnalysis>, std::shared_ptr<ApkAnalysis>> diffApps() {
    const auto helper = [](TestDex& d, const std::string& cls) {
        d.addClass(cls);
        d.addMethod(cls, "x", "(Ljava/lang/String;)V", 0x9,
                    {T::invokeStatic("Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I", {6, 6}),
                     T::invokeStatic("Ljava/lang/System;->gc()V"), T::returnVoid()});
        d.addMethod(cls, "y", "()V", 0x9, {T::const4(0, 1), T::const4(1, 2), T::returnVoid()});
    };
    TestDex a, b;
    a.addClass("Lcom/app/Main;");
    a.addMethod("Lcom/app/Main;", "run", "()V", 0x1,
                {T::constString(0, "http://old.example.com/api"),
                 T::invokeStatic("Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", {0, 0}), T::returnVoid()});
    a.addMethod("Lcom/app/Main;", "cosmetic", "()V", 0x1, {T::constString(0, "same"), T::returnVoid()});
    helper(a, "Lcom/app/a;");
    a.addClass("Lcom/app/Gone;");
    a.addMethod("Lcom/app/Gone;", "z", "()V", 0x9, {});

    b.addClass("Lcom/app/Main;");
    b.addMethod("Lcom/app/Main;", "run", "()V", 0x1,
                {T::constString(0, "https://new.example.com/api"),
                 T::invokeStatic("Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", {0, 0}),
                 T::constString(1, "AES/GCM/NoPadding"),
                 T::invokeStatic("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", {1}),
                 T::returnVoid()});
    b.addMethod("Lcom/app/Main;", "cosmetic", "()V", 0x1, {T::constString(2, "same"), T::returnVoid()});
    helper(b, "Lcom/app/b;");
    b.addClass("Lcom/app/New;");
    b.addMethod("Lcom/app/New;", "w", "()V", 0x9, {});
    b.addClass("Lokhttp3/OkHttpClient;");
    b.addMethod("Lokhttp3/OkHttpClient;", "newCall", "()V", 0x1, {});
    return {analyse(a), analyse(b)};
}

}  // namespace fixtures

static void testApkDiff() {
    std::printf("== apk diff ==\n");
    {
        const std::vector<std::string_view> a = {"a", "b", "c", "d"}, b = {"a", "x", "c", "d", "e"};
        const auto edits = textdiff::diff(a, b);
        int eq = 0, del = 0, ins = 0;
        for (const auto& e : edits) (e.op == textdiff::Op::Equal ? eq : e.op == textdiff::Op::Delete ? del : ins)++;
        CHECK(eq == 3 && del == 1 && ins == 2, "myers diff: b->x replaced, e appended");
        const auto rows = textdiff::sideBySide(edits);
        CHECK(rows.size() == 5 && rows[1].changed && rows[1].a == 1 && rows[1].b == 1 && rows[4].a < 0 && rows[4].b == 4,
              "side by side pairs the replaced line, appends the insert");
        const auto same = textdiff::diff(a, a);
        CHECK(same.size() == 4 && std::all_of(same.begin(), same.end(), [](const textdiff::Edit& e) { return e.op == textdiff::Op::Equal; }),
              "identical texts are all equal");
        std::vector<std::string> big1, big2;
        for (int i = 0; i < 3000; ++i) big1.push_back(std::to_string(i)), big2.push_back(std::to_string(i * 7 + 1));
        std::vector<std::string_view> v1(big1.begin(), big1.end()), v2(big2.begin(), big2.end());
        const auto capped = textdiff::diff(v1, v2, 50);
        CHECK(capped.size() >= 5900, "edit cap falls back to replace-all without blowing up");
        CHECK(textdiff::splitLines("a\r\nb\n").size() == 2 && textdiff::splitLines("").empty(), "line splitting");
    }
    auto [a, b] = fixtures::diffApps();
    CHECK(a && b, "diff fixtures analysed");
    if (!a || !b) return;
    {
        const auto defs = a->findMethodDefs("Lcom/app/Main;", "run");
        const std::string listing = defs.empty() ? "" : ApkDiff::normalizedListing(*a, defs.front());
        CHECK(listing.find("/* 0") == std::string::npos && listing.find("const-string") != std::string::npos,
              "normalised listing drops offsets");
    }
    ApkDiff::Side sa, sb;
    sa.analysis = a;
    sb.analysis = b;
    sa.info.packageName = sb.info.packageName = "com.app";
    sa.info.versionName = "1.0";
    sb.info.versionName = "1.1";
    sa.info.permissions = {"android.permission.INTERNET", "android.permission.READ_SMS"};
    sb.info.permissions = {"android.permission.INTERNET", "android.permission.CAMERA"};
    ApkComponent recv;
    recv.type = "receiver";
    recv.name = ".Recv";
    sa.info.components = {recv};
    recv.exported = true;
    recv.actions = {"android.intent.action.BOOT_COMPLETED"};
    sb.info.components = {recv};
    sa.entries = {{"classes.dex", 100, 50, 1, 8}, {"lib/arm64-v8a/libx.so", 10, 5, 7, 8}, {"res/a.png", 4, 4, 9, 0}};
    sb.entries = {{"classes.dex", 120, 60, 2, 8}, {"lib/arm64-v8a/libx.so", 10, 5, 8, 8}, {"res/b.png", 4, 4, 9, 0}};
    const ApkDiff d = ApkDiff::compare(sa, sb, {});
    CHECK(d.manifest.size() == 1 && d.manifest[0].field == "versionName" && d.manifest[0].b == "1.1", "manifest field change");
    CHECK(d.permissionsAdded == std::vector<std::string>{"android.permission.CAMERA"} &&
              d.permissionsRemoved == std::vector<std::string>{"android.permission.READ_SMS"},
          "permission changes");
    CHECK(d.components.size() == 1 && d.components[0].kind == ApkDiff::Kind::Changed &&
              d.components[0].detail.find("exported: no -> yes") != std::string::npos &&
              d.components[0].detail.find("BOOT_COMPLETED") != std::string::npos,
          "component became exported with a new action");
    CHECK(d.entries.size() == 4 && d.natives.size() == 1 && d.natives[0].kind == ApkDiff::Kind::Changed, "files and native libraries");
    CHECK(d.classesRenamed.size() == 1 && d.classesRenamed[0].from == "com.app.a" && d.classesRenamed[0].to == "com.app.b",
          "obfuscator rename detected by code shape");
    CHECK(d.classesRemoved == std::vector<std::string>{"com.app.Gone"}, "renamed class not reported as removed");
    CHECK(std::find(d.classesAdded.begin(), d.classesAdded.end(), "com.app.New") != d.classesAdded.end() &&
              std::find(d.classesAdded.begin(), d.classesAdded.end(), "com.app.b") == d.classesAdded.end(),
          "renamed class not reported as added");
    CHECK(d.methodsCosmetic == 1, "register-only change is cosmetic");
    CHECK(d.methodsChanged.size() == 1 && d.methodDetails.size() == 1 && d.methodDetails[0].signature == "Lcom/app/Main;->run()V",
          "one meaningful method change");
    if (!d.methodDetails.empty()) {
        const auto& m = d.methodDetails[0];
        CHECK(m.callsAdded.size() == 1 && m.callsAdded[0].find("Cipher;->getInstance") != std::string::npos, "new call reported");
        CHECK(std::find(m.stringsAdded.begin(), m.stringsAdded.end(), "AES/GCM/NoPadding") != m.stringsAdded.end() &&
                  m.stringsRemoved == std::vector<std::string>{"http://old.example.com/api"},
              "strings added and removed");
        CHECK(m.added >= 3 && m.removed >= 1 && m.summary.find("Cipher.getInstance") != std::string::npos, "instruction counts and summary");
    }
    CHECK(d.endpointsAdded == std::vector<std::string>{"https://new.example.com/api"} &&
              d.endpointsRemoved == std::vector<std::string>{"http://old.example.com/api"},
          "endpoint changes");
    CHECK(d.libraries.size() == 1 && d.libraries[0].name == "OkHttp" && d.libraries[0].kind == ApkDiff::Kind::Added, "library added");

    // Library detection from version files.
    CHECK(libcatalog::isVersionFile("META-INF/androidx.core_core.version") && !libcatalog::isVersionFile("META-INF/x/y.version") &&
              !libcatalog::isVersionFile("res/a.version"),
          "version file names");
    const auto found = libcatalog::detect(b.get(), {{"META-INF/com.squareup.okhttp3_okhttp.version", "4.12.0\n"},
                                                    {"META-INF/androidx.lifecycle_lifecycle-runtime.version", "2.6.2"}});
    const auto ok = std::find_if(found.begin(), found.end(), [](const libcatalog::Detection& x) { return x.lib && std::string(x.lib->id) == "okhttp3"; });
    CHECK(ok != found.end() && ok->classes == 1 && ok->version == "4.12.0", "catalogued library gets its version from META-INF");
    const auto other = std::find_if(found.begin(), found.end(), [](const libcatalog::Detection& x) { return !x.lib; });
    CHECK(other != found.end() && other->maven == "androidx.lifecycle:lifecycle-runtime" && other->version == "2.6.2",
          "uncatalogued artifact kept by its coordinates");
}

namespace fixtures {

// jadx-style source of com.app.Demo (line numbers matter: see the checks).
inline const char* kDemoJava =
    "package com.app;\n"                                        // 0
    "\n"                                                        // 1
    "import android.util.Log;\n"                                // 2
    "\n"                                                        // 3
    "public class Demo {\n"                                     // 4
    "    @Override\n"                                           // 5
    "    public void run(String name) {\n"                      // 6
    "        Log.d(\"tag\", \"start\");\n"                      // 7
    "        helper(name);\n"                                   // 8
    "        if (name.equals(new String())) {\n"                // 9
    "            save();\n"                                     // 10
    "        }\n"                                               // 11
    "        Log.d(\"tag\", \"end\");\n"                        // 12
    "    }\n"                                                   // 13
    "\n"                                                        // 14
    "    private void helper(String s) {\n"                     // 15
    "        Runnable r = new Runnable() {\n"                   // 16
    "            @Override\n"                                   // 17
    "            public void run() {\n"                         // 18
    "                System.loadLibrary(\"x\");\n"              // 19
    "            }\n"                                           // 20
    "        };\n"                                              // 21
    "        r.run();\n"                                        // 22
    "    }\n"                                                   // 23
    "\n"                                                        // 24
    "    public void go() {\n"                                  // 25
    "        post(() -> {\n"                                    // 26
    "            save();\n"                                     // 27
    "        });\n"                                             // 28
    "    }\n"                                                   // 29
    "\n"                                                        // 30
    "    void save() {\n"                                       // 31
    "    }\n"                                                   // 32
    "\n"                                                        // 33
    "    void post(Runnable r) {\n"                             // 34
    "    }\n"                                                   // 35
    "}\n";                                                      // 36

inline std::shared_ptr<ApkAnalysis> demoApp() {
    TestDex d;
    d.addClass("Lcom/app/Demo;");
    d.addClass("Lcom/app/Demo$1;", "Ljava/lang/Object;", {"Ljava/lang/Runnable;"});
    const std::string logD = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I";
    d.addMethod("Lcom/app/Demo;", "run", "(Ljava/lang/String;)V", 0x1,
                {T::constString(0, "tag"), T::constString(1, "start"), T::invokeStatic(logD, {0, 1}),             // pcs 0, 2, 4
                 T::invokeDirect("Lcom/app/Demo;->helper(Ljava/lang/String;)V", {6, 7}),                         // 7
                 T::newInstance(0, "Ljava/lang/String;"), T::invokeDirect("Ljava/lang/String;-><init>()V", {0}),  // 10, 12
                 T::invokeVirtual("Ljava/lang/String;->equals(Ljava/lang/Object;)Z", {7, 0}),                   // 15
                 T::invokeDirect("Lcom/app/Demo;->save()V", {6}),                                                // 18
                 T::constString(0, "tag"), T::constString(1, "end"), T::invokeStatic(logD, {0, 1}),               // 21, 23, 25
                 T::returnVoid()});
    d.addMethod("Lcom/app/Demo;", "helper", "(Ljava/lang/String;)V", 0x2,
                {T::newInstance(0, "Lcom/app/Demo$1;"), T::invokeDirect("Lcom/app/Demo$1;-><init>(Lcom/app/Demo;)V", {0, 6}),
                 T::invokeVirtual("Ljava/lang/Runnable;->run()V", {0}), T::returnVoid()});
    d.addMethod("Lcom/app/Demo;", "go", "()V", 0x1,
                {T::invokeDirect("Lcom/app/Demo;->post(Ljava/lang/Runnable;)V", {6, 0}), T::returnVoid()});
    d.addMethod("Lcom/app/Demo;", "lambda$go$0", "()V", 0x1002,
                {T::invokeDirect("Lcom/app/Demo;->save()V", {6}), T::returnVoid()});
    d.addMethod("Lcom/app/Demo;", "save", "()V", 0x0, {});
    d.addMethod("Lcom/app/Demo;", "post", "(Ljava/lang/Runnable;)V", 0x0, {});
    d.addMethod("Lcom/app/Demo$1;", "<init>", "(Lcom/app/Demo;)V", 0x10000, {});
    d.addMethod("Lcom/app/Demo$1;", "run", "()V", 0x1,
                {T::constString(0, "x"), T::invokeStatic("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", {0}), T::returnVoid()});
    return analyse(d);
}

}  // namespace fixtures

static void testSourceMap() {
    std::printf("== java <-> smali source map ==\n");
    const std::vector<std::string_view> lines = textdiff::splitLines(fixtures::kDemoJava);
    const sourcemap::JavaFile file(lines);
    CHECK(file.packageName() == "com.app", "package name");
    const auto& ms = file.methods();
    const auto has = [&](const char* cls, const char* name, int decl) {
        return std::any_of(ms.begin(), ms.end(), [&](const sourcemap::JavaMethod& m) { return m.cls == cls && m.name == name && m.declLine == decl; });
    };
    CHECK(ms.size() == 6, "six method bodies parsed");
    CHECK(has("com.app.Demo", "run", 5) && has("com.app.Demo", "helper", 15) && has("com.app.Demo$1", "run", 17) &&
              has("com.app.Demo", "go", 25),
          "methods with their classes (annotation starts the declaration)");
    const sourcemap::JavaMethod* inner = file.methodAt(19);
    CHECK(inner && inner->cls == "com.app.Demo$1" && inner->name == "run", "anonymous class numbered like javac");
    CHECK(file.methodAt(10) && file.methodAt(10)->name == "run" && file.methodAt(10)->cls == "com.app.Demo",
          "a block after `new String()` is not an anonymous class");
    CHECK(!ms.empty() && ms[0].params == std::vector<std::string>{"String"}, "parameter types");
    CHECK(sourcemap::paramSimpleTypes("(Ljava/lang/String;[ILcom/a/B$C;)V") == std::vector<std::string>({"String", "int[]", "C"}),
          "bytecode parameter names");
    CHECK(file.lambdaRanges().size() == 1 && file.lambdaRanges()[0].first == 26, "lambda body range");
    const std::vector<std::string_view> dbg = {"    /* 42 */ foo();", "    bar();"};
    const sourcemap::JavaFile withDebug(dbg);
    CHECK(withDebug.hasDebugLines() && withDebug.debugLine(0) == 42 && withDebug.debugLine(1) == -1, "jadx debug line comments");

    auto a = fixtures::demoApp();
    CHECK(a != nullptr, "source map fixture analysed");
    if (!a) return;
    sourcemap::Target t;
    CHECK(sourcemap::javaToBytecode(*a, file, 12, t) && t.pcs == std::vector<uint32_t>({21, 23, 25}),
          "second Log.d line -> the second call and its constants (not the first)");
    CHECK(sourcemap::javaToBytecode(*a, file, 7, t) && t.pcs == std::vector<uint32_t>({0, 2, 4}), "first Log.d line -> first call");
    CHECK(sourcemap::javaToBytecode(*a, file, 9, t) && t.pcs == std::vector<uint32_t>({10, 12, 15}),
          "condition line -> new String() and equals()");
    CHECK(sourcemap::javaToBytecode(*a, file, 19, t) && a->methodSignature(t.method) == "Lcom/app/Demo$1;->run()V" && t.pcs.size() == 2,
          "line in the anonymous class -> Demo$1.run()");
    CHECK(sourcemap::javaToBytecode(*a, file, 27, t) && a->methodSignature(t.method) == "Lcom/app/Demo;->lambda$go$0()V" &&
              t.pcs == std::vector<uint32_t>({0}),
          "line in a lambda -> its synthetic method");
    const auto run = a->findMethodDefs("Lcom/app/Demo;", "run");
    if (!run.empty()) {
        CHECK(sourcemap::bytecodeToJava(*a, file, run.front(), 7) == 8, "helper() invoke -> its Java line");
        CHECK(sourcemap::bytecodeToJava(*a, file, run.front(), 21) == 12, "setup constant -> the statement it feeds");
        CHECK(sourcemap::bytecodeToJava(*a, file, run.front(), 18) == 10, "save() inside the if block");
    }
    const auto lambda = a->findMethodDefs("Lcom/app/Demo;", "lambda$go$0");
    CHECK(!lambda.empty() && sourcemap::bytecodeToJava(*a, file, lambda.front(), 0) == 27, "lambda instruction -> lambda body line");
}

namespace fixtures {

// An app with one instance of most issues the scanner knows.
inline std::shared_ptr<ApkAnalysis> insecureApp() {
    TestDex d;
    d.addClass("Lcom/app/Crypto;");
    d.addMethod("Lcom/app/Crypto;", "enc", "()V", 0x9,
                {T::constString(0, "AES/ECB/PKCS5Padding"), T::invokeStatic("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", {0}),
                 T::constString(1, "MD5"), T::invokeStatic("Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;", {1}),
                 T::constString(2, "s3cr3tk3y1234567"), T::invokeVirtual("Ljava/lang/String;->getBytes()[B", {2}),
                 T::newInstance(3, "Ljavax/crypto/spec/SecretKeySpec;"),
                 T::invokeDirect("Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V", {3, 4, 5}), T::returnVoid()});
    d.addClass("Lcom/app/Web;");
    d.addMethod("Lcom/app/Web;", "setup", "(Landroid/webkit/WebView;Landroid/webkit/WebSettings;)V", 0x9,
                {T::const4(1, 1), T::invokeVirtual("Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V", {7, 1}),
                 T::invokeVirtual("Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V", {7, 1}),
                 T::invokeVirtual("Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V", {6, 0, 2}),
                 T::invokeStatic("Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V", {1}), T::returnVoid()});
    d.addClass("Lcom/app/Trust;", "Ljava/lang/Object;", {"Ljavax/net/ssl/X509TrustManager;"});
    d.addMethod("Lcom/app/Trust;", "checkServerTrusted", "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", 0x1, {T::returnVoid()});
    d.addClass("Lcom/app/Verifier;", "Ljava/lang/Object;", {"Ljavax/net/ssl/HostnameVerifier;"});
    d.addMethod("Lcom/app/Verifier;", "verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", 0x1,
                {T::const4(0, 1), T::raw({0x000f})});  // return v0
    d.addClass("Lcom/app/Main;", "Landroid/app/Activity;");
    d.addMethod("Lcom/app/Main;", "keys", "()V", 0x1,
                {T::constString(0, "AKIAIOSFODNN7EXAMPLE"), T::constString(1, "user password is wrong"),
                 T::invokeStatic("Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", {0, 1}),
                 T::constString(2, "http://tracker.example.org/collect"),
                 T::constString(3, "prefs"), T::const4(4, 1),
                 T::invokeVirtual("Lcom/app/Main;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;", {6, 3, 4}),
                 T::returnVoid()});
    d.addClass("Lokhttp3/internal/Legacy;");
    d.addMethod("Lokhttp3/internal/Legacy;", "old", "()V", 0x9,
                {T::constString(0, "DES"), T::invokeStatic("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", {0}),
                 T::returnVoid()});
    return analyse(d);
}

}  // namespace fixtures

static void testSecurityScanner() {
    std::printf("== security scanner ==\n");
    using security::Severity;
    security::SecretMatch m;
    CHECK(security::findSecret("key=AKIAIOSFODNN7EXAMPLE;", m) && m.kind == "AWS access key ID" && m.token == "AKIAIOSFODNN7EXAMPLE", "AWS key");
    CHECK(security::findSecret("AIzaSyA-1234567890abcdefghijklmnopqrstu", m) && m.kind == "Google API key", "Google API key");
    CHECK(security::findSecret("-----BEGIN RSA PRIVATE KEY-----\nMIIE", m) && m.kind == "private key" && m.severity == Severity::Critical,
          "PEM private key");
    CHECK(security::findSecret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", m) &&
              m.kind == "JSON Web Token",
          "JWT");
    CHECK(!security::findSecret("AKIA123 hello world", m) && !security::findSecret("https://example.com/api/v1", m) &&
              !security::findSecret("xAKIAIOSFODNN7EXAMPLE", m),
          "no false positives on short or embedded tokens");

    auto a = fixtures::insecureApp();
    CHECK(a != nullptr, "security fixture analysed");
    if (!a) return;
    security::Input in;
    in.analysis = a;
    in.info.ok = true;
    in.info.packageName = "com.app";
    in.info.debuggable = true;
    in.info.usesCleartextTraffic = "true";
    in.info.targetSdk = "33";
    in.info.minSdk = "21";
    ApkComponent launcher;
    launcher.type = "activity";
    launcher.name = ".Main";
    launcher.exported = launcher.exportedSet = launcher.hasIntentFilter = true;
    launcher.categories = {"android.intent.category.LAUNCHER"};
    ApkComponent svc;
    svc.type = "service";
    svc.name = ".SyncService";
    svc.exported = svc.exportedSet = true;
    ApkComponent provider;
    provider.type = "provider";
    provider.name = ".Files";
    provider.exported = provider.exportedSet = provider.grantUriPermissions = true;
    ApkComponent boot;
    boot.type = "receiver";
    boot.name = ".Boot";
    boot.exported = boot.exportedSet = true;
    boot.actions = {"android.intent.action.BOOT_COMPLETED"};
    ApkComponent guarded = svc;
    guarded.name = ".Guarded";
    guarded.permission = "android.permission.BIND_JOB_SERVICE";
    in.info.components = {launcher, svc, provider, boot, guarded};
    in.networkSecurityConfig =
        "<network-security-config>\n  <base-config cleartextTrafficPermitted=\"true\">\n    <trust-anchors>\n"
        "      <certificates src=\"system\"/>\n      <certificates src=\"user\"/>\n    </trust-anchors>\n  </base-config>\n"
        "  <domain-config cleartextTrafficPermitted=\"true\">\n    <domain includeSubdomains=\"true\">legacy.example.com</domain>\n"
        "  </domain-config>\n  <debug-overrides>\n    <trust-anchors><certificates src=\"user\"/></trust-anchors>\n  </debug-overrides>\n"
        "</network-security-config>\n";
    in.networkSecurityConfigPath = "res/xml/network_security_config.xml";
    const security::Report r = security::scan(in);
    const auto count = [&](const char* rule) {
        return std::count_if(r.findings.begin(), r.findings.end(), [&](const security::Finding& f) { return f.rule == rule; });
    };
    const auto find = [&](const char* rule) -> const security::Finding* {
        for (const auto& f : r.findings)
            if (f.rule == rule) return &f;
        return nullptr;
    };
    CHECK(r.bytecodeScanned && r.methodsScanned >= 6, "bytecode scanned");
    CHECK(count("manifest-debuggable") == 1 && count("manifest-cleartext") == 1, "debuggable and cleartext manifest flags");
    CHECK(count("manifest-allow-backup") == 1 && find("manifest-allow-backup")->severity == Severity::Low, "allowBackup unset is the default true");
    CHECK(count("component-exported") == 3, "exported service, provider and boot receiver; launcher and guarded service skipped");
    for (const auto& f : r.findings)
        if (f.rule == "component-exported" && f.location.ref == ".Files") CHECK(f.severity == Severity::High, "exported provider is high");
        else if (f.rule == "component-exported" && f.location.ref == ".Boot") CHECK(f.severity == Severity::Low, "system-broadcast receiver is low");
    CHECK(count("provider-grant-uri") == 1, "grantUriPermissions");
    CHECK(count("nsc-cleartext") == 2 && count("nsc-user-certs") == 1, "network config: base + domain cleartext, user CAs outside debug-overrides only");
    const auto* ecb = find("crypto-ecb");
    CHECK(ecb && ecb->location.kind == security::Location::Kind::Method && ecb->location.ref == "Lcom/app/Crypto;->enc()V" &&
              ecb->location.pc == 2 && ecb->library.empty(),
          "ECB cipher located at its call");
    CHECK(count("crypto-weak-hash") == 1 && count("crypto-hardcoded-key") == 1, "MD5 and a key from a constant string");
    const auto* des = find("crypto-weak-cipher");
    CHECK(des && des->library == "OkHttp", "finding in library code names the library");
    CHECK(count("tls-trust-all") == 1 && find("tls-trust-all")->severity == Severity::Critical, "empty checkServerTrusted");
    CHECK(count("tls-hostname-all") == 1, "verify() returning true");
    CHECK(count("webview-js-enabled") == 1 && count("webview-file-access") == 1 && count("webview-js-interface") == 1 &&
              count("webview-debugging") == 1,
          "WebView settings");
    CHECK(count("storage-world-readable") == 1, "MODE_WORLD_READABLE through the Activity receiver");
    CHECK(count("log-sensitive") == 1, "password in a log message");
    const auto* aws = find("secret-api-key");
    CHECK(aws && aws->title == "Hardcoded AWS access key ID" && aws->location.ref == "Lcom/app/Main;->keys()V" &&
              aws->evidence.find("AKIAIOSF") != std::string::npos && aws->evidence.find("AKIAIOSFODNN7EXAMPLE") == std::string::npos,
          "AWS key located and masked");
    CHECK(count("cleartext-url") == 1 && find("cleartext-url")->evidence.find("tracker.example.org") != std::string::npos, "cleartext URL by host");
    bool sorted = true;
    for (size_t i = 1; i < r.findings.size(); ++i) sorted = sorted && r.findings[i - 1].severity >= r.findings[i].severity;
    CHECK(sorted && r.findings.front().severity == Severity::Critical, "most severe first");
    const std::string md = security::toMarkdown(r, in.info), json = security::toJson(r, in.info);
    CHECK(md.find("## [Critical]") != std::string::npos && md.find("CWE-295") != std::string::npos, "markdown report");
    CHECK(json.find("\"rule\": \"crypto-ecb\"") != std::string::npos && json.find("\"pc\": 2") != std::string::npos, "json report");
}

static void testDependencies() {
    std::printf("== dependencies / vulnerability database ==\n");
    using vulndb::compareVersions;
    CHECK(compareVersions("2.0-beta9", "2.0") < 0 && compareVersions("2.0", "2.0.1") < 0 && compareVersions("1.0", "1.0.0") == 0,
          "versions: qualifiers before releases, trailing zeros ignored");
    CHECK(compareVersions("1.0-rc1", "1.0.1") < 0 && compareVersions("1.0-sp1", "1.0") > 0 && compareVersions("2.15.0", "2.2") > 0,
          "versions: rc, service packs, numeric parts");
    CHECK(compareVersions("2.12.6.1", "2.12.6") > 0 && compareVersions("1.0-alpha", "1.0-beta") < 0, "versions: four parts, alpha < beta");
    CHECK(vulndb::inRange("2.8.5", {"0", "2.8.9", ""}) && !vulndb::inRange("2.8.9", {"0", "2.8.9", ""}) &&
              vulndb::inRange("1.2.17", {"1.2", "", "1.2.17"}) && !vulndb::inRange("1.1", {"1.2", "", "1.2.17"}),
          "OSV ranges: introduced <= v < fixed, last_affected inclusive");
    const vulndb::Database db = vulndb::Database::builtin();
    CHECK(db.all().size() >= 20, "built-in database loads");
    CHECK(db.affecting("com.google.code.gson:gson", "2.8.6").size() == 1 && db.affecting("com.google.code.gson:gson", "2.10.1").empty(),
          "gson 2.8.6 vulnerable, 2.10.1 not");
    CHECK(db.affecting("org.apache.logging.log4j:log4j-core", "2.14.1").size() == 2 &&
              db.affecting("org.apache.logging.log4j:log4j-core", "2.12.2").empty(),
          "Log4Shell ranges include the 2.12.2 backport");
    vulndb::Database extra;
    std::string err;
    CHECK(extra.loadText(R"({"format":"apkspy-vulndb-1","updated":"2026-01-01","vulnerabilities":[)"
                         R"({"id":"CVE-2022-25647","package":"com.google.code.gson:gson","severity":"Low","summary":"changed","ranges":[{"introduced":"0","fixed":"2.8.9"}]},)"
                         R"({"id":"GHSA-test","package":"com.example:lib","severity":"High","summary":"x","ranges":[{"introduced":"1.0"}]}]})",
                         err),
          "database file parses");
    vulndb::Database merged = db;
    merged.merge(extra);
    CHECK(merged.all().size() == db.all().size() + 1 && merged.affecting("com.google.code.gson:gson", "2.8.0")[0]->severity == "Low" &&
              merged.affecting("com.example:lib", "3.0").size() == 1,
          "merge replaces by id + package and adds new advisories");
    vulndb::Database bad;
    CHECK(!bad.loadText("{\"format\":\"other\"}", err) && !err.empty(), "foreign files are refused");
    std::string roundTrip = db.toJson();
    vulndb::Database again;
    CHECK(again.loadText(roundTrip, err) && again.all().size() == db.all().size(), "database round-trips through JSON");

    CHECK(libcatalog::isVersionFile("META-INF/maven/com.google.code.gson/gson/pom.properties") &&
              !libcatalog::isVersionFile("META-INF/maven/a/b/c/pom.properties"),
          "pom.properties are version files");
    const auto* flutter = libcatalog::forNativeLibrary("lib/arm64-v8a/libflutter.so");
    CHECK(flutter && std::string(flutter->id) == "flutter" && !libcatalog::forNativeLibrary("lib/x86/libfoo.so"), "native library fingerprints");
    const auto found = libcatalog::detect(nullptr, {{"META-INF/maven/com.google.code.gson/gson/pom.properties", "#x\nversion=2.8.6\ngroupId=com.google.code.gson\n"}},
                                          {"lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libmystery.so"});
    const auto gson = std::find_if(found.begin(), found.end(), [](const libcatalog::Detection& x) { return x.lib && std::string(x.lib->id) == "gson"; });
    CHECK(gson != found.end() && gson->version == "2.8.6" && gson->versionSource.find("pom.properties") != std::string::npos, "version from pom.properties");
    const auto fl = std::find_if(found.begin(), found.end(), [](const libcatalog::Detection& x) { return x.lib && std::string(x.lib->id) == "flutter"; });
    CHECK(fl != found.end() && fl->nativeLibs.size() == 2 && fl->classes == 0, "Flutter detected from its native libraries alone");
    CHECK(deps::licenseKind("Apache-2.0") == deps::LicenseKind::Permissive && deps::licenseKind("GPL-3.0") == deps::LicenseKind::Copyleft &&
              deps::licenseKind("GPL-2.0-with-classpath-exception") == deps::LicenseKind::WeakCopyleft &&
              deps::licenseKind("Proprietary") == deps::LicenseKind::Proprietary && deps::licenseKind("") == deps::LicenseKind::Unknown,
          "license kinds");
    // analyze(): the behavior fixture bundles OkHttp; no archive, so no versions.
    auto app = fixtures::behaviorApp();
    if (app) {
        const deps::Report r = deps::analyze(app.get(), "", {"lib/arm64-v8a/libmystery.so"}, db);
        const auto ok = std::find_if(r.dependencies.begin(), r.dependencies.end(), [](const deps::Dependency& d) { return d.id == "okhttp3"; });
        CHECK(ok != r.dependencies.end() && ok->classes == 1 && ok->prefixes == std::vector<std::string>{"okhttp3."} && ok->version.empty(),
              "OkHttp found by package, version unknown");
        CHECK(r.unidentifiedNative == std::vector<std::string>{"libmystery.so"} && r.totalClasses == 7 && r.libraryClasses == 1,
              "unidentified native libraries and code share");
    }
}
