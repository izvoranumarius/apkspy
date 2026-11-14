#pragma once
// Tests for the analysis features (behavior graph, diff, security scanner,
// dependencies, ...). Included by apkspy_platform_test.cpp after its CHECK
// macro; every fixture is built in memory with TestDex.
#include <memory>
#include "TestDex.hpp"
#include "analysis/ApkDiff.hpp"
#include "analysis/BehaviorGraph.hpp"
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
