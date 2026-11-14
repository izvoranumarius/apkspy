#pragma once
// Tests for the analysis features (behavior graph, diff, security scanner,
// dependencies, ...). Included by apkspy_platform_test.cpp after its CHECK
// macro; every fixture is built in memory with TestDex.
#include <memory>
#include "TestDex.hpp"
#include "analysis/BehaviorGraph.hpp"
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
