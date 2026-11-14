#include "analysis/LibraryCatalog.hpp"
#include <algorithm>

namespace libcatalog {
namespace {

// Specific entries come before the generic families they belong to only for
// readability: lookups pick the longest matching prefix.
std::vector<Library> makeTable() {
    return {
        // Languages and runtimes
        {"kotlin-stdlib", "Kotlin Standard Library", "Language", "Apache-2.0", "https://kotlinlang.org", {"Lkotlin/"}, "org.jetbrains.kotlin:kotlin-stdlib"},
        {"kotlinx-coroutines", "Kotlin Coroutines", "Language", "Apache-2.0", "https://github.com/Kotlin/kotlinx.coroutines", {"Lkotlinx/coroutines/"}, "org.jetbrains.kotlinx:kotlinx-coroutines-core"},
        {"kotlinx-serialization", "Kotlin Serialization", "Serialization", "Apache-2.0", "https://github.com/Kotlin/kotlinx.serialization", {"Lkotlinx/serialization/"}, "org.jetbrains.kotlinx:kotlinx-serialization-core"},
        {"jetbrains-annotations", "JetBrains Annotations", "Language", "Apache-2.0", "https://github.com/JetBrains/java-annotations", {"Lorg/jetbrains/annotations/", "Lorg/intellij/lang/annotations/"}, "org.jetbrains:annotations"},
        {"desugar-jdk-libs", "Core Library Desugaring", "Language", "GPL-2.0-with-classpath-exception", "https://github.com/google/desugar_jdk_libs", {"Lj$/"}, "com.android.tools:desugar_jdk_libs"},

        // Android
        {"androidx", "AndroidX (Jetpack)", "Android", "Apache-2.0", "https://developer.android.com/jetpack/androidx", {"Landroidx/"}, ""},
        {"androidx-appcompat", "AndroidX AppCompat", "Android", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/appcompat", {"Landroidx/appcompat/"}, "androidx.appcompat:appcompat"},
        {"androidx-room", "Room", "Storage", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/room", {"Landroidx/room/"}, "androidx.room:room-runtime"},
        {"androidx-work", "WorkManager", "Android", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/work", {"Landroidx/work/"}, "androidx.work:work-runtime"},
        {"androidx-compose", "Jetpack Compose", "UI", "Apache-2.0", "https://developer.android.com/jetpack/compose", {"Landroidx/compose/"}, "androidx.compose.ui:ui"},
        {"androidx-webkit", "AndroidX WebKit", "Web", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/webkit", {"Landroidx/webkit/"}, "androidx.webkit:webkit"},
        {"androidx-biometric", "AndroidX Biometric", "Security", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/biometric", {"Landroidx/biometric/"}, "androidx.biometric:biometric"},
        {"androidx-security-crypto", "AndroidX Security Crypto", "Security", "Apache-2.0", "https://developer.android.com/jetpack/androidx/releases/security", {"Landroidx/security/crypto/"}, "androidx.security:security-crypto"},
        {"androidx-media3", "Media3 / ExoPlayer", "Media", "Apache-2.0", "https://developer.android.com/media/media3", {"Landroidx/media3/"}, "androidx.media3:media3-exoplayer"},
        {"android-support", "Android Support Library", "Android", "Apache-2.0", "https://developer.android.com/topic/libraries/support-library", {"Landroid/support/"}, "com.android.support:support-compat"},
        {"material", "Material Components", "UI", "Apache-2.0", "https://github.com/material-components/material-components-android", {"Lcom/google/android/material/"}, "com.google.android.material:material"},

        // Google
        {"play-services", "Google Play Services", "Google", "Proprietary", "https://developers.google.com/android/guides/overview", {"Lcom/google/android/gms/"}, "com.google.android.gms:play-services-basement"},
        {"play-services-ads", "Google Mobile Ads", "Ads", "Proprietary", "https://developers.google.com/admob/android", {"Lcom/google/android/gms/ads/"}, "com.google.android.gms:play-services-ads"},
        {"play-services-location", "Play Services Location", "Location", "Proprietary", "https://developers.google.com/android/reference/com/google/android/gms/location/package-summary", {"Lcom/google/android/gms/location/"}, "com.google.android.gms:play-services-location"},
        {"play-services-maps", "Google Maps SDK", "Location", "Proprietary", "https://developers.google.com/maps/documentation/android-sdk", {"Lcom/google/android/gms/maps/"}, "com.google.android.gms:play-services-maps"},
        {"play-services-auth", "Google Sign-In", "Auth", "Proprietary", "https://developers.google.com/identity/sign-in/android", {"Lcom/google/android/gms/auth/"}, "com.google.android.gms:play-services-auth"},
        {"firebase", "Firebase", "Google", "Apache-2.0", "https://firebase.google.com", {"Lcom/google/firebase/"}, "com.google.firebase:firebase-common"},
        {"firebase-messaging", "Firebase Cloud Messaging", "Push", "Apache-2.0", "https://firebase.google.com/docs/cloud-messaging", {"Lcom/google/firebase/messaging/", "Lcom/google/firebase/iid/"}, "com.google.firebase:firebase-messaging"},
        {"firebase-analytics", "Firebase Analytics", "Analytics", "Proprietary", "https://firebase.google.com/docs/analytics", {"Lcom/google/firebase/analytics/", "Lcom/google/android/gms/measurement/"}, "com.google.firebase:firebase-analytics"},
        {"firebase-crashlytics", "Firebase Crashlytics", "Crash reporting", "Apache-2.0", "https://firebase.google.com/docs/crashlytics", {"Lcom/google/firebase/crashlytics/"}, "com.google.firebase:firebase-crashlytics"},
        {"firebase-firestore", "Cloud Firestore", "Storage", "Apache-2.0", "https://firebase.google.com/docs/firestore", {"Lcom/google/firebase/firestore/"}, "com.google.firebase:firebase-firestore"},
        {"firebase-database", "Firebase Realtime Database", "Storage", "Apache-2.0", "https://firebase.google.com/docs/database", {"Lcom/google/firebase/database/"}, "com.google.firebase:firebase-database"},
        {"firebase-auth", "Firebase Authentication", "Auth", "Proprietary", "https://firebase.google.com/docs/auth", {"Lcom/google/firebase/auth/"}, "com.google.firebase:firebase-auth"},
        {"gson", "Gson", "Serialization", "Apache-2.0", "https://github.com/google/gson", {"Lcom/google/gson/"}, "com.google.code.gson:gson"},
        {"guava", "Guava", "Utilities", "Apache-2.0", "https://github.com/google/guava", {"Lcom/google/common/"}, "com.google.guava:guava"},
        {"protobuf", "Protocol Buffers", "Serialization", "BSD-3-Clause", "https://protobuf.dev", {"Lcom/google/protobuf/"}, "com.google.protobuf:protobuf-javalite"},
        {"exoplayer", "ExoPlayer", "Media", "Apache-2.0", "https://github.com/google/ExoPlayer", {"Lcom/google/android/exoplayer2/"}, "com.google.android.exoplayer:exoplayer"},
        {"zxing", "ZXing", "Barcode", "Apache-2.0", "https://github.com/zxing/zxing", {"Lcom/google/zxing/"}, "com.google.zxing:core"},
        {"mlkit", "ML Kit", "Machine learning", "Proprietary", "https://developers.google.com/ml-kit", {"Lcom/google/mlkit/"}, "com.google.mlkit:common"},
        {"tink", "Tink", "Security", "Apache-2.0", "https://github.com/tink-crypto/tink-java", {"Lcom/google/crypto/tink/"}, "com.google.crypto.tink:tink-android"},
        {"dagger", "Dagger", "Dependency injection", "Apache-2.0", "https://dagger.dev", {"Ldagger/"}, "com.google.dagger:dagger"},
        {"hilt", "Hilt", "Dependency injection", "Apache-2.0", "https://dagger.dev/hilt", {"Ldagger/hilt/"}, "com.google.dagger:hilt-android"},
        {"javax-inject", "javax.inject", "Dependency injection", "Apache-2.0", "https://github.com/javax-inject/javax-inject", {"Ljavax/inject/"}, "javax.inject:javax.inject"},

        // Square and networking
        {"okhttp3", "OkHttp", "Networking", "Apache-2.0", "https://square.github.io/okhttp", {"Lokhttp3/"}, "com.squareup.okhttp3:okhttp"},
        {"okhttp2", "OkHttp 2", "Networking", "Apache-2.0", "https://square.github.io/okhttp", {"Lcom/squareup/okhttp/"}, "com.squareup.okhttp:okhttp"},
        {"okio", "Okio", "Networking", "Apache-2.0", "https://square.github.io/okio", {"Lokio/"}, "com.squareup.okio:okio"},
        {"retrofit2", "Retrofit", "Networking", "Apache-2.0", "https://square.github.io/retrofit", {"Lretrofit2/"}, "com.squareup.retrofit2:retrofit"},
        {"retrofit1", "Retrofit 1", "Networking", "Apache-2.0", "https://square.github.io/retrofit", {"Lretrofit/"}, "com.squareup.retrofit:retrofit"},
        {"moshi", "Moshi", "Serialization", "Apache-2.0", "https://github.com/square/moshi", {"Lcom/squareup/moshi/"}, "com.squareup.moshi:moshi"},
        {"picasso", "Picasso", "Images", "Apache-2.0", "https://square.github.io/picasso", {"Lcom/squareup/picasso/"}, "com.squareup.picasso:picasso"},
        {"leakcanary", "LeakCanary", "Debugging", "Apache-2.0", "https://square.github.io/leakcanary", {"Lleakcanary/", "Lcom/squareup/leakcanary/"}, "com.squareup.leakcanary:leakcanary-android"},
        {"volley", "Volley", "Networking", "Apache-2.0", "https://google.github.io/volley", {"Lcom/android/volley/"}, "com.android.volley:volley"},
        {"apache-httpclient", "Apache HttpClient", "Networking", "Apache-2.0", "https://hc.apache.org", {"Lorg/apache/http/"}, "org.apache.httpcomponents:httpclient"},
        {"grpc", "gRPC", "Networking", "Apache-2.0", "https://grpc.io", {"Lio/grpc/"}, "io.grpc:grpc-core"},
        {"netty", "Netty", "Networking", "Apache-2.0", "https://netty.io", {"Lio/netty/"}, "io.netty:netty-common"},
        {"ktor", "Ktor Client", "Networking", "Apache-2.0", "https://ktor.io", {"Lio/ktor/"}, "io.ktor:ktor-client-core"},
        {"jsoup", "jsoup", "Web", "MIT", "https://jsoup.org", {"Lorg/jsoup/"}, "org.jsoup:jsoup"},

        // Reactive, DI, utilities
        {"rxjava2", "RxJava 2", "Reactive", "Apache-2.0", "https://github.com/ReactiveX/RxJava", {"Lio/reactivex/"}, "io.reactivex.rxjava2:rxjava"},
        {"rxjava3", "RxJava 3", "Reactive", "Apache-2.0", "https://github.com/ReactiveX/RxJava", {"Lio/reactivex/rxjava3/"}, "io.reactivex.rxjava3:rxjava"},
        {"rxandroid", "RxAndroid", "Reactive", "Apache-2.0", "https://github.com/ReactiveX/RxAndroid", {"Lio/reactivex/android/", "Lio/reactivex/rxjava3/android/"}, "io.reactivex.rxjava2:rxandroid"},
        {"koin", "Koin", "Dependency injection", "Apache-2.0", "https://insert-koin.io", {"Lorg/koin/"}, "io.insert-koin:koin-android"},
        {"eventbus", "EventBus", "Utilities", "Apache-2.0", "https://greenrobot.org/eventbus", {"Lorg/greenrobot/eventbus/"}, "org.greenrobot:eventbus"},
        {"timber", "Timber", "Logging", "Apache-2.0", "https://github.com/JakeWharton/timber", {"Ltimber/log/"}, "com.jakewharton.timber:timber"},
        {"butterknife", "Butter Knife", "UI", "Apache-2.0", "https://github.com/JakeWharton/butterknife", {"Lbutterknife/"}, "com.jakewharton:butterknife"},
        {"threetenabp", "ThreeTenABP", "Utilities", "BSD-3-Clause", "https://github.com/JakeWharton/ThreeTenABP", {"Lorg/threeten/bp/", "Lcom/jakewharton/threetenabp/"}, "com.jakewharton.threetenabp:threetenabp"},
        {"joda-time", "Joda-Time", "Utilities", "Apache-2.0", "https://www.joda.org/joda-time", {"Lorg/joda/time/"}, "joda-time:joda-time"},
        {"slf4j", "SLF4J", "Logging", "MIT", "https://www.slf4j.org", {"Lorg/slf4j/"}, "org.slf4j:slf4j-api"},
        {"log4j", "Apache Log4j 2", "Logging", "Apache-2.0", "https://logging.apache.org/log4j", {"Lorg/apache/logging/log4j/"}, "org.apache.logging.log4j:log4j-core"},
        {"log4j1", "Apache Log4j 1", "Logging", "Apache-2.0", "https://logging.apache.org/log4j/1.x", {"Lorg/apache/log4j/"}, "log4j:log4j"},
        {"commons-lang3", "Apache Commons Lang", "Utilities", "Apache-2.0", "https://commons.apache.org/lang", {"Lorg/apache/commons/lang3/"}, "org.apache.commons:commons-lang3"},
        {"commons-io", "Apache Commons IO", "Utilities", "Apache-2.0", "https://commons.apache.org/io", {"Lorg/apache/commons/io/"}, "commons-io:commons-io"},
        {"commons-codec", "Apache Commons Codec", "Utilities", "Apache-2.0", "https://commons.apache.org/codec", {"Lorg/apache/commons/codec/"}, "commons-codec:commons-codec"},
        {"commons-collections", "Apache Commons Collections", "Utilities", "Apache-2.0", "https://commons.apache.org/collections", {"Lorg/apache/commons/collections/"}, "commons-collections:commons-collections"},
        {"commons-text", "Apache Commons Text", "Utilities", "Apache-2.0", "https://commons.apache.org/text", {"Lorg/apache/commons/text/"}, "org.apache.commons:commons-text"},

        // Serialization
        {"jackson", "Jackson", "Serialization", "Apache-2.0", "https://github.com/FasterXML/jackson", {"Lcom/fasterxml/jackson/"}, "com.fasterxml.jackson.core:jackson-databind"},
        {"fastjson", "Fastjson", "Serialization", "Apache-2.0", "https://github.com/alibaba/fastjson", {"Lcom/alibaba/fastjson/"}, "com.alibaba:fastjson"},
        {"xstream", "XStream", "Serialization", "BSD-3-Clause", "https://x-stream.github.io", {"Lcom/thoughtworks/xstream/"}, "com.thoughtworks.xstream:xstream"},
        {"snakeyaml", "SnakeYAML", "Serialization", "Apache-2.0", "https://bitbucket.org/snakeyaml/snakeyaml", {"Lorg/yaml/snakeyaml/"}, "org.yaml:snakeyaml"},

        // Storage and crypto
        {"sqlcipher", "SQLCipher", "Storage", "BSD-3-Clause", "https://www.zetetic.net/sqlcipher", {"Lnet/sqlcipher/", "Lnet/zetetic/"}, "net.zetetic:android-database-sqlcipher"},
        {"realm", "Realm", "Storage", "Apache-2.0", "https://github.com/realm/realm-java", {"Lio/realm/"}, "io.realm:realm-android-library"},
        {"mmkv", "MMKV", "Storage", "BSD-3-Clause", "https://github.com/Tencent/MMKV", {"Lcom/tencent/mmkv/"}, "com.tencent:mmkv"},
        {"greendao", "greenDAO", "Storage", "Apache-2.0", "https://greenrobot.org/greendao", {"Lorg/greenrobot/greendao/"}, "org.greenrobot:greendao"},
        {"bouncycastle", "Bouncy Castle", "Security", "MIT", "https://www.bouncycastle.org", {"Lorg/bouncycastle/"}, "org.bouncycastle:bcprov-jdk15on"},
        {"spongycastle", "Spongy Castle", "Security", "MIT", "https://rtyley.github.io/spongycastle", {"Lorg/spongycastle/"}, "com.madgag.spongycastle:prov"},
        {"conscrypt", "Conscrypt", "Security", "Apache-2.0", "https://github.com/google/conscrypt", {"Lorg/conscrypt/"}, "org.conscrypt:conscrypt-android"},

        // Images and UI
        {"glide", "Glide", "Images", "BSD-2-Clause", "https://github.com/bumptech/glide", {"Lcom/bumptech/glide/"}, "com.github.bumptech.glide:glide"},
        {"coil", "Coil", "Images", "Apache-2.0", "https://coil-kt.github.io/coil", {"Lcoil/"}, "io.coil-kt:coil"},
        {"fresco", "Fresco", "Images", "MIT", "https://frescolib.org", {"Lcom/facebook/fresco/", "Lcom/facebook/imagepipeline/", "Lcom/facebook/drawee/"}, "com.facebook.fresco:fresco"},
        {"lottie", "Lottie", "UI", "Apache-2.0", "https://airbnb.io/lottie", {"Lcom/airbnb/lottie/"}, "com.airbnb.android:lottie"},

        // Cross-platform frameworks
        {"flutter", "Flutter", "Framework", "BSD-3-Clause", "https://flutter.dev", {"Lio/flutter/"}, "io.flutter:flutter_embedding_release"},
        {"react-native", "React Native", "Framework", "MIT", "https://reactnative.dev", {"Lcom/facebook/react/"}, "com.facebook.react:react-native"},
        {"hermes", "Hermes", "Framework", "MIT", "https://hermesengine.dev", {"Lcom/facebook/hermes/"}, "com.facebook.react:hermes-android"},
        {"xamarin", "Xamarin / .NET for Android", "Framework", "MIT", "https://dotnet.microsoft.com/apps/xamarin", {"Lmono/android/", "Lmono/"}, ""},
        {"unity", "Unity", "Framework", "Proprietary", "https://unity.com", {"Lcom/unity3d/player/"}, ""},
        {"cordova", "Apache Cordova", "Framework", "Apache-2.0", "https://cordova.apache.org", {"Lorg/apache/cordova/"}, "org.apache.cordova:framework"},
        {"capacitor", "Capacitor", "Framework", "MIT", "https://capacitorjs.com", {"Lcom/getcapacitor/"}, "com.capacitorjs:core"},

        // Social, analytics, ads, payments
        {"facebook-sdk", "Facebook SDK", "Social", "Proprietary", "https://developers.facebook.com/docs/android", {"Lcom/facebook/"}, "com.facebook.android:facebook-android-sdk"},
        {"sentry", "Sentry", "Crash reporting", "MIT", "https://sentry.io", {"Lio/sentry/"}, "io.sentry:sentry-android"},
        {"appsflyer", "AppsFlyer", "Analytics", "Proprietary", "https://www.appsflyer.com", {"Lcom/appsflyer/"}, "com.appsflyer:af-android-sdk"},
        {"adjust", "Adjust", "Analytics", "MIT", "https://www.adjust.com", {"Lcom/adjust/sdk/"}, "com.adjust.sdk:adjust-android"},
        {"branch", "Branch", "Analytics", "MIT", "https://branch.io", {"Lio/branch/"}, "io.branch.sdk.android:library"},
        {"mixpanel", "Mixpanel", "Analytics", "Apache-2.0", "https://mixpanel.com", {"Lcom/mixpanel/"}, "com.mixpanel.android:mixpanel-android"},
        {"amplitude", "Amplitude", "Analytics", "MIT", "https://amplitude.com", {"Lcom/amplitude/"}, "com.amplitude:android-sdk"},
        {"segment", "Segment", "Analytics", "MIT", "https://segment.com", {"Lcom/segment/analytics/"}, "com.segment.analytics.android:analytics"},
        {"braze", "Braze", "Analytics", "Proprietary", "https://www.braze.com", {"Lcom/appboy/", "Lcom/braze/"}, "com.braze:android-sdk-ui"},
        {"onesignal", "OneSignal", "Push", "MIT", "https://onesignal.com", {"Lcom/onesignal/"}, "com.onesignal:OneSignal"},
        {"applovin", "AppLovin", "Ads", "Proprietary", "https://www.applovin.com", {"Lcom/applovin/"}, "com.applovin:applovin-sdk"},
        {"ironsource", "ironSource", "Ads", "Proprietary", "https://www.is.com", {"Lcom/ironsource/"}, "com.ironsource.sdk:mediationsdk"},
        {"unity-ads", "Unity Ads", "Ads", "Proprietary", "https://unity.com/products/unity-ads", {"Lcom/unity3d/ads/", "Lcom/unity3d/services/"}, "com.unity3d.ads:unity-ads"},
        {"mopub", "MoPub", "Ads", "Proprietary", "https://github.com/mopub/mopub-android-sdk", {"Lcom/mopub/"}, "com.mopub:mopub-sdk"},
        {"chartboost", "Chartboost", "Ads", "Proprietary", "https://www.chartboost.com", {"Lcom/chartboost/"}, "com.chartboost:chartboost-sdk"},
        {"vungle", "Vungle", "Ads", "Proprietary", "https://vungle.com", {"Lcom/vungle/"}, "com.vungle:publisher-sdk-android"},
        {"stripe", "Stripe", "Payments", "MIT", "https://stripe.com/docs/mobile/android", {"Lcom/stripe/android/"}, "com.stripe:stripe-android"},
        {"paypal", "PayPal", "Payments", "Proprietary", "https://developer.paypal.com", {"Lcom/paypal/"}, "com.paypal.android:paypal-android-sdk"},
    };
}

}  // namespace

const std::vector<Library>& all() {
    static const std::vector<Library> table = makeTable();
    return table;
}

const Library* forClass(std::string_view descriptor) {
    const Library* best = nullptr;
    size_t bestLen = 0;
    for (const Library& lib : all())
        for (const char* p : lib.prefixes) {
            const std::string_view prefix(p);
            if (prefix.size() > bestLen && descriptor.substr(0, prefix.size()) == prefix) {
                best = &lib;
                bestLen = prefix.size();
            }
        }
    return best;
}

const Library* byId(std::string_view id) {
    for (const Library& lib : all())
        if (id == lib.id || (lib.maven[0] && id == lib.maven)) return &lib;
    return nullptr;
}

bool isPlatformClass(std::string_view d) {
    static constexpr std::string_view kPlatform[] = {"Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Lsun/",
                                                     "Llibcore/", "Lorg/json/", "Lorg/xml/", "Lorg/w3c/", "Lcom/android/internal/"};
    if (d.substr(0, 17) == "Landroid/support/") return false;
    if (d.substr(0, 14) == "Ljavax/inject/") return false;
    return std::any_of(std::begin(kPlatform), std::end(kPlatform), [&](std::string_view p) { return d.substr(0, p.size()) == p; });
}

}  // namespace libcatalog
