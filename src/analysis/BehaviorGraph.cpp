#include "analysis/BehaviorGraph.hpp"
#include <algorithm>
#include <deque>
#include <set>
#include <unordered_set>
#include "analysis/Dalvik.hpp"
#include "analysis/Jni.hpp"
#include "analysis/LibraryCatalog.hpp"

namespace behavior {
namespace {

constexpr uint32_t kAccNative = 0x0100;
constexpr uint32_t kNone = UINT32_MAX;
constexpr size_t kMaxEvidence = 40;

// One API rule: a class (descriptor; a trailing '/' makes it a package
// prefix) and a method name ("*" = any method) mapped to a value.
struct Rule {
    std::string_view cls;
    std::string_view method;
    const char* value;
};

constexpr const char* kFineLocation = "android.permission.ACCESS_FINE_LOCATION";
constexpr const char* kPhoneState = "android.permission.READ_PHONE_STATE";
constexpr const char* kCamera = "android.permission.CAMERA";
constexpr const char* kRecordAudio = "android.permission.RECORD_AUDIO";
constexpr const char* kSendSms = "android.permission.SEND_SMS";
constexpr const char* kInternet = "android.permission.INTERNET";
constexpr const char* kWifiState = "android.permission.ACCESS_WIFI_STATE";
constexpr const char* kChangeWifi = "android.permission.CHANGE_WIFI_STATE";
constexpr const char* kBtScan = "android.permission.BLUETOOTH_SCAN";
constexpr const char* kBtConnect = "android.permission.BLUETOOTH_CONNECT";
constexpr const char* kNetworkState = "android.permission.ACCESS_NETWORK_STATE";

const Rule kPermissionRules[] = {
    {"Landroid/location/LocationManager;", "requestLocationUpdates", kFineLocation},
    {"Landroid/location/LocationManager;", "requestSingleUpdate", kFineLocation},
    {"Landroid/location/LocationManager;", "getLastKnownLocation", kFineLocation},
    {"Landroid/location/LocationManager;", "getCurrentLocation", kFineLocation},
    {"Landroid/location/LocationManager;", "addGpsStatusListener", kFineLocation},
    {"Landroid/location/LocationManager;", "registerGnssStatusCallback", kFineLocation},
    {"Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation", kFineLocation},
    {"Lcom/google/android/gms/location/FusedLocationProviderClient;", "getCurrentLocation", kFineLocation},
    {"Lcom/google/android/gms/location/FusedLocationProviderClient;", "requestLocationUpdates", kFineLocation},
    {"Landroid/telephony/TelephonyManager;", "getAllCellInfo", kFineLocation},
    {"Landroid/telephony/TelephonyManager;", "getCellLocation", kFineLocation},
    {"Landroid/telephony/TelephonyManager;", "getDeviceId", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getImei", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getMeid", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getSubscriberId", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getSimSerialNumber", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getVoiceMailNumber", kPhoneState},
    {"Landroid/telephony/TelephonyManager;", "getLine1Number", "android.permission.READ_PHONE_NUMBERS"},
    {"Landroid/os/Build;", "getSerial", kPhoneState},
    {"Landroid/hardware/Camera;", "open", kCamera},
    {"Landroid/hardware/camera2/CameraManager;", "openCamera", kCamera},
    {"Landroid/media/MediaRecorder;", "setVideoSource", kCamera},
    {"Landroid/media/AudioRecord;", "<init>", kRecordAudio},
    {"Landroid/media/AudioRecord;", "startRecording", kRecordAudio},
    {"Landroid/media/MediaRecorder;", "setAudioSource", kRecordAudio},
    {"Landroid/speech/SpeechRecognizer;", "startListening", kRecordAudio},
    {"Landroid/telephony/SmsManager;", "sendTextMessage", kSendSms},
    {"Landroid/telephony/SmsManager;", "sendMultipartTextMessage", kSendSms},
    {"Landroid/telephony/SmsManager;", "sendDataMessage", kSendSms},
    {"Landroid/telecom/TelecomManager;", "placeCall", "android.permission.CALL_PHONE"},
    {"Landroid/accounts/AccountManager;", "getAccounts", "android.permission.GET_ACCOUNTS"},
    {"Landroid/accounts/AccountManager;", "getAccountsByType", "android.permission.GET_ACCOUNTS"},
    {"Landroid/net/wifi/WifiManager;", "getConnectionInfo", kWifiState},
    {"Landroid/net/wifi/WifiManager;", "getScanResults", kWifiState},
    {"Landroid/net/wifi/WifiManager;", "getConfiguredNetworks", kWifiState},
    {"Landroid/net/wifi/WifiManager;", "startScan", kChangeWifi},
    {"Landroid/net/wifi/WifiManager;", "setWifiEnabled", kChangeWifi},
    {"Landroid/bluetooth/BluetoothAdapter;", "startDiscovery", kBtScan},
    {"Landroid/bluetooth/le/BluetoothLeScanner;", "startScan", kBtScan},
    {"Landroid/bluetooth/BluetoothAdapter;", "getBondedDevices", kBtConnect},
    {"Landroid/bluetooth/BluetoothAdapter;", "enable", kBtConnect},
    {"Landroid/bluetooth/BluetoothDevice;", "connectGatt", kBtConnect},
    {"Landroid/os/Vibrator;", "vibrate", "android.permission.VIBRATE"},
    {"Landroid/os/PowerManager;", "newWakeLock", "android.permission.WAKE_LOCK"},
    {"Landroid/content/pm/PackageManager;", "getInstalledPackages", "android.permission.QUERY_ALL_PACKAGES"},
    {"Landroid/content/pm/PackageManager;", "getInstalledApplications", "android.permission.QUERY_ALL_PACKAGES"},
    {"Landroid/app/NotificationManager;", "notify", "android.permission.POST_NOTIFICATIONS"},
    {"Landroidx/core/app/NotificationManagerCompat;", "notify", "android.permission.POST_NOTIFICATIONS"},
    {"Landroid/net/ConnectivityManager;", "getActiveNetworkInfo", kNetworkState},
    {"Landroid/net/ConnectivityManager;", "getActiveNetwork", kNetworkState},
    {"Landroid/net/ConnectivityManager;", "getNetworkCapabilities", kNetworkState},
    {"Landroid/net/ConnectivityManager;", "registerNetworkCallback", kNetworkState},
    {"Landroid/hardware/biometrics/BiometricPrompt;", "authenticate", "android.permission.USE_BIOMETRIC"},
    {"Landroidx/biometric/BiometricPrompt;", "authenticate", "android.permission.USE_BIOMETRIC"},
    {"Landroid/hardware/fingerprint/FingerprintManager;", "authenticate", "android.permission.USE_FINGERPRINT"},
    {"Landroid/app/WallpaperManager;", "setBitmap", "android.permission.SET_WALLPAPER"},
    {"Landroid/app/WallpaperManager;", "setResource", "android.permission.SET_WALLPAPER"},
    {"Landroid/app/WallpaperManager;", "setStream", "android.permission.SET_WALLPAPER"},
    {"Landroid/os/Environment;", "getExternalStorageDirectory", "android.permission.READ_EXTERNAL_STORAGE"},
    {"Landroid/os/Environment;", "getExternalStoragePublicDirectory", "android.permission.READ_EXTERNAL_STORAGE"},
    {"Landroid/provider/MediaStore$Images$Media;", "insertImage", "android.permission.WRITE_EXTERNAL_STORAGE"},
    {"Ljava/net/URL;", "openConnection", kInternet},
    {"Ljava/net/URL;", "openStream", kInternet},
    {"Ljava/net/Socket;", "<init>", kInternet},
    {"Lokhttp3/OkHttpClient;", "newCall", kInternet},
    {"Lokhttp3/OkHttpClient;", "newWebSocket", kInternet},
    {"Landroid/webkit/WebView;", "loadUrl", kInternet},
};

const Rule kNetworkRules[] = {
    {"Ljava/net/URL;", "openConnection", "HttpURLConnection"},
    {"Ljava/net/URL;", "openStream", "HttpURLConnection"},
    {"Ljava/net/HttpURLConnection;", "connect", "HttpURLConnection"},
    {"Ljavax/net/ssl/HttpsURLConnection;", "connect", "HttpURLConnection"},
    {"Lokhttp3/OkHttpClient;", "newCall", "OkHttp"},
    {"Lokhttp3/OkHttpClient;", "newWebSocket", "OkHttp WebSocket"},
    {"Lokhttp3/Request$Builder;", "url", "OkHttp"},
    {"Lcom/squareup/okhttp/OkHttpClient;", "newCall", "OkHttp"},
    {"Lretrofit2/Retrofit$Builder;", "baseUrl", "Retrofit"},
    {"Lretrofit2/Retrofit;", "create", "Retrofit"},
    {"Landroid/webkit/WebView;", "loadUrl", "WebView"},
    {"Landroid/webkit/WebView;", "postUrl", "WebView"},
    {"Landroid/webkit/WebView;", "loadDataWithBaseURL", "WebView"},
    {"Lorg/apache/http/client/HttpClient;", "execute", "Apache HttpClient"},
    {"Lorg/apache/http/impl/client/DefaultHttpClient;", "execute", "Apache HttpClient"},
    {"Lcom/android/volley/RequestQueue;", "add", "Volley"},
    {"Ljava/net/Socket;", "<init>", "Socket"},
    {"Ljavax/net/ssl/SSLSocketFactory;", "createSocket", "Socket"},
    {"Lio/ktor/client/", "*", "Ktor"},
    {"Lio/grpc/ManagedChannelBuilder;", "forAddress", "gRPC"},
    {"Lio/grpc/ManagedChannelBuilder;", "forTarget", "gRPC"},
};

const Rule kStorageRules[] = {
    {"Landroid/database/sqlite/SQLiteDatabase;", "*", "SQLite"},
    {"Landroid/database/sqlite/SQLiteOpenHelper;", "<init>", "SQLite"},
    {"Landroid/database/sqlite/SQLiteOpenHelper;", "getWritableDatabase", "SQLite"},
    {"Landroid/database/sqlite/SQLiteOpenHelper;", "getReadableDatabase", "SQLite"},
    {"Landroid/content/Context;", "openOrCreateDatabase", "SQLite"},
    {"Landroid/content/Context;", "getSharedPreferences", "SharedPreferences"},
    {"Landroid/preference/PreferenceManager;", "getDefaultSharedPreferences", "SharedPreferences"},
    {"Landroidx/preference/PreferenceManager;", "getDefaultSharedPreferences", "SharedPreferences"},
    {"Landroidx/security/crypto/EncryptedSharedPreferences;", "create", "EncryptedSharedPreferences"},
    {"Landroidx/room/Room;", "databaseBuilder", "Room"},
    {"Landroidx/room/Room;", "inMemoryDatabaseBuilder", "Room"},
    {"Landroidx/datastore/", "*", "DataStore"},
    {"Lio/realm/Realm;", "*", "Realm"},
    {"Lnet/sqlcipher/database/SQLiteDatabase;", "*", "SQLCipher"},
    {"Lnet/zetetic/database/sqlcipher/SQLiteDatabase;", "*", "SQLCipher"},
    {"Lcom/tencent/mmkv/MMKV;", "*", "MMKV"},
    {"Landroid/content/ContentResolver;", "query", "ContentProvider"},
    {"Landroid/content/ContentResolver;", "insert", "ContentProvider"},
    {"Landroid/content/ContentResolver;", "update", "ContentProvider"},
    {"Landroid/content/ContentResolver;", "delete", "ContentProvider"},
    {"Landroid/content/Context;", "openFileOutput", "Files"},
    {"Landroid/content/Context;", "openFileInput", "Files"},
    {"Lcom/google/firebase/firestore/FirebaseFirestore;", "collection", "Firestore"},
    {"Lcom/google/firebase/database/FirebaseDatabase;", "getReference", "Firebase Realtime Database"},
};

const Rule kLibraryRules[] = {
    {"Ljava/lang/System;", "loadLibrary", "loadLibrary"},
    {"Ljava/lang/System;", "load", "load"},
    {"Ljava/lang/Runtime;", "loadLibrary", "loadLibrary"},
    {"Ljava/lang/Runtime;", "load", "load"},
    {"Lcom/getkeepsafe/relinker/ReLinker;", "loadLibrary", "loadLibrary"},
};

// Framework classes that are a Context (the receiver type compilers emit for
// this.getSharedPreferences() is the app's own Activity or Service).
bool isContextClass(std::string_view d) {
    static constexpr std::string_view kContexts[] = {
        "Landroid/content/Context;",       "Landroid/content/ContextWrapper;", "Landroid/view/ContextThemeWrapper;",
        "Landroid/app/Activity;",          "Landroid/app/Service;",           "Landroid/app/Application;",
        "Landroid/app/IntentService;",     "Landroid/app/ListActivity;",      "Landroid/app/NativeActivity;",
        "Landroid/inputmethodservice/InputMethodService;", "Landroid/accessibilityservice/AccessibilityService;",
    };
    return std::find(std::begin(kContexts), std::end(kContexts), d) != std::end(kContexts);
}

bool ruleClassMatches(std::string_view rule, std::string_view cls) {
    if (!rule.empty() && rule.back() == '/') return cls.substr(0, rule.size()) == rule;
    if (rule == cls) return true;
    return rule == "Landroid/content/Context;" && isContextClass(cls);
}

std::string toDescriptor(const std::string& javaName) {
    std::string d = "L" + javaName + ";";
    std::replace(d.begin(), d.end(), '.', '/');
    return d;
}

std::string shortClass(std::string_view d) {
    if (d.size() >= 2 && d.front() == 'L' && d.back() == ';') d = d.substr(1, d.size() - 2);
    const size_t slash = d.rfind('/');
    return std::string(slash == std::string_view::npos ? d : d.substr(slash + 1));
}

std::string javaName(std::string_view d) { return DexFile::descriptorToJava(d); }

// "(Ljava/lang/String;I)V" -> "String, int" (overloads stay apart in labels).
std::string shortParams(std::string_view proto) {
    std::string out;
    size_t i = proto.find('(');
    const size_t close = proto.find(')');
    if (i == std::string_view::npos || close == std::string_view::npos) return out;
    for (++i; i < close;) {
        size_t j = i;
        while (j < close && proto[j] == '[') ++j;
        if (j < close && proto[j] == 'L') j = proto.find(';', j);
        if (j == std::string_view::npos || j >= close) break;
        const std::string_view t = proto.substr(i, j - i + 1);
        std::string_view base = t.substr(t.find_first_not_of('['));
        std::string name;
        switch (base[0]) {
        case 'Z': name = "boolean"; break;
        case 'B': name = "byte"; break;
        case 'S': name = "short"; break;
        case 'C': name = "char"; break;
        case 'I': name = "int"; break;
        case 'J': name = "long"; break;
        case 'F': name = "float"; break;
        case 'D': name = "double"; break;
        default: name = shortClass(base); break;
        }
        for (size_t k = 0; k < t.size() && t[k] == '['; ++k) name += "[]";
        if (!out.empty()) out += ", ";
        out += name;
        i = j + 1;
    }
    return out;
}

// "Lcom/a/B;->name(I)V" -> "B.name(int)"
std::string methodLabel(std::string_view cls, std::string_view name, std::string_view proto = {}) {
    const std::string params = shortParams(proto);
    if (name == "<init>") return "new " + shortClass(cls) + "(" + params + ")";
    if (name == "<clinit>") return shortClass(cls) + ".<clinit>";
    return shortClass(cls) + "." + std::string(name) + "(" + params + ")";
}

std::string permissionLabel(std::string_view p) {
    const size_t dot = p.rfind('.');
    return std::string(dot == std::string_view::npos ? p : p.substr(dot + 1));
}

// A capability one method touches.
struct Hit {
    NodeKind kind;
    EdgeKind edge;
    std::string key, label, detail, evidence, target, via;
    bool flagged = false;
};

struct MethodInfo {
    ApkAnalysis::MethodDef def;
    uint32_t cls = kNone;  // index into ApkAnalysis::classes()
};

struct Visit {
    std::vector<std::pair<uint32_t, EdgeKind>> succ;
    std::vector<Hit> hits;
};

class Builder {
public:
    Builder(const ApkAnalysis& a, const Input& in, const Options& opt, const std::atomic<bool>* cancel)
        : a_(a), in_(in), opt_(opt), cancel_(cancel) {}

    Graph run() {
        indexMethods();
        if (stopped()) return std::move(g_);
        walk();
        if (stopped()) return std::move(g_);
        emit();
        return std::move(g_);
    }

private:
    bool stopped() const { return cancel_ && cancel_->load(); }

    void indexMethods() {
        const auto& classes = a_.classes();
        for (uint32_t c = 0; c < static_cast<uint32_t>(classes.size()); ++c) {
            if ((c & 1023) == 0 && stopped()) return;
            for (const ApkAnalysis::MethodDef& m : a_.methodsOf(classes[c])) {
                const auto id = static_cast<uint32_t>(methods_.size());
                methods_.push_back({m, c});
                bySig_.emplace(a_.methodSignature(m), id);
                byClass_[c].push_back(id);
            }
        }
    }

    // App superclasses (descriptors), nearest first, framework class last when known.
    const std::vector<std::string>& ancestors(const std::string& cls) {
        auto it = ancestors_.find(cls);
        if (it != ancestors_.end()) return it->second;
        std::vector<std::string> out;
        const std::vector<std::string> chain = a_.superChain(cls);
        for (size_t i = 1; i < chain.size(); ++i) out.push_back(toDescriptor(chain[i]));
        return ancestors_.emplace(cls, std::move(out)).first->second;
    }

    template <size_t N>
    const char* match(const Rule (&rules)[N], const std::string& cls, std::string_view name) {
        const auto test = [&](std::string_view c) -> const char* {
            for (const Rule& r : rules)
                if ((r.method == "*" || r.method == name) && ruleClassMatches(r.cls, c)) return r.value;
            return nullptr;
        };
        if (const char* v = test(cls)) return v;
        if (!a_.findClass(cls)) return nullptr;  // framework class: no hierarchy to climb
        for (const std::string& up : ancestors(cls))
            if (const char* v = test(up)) return v;
        return nullptr;
    }

    // App method a reference resolves to (exact, then up the app hierarchy).
    uint32_t resolve(const std::string& cls, std::string_view name, const std::string& proto) {
        const std::string tail = "->" + std::string(name) + proto;
        auto it = bySig_.find(cls + tail);
        if (it != bySig_.end()) return it->second;
        if (!a_.findClass(cls)) return kNone;
        for (const std::string& up : ancestors(cls)) {
            it = bySig_.find(up + tail);
            if (it != bySig_.end()) return it->second;
        }
        return kNone;
    }

    // Library code is a boundary: calls into it count as API calls, not as code to walk.
    bool isLibrary(uint32_t m) {
        const uint32_t c = methods_[m].cls;
        auto it = libraryClass_.find(c);
        if (it != libraryClass_.end()) return it->second;
        const std::string_view d = a_.classDescriptor(a_.classes()[c]);
        const bool lib = libcatalog::forClass(d) != nullptr || libcatalog::isPlatformClass(d);
        libraryClass_.emplace(c, lib);
        return lib;
    }

    void addHit(Visit& v, Hit h) {
        for (Hit& existing : v.hits)
            if (existing.kind == h.kind && existing.key == h.key && existing.via == h.via) {
                if (!h.evidence.empty() && existing.evidence.find(h.evidence) == std::string::npos) {
                    if (!existing.evidence.empty()) existing.evidence += '\n';
                    existing.evidence += h.evidence;
                }
                return;
            }
        v.hits.push_back(std::move(h));
    }

    Visit sweep(uint32_t id) {
        Visit v;
        const MethodInfo& mi = methods_[id];
        const DexFile& dex = *a_.dexes()[mi.def.dex];
        DexFile::CodeItem code;
        if (!mi.def.method.codeOff || !dex.codeItem(mi.def.method.codeOff, code)) return v;
        const std::string self(a_.classDescriptor(a_.classes()[mi.cls]));
        struct Pending {
            uint32_t pc;
            const char* family;
            bool library;  // a loadLibrary call rather than storage
            std::string via;
        };
        std::vector<Pending> pending;  // calls whose constant arguments name the store / library
        std::vector<std::pair<const char*, std::string>> networkCalls;
        bool hasUrl = false;
        std::unordered_set<uint32_t> seenSucc;
        for (uint32_t pc = 0; pc < code.insnsSize;) {
            const dalvik::Insn in = dalvik::decode(code, pc);
            pc += std::max<uint32_t>(in.size, 1);
            if (!in.valid || in.payload) continue;
            const dalvik::OpInfo& info = dalvik::opInfo(in.opcode);
            if (info.ref == dalvik::RefKind::String && in.index != DexFile::kNoIndex) {
                const std::string s = dex.string(in.index);
                for (const std::string& url : ApkAnalysis::extractUrls(s)) {
                    const std::string host = urlHost(url);
                    if (host.empty()) continue;
                    hasUrl = true;
                    const bool cleartext = url.rfind("http://", 0) == 0 || url.rfind("ws://", 0) == 0;
                    const bool local = host == "localhost" || host == "127.0.0.1" || host == "10.0.2.2";
                    addHit(v, {NodeKind::Endpoint, EdgeKind::Network, host, host, "", url, url, "", cleartext && !local});
                }
                continue;
            }
            if (info.flow != dalvik::Flow::Invoke || info.ref != dalvik::RefKind::Method || in.index == DexFile::kNoIndex) continue;
            const std::string cls(dex.typeDescriptor(dex.methodClass(in.index)));
            const std::string_view name = dex.methodName(in.index);
            const std::string proto = dex.protoDescriptor(dex.methodProto(in.index));
            const std::string via = methodLabel(cls, name);
            const uint32_t target = resolve(cls, name, proto);
            if (target != kNone && (methods_[target].def.method.accessFlags & kAccNative)) {
                const MethodInfo& t = methods_[target];
                const std::string tcls(a_.classDescriptor(a_.classes()[t.cls]));
                const std::string tname(a_.dexes()[t.def.dex]->methodName(t.def.method.methodIdx));
                const std::string symbol = jni::shortName(tcls, tname);
                const DexFile& tdex = *a_.dexes()[t.def.dex];
                addHit(v, {NodeKind::Native, EdgeKind::CallsNative, symbol,
                           methodLabel(tcls, tname, tdex.protoDescriptor(tdex.methodProto(t.def.method.methodIdx))), "native method",
                           a_.methodSignature(t.def), symbol, via});
                continue;
            }
            if (target != kNone && !isLibrary(target)) {
                const uint32_t tcls = methods_[target].cls;
                if (seenSucc.insert(target).second) v.succ.emplace_back(target, EdgeKind::Calls);
                // `new X()` of another app class: the framework calls X's other methods.
                if (name == "<init>" && tcls != mi.cls) {
                    auto it = byClass_.find(tcls);
                    if (it != byClass_.end())
                        for (uint32_t m : it->second) {
                            const std::string_view mn = a_.dexes()[methods_[m].def.dex]->methodName(methods_[m].def.method.methodIdx);
                            if (mn == "<init>" || mn == "<clinit>" || !methods_[m].def.method.codeOff) continue;
                            if (seenSucc.insert(m).second) v.succ.emplace_back(m, EdgeKind::Callback);
                        }
                }
                continue;
            }
            // Framework or library API: what does it give access to?
            if (const char* perm = match(kPermissionRules, cls, name))
                addHit(v, {NodeKind::Permission, EdgeKind::UsesPermission, perm, permissionLabel(perm), "", via, perm, via});
            if (const char* net = match(kNetworkRules, cls, name)) networkCalls.emplace_back(net, via);
            if (const char* store = match(kStorageRules, cls, name)) pending.push_back({in.pc, store, false, via});
            if (const char* lib = match(kLibraryRules, cls, name)) pending.push_back({in.pc, lib, true, via});
        }
        if (!pending.empty()) {
            // Constant arguments name the database, preferences file or library.
            const auto consts = a_.constantArguments(mi.def);
            for (const Pending& p : pending) {
                std::vector<std::string> names;
                for (const auto& c : consts)
                    if (c.pc == p.pc)
                        for (const auto& [pos, value] : c.args)
                            if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
                                names.push_back(value.substr(1, value.size() - 2));
                if (p.library) {
                    for (const std::string& n : names) {
                        std::string lib = n;
                        if (std::string(p.family) == "loadLibrary") lib = "lib" + n + ".so";
                        else if (const size_t slash = lib.find_last_of('/'); slash != std::string::npos) lib = lib.substr(slash + 1);
                        addHit(v, {NodeKind::Native, EdgeKind::LoadsLibrary, "lib:" + lib, lib, "native library", "", lib, p.via});
                    }
                    if (names.empty())
                        addHit(v, {NodeKind::Native, EdgeKind::LoadsLibrary, "lib:?", "(dynamic library)", "native library", "", "", p.via});
                    continue;
                }
                // SQL text is evidence; a short identifier-like constant is the store's name.
                std::string storeName, sql;
                for (const std::string& n : names) {
                    const bool looksSql = n.find(' ') != std::string::npos;
                    if (looksSql) sql = n;
                    else if (storeName.empty() && !n.empty() && n.size() < 96) storeName = n;
                }
                const std::string family = p.family;
                const std::string key = storeName.empty() ? family : family + ":" + storeName;
                addHit(v, {NodeKind::Storage, EdgeKind::Storage, key, storeName.empty() ? family : storeName, family,
                           sql.empty() ? p.via : sql, "", p.via});
            }
        }
        if (!hasUrl)
            for (const auto& [family, via] : networkCalls)
                addHit(v, {NodeKind::Endpoint, EdgeKind::Network, "(dynamic)", "Dynamic URL", "", via, "", via});
        else
            for (Hit& h : v.hits)
                if (h.kind == NodeKind::Endpoint && h.via.empty() && !networkCalls.empty()) h.via = networkCalls.front().second;
        return v;
    }

    void walk() {
        std::deque<std::pair<uint32_t, int>> queue;
        const auto enqueue = [&](uint32_t m, int depth) {
            if (visits_.count(m) || depth > opt_.maxDepth) return;
            if (visits_.size() >= opt_.maxMethods) {
                g_.truncated = true;
                return;
            }
            visits_.emplace(m, Visit{});
            queue.emplace_back(m, depth);
        };
        for (const ApkComponent& comp : in_.components) {
            const std::string java = componentClass(in_.packageName, comp.name);
            const ApkAnalysis::ClassEntry* entry = a_.findClass(java);
            const std::string desc = toDescriptor(java);
            std::vector<uint32_t> entries;
            if (entry) {
                ++g_.componentsResolved;
                // The component's methods plus inherited app (not library) methods it does not override.
                std::set<std::string> own;
                std::vector<std::string> chain = {desc};
                for (const std::string& up : ancestors(desc)) chain.push_back(up);
                for (const std::string& c : chain) {
                    const ApkAnalysis::ClassEntry* ce = a_.findClass(c);
                    if (!ce) break;
                    if (c != desc && (libcatalog::forClass(c) || libcatalog::isPlatformClass(c))) break;
                    const uint32_t ci = classIndex(*ce);
                    auto it = byClass_.find(ci);
                    if (it == byClass_.end()) continue;
                    for (uint32_t m : it->second) {
                        const DexFile& dex = *a_.dexes()[methods_[m].def.dex];
                        const uint32_t idx = methods_[m].def.method.methodIdx;
                        const std::string nameProto = std::string(dex.methodName(idx)) + dex.protoDescriptor(dex.methodProto(idx));
                        if (!own.insert(nameProto).second) continue;  // overridden lower in the chain
                        if (c != desc && nameProto.rfind("<init>", 0) == 0) continue;
                        if (methods_[m].def.method.codeOff) entries.push_back(m);
                    }
                }
            }
            componentEntries_.push_back({desc, std::move(entries)});
            for (uint32_t m : componentEntries_.back().second) enqueue(m, 0);
        }
        while (!queue.empty()) {
            if (stopped()) return;
            const auto [m, depth] = queue.front();
            queue.pop_front();
            Visit v = sweep(m);
            for (const auto& s : v.succ) enqueue(s.first, depth + 1);
            visits_[m] = std::move(v);
        }
        g_.methodsVisited = visits_.size();
    }

    uint32_t classIndex(const ApkAnalysis::ClassEntry& e) {
        if (classIndex_.empty())
            for (uint32_t i = 0; i < static_cast<uint32_t>(a_.classes().size()); ++i)
                classIndex_.emplace(static_cast<uint64_t>(a_.classes()[i].dex) << 32 | a_.classes()[i].def, i);
        auto it = classIndex_.find(static_cast<uint64_t>(e.dex) << 32 | e.def);
        return it == classIndex_.end() ? kNone : it->second;
    }

    uint32_t node(NodeKind kind, const std::string& key, const std::string& label, const std::string& detail) {
        const std::string id = std::to_string(static_cast<int>(kind)) + "|" + key;
        auto it = nodeIds_.find(id);
        if (it != nodeIds_.end()) return it->second;
        const auto index = static_cast<uint32_t>(g_.nodes.size());
        Node n;
        n.kind = kind;
        n.key = key;
        n.label = label;
        n.detail = detail;
        g_.nodes.push_back(std::move(n));
        nodeIds_.emplace(id, index);
        return index;
    }

    void edge(uint32_t from, uint32_t to, EdgeKind kind, const std::string& via = {}) {
        if (from == to) return;
        const uint64_t id = (static_cast<uint64_t>(from) << 32 | to) * 16 + static_cast<uint64_t>(kind);
        if (!edgeIds_.insert(id).second) return;
        g_.edges.push_back({from, to, kind, via});
    }

    void addEvidence(Node& n, const std::string& text) {
        size_t start = 0;
        while (start <= text.size()) {
            size_t end = text.find('\n', start);
            if (end == std::string::npos) end = text.size();
            const std::string line = text.substr(start, end - start);
            if (!line.empty() && n.evidence.size() < kMaxEvidence &&
                std::find(n.evidence.begin(), n.evidence.end(), line) == n.evidence.end())
                n.evidence.push_back(line);
            start = end + 1;
        }
    }

    void emit() {
        // Methods that lead to a capability: those with hits, and everything that reaches them.
        std::unordered_map<uint32_t, std::vector<uint32_t>> reverse;
        std::deque<uint32_t> work;
        std::unordered_set<uint32_t> useful;
        for (const auto& [m, v] : visits_) {
            for (const auto& s : v.succ) reverse[s.first].push_back(m);
            if (!v.hits.empty() && useful.insert(m).second) work.push_back(m);
        }
        while (!work.empty()) {
            const uint32_t m = work.front();
            work.pop_front();
            auto it = reverse.find(m);
            if (it == reverse.end()) continue;
            for (uint32_t caller : it->second)
                if (useful.insert(caller).second) work.push_back(caller);
        }

        std::unordered_map<std::string, uint32_t> componentNode;  // descriptor -> node
        for (size_t i = 0; i < in_.components.size(); ++i) {
            const ApkComponent& c = in_.components[i];
            const std::string& desc = componentEntries_[i].first;
            const bool launcher = std::find(c.categories.begin(), c.categories.end(), "android.intent.category.LAUNCHER") != c.categories.end();
            std::string detail = c.type;
            if (c.exported) detail += launcher ? ", exported (launcher)" : ", exported";
            const uint32_t n = node(NodeKind::Component, desc, shortClass(desc), detail);
            g_.nodes[n].flagged = c.exported && !launcher;
            g_.nodes[n].target = desc;
            for (const std::string& action : c.actions) addEvidence(g_.nodes[n], "action " + action);
            componentNode.emplace(desc, n);
        }

        std::unordered_map<uint32_t, uint32_t> methodNode;
        const auto methodNodeOf = [&](uint32_t m) {
            auto it = methodNode.find(m);
            if (it != methodNode.end()) return it->second;
            const MethodInfo& mi = methods_[m];
            const DexFile& dex = *a_.dexes()[mi.def.dex];
            const std::string cls(a_.classDescriptor(a_.classes()[mi.cls]));
            const std::string sig = a_.methodSignature(mi.def);
            const uint32_t idx = mi.def.method.methodIdx;
            const uint32_t n = node(NodeKind::Method, sig, methodLabel(cls, dex.methodName(idx), dex.protoDescriptor(dex.methodProto(idx))), javaName(cls));
            g_.nodes[n].target = sig;
            // Its class: the component node when it is one, a class node otherwise.
            auto comp = componentNode.find(cls);
            const uint32_t owner = comp != componentNode.end() ? comp->second : node(NodeKind::Class, cls, shortClass(cls), javaName(cls));
            if (comp == componentNode.end()) g_.nodes[owner].target = cls;
            edge(owner, n, EdgeKind::Contains);
            methodNode.emplace(m, n);
            return n;
        };

        // Sort for a stable node order (and so a stable layout) between runs.
        std::vector<uint32_t> kept(useful.begin(), useful.end());
        std::sort(kept.begin(), kept.end());
        for (size_t i = 0; i < in_.components.size(); ++i) {
            const uint32_t compNode = componentNode[componentEntries_[i].first];
            for (uint32_t m : componentEntries_[i].second)
                if (useful.count(m)) edge(compNode, methodNodeOf(m), EdgeKind::Entry);
        }
        for (uint32_t m : kept) {
            const uint32_t from = methodNodeOf(m);
            const Visit& v = visits_[m];
            for (const auto& [succ, kind] : v.succ)
                if (useful.count(succ)) edge(from, methodNodeOf(succ), kind);
            for (const Hit& h : v.hits) {
                std::string detail = h.detail;
                bool undeclared = false;
                if (h.kind == NodeKind::Permission) {
                    const bool exact = std::find(in_.declaredPermissions.begin(), in_.declaredPermissions.end(), h.key) != in_.declaredPermissions.end();
                    undeclared = !permissionSatisfied(h.key, in_.declaredPermissions, in_.targetSdk);
                    detail = exact ? "declared" : undeclared ? "used but not declared" : "covered by the manifest";
                }
                const uint32_t sink = node(h.kind, h.key, h.label, detail);
                Node& sn = g_.nodes[sink];
                if (h.flagged || undeclared) sn.flagged = true;
                if (!h.target.empty() && sn.target.empty()) sn.target = h.target;
                addEvidence(sn, h.evidence);
                edge(from, sink, h.edge, h.via);
            }
        }
        // Declared permissions that no reached code uses still belong in the picture.
        for (const std::string& p : in_.declaredPermissions)
            if (g_.find(NodeKind::Permission, p) < 0) node(NodeKind::Permission, p, permissionLabel(p), "declared; no use in reached code");
    }

    const ApkAnalysis& a_;
    const Input& in_;
    const Options& opt_;
    const std::atomic<bool>* cancel_;
    Graph g_;
    std::vector<MethodInfo> methods_;
    std::unordered_map<std::string, uint32_t> bySig_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> byClass_;
    std::unordered_map<std::string, std::vector<std::string>> ancestors_;
    std::unordered_map<uint32_t, bool> libraryClass_;
    std::unordered_map<uint64_t, uint32_t> classIndex_;
    std::unordered_map<uint32_t, Visit> visits_;
    std::vector<std::pair<std::string, std::vector<uint32_t>>> componentEntries_;  // descriptor, entry methods
    std::unordered_map<std::string, uint32_t> nodeIds_;
    std::unordered_set<uint64_t> edgeIds_;
};

}  // namespace

int Graph::find(NodeKind kind, std::string_view key) const {
    for (size_t i = 0; i < nodes.size(); ++i)
        if (nodes[i].kind == kind && nodes[i].key == key) return static_cast<int>(i);
    return -1;
}

size_t Graph::count(NodeKind kind) const {
    return static_cast<size_t>(std::count_if(nodes.begin(), nodes.end(), [&](const Node& n) { return n.kind == kind; }));
}

Graph build(const ApkAnalysis& a, const Input& in, const Options& opt, const std::atomic<bool>* cancel) {
    return Builder(a, in, opt, cancel).run();
}

std::vector<Reach> reachableCapabilities(const Graph& g, uint32_t from) {
    std::vector<Reach> out;
    if (from >= g.nodes.size()) return out;
    std::vector<std::vector<uint32_t>> next(g.nodes.size());
    for (const Edge& e : g.edges)
        if (e.kind != EdgeKind::Contains) next[e.from].push_back(e.to);
    std::vector<uint32_t> parent(g.nodes.size(), kNone);
    std::deque<uint32_t> q = {from};
    parent[from] = from;
    while (!q.empty()) {  // BFS: paths come out shortest first
        const uint32_t u = q.front();
        q.pop_front();
        for (uint32_t v : next[u]) {
            if (parent[v] != kNone) continue;
            parent[v] = u;
            const NodeKind k = g.nodes[v].kind;
            if (k == NodeKind::Method || k == NodeKind::Class || k == NodeKind::Component) {
                q.push_back(v);
                continue;
            }
            Reach r{v, {}};
            for (uint32_t at = v; at != from; at = parent[at]) r.path.push_back(at);
            r.path.push_back(from);
            std::reverse(r.path.begin(), r.path.end());
            out.push_back(std::move(r));
        }
    }
    return out;
}

bool permissionSatisfied(std::string_view permission, const std::vector<std::string>& declared, int targetSdk) {
    const auto has = [&](std::string_view p) { return std::find(declared.begin(), declared.end(), p) != declared.end(); };
    if (has(permission)) return true;
    // Permissions added in a later API level are not required by apps targeting an older one.
    static constexpr std::pair<std::string_view, int> kIntroduced[] = {
        {"android.permission.POST_NOTIFICATIONS", 33}, {"android.permission.BLUETOOTH_SCAN", 31},
        {"android.permission.BLUETOOTH_CONNECT", 31},  {"android.permission.QUERY_ALL_PACKAGES", 30},
        {"android.permission.USE_BIOMETRIC", 28},      {"android.permission.READ_PHONE_NUMBERS", 26},
    };
    for (const auto& [p, api] : kIntroduced)
        if (p == permission && targetSdk > 0 && targetSdk < api) return true;
    // Equivalent grants.
    if (permission == "android.permission.ACCESS_FINE_LOCATION") return has("android.permission.ACCESS_COARSE_LOCATION");
    if (permission == "android.permission.READ_PHONE_NUMBERS") return has("android.permission.READ_PHONE_STATE") || has("android.permission.READ_SMS");
    if (permission == "android.permission.BLUETOOTH_SCAN" || permission == "android.permission.BLUETOOTH_CONNECT")
        return targetSdk > 0 && targetSdk < 31 && has("android.permission.BLUETOOTH");
    if (permission == "android.permission.USE_BIOMETRIC") return has("android.permission.USE_FINGERPRINT");
    if (permission == "android.permission.READ_EXTERNAL_STORAGE")
        return has("android.permission.WRITE_EXTERNAL_STORAGE") || has("android.permission.READ_MEDIA_IMAGES") ||
               has("android.permission.MANAGE_EXTERNAL_STORAGE");
    return false;
}

std::string componentClass(const std::string& packageName, const std::string& name) {
    if (name.empty()) return name;
    if (name[0] == '.') return packageName + name;
    if (name.find('.') == std::string::npos) return packageName.empty() ? name : packageName + "." + name;
    return name;
}

const char* permissionFor(std::string_view cls, std::string_view method) {
    for (const Rule& r : kPermissionRules)
        if ((r.method == "*" || r.method == method) && ruleClassMatches(r.cls, cls)) return r.value;
    return nullptr;
}

const char* storageFor(std::string_view cls, std::string_view method) {
    for (const Rule& r : kStorageRules)
        if ((r.method == "*" || r.method == method) && ruleClassMatches(r.cls, cls)) return r.value;
    return nullptr;
}

const char* networkFor(std::string_view cls, std::string_view method) {
    for (const Rule& r : kNetworkRules)
        if ((r.method == "*" || r.method == method) && ruleClassMatches(r.cls, cls)) return r.value;
    return nullptr;
}

std::string urlHost(std::string_view url) {
    const size_t scheme = url.find("://");
    if (scheme == std::string_view::npos) return {};
    const std::string_view s = url.substr(0, scheme);
    if (s != "http" && s != "https" && s != "ws" && s != "wss") return {};
    std::string_view rest = url.substr(scheme + 3);
    const size_t end = rest.find_first_of("/?#");
    if (end != std::string_view::npos) rest = rest.substr(0, end);
    if (const size_t at = rest.rfind('@'); at != std::string_view::npos) rest = rest.substr(at + 1);  // user:pass@
    if (!rest.empty() && rest.front() == '[') {                                                        // [ipv6]:port
        const size_t close = rest.find(']');
        return close == std::string_view::npos ? std::string() : std::string(rest.substr(1, close - 1));
    }
    if (const size_t colon = rest.find(':'); colon != std::string_view::npos) rest = rest.substr(0, colon);
    std::string host(rest);
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // Format strings and placeholders ("%s", "{host}") are not hosts.
    if (host.empty() || host.find_first_of("%{}$<> \"'\\") != std::string::npos) return {};
    return host;
}

const char* kindName(NodeKind k) {
    switch (k) {
    case NodeKind::Component: return "Component";
    case NodeKind::Class: return "Class";
    case NodeKind::Method: return "Method";
    case NodeKind::Permission: return "Permission";
    case NodeKind::Endpoint: return "Endpoint";
    case NodeKind::Storage: return "Storage";
    case NodeKind::Native: return "Native";
    }
    return "?";
}

const char* edgeName(EdgeKind k) {
    switch (k) {
    case EdgeKind::Entry: return "entry point";
    case EdgeKind::Contains: return "contains";
    case EdgeKind::Calls: return "calls";
    case EdgeKind::Callback: return "callback";
    case EdgeKind::UsesPermission: return "needs permission";
    case EdgeKind::Network: return "network";
    case EdgeKind::Storage: return "storage";
    case EdgeKind::CallsNative: return "calls native";
    case EdgeKind::LoadsLibrary: return "loads library";
    }
    return "?";
}

}  // namespace behavior
