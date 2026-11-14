#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "core/ApkInfo.hpp"

// What an APK does, as a graph: the manifest components, the app methods
// they reach, and the capabilities those methods touch - permission-guarded
// APIs, network endpoints, local storage and native code.
//
// Built on a worker thread from an immutable ApkAnalysis plus the manifest
// facts (ApkInfo is read on the UI thread and passed in by value). The walk
// starts at every component class (and its app superclasses), follows calls
// into app code, treats `new X()` of an app class as reaching X's methods
// (listeners, runnables and lambdas are invoked by the framework), and keeps
// only the methods that lead to a capability. The result is plain data with
// no reference back to the analysis.
namespace behavior {

enum class NodeKind : uint8_t { Component, Class, Method, Permission, Endpoint, Storage, Native };
constexpr int kNodeKinds = 7;

enum class EdgeKind : uint8_t {
    Entry,         // component -> one of its methods
    Contains,      // class -> method
    Calls,         // method -> method
    Callback,      // method -> method of a class it instantiates
    UsesPermission,
    Network,
    Storage,
    CallsNative,   // method -> native method
    LoadsLibrary,  // method -> native library
};

struct Node {
    NodeKind kind = NodeKind::Method;
    std::string key;     // unique per kind: descriptor, signature, permission, host, store, JNI name
    std::string label;   // short display name
    std::string detail;  // second line: component type, API family, library...
    std::vector<std::string> evidence;  // URLs of a host, names of a store, APIs that need a permission...
    bool flagged = false;  // exported component, undeclared permission, cleartext endpoint
    std::string target;    // navigation: method signature / class descriptor / JNI symbol
};

struct Edge {
    uint32_t from = 0, to = 0;
    EdgeKind kind = EdgeKind::Calls;
    std::string via;  // capability edges: the API call that makes the connection
};

struct Input {
    std::string packageName;
    std::vector<ApkComponent> components;
    std::vector<std::string> declaredPermissions;
    int targetSdk = 0;  // 0 = unknown (every permission counts)
};

// Whether the declared permissions cover an API's permission: also true when
// an equivalent one is declared (coarse for fine location, READ_PHONE_STATE
// for READ_PHONE_NUMBERS) or the permission postdates the target SDK
// (POST_NOTIFICATIONS before 33, BLUETOOTH_SCAN before 31, ...).
bool permissionSatisfied(std::string_view permission, const std::vector<std::string>& declared, int targetSdk);

struct Options {
    int maxDepth = 10;          // call depth from a component
    size_t maxMethods = 6000;   // methods swept before the walk stops (sets truncated)
};

struct Graph {
    std::vector<Node> nodes;
    std::vector<Edge> edges;
    size_t methodsVisited = 0;
    size_t componentsResolved = 0;  // components whose class has bytecode
    bool truncated = false;

    // Index of the node with this kind and key, or -1.
    int find(NodeKind kind, std::string_view key) const;
    size_t count(NodeKind kind) const;
};

Graph build(const ApkAnalysis& a, const Input& in, const Options& opt = {}, const std::atomic<bool>* cancel = nullptr);

// Capability nodes (permission, endpoint, storage, native) reachable from
// `from`, each with its shortest path (node indices, `from` first, the
// capability last) over the call edges. Ordered by path length.
struct Reach {
    uint32_t node;
    std::vector<uint32_t> path;
};
std::vector<Reach> reachableCapabilities(const Graph& g, uint32_t from);

// Fully qualified component class from a manifest name (".Main" -> "com.app.Main").
std::string componentClass(const std::string& packageName, const std::string& name);

// API knowledge, shared with the security scanner. `cls` is a descriptor.
// The Android permission an API needs ("android.permission.CAMERA"), or nullptr.
const char* permissionFor(std::string_view cls, std::string_view method);
// Storage family of an API ("SQLite", "SharedPreferences", "Room", ...), or nullptr.
const char* storageFor(std::string_view cls, std::string_view method);
// Network client family of an API ("HttpURLConnection", "OkHttp", "WebView", ...), or nullptr.
const char* networkFor(std::string_view cls, std::string_view method);
// Host of an http(s)/ws(s) URL ("" when it is not one).
std::string urlHost(std::string_view url);

const char* kindName(NodeKind k);
const char* edgeName(EdgeKind k);

}  // namespace behavior
