#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "core/ApkArchive.hpp"
#include "core/ApkInfo.hpp"
#include "core/ResourceTable.hpp"

// Static security review of one APK: hardcoded secrets (bytecode strings,
// resources, bundled text files and key stores), the manifest and network
// security configuration, exported components, cryptography, TLS
// validation, WebView settings, file permissions, SQL, logging, command
// execution and dynamic code loading.
//
// Every finding carries a severity, a confidence (how sure the rule is that
// this is the issue it describes, not a probability of exploitability), the
// evidence it saw and where: a method + instruction, a class, a manifest
// element, a resource or a file. Findings in bundled third-party libraries
// name the library, so the app's own code can be reviewed first.
//
// scan() runs on a worker. Its Input is gathered on the thread owning the
// workspace (Workspace::securityInput); the archive is reopened privately
// for the text files it reads.
namespace security {

enum class Severity : uint8_t { Info, Low, Medium, High, Critical };
const char* severityName(Severity s);

struct Location {
    enum class Kind : uint8_t { None, Method, Class, Manifest, Resource, File } kind = Kind::None;
    std::string ref;  // method signature, class descriptor, manifest component / attribute, "string/name", entry path
    uint32_t pc = 0;  // Method: instruction
    int line = -1;    // File: 0-based line
};

struct Finding {
    std::string rule;  // id into rules()
    std::string title;
    Severity severity = Severity::Info;
    int confidence = 50;  // 0-100
    std::string evidence;
    Location location;
    std::string library;  // third-party library the code belongs to, "" for app code
};

struct Rule {
    const char* id;
    const char* category;  // "Secrets", "Manifest", "Components", "Cryptography", "Network", "WebView", "Storage", "Code"
    const char* title;
    const char* description;
    const char* recommendation;
    const char* cwe;    // "CWE-798"
    const char* masvs;  // OWASP MASVS v2 category, e.g. "MASVS-CRYPTO"
};
const std::vector<Rule>& rules();
const Rule* rule(const std::string& id);

struct Input {
    ApkInfo info;
    std::shared_ptr<const ApkAnalysis> analysis;     // optional: bytecode rules need it
    std::shared_ptr<const ResourceTable> resources;  // optional
    std::string networkSecurityConfig;  // decoded XML text of the referenced file, "" when none
    std::string networkSecurityConfigPath;
    std::string apkPath;                // reopened for text files
    std::vector<ApkArchive::Entry> entries;
};

struct Report {
    std::vector<Finding> findings;  // most severe first
    size_t methodsScanned = 0;
    size_t stringsScanned = 0;
    size_t filesScanned = 0;
    bool bytecodeScanned = false;
};

Report scan(const Input& in, const std::atomic<bool>* cancel = nullptr, std::atomic<size_t>* progress = nullptr);

// Secret patterns, exposed for the tests: the kind of secret a text contains
// ("AWS access key ID", ...) with the matching token, or false.
struct SecretMatch {
    std::string kind;
    std::string token;
    Severity severity;
    int confidence;
};
bool findSecret(std::string_view text, SecretMatch& out);

// Markdown and JSON renderings of a report (export).
std::string toMarkdown(const Report& r, const ApkInfo& info);
std::string toJson(const Report& r, const ApkInfo& info);

}  // namespace security
