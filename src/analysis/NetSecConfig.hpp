#pragma once
#include <string>
#include <vector>
#include "core/AxmlDecoder.hpp"

// Android's network security config (res/xml/network_security_config.xml):
// which CAs the app trusts, where cleartext HTTP is allowed and which
// certificates are pinned. Parsed from the already-decoded AXML events, so
// it works on any APK without running anything.
namespace netsec {

struct Anchor {
    std::string src;  // "system", "user" or "@raw/some_ca"
    bool overridePins = false;
};

struct Pin {
    std::string digest;  // "SHA-256"
    std::string value;   // base64
};

struct Domain {
    std::string name;
    bool includeSubdomains = false;
};

struct Scope {  // <base-config> or <domain-config>
    std::vector<Domain> domains;  // empty for base-config
    int cleartext = -1;           // -1 unset, 0 false, 1 true
    std::vector<Anchor> anchors;
    std::vector<Pin> pins;
    std::string pinExpiration;
};

struct Config {
    bool present = false;
    bool hasBase = false;
    Scope base;
    std::vector<Scope> domainConfigs;
    std::vector<Anchor> debugAnchors;  // <debug-overrides>
    bool hasDebugOverrides = false;
};

// Collects a Config from AXML events (feed it through
// AxmlDecoder::decodeEvents, or call the callbacks directly in tests).
class Collector : public AxmlDecoder::Visitor {
public:
    Config result;
    void startElement(const std::string& name, const std::vector<AxmlDecoder::Attr>& attrs) override;
    void endElement(const std::string& name) override;
    void text(const std::string& text) override;

private:
    enum class Ctx { None, Base, Domain, Debug };
    Ctx ctx_ = Ctx::None;
    Scope* open_ = nullptr;
    bool inDomain_ = false;
    bool inPinSet_ = false;
    bool inPin_ = false;
    Pin pin_;
};

// One human-readable line per notable fact (cleartext, user CAs, pinning,
// debug overrides). `targetSdk` decides the platform default: cleartext is
// allowed below API 28 and blocked from 28, user CAs trusted below 24.
std::vector<std::string> notes(const Config& c, int targetSdk);

}  // namespace netsec
