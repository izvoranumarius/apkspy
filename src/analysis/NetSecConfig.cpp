#include "analysis/NetSecConfig.hpp"

namespace netsec {

namespace {

// "android:foo" -> "foo" (the config's own attributes carry no namespace,
// but be lenient).
std::string local(const std::string& n) {
    const size_t c = n.rfind(':');
    return c == std::string::npos ? n : n.substr(c + 1);
}

std::string attr(const std::vector<AxmlDecoder::Attr>& attrs, const char* key) {
    for (const auto& a : attrs)
        if (local(a.name) == key) return a.value;
    return {};
}

int boolOf(const std::string& v) { return v.empty() ? -1 : (v == "true" || v == "1" ? 1 : 0); }

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\n' || s[a] == '\t' || s[a] == '\r')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\n' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
    return s.substr(a, b - a);
}

}  // namespace

// The element stack: scopes are reached through indices (-1 = base-config) so
// vector growth never invalidates them.
void Collector::startElement(const std::string& rawName, const std::vector<AxmlDecoder::Attr>& attrs) {
    const std::string name = local(rawName);
    Config& c = result;
    if (name == "network-security-config") {
        c.present = true;
    } else if (name == "base-config") {
        c.hasBase = true;
        ctx_ = Ctx::Base;
        c.base.cleartext = boolOf(attr(attrs, "cleartextTrafficPermitted"));
        open_ = &c.base;
    } else if (name == "domain-config") {
        c.domainConfigs.emplace_back();
        c.domainConfigs.back().cleartext = boolOf(attr(attrs, "cleartextTrafficPermitted"));
        ctx_ = Ctx::Domain;
        open_ = &c.domainConfigs.back();
    } else if (name == "debug-overrides") {
        c.hasDebugOverrides = true;
        ctx_ = Ctx::Debug;
        open_ = nullptr;
    } else if (name == "domain" && ctx_ == Ctx::Domain && open_) {
        open_->domains.push_back({"", boolOf(attr(attrs, "includeSubdomains")) == 1});
        inDomain_ = true;
    } else if (name == "certificates") {
        Anchor a{attr(attrs, "src"), boolOf(attr(attrs, "overridePins")) == 1};
        if (ctx_ == Ctx::Debug) c.debugAnchors.push_back(a);
        else if (open_) open_->anchors.push_back(a);
    } else if (name == "pin-set" && open_) {
        open_->pinExpiration = attr(attrs, "expiration");
        inPinSet_ = true;
    } else if (name == "pin" && inPinSet_) {
        pin_ = {attr(attrs, "digest"), ""};
        inPin_ = true;
    }
}

void Collector::text(const std::string& t) {
    if (inDomain_ && open_ && !open_->domains.empty()) open_->domains.back().name += trim(t);
    else if (inPin_) pin_.value += trim(t);
}

void Collector::endElement(const std::string& rawName) {
    const std::string name = local(rawName);
    if (name == "domain") {
        inDomain_ = false;
    } else if (name == "pin") {
        if (inPin_ && open_) open_->pins.push_back(pin_);
        inPin_ = false;
    } else if (name == "pin-set") {
        inPinSet_ = false;
    } else if (name == "base-config" || name == "domain-config" || name == "debug-overrides") {
        ctx_ = Ctx::None;
        open_ = nullptr;
    }
}

std::vector<std::string> notes(const Config& c, int targetSdk, bool manifestCleartext) {
    std::vector<std::string> out;
    if (!c.present) {
        if (manifestCleartext) {
            out.push_back("No network security config, but android:usesCleartextTraffic=\"true\" allows cleartext HTTP for every domain.");
            return out;
        }
        out.push_back(targetSdk >= 28 ? "No network security config: defaults apply (HTTPS only, system CAs; user CAs are not trusted from API 24)."
                                      : "No network security config: below API 28 cleartext HTTP is allowed.");
        return out;
    }
    const auto userTrusted = [](const std::vector<Anchor>& a) {
        for (const auto& x : a)
            if (x.src == "user") return true;
        return false;
    };
    if (c.hasBase) {
        if (c.base.cleartext == 1) out.push_back("base-config allows cleartext HTTP for every domain.");
        if (userTrusted(c.base.anchors)) out.push_back("base-config trusts user-installed CAs (a user CA can intercept this app's HTTPS).");
        for (const auto& a : c.base.anchors)
            if (a.src.rfind("@raw/", 0) == 0) out.push_back("base-config trusts a bundled CA: " + a.src + ".");
    } else if (targetSdk < 24) {
        out.push_back("No base-config and target SDK < 24: user-installed CAs are trusted by default.");
    }
    for (const Scope& s : c.domainConfigs) {
        std::string who;
        for (const auto& d : s.domains) who += (who.empty() ? "" : ", ") + d.name + (d.includeSubdomains ? " (+subdomains)" : "");
        if (who.empty()) who = "(unnamed domain-config)";
        if (s.cleartext == 1) out.push_back("Cleartext HTTP allowed for " + who + ".");
        if (userTrusted(s.anchors)) out.push_back("User CAs trusted for " + who + ".");
        if (!s.pins.empty()) {
            std::string line = "Certificate pinning for " + who + ": " + std::to_string(s.pins.size()) + " pin(s)";
            if (!s.pinExpiration.empty()) line += ", expires " + s.pinExpiration;
            out.push_back(line + ".");
        }
        for (const auto& a : s.anchors)
            if (a.overridePins) out.push_back("Pinning is overridden by a trust anchor for " + who + ".");
    }
    if (c.hasDebugOverrides) {
        std::string line = "debug-overrides present";
        if (userTrusted(c.debugAnchors)) line += ": user CAs are trusted in debuggable builds";
        out.push_back(line + " (ignored in release builds).");
    }
    bool anyPins = false;
    for (const Scope& s : c.domainConfigs) anyPins |= !s.pins.empty();
    if (!anyPins) out.push_back("No certificate pins configured here (pinning, if any, is done in code).");
    return out;
}

}  // namespace netsec
