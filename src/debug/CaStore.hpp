#pragma once
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "debug/Tls.hpp"

// ApkSpy's local certificate authority: generated once on first use, kept in
// the user config directory, and the signer of a per-host leaf certificate
// for every HTTPS host the proxy intercepts.
//
// Files on disk (both in <dir>):
//   apkspy-ca.pem - the certificate, exportable / installable anywhere
//   apkspy-ca.key - the private key, never exported through any API below
// (POSIX: the key file is created 0600; the directory is the per-user config
// dir, which the OS restricts to the user already.)
namespace ca {

class Store {
public:
    // Loads the CA from <dir>, generating it when the files are missing.
    // Safe to call again (e.g. after regenerate()).
    bool loadOrGenerate(const std::string& dir, std::string& error);

    bool ready() const;
    // The current CA. A snapshot: regenerate() swaps in a new identity, and
    // whoever still holds the old one (a worker signing a leaf) keeps it alive.
    std::shared_ptr<const tls::Identity> ca() const;

    // A leaf certificate for `host` (DNS or IP). Cached; the same leaf is
    // reused for the host until the CA changes. Returns null on error.
    std::shared_ptr<const tls::Identity> leafFor(const std::string& host, std::string& error);

    // A brand new CA. Devices that trusted the old one stop trusting the
    // proxy's certificates until the new CA is installed there.
    bool regenerate(std::string& error);

    std::string caPem() const;
    std::string caDer() const;
    std::string androidFileName() const;  // "<subject hash>.0" for Android's stores
    size_t leafCount() const;
    const std::string& dir() const { return dir_; }

private:
    bool save(const tls::Identity& id, std::string& error) const;
    // Installs `id` as the CA and drops every leaf signed by the previous one.
    void setCa(std::shared_ptr<const tls::Identity> id);
    std::string dir_;
    mutable std::mutex mutex_;  // guards ca_ / leaves_ / leafOrder_ (leafFor runs on proxy workers)
    std::shared_ptr<const tls::Identity> ca_;
    std::unordered_map<std::string, std::shared_ptr<const tls::Identity>> leaves_;
    std::vector<std::string> leafOrder_;  // insertion order, for the cap
};

}  // namespace ca
