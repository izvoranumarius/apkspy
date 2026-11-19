#include "debug/CaStore.hpp"
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "core/Paths.hpp"

namespace fs = std::filesystem;

namespace ca {
namespace {

constexpr int kCaYears = 10;
constexpr int kLeafYears = 2;
constexpr size_t kMaxLeaves = 256;  // enough hosts for a test session

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool writeFile(const std::string& path, const std::string& data, bool secret) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) return false;
    if (secret) {
        std::error_code ec;
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        // A failure to tighten permissions is not fatal (e.g. some FAT
        // filesystems); the key still lives only in the user config dir.
    }
    return true;
}

}  // namespace

bool Store::ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ca_ && ca_->valid();
}

std::shared_ptr<const tls::Identity> Store::ca() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ca_;
}

void Store::setCa(std::shared_ptr<const tls::Identity> id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ca_ = std::move(id);
    leaves_.clear();
    leafOrder_.clear();
}

bool Store::loadOrGenerate(const std::string& dir, std::string& error) {
    dir_ = dir;
    std::error_code ec;
    fs::create_directories(pathutil::fromUtf8(dir), ec);
    const std::string certPath = dir + "/apkspy-ca.pem";
    const std::string keyPath = dir + "/apkspy-ca.key";
    const std::string cert = readFile(certPath);
    const std::string key = readFile(keyPath);
    if (!cert.empty() && !key.empty()) {
        auto loaded = std::make_shared<tls::Identity>();
        // Present but unreadable: say so instead of silently replacing a CA
        // the user may already have installed on devices.
        if (!tls::loadIdentity(cert, key, *loaded, error)) return false;
        const bool expired = loaded->secondsUntilExpiry() <= 0;
        setCa(std::move(loaded));  // still shown (and regenerable) in Settings
        if (expired) return error = "the ApkSpy CA has expired - regenerate it in Settings", false;
        return true;
    }
    // First launch (or leftover half): a fresh CA.
    auto fresh = std::make_shared<tls::Identity>();
    if (!tls::makeCa("CN=ApkSpy CA,O=ApkSpy,C=XX", kCaYears, *fresh, error)) return false;
    if (!save(*fresh, error)) return false;
    setCa(std::move(fresh));
    return true;
}

bool Store::save(const tls::Identity& id, std::string& error) const {
    std::string cert, key;
    if (!id.toPem(cert, error) || !id.keyToPem(key, error)) return false;
    if (!writeFile(dir_ + "/apkspy-ca.pem", cert, false) || !writeFile(dir_ + "/apkspy-ca.key", key, true)) {
        error = "could not write the CA to " + dir_;
        return false;
    }
    return true;
}

std::shared_ptr<const tls::Identity> Store::leafFor(const std::string& host, std::string& error) {
    std::string normalized = host;
    for (char& c : normalized) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::shared_ptr<const tls::Identity> signer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = leaves_.find(normalized);
        if (it != leaves_.end()) return it->second;
        signer = ca_;
    }
    if (!signer) return error = "the CA is not loaded", nullptr;
    // Signed outside the lock (RSA keygen is slow); `signer` keeps this CA
    // alive even if regenerate() swaps in a new one meanwhile.
    auto leaf = std::make_shared<tls::Identity>();
    if (!tls::makeLeaf(*signer, normalized, kLeafYears, *leaf, error)) return nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    // The CA changed while signing: serve this leaf once, never cache it.
    if (ca_ != signer) return leaf;
    const auto [it, fresh] = leaves_.emplace(normalized, leaf);
    if (fresh) {
        leafOrder_.push_back(normalized);
        while (leafOrder_.size() > kMaxLeaves) {  // oldest out
            leaves_.erase(leafOrder_.front());
            leafOrder_.erase(leafOrder_.begin());
        }
    }
    return it->second;
}

bool Store::regenerate(std::string& error) {
    auto fresh = std::make_shared<tls::Identity>();
    if (!tls::makeCa("CN=ApkSpy CA,O=ApkSpy,C=XX", kCaYears, *fresh, error)) return false;
    if (!save(*fresh, error)) return false;
    setCa(std::move(fresh));
    return true;
}

std::string Store::caPem() const {
    const auto id = ca();
    std::string out, error;
    return id && id->toPem(out, error) ? out : std::string();
}

std::string Store::caDer() const {
    const auto id = ca();
    std::string out, error;
    return id && id->toDer(out, error) ? out : std::string();
}

std::string Store::androidFileName() const {
    const auto id = ca();
    return id ? id->androidFileName() : std::string();
}

size_t Store::leafCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return leaves_.size();
}

}  // namespace ca
