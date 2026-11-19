#include "debug/Tls.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>
#include "core/Socket.hpp"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/private_access.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

#include "core/Paths.hpp"

#if defined(_WIN32)
// mbedTLS is built with MBEDTLS_THREADING_ALT (no native Win32 backend). Supply
// the mutex callbacks with Win32 critical sections so the shared CA/leaf RSA key
// signing (TrafficProxy worker threads) is serialised by mbedTLS as intended.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "mbedtls/threading.h"
namespace {
static_assert(sizeof(CRITICAL_SECTION) <= sizeof(reinterpret_cast<mbedtls_threading_mutex_t*>(0)->cs),
              "threading_alt.h buffer too small for CRITICAL_SECTION");
void altMutexInit(mbedtls_threading_mutex_t* m) {
    InitializeCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(m->cs));
    m->is_valid = 1;
}
void altMutexFree(mbedtls_threading_mutex_t* m) {
    if (m->is_valid) {
        DeleteCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(m->cs));
        m->is_valid = 0;
    }
}
int altMutexLock(mbedtls_threading_mutex_t* m) {
    if (!m->is_valid) return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    EnterCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(m->cs));
    return 0;
}
int altMutexUnlock(mbedtls_threading_mutex_t* m) {
    if (!m->is_valid) return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    LeaveCriticalSection(reinterpret_cast<CRITICAL_SECTION*>(m->cs));
    return 0;
}
// Registers the callbacks before main(), i.e. before any mbedTLS mutex is used.
struct AltThreadingRegistrar {
    AltThreadingRegistrar() { mbedtls_threading_set_alt(altMutexInit, altMutexFree, altMutexLock, altMutexUnlock); }
} g_altThreadingRegistrar;
}  // namespace
#endif  // _WIN32

namespace tls {
namespace {

// One per-Connection RNG seeded from its own entropy source: nothing mutable
// is shared between connections (mbedTLS contexts are not thread-safe unless
// guarded, and the proxy runs many handshakes in parallel).
// The contexts are initialised in the constructor and freed in the
// destructor, so an Rng that was never seeded (an early error return) is
// still safe to destroy.
struct Rng {
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
    bool ok = false;
    Rng() {
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_entropy_init(&entropy);
    }
    ~Rng() {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
    }
    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;
    bool init(const char* label) {
        if (ok) return true;
        ok = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(label),
                                   std::strlen(label)) == 0;
        return ok;
    }
};

std::string x509NameToString(const mbedtls_x509_name* name) {
    // mbedtls_x509_dn_gets prints "CN=ApkSpy CA,O=ApkSpy" already.
    char buf[512];
    const int n = mbedtls_x509_dn_gets(buf, sizeof buf, name);
    return n > 0 ? std::string(buf, static_cast<size_t>(n)) : std::string();
}

std::string timeToString(const mbedtls_x509_time& t) {
    if (t.year < 1970) return {};
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d UTC", t.year, t.mon, t.day, t.hour, t.min, t.sec);
    return buf;
}

#ifdef _WIN32
time_t _mkgmtime_like(std::tm& tm);
#else
time_t _mkgmtime_like(std::tm& tm);
#endif

time_t x509TimeToUnix(const mbedtls_x509_time& t) {
    std::tm tm{};
    tm.tm_year = t.year - 1900;
    tm.tm_mon = t.mon - 1;
    tm.tm_mday = t.day;
    tm.tm_hour = t.hour;
    tm.tm_min = t.min;
    tm.tm_sec = t.sec;
    return _mkgmtime_like(tm);
}

#ifdef _WIN32
time_t _mkgmtime_like(std::tm& tm) { return _mkgmtime(&tm); }
#else
time_t _mkgmtime_like(std::tm& tm) { return timegm(&tm); }
#endif

// "aa:bb:cc..." from raw bytes.
std::string colonHex(const unsigned char* p, size_t n) {
    std::string out;
    out.reserve(n * 3);
    char buf[4];
    for (size_t i = 0; i < n; ++i) {
        std::snprintf(buf, sizeof buf, "%02x:", p[i]);
        out += buf;
    }
    if (!out.empty()) out.pop_back();
    return out;
}

// ClientHello alerts say why an app refused the certificate; without the
// number the user only sees "fatal alert" which explains nothing.
const char* alertExplanation(unsigned char desc) {
    switch (desc) {
    case 40: return "the app and the proxy share no cipher suite (a custom TLS stack?)";
    case 42: return "the app rejected the certificate (bad_certificate) - certificate pinning, or the ApkSpy CA is not trusted";
    case 43: return "the app rejected the certificate type (unsupported_certificate)";
    case 45: return "the app saw the certificate as expired (certificate_expired) - check the device clock";
    case 46: return "the app rejected the certificate (certificate_unknown) - most likely certificate pinning or an untrusted ApkSpy CA";
    case 47: return "the app rejected the TLS parameters (illegal_parameter)";
    case 48: return "the app does not trust the ApkSpy CA (unknown_ca) - install it on the device (user store) or in the system store";
    case 50: return "the app could not parse the TLS handshake (decode_error)";
    case 70: return "the app requires a TLS version the proxy did not offer";
    case 80: return "the app reported an internal error during the handshake (possibly pinning)";
    case 112: return "the app requires an unadvertised certificate type";
    case 120: return "the app found no common application protocol (no_application_protocol)";
    default: return "the app aborted the TLS handshake";
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

bool init() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [&] { ok = psa_crypto_init() == PSA_SUCCESS; });
    return ok;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

struct Identity::Impl {
    mbedtls_x509_crt crt;   // the certificate chain (one certificate)
    mbedtls_pk_context key; // its private key
    bool hasKey = false;
    Impl() {
        mbedtls_x509_crt_init(&crt);
        mbedtls_pk_init(&key);
    }
    ~Impl() {
        mbedtls_x509_crt_free(&crt);
        mbedtls_pk_free(&key);
    }
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
};

Identity::Identity() = default;
Identity::~Identity() = default;
Identity::Identity(Identity&&) noexcept = default;
Identity& Identity::operator=(Identity&&) noexcept = default;
Identity::Identity(std::unique_ptr<Impl> i) : impl_(std::move(i)) {}

std::string Identity::sha256Fingerprint() const {
    if (!impl_) return {};
    unsigned char hash[32];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), impl_->crt.raw.p, impl_->crt.raw.len, hash) != 0)
        return {};
    return colonHex(hash, sizeof hash);
}

std::string Identity::subject() const { return impl_ ? x509NameToString(&impl_->crt.subject) : std::string(); }
std::string Identity::issuer() const { return impl_ ? x509NameToString(&impl_->crt.issuer) : std::string(); }

std::string Identity::serialHex() const {
    if (!impl_) return {};
    return colonHex(impl_->crt.serial.p, impl_->crt.serial.len);
}

std::string Identity::notBefore() const { return impl_ ? timeToString(impl_->crt.valid_from) : std::string(); }
std::string Identity::notAfter() const { return impl_ ? timeToString(impl_->crt.valid_to) : std::string(); }

long long Identity::secondsUntilExpiry() const {
    if (!impl_) return 0;
    const time_t end = x509TimeToUnix(impl_->crt.valid_to);
    return static_cast<long long>(end - std::time(nullptr));
}

bool Identity::toPem(std::string& out, std::string& error) const {
    if (!impl_) return error = "no certificate", false;
    unsigned char buf[16384];
    size_t len = 0;
    if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", impl_->crt.raw.p,
                                 impl_->crt.raw.len, buf, sizeof buf, &len) != 0)
        return error = "could not encode the certificate", false;
    out.assign(reinterpret_cast<const char*>(buf), len);
    return true;
}

bool Identity::keyToPem(std::string& out, std::string& error) const {
    if (!impl_ || !impl_->hasKey) return error = "no private key", false;
    unsigned char buf[16384];
    if (mbedtls_pk_write_key_pem(&impl_->key, buf, sizeof buf) != 0)
        return error = "could not encode the private key", false;
    out.assign(reinterpret_cast<const char*>(buf), std::strlen(reinterpret_cast<const char*>(buf)));
    while (!out.empty() && (out.back() == '\0' || out.back() == '\r')) out.pop_back();
    if (!out.empty() && out.back() != '\n') out += '\n';
    return true;
}

bool Identity::toDer(std::string& out, std::string& error) const {
    if (!impl_) return error = "no certificate", false;
    out.assign(reinterpret_cast<const char*>(impl_->crt.raw.p), impl_->crt.raw.len);
    return true;
}

bool Identity::isCa() const { return impl_ && impl_->crt.MBEDTLS_PRIVATE(ca_istrue) != 0; }

std::string Identity::androidFileName() const {
    // Android's store layout names files "<subject_hash_old>.0": the MD5 of
    // the DER-encoded subject, first four bytes, little endian. Reusing
    // OpenSSL's naming keeps `ls` output comparable with other tools.
    if (!impl_) return {};
    unsigned char md5[16];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), impl_->crt.subject_raw.p, impl_->crt.subject_raw.len,
                   md5) != 0)
        return {};
    char buf[16];
    std::snprintf(buf, sizeof buf, "%08x.0",
                  static_cast<unsigned>(md5[0]) | static_cast<unsigned>(md5[1]) << 8 |
                      static_cast<unsigned>(md5[2]) << 16 | static_cast<unsigned>(md5[3]) << 24);
    return buf;
}

// Grants the cert-building helpers access to Identity's internals without
// exposing them in the header.
struct IdentityBuild {
    static Identity make(std::unique_ptr<Identity::Impl> impl) { return Identity(std::move(impl)); }
    static Identity::Impl& parts(Identity& id) { return *id.impl_; }
    static const Identity::Impl& parts(const Identity& id) { return *id.impl_; }
};

namespace {

// x509 write boilerplate shared by makeCa / makeLeaf.
bool writeCert(mbedtls_x509write_cert& wc, Identity& out, Rng& rng, std::string& error) {
    unsigned char der[16384];
    const int len = mbedtls_x509write_crt_der(&wc, der, sizeof der, mbedtls_ctr_drbg_random, &rng.drbg);
    if (len < 0) {
        error = "certificate write failed: " + errorString(len);
        return false;
    }
    auto impl = std::make_unique<Identity::Impl>();
    const int prc = mbedtls_x509_crt_parse_der(&impl->crt, der + sizeof der - len, static_cast<size_t>(len));
    if (prc != 0) {
        error = "generated certificate did not parse (rc " + std::to_string(prc) + ", len " + std::to_string(len) + ")";
        return false;
    }
    out = IdentityBuild::make(std::move(impl));
    return true;
}

// An RSA-2048 key freed automatically (mbedTLS contexts have no destructor).
struct RsaKey {
    mbedtls_pk_context pk;
    bool ok = false;
    explicit RsaKey(Rng& rng) {
        mbedtls_pk_init(&pk);
        ok = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
             mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &rng.drbg, 2048, 65537) == 0;
    }
    ~RsaKey() { mbedtls_pk_free(&pk); }
};

struct CertWriter {
    mbedtls_x509write_cert wc;
    CertWriter() { mbedtls_x509write_crt_init(&wc); }
    ~CertWriter() { mbedtls_x509write_crt_free(&wc); }
};

// Moves a copy of `key` into a freshly written identity so it can sign /
// serve on its own; the caller's key stays valid.
bool takeKey(Identity& id, mbedtls_pk_context& key, std::string& error) {
    auto& parts = IdentityBuild::parts(id);
    mbedtls_pk_free(&parts.key);
    mbedtls_pk_init(&parts.key);
    if (mbedtls_pk_setup(&parts.key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0 ||
        mbedtls_rsa_copy(mbedtls_pk_rsa(parts.key), mbedtls_pk_rsa(key)) != 0) {
        id = Identity{};
        error = "could not keep the private key";
        return false;
    }
    IdentityBuild::parts(id).hasKey = true;
    return true;
}

// notBefore/notAfter as YYYYMMDDhhmmss (mbedTLS appends the Z).
void validityFromNow(int years, char from[16], char to[16]) {
    const time_t now = std::time(nullptr) - 24 * 3600;  // start yesterday: clocks run behind
    std::tm fromTm{};
#ifdef _WIN32
    gmtime_s(&fromTm, &now);
#else
    gmtime_r(&now, &fromTm);
#endif
    std::tm toTm = fromTm;
    toTm.tm_year += years;
    const time_t end = _mkgmtime_like(toTm);
#ifdef _WIN32
    gmtime_s(&toTm, &end);
#else
    gmtime_r(&end, &toTm);
#endif
    std::snprintf(from, 16, "%04d%02d%02d%02d%02d%02d", fromTm.tm_year + 1900, fromTm.tm_mon + 1, fromTm.tm_mday,
                  fromTm.tm_hour, fromTm.tm_min, fromTm.tm_sec);
    std::snprintf(to, 16, "%04d%02d%02d%02d%02d%02d", toTm.tm_year + 1900, toTm.tm_mon + 1, toTm.tm_mday, toTm.tm_hour,
                  toTm.tm_min, toTm.tm_sec);
}

bool randomSerial(mbedtls_x509write_cert& wc, Rng& rng, std::string& error) {
    unsigned char serial[16];
    if (mbedtls_ctr_drbg_random(&rng.drbg, serial, sizeof serial) != 0) return error = "no randomness for the serial", false;
    serial[0] &= 0x7f;  // positive, as RFC 5280 wants
    if (mbedtls_x509write_crt_set_serial_raw(&wc, serial, sizeof serial) != 0)
        return error = "could not set the serial", false;
    return true;
}

}  // namespace

bool makeCa(const std::string& subject, int years, Identity& out, std::string& error) {
    if (!init()) return error = "TLS subsystem did not initialise", false;
    Rng rng;
    if (!rng.init("apkspy-ca")) return error = "could not seed the random generator", false;
    RsaKey key(rng);
    if (!key.ok) return error = "could not generate an RSA-2048 key", false;
    CertWriter w;
    mbedtls_x509write_crt_set_version(&w.wc, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&w.wc, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&w.wc, &key.pk);
    mbedtls_x509write_crt_set_issuer_key(&w.wc, &key.pk);
    if (mbedtls_x509write_crt_set_subject_name(&w.wc, subject.c_str()) != 0)
        return error = "could not build the CA subject name", false;
    if (mbedtls_x509write_crt_set_issuer_name(&w.wc, subject.c_str()) != 0)
        return error = "could not build the CA issuer name", false;
    char from[16], to[16];
    validityFromNow(years, from, to);
    if (mbedtls_x509write_crt_set_validity(&w.wc, from, to) != 0) return error = "invalid validity window", false;
    if (mbedtls_x509write_crt_set_basic_constraints(&w.wc, 1, 0) != 0) return error = "could not set CA constraints", false;
    if (mbedtls_x509write_crt_set_key_usage(&w.wc, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN) != 0)
        return error = "could not set the key usage", false;
    if (mbedtls_x509write_crt_set_subject_key_identifier(&w.wc) != 0 ||
        mbedtls_x509write_crt_set_authority_key_identifier(&w.wc) != 0)
        return error = "could not set the key identifiers", false;
    if (!randomSerial(w.wc, rng, error)) return false;
    if (!writeCert(w.wc, out, rng, error)) return false;
    return takeKey(out, key.pk, error);
}

bool makeLeaf(const Identity& ca, const std::string& host, int years, Identity& out, std::string& error) {
    if (!ca.valid() || !IdentityBuild::parts(ca).hasKey) return error = "the CA is not loaded", false;
    if (host.empty() || host.size() > 253) return error = "invalid host name", false;
    if (!init()) return error = "TLS subsystem did not initialise", false;
    // Leaves never outlive their CA.
    long long yearsLeft = ca.secondsUntilExpiry() / (365 * 24 * 3600);
    if (yearsLeft < 1) return error = "the ApkSpy CA has expired - regenerate it in Settings", false;
    if (yearsLeft < years) years = static_cast<int>(yearsLeft);
    Rng rng;
    if (!rng.init("apkspy-leaf")) return error = "could not seed the random generator", false;
    RsaKey key(rng);
    if (!key.ok) return error = "could not generate an RSA-2048 key", false;
    CertWriter w;
    mbedtls_x509write_crt_set_version(&w.wc, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&w.wc, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&w.wc, &key.pk);
    // Signing updates the CA key's CRT blinding state; mbedTLS guards that
    // with the threading lock, so the key is shared safely despite the const.
    auto& caKey = const_cast<mbedtls_pk_context&>(IdentityBuild::parts(ca).key);
    mbedtls_x509write_crt_set_issuer_key(&w.wc, &caKey);
    if (mbedtls_x509write_crt_set_issuer_name(&w.wc, ca.subject().c_str()) != 0)
        return error = "could not copy the CA issuer name", false;
    const std::string cn = "CN=" + host;
    if (mbedtls_x509write_crt_set_subject_name(&w.wc, cn.c_str()) != 0)
        return error = "could not build the subject name", false;
    char from[16], to[16];
    validityFromNow(years, from, to);
    if (mbedtls_x509write_crt_set_validity(&w.wc, from, to) != 0) return error = "invalid validity window", false;
    if (mbedtls_x509write_crt_set_basic_constraints(&w.wc, 0, -1) != 0) return error = "could not set constraints", false;
    if (mbedtls_x509write_crt_set_key_usage(&w.wc, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT) != 0)
        return error = "could not set the key usage", false;
    if (mbedtls_x509write_crt_set_subject_key_identifier(&w.wc) != 0 ||
        mbedtls_x509write_crt_set_authority_key_identifier(&w.wc) != 0)
        return error = "could not set the key identifiers", false;
    if (!randomSerial(w.wc, rng, error)) return false;
    // SAN: dNSName for names, iPAddress for literals (RFC 5280 GeneralNames).
    std::vector<unsigned char> san;
    unsigned char ip[16];
    size_t ipLen = 0;
    bool v4 = !host.empty() && host.find(':') == std::string::npos;
    int dots = 0;
    for (char c : host) {
        if (c == '.') ++dots;
        else if (!std::isdigit(static_cast<unsigned char>(c))) v4 = false;
    }
    v4 = v4 && dots == 3;
    if (v4) {
        unsigned part = 0;
        int have = 0;
        for (size_t i = 0; i <= host.size() && have < 4; ++i) {
            if (i == host.size() || host[i] == '.') {
                ip[have++] = static_cast<unsigned char>(part);
                part = 0;
            } else
                part = part * 10 + static_cast<unsigned>(host[i] - '0');
        }
        ipLen = 4;
    } else if (host.find(':') != std::string::npos) {
        // IPv6, including one "::" abbreviation: expand into 16 bytes.
        unsigned char groups[8][2];
        int seen = 0, before = -1;
        unsigned cur = 0;
        bool hasCur = false;
        for (size_t i = 0; i <= host.size(); ++i) {
            const char c = i < host.size() ? host[i] : '\0';
            if (c != '\0' && std::isxdigit(static_cast<unsigned char>(c))) {
                cur = cur * 16 + (std::isdigit(static_cast<unsigned char>(c)) ? c - '0'
                        : (std::tolower(static_cast<unsigned char>(c)) - 'a' + 10));
                hasCur = true;
            } else if (c == ':') {
                if (hasCur) {
                    if (seen >= 8) { seen = -1; break; }
                    groups[seen][0] = static_cast<unsigned char>(cur >> 8);
                    groups[seen++][1] = static_cast<unsigned char>(cur & 0xff);
                    cur = 0;
                    hasCur = false;
                } else if (i + 1 < host.size() && host[i + 1] == ':') {
                    if (before >= 0) { seen = -1; break; }  // two "::"
                    before = seen;
                    ++i;
                } else if (i != 0) {
                    seen = -1;  // ":" without digits and not "::"
                    break;
                }
            } else if (c == '\0') {
                if (hasCur) {
                    if (seen >= 8) { seen = -1; break; }
                    groups[seen][0] = static_cast<unsigned char>(cur >> 8);
                    groups[seen++][1] = static_cast<unsigned char>(cur & 0xff);
                }
            } else {
                seen = -1;  // not an address literal after all
                break;
            }
        }
        const int missing = 8 - seen;
        if (seen > 0 && seen <= 8 && (before >= 0 ? missing >= 0 : seen == 8)) {
            size_t at = 0;
            for (int g = 0; g < seen; ++g) {
                if (g == before)
                    for (int z = 0; z < missing; ++z) ip[at++] = 0, ip[at++] = 0;
                ip[at++] = groups[g][0];
                ip[at++] = groups[g][1];
            }
            for (int z = before >= 0 && before == seen ? missing * 2 : 0; z > 0 && at < 16; --z) ip[at++] = 0;
            if (at == 16) ipLen = 16;
        }
        if (ipLen == 0) return error = "could not parse the address '" + host + "'", false;
    }
    // GeneralNames SEQUENCE { [2] dNSName | [7] iPAddress } - the sequence
    // length is the content after it (tag + length + value).
    if (ipLen) {
        san.insert(san.end(), {0x30, static_cast<unsigned char>(2 + ipLen), 0x87, static_cast<unsigned char>(ipLen)});
        san.insert(san.end(), ip, ip + ipLen);
    } else {
        san.insert(san.end(),
                   {0x30, static_cast<unsigned char>(2 + host.size()), 0x82, static_cast<unsigned char>(host.size())});
        san.insert(san.end(), host.begin(), host.end());
    }
    if (mbedtls_x509write_crt_set_extension(&w.wc, MBEDTLS_OID_SUBJECT_ALT_NAME,
                                            MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME), 0, san.data(), san.size()) != 0)
        return error = "could not set the subject alternative name", false;
    if (!writeCert(w.wc, out, rng, error)) return false;
    return takeKey(out, key.pk, error);
}

bool loadIdentity(const std::string& certPemOrDer, const std::string& keyPem, Identity& out, std::string& error) {
    auto impl = std::make_unique<Identity::Impl>();
    const unsigned char* cp = reinterpret_cast<const unsigned char*>(certPemOrDer.data());
    int rc = mbedtls_x509_crt_parse(&impl->crt, cp, certPemOrDer.size() + 1);  // PEM needs the NUL
    if (rc != 0 && certPemOrDer.size() > 0) {
        mbedtls_x509_crt_free(&impl->crt);
        mbedtls_x509_crt_init(&impl->crt);
        rc = mbedtls_x509_crt_parse_der(&impl->crt, cp, certPemOrDer.size());
    }
    if (rc != 0) return error = "could not parse the certificate: " + errorString(rc), false;
    const unsigned char* kp = reinterpret_cast<const unsigned char*>(keyPem.data());
    rc = mbedtls_pk_parse_key(&impl->key, kp, keyPem.size() + 1, nullptr, 0, nullptr, nullptr);
    if (rc != 0) return error = "could not parse the private key: " + errorString(rc), false;
    impl->hasKey = true;
    out = IdentityBuild::make(std::move(impl));
    return true;
}

// ---------------------------------------------------------------------------
// TrustStore
// ---------------------------------------------------------------------------

struct TrustStore::Impl {
    mbedtls_x509_crt chain;
    size_t count = 0;
    Impl() { mbedtls_x509_crt_init(&chain); }
    ~Impl() { mbedtls_x509_crt_free(&chain); }
};

TrustStore::TrustStore() : impl_(std::make_unique<Impl>()) {}
TrustStore::~TrustStore() = default;

bool TrustStore::loadPem(const std::string& pem, std::string& error) {
    std::string copy = pem;
    if (copy.empty() || copy.back() != '\n') copy += '\n';
    const unsigned char* p = reinterpret_cast<const unsigned char*>(copy.data());
    const int rc = mbedtls_x509_crt_parse(&impl_->chain, p, copy.size() + 1);
    if (rc < 0) return error = "could not parse the certificate bundle: " + errorString(rc), false;
    impl_->count = 0;
    for (const mbedtls_x509_crt* c = &impl_->chain; c; c = c->next) ++impl_->count;
    return true;
}

bool TrustStore::loadPemFile(const std::string& path, std::string& error) {
    if (path.empty()) return error = "no CA bundle path", false;
    FILE* f =
#ifdef _WIN32
        nullptr;
    fopen_s(&f, path.c_str(), "rb");
#else
        std::fopen(path.c_str(), "rb");
#endif
    if (!f) return error = "could not open " + path, false;
    std::string pem;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) pem.append(buf, n);
    std::fclose(f);
    return loadPem(pem, error);
}

size_t TrustStore::count() const { return impl_->count; }

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

struct Connection::Impl {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cfg;
    Rng rng;
    Socket* sock = nullptr;
    int timeoutMs = 10000;
    bool closed = false;    // close_notify already sent/received
    bool connected = false; // handshake finished
    std::string pushback;   // socket bytes read before the TLS engine was attached
    size_t pushbackAt = 0;
    bool maxTls12 = false;  // cap the handshake at TLS 1.2
    // An mbedTLS SSL context must not be used by two threads at once, but
    // relays (WebSocket, upgrades) read one direction and write the other
    // concurrently. Every post-handshake call on `ssl` holds this lock;
    // callers wait for readability first so a read rarely holds it long.
    mutable std::mutex io;

    // mbedTLS BIO over our blocking socket: reads wait only timeoutMs.
    static int send(void* ctx, const unsigned char* buf, size_t len) {
        auto* impl = static_cast<Impl*>(ctx);
        return impl->sock->sendAll(buf, len) ? static_cast<int>(len) : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    static int recv(void* ctx, unsigned char* buf, size_t len) {
        auto* impl = static_cast<Impl*>(ctx);
        if (impl->pushbackAt < impl->pushback.size()) {  // replayed pre-read bytes
            const size_t n = std::min(len, impl->pushback.size() - impl->pushbackAt);
            std::memcpy(buf, impl->pushback.data() + impl->pushbackAt, n);
            impl->pushbackAt += n;
            return static_cast<int>(n);
        }
        if (!impl->sock->waitReadable(impl->timeoutMs)) return MBEDTLS_ERR_SSL_WANT_READ;
        const long n = impl->sock->recvSome(buf, len);
        if (n > 0) return static_cast<int>(n);
        if (n == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    Impl() {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&cfg);
    }
    ~Impl() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&cfg);
    }
};

Connection::Connection() : impl_(std::make_unique<Impl>()) {}
Connection::~Connection() = default;

bool Connection::connect(Socket& s, const std::string& hostname, const TrustStore* roots, bool verify, int timeoutMs,
                         std::string& error) {
    if (!init()) return error = "TLS subsystem did not initialise", false;
    if (hostname.empty()) return error = "no host name", false;
    impl_->sock = &s;
    impl_->timeoutMs = timeoutMs;
    if (impl_->rng.init("apkspy-client") != true) return error = "could not seed the random generator", false;
    if (mbedtls_ssl_config_defaults(&impl_->cfg, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        return error = "TLS defaults failed", false;
    mbedtls_ssl_conf_rng(&impl_->cfg, mbedtls_ctr_drbg_random, &impl_->rng.drbg);
    if (impl_->maxTls12)
        mbedtls_ssl_conf_max_version(&impl_->cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    // The proxy and the Repeater speak HTTP/1.1 - offering anything else would
    // just get us an h2 connection we cannot parse.
    const char* alpn[] = {"http/1.1", nullptr};
    mbedtls_ssl_conf_alpn_protocols(&impl_->cfg, alpn);
    if (verify && roots && roots->count() > 0) {
        mbedtls_ssl_conf_ca_chain(&impl_->cfg, &roots->impl_->chain, nullptr);
        mbedtls_ssl_conf_authmode(&impl_->cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else if (verify) {
        // Verification without roots is never silently skipped.
        return error = "no root certificates loaded to verify " + hostname, false;
    } else {
        mbedtls_ssl_conf_authmode(&impl_->cfg, MBEDTLS_SSL_VERIFY_NONE);
        // mbedTLS 3.5's TLS 1.3 client always verifies the server (authmode is
        // hardcoded REQUIRED on the client side), so an explicitly unverified
        // connection caps itself at TLS 1.2, where VERIFY_NONE is honored.
        mbedtls_ssl_conf_max_version(&impl_->cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    }
    if (mbedtls_ssl_setup(&impl_->ssl, &impl_->cfg) != 0) return error = "TLS setup failed", false;
    const int rc = mbedtls_ssl_set_hostname(&impl_->ssl, hostname.c_str());
    if (rc != 0) return error = "could not set the server name: " + errorString(rc), false;
    mbedtls_ssl_set_bio(&impl_->ssl, impl_.get(), &Connection::Impl::send, &Connection::Impl::recv, nullptr);
    const int hr = mbedtls_ssl_handshake(&impl_->ssl);
    if (hr != 0) {
        error = "TLS handshake with " + hostname + " failed: ";
        const uint32_t vr = mbedtls_ssl_get_verify_result(&impl_->ssl);
        if (hr == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            if (vr & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
                error += "the server's certificate is not signed by a root in the CA bundle";
            else if (vr & MBEDTLS_X509_BADCERT_CN_MISMATCH)
                error += "the certificate does not match the host name";
            else if (vr & MBEDTLS_X509_BADCERT_EXPIRED)
                error += "the server's certificate has expired";
            else if (vr & MBEDTLS_X509_BADCERT_FUTURE)
                error += "the server's certificate is not valid yet";
            else
                error += "certificate verification failed";
        } else if (hr == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
            const unsigned char* in = impl_->ssl.MBEDTLS_PRIVATE(in_msg);
            error += "the server refused the handshake: " + std::string(alertExplanation(in ? in[1] : 0));
        } else {
            error += errorString(hr);
        }
        return false;
    }
    impl_->connected = true;
    return true;
}

bool Connection::accept(Socket& s, const Identity& cert, int timeoutMs, std::string& error, std::string& handshakeNote) {
    if (!init()) return error = "TLS subsystem did not initialise", false;
    if (!cert.valid() || !cert.impl_->hasKey) return error = "no certificate to present", false;
    impl_->sock = &s;
    impl_->timeoutMs = timeoutMs;
    if (!impl_->rng.init("apkspy-server")) return error = "could not seed the random generator", false;
    if (mbedtls_ssl_config_defaults(&impl_->cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        return error = "TLS defaults failed", false;
    mbedtls_ssl_conf_rng(&impl_->cfg, mbedtls_ctr_drbg_random, &impl_->rng.drbg);
    if (impl_->maxTls12)
        mbedtls_ssl_conf_max_version(&impl_->cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_own_cert(&impl_->cfg, &cert.impl_->crt, &cert.impl_->key);
    const char* alpn[] = {"http/1.1", nullptr};  // negotiation order = preference
    mbedtls_ssl_conf_alpn_protocols(&impl_->cfg, alpn);
    mbedtls_ssl_conf_authmode(&impl_->cfg, MBEDTLS_SSL_VERIFY_NONE);  // we cannot know the app's client cert
    if (mbedtls_ssl_setup(&impl_->ssl, &impl_->cfg) != 0) return error = "TLS setup failed", false;
    mbedtls_ssl_set_bio(&impl_->ssl, impl_.get(), &Connection::Impl::send, &Connection::Impl::recv, nullptr);
    const int hr = mbedtls_ssl_handshake(&impl_->ssl);
    if (hr != 0) {
        error = "TLS handshake failed: ";
        if (hr == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE) {
            const unsigned char* in = impl_->ssl.MBEDTLS_PRIVATE(in_msg);
            const unsigned char desc = in ? in[1] : 0;
            error += alertExplanation(desc);
            handshakeNote = "alert " + std::to_string(desc) + " (" + alertExplanation(desc) + ")";
        } else if (hr == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || hr == MBEDTLS_ERR_SSL_CONN_EOF) {
            error += "the application closed the connection during the handshake - it may reject the ApkSpy "
                     "certificate (pinning) or not trust the CA";
            handshakeNote = "closed during handshake (possible pinning or untrusted CA)";
        } else {
            // Anything else mid-handshake (encrypted TLS 1.3 alerts arrive as
            // MAC errors, for example) is still, overwhelmingly, an app
            // refusing this proxy's certificate.
            error += errorString(hr);
            handshakeNote = "the app rejected the TLS handshake (" + errorString(hr) +
                            ") - likely certificate pinning or an untrusted ApkSpy CA";
        }
        return false;
    }
    impl_->connected = true;
    return true;
}

int Connection::read(void* buf, size_t len, int timeoutMs) {
    std::lock_guard<std::mutex> lock(impl_->io);
    if (!impl_->connected || impl_->closed) return impl_->closed ? 0 : -1;
    impl_->timeoutMs = timeoutMs;
    for (;;) {
        const int n = mbedtls_ssl_read(&impl_->ssl, static_cast<unsigned char*>(buf), len);
        if (n > 0) return n;
        if (n == 0) return 0;
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            impl_->closed = true;
            return 0;
        }
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return -1;  // timed out
        if (n == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) continue;
        impl_->closed = true;
        return -1;
    }
}

bool Connection::writeAll(const void* buf, size_t len) {
    std::lock_guard<std::mutex> lock(impl_->io);
    if (!impl_->connected || impl_->closed) return false;
    const unsigned char* p = static_cast<const unsigned char*>(buf);
    while (len > 0) {
        const int n = mbedtls_ssl_write(&impl_->ssl, p, len);
        if (n > 0) {
            p += n;
            len -= static_cast<size_t>(n);
            continue;
        }
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        return false;
    }
    return true;
}

void Connection::setMaxTls12() { impl_->maxTls12 = true; }

void Connection::pushBack(const void* data, size_t len) {
    impl_->pushback.append(static_cast<const char*>(data), len);
}

size_t Connection::pending() const {
    std::lock_guard<std::mutex> lock(impl_->io);
    if (!impl_->connected || impl_->closed) return 0;
    return mbedtls_ssl_get_bytes_avail(&impl_->ssl);
}

void Connection::close() {
    std::lock_guard<std::mutex> lock(impl_->io);
    if (impl_->connected && !impl_->closed) {
        impl_->timeoutMs = 2000;
        mbedtls_ssl_close_notify(&impl_->ssl);
    }
    impl_->closed = true;
}

const char* Connection::version() const { return impl_->connected ? mbedtls_ssl_get_version(&impl_->ssl) : ""; }
const char* Connection::cipher() const { return impl_->connected ? mbedtls_ssl_get_ciphersuite(&impl_->ssl) : ""; }
const char* Connection::alpn() const {
    if (!impl_->connected) return "";
    const char* a = mbedtls_ssl_get_alpn_protocol(&impl_->ssl);
    return a ? a : "";
}

std::shared_ptr<TrustStore> defaultTrustStore(std::string& error) {
    static std::mutex mutex;
    static std::shared_ptr<TrustStore> cached;
    std::lock_guard<std::mutex> lock(mutex);
    if (cached && cached->count() > 0) return cached;
    auto store = std::make_shared<TrustStore>();
    std::string err;
    bool loaded = false;
    if (const std::string bundled = pathutil::assetsFile("cacert.pem"); !bundled.empty())
        loaded = store->loadPemFile(bundled, err);
    if (!loaded) {
        static const char* kSystemPaths[] = {
            "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem", "/etc/openssl/certs/ca-certificates.crt"};
        for (const char* p : kSystemPaths) {
            err.clear();
            if (store->loadPemFile(p, err)) {
                loaded = true;
                break;
            }
        }
    }
    if (!loaded || store->count() == 0) {
        error = "no root certificates could be loaded (tried assets/cacert.pem and the system bundle)";
        return {};
    }
    cached = store;
    return cached;
}

std::string errorString(int code) {
    char buf[256];
    buf[0] = '\0';
    mbedtls_strerror(code < 0 ? code : -code, buf, sizeof buf);
    return buf[0] != '\0' ? buf : ("mbedTLS error " + std::to_string(code));
}

}  // namespace tls
