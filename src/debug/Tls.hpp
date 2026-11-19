#pragma once
#include <memory>
#include <string>

class Socket;

// TLS on top of the project's blocking Socket layer, built on the bundled
// mbedTLS (include/mbedtls + lib/mbedtls). No cryptographic primitive is
// implemented here - this is only the glue that mbedTLS needs to run over our
// sockets with timeouts, so a stalled peer can never pin a proxy worker.
//
// Concurrency: every Connection owns its whole mbedTLS state (SSL context,
// config, RNG, entropy), so connections are independent. Within one
// Connection, read / writeAll / close / pending are serialised by a lock, so
// a relay may read on one thread while another writes. The CA and leaf keys
// are shared between connections; mbedTLS's own threading lock guards their
// RSA blinding state.
namespace tls {

// Process-wide init: PSA crypto (TLS 1.3 needs it) - safe to call repeatedly.
bool init();

// An X.509 certificate with its private key (the CA, or a per-host leaf).
class Identity {
public:
    Identity();
    ~Identity();
    Identity(Identity&&) noexcept;
    Identity& operator=(Identity&&) noexcept;
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;

    bool valid() const { return impl_ != nullptr; }
    // SHA-256 of the certificate, "aa:bb:..." (what the UI shows).
    std::string sha256Fingerprint() const;
    std::string subject() const;   // "CN=ApkSpy CA,O=ApkSpy"
    std::string issuer() const;
    std::string serialHex() const;
    // "2036-01-01 00:00:00 UTC" style; empty on parse failure.
    std::string notBefore() const;
    std::string notAfter() const;
    // Seconds from now until notAfter (negative when already expired).
    long long secondsUntilExpiry() const;
    // The certificate as PEM ("-----BEGIN CERTIFICATE-----...").
    bool toPem(std::string& out, std::string& error) const;
    // The certificate as DER bytes.
    bool toDer(std::string& out, std::string& error) const;
    // The private key as an unencrypted PEM (used only to store ApkSpy's own
    // CA on disk; never offered through any export or copy path).
    bool keyToPem(std::string& out, std::string& error) const;
    // "<openssl x509 -subject_hash_old>.0" - the file name Android's
    // certificate stores expect (MD5 of the DER subject, first 4 bytes,
    // little endian; a naming convention, not a security hash).
    std::string androidFileName() const;
    // True when the certificate is a CA (basicConstraints CA:true).
    bool isCa() const;

    struct Impl;
    const Impl* impl() const { return impl_.get(); }

private:
    friend struct IdentityBuild;  // the cpp's cert-building helpers
    friend class Connection;
    explicit Identity(std::unique_ptr<Impl> i);  // Impl is incomplete here
    std::unique_ptr<Impl> impl_;
};

// Builds a self-signed CA. `subject` is an x509 name string
// ("CN=ApkSpy CA,O=ApkSpy"); years = validity in years.
bool makeCa(const std::string& subject, int years, Identity& out, std::string& error);

// Signs a leaf certificate for `host` (DNS name or IP literal) with the CA.
// Validity ends at the CA's own end or `years`, whichever comes first.
bool makeLeaf(const Identity& ca, const std::string& host, int years, Identity& out, std::string& error);

// Loads a PEM or DER certificate + private key pair.
bool loadIdentity(const std::string& certPemOrDer, const std::string& keyPem, Identity& out, std::string& error);

// Verification roots for client (upstream) connections.
class TrustStore {
public:
    TrustStore();
    ~TrustStore();
    TrustStore(const TrustStore&) = delete;
    TrustStore& operator=(const TrustStore&) = delete;

    // Parses a PEM bundle with any number of certificates. An empty path
    // loads nothing (verification then fails with a clear error, it is never
    // silently skipped).
    bool loadPemFile(const std::string& path, std::string& error);
    bool loadPem(const std::string& pem, std::string& error);
    size_t count() const;

    struct Impl;
    const Impl* impl() const { return impl_.get(); }

private:
    friend class Connection;
    std::unique_ptr<Impl> impl_;
};

// One TLS endpoint (client or server) over an already connected TCP socket.
class Connection {
public:
    Connection();
    ~Connection();
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // Client side: handshake with `hostname` (SNI + name verification).
    // verify=false is for one-off testing (the Repeater's ignore-certificates
    // option) and must never be a global default.
    bool connect(Socket& s, const std::string& hostname, const TrustStore* roots, bool verify, int timeoutMs,
                 std::string& error);
    // Server side: handshake presenting `cert` to the peer. `alpnError` gets
    // a short explanation when the peer rejects the certificate (pinning /
    // untrusted CA), for the Traffic panel to show.
    bool accept(Socket& s, const Identity& cert, int timeoutMs, std::string& error, std::string& handshakeNote);

    // Application data. read() returns the bytes got (>0), 0 on clean close,
    // -1 on error / timeout. writeAll() blocks until everything is sent.
    int read(void* buf, size_t len, int timeoutMs);
    bool writeAll(const void* buf, size_t len);
    // Sends close_notify and releases the TLS state (the socket stays open).
    void close();
    // Decrypted bytes already buffered inside the TLS engine: read() returns
    // them without the socket becoming readable.
    size_t pending() const;

    // Feeds bytes that were already read off the socket back into the TLS
    // engine: the proxy pre-reads the ClientHello to learn the server name,
    // and the handshake must still see those bytes.
    void pushBack(const void* data, size_t len);

    // Caps the handshake at TLS 1.2 (tests, and stacks that reject 1.3).
    // Must be called before connect()/accept().
    void setMaxTls12();

    const char* version() const;    // "TLSv1.2" / "TLSv1.3"
    const char* cipher() const;     // "TLS_RSA_WITH_AES_128_GCM_SHA256"
    const char* alpn() const;       // "http/1.1" or "" when none was negotiated

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// A short human explanation of an mbedTLS error code.
std::string errorString(int code);

// The process-wide root store used to verify upstream servers: the bundled
// Mozilla bundle (assets/cacert.pem next to the executable / the solution
// folder), then the usual system bundle paths. Cached after the first call.
// Returns an empty store (and sets `error`) when nothing can be loaded -
// verification is then impossible and callers must say so, never skip it.
std::shared_ptr<TrustStore> defaultTrustStore(std::string& error);

}  // namespace tls
