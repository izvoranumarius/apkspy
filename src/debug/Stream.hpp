#pragma once
#include <cstddef>
#include <string>
#include "core/Socket.hpp"
#include "debug/Tls.hpp"

// A byte stream: the traffic proxy's HTTP engine works over this, so plain
// sockets (HTTP) and TLS sessions (intercepted HTTPS) share one code path.
// Implementations: PlainStream (Socket) and TlsStream (Socket + tls::Connection),
// both in debug/TrafficProxy.cpp. Reads block for the first byte like Socket
// does; waitReadable() bounds every wait so a silent peer cannot pin a worker.
namespace net {

class Stream {
public:
    virtual ~Stream() = default;
    virtual bool waitReadable(int timeoutMs) = 0;
    // Whatever is available; <= 0 = closed / error / timeout (after waitReadable).
    virtual long recvSome(void* buf, size_t len) = 0;
    virtual bool sendAll(const void* buf, size_t len) = 0;
    bool sendAll(const std::string& s) { return sendAll(s.data(), s.size()); }
    // Unblocks a thread blocked reading this stream (shutdown).
    virtual void shutdown() = 0;
};

// A Stream over the project's Socket class (plain HTTP, and the TCP side of
// TLS streams).
class PlainStream final : public Stream {
public:
    explicit PlainStream(Socket& socket) : s(socket) {}
    bool waitReadable(int ms) override { return s.waitReadable(ms); }
    long recvSome(void* buf, size_t len) override { return s.recvSome(buf, len); }
    bool sendAll(const void* buf, size_t len) override { return s.sendAll(buf, len); }
    void shutdown() override { s.shutdownBoth(); }
    using Stream::sendAll;

private:
    Socket& s;
};

// A Stream over a TLS session (the socket stays beneath it).
class TlsStream final : public Stream {
public:
    TlsStream(Socket& socket, tls::Connection& conn) : s(socket), tls(conn) {}
    // Plaintext the TLS engine already holds counts as readable: the socket
    // stays quiet for it.
    bool waitReadable(int ms) override { return tls.pending() > 0 || s.waitReadable(ms); }
    long recvSome(void* buf, size_t len) override { return tls.read(buf, len, kTlsReadTimeoutMs); }
    bool sendAll(const void* buf, size_t len) override { return tls.writeAll(buf, len); }
    void shutdown() override { s.shutdownBoth(); }
    using Stream::sendAll;

    static constexpr int kTlsReadTimeoutMs = 60000;  // bounded like the proxy's idle timeout
private:
    Socket& s;
    tls::Connection& tls;
};

}  // namespace net
