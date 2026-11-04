#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Minimal blocking TCP socket (Winsock / BSD sockets), loopback oriented:
// the JDWP client connects to an adb-forwarded port on 127.0.0.1 and the
// MCP HTTP transport listens on 127.0.0.1 only. RAII: the destructor closes.
class Socket {
public:
    Socket() = default;
    ~Socket() { close(); }
    Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = kInvalid; }
    Socket& operator=(Socket&& o) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Process-wide init (WSAStartup); safe to call repeatedly.
    static bool initNetworking();

    bool connectLoopback(int port, int timeoutMs, std::string& error);
    // Resolves `host` (name, IPv4 or IPv6 literal) and connects to the first
    // address that answers within `timeoutMs` (used by the traffic proxy).
    bool connectHost(const std::string& host, int port, int timeoutMs, std::string& error);
    // Binds 127.0.0.1:port (0 = ephemeral) and listens.
    bool listenLoopback(int port, std::string& error);
    int localPort() const;
    // Waits up to timeoutMs for a client; returns an invalid socket on
    // timeout (check valid()).
    Socket accept(int timeoutMs);

    bool valid() const { return fd_ != kInvalid; }
    void close();
    // Unblocks a thread sitting in recv/accept on this socket.
    void shutdownBoth();

    bool sendAll(const void* data, size_t len);
    bool sendAll(const std::string& s) { return sendAll(s.data(), s.size()); }
    // Reads exactly `len` bytes (false on EOF/error/timeout).
    bool recvAll(void* data, size_t len);
    // Reads whatever is available (blocks for the first byte). <= 0 = closed.
    long recvSome(void* data, size_t len);
    // Waits for readability; false on timeout.
    bool waitReadable(int timeoutMs);
    void setRecvTimeout(int ms);

private:
#ifdef _WIN32
    using Fd = uintptr_t;
    static constexpr Fd kInvalid = ~(uintptr_t)0;
#else
    using Fd = int;
    static constexpr Fd kInvalid = -1;
#endif
    explicit Socket(Fd fd) : fd_(fd) {}
    Fd fd_ = kInvalid;
};
