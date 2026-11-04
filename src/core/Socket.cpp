#include "core/Socket.hpp"
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socklen_type = int;
#define APKSPY_CLOSESOCK closesocket
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
using socklen_type = socklen_t;
#define APKSPY_CLOSESOCK ::close
#ifndef MSG_NOSIGNAL  // macOS: no per-call flag; SO_NOSIGPIPE is set per socket instead
#define MSG_NOSIGNAL 0
#endif
#endif

Socket& Socket::operator=(Socket&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        o.fd_ = kInvalid;
    }
    return *this;
}

bool Socket::initNetworking() {
#ifdef _WIN32
    static const bool ok = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ok;
#else
    return true;
#endif
}

void Socket::close() {
    if (fd_ == kInvalid) return;
    APKSPY_CLOSESOCK((decltype(fd_))fd_);
    fd_ = kInvalid;
}

void Socket::shutdownBoth() {
    if (fd_ == kInvalid) return;
#ifdef _WIN32
    ::shutdown((SOCKET)fd_, SD_BOTH);
#else
    ::shutdown(fd_, SHUT_RDWR);
#endif
}

static bool waitFor(uintptr_t fd, bool write, int timeoutMs) {
#ifdef _WIN32
    WSAPOLLFD p{};
    p.fd = (SOCKET)fd;
    p.events = write ? POLLWRNORM : POLLRDNORM;
    return WSAPoll(&p, 1, timeoutMs) > 0;
#else
    pollfd p{};
    p.fd = (int)fd;
    p.events = write ? POLLOUT : POLLIN;
    int r;
    do r = ::poll(&p, 1, timeoutMs);
    while (r < 0 && errno == EINTR);
    return r > 0;
#endif
}

bool Socket::connectLoopback(int port, int timeoutMs, std::string& error) {
    initNetworking();
    close();
    fd_ = (Fd)::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ == kInvalid) {
        error = "socket() failed";
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // Non-blocking connect so a dead forward cannot hang the caller.
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket((SOCKET)fd_, FIONBIO, &nb);
#else
    const int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
#endif
    int rc = ::connect((decltype(fd_))fd_, (sockaddr*)&addr, sizeof addr);
    bool ok = rc == 0;
    if (!ok) {
#ifdef _WIN32
        const bool pending = WSAGetLastError() == WSAEWOULDBLOCK;
#else
        const bool pending = errno == EINPROGRESS;
#endif
        if (pending && waitFor((uintptr_t)fd_, true, timeoutMs)) {
            int soErr = 0;
            socklen_type len = sizeof soErr;
            getsockopt((decltype(fd_))fd_, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
            ok = soErr == 0;
        }
    }
#ifdef _WIN32
    nb = 0;
    ioctlsocket((SOCKET)fd_, FIONBIO, &nb);
#else
    fcntl(fd_, F_SETFL, flags);
#endif
    if (!ok) {
        error = "cannot connect to 127.0.0.1:" + std::to_string(port);
        close();
        return false;
    }
    int one = 1;
    setsockopt((decltype(fd_))fd_, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return true;
}

bool Socket::connectHost(const std::string& host, int port, int timeoutMs, std::string& error) {
    initNetworking();
    close();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* list = nullptr;
    const std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &list) != 0 || !list) {
        error = "cannot resolve " + host;
        return false;
    }
    for (addrinfo* ai = list; ai; ai = ai->ai_next) {
        fd_ = (Fd)::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd_ == kInvalid) continue;
#ifdef _WIN32
        u_long nb = 1;
        ioctlsocket((SOCKET)fd_, FIONBIO, &nb);
#else
        const int flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
#endif
        bool ok = ::connect((decltype(fd_))fd_, ai->ai_addr, (socklen_type)ai->ai_addrlen) == 0;
        if (!ok) {
#ifdef _WIN32
            const bool pending = WSAGetLastError() == WSAEWOULDBLOCK;
#else
            const bool pending = errno == EINPROGRESS;
#endif
            if (pending && waitFor((uintptr_t)fd_, true, timeoutMs)) {
                int soErr = 0;
                socklen_type len = sizeof soErr;
                getsockopt((decltype(fd_))fd_, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
                ok = soErr == 0;
            }
        }
#ifdef _WIN32
        nb = 0;
        ioctlsocket((SOCKET)fd_, FIONBIO, &nb);
#else
        fcntl(fd_, F_SETFL, flags);
#endif
        if (ok) {
            freeaddrinfo(list);
            int one = 1;
            setsockopt((decltype(fd_))fd_, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
#ifdef SO_NOSIGPIPE
            setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            return true;
        }
        close();
    }
    freeaddrinfo(list);
    error = "cannot connect to " + host + ":" + std::to_string(port);
    return false;
}

bool Socket::listenLoopback(int port, std::string& error) {
    initNetworking();
    close();
    fd_ = (Fd)::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ == kInvalid) {
        error = "socket() failed";
        return false;
    }
#ifdef _WIN32
    // Exclusive: another process must not be able to hijack the port.
    BOOL excl = TRUE;
    setsockopt((SOCKET)fd_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof excl);
#else
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // never reachable from the network
    if (::bind((decltype(fd_))fd_, (sockaddr*)&addr, sizeof addr) != 0) {
        error = "cannot bind 127.0.0.1:" + std::to_string(port) + " (port in use?)";
        close();
        return false;
    }
    if (::listen((decltype(fd_))fd_, 16) != 0) {
        error = "listen() failed";
        close();
        return false;
    }
    return true;
}

int Socket::localPort() const {
    if (fd_ == kInvalid) return 0;
    sockaddr_in addr{};
    socklen_type len = sizeof addr;
    if (getsockname((decltype(fd_))fd_, (sockaddr*)&addr, &len) != 0) return 0;
    return ntohs(addr.sin_port);
}

Socket Socket::accept(int timeoutMs) {
    if (fd_ == kInvalid || !waitFor((uintptr_t)fd_, false, timeoutMs)) return Socket();
    Fd c = (Fd)::accept((decltype(fd_))fd_, nullptr, nullptr);
    if (c == kInvalid) return Socket();
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return Socket(c);
}

bool Socket::sendAll(const void* data, size_t len) {
    const char* p = (const char*)data;
    while (len > 0) {
#ifdef _WIN32
        const int n = ::send((SOCKET)fd_, p, (int)std::min<size_t>(len, 1 << 20), 0);
#else
        const ssize_t n = ::send(fd_, p, len, MSG_NOSIGNAL);
#endif
        if (n <= 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

long Socket::recvSome(void* data, size_t len) {
#ifdef _WIN32
    return ::recv((SOCKET)fd_, (char*)data, (int)std::min<size_t>(len, 1 << 20), 0);
#else
    ssize_t n;
    do n = ::recv(fd_, data, len, 0);
    while (n < 0 && errno == EINTR);
    return (long)n;
#endif
}

bool Socket::recvAll(void* data, size_t len) {
    char* p = (char*)data;
    while (len > 0) {
        const long n = recvSome(p, len);
        if (n <= 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

bool Socket::waitReadable(int timeoutMs) { return fd_ != kInvalid && waitFor((uintptr_t)fd_, false, timeoutMs); }

void Socket::setRecvTimeout(int ms) {
    if (fd_ == kInvalid) return;
#ifdef _WIN32
    DWORD t = (DWORD)ms;
    setsockopt((SOCKET)fd_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
#else
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#endif
}
