#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "core/Socket.hpp"
#include "core/WorkerSet.hpp"

namespace adb {
class Adb;
}

// Network traffic sniffer: an HTTP(S) proxy on 127.0.0.1 that a device or
// emulator is routed through (adb reverse + the device's global HTTP proxy
// setting), recording every request it relays.
//
//  - Plain HTTP is captured completely: request / response line, headers and
//    bodies (capped), so API calls and their payloads can be inspected.
//  - HTTPS arrives as CONNECT tunnels: the proxy relays the encrypted bytes
//    untouched and records host, port, TLS SNI, timing and byte counts. The
//    contents stay encrypted (no interception).
//
// Memory: at most kMaxFlows flows are kept (oldest dropped) and each body is
// capped at kMaxBody bytes. Threading: one worker per client connection;
// readers get immutable snapshots.
class TrafficProxy {
public:
    static constexpr size_t kMaxFlows = 5000;
    static constexpr size_t kMaxBody = 2u << 20;

    using Headers = std::vector<std::pair<std::string, std::string>>;

    struct Message {
        std::string startLine;  // "GET /x HTTP/1.1" / "HTTP/1.1 200 OK"
        Headers headers;
        std::string body;       // raw bytes as sent (chunked / compressed), capped
        uint64_t bodySize = 0;  // full size (even when the copy was capped)
        bool truncated = false;
        std::string header(const std::string& name) const;  // case-insensitive, "" if absent
    };

    struct Flow {
        uint64_t id = 0;
        double startedAt = 0;   // unix time, seconds
        double durationMs = 0;
        bool tunnel = false;    // CONNECT (HTTPS) - contents not visible
        bool complete = false;
        std::string method;
        std::string host;
        int port = 80;
        std::string path;       // origin-form path + query ("" for tunnels)
        std::string sni;        // TLS server name of a tunnel
        int status = 0;
        uint64_t bytesUp = 0;   // client -> server
        uint64_t bytesDown = 0; // server -> client
        std::string error;
        Message request;
        Message response;

        std::string url() const;
        std::string contentType() const { return response.header("content-type"); }
    };

    struct Endpoint {
        std::string method;
        std::string host;
        std::string pathTemplate;  // "/api/users/{id}" (tunnels: "")
        int count = 0;
        std::vector<int> statuses; // distinct, sorted
        uint64_t bytes = 0;
        uint64_t lastFlow = 0;
        bool tunnel = false;
    };

    TrafficProxy() = default;
    ~TrafficProxy() { stop(); }
    TrafficProxy(const TrafficProxy&) = delete;
    TrafficProxy& operator=(const TrafficProxy&) = delete;

    bool start(int port, std::string& error);
    void stop();
    bool running() const { return running_.load(); }
    int port() const { return port_; }

    // Snapshots (newest last). `sinceId` returns only flows with a higher id.
    std::vector<Flow> flows(uint64_t sinceId = 0, size_t limit = kMaxFlows) const;
    bool flow(uint64_t id, Flow& out) const;
    std::vector<Endpoint> endpoints() const;
    uint64_t lastId() const;
    void clear();

    // Routes the device through the proxy (adb reverse + global http_proxy)
    // and undoes it. The device setting survives ApkSpy: always restore.
    bool routeDevice(adb::Adb& adb, const std::string& serial, std::string& error);
    bool restoreDevice(adb::Adb& adb, const std::string& serial, std::string& error);
    const std::string& routedSerial() const { return routedSerial_; }

    // Helpers (exposed for tests and the UI).
    static std::string pathTemplate(const std::string& path);        // ids -> {id}, query dropped
    static std::string decodeBody(const Message& m, std::string* note);  // dechunk + gzip/deflate
    static std::string parseSni(const uint8_t* data, size_t len);     // TLS ClientHello -> server name
    static bool parseHead(const std::string& head, Message& m);       // start line + headers
    static std::string curl(const Flow& f);                           // "copy as cURL"

private:
    void acceptLoop();
    void serve(std::shared_ptr<Socket> client);
    void serveTunnel(Socket& client, std::shared_ptr<Flow> flow, std::string pending);
    void serveHttp(Socket& client, std::shared_ptr<Flow> flow, std::string pending);
    std::shared_ptr<Flow> newFlow();
    void finish(const std::shared_ptr<Flow>& f, std::chrono::steady_clock::time_point t0);

    Socket listener_;
    std::thread acceptThread_;
    std::atomic<bool> running_{false};
    int port_ = 0;
    WorkerSet workers_;
    std::mutex clientsMutex_;
    std::vector<std::weak_ptr<Socket>> clients_;

    mutable std::mutex mutex_;  // guards flows_ and the Flow objects' fields
    std::deque<std::shared_ptr<Flow>> flows_;
    uint64_t nextId_ = 1;
    std::string routedSerial_;
};
