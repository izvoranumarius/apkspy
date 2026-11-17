#pragma once
#include <atomic>
#include <condition_variable>
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
#include "debug/MatchReplace.hpp"

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
//  - Match & replace rules rewrite plain-HTTP requests and responses on the way.
//  - Intercept (as in Burp): matching plain-HTTP requests and / or responses
//    wait in the proxy until the user forwards them (possibly edited) or drops
//    them. Tunnels are never held.
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
        bool edited = false;    // changed at the intercept before it went on
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
    // Ids (above `sinceId`) of the flows whose request or response contains `text`
    // (case-insensitive) in the start line, a header or the decoded body.
    std::vector<uint64_t> searchFlows(const std::string& text, uint64_t sinceId = 0) const;
    uint64_t lastId() const;
    void clear();

    // A message waiting at the intercept.
    struct Held {
        uint64_t id = 0;
        uint64_t flowId = 0;
        bool response = false;  // false: a request on its way to the server
        std::string url;
        std::string raw;        // start line, headers (CRLF), blank line, body as received
    };
    // What to hold: requests, responses, and only URLs containing `filter`
    // (case-insensitive; empty = all). Turning a kind off releases what waits.
    void setIntercept(bool requests, bool responses, const std::string& filter);
    std::vector<Held> held() const;
    size_t heldCount() const;
    // Sends a held message on: `edited` replaces it (LF or CRLF lines; Content-Length
    // follows the body), empty sends it unchanged.
    void forward(uint64_t heldId, const std::string& edited = {});
    void drop(uint64_t heldId);
    void forwardAll();

    // Match & replace: the rules applied from now on (hit counts start over).
    void setRules(matchreplace::RuleSet rules);
    std::vector<int> ruleHits() const;  // replacements made by each rule

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
    struct Waiter {
        Held held;
        bool decided = false;
        bool dropped = false;
        std::string raw;  // what to send on
    };
    bool interceptMatches(bool response, const std::string& url) const;  // under interceptMutex_
    // Blocks until the waiter is forwarded (true; w.raw is what to send) or dropped (false).
    bool hold(const std::shared_ptr<Waiter>& w);

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

    mutable std::mutex interceptMutex_;  // guards the intercept settings and waiting_
    std::condition_variable interceptCv_;
    std::deque<std::shared_ptr<Waiter>> waiting_;
    bool interceptRequests_ = false;
    bool interceptResponses_ = false;
    std::string interceptFilter_;
    uint64_t nextHeldId_ = 1;

    mutable std::mutex rulesMutex_;
    std::shared_ptr<const matchreplace::RuleSet> rules_;
    std::vector<int> ruleHits_;
    void countHits(const std::vector<int>& hits);
};
