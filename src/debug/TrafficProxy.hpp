#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include "core/Socket.hpp"
#include "core/WorkerSet.hpp"
#include "debug/CaStore.hpp"
#include "debug/MatchReplace.hpp"
#include "debug/Stream.hpp"
#include "debug/Tls.hpp"

namespace adb {
class Adb;
}

// Network traffic sniffer: an HTTP(S) proxy on 127.0.0.1 that a device or
// emulator is routed through (adb reverse + the device's global HTTP proxy
// setting), recording every request it relays.
//
//  - Plain HTTP is captured completely: request / response line, headers and
//    bodies (capped), so API calls and their payloads can be inspected.
//  - HTTPS (CONNECT) is intercepted when a CA is set (setCa): the proxy
//    terminates the client's TLS with a per-host leaf certificate signed by
//    ApkSpy's CA, decrypts the HTTP inside, and re-encrypts to the upstream
//    server (which it verifies against the configured root bundle). Decrypted
//    requests and responses flow through exactly the same pipeline as plain
//    HTTP: capture, match & replace, intercept, Repeater, Comparer. Without a
//    CA the CONNECT is relayed as a blind tunnel: host, SNI, timing and byte
//    counts only. An app that refuses the leaf certificate (pinning, an
//    untrusted CA) gets a recorded explanation instead of a silent failure.
//  - Match & replace rules rewrite request and response bytes on the way.
//  - Intercept (as in Burp): matching requests and / or responses wait in the
//    proxy until the user forwards them (possibly edited) or drops them.
//  - WebSocket upgrades (plain and intercepted HTTPS) are relayed with their
//    frames recorded on the flow (direction, opcode, size, payload preview).
//  - Modes (as in mitmproxy): regular (HTTP proxy + CONNECT; SOCKS5 clients
//    are recognised on the same port), reverse (every request goes to one
//    fixed server, for apps pointed straight at the proxy), and an optional
//    upstream proxy that all outgoing connections are chained through.
//  - Hooks (scripts) see every request and response and may change them,
//    answer a request themselves, or kill the flow.
//
// Memory: at most kMaxFlows flows are kept (oldest dropped) and each body is
// capped at kMaxBody bytes. Threading: one worker per client connection;
// readers get immutable snapshots.
class TrafficProxy {
public:
    static constexpr size_t kMaxFlows = 5000;
    static constexpr size_t kMaxBody = 2u << 20;
    static constexpr size_t kMaxWsFrames = 10000;         // per WebSocket connection
    static constexpr size_t kMaxWsPayload = 256 * 1024;   // payload kept per frame
    static constexpr size_t kMaxWsFlowBytes = 32u << 20;  // payload kept per connection
    static constexpr size_t kMaxWsEditable = 1u << 20;    // larger messages stream past the intercept / scripts

    using Headers = std::vector<std::pair<std::string, std::string>>;

    struct Message {
        std::string startLine;  // "GET /x HTTP/1.1" / "HTTP/1.1 200 OK"
        Headers headers;
        std::string body;       // raw bytes as sent (chunked / compressed), capped
        uint64_t bodySize = 0;  // full size (even when the copy was capped)
        bool truncated = false;
        std::string header(const std::string& name) const;  // case-insensitive, "" if absent
    };

    // One WebSocket frame, recorded while the connection is relayed.
    struct WsFrame {
        bool fromClient = false;
        int opcode = 0;       // 1 text, 2 binary, 8 close, 9 ping, 10 pong
        uint64_t size = 0;    // payload bytes
        std::string preview;  // the payload (unmasked), up to kMaxWsPayload
        double at = 0;        // unix time
        bool truncated = false;  // preview holds only the start of the payload
        bool injected = false;   // sent by ApkSpy (Send message), not by either side
        bool edited = false;     // changed at the intercept or by a script
        bool dropped = false;    // dropped at the intercept or by a script (never delivered)
    };

    struct Flow {
        uint64_t id = 0;
        double startedAt = 0;   // unix time, seconds
        double durationMs = 0;
        bool tunnel = false;    // CONNECT relayed blind - contents not visible
        bool https = false;     // CONNECT intercepted: TLS terminated here, HTTP decrypted
        bool complete = false;
        bool websocket = false; // the exchange upgraded to WebSocket (frames on wsFrames)
        std::string method;
        std::string host;
        int port = 80;
        std::string path;       // origin-form path + query ("" for tunnels)
        std::string sni;        // TLS server name (tunnel or interception)
        std::string tlsVersion; // "TLSv1.3" (client side of an interception)
        std::string tlsCipher;
        std::string alpn;       // "http/1.1" when negotiated
        std::string tlsError;   // why the interception attempt failed (pinning, untrusted CA...)
        int status = 0;
        uint64_t bytesUp = 0;   // client -> server
        uint64_t bytesDown = 0; // server -> client
        std::string error;
        bool edited = false;    // changed at the intercept before it went on
        std::string note;       // what ApkSpy did (map local / remote, replay, a script answered)
        std::string transport;  // "" HTTP; "tcp" a raw TCP stream / "udp" datagrams (data on wsFrames)
        Message request;
        Message response;
        std::vector<WsFrame> wsFrames;  // WebSocket traffic (the connection's flow)
        uint64_t wsKept = 0;            // payload bytes held in wsFrames

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

    // How the proxy is reached and where it sends traffic.
    struct Mode {
        enum class Kind { Regular, Reverse } kind = Kind::Regular;
        // Reverse: the one server every request goes to.
        bool reverseTls = false;
        std::string reverseHost;
        int reversePort = 0;
        // Upstream proxy (empty host = connect directly): an HTTP proxy that
        // gets CONNECT for tunnels / HTTPS and absolute-form plain requests.
        std::string upstreamHost;
        int upstreamPort = 0;
        std::string upstreamAuth;  // "user:password" -> Proxy-Authorization: Basic
        bool reverse() const { return kind == Kind::Reverse && !reverseHost.empty(); }
        bool chained() const { return !upstreamHost.empty() && upstreamPort > 0; }
    };
    // "https://api.example.com:8443" -> reverse target. False (with `error`)
    // when it is not http(s)://host[:port].
    static bool parseReverseTarget(const std::string& url, Mode& mode, std::string& error);
    // "host:port" -> upstream proxy ("" clears it).
    static bool parseUpstream(const std::string& hostPort, Mode& mode, std::string& error);
    void setMode(const Mode& mode);
    Mode mode() const;

    // Scripts: called for every HTTP exchange (plain and decrypted). Calls
    // come from proxy workers, several at once.
    class Hooks {
    public:
        enum class Verdict { Continue, Modified, Respond, Kill };
        virtual ~Hooks() = default;
        // `raw` is the request as it would go out; Modified replaces it,
        // Respond answers the app with `reply` (a raw response) without
        // contacting the server, Kill drops the flow.
        virtual Verdict onRequest(const Flow& flow, std::string& raw, std::string& reply) = 0;
        // `raw` is the response as it would reach the app (whole, decoded
        // framing kept); Modified replaces it, Kill drops it.
        virtual Verdict onResponse(const Flow& flow, const std::string& request, std::string& raw) = 0;
        // Responses are buffered (not streamed) only while a hook wants them.
        virtual bool wantsResponses() const = 0;
        // A whole WebSocket text / binary message; Modified replaces `payload`,
        // Kill drops the message.
        virtual Verdict onWebSocket(const Flow& flow, bool fromClient, int opcode, std::string& payload) {
            (void)flow, (void)fromClient, (void)opcode, (void)payload;
            return Verdict::Continue;
        }
        virtual bool wantsWebSocket() const { return false; }
        // A flow that ended with an error (notification only).
        virtual void onError(const Flow& flow) { (void)flow; }
        virtual bool wantsErrors() const { return false; }
    };
    void setHooks(std::shared_ptr<Hooks> hooks);

    // Which connections are looked into, and where requests go (as Charles'
    // map local / map remote and mitmproxy's ignore_hosts / allow_hosts).
    struct Routing {
        // Host patterns ("*.google.com", "firebaseio.com" = it and its
        // subdomains). Ignored hosts, and hosts outside a non-empty allow list,
        // are relayed as blind tunnels: never decrypted.
        std::vector<std::string> ignoreHosts;
        std::vector<std::string> allowHosts;
        struct MapLocal {
            bool enabled = true;
            std::string urlPattern;   // glob over the URL ("https://api.x.com/v1/*")
            std::string localPath;    // a file, or a directory the rest of the path is looked up in
            std::string contentType;  // "" = from the file extension
        };
        struct MapRemote {
            bool enabled = true;
            std::string from;  // URL prefix: "https://api.example.com/v1"
            std::string to;    // replacement: "http://127.0.0.1:8080/v1"
        };
        std::vector<MapLocal> mapLocal;
        std::vector<MapRemote> mapRemote;
        bool intercepts(const std::string& host) const;  // not ignored and allowed
    };
    void setRouting(Routing routing);
    Routing routing() const;
    static bool hostMatches(const std::string& pattern, const std::string& host);
    static bool globMatch(const std::string& pattern, const std::string& text);  // '*' and '?', case-insensitive

    // Server replay: requests that match a recorded flow (method + URL) are
    // answered with its recorded response, without contacting the server.
    struct ReplayOptions {
        bool reuse = false;          // a recorded response may answer again (else each once, in order)
        bool ignoreQuery = false;    // match on the path without its query string
        bool refuseUnmatched = false;  // unmatched requests get 404 instead of going to the server
    };
    // Network conditions (as Charles' throttling): added latency per
    // request, bandwidth caps per connection and a share of connections
    // that fail - to see how the app copes with a bad network.
    struct Conditions {
        int latencyMs = 0;    // before each upstream connection
        int downKbps = 0;     // server -> app, 0 = unlimited (kilobits per second)
        int upKbps = 0;       // app -> server
        int failPercent = 0;  // upstream connections refused, 0-100
        bool active() const { return latencyMs > 0 || downKbps > 0 || upKbps > 0 || failPercent > 0; }
    };
    void setConditions(const Conditions& c);
    Conditions conditions() const;
    // Capture limits: flows kept and body bytes kept per message.
    void setLimits(size_t maxFlows, size_t maxBody);
    size_t maxFlows() const { return maxFlows_.load(); }
    static size_t maxBody();

    void setServerReplay(std::vector<Flow> recorded, ReplayOptions options);
    void clearServerReplay();
    size_t serverReplayLeft() const;  // recorded responses not used yet

    TrafficProxy() = default;
    ~TrafficProxy() { stop(); }
    TrafficProxy(const TrafficProxy&) = delete;
    TrafficProxy& operator=(const TrafficProxy&) = delete;

    bool start(int port, std::string& error);
    void stop();
    bool running() const { return running_.load(); }
    int port() const { return port_; }

    // HTTPS interception: with a CA, CONNECTs get a per-host leaf certificate
    // and their HTTP is decrypted into normal flows. Without one, CONNECTs
    // are relayed as blind tunnels. The store is kept alive by the proxy.
    void setCa(const std::shared_ptr<ca::Store>& store);
    bool interceptingHttps() const { return ca_ != nullptr; }
    // Roots used to verify upstream servers (and whether to verify at all -
    // verification is on by default; turning it off is a global, deliberate
    // choice, never a silent fallback).
    void setUpstreamTrust(const std::shared_ptr<tls::TrustStore>& roots, bool verify);

    // Snapshots (newest last). `sinceId` returns only flows with a higher id.
    std::vector<Flow> flows(uint64_t sinceId = 0, size_t limit = kMaxFlows) const;
    bool flow(uint64_t id, Flow& out) const;
    std::vector<Endpoint> endpoints() const;
    // Ids (above `sinceId`) of the flows whose request or response contains `text`
    // (case-insensitive) in the start line, a header or the decoded body.
    std::vector<uint64_t> searchFlows(const std::string& text, uint64_t sinceId = 0) const;
    uint64_t lastId() const;
    void clear();
    // Full flows (bodies included) matching `pred`, above `sinceId`. Flows
    // are copied one at a time, so a slow predicate does not hold up the relay.
    std::vector<uint64_t> selectFlows(const std::function<bool(const Flow&)>& pred, uint64_t sinceId = 0) const;
    // Full copies of the given flows (missing ids are skipped).
    std::vector<Flow> fullFlows(const std::vector<uint64_t>& ids) const;
    // Adds flows from a saved session / HAR file; they get fresh ids.
    size_t importFlows(std::vector<Flow> flows, std::vector<uint64_t>* ids = nullptr);

    // A message waiting at the intercept.
    struct Held {
        uint64_t id = 0;
        uint64_t flowId = 0;
        bool response = false;  // false: a request on its way to the server
        std::string url;
        std::string raw;        // start line, headers (CRLF), blank line, body as received
                                // (a WebSocket message: its payload)
        bool websocket = false; // a WebSocket message (`response` = from the server)
        int wsOpcode = 0;       // 1 text, 2 binary
    };
    // What to hold: requests, responses, and only URLs containing `filter`
    // (case-insensitive; empty = all). Turning a kind off releases what waits.
    void setIntercept(bool requests, bool responses, const std::string& filter, bool websocket = false);
    // Sends a message into a live WebSocket connection (to the server or to
    // the app); it is recorded on the flow as injected.
    bool injectWebSocket(uint64_t flowId, bool toServer, int opcode, const std::string& payload, std::string& error);
    bool webSocketLive(uint64_t flowId) const;
    // A WebSocket frame (exposed for tests): FIN set, masked when `mask`.
    static std::string wsFrame(int opcode, const std::string& payload, bool mask);
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
    // `established`: the client was already told the tunnel is up (SOCKS5).
    void serveTunnel(Socket& client, std::shared_ptr<Flow> flow, std::string pending, bool established = false);
    // A SOCKS5 client (its greeting starts `pending`).
    void serveSocks(std::shared_ptr<Socket> client, std::string pending);
    // An outgoing TCP connection to host:port, directly or through the
    // upstream proxy. `viaConnect`: tunnel through it with CONNECT (TLS and
    // raw tunnels); otherwise plain HTTP is sent to the upstream proxy as is.
    bool connectOut(Socket& sock, const std::string& host, int port, bool viaConnect, std::string& error);
    // Relay both directions of a blind tunnel (used by serveTunnel and the
    // non-TLS fallback in serveHttps).
    // `record`: keep the bytes on the flow (a readable, non-TLS stream).
    void relayTunnelBytes(Socket& client, Socket& upstream, const std::shared_ptr<Flow>& flow, bool record = false);
    // Plain-text HTTP/2 (prior knowledge): relays the bytes both ways
    // unchanged and lists each stream as its own flow. `conn` is the
    // connection's flow; `clientSeed` (already sent upstream) starts the
    // client's bytes.
    void relayH2c(net::Stream& client, net::Stream& upstream, const std::string& host, int port, const std::string& clientSeed,
                  const std::shared_ptr<Flow>& conn);
    // SOCKS5 UDP ASSOCIATE: relays datagrams while the control connection stays open.
    void serveSocksUdp(Socket& control);
    // CONNECT with a CA: terminate the client's TLS with a per-host leaf,
    // then run HTTP exchanges until the app closes the session. Not TLS after
    // all: falls back to a blind relay.
    void serveHttps(Socket& client, const std::string& connectHost, int port, std::string pending,
                    bool established = false);
    // One request/response exchange over `client` (plain or TLS). The upstream
    // connection is plain or TLS depending on the flow. Returns true when the
    // client session can take another request (persistent TLS session with a
    // cleanly framed exchange).
    // `flow` is the exchange's flow: pre-created by the plain path, created
    // here (from `preset`) when a request arrives on a persistent TLS session.
    // `leftover` (optional) receives client bytes read past this request -
    // the start of the next one on a persistent session.
    bool serveExchange(net::Stream& client, std::shared_ptr<Flow>& flow, const Flow* preset, std::string pending,
                       bool persistent, std::string* leftover = nullptr);
    // WebSocket frames of one direction, recorded on the flow while relayed.
    struct WsSession;
    void relayWsDirection(net::Stream& from, net::Stream& to, std::mutex& toWrite, const std::shared_ptr<Flow>& flow, bool fromClient,
                          const std::string& seed = {});
    // After a 101 Upgrade: relay frames both ways, recording them on the flow.
    // The seeds carry bytes that arrived together with the 101 head.
    void relayWebSockets(net::Stream& client, net::Stream& upstream, const std::shared_ptr<Flow>& flow,
                         const std::string& clientSeed = {}, const std::string& upstreamSeed = {});
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

    mutable std::mutex caMutex_;                // guards the three below
    std::shared_ptr<ca::Store> ca_;              // set = HTTPS interception on
    std::shared_ptr<tls::TrustStore> upstreamRoots_;
    bool verifyUpstream_ = true;

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
    bool interceptWs_ = false;
    void recordWs(const std::shared_ptr<Flow>& flow, WsFrame frame, uint64_t wireBytes);
    // Live WebSocket connections (for injection), by flow id.
    mutable std::mutex wsMutex_;
    std::unordered_map<uint64_t, std::weak_ptr<WsSession>> wsSessions_;
    uint64_t nextHeldId_ = 1;

    mutable std::mutex modeMutex_;  // guards mode_, hooks_ and routing_
    Mode mode_;
    std::shared_ptr<Hooks> hooks_;
    Routing routing_;
    bool interceptsHost(const std::string& host) const;  // routing check (takes modeMutex_)
    // Map local / server replay: the raw response that answers this request, if any.
    bool localAnswer(const std::string& method, const std::string& url, std::string& reply, std::string& why);
    std::atomic<int> latencyMs_{0}, downBps_{0}, upBps_{0}, failPercent_{0};
    std::atomic<size_t> maxFlows_{kMaxFlows};
    // Waits for data on a long-lived relay (WebSocket, h2c, upgrades): no idle
    // limit - one quiet direction is normal there. False once the proxy stops;
    // a closed peer reads as readable (the read then returns 0).
    bool waitLongLived(net::Stream& s) const;
    // Pauses after `n` bytes so a direction stays under its cap.
    void pace(size_t n, bool down) const;
    mutable std::mutex replayMutex_;
    struct ReplayEntry {
        std::string key;
        std::string response;  // raw
        bool used = false;
    };
    std::vector<ReplayEntry> replay_;
    ReplayOptions replayOptions_;
    bool replayOn_ = false;

    mutable std::mutex rulesMutex_;
    std::shared_ptr<const matchreplace::RuleSet> rules_;
    std::vector<int> ruleHits_;
    void countHits(const std::vector<int>& hits);
};
