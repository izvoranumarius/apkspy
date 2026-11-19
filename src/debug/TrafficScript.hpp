#pragma once
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/Process.hpp"
#include "core/Socket.hpp"
#include "debug/TrafficProxy.hpp"

class Json;

// Traffic scripts (as mitmproxy addons): a Python file with
//
//     def request(flow): ...            # before the request goes to the server
//     def response(flow): ...           # before the response reaches the app
//     def websocket_message(flow): ...  # each WebSocket text / binary message
//     def error(flow): ...              # a flow that failed
//
// (or an `addons = [obj, ...]` list of objects with those methods) that can
// read and change every HTTP exchange and WebSocket message, answer a request
// itself (flow.response = Response.make(...)) or drop it (flow.kill()).
// Several scripts can be loaded together; their hooks run in order, like
// mitmproxy's addon chain.
//
// The script runs in the installed Python (no embedded interpreter), in a
// long-lived child process started by ApkSpy. The process connects back to a
// loopback socket and proves it is ours with a random token; then each hook
// call is one JSON line each way. Calls are serialised (one at a time) and
// bounded by a timeout: a stuck or crashed script lets traffic through
// unchanged instead of stalling the app. print() output goes to the log.
namespace trafficscript {

class Host final : public TrafficProxy::Hooks {
public:
    Host() = default;
    ~Host() override;
    Host(const Host&) = delete;
    Host& operator=(const Host&) = delete;

    // Starts `python` on `scripts` (writes the support files into `supportDir`).
    // Returns once they have loaded (or one failed to).
    bool start(const std::string& python, const std::vector<std::string>& scripts, const std::string& supportDir,
               std::string& error);
    void stop();
    bool running() const { return running_.load(); }
    const std::vector<std::string>& scripts() const { return scripts_; }
    // Which hooks the scripts define (known once they are loaded).
    bool hasRequestHook() const { return wantsRequests_.load(); }
    bool hasResponseHook() const { return wantsResponses_.load(); }
    bool hasWebSocketHook() const { return wantsWs_.load(); }
    bool hasErrorHook() const { return wantsErrors_.load(); }
    // Log lines (print output, tracebacks, ApkSpy notes) since the last call.
    std::vector<std::string> takeLog();
    uint64_t calls() const { return calls_.load(); }
    uint64_t changes() const { return changes_.load(); }

    // TrafficProxy::Hooks
    Verdict onRequest(const TrafficProxy::Flow& flow, std::string& raw, std::string& reply) override;
    Verdict onResponse(const TrafficProxy::Flow& flow, const std::string& request, std::string& raw) override;
    bool wantsResponses() const override { return running_.load() && wantsResponses_.load(); }
    Verdict onWebSocket(const TrafficProxy::Flow& flow, bool fromClient, int opcode, std::string& payload) override;
    bool wantsWebSocket() const override { return running_.load() && wantsWs_.load(); }
    void onError(const TrafficProxy::Flow& flow) override;
    bool wantsErrors() const override { return running_.load() && wantsErrors_.load(); }

    static constexpr int kCallTimeoutMs = 10000;

    // The pieces, exposed for tests: a raw HTTP message <-> the JSON the
    // script side reads (body decoded, base64).
    static std::string messageJson(const std::string& raw, bool response);
    static std::string rebuild(const std::string& messageJson, bool response, std::string& error);
    // Writes apkspy_addon.py (the API) and apkspy_addon_host.py (the runner).
    static bool writeSupport(const std::string& dir, std::string& error);
    static const char* exampleScript();

private:
    // Sends one hook call and waits (bounded) for the answer carrying its id.
    bool call(const Json& msg, uint64_t id, Json& answer);
    void log(std::string line);

    std::atomic<bool> running_{false};
    std::atomic<bool> wantsRequests_{false};
    std::atomic<bool> wantsResponses_{false};
    std::atomic<bool> wantsWs_{false};
    std::atomic<bool> wantsErrors_{false};
    std::atomic<uint64_t> calls_{0};
    std::atomic<uint64_t> changes_{0};
    std::vector<std::string> scripts_;
    ChildProcess child_;
    ChildProcess::Handle killHandle_{};
    std::thread reader_;
    std::mutex callMutex_;  // one hook call at a time over the socket
    Socket conn_;
    std::string inbuf_;
    std::mutex logMutex_;
    std::deque<std::string> log_;
};

}  // namespace trafficscript
