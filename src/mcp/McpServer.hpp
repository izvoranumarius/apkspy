#pragma once
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "mcp/Json.hpp"

// Model Context Protocol server core (JSON-RPC 2.0), independent of the UI
// and of the transport (stdio / HTTP feed it message strings).
//
// Threading model - the important part:
//  * Transports call handleMessage() from their own threads, possibly
//    concurrently.
//  * Project state (Workspace, trees, archives) is owned by ONE thread: the
//    UI thread in the app, the main loop in headless mode. Every tool
//    handler therefore runs on that owner thread through McpDispatcher,
//    one at a time - concurrent requests are serialized and can never
//    observe or corrupt half-updated state.
//  * Expensive work must not stall the owner thread: a handler may return a
//    `continuation` that is executed on the calling transport thread. It
//    may only use thread-safe data captured by value (immutable analysis
//    snapshots, file path lists, the device service) - never the workspace.
//  * Long-running calls observe a cancel flag (notifications/cancelled,
//    client disconnect, server shutdown) and can report progress.

class McpDispatcher {
public:
    // Runs `fn` on the owner thread and waits for it. Returns false when it
    // could not run (cancelled/timeout/shutdown before the owner picked it
    // up; `fn` is then never executed).
    bool runOnOwner(std::function<void()> fn, const std::atomic<bool>* cancel, int timeoutMs);
    // Owner thread: runs queued tasks (at most `maxTasks` per call).
    void pump(int maxTasks = 16);
    // Wakes the owner loop when a task is queued (e.g. glfwPostEmptyEvent).
    void setWake(std::function<void()> wake) { wake_ = std::move(wake); }
    // Refuses new tasks and abandons queued ones.
    void shutdown();
    bool hasPending() const;

private:
    struct Task {
        std::function<void()> fn;
        std::mutex m;
        std::condition_variable cv;
        bool done = false;
        bool abandoned = false;
    };
    mutable std::mutex mutex_;
    std::deque<std::shared_ptr<Task>> queue_;
    std::function<void()> wake_;
    bool shutdown_ = false;
};

struct McpToolContext {
    const std::atomic<bool>* cancel = nullptr;
    // Reports progress (sent as notifications/progress when the client asked
    // for it with a progressToken). Safe to call from the continuation.
    std::function<void(double progress, double total, const std::string& message)> progress;
    bool cancelled() const { return cancel && cancel->load(); }
};

struct McpToolResult {
    bool isError = false;
    Json structured;   // structuredContent (object) - also rendered as text
    std::string text;  // optional human-readable text (defaults to the JSON)

    static McpToolResult ok(Json data) {
        McpToolResult r;
        r.structured = std::move(data);
        return r;
    }
    static McpToolResult error(std::string message) {
        McpToolResult r;
        r.isError = true;
        r.text = std::move(message);
        return r;
    }
};

struct McpToolOutcome {
    McpToolResult result;
    // When set, runs on the transport thread after the owner-thread part
    // returned; its result replaces `result`.
    std::function<McpToolResult(McpToolContext&)> continuation;

    McpToolOutcome() = default;
    McpToolOutcome(McpToolResult r) : result(std::move(r)) {}
    static McpToolOutcome later(std::function<McpToolResult(McpToolContext&)> fn) {
        McpToolOutcome o;
        o.continuation = std::move(fn);
        return o;
    }
};

struct McpTool {
    std::string name;
    std::string title;
    std::string description;
    Json inputSchema;  // JSON Schema (object); arguments are validated against it
    bool readOnly = true;
    bool openWorld = false;  // talks to devices / external processes
    // Runs on the owner thread.
    std::function<McpToolOutcome(const Json& args, McpToolContext& ctx)> handler;
};

class McpServer {
public:
    struct Info {
        std::string name = "apkspy";
        std::string version = "1.0.0";
        std::string instructions;
    };

    McpServer(McpDispatcher& dispatcher, Info info);

    void addTool(McpTool tool);
    const std::vector<McpTool>& tools() const { return tools_; }

    // Outgoing notifications for a session (progress). Stdio writes them to
    // stdout; HTTP without a stream drops them.
    using Notifier = std::function<void(const std::string& message)>;

    // Handles one incoming JSON-RPC message (object or batch). Returns the
    // response text, or "" for notifications. `sessionKey` scopes in-flight
    // request ids (cancellation) per client connection.
    std::string handleMessage(const std::string& text, const std::string& sessionKey, const Notifier& notify);

    // Cancels every in-flight request (shutdown / transport closed).
    void cancelAll();
    void cancelSession(const std::string& sessionKey);

    // Per-call timeout for the owner-thread part (the UI must answer within
    // this time or the call fails cleanly).
    void setOwnerTimeoutMs(int ms) { ownerTimeoutMs_ = ms; }

    // Validates `args` against a (subset of) JSON Schema: type, required,
    // properties, enum, minimum/maximum, items. Exposed for tests.
    static bool validate(const Json& schema, const Json& args, std::string& error, const std::string& path = "");

    // Statistics for the UI.
    uint64_t requestCount() const { return requests_.load(); }
    size_t inFlight() const;

private:
    Json handleOne(const Json& msg, const std::string& sessionKey, const Notifier& notify, bool& isNotification);
    Json callTool(const Json& id, const Json& params, const std::string& sessionKey, const Notifier& notify);
    Json listTools() const;
    static Json errorResponse(const Json& id, int code, const std::string& message);
    static Json resultResponse(const Json& id, Json result);
    static Json renderResult(const McpToolResult& r);

    McpDispatcher& dispatcher_;
    Info info_;
    std::vector<McpTool> tools_;
    int ownerTimeoutMs_ = 30000;
    std::atomic<uint64_t> requests_{0};

    mutable std::mutex inflightMutex_;
    // "<session>\n<id json>" -> cancel flag of the running call
    std::unordered_map<std::string, std::shared_ptr<std::atomic<bool>>> inflight_;
};

// Convenience builders for tool input schemas.
namespace schema {
Json object(std::initializer_list<std::pair<std::string, Json>> props, std::vector<std::string> required = {});
Json str(const std::string& description);
Json strEnum(const std::string& description, std::vector<std::string> values);
Json integer(const std::string& description, int64_t min, int64_t max);
Json boolean(const std::string& description);
}  // namespace schema
