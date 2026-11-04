#include "mcp/McpServer.hpp"
#include <chrono>
#include <exception>

namespace {

// Protocol revisions this server speaks (newest first).
const char* kProtocolVersions[] = {"2025-06-18", "2025-03-26", "2024-11-05"};

constexpr int kParseError = -32700;
constexpr int kInvalidRequest = -32600;
constexpr int kMethodNotFound = -32601;
constexpr int kInvalidParams = -32602;
constexpr int kInternalError = -32603;
constexpr int kRequestCancelled = -32800;

// Tool results are capped: a model context is precious and a runaway tool
// must not produce megabytes. Tools paginate (offset/limit) below this.
constexpr size_t kMaxResultText = 512 * 1024;

std::string typeOf(const Json& v) {
    switch (v.type()) {
    case Json::Type::Null: return "null";
    case Json::Type::Bool: return "boolean";
    case Json::Type::Number: return "number";
    case Json::Type::String: return "string";
    case Json::Type::Array: return "array";
    case Json::Type::Object: return "object";
    }
    return "unknown";
}

}  // namespace

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

bool McpDispatcher::runOnOwner(std::function<void()> fn, const std::atomic<bool>* cancel, int timeoutMs) {
    auto task = std::make_shared<Task>();
    task->fn = std::move(fn);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (shutdown_) return false;
        queue_.push_back(task);
    }
    if (wake_) wake_();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    std::unique_lock<std::mutex> lock(task->m);
    while (!task->done) {
        if ((cancel && cancel->load()) || std::chrono::steady_clock::now() >= deadline) {
            task->abandoned = true;  // the owner skips it if not started yet
            // If the owner already started it we must wait: the closure
            // references state of this call.
            if (!task->fn) {
                while (!task->done) task->cv.wait(lock);
                return true;
            }
            return false;
        }
        task->cv.wait_for(lock, std::chrono::milliseconds(20));
    }
    return true;
}

void McpDispatcher::pump(int maxTasks) {
    for (int i = 0; i < maxTasks; ++i) {
        std::shared_ptr<Task> task;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) return;
            task = queue_.front();
            queue_.pop_front();
        }
        std::function<void()> fn;
        {
            std::lock_guard<std::mutex> lock(task->m);
            if (task->abandoned) continue;
            fn = std::move(task->fn);
            task->fn = nullptr;  // marks "started"
        }
        try {
            fn();
        } catch (...) {
            // Handlers report errors through their result; an escaping
            // exception must not take the UI thread down.
        }
        {
            std::lock_guard<std::mutex> lock(task->m);
            task->done = true;
        }
        task->cv.notify_all();
    }
}

void McpDispatcher::shutdown() {
    std::deque<std::shared_ptr<Task>> dropped;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        dropped.swap(queue_);
    }
    for (auto& t : dropped) {
        std::lock_guard<std::mutex> lock(t->m);
        t->abandoned = true;
    }
}

bool McpDispatcher::hasPending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !queue_.empty();
}

// ---------------------------------------------------------------------------
// Schema helpers + validation
// ---------------------------------------------------------------------------

namespace schema {

Json object(std::initializer_list<std::pair<std::string, Json>> props, std::vector<std::string> required) {
    Json s = Json::obj({{"type", "object"}});
    Json p = Json::object();
    for (const auto& kv : props) p.set(kv.first, kv.second);
    s.set("properties", std::move(p));
    if (!required.empty()) {
        Json r = Json::array();
        for (auto& name : required) r.push(Json(name));
        s.set("required", std::move(r));
    }
    s.set("additionalProperties", false);
    return s;
}

Json str(const std::string& description) { return Json::obj({{"type", "string"}, {"description", description}}); }

Json strEnum(const std::string& description, std::vector<std::string> values) {
    Json e = Json::array();
    for (auto& v : values) e.push(Json(v));
    return Json::obj({{"type", "string"}, {"description", description}, {"enum", std::move(e)}});
}

Json integer(const std::string& description, int64_t min, int64_t max) {
    return Json::obj({{"type", "integer"}, {"description", description}, {"minimum", (long long)min},
                      {"maximum", (long long)max}});
}

Json boolean(const std::string& description) { return Json::obj({{"type", "boolean"}, {"description", description}}); }

}  // namespace schema

bool McpServer::validate(const Json& schema, const Json& v, std::string& error, const std::string& path) {
    const std::string where = path.empty() ? "arguments" : path;
    const std::string& type = schema.get("type").asString();
    if (!type.empty()) {
        bool ok = false;
        if (type == "object") ok = v.isObject();
        else if (type == "array") ok = v.isArray();
        else if (type == "string") ok = v.isString();
        else if (type == "boolean") ok = v.isBool();
        else if (type == "number") ok = v.isNumber();
        else if (type == "integer") ok = v.isNumber() && (double)v.asInt() == v.asNumber();
        else ok = true;
        if (!ok) {
            error = where + ": expected " + type + ", got " + typeOf(v);
            return false;
        }
    }
    if (schema.has("enum")) {
        bool found = false;
        for (const Json& e : schema.get("enum").items())
            if (e == v) found = true;
        if (!found) {
            std::string allowed;
            for (const Json& e : schema.get("enum").items()) allowed += (allowed.empty() ? "" : ", ") + e.dump();
            error = where + ": must be one of " + allowed;
            return false;
        }
    }
    if (v.isNumber()) {
        if (schema.has("minimum") && v.asNumber() < schema.get("minimum").asNumber()) {
            error = where + ": must be >= " + schema.get("minimum").dump();
            return false;
        }
        if (schema.has("maximum") && v.asNumber() > schema.get("maximum").asNumber()) {
            error = where + ": must be <= " + schema.get("maximum").dump();
            return false;
        }
    }
    if (v.isString() && schema.has("maxLength") && (int64_t)v.asString().size() > schema.get("maxLength").asInt()) {
        error = where + ": string too long";
        return false;
    }
    if (v.isObject()) {
        for (const Json& r : schema.get("required").items())
            if (!v.has(r.asString())) {
                error = where + ": missing required property '" + r.asString() + "'";
                return false;
            }
        const Json& props = schema.get("properties");
        const bool closed = schema.get("additionalProperties").isBool() && !schema.get("additionalProperties").asBool();
        for (const auto& kv : v.members()) {
            const Json& sub = props.get(kv.first);
            if (sub.isNull()) {
                if (closed) {
                    error = where + ": unknown property '" + kv.first + "'";
                    return false;
                }
                continue;
            }
            if (!validate(sub, kv.second, error, where + "." + kv.first)) return false;
        }
    }
    if (v.isArray() && schema.has("items")) {
        for (size_t i = 0; i < v.size(); ++i)
            if (!validate(schema.get("items"), v[i], error, where + "[" + std::to_string(i) + "]")) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

McpServer::McpServer(McpDispatcher& dispatcher, Info info) : dispatcher_(dispatcher), info_(std::move(info)) {}

void McpServer::addTool(McpTool tool) {
    if (tool.inputSchema.isNull()) tool.inputSchema = schema::object({});
    tools_.push_back(std::move(tool));
}

Json McpServer::errorResponse(const Json& id, int code, const std::string& message) {
    return Json::obj({{"jsonrpc", "2.0"}, {"id", id}, {"error", Json::obj({{"code", code}, {"message", message}})}});
}

Json McpServer::resultResponse(const Json& id, Json result) {
    return Json::obj({{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}});
}

Json McpServer::listTools() const {
    Json list = Json::array();
    for (const McpTool& t : tools_) {
        Json annotations = Json::obj({{"readOnlyHint", t.readOnly},
                                      {"destructiveHint", false},
                                      {"idempotentHint", t.readOnly},
                                      {"openWorldHint", t.openWorld}});
        if (!t.title.empty()) annotations.set("title", t.title);
        Json entry = Json::obj({{"name", t.name}, {"description", t.description}, {"inputSchema", t.inputSchema},
                                {"annotations", std::move(annotations)}});
        if (!t.title.empty()) entry.set("title", t.title);
        list.push(std::move(entry));
    }
    return Json::obj({{"tools", std::move(list)}});
}

Json McpServer::renderResult(const McpToolResult& r) {
    std::string text = r.text;
    if (text.empty() && !r.structured.isNull()) text = r.structured.dump(true);
    bool truncated = false;
    if (text.size() > kMaxResultText) {
        text.resize(kMaxResultText);
        text += "\n... [output truncated - use offset/limit parameters to page through the data]";
        truncated = true;
    }
    Json content = Json::array();
    content.push(Json::obj({{"type", "text"}, {"text", std::move(text)}}));
    Json out = Json::obj({{"content", std::move(content)}, {"isError", r.isError}});
    // structuredContent must be an object; it is dropped when the text had
    // to be truncated (the two must not disagree).
    if (r.structured.isObject() && !truncated) out.set("structuredContent", r.structured);
    return out;
}

size_t McpServer::inFlight() const {
    std::lock_guard<std::mutex> lock(inflightMutex_);
    return inflight_.size();
}

void McpServer::cancelAll() {
    std::lock_guard<std::mutex> lock(inflightMutex_);
    for (auto& kv : inflight_) *kv.second = true;
}

void McpServer::cancelSession(const std::string& sessionKey) {
    std::lock_guard<std::mutex> lock(inflightMutex_);
    const std::string prefix = sessionKey + "\n";
    for (auto& kv : inflight_)
        if (kv.first.compare(0, prefix.size(), prefix) == 0) *kv.second = true;
}

std::string McpServer::handleMessage(const std::string& text, const std::string& sessionKey, const Notifier& notify) {
    Json msg;
    std::string err;
    if (!Json::parse(text, msg, &err)) return errorResponse(Json(), kParseError, "Parse error: " + err).dump();
    if (msg.isArray()) {  // JSON-RPC batch (2025-03-26)
        if (msg.size() == 0) return errorResponse(Json(), kInvalidRequest, "empty batch").dump();
        Json responses = Json::array();
        for (const Json& m : msg.items()) {
            bool isNotification = false;
            Json r = handleOne(m, sessionKey, notify, isNotification);
            if (!isNotification) responses.push(std::move(r));
        }
        return responses.size() ? responses.dump() : std::string();
    }
    bool isNotification = false;
    Json r = handleOne(msg, sessionKey, notify, isNotification);
    return isNotification ? std::string() : r.dump();
}

Json McpServer::handleOne(const Json& msg, const std::string& sessionKey, const Notifier& notify,
                          bool& isNotification) {
    ++requests_;
    if (!msg.isObject() || msg.get("jsonrpc").asString() != "2.0") {
        isNotification = false;
        return errorResponse(Json(), kInvalidRequest, "not a JSON-RPC 2.0 message");
    }
    const std::string& method = msg.get("method").asString();
    isNotification = !msg.has("id");
    const Json& id = msg.get("id");
    if (method.empty()) {
        // A response from the client (we never send requests) - ignore.
        isNotification = true;
        return Json();
    }
    if (!isNotification && !(id.isString() || id.isNumber()))
        return errorResponse(Json(), kInvalidRequest, "id must be a string or number");
    const Json& params = msg.get("params");

    if (method == "notifications/cancelled") {
        const std::string key = sessionKey + "\n" + params.get("requestId").dump();
        std::lock_guard<std::mutex> lock(inflightMutex_);
        auto it = inflight_.find(key);
        if (it != inflight_.end()) *it->second = true;
        return Json();
    }
    if (isNotification) return Json();  // initialized, roots/list_changed, ...

    if (method == "initialize") {
        const std::string& requested = params.get("protocolVersion").asString();
        std::string version = kProtocolVersions[0];
        for (const char* v : kProtocolVersions)
            if (requested == v) version = v;
        Json caps = Json::obj({{"tools", Json::obj({{"listChanged", false}})}});
        Json result = Json::obj({{"protocolVersion", version},
                                 {"capabilities", std::move(caps)},
                                 {"serverInfo", Json::obj({{"name", info_.name}, {"version", info_.version}})}});
        if (!info_.instructions.empty()) result.set("instructions", info_.instructions);
        return resultResponse(id, std::move(result));
    }
    if (method == "ping") return resultResponse(id, Json::object());
    if (method == "tools/list") return resultResponse(id, listTools());
    if (method == "tools/call") return callTool(id, params, sessionKey, notify);
    if (method == "resources/list") return resultResponse(id, Json::obj({{"resources", Json::array()}}));
    if (method == "resources/templates/list") return resultResponse(id, Json::obj({{"resourceTemplates", Json::array()}}));
    if (method == "prompts/list") return resultResponse(id, Json::obj({{"prompts", Json::array()}}));
    if (method == "logging/setLevel") return resultResponse(id, Json::object());
    return errorResponse(id, kMethodNotFound, "Method not found: " + method);
}

Json McpServer::callTool(const Json& id, const Json& params, const std::string& sessionKey, const Notifier& notify) {
    const std::string& name = params.get("name").asString();
    const McpTool* tool = nullptr;
    for (const McpTool& t : tools_)
        if (t.name == name) tool = &t;
    if (!tool) return errorResponse(id, kInvalidParams, "Unknown tool: " + name);
    Json args = params.get("arguments");
    if (args.isNull()) args = Json::object();
    std::string verr;
    if (!validate(tool->inputSchema, args, verr)) {
        // Invalid arguments are a tool-level error the model can correct.
        return resultResponse(id, renderResult(McpToolResult::error("Invalid arguments: " + verr)));
    }

    auto cancel = std::make_shared<std::atomic<bool>>(false);
    const std::string key = sessionKey + "\n" + id.dump();
    {
        std::lock_guard<std::mutex> lock(inflightMutex_);
        inflight_[key] = cancel;
    }
    struct Unregister {
        McpServer* self;
        std::string key;
        ~Unregister() {
            std::lock_guard<std::mutex> lock(self->inflightMutex_);
            self->inflight_.erase(key);
        }
    } unregister{this, key};

    McpToolContext ctx;
    ctx.cancel = cancel.get();
    const Json progressToken = params.get("_meta").get("progressToken");
    if (!progressToken.isNull() && notify) {
        ctx.progress = [notify, progressToken](double progress, double total, const std::string& message) {
            Json p = Json::obj({{"progressToken", progressToken}, {"progress", progress}});
            if (total > 0) p.set("total", total);
            if (!message.empty()) p.set("message", message);
            notify(Json::obj({{"jsonrpc", "2.0"}, {"method", "notifications/progress"}, {"params", std::move(p)}})
                       .dump());
        };
    }

    McpToolOutcome outcome;
    std::string failure;
    const bool ran = dispatcher_.runOnOwner(
        [&] {
            try {
                outcome = tool->handler(args, ctx);
            } catch (const std::exception& e) {
                failure = e.what();
            } catch (...) {
                failure = "unknown error";
            }
        },
        cancel.get(), ownerTimeoutMs_);
    if (!ran) {
        if (cancel->load()) return errorResponse(id, kRequestCancelled, "Request cancelled");
        return resultResponse(id, renderResult(McpToolResult::error(
                                      "ApkSpy did not process the request in time (is a modal dialog open?)")));
    }
    if (!failure.empty()) return errorResponse(id, kInternalError, "Tool failed: " + failure);
    if (outcome.continuation) {
        try {
            outcome.result = outcome.continuation(ctx);
        } catch (const std::exception& e) {
            return errorResponse(id, kInternalError, std::string("Tool failed: ") + e.what());
        }
    }
    if (cancel->load()) return errorResponse(id, kRequestCancelled, "Request cancelled");
    return resultResponse(id, renderResult(outcome.result));
}
