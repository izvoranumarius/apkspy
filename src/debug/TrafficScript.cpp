#include "debug/TrafficScript.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include "core/Codec.hpp"
#include "core/Paths.hpp"
#include "core/TextUtils.hpp"
#include "debug/HttpClient.hpp"
#include "mcp/Json.hpp"

namespace trafficscript {

namespace fs = std::filesystem;

namespace {

// ---- The Python side ---------------------------------------------------------

const char* kApiPy = R"PY("""ApkSpy traffic script API - mitmproxy-style flows for ApkSpy's proxy.

A script defines request(flow) and / or response(flow) (or a list
`addons = [...]` of objects with those methods). In them:

    flow.request.method / scheme / host / port / path / url / http_version
    flow.request.headers            case-insensitive, multi-valued
    flow.request.content / .text    the decoded body (bytes / str), settable
    flow.request.query              dict of query parameters, settable
    flow.response.status_code / reason / headers / content / text
    flow.response = Response.make(200, b"...", {"Content-Type": "..."})
                                    (in request(): answer without the server)
    flow.kill()                     drop the flow
    flow.error                      why the flow failed (in error())
    flow.websocket.messages[-1]     the message (in websocket_message()):
                                    .content / .text / .from_client / .is_text / .drop()
    ctx.log("...")                  write to ApkSpy's script log

Changing request.host only rewrites the Host header for HTTPS flows (the
connection is already made); for plain HTTP the proxy follows it.
"""
import json as _json
import sys
from http.client import responses as _reasons
from urllib.parse import parse_qsl, urlencode, urlsplit


class Headers:
    """Ordered, case-insensitive, multi-valued HTTP headers."""

    def __init__(self, fields=None, **kwargs):
        if isinstance(fields, dict):
            fields = list(fields.items())
        self.fields = [[str(k), str(v)] for k, v in (fields or [])]
        for k, v in kwargs.items():
            self.fields.append([k.replace("_", "-"), str(v)])

    def _is(self, a, b):
        return a.lower() == b.lower()

    def __getitem__(self, name):
        for k, v in self.fields:
            if self._is(k, name):
                return v
        raise KeyError(name)

    def get(self, name, default=None):
        try:
            return self[name]
        except KeyError:
            return default

    def get_all(self, name):
        return [v for k, v in self.fields if self._is(k, name)]

    def set_all(self, name, values):
        self.fields = [f for f in self.fields if not self._is(f[0], name)]
        for v in values:
            self.fields.append([name, str(v)])

    def add(self, name, value):
        self.fields.append([name, str(value)])

    def __setitem__(self, name, value):
        out, done = [], False
        for k, v in self.fields:
            if self._is(k, name):
                if not done:
                    out.append([k, str(value)])
                    done = True
            else:
                out.append([k, v])
        if not done:
            out.append([name, str(value)])
        self.fields = out

    def __delitem__(self, name):
        before = len(self.fields)
        self.fields = [f for f in self.fields if not self._is(f[0], name)]
        if len(self.fields) == before:
            raise KeyError(name)

    def pop(self, name, default=None):
        value = self.get(name, default)
        self.fields = [f for f in self.fields if not self._is(f[0], name)]
        return value

    def __contains__(self, name):
        return any(self._is(k, name) for k, _ in self.fields)

    def keys(self):
        seen, out = set(), []
        for k, _ in self.fields:
            if k.lower() not in seen:
                seen.add(k.lower())
                out.append(k)
        return out

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self.keys())

    def items(self, multi=False):
        if multi:
            return [(k, v) for k, v in self.fields]
        return [(k, self[k]) for k in self.keys()]

    def values(self):
        return [self[k] for k in self.keys()]

    def copy(self):
        return Headers([list(f) for f in self.fields])

    def __repr__(self):
        return "Headers(%r)" % (self.fields,)


class Message:
    def __init__(self, headers=None, content=b"", http_version="HTTP/1.1"):
        self.headers = headers if isinstance(headers, Headers) else Headers(headers)
        self.content = content or b""
        self.http_version = http_version

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        self._content = bytes(value or b"")

    raw_content = content

    def _charset(self):
        ct = self.headers.get("content-type", "")
        for part in ct.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                return part[8:].strip('"') or "utf-8"
        return "utf-8"

    def get_text(self, strict=True):
        try:
            return self._content.decode(self._charset(), "strict" if strict else "replace")
        except (UnicodeDecodeError, LookupError):
            if strict:
                return None
            return self._content.decode("utf-8", "replace")

    def set_text(self, text):
        try:
            self._content = text.encode(self._charset())
        except LookupError:
            self._content = text.encode("utf-8")

    text = property(lambda self: self.get_text(strict=False), lambda self, t: self.set_text(t))

    def get_content(self):
        return self._content

    def set_content(self, value):
        self.content = value

    def json(self, **kwargs):
        return _json.loads(self.get_text(strict=False), **kwargs)

    def _state(self):
        return (self.http_version, [tuple(f) for f in self.headers.fields], self._content)


class Request(Message):
    def __init__(self, method="GET", scheme="http", host="", port=80, path="/", headers=None, content=b"",
                 http_version="HTTP/1.1"):
        super().__init__(headers, content, http_version)
        self.method = method
        self.scheme = scheme
        self._host = host
        self.port = port
        self.path = path

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value
        if "host" in self.headers:
            default = 443 if self.scheme == "https" else 80
            self.headers["Host"] = value if self.port == default else "%s:%d" % (value, self.port)

    @property
    def pretty_host(self):
        return self.headers.get("host", self._host).split(":")[0]

    @property
    def url(self):
        default = 443 if self.scheme == "https" else 80
        netloc = self._host if self.port == default else "%s:%d" % (self._host, self.port)
        return "%s://%s%s" % (self.scheme, netloc, self.path)

    @url.setter
    def url(self, value):
        parts = urlsplit(value)
        self.scheme = parts.scheme or self.scheme
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.host = parts.hostname or self._host
        self.path = (parts.path or "/") + ("?" + parts.query if parts.query else "")

    pretty_url = url

    @property
    def query(self):
        return dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))

    @query.setter
    def query(self, values):
        base = self.path.split("?", 1)[0]
        q = urlencode(list(values.items()) if isinstance(values, dict) else list(values))
        self.path = base + ("?" + q if q else "")

    @property
    def urlencoded_form(self):
        return dict(parse_qsl(self.get_text(strict=False), keep_blank_values=True))

    @urlencoded_form.setter
    def urlencoded_form(self, values):
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.content = urlencode(list(values.items()) if isinstance(values, dict) else list(values)).encode()

    @classmethod
    def make(cls, method, url, content=b"", headers=None):
        r = cls(method=method, headers=headers, content=content)
        r.url = url
        if "host" not in r.headers:
            r.headers["Host"] = urlsplit(url).netloc
        return r

    def _state(self):
        return (self.method, self.scheme, self._host, self.port, self.path) + super()._state()


class Response(Message):
    def __init__(self, status_code=200, reason=None, headers=None, content=b"", http_version="HTTP/1.1"):
        super().__init__(headers, content, http_version)
        self.status_code = int(status_code)
        self.reason = reason if reason is not None else _reasons.get(int(status_code), "")

    @classmethod
    def make(cls, status_code=200, content=b"", headers=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        return cls(status_code=status_code, headers=headers, content=content)

    def _state(self):
        return (self.status_code, self.reason) + super()._state()


class WebSocketMessage:
    TEXT, BINARY = 1, 2

    def __init__(self, from_client, type, content):
        self.from_client = from_client
        self.type = type
        self.content = content
        self.dropped = False

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        self._content = bytes(value or b"")

    @property
    def is_text(self):
        return self.type == WebSocketMessage.TEXT

    @property
    def text(self):
        return self._content.decode("utf-8", "replace")

    @text.setter
    def text(self, value):
        self._content = value.encode("utf-8")

    def drop(self):
        self.dropped = True

    def __repr__(self):
        return "WebSocketMessage(%s, %r)" % ("client" if self.from_client else "server", self._content[:60])


class WebSocketData:
    def __init__(self, messages=None):
        self.messages = messages or []


class Flow:
    def __init__(self, id, request, response=None, https=False, sni=""):
        self.id = id
        self.request = request
        self.response = response
        self.https = https
        self.sni = sni
        self.killed = False
        self.metadata = {}
        self.websocket = None
        self.error = None

    def kill(self):
        self.killed = True


class _Log:
    def __call__(self, *args):
        print(*args, flush=True)

    def info(self, *args):
        self(*args)

    def debug(self, *args):
        self("[debug]", *args)

    def warn(self, *args):
        self("[warn]", *args)

    warning = warn

    def error(self, *args):
        self("[error]", *args)


class _Ctx:
    log = _Log()


ctx = _Ctx()
)PY";

const char* kHostPy = R"PY("""Runs one ApkSpy traffic script and answers the proxy's hook calls (internal)."""
import base64
import importlib.util
import json
import os
import socket
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apkspy_addon as api  # noqa: E402


def _message(obj, cls, flow):
    body = base64.b64decode(obj.get("body_b64", ""))
    headers = api.Headers(obj.get("headers", []))
    if cls is api.Request:
        return api.Request(obj.get("method", "GET"), "https" if flow.get("https") else "http", flow.get("host", ""),
                           int(flow.get("port", 80)), obj.get("path", "/"), headers, body,
                           obj.get("http_version", "HTTP/1.1"))
    return api.Response(obj.get("status_code", 200), obj.get("reason", ""), headers, body,
                        obj.get("http_version", "HTTP/1.1"))


def _json_of(m, decoded):
    out = {"headers": [list(f) for f in m.headers.fields], "body_b64": base64.b64encode(m.content).decode(),
           "http_version": m.http_version, "content_decoded": decoded}
    if isinstance(m, api.Request):
        out.update(method=m.method, path=m.path, host=m.host, port=m.port, scheme=m.scheme)
    else:
        out.update(status_code=m.status_code, reason=m.reason)
    return out


def main():
    port, token_file, scripts = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
    with open(token_file) as f:
        token = f.read().strip()
    try:
        os.remove(token_file)
    except OSError:
        pass
    for script in scripts:
        sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
    conn = socket.create_connection(("127.0.0.1", port))
    stream = conn.makefile("rwb")

    def send(obj):
        stream.write(json.dumps(obj).encode() + b"\n")
        stream.flush()

    hooks = {"request": [], "response": [], "websocket_message": [], "error": []}
    error = None
    for index, script in enumerate(scripts):
        try:
            spec = importlib.util.spec_from_file_location("apkspy_user_script_%d" % index, script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            found = []
            for target in [module] + list(getattr(module, "addons", None) or []):
                for name in hooks:
                    fn = getattr(target, name, None)
                    if callable(fn):
                        hooks[name].append(fn)
                        found.append(name)
            print("loaded %s (hooks: %s)" % (os.path.basename(script), ", ".join(sorted(set(found))) or "none"),
                  flush=True)
        except Exception:
            error = "%s:\n%s" % (script, traceback.format_exc())
            break
    send({"token": token, "hooks": [n for n in hooks if hooks[n]], "error": error})
    if error:
        return

    for line in stream:
        msg = json.loads(line)
        hook, fl = msg["hook"], msg["flow"]
        if hook in ("websocket_message", "error"):
            send(_side_hook(hooks, msg))
            continue
        req_obj = fl["request"]
        resp_obj = fl.get("response")
        flow = api.Flow(fl["id"], _message(req_obj, api.Request, fl),
                        _message(resp_obj, api.Response, fl) if resp_obj else None, fl.get("https", False),
                        fl.get("sni", ""))
        before_req = flow.request._state()
        original_resp = flow.response
        before_resp = original_resp._state() if original_resp else None
        for fn in hooks.get(hook, []):
            try:
                fn(flow)
            except Exception:
                print("error in %s():\n%s" % (hook, traceback.format_exc()), flush=True)
            if flow.killed:
                break
        out = {"id": msg["id"], "verdict": "continue"}
        if flow.killed:
            out["verdict"] = "kill"
        elif hook == "request" and flow.response is not None:
            out["verdict"] = "respond"
            out["response"] = _json_of(flow.response, False)
        elif hook == "request" and flow.request._state() != before_req:
            out["verdict"] = "modified"
            out["request"] = _json_of(flow.request, req_obj.get("content_decoded", False))
        elif hook == "response" and flow.response is not None and (
                flow.response is not original_resp or flow.response._state() != before_resp):
            out["verdict"] = "modified"
            decoded = resp_obj.get("content_decoded", False) if flow.response is original_resp else False
            out["response"] = _json_of(flow.response, decoded)
        send(out)


def _side_hook(hooks, msg):
    """websocket_message() and error(): the flow's request plus the event."""
    hook, fl = msg["hook"], msg["flow"]
    flow = api.Flow(fl["id"], _message(fl["request"], api.Request, fl), None, fl.get("https", False), fl.get("sni", ""))
    out = {"id": msg["id"], "verdict": "continue"}
    if hook == "error":
        flow.error = fl.get("error", "")
        for fn in hooks["error"]:
            try:
                fn(flow)
            except Exception:
                print("error in error():\n%s" % traceback.format_exc(), flush=True)
        return out
    m = msg["message"]
    message = api.WebSocketMessage(m["from_client"], m["opcode"], base64.b64decode(m["content_b64"]))
    original = message.content
    flow.websocket = api.WebSocketData([message])
    for fn in hooks["websocket_message"]:
        try:
            fn(flow)
        except Exception:
            print("error in websocket_message():\n%s" % traceback.format_exc(), flush=True)
        if message.dropped or flow.killed:
            break
    if message.dropped or flow.killed:
        out["verdict"] = "kill"
    elif message.content != original:
        out["verdict"] = "modified"
        out["content_b64"] = base64.b64encode(message.content).decode()
    return out


if __name__ == "__main__":
    main()
)PY";

const char* kExamplePy = R"PY("""Example ApkSpy traffic script (mitmproxy-style hooks).

Load it from the Traffic panel's Scripts tab. It is reloaded automatically
when you save it. print() / ctx.log() output appears in the Scripts tab.
"""
from apkspy_addon import Response, ctx


def request(flow):
    # Mark every request so it is easy to spot server-side.
    flow.request.headers["X-ApkSpy"] = "1"

    # Answer one path locally: the server is never contacted.
    if flow.request.path.startswith("/apkspy-test"):
        flow.response = Response.make(200, b'{"ok": true}', {"Content-Type": "application/json"})


def response(flow):
    ctx.log("%s %s -> %d" % (flow.request.method, flow.request.url, flow.response.status_code))

    # Example: flip a flag in JSON answers.
    if "json" in flow.response.headers.get("content-type", ""):
        text = flow.response.text
        if '"debug":false' in text:
            flow.response.text = text.replace('"debug":false', '"debug":true')
)PY";

// ---- C++ side -------------------------------------------------------------------

std::string randomToken() {
    std::random_device rd;
    static const char* kHex = "0123456789abcdef";
    std::string t;
    for (int i = 0; i < 32; ++i) t += kHex[rd() & 15];
    return t;
}

bool writeFile(const fs::path& path, const std::string& text, std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    if (!out.good()) {
        error = "could not write " + pathutil::toUtf8(path);
        return false;
    }
    return true;
}

Json messageJsonImpl(const std::string& raw, bool response) {
    Json out = Json::object();
    const size_t headEnd = raw.find("\r\n\r\n");
    TrafficProxy::Message m;
    if (headEnd == std::string::npos || !TrafficProxy::parseHead(raw.substr(0, headEnd + 2), m)) return out;
    m.body = raw.substr(headEnd + 4);
    const std::string decoded = TrafficProxy::decodeBody(m, nullptr);
    const std::string& line = m.startLine;
    const size_t sp1 = line.find(' ');
    if (response) {
        const size_t sp2 = line.find(' ', sp1 == std::string::npos ? line.size() : sp1 + 1);
        out.set("http_version", line.substr(0, sp1));
        out.set("status_code", std::atoi(line.c_str() + std::min(line.size(), sp1 + 1)));
        out.set("reason", sp2 == std::string::npos ? std::string() : line.substr(sp2 + 1));
    } else {
        const size_t sp2 = line.rfind(' ');
        out.set("method", line.substr(0, sp1));
        out.set("path", sp1 != std::string::npos && sp2 > sp1 ? line.substr(sp1 + 1, sp2 - sp1 - 1) : std::string("/"));
        out.set("http_version", sp2 != std::string::npos ? line.substr(sp2 + 1) : std::string("HTTP/1.1"));
    }
    Json headers = Json::array();
    for (const auto& [name, value] : m.headers) {
        Json pair = Json::array();
        pair.push(name);
        pair.push(value);
        headers.push(pair);
    }
    out.set("headers", headers);
    out.set("body_b64", codec::base64Encode(decoded));
    out.set("content_decoded", decoded != m.body);  // chunked / gzip undone
    return out;
}

std::string rebuildImpl(const Json& m, bool response, std::string& error) {
    if (!m.isObject()) return error = "no message", std::string();
    std::string out;
    int status = 0;
    if (response) {
        status = static_cast<int>(m.get("status_code").asInt(200));
        if (status < 100 || status > 999) return error = "invalid status code", std::string();
        out = m.get("http_version").asString("HTTP/1.1") + " " + std::to_string(status) + " " + m.get("reason").asString("");
    } else {
        const std::string method = m.get("method").asString(""), path = m.get("path").asString("");
        if (method.empty() || path.empty() || method.find_first_of(" \r\n") != std::string::npos ||
            path.find_first_of(" \r\n") != std::string::npos)
            return error = "invalid method or path", std::string();
        out = method + " " + path + " " + m.get("http_version").asString("HTTP/1.1");
    }
    out += "\r\n";
    std::string body;
    if (!codec::base64Decode(m.get("body_b64").asString(""), body)) return error = "invalid body encoding", std::string();
    const bool decoded = m.get("content_decoded").asBool(false);
    for (const Json& h : m.get("headers").items()) {
        const std::string name = h[0].asString(""), value = h[1].asString("");
        if (name.empty() || name.find_first_of(":\r\n") != std::string::npos || value.find_first_of("\r\n") != std::string::npos)
            continue;
        const std::string lower = tex::asciiLower(name);
        if (lower == "content-length" || lower == "transfer-encoding") continue;  // set below for the new body
        if (decoded && lower == "content-encoding") continue;                      // the body is plain now
        out += name + ": " + value + "\r\n";
    }
    const bool bodyless = response && ((status >= 100 && status < 200) || status == 204 || status == 304);
    if (!bodyless) {
        const std::string method = response ? std::string() : tex::asciiLower(m.get("method").asString(""));
        if (response || !body.empty() || method == "post" || method == "put" || method == "patch")
            out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    out += "\r\n";
    out += body;
    return out;
}

Json flowJson(const TrafficProxy::Flow& f) {
    Json out = Json::object();
    out.set("id", static_cast<unsigned long long>(f.id));
    out.set("https", f.https);
    out.set("host", f.sni.empty() ? f.host : f.sni);
    out.set("port", f.port);
    out.set("sni", f.sni);
    return out;
}

}  // namespace

Host::~Host() { stop(); }

bool Host::writeSupport(const std::string& dir, std::string& error) {
    std::error_code ec;
    const fs::path d = pathutil::fromUtf8(dir);
    fs::create_directories(d, ec);
    return writeFile(d / "apkspy_addon.py", kApiPy, error) && writeFile(d / "apkspy_addon_host.py", kHostPy, error);
}

const char* Host::exampleScript() { return kExamplePy; }

std::string Host::messageJson(const std::string& raw, bool response) { return messageJsonImpl(raw, response).dump(); }

std::string Host::rebuild(const std::string& messageJson, bool response, std::string& error) {
    Json m;
    if (!Json::parse(messageJson, m, &error)) return {};
    return rebuildImpl(m, response, error);
}

void Host::log(std::string line) {
    std::lock_guard<std::mutex> lock(logMutex_);
    log_.push_back(std::move(line));
    while (log_.size() > 5000) log_.pop_front();
}

std::vector<std::string> Host::takeLog() {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::vector<std::string> out(log_.begin(), log_.end());
    log_.clear();
    return out;
}

bool Host::start(const std::string& python, const std::vector<std::string>& scripts, const std::string& supportDir,
                 std::string& error) {
    stop();
    std::error_code ec;
    if (scripts.empty()) return error = "no script to load", false;
    for (const auto& script : scripts)
        if (!fs::is_regular_file(pathutil::fromUtf8(script), ec)) return error = "no such script: " + script, false;
    if (!writeSupport(supportDir, error)) return false;
    Socket listener;
    if (!listener.listenLoopback(0, error)) return false;
    const int port = listener.localPort();
    // The token goes through a file, not the command line (which other local
    // users can read); the script side deletes it once read.
    const std::string token = randomToken();
    const fs::path tokenFile = pathutil::fromUtf8(supportDir) / (".session-" + std::to_string(port));
    if (!writeFile(tokenFile, token, error)) return false;
    std::vector<std::string> argv = {python, "-u", pathutil::toUtf8(pathutil::fromUtf8(supportDir) / "apkspy_addon_host.py"),
                                     std::to_string(port), pathutil::toUtf8(tokenFile)};
    argv.insert(argv.end(), scripts.begin(), scripts.end());
    child_ = ChildProcess::spawn(argv);
    if (!child_.valid()) {
        fs::remove(tokenFile, ec);
        return error = "could not start Python (" + python + ") - set its path in Settings", false;
    }
    scripts_ = scripts;
    killHandle_ = child_.killHandle();
    auto exited = std::make_shared<std::atomic<bool>>(false);
    reader_ = std::thread([this, exited] {
        child_.readAll([this](std::string line) { log(std::move(line)); });
        const int code = child_.waitForExit();
        exited->store(true);
        if (running_.exchange(false)) log("[ApkSpy] the script stopped (exit code " + std::to_string(code) + ") - traffic passes unchanged");
    });
    // Wait for the script side to connect and load the script.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    Socket conn;
    while (!conn.valid() && !exited->load() && std::chrono::steady_clock::now() < deadline) conn = listener.accept(200);
    fs::remove(tokenFile, ec);
    if (!conn.valid()) {
        stop();
        return error = exited->load() ? "Python exited before loading the script - see the log" : "the script did not start within 20 s", false;
    }
    // Hello: the token, the hooks it defines, or the import error.
    std::string line;
    char buf[4096];
    while (line.find('\n') == std::string::npos && conn.waitReadable(20000)) {
        const long n = conn.recvSome(buf, sizeof buf);
        if (n <= 0) break;
        line.append(buf, static_cast<size_t>(n));
    }
    const size_t nl = line.find('\n');
    Json hello;
    if (nl == std::string::npos || !Json::parse(line.substr(0, nl), hello) || hello.get("token").asString("") != token) {
        stop();
        return error = "the script process did not identify itself", false;
    }
    if (!hello.get("error").isNull() && !hello.get("error").asString("").empty()) {
        log(hello.get("error").asString(""));
        stop();
        return error = "the script failed to load - see the log", false;
    }
    bool req = false, resp = false, ws = false, err = false;
    for (const Json& h : hello.get("hooks").items()) {
        req |= h.asString("") == "request";
        resp |= h.asString("") == "response";
        ws |= h.asString("") == "websocket_message";
        err |= h.asString("") == "error";
    }
    wantsRequests_ = req;
    wantsResponses_ = resp;
    wantsWs_ = ws;
    wantsErrors_ = err;
    inbuf_ = line.substr(nl + 1);
    conn_ = std::move(conn);
    running_ = true;
    if (!req && !resp && !ws && !err) log("[ApkSpy] the scripts define no hooks (request, response, websocket_message, error)");
    return true;
}

void Host::stop() {
    running_ = false;
    {
        std::lock_guard<std::mutex> lock(callMutex_);
        conn_.shutdownBoth();
        conn_.close();
        inbuf_.clear();
    }
    if (child_.valid()) ChildProcess::killByHandle(killHandle_);
    if (reader_.joinable()) reader_.join();
    child_ = ChildProcess();
    wantsRequests_ = wantsResponses_ = wantsWs_ = wantsErrors_ = false;
}

bool Host::call(const Json& msg, uint64_t id, Json& answer) {
    std::lock_guard<std::mutex> lock(callMutex_);
    if (!running_.load() || !conn_.valid()) return false;
    if (!conn_.sendAll(msg.dump() + "\n")) return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCallTimeoutMs);
    char buf[65536];
    for (;;) {
        const size_t nl = inbuf_.find('\n');
        if (nl != std::string::npos) {
            const std::string line = inbuf_.substr(0, nl);
            inbuf_.erase(0, nl + 1);
            // A late answer to a call that already timed out is skipped.
            if (!Json::parse(line, answer) || static_cast<uint64_t>(answer.get("id").asInt(0)) != id) continue;
            return true;
        }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0 || !conn_.waitReadable(static_cast<int>(left))) {
            log("[ApkSpy] the script took longer than 10 s - the flow went on unchanged");
            return false;
        }
        const long n = conn_.recvSome(buf, sizeof buf);
        if (n <= 0) return false;
        inbuf_.append(buf, static_cast<size_t>(n));
    }
}

TrafficProxy::Hooks::Verdict Host::onRequest(const TrafficProxy::Flow& flow, std::string& raw, std::string& reply) {
    if (!running_.load() || !wantsRequests_.load()) return Verdict::Continue;
    const uint64_t id = ++calls_;
    Json f = flowJson(flow);
    f.set("request", messageJsonImpl(raw, false));
    const Json msg = Json::obj({{"id", static_cast<unsigned long long>(id)}, {"hook", "request"}, {"flow", f}});
    Json a;
    if (!call(msg, id, a)) return Verdict::Continue;
    const std::string verdict = a.get("verdict").asString("continue");
    std::string error;
    if (verdict == "kill") return ++changes_, Verdict::Kill;
    if (verdict == "respond") {
        reply = rebuildImpl(a.get("response"), true, error);
        if (reply.empty()) return log("[ApkSpy] request(): bad response from the script: " + error), Verdict::Continue;
        return ++changes_, Verdict::Respond;
    }
    if (verdict == "modified") {
        const std::string rebuilt = rebuildImpl(a.get("request"), false, error);
        if (rebuilt.empty()) return log("[ApkSpy] request(): bad request from the script: " + error), Verdict::Continue;
        raw = rebuilt;
        return ++changes_, Verdict::Modified;
    }
    return Verdict::Continue;
}

TrafficProxy::Hooks::Verdict Host::onResponse(const TrafficProxy::Flow& flow, const std::string& request, std::string& raw) {
    if (!running_.load() || !wantsResponses_.load()) return Verdict::Continue;
    const uint64_t id = ++calls_;
    Json f = flowJson(flow);
    f.set("request", messageJsonImpl(request, false));
    f.set("response", messageJsonImpl(raw, true));
    const Json msg = Json::obj({{"id", static_cast<unsigned long long>(id)}, {"hook", "response"}, {"flow", f}});
    Json a;
    if (!call(msg, id, a)) return Verdict::Continue;
    const std::string verdict = a.get("verdict").asString("continue");
    if (verdict == "kill") return ++changes_, Verdict::Kill;
    if (verdict == "modified") {
        std::string error;
        const std::string rebuilt = rebuildImpl(a.get("response"), true, error);
        if (rebuilt.empty()) return log("[ApkSpy] response(): bad response from the script: " + error), Verdict::Continue;
        raw = rebuilt;
        return ++changes_, Verdict::Modified;
    }
    return Verdict::Continue;
}

TrafficProxy::Hooks::Verdict Host::onWebSocket(const TrafficProxy::Flow& flow, bool fromClient, int opcode, std::string& payload) {
    if (!running_.load() || !wantsWs_.load()) return Verdict::Continue;
    const uint64_t id = ++calls_;
    Json f = flowJson(flow);
    f.set("request", messageJsonImpl(httpclient::rawMessage(flow.request), false));
    const Json msg = Json::obj({{"id", static_cast<unsigned long long>(id)},
                                {"hook", "websocket_message"},
                                {"flow", f},
                                {"message", Json::obj({{"from_client", fromClient},
                                                       {"opcode", opcode},
                                                       {"content_b64", codec::base64Encode(payload)}})}});
    Json a;
    if (!call(msg, id, a)) return Verdict::Continue;
    const std::string verdict = a.get("verdict").asString("continue");
    if (verdict == "kill") return ++changes_, Verdict::Kill;
    if (verdict == "modified") {
        std::string content;
        if (!codec::base64Decode(a.get("content_b64").asString(""), content)) return Verdict::Continue;
        payload = content;
        return ++changes_, Verdict::Modified;
    }
    return Verdict::Continue;
}

void Host::onError(const TrafficProxy::Flow& flow) {
    if (!running_.load() || !wantsErrors_.load()) return;
    const uint64_t id = ++calls_;
    Json f = flowJson(flow);
    f.set("request", messageJsonImpl(httpclient::rawMessage(flow.request), false));
    f.set("error", flow.error.empty() ? flow.tlsError : flow.error);
    Json a;
    call(Json::obj({{"id", static_cast<unsigned long long>(id)}, {"hook", "error"}, {"flow", f}}), id, a);
}

}  // namespace trafficscript
