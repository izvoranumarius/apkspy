#include "core/ScriptRunner.hpp"
#include <filesystem>
#include <fstream>
#include <utility>
#include "core/Paths.hpp"

namespace fs = std::filesystem;

ScriptRunner::~ScriptRunner() {
    stop();
    join();
}

void ScriptRunner::join() {
    if (worker_.joinable()) worker_.join();
}

bool ScriptRunner::start(const std::vector<std::string>& argv, std::string& error) {
    if (running_.load()) {
        error = "a script is already running";
        return false;
    }
    join();
    ChildProcess child = ChildProcess::spawn(argv);
    if (!child.valid()) {
        error = "could not start " + (argv.empty() ? std::string("the interpreter") : argv[0]);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        kill_ = child.killHandle();
        killable_ = true;
        dropped_ = 0;
    }
    exitCode_ = 0;
    running_ = true;
    worker_ = std::thread([this, child = std::move(child)]() mutable {
        child.readAll([this](std::string line) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (output_.size() >= kMaxQueuedLines) {
                output_.pop_front();
                ++dropped_;
            }
            output_.push_back(std::move(line));
        });
        const int code = child.waitForExit();
        {
            // After this nobody uses the handle: the process object may go away.
            std::lock_guard<std::mutex> lock(mutex_);
            killable_ = false;
        }
        exitCode_ = code;
        running_ = false;
    });
    return true;
}

void ScriptRunner::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (killable_) ChildProcess::killByHandle(kill_);
}

std::vector<std::string> ScriptRunner::takeOutput() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> lines;
    if (dropped_) {
        lines.push_back("... " + std::to_string(dropped_) + " lines dropped ...");
        dropped_ = 0;
    }
    lines.insert(lines.end(), std::make_move_iterator(output_.begin()), std::make_move_iterator(output_.end()));
    output_.clear();
    return lines;
}

namespace scripting {
namespace {

const char* const kApkSpyModule = R"PY("""ApkSpy scripting API.

Every MCP tool of the running ApkSpy is a function of this module:

    import apkspy
    print(apkspy.apk_info()["package"])
    for c in apkspy.list_classes(filter="login")["classes"]:
        print(c)

Arguments are the tool's arguments; a trailing underscore is dropped, so a
Python keyword can be passed (get_class(class_="com.example.Foo")). Results are
the tool's structured data. apkspy.tools() lists every tool, and a failing
tool raises ApkSpyError.
"""
import itertools
import json
import os
import urllib.request

__all__ = ["call", "tools", "ApkSpyError"]

_ids = itertools.count(1)
_session = None


class ApkSpyError(RuntimeError):
    """A tool failed, or ApkSpy could not be reached."""


def _rpc(method, params):
    global _session
    if _session is None:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "session.json"), encoding="utf-8") as f:
            _session = json.load(f)
    request = urllib.request.Request(
        _session["url"],
        data=json.dumps({"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + _session["token"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=3600) as response:
            reply = json.loads(response.read().decode("utf-8"))
    except OSError as e:
        raise ApkSpyError("cannot reach ApkSpy: %s" % e) from None
    if "error" in reply:
        raise ApkSpyError(reply["error"].get("message", "request failed"))
    return reply["result"]


def call(tool, **arguments):
    """Calls an MCP tool by name and returns its structured result."""
    arguments = {k.rstrip("_"): v for k, v in arguments.items()}
    result = _rpc("tools/call", {"name": tool, "arguments": arguments})
    text = "".join(c.get("text", "") for c in result.get("content", []))
    if result.get("isError"):
        raise ApkSpyError(text or "%s failed" % tool)
    structured = result.get("structuredContent")
    return structured if structured is not None else text


def tools():
    """Every tool name with its description."""
    return {t["name"]: t.get("description", "") for t in _rpc("tools/list", {})["tools"]}


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)

    def tool(**arguments):
        return call(name, **arguments)

    tool.__name__ = name
    return tool
)PY";

const char* const kRunner = R"PY(import os
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
script = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
runpy.run_path(script, run_name="__main__")
)PY";

const char* const kExample = R"PY("""Summary of the open APKs. Press Run (F5).

Every ApkSpy tool is available as apkspy.<tool>(...): see apkspy.tools().
"""
import apkspy

for entry in apkspy.list_apks()["apks"]:
    name = entry["apk"]
    info = apkspy.apk_info(apk=name)
    print(name, "-", info.get("package"), "version", info.get("version_name"))

    permissions = info.get("permissions", [])
    print(" ", len(permissions), "permissions")

    libraries = apkspy.list_native_libs(apk=name)["libraries"]
    print(" ", len(libraries), "native libraries")
    for library in libraries:
        if "arm64" not in library["path"]:
            continue
        functions = apkspy.native_functions(apk=name, path=library["path"], exported_only=True, limit=1)
        print("   ", library["path"], "-", functions["total_functions"], "functions")

print()
print(len(apkspy.tools()), "tools available")
)PY";

bool writeFile(const fs::path& path, const std::string& text, std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
    out.flush();
    if (out) return true;
    error = "cannot write " + pathutil::toUtf8(path);
    return false;
}

std::string jsonString(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out + "\"";
}

}  // namespace

bool writeSupport(const std::string& dir, const std::string& url, const std::string& token, std::string& error) {
    const fs::path base = pathutil::fromUtf8(dir);
    std::error_code ec;
    fs::create_directories(base, ec);
    if (ec) {
        error = "cannot create " + dir;
        return false;
    }
    return writeFile(base / "apkspy.py", kApkSpyModule, error) && writeFile(base / "run_script.py", kRunner, error) &&
           writeFile(base / "session.json", "{\"url\": " + jsonString(url) + ", \"token\": " + jsonString(token) + "}\n", error);
}

std::vector<std::string> command(const std::string& python, const std::string& dir, const std::string& script) {
    return {python, "-u", pathutil::toUtf8(pathutil::fromUtf8(dir) / "run_script.py"), script};
}

const char* exampleScript() { return kExample; }

}  // namespace scripting
