#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// A child process with its stdout+stderr merged into one pipe. No shell is
// involved anywhere: the argv array is passed straight to the OS
// (CreateProcessW on Windows, posix_spawn elsewhere), so arguments can never
// inject commands. Shared by the jadx runner and the adb/debugger tooling.
//
// Ownership: a ChildProcess owns its pipe, process and (on Windows) job
// handles; they are closed by the destructor. The job object is created with
// KILL_ON_JOB_CLOSE, so a destroyed ChildProcess never leaves a running tree
// behind.
class ChildProcess {
public:
#ifdef _WIN32
    using Handle = void*;  // HANDLE
#else
    using Handle = int;    // pid / process group id
#endif

    // argv[0] is the executable (resolved via PATH on POSIX; on Windows a
    // .bat/.cmd is run through cmd.exe). Returns an invalid process when it
    // could not be started.
    static ChildProcess spawn(const std::vector<std::string>& argv);

    ChildProcess() = default;
    ChildProcess(ChildProcess&& other) noexcept { steal(std::move(other)); }
    ChildProcess& operator=(ChildProcess&& other) noexcept;
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ~ChildProcess() { destroy(); }

    bool valid() const { return valid_; }
    // The handle cancellation uses: the Windows job object (kills the whole
    // tree) or the POSIX process group id.
    Handle killHandle() const;

    // Reads merged stdout+stderr until end-of-file, calling onLine() per
    // complete line (lines longer than maxLine are truncated).
    void readAll(const std::function<void(std::string)>& onLine, size_t maxLine = kMaxLineLength);
    // Reads raw output until EOF into `out`, keeping at most `maxBytes`
    // (further output is drained and dropped). Returns false when truncated.
    bool readRaw(std::string& out, size_t maxBytes);

    // Blocks until the process exits and returns its exit code (-1 = killed).
    int waitForExit();
    // May be called from any thread while the process runs. Kills the whole
    // process tree (launcher script + children), not just the direct child.
    void killProcess();
    // Kills by a handle previously taken from killHandle() (thread-safe as
    // long as the owning ChildProcess is alive).
    static void killByHandle(Handle h);

    static constexpr size_t kMaxLineLength = 8192;

private:
    void steal(ChildProcess&& other);
    void destroy();

#ifdef _WIN32
    void* readPipe_ = nullptr;
    void* process_ = nullptr;
    void* job_ = nullptr;
#else
    int readPipe_ = -1;
    int pid_ = -1;
    int pgid_ = -1;
#endif
    bool valid_ = false;
};

namespace proc {

// Splits a command line on whitespace, honouring "double quotes".
std::vector<std::string> splitArgs(const std::string& s);

struct RunResult {
    bool started = false;   // the executable could be launched
    bool timedOut = false;  // killed after `timeoutMs`
    bool cancelled = false; // killed because `cancel` became true
    bool truncated = false; // output exceeded `maxBytes`
    int exitCode = -1;
    std::string output;     // merged stdout + stderr
};

// Runs a command to completion and captures its output. The process is
// killed when `timeoutMs` elapses (0 = no timeout) or `cancel` (optional)
// turns true; output beyond `maxBytes` is dropped. Blocking: call it from a
// worker thread for anything that may take a while.
RunResult run(const std::vector<std::string>& argv, int timeoutMs = 15000, size_t maxBytes = 4 << 20,
              const std::atomic<bool>* cancel = nullptr);

}  // namespace proc
