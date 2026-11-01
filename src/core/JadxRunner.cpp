#include "core/JadxRunner.hpp"
#include "core/LogSeverity.hpp"
#include "core/TextUtils.hpp"
#include "core/Paths.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace {

constexpr size_t kMaxLineLength = 8192;  // absurdly long single log lines are cut

// Splits a command line on whitespace, honouring double quotes.
std::vector<std::string> splitArgs(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool quoted = false;
    for (char c : s) {
        if (c == '"') {
            quoted = !quoted;
        } else if (!quoted && (c == ' ' || c == '\t')) {
            if (!cur.empty()) out.push_back(std::exchange(cur, std::string()));
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

#ifdef _WIN32

std::wstring toWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), w.data(), n);
    return w;
}

// Quotes one argument following the CommandLineToArgvW rules so paths with
// spaces survive round-tripping through a process command line.
std::wstring quoteArg(const std::wstring& s) {
    if (!s.empty() && s.find_first_of(L" \t\"") == std::wstring::npos) return s;
    std::wstring out(1, L'"');
    size_t backslashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(c);
        }
        backslashes = 0;
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

bool isBatchFile(const std::string& path) {
    std::string low = tex::asciiLower(path);
    return low.size() >= 4 && (low.compare(low.size() - 4, 4, ".bat") == 0 ||
                               low.compare(low.size() - 4, 4, ".cmd") == 0);
}

#endif

// A child process with its stdout+stderr merged into one pipe. No shell is
// involved anywhere: the argv array is passed straight to the OS.
class ChildProcess {
public:
#ifdef _WIN32
    using Handle = void*;  // HANDLE
#else
    using Handle = int;    // pid
#endif

    // argv[0] is the executable (resolved via PATH on POSIX). Returns an
    // invalid handle when the process could not be started.
    static ChildProcess spawn(const std::vector<std::string>& argv) {
        ChildProcess proc;
#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        HANDLE readEnd = nullptr, writeEnd = nullptr;
        if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) return proc;
        // The parent's read end must not leak into the child.
        SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

        std::wstring cmdline;
        if (isBatchFile(argv[0])) {
            // .bat/.cmd can only be executed through cmd.exe; wrap the
            // command in an extra quote pair for cmd's parser.
            wchar_t comspecBuf[MAX_PATH] = {};
            if (GetEnvironmentVariableW(L"COMSPEC", comspecBuf, MAX_PATH) == 0)
                wcsncpy(comspecBuf, L"cmd.exe", MAX_PATH - 1);
            cmdline = std::wstring(L"\"") + comspecBuf + L"\" /c \"";
            for (size_t i = 0; i < argv.size(); ++i)
                cmdline += (i ? L" " : std::wstring()) + quoteArg(toWide(argv[i]));
            cmdline += L"\"";
        } else {
            for (size_t i = 0; i < argv.size(); ++i)
                cmdline += (i ? L" " : std::wstring()) + quoteArg(toWide(argv[i]));
        }

        STARTUPINFOW si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = writeEnd;
        si.hStdError = writeEnd;
        si.hStdInput = nullptr;
        PROCESS_INFORMATION pi{};
        std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
        buf.push_back(0);
        BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                                 nullptr, &si, &pi);
        CloseHandle(writeEnd);  // the child holds its own copy now
        if (!ok) {
            CloseHandle(readEnd);
            return proc;
        }
        CloseHandle(pi.hThread);
        // Put the child into a job object so cancellation takes down the
        // whole tree (jadx.bat runs cmd.exe -> java).
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits);
            AssignProcessToJobObject(job, pi.hProcess);
        }
        proc.readPipe_ = readEnd;
        proc.process_ = pi.hProcess;
        proc.job_ = job;
        proc.valid_ = true;
#else
        int fds[2];
        if (pipe(fds) != 0) return proc;
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const std::string& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, fds[0]);
        posix_spawn_file_actions_addclose(&actions, fds[1]);
        // Own process group: cancellation signals the group, not just the
        // launcher script (which would orphan its java child).
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        posix_spawnattr_setpgroup(&attr, 0);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
        pid_t pid = 0;
        if (posix_spawn(&pid, cargv[0], &actions, &attr, cargv.data(), environ) != 0) {
            posix_spawnattr_destroy(&attr);
            posix_spawn_file_actions_destroy(&actions);
            close(fds[0]);
            close(fds[1]);
            return proc;
        }
        posix_spawnattr_destroy(&attr);
        posix_spawn_file_actions_destroy(&actions);
        close(fds[1]);
        proc.readPipe_ = fds[0];
        proc.pid_ = pid;
        proc.pgid_ = pid;
        proc.valid_ = true;
#endif
        return proc;
    }

    ChildProcess() = default;
    ChildProcess(ChildProcess&& other) { steal(std::move(other)); }
    ChildProcess& operator=(ChildProcess&& other) {
        if (this != &other) {
            destroy();
            steal(std::move(other));
        }
        return *this;
    }
    ~ChildProcess() { destroy(); }

    bool valid() const { return valid_; }
    // The handle cancellation uses: the Windows job object (kills the whole
    // tree) or the POSIX process group id.
    Handle killHandle() const {
#ifdef _WIN32
        return job_ ? job_ : process_;
#else
        return pgid_;
#endif
    }

    // Reads merged stdout+stderr until end-of-file, calling onLine() per
    // complete line (very long lines are truncated at kMaxLineLength).
    void readAll(const std::function<void(std::string)>& onLine) {
        std::string pending;
        char buffer[4096];
        for (;;) {
#ifdef _WIN32
            DWORD got = 0;
            if (!ReadFile(readPipe_, buffer, sizeof buffer, &got, nullptr) || got == 0) break;
#else
            ssize_t got = read(readPipe_, buffer, sizeof buffer);
            if (got <= 0) break;
#endif
            pending.append(buffer, (size_t)got);
            size_t start = 0;
            for (size_t nl = pending.find('\n', start); nl != std::string::npos; nl = pending.find('\n', start)) {
                std::string line = pending.substr(start, nl - start);
                trimEol(line);
                if (line.size() > kMaxLineLength) line.resize(kMaxLineLength), line += " [...]";
                onLine(std::move(line));
                start = nl + 1;
            }
            pending.erase(0, start);
            if (pending.size() > kMaxLineLength) {  // runaway line without newlines
                trimEol(pending);
                pending += " [...]";
                onLine(std::move(pending));
                pending.clear();
            }
        }
        if (!pending.empty()) {
            trimEol(pending);
            if (pending.size() > kMaxLineLength) pending.resize(kMaxLineLength), pending += " [...]";
            onLine(std::move(pending));
        }
    }

    // Blocks until the process exits and returns its exit code (-1 = killed).
    int waitForExit() {
        if (!valid_) return -1;
#ifdef _WIN32
        WaitForSingleObject(process_, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(process_, &code);
        return (int)code;
#else
        int status = 0;
        while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        return -1;
#endif
    }

    // May be called from any thread while the process runs. Kills the whole
    // process tree (launcher script + java), not just the direct child.
    void killProcess() {
        if (!valid_) return;
#ifdef _WIN32
        if (job_) TerminateJobObject((HANDLE)job_, 1);
        if (process_) TerminateProcess((HANDLE)process_, 1);
#else
        if (pgid_ > 0) ::kill(-pgid_, SIGTERM);
#endif
    }

private:
    static void trimEol(std::string& s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    }
    void steal(ChildProcess&& other) {
        readPipe_ = std::exchange(other.readPipe_,
#ifdef _WIN32
                                  (void*)nullptr);
        process_ = std::exchange(other.process_, (void*)nullptr);
        job_ = std::exchange(other.job_, (void*)nullptr);
#else
                                  -1);
        pid_ = std::exchange(other.pid_, -1);
        pgid_ = std::exchange(other.pgid_, -1);
#endif
        valid_ = std::exchange(other.valid_, false);
    }
    void destroy() {
        if (!valid_) return;
#ifdef _WIN32
        if (readPipe_) CloseHandle((HANDLE)readPipe_);
        if (process_) CloseHandle((HANDLE)process_);
        if (job_) CloseHandle((HANDLE)job_);
        readPipe_ = nullptr;
        process_ = nullptr;
        job_ = nullptr;
#else
        if (readPipe_ >= 0) close(readPipe_);
        readPipe_ = -1;
        pid_ = -1;
        pgid_ = -1;
#endif
        valid_ = false;
    }

#ifdef _WIN32
    void* readPipe_ = nullptr;
    void* process_ = nullptr;
    void* job_ = nullptr;
#else
    int readPipe_ = -1;
    int pid_ = -1;
    pid_t pgid_ = -1;
#endif
    bool valid_ = false;
};

}  // namespace

JadxRunner::~JadxRunner() {
    if (worker_.joinable()) {
        cancel();  // never block the shutdown on a live jadx
        worker_.join();
    }
    if (testWorker_.joinable()) testWorker_.join();
}

bool JadxRunner::start(const std::string& jadxPath, const std::string& apkPath, const std::string& outDir,
                       const std::string& extraArgs) {
    if (state_ == State::Running) return false;
    if (worker_.joinable()) worker_.join();
    if (jadxPath.empty() || apkPath.empty() || outDir.empty()) return false;

    outDir_ = outDir;
    warnings_ = 0;
    errors_ = 0;
    processed_ = 0;
    exitCode_ = 0;
    cancelRequested_ = false;

    std::vector<std::string> argv;
    argv.push_back(jadxPath);
    for (std::string& a : splitArgs(extraArgs)) argv.push_back(std::move(a));
    argv.push_back("-d");
    argv.push_back(outDir);
    argv.push_back(apkPath);

    started_ = std::chrono::steady_clock::now();
    state_ = State::Running;
    worker_ = std::thread(&JadxRunner::runDecompile, this, std::move(argv));
    return true;
}

bool JadxRunner::cancel() {
    if (state_.load() != State::Running) return false;
    cancelRequested_ = true;
    std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
    if (childProcess_) TerminateJobObject((HANDLE)childProcess_, 1);
#else
    if (childPid_ > 0) ::kill(-childPid_, SIGTERM);  // the whole process group
#endif
    return true;
}

int JadxRunner::elapsedSeconds() const {
    if (state_.load() != State::Running) return 0;
    return (int)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_)
        .count();
}

std::vector<std::string> JadxRunner::drainLog() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.swap(pending_);
    return out;
}

void JadxRunner::pushLine(std::string line) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.push_back(std::move(line));
}

void JadxRunner::countLine(const std::string& line) {
    switch (logsev::classify(line)) {
    case LogSeverity::Warn: warnings_++; break;
    case LogSeverity::Error: errors_++; break;
    default: break;
    }
    if (tex::ciFind(line, "processing") != std::string_view::npos) processed_++;
}

void JadxRunner::runDecompile(std::vector<std::string> argv) {
    ChildProcess proc = ChildProcess::spawn(argv);
    if (!proc.valid()) {
        state_ = State::Failed;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
        childProcess_ = proc.killHandle();  // job object: kills the tree
#else
        childPid_ = proc.killHandle();      // process group id
#endif
    }
    proc.readAll([this](std::string line) {
        countLine(line);
        pushLine(std::move(line));
    });
    int code = proc.waitForExit();
    {
        std::lock_guard<std::mutex> lock(handleMutex_);
#ifdef _WIN32
        childProcess_ = nullptr;
#else
        childPid_ = -1;
#endif
    }
    exitCode_ = code;
    if (code != 0 && cancelRequested_.load()) {
        state_ = State::Cancelled;
        return;
    }
    std::error_code ec;
    bool hasSources = std::filesystem::is_directory(
        std::filesystem::path(pathutil::fromUtf8(outDir_)) / "sources", ec);
    state_ = (code == 0 && hasSources) ? State::Done : State::Failed;
}

void JadxRunner::testInstall(const std::string& jadxPath) {
    if (testRunning_.load()) return;  // never join a live test on the UI thread
    if (testWorker_.joinable()) testWorker_.join();
    {
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_.clear();
    }
    testRunning_ = true;
    testWorker_ = std::thread([this, jadxPath] {
        ChildProcess proc = ChildProcess::spawn({jadxPath, "--version"});
        std::string first;
        int code = -1;
        if (proc.valid()) {
            proc.readAll([&first](std::string line) {
                if (first.empty() && !line.empty()) first = std::move(line);
            });
            code = proc.waitForExit();
        }
        bool ok = code == 0 && !first.empty();
        std::string result = first;
        if (result.empty()) result = ok ? "jadx is installed" : "jadx could not be executed";
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_ = std::move(result);
        testOk_ = ok;
        testRunning_ = false;
    });
}

std::string JadxRunner::takeTestResult(bool& ok) {
    std::lock_guard<std::mutex> lock(testMutex_);
    if (testResult_.empty()) return {};
    std::string out = testResult_;
    ok = testOk_.load();
    return out;
}
