#include "core/Process.hpp"
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>
#include "core/TextUtils.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace {

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

void trimEol(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
}

}  // namespace

ChildProcess ChildProcess::spawn(const std::vector<std::string>& argv) {
    ChildProcess proc;
    if (argv.empty() || argv[0].empty()) return proc;
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
        // .bat/.cmd can only be executed through cmd.exe; wrap the command
        // in an extra quote pair for cmd's parser.
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

    // stdin is the null device: a child waiting for input must never hang
    // on a pipe nobody writes to.
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0,
                             nullptr);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;
    si.hStdInput = nul != INVALID_HANDLE_VALUE ? nul : nullptr;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(0);
    // Created suspended so it is inside the job before it can spawn children.
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                             nullptr, nullptr, &si, &pi);
    CloseHandle(writeEnd);  // the child holds its own copy now
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) {
        CloseHandle(readEnd);
        return proc;
    }
    // Put the child into a job object so cancellation takes down the whole
    // tree (jadx.bat runs cmd.exe -> java), and so closing the job (our
    // destructor, or a crash of ApkSpy) never leaves orphans behind.
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits);
        AssignProcessToJobObject(job, pi.hProcess);
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
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
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
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
    int rc = posix_spawnp(&pid, cargv[0], &actions, &attr, cargv.data(), environ);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        return proc;
    }
    proc.readPipe_ = fds[0];
    proc.pid_ = pid;
    proc.pgid_ = pid;
    proc.valid_ = true;
#endif
    return proc;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        destroy();
        steal(std::move(other));
    }
    return *this;
}

ChildProcess::Handle ChildProcess::killHandle() const {
#ifdef _WIN32
    return job_ ? job_ : process_;
#else
    return pgid_;
#endif
}

void ChildProcess::readAll(const std::function<void(std::string)>& onLine, size_t maxLine) {
    if (!valid_) return;
    std::string pending;
    char buffer[4096];
    bool afterCR = false;  // a '\n' right after a '\r' (CRLF) ends no extra line
    for (;;) {
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile((HANDLE)readPipe_, buffer, sizeof buffer, &got, nullptr) || got == 0) break;
#else
        ssize_t got = read(readPipe_, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
#endif
        pending.append(buffer, (size_t)got);
        size_t start = 0;
        // '\r' ends a line as well: progress output (jadx, adb) redraws one
        // line with carriage returns and would otherwise become one runaway
        // line truncated at maxLine.
        for (size_t nl = pending.find_first_of("\r\n", start); nl != std::string::npos;
             nl = pending.find_first_of("\r\n", start)) {
            const bool cr = pending[nl] == '\r';
            if (afterCR && nl == start && !cr) {  // the '\n' of a CRLF
                afterCR = false;
                start = nl + 1;
                continue;
            }
            afterCR = cr;
            std::string line = pending.substr(start, nl - start);
            while (!line.empty() && line.back() == ' ') line.pop_back();  // progress padding
            if (line.size() > maxLine) line.resize(maxLine), line += " [...]";
            if (!line.empty() || !cr) onLine(std::move(line));
            start = nl + 1;
        }
        pending.erase(0, start);
        if (pending.size() > maxLine) {  // runaway line without newlines
            trimEol(pending);
            pending.resize(maxLine);
            pending += " [...]";
            onLine(std::move(pending));
            pending.clear();
        }
    }
    if (!pending.empty()) {
        trimEol(pending);
        if (pending.size() > maxLine) pending.resize(maxLine), pending += " [...]";
        onLine(std::move(pending));
    }
}

bool ChildProcess::readRaw(std::string& out, size_t maxBytes) {
    if (!valid_) return true;
    bool complete = true;
    char buffer[8192];
    for (;;) {
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile((HANDLE)readPipe_, buffer, sizeof buffer, &got, nullptr) || got == 0) break;
#else
        ssize_t got = read(readPipe_, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
#endif
        const size_t room = out.size() < maxBytes ? maxBytes - out.size() : 0;
        const size_t take = std::min<size_t>(room, (size_t)got);
        out.append(buffer, take);
        if (take < (size_t)got) complete = false;  // keep draining so the child never blocks
    }
    return complete;
}

int ChildProcess::waitForExit() {
    if (!valid_) return -1;
#ifdef _WIN32
    WaitForSingleObject((HANDLE)process_, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess((HANDLE)process_, &code);
    return (int)code;
#else
    int status = 0;
    while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    pid_ = -1;  // reaped
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
}

void ChildProcess::killProcess() {
    if (!valid_) return;
#ifdef _WIN32
    if (job_) TerminateJobObject((HANDLE)job_, 1);
    if (process_) TerminateProcess((HANDLE)process_, 1);
#else
    if (pgid_ > 0) ::kill(-pgid_, SIGTERM);
#endif
}

void ChildProcess::killByHandle(Handle h) {
#ifdef _WIN32
    if (!h) return;
    // Either a job object or a process handle: try both kinds.
    if (!TerminateJobObject((HANDLE)h, 1)) TerminateProcess((HANDLE)h, 1);
#else
    if (h > 0) ::kill(-h, SIGTERM);
#endif
}

void ChildProcess::steal(ChildProcess&& other) {
#ifdef _WIN32
    readPipe_ = std::exchange(other.readPipe_, nullptr);
    process_ = std::exchange(other.process_, nullptr);
    job_ = std::exchange(other.job_, nullptr);
#else
    readPipe_ = std::exchange(other.readPipe_, -1);
    pid_ = std::exchange(other.pid_, -1);
    pgid_ = std::exchange(other.pgid_, -1);
#endif
    valid_ = std::exchange(other.valid_, false);
}

void ChildProcess::destroy() {
    if (!valid_) return;
#ifdef _WIN32
    if (readPipe_) CloseHandle((HANDLE)readPipe_);
    if (process_) CloseHandle((HANDLE)process_);
    if (job_) CloseHandle((HANDLE)job_);  // KILL_ON_JOB_CLOSE ends any leftovers
    readPipe_ = nullptr;
    process_ = nullptr;
    job_ = nullptr;
#else
    if (readPipe_ >= 0) close(readPipe_);
    if (pid_ > 0) {
        // Never leave a zombie behind: a still-running child is terminated
        // and reaped (callers that care wait for it themselves first).
        ::kill(-pgid_, SIGTERM);
        int status = 0;
        while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    }
    readPipe_ = -1;
    pid_ = -1;
    pgid_ = -1;
#endif
    valid_ = false;
}

namespace proc {

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

RunResult run(const std::vector<std::string>& argv, int timeoutMs, size_t maxBytes,
              const std::atomic<bool>* cancel) {
    RunResult result;
    ChildProcess child = ChildProcess::spawn(argv);
    if (!child.valid()) return result;
    result.started = true;

    // Watchdog: kills the process tree on timeout / cancellation. Reading
    // happens on this thread, so the kill is what unblocks it.
    std::mutex m;
    std::condition_variable cv;
    bool finished = false;
    std::atomic<bool> timedOut{false}, cancelled{false};
    const ChildProcess::Handle killHandle = child.killHandle();
    std::thread watchdog([&] {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        std::unique_lock<std::mutex> lock(m);
        while (!finished) {
            if (cancel && cancel->load()) {
                cancelled = true;
                ChildProcess::killByHandle(killHandle);
                return;
            }
            if (timeoutMs > 0 && std::chrono::steady_clock::now() >= deadline) {
                timedOut = true;
                ChildProcess::killByHandle(killHandle);
                return;
            }
            cv.wait_for(lock, std::chrono::milliseconds(50));
        }
    });
    result.truncated = !child.readRaw(result.output, maxBytes);
    result.exitCode = child.waitForExit();
    {
        std::lock_guard<std::mutex> lock(m);
        finished = true;
    }
    cv.notify_all();
    watchdog.join();
    result.timedOut = timedOut.load();
    result.cancelled = cancelled.load();
    return result;
}

}  // namespace proc
