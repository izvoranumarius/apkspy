#include "core/Pty.hpp"
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// ConPTY entry points are looked up at run time so the app still starts on
// Windows versions without them (the terminal then reports it).
using CreatePseudoConsoleFn = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, void**);
using ResizePseudoConsoleFn = HRESULT(WINAPI*)(void*, COORD);
using ClosePseudoConsoleFn = void(WINAPI*)(void*);

struct Pty::Impl {
    void* console = nullptr;
    HANDLE inWrite = nullptr;   // our end: keyboard -> shell
    HANDLE outRead = nullptr;   // our end: shell -> screen
    HANDLE process = nullptr;
    HANDLE job = nullptr;
    CreatePseudoConsoleFn create = nullptr;
    ResizePseudoConsoleFn resize = nullptr;
    ClosePseudoConsoleFn close = nullptr;
};

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

// One command line, quoted the way CommandLineToArgvW parses it.
std::wstring commandLine(const std::vector<std::string>& argv) {
    std::wstring out;
    for (const std::string& a : argv) {
        if (!out.empty()) out += L' ';
        const std::wstring w = widen(a);
        if (!w.empty() && w.find_first_of(L" \t\"") == std::wstring::npos) {
            out += w;
            continue;
        }
        out += L'"';
        size_t slashes = 0;
        for (wchar_t c : w) {
            if (c == L'\\') {
                ++slashes;
                continue;
            }
            if (c == L'"') out.append(slashes * 2 + 1, L'\\');
            else out.append(slashes, L'\\');
            slashes = 0;
            out += c;
        }
        out.append(slashes * 2, L'\\');
        out += L'"';
    }
    return out;
}

}  // namespace

Pty::Pty() : impl_(std::make_unique<Impl>()) {}

Pty::~Pty() { stop(); }

bool Pty::start(const std::vector<std::string>& argv, const std::string& cwd, const std::vector<std::string>& extraPath,
                int cols, int rows, std::string& error) {
    Impl& d = *impl_;
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    d.create = (CreatePseudoConsoleFn)(void*)GetProcAddress(kernel, "CreatePseudoConsole");
    d.resize = (ResizePseudoConsoleFn)(void*)GetProcAddress(kernel, "ResizePseudoConsole");
    d.close = (ClosePseudoConsoleFn)(void*)GetProcAddress(kernel, "ClosePseudoConsole");
    if (!d.create || !d.resize || !d.close) {
        error = "The terminal needs Windows 10 version 1809 or later (ConPTY)";
        return false;
    }
    HANDLE inRead = nullptr, outWrite = nullptr;
    if (!CreatePipe(&inRead, &d.inWrite, nullptr, 0) || !CreatePipe(&d.outRead, &outWrite, nullptr, 0)) {
        error = "Could not create the terminal pipes";
        return false;
    }
    const COORD size{(SHORT)std::max(1, cols), (SHORT)std::max(1, rows)};
    if (FAILED(d.create(size, inRead, outWrite, 0, &d.console))) {
        CloseHandle(inRead);
        CloseHandle(outWrite);
        error = "Could not create the pseudo-console";
        return false;
    }
    // The pseudo-console owns its ends of the pipes now.
    CloseHandle(inRead);
    CloseHandle(outWrite);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<char> attrBuf(attrSize);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, d.console, sizeof(d.console), nullptr, nullptr);

    // Environment: ours, with the tool folders first on PATH.
    std::wstring env;
    {
        wchar_t* block = GetEnvironmentStringsW();
        std::wstring prefix;
        for (const std::string& dir : extraPath)
            if (!dir.empty()) prefix += widen(dir) + L";";
        for (const wchar_t* p = block; *p; p += wcslen(p) + 1) {
            std::wstring entry = p;
            if (!prefix.empty() && _wcsnicmp(entry.c_str(), L"PATH=", 5) == 0) entry = entry.substr(0, 5) + prefix + entry.substr(5);
            env += entry;
            env += L'\0';
        }
        env += L'\0';
        FreeEnvironmentStringsW(block);
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi{};
    std::wstring cmd = commandLine(argv);
    const std::wstring dir = widen(cwd);
    const BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                                   EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, env.data(),
                                   dir.empty() ? nullptr : dir.c_str(), &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    if (!ok) {
        error = "Could not start " + (argv.empty() ? std::string("the shell") : argv[0]);
        d.close(d.console);
        d.console = nullptr;
        return false;
    }
    // A job object ends the whole tree (shell and what it started) with us.
    d.job = CreateJobObjectW(nullptr, nullptr);
    if (d.job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(d.job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
        AssignProcessToJobObject(d.job, pi.hProcess);
    }
    CloseHandle(pi.hThread);
    d.process = pi.hProcess;
    running_ = true;
    reader_ = std::thread([this] {
        char buf[8192];
        DWORD n = 0;
        while (ReadFile(impl_->outRead, buf, sizeof buf, &n, nullptr) && n > 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_.append(buf, n);
            if (pending_.size() > (8u << 20)) pending_.erase(0, pending_.size() - (4u << 20));
        }
        DWORD code = 0;
        if (impl_->process && GetExitCodeProcess(impl_->process, &code)) exitCode_ = (int)code;
        running_ = false;
    });
    return true;
}

// The pipe stays open after the shell exits (the console holds it), so the
// process itself says whether the shell still runs.
bool Pty::running() const {
    if (!running_.load() || !impl_->process) return false;
    if (WaitForSingleObject(impl_->process, 0) != WAIT_OBJECT_0) return true;
    DWORD code = 0;
    if (GetExitCodeProcess(impl_->process, &code)) const_cast<Pty*>(this)->exitCode_ = (int)code;
    return false;
}

void Pty::write(const std::string& bytes) {
    if (!impl_->inWrite || bytes.empty()) return;
    DWORD written = 0;
    WriteFile(impl_->inWrite, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
}

void Pty::resize(int cols, int rows) {
    if (impl_->console && impl_->resize) impl_->resize(impl_->console, COORD{(SHORT)std::max(1, cols), (SHORT)std::max(1, rows)});
}

void Pty::stop() {
    Impl& d = *impl_;
    if (d.job) {
        TerminateJobObject(d.job, 1);
        CloseHandle(d.job);
        d.job = nullptr;
    } else if (d.process) {
        TerminateProcess(d.process, 1);
    }
    // Closing the console ends the reader (it may print a last bit first).
    if (d.console) {
        d.close(d.console);
        d.console = nullptr;
    }
    if (d.inWrite) {
        CloseHandle(d.inWrite);
        d.inWrite = nullptr;
    }
    if (reader_.joinable()) reader_.join();
    if (d.outRead) {
        CloseHandle(d.outRead);
        d.outRead = nullptr;
    }
    if (d.process) {
        WaitForSingleObject(d.process, 2000);
        CloseHandle(d.process);
        d.process = nullptr;
    }
    running_ = false;
}

#else  // POSIX: forkpty

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif

struct Pty::Impl {
    int fd = -1;
    pid_t pid = -1;
};

Pty::Pty() : impl_(std::make_unique<Impl>()) {}
Pty::~Pty() { stop(); }

bool Pty::start(const std::vector<std::string>& argv, const std::string& cwd, const std::vector<std::string>& extraPath,
                int cols, int rows, std::string& error) {
    if (argv.empty()) {
        error = "No shell given";
        return false;
    }
    struct winsize ws{};
    ws.ws_col = (unsigned short)std::max(1, cols);
    ws.ws_row = (unsigned short)std::max(1, rows);
    int fd = -1;
    const pid_t pid = forkpty(&fd, nullptr, nullptr, &ws);
    if (pid < 0) {
        error = "Could not create a pseudo-terminal";
        return false;
    }
    if (pid == 0) {  // child
        if (!cwd.empty() && chdir(cwd.c_str()) != 0) {}
        std::string path;
        for (const std::string& d : extraPath)
            if (!d.empty()) path += d + ":";
        if (const char* old = std::getenv("PATH")) path += old;
        setenv("PATH", path.c_str(), 1);
        setenv("TERM", "xterm-256color", 1);
        std::vector<char*> args;
        for (const std::string& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        execvp(args[0], args.data());
        _exit(127);
    }
    impl_->fd = fd;
    impl_->pid = pid;
    running_ = true;
    reader_ = std::thread([this] {
        char buf[8192];
        for (;;) {
            const ssize_t n = read(impl_->fd, buf, sizeof buf);
            if (n <= 0) break;
            std::lock_guard<std::mutex> lock(mutex_);
            pending_.append(buf, (size_t)n);
            if (pending_.size() > (8u << 20)) pending_.erase(0, pending_.size() - (4u << 20));
        }
        int status = 0;
        if (waitpid(impl_->pid, &status, 0) > 0 && WIFEXITED(status)) exitCode_ = WEXITSTATUS(status);
        running_ = false;
    });
    return true;
}

bool Pty::running() const { return running_.load(); }

void Pty::write(const std::string& bytes) {
    if (impl_->fd < 0) return;
    size_t done = 0;
    while (done < bytes.size()) {
        const ssize_t n = ::write(impl_->fd, bytes.data() + done, bytes.size() - done);
        if (n <= 0) break;
        done += (size_t)n;
    }
}

void Pty::resize(int cols, int rows) {
    if (impl_->fd < 0) return;
    struct winsize ws{};
    ws.ws_col = (unsigned short)std::max(1, cols);
    ws.ws_row = (unsigned short)std::max(1, rows);
    ioctl(impl_->fd, TIOCSWINSZ, &ws);
}

void Pty::stop() {
    if (impl_->pid > 0) kill(-impl_->pid, SIGHUP), kill(impl_->pid, SIGKILL);
    if (impl_->fd >= 0) {
        close(impl_->fd);
        impl_->fd = -1;
    }
    if (reader_.joinable()) reader_.join();
    impl_->pid = -1;
    running_ = false;
}

#endif

std::string Pty::take() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string out;
    out.swap(pending_);
    return out;
}
