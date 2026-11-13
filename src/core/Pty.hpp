#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// A shell running in a pseudo-terminal: ConPTY on Windows 10 1809 and later,
// forkpty on Linux and macOS. Output is collected on a reader thread and
// taken by the UI with take(); input goes through write().
class Pty {
public:
    Pty();
    ~Pty();
    Pty(const Pty&) = delete;
    Pty& operator=(const Pty&) = delete;

    // `argv` is the shell and its arguments; `cwd` may be empty; `extraPath`
    // directories are put in front of PATH for this shell only.
    bool start(const std::vector<std::string>& argv, const std::string& cwd, const std::vector<std::string>& extraPath,
               int cols, int rows, std::string& error);
    void write(const std::string& bytes);
    void resize(int cols, int rows);
    std::string take();  // output since the last call
    bool running() const;
    int exitCode() const { return exitCode_.load(); }
    void stop();  // ends the shell and its children

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::mutex mutex_;
    std::string pending_;
    std::thread reader_;
    std::atomic<bool> running_{false};
    std::atomic<int> exitCode_{0};
};
