#include "core/JadxRunner.hpp"
#include <cstdio>
#include <filesystem>
#include <cctype>

#ifdef _WIN32
#define APKSPY_POPEN _popen
#define APKSPY_PCLOSE _pclose
#else
#define APKSPY_POPEN popen
#define APKSPY_PCLOSE pclose
#endif

namespace {
std::string quote(const std::string& s) { return "\"" + s + "\""; }

std::string lowerCopy(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Heuristic classification of a jadx log line (jadx prints "WARN - ...",
// "ERROR - ...", "INFO - processing class ..." etc.).
enum class LineKind { Info, Warn, Error, Processing };
LineKind classify(const std::string& raw) {
    std::string line = lowerCopy(raw);
    if (line.find("error") != std::string::npos) return LineKind::Error;
    if (line.find("warn") != std::string::npos) return LineKind::Warn;
    if (line.find("processing") != std::string::npos) return LineKind::Processing;
    return LineKind::Info;
}
}  // namespace

JadxRunner::~JadxRunner() {
    if (worker_.joinable()) worker_.join();
    if (testWorker_.joinable()) testWorker_.join();
}

bool JadxRunner::start(const std::string& jadxPath, const std::string& apkPath, const std::string& outDir,
                       const std::string& extraArgs) {
    if (state_ == State::Running) return false;
    if (worker_.joinable()) worker_.join();
    outDir_ = outDir;
    warnings_ = 0;
    errors_ = 0;
    processed_ = 0;
    std::string cmd = quote(jadxPath);
    if (!extraArgs.empty()) cmd += " " + extraArgs;
    cmd += " -d " + quote(outDir) + " " + quote(apkPath) + " 2>&1";
#ifdef _WIN32
    cmd = "\"" + cmd + "\"";
#endif
    started_ = std::chrono::steady_clock::now();
    state_ = State::Running;
    worker_ = std::thread(&JadxRunner::run, this, std::move(cmd));
    return true;
}

int JadxRunner::elapsedSeconds() const {
    if (state_.load() != State::Running) return 0;
    return (int)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_).count();
}

std::vector<std::string> JadxRunner::drainLog() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.swap(pending_);
    return out;
}

void JadxRunner::testInstall(const std::string& jadxPath) {
    if (testWorker_.joinable()) testWorker_.join();
    {
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_.clear();
    }
    testRunning_ = true;
    std::string cmd = quote(jadxPath) + " --version 2>&1";
#ifdef _WIN32
    cmd = "\"" + cmd + "\"";
#endif
    testWorker_ = std::thread([this, cmd] {
        FILE* pipe = APKSPY_POPEN(cmd.c_str(), "r");
        std::string result;
        bool ok = false;
        if (pipe) {
            char buffer[512];
            while (result.empty() && std::fgets(buffer, sizeof buffer, pipe)) {
                std::string line(buffer);
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
                if (!line.empty()) result = line;
            }
            int code = APKSPY_PCLOSE(pipe);
            ok = (code == 0) && !result.empty();
        }
        if (result.empty()) result = ok ? "jadx is installed" : "jadx could not be executed";
        std::lock_guard<std::mutex> lock(testMutex_);
        testResult_ = result;
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

void JadxRunner::countLine(const std::string& line) {
    switch (classify(line)) {
    case LineKind::Warn: warnings_++; break;
    case LineKind::Error: errors_++; break;
    case LineKind::Processing: processed_++; break;
    default: break;
    }
}

void JadxRunner::run(std::string command) {
    FILE* pipe = APKSPY_POPEN(command.c_str(), "r");
    if (!pipe) {
        state_ = State::Failed;
        return;
    }
    char buffer[4096];
    while (std::fgets(buffer, sizeof buffer, pipe)) {
        std::string line(buffer);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        countLine(line);
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.push_back(std::move(line));
    }
    APKSPY_PCLOSE(pipe);
    bool ok = std::filesystem::exists(std::filesystem::path(outDir_) / "sources");
    state_ = ok ? State::Done : State::Failed;
}
