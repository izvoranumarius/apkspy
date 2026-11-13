#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/Process.hpp"
#include "debug/Adb.hpp"
#include "debug/Jdwp.hpp"
#include "debug/TrafficProxy.hpp"

// A worker thread with a FIFO of jobs. Used so device round-trips (adb
// commands, JDWP replies) never run on the UI thread or inside an MCP
// owner-thread call.
class JobQueue {
public:
    JobQueue() = default;
    ~JobQueue() { stop(); }
    JobQueue(const JobQueue&) = delete;
    JobQueue& operator=(const JobQueue&) = delete;
    void post(std::function<void()> job);
    void stop();  // drops pending jobs, joins the worker
    bool busy() const { return busy_.load(); }

private:
    void loop();
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> jobs_;
    std::thread worker_;
    bool stopping_ = false;
    std::atomic<bool> busy_{false};
};

// Live debugging of one Java process through JDWP.
class DebugSession {
public:
    using Id = JdwpClient::Id;
    enum class State { Detached, Attaching, Running, Suspended, Failed };

    struct ThreadRow {
        Id id = 0;
        std::string name;
        int32_t status = 0;   // JDWP ThreadStatus
        int32_t suspend = 0;  // 1 = suspended
    };
    struct FrameRow {
        Id frameId = 0;
        JdwpClient::Location location;
        std::string method;  // "Lcom/a/B;->m(I)V"
        int line = -1;
    };
    struct Local {
        std::string name;
        std::string type;
        std::string value;
        uint64_t objectId = 0;  // non-zero for objects / arrays that can be expanded (see expand())
    };
    struct Breakpoint {
        int id = 0;
        std::string classDescriptor;  // "Lcom/a/B;"
        std::string method;           // name (all overloads)
        int line = -1;                // -1 = method entry
        bool resolved = false;
        std::vector<int32_t> requests;
        int hits = 0;
        std::string status;
        // Exception breakpoint (method empty): classDescriptor empty = any exception.
        bool exception = false;
        bool caught = true;
        bool uncaught = true;
    };
    struct Snapshot {
        State state = State::Detached;
        std::string serial;
        int pid = 0;
        int localPort = 0;
        std::string vm;
        std::vector<ThreadRow> threads;
        Id currentThread = 0;
        std::vector<FrameRow> frames;
        int selectedFrame = 0;
        std::vector<Local> locals;
        // Fields / elements of expanded objects, by object id (cleared at every stop).
        std::map<uint64_t, std::vector<Local>> children;
        std::string exception;  // "java.lang.Foo thrown at ..." when stopped on an exception
        std::string exceptionType, exceptionAt, exceptionCatch;  // class, throw / catch method refs ("" = uncaught)
        std::vector<Breakpoint> breakpoints;
        std::vector<std::string> events;  // newest last (bounded)
        std::string error;
        uint64_t revision = 0;
    };

    explicit DebugSession(adb::Adb& adb) : adb_(adb) {}
    ~DebugSession();

    // All actions are asynchronous (queued on the session worker).
    void attach(const std::string& serial, int pid);
    void detach();
    void suspend();
    void resume();
    void step(int depth);  // 0 into, 1 over, 2 out
    void refreshThreads();
    void selectThread(Id thread);
    void selectFrame(int index);
    int addBreakpoint(const std::string& classNameOrDescriptor, const std::string& method, int line = -1);
    // Stops when an exception is thrown (class empty = any; subclasses included).
    int addExceptionBreakpoint(const std::string& classNameOrDescriptor, bool caught, bool uncaught);
    // Loads the fields (objects) or first elements (arrays) of an object into Snapshot::children.
    void expand(uint64_t objectId);
    void removeBreakpoint(int id);

    Snapshot snapshot() const;
    State state() const;
    static const char* stateName(State s);
    static const char* threadStatusName(int32_t status);
    // Blocks (max timeoutMs) until queued actions ran - for MCP tools that
    // want to return the post-action state.
    bool waitIdle(int timeoutMs);

private:
    void doAttach(std::string serial, int pid);
    void doDetach(bool keepError);
    void loadThreads();
    void loadFrames(Id thread);
    void loadLocals();
    void loadChildren(uint64_t objectId);
    Local makeLocal(const std::string& name, const std::string& declaredType, const JdwpClient::Value& v);
    void resolveBreakpoint(Breakpoint& bp, Id refType);
    void tryResolveAll();
    void onEvent(const JdwpClient::Event& e);
    void pushEvent(std::string text);
    void bump() { ++snap_.revision; }

    adb::Adb& adb_;
    JdwpClient jdwp_;
    JobQueue jobs_;
    mutable std::mutex mutex_;  // guards snap_ + bookkeeping below
    Snapshot snap_;
    int nextBreakpointId_ = 1;
    std::vector<int32_t> classPrepareRequests_;
    int32_t stepRequest_ = 0;
    Id exceptionObject_ = 0;  // thrown object of the current EXCEPTION stop (worker thread only)
    std::atomic<int> pending_{0};
};

// Device-side tooling around adb: devices, processes, Logcat, monitoring
// and the debugger session. Thread-safe; the UI and MCP read snapshots.
class DeviceService {
public:
    struct LogEntry {
        uint64_t seq = 0;
        std::string time;  // "MM-DD HH:MM:SS.mmm"
        int pid = 0;
        int tid = 0;
        char level = 'I';  // V D I W E F
        std::string tag;
        std::string message;
    };
    struct Sample {
        double t = 0;  // seconds since monitoring started
        double cpuPercent = 0;
        uint64_t rssKb = 0;
        int threads = 0;
    };
    struct LogFilter {
        char minLevel = 'V';
        int pid = 0;           // 0 = any
        std::string tag;       // substring
        std::string text;      // substring in tag or message
    };

    DeviceService();
    ~DeviceService();

    void setAdbPath(const std::string& path);
    std::string adbPath() const;
    adb::Adb& adb() { return adb_; }

    // Device list (refreshed asynchronously).
    void refreshDevices();
    std::vector<adb::Device> devices() const;
    std::string lastError() const;
    void select(const std::string& serial);
    std::string selected() const;

    // Processes of the selected device (async refresh).
    void refreshProcesses();
    std::vector<adb::ProcessInfo> processes() const;
    std::vector<int> debuggablePids() const;
    bool refreshing() const { return jobs_.busy(); }

    // Logcat streaming (bounded ring buffer).
    bool startLogcat(const std::string& serial, std::string& error);
    void stopLogcat();
    bool logcatRunning() const { return logcatRunning_.load(); }
    const std::string& logcatSerial() const { return logcatSerial_; }  // device of the last start
    void clearLog();
    // UI hand-off: the Devices panel asks the Logcat panel to filter a pid.
    void requestLogFilter(int pid) { logFilterRequest_ = pid; }
    int takeLogFilterRequest() { return logFilterRequest_.exchange(0); }
    uint64_t logHead() const;  // seq of the newest entry
    // Entries with seq > since, filtered, at most maxEntries (newest kept).
    std::vector<LogEntry> logEntries(uint64_t since, const LogFilter& filter, size_t maxEntries) const;
    size_t logCapacity() const { return kLogCapacity; }

    // CPU / memory / thread-count sampling of one process (1 s period).
    void startMonitor(const std::string& serial, int pid);
    void stopMonitor();
    bool monitoring() const { return monitorRunning_.load(); }
    int monitoredPid() const { return monitorPid_.load(); }
    std::vector<Sample> samples() const;

    DebugSession& debugger() { return debugger_; }
    // Network traffic sniffer (proxy the device is routed through).
    TrafficProxy& traffic() { return traffic_; }
    // Stops the proxy and restores the routed device's proxy setting.
    void stopTraffic();

    static LogEntry parseLogLine(const std::string& line);  // threadtime format; exposed for tests

private:
    static constexpr size_t kLogCapacity = 50000;
    static constexpr size_t kSampleCapacity = 600;

    mutable std::mutex mutex_;
    adb::Adb adb_;
    std::vector<adb::Device> devices_;
    std::vector<adb::ProcessInfo> processes_;
    std::vector<int> jdwpPids_;
    std::string selected_;
    std::string error_;
    JobQueue jobs_;

    // Logcat
    mutable std::mutex logMutex_;
    std::deque<LogEntry> log_;
    uint64_t logSeq_ = 0;
    std::thread logThread_;
    std::atomic<bool> logcatRunning_{false};
    std::string logcatSerial_;
    std::atomic<bool> logStop_{false};
    std::atomic<int> logFilterRequest_{0};
    std::mutex logHandleMutex_;
    ChildProcess::Handle logKill_{};  // valid while the logcat child runs

    // Monitor
    mutable std::mutex sampleMutex_;
    std::deque<Sample> samples_;
    std::thread monitorThread_;
    std::atomic<bool> monitorRunning_{false};
    std::atomic<bool> monitorStop_{false};
    std::atomic<int> monitorPid_{0};
    std::mutex monitorWaitMutex_;
    std::condition_variable monitorWait_;

    DebugSession debugger_;
    TrafficProxy traffic_;
};
