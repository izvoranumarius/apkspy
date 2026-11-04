#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "core/Socket.hpp"

// Client side of the Java Debug Wire Protocol, as spoken by ART for
// debuggable apps (reached through `adb forward tcp:N jdwp:<pid>`).
//
// Threading: a reader thread receives packets; replies are matched to the
// waiting command by packet id, events are handed to the event callback on
// the reader thread. Commands are synchronous (send + wait for the reply
// with a timeout) and may be issued from any one thread - DebugSession uses
// its own worker so neither the UI nor MCP ever blocks on the device.
class JdwpClient {
public:
    using Id = uint64_t;

    struct Location {
        uint8_t typeTag = 0;
        Id classId = 0;
        Id methodId = 0;
        uint64_t index = 0;  // bytecode index (code units)
    };

    struct Event {
        uint8_t kind = 0;     // 1 step, 2 breakpoint, 4 exception, 6/7 thread, 8 class prepare, 90 VM start, 99 VM death
        int32_t requestId = 0;
        Id thread = 0;
        Location location;
        std::string signature;  // class prepare
        Id refType = 0;
        // EXCEPTION events
        Id exception = 0;            // the thrown object
        Location catchLocation;      // classId == 0 when uncaught
    };

    struct MethodInfo {
        Id id = 0;
        std::string name;
        std::string signature;
        int32_t modBits = 0;
    };

    struct FieldInfo {
        Id id = 0;
        std::string name;
        std::string signature;
        int32_t modBits = 0;  // 0x8 = static
    };
    struct Variable {
        uint64_t codeIndex = 0;
        std::string name;
        std::string signature;
        uint32_t length = 0;
        int32_t slot = 0;
    };

    struct Value {
        uint8_t tag = 0;  // JDWP tag: 'I', 'J', 'Z', 'L', 's', '[', ...
        uint64_t raw = 0;
        std::string text;  // rendered (strings are fetched)
        std::string type;  // runtime type signature of objects ("Lcom/x/Foo;", "[I"), when known
        // Object-like values (objects, arrays, threads, class loaders, ...) that can be expanded.
        bool isObject() const { return raw != 0 && (tag == 'L' || tag == '[' || tag == 't' || tag == 'g' || tag == 'l' || tag == 'c'); }
    };

    JdwpClient() = default;
    ~JdwpClient();
    JdwpClient(const JdwpClient&) = delete;
    JdwpClient& operator=(const JdwpClient&) = delete;

    // Connects to 127.0.0.1:port, performs the handshake and IDSizes.
    bool connect(int port, std::string& error);
    void disconnect();
    bool connected() const { return connected_.load(); }

    void setEventHandler(std::function<void(const Event&)> handler) { onEvent_ = std::move(handler); }
    void setDisconnectHandler(std::function<void()> handler) { onDisconnect_ = std::move(handler); }

    // Commands (all return false + error on failure / timeout).
    bool version(std::string& description, std::string& vmName, std::string& error);
    bool allThreads(std::vector<Id>& out, std::string& error);
    bool threadName(Id thread, std::string& out, std::string& error);
    bool threadStatus(Id thread, int32_t& status, int32_t& suspendStatus, std::string& error);
    bool threadFrames(Id thread, std::vector<std::pair<Id, Location>>& out, std::string& error, int32_t max = -1);
    bool suspendVm(std::string& error);
    bool resumeVm(std::string& error);
    bool suspendThread(Id thread, std::string& error);
    bool resumeThread(Id thread, std::string& error);
    bool classesBySignature(const std::string& sig, std::vector<std::pair<uint8_t, Id>>& out, std::string& error);
    bool signature(Id refType, std::string& out, std::string& error);  // cached
    bool methods(Id refType, std::vector<MethodInfo>& out, std::string& error);  // cached
    bool lineTable(Id refType, Id method, std::vector<std::pair<uint64_t, int32_t>>& out, std::string& error);
    bool variableTable(Id refType, Id method, std::vector<Variable>& out, std::string& error);
    bool frameValues(Id thread, Id frame, const std::vector<std::pair<int32_t, uint8_t>>& slots, std::vector<Value>& out,
                     std::string& error);
    bool thisObject(Id thread, Id frame, Value& out, std::string& error);
    bool stringValue(Id object, std::string& out, std::string& error);
    bool objectType(Id object, std::string& signature, std::string& error);  // runtime class of an object
    bool arrayLength(Id array, int32_t& out, std::string& error);
    bool objectRefType(Id object, Id& refType, std::string& error);
    bool superclass(Id classId, Id& out, std::string& error);  // 0 for java.lang.Object
    bool fields(Id refType, std::vector<FieldInfo>& out, std::string& error);  // declared fields (cached)
    bool objectValues(Id object, const std::vector<Id>& fieldIds, std::vector<Value>& out, std::string& error);
    bool arrayValues(Id array, int32_t first, int32_t length, std::vector<Value>& out, std::string& error);
    // EventRequest.Set helpers (suspend policy ALL). Return the request id.
    bool setBreakpoint(const Location& loc, int32_t& requestId, std::string& error);
    bool setClassPrepare(const std::string& classPattern, int32_t& requestId, std::string& error);
    bool setStep(Id thread, int32_t depth /*0 into,1 over,2 out*/, int32_t& requestId, std::string& error);
    // Exception breakpoint; refType 0 = any exception class.
    bool setExceptionBreak(Id refType, bool caught, bool uncaught, int32_t& requestId, std::string& error);
    bool clearRequest(uint8_t eventKind, int32_t requestId, std::string& error);

    // Renders "Lcom/foo/Bar;" + method name for a location (uses caches).
    std::string describe(const Location& loc);

    // Wire helpers (exposed for tests).
    static std::string tagName(uint8_t tag);

private:
    struct Reply {
        bool done = false;
        uint16_t error = 0;
        std::vector<uint8_t> data;
    };
    bool command(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload, std::vector<uint8_t>& reply,
                 std::string& error, int timeoutMs = 8000);
    void readerLoop();
    void handleEventPacket(const std::vector<uint8_t>& data);

    // Encoding helpers sized by the negotiated id sizes.
    void putId(std::vector<uint8_t>& b, Id v, int size) const;
    void putU32(std::vector<uint8_t>& b, uint32_t v) const;
    void putU64(std::vector<uint8_t>& b, uint64_t v) const;
    void putString(std::vector<uint8_t>& b, const std::string& s) const;
    void putLocation(std::vector<uint8_t>& b, const Location& l) const;
    struct Reader {
        const std::vector<uint8_t>& d;
        size_t p = 0;
        bool ok = true;
        uint8_t u8();
        uint32_t u32();
        uint64_t u64();
        uint64_t id(int size);
        std::string str();
    };
    Location readLocation(Reader& r) const;
    Value readTaggedValue(Reader& r);
    Value readValue(uint8_t tag, Reader& r);  // untagged value of a known tag (array regions)

    Socket socket_;
    std::thread reader_;
    std::atomic<bool> connected_{false};
    std::mutex sendMutex_;
    std::mutex replyMutex_;
    std::condition_variable replyCv_;
    std::unordered_map<uint32_t, Reply> replies_;
    std::atomic<uint32_t> nextId_{1};
    int fieldIdSize_ = 8, methodIdSize_ = 8, objectIdSize_ = 8, refTypeIdSize_ = 8, frameIdSize_ = 8;
    std::function<void(const Event&)> onEvent_;
    std::function<void()> onDisconnect_;

    std::mutex cacheMutex_;
    std::unordered_map<Id, std::string> sigCache_;
    std::unordered_map<Id, std::vector<MethodInfo>> methodCache_;
    std::unordered_map<Id, std::vector<FieldInfo>> fieldCache_;
};
