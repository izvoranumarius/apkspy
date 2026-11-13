#include "debug/Jdwp.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>

namespace {
constexpr uint8_t kReplyFlag = 0x80;
constexpr size_t kHeader = 11;
constexpr uint32_t kMaxPacket = 64u << 20;  // refuse absurd lengths from a broken peer
const char kHandshake[] = "JDWP-Handshake";

const char* errorName(uint16_t code) {
    switch (code) {
    case 10: return "INVALID_THREAD";
    case 13: return "THREAD_NOT_SUSPENDED";
    case 20: return "INVALID_OBJECT";
    case 21: return "INVALID_CLASS";
    case 23: return "INVALID_METHODID";
    case 24: return "INVALID_LOCATION";
    case 30: return "INVALID_FRAMEID";
    case 35: return "INVALID_SLOT";
    case 41: return "NOT_FOUND";
    case 99: return "NOT_IMPLEMENTED";
    case 100: return "NULL_POINTER";
    case 101: return "ABSENT_INFORMATION";
    case 102: return "INVALID_EVENT_TYPE";
    case 112: return "VM_DEAD";
    default: return nullptr;
    }
}
}  // namespace

JdwpClient::~JdwpClient() { disconnect(); }

uint8_t JdwpClient::Reader::u8() {
    if (p + 1 > d.size()) return ok = false, 0;
    return d[p++];
}
uint32_t JdwpClient::Reader::u32() {
    if (p + 4 > d.size()) return ok = false, 0;
    uint32_t v = static_cast<uint32_t>(d[p]) << 24 | static_cast<uint32_t>(d[p + 1]) << 16 | static_cast<uint32_t>(d[p + 2]) << 8 | d[p + 3];
    p += 4;
    return v;
}
uint64_t JdwpClient::Reader::u64() {
    const uint64_t hi = u32();
    return hi << 32 | u32();
}
uint64_t JdwpClient::Reader::id(int size) {
    if (p + static_cast<size_t>(size) > d.size()) return ok = false, 0;
    uint64_t v = 0;
    for (int i = 0; i < size; ++i) v = v << 8 | d[p++];
    return v;
}
std::string JdwpClient::Reader::str() {
    const uint32_t n = u32();
    if (!ok || p + n > d.size()) return ok = false, std::string();
    std::string s(reinterpret_cast<const char*>(d.data()) + p, n);
    p += n;
    return s;
}

void JdwpClient::putId(std::vector<uint8_t>& b, Id v, int size) const {
    for (int i = size - 1; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void JdwpClient::putU32(std::vector<uint8_t>& b, uint32_t v) const { putId(b, v, 4); }
void JdwpClient::putU64(std::vector<uint8_t>& b, uint64_t v) const { putId(b, v, 8); }
void JdwpClient::putString(std::vector<uint8_t>& b, const std::string& s) const {
    putU32(b, static_cast<uint32_t>(s.size()));
    b.insert(b.end(), s.begin(), s.end());
}
void JdwpClient::putLocation(std::vector<uint8_t>& b, const Location& l) const {
    b.push_back(l.typeTag);
    putId(b, l.classId, refTypeIdSize_);
    putId(b, l.methodId, methodIdSize_);
    putU64(b, l.index);
}

JdwpClient::Location JdwpClient::readLocation(Reader& r) const {
    Location l;
    l.typeTag = r.u8();
    l.classId = r.id(refTypeIdSize_);
    l.methodId = r.id(methodIdSize_);
    l.index = r.u64();
    return l;
}

bool JdwpClient::connect(int port, std::string& error) {
    disconnect();
    if (!socket_.connectLoopback(port, 5000, error)) return false;
    socket_.setRecvTimeout(5000);
    char reply[sizeof kHandshake - 1];
    if (!socket_.sendAll(kHandshake, sizeof kHandshake - 1) || !socket_.recvAll(reply, sizeof reply) ||
        std::memcmp(reply, kHandshake, sizeof reply) != 0) {
        // Seen on real devices: the process registers with adbd but its
        // runtime refuses to load the debugger agent ("cannot load the jdwp
        // agent" in logcat) unless the app is built debuggable.
        error = "JDWP handshake failed: the process did not answer. Usually the app is not debuggable "
                "(Android 14+ only debugs apps built with android:debuggable=\"true\"), or another debugger "
                "such as Android Studio is already attached.";
        socket_.close();
        return false;
    }
    socket_.setRecvTimeout(0);  // the reader thread blocks until data / shutdown
    connected_ = true;
    reader_ = std::thread(&JdwpClient::readerLoop, this);
    std::vector<uint8_t> r;
    if (!command(1, 7, {}, r, error)) {  // IDSizes
        disconnect();
        return false;
    }
    Reader rd{r};
    fieldIdSize_ = static_cast<int>(rd.u32());
    methodIdSize_ = static_cast<int>(rd.u32());
    objectIdSize_ = static_cast<int>(rd.u32());
    refTypeIdSize_ = static_cast<int>(rd.u32());
    frameIdSize_ = static_cast<int>(rd.u32());
    const auto sane = [](int s) { return s >= 1 && s <= 8; };
    if (!rd.ok || !sane(fieldIdSize_) || !sane(methodIdSize_) || !sane(objectIdSize_) || !sane(refTypeIdSize_) ||
        !sane(frameIdSize_)) {
        error = "invalid IDSizes reply";
        disconnect();
        return false;
    }
    return true;
}

void JdwpClient::disconnect() {
    const bool was = connected_.exchange(false);
    socket_.shutdownBoth();
    if (reader_.joinable()) reader_.join();
    socket_.close();
    {
        std::lock_guard<std::mutex> lock(replyMutex_);
        replies_.clear();
    }
    replyCv_.notify_all();
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        sigCache_.clear();
        methodCache_.clear();
        fieldCache_.clear();
    }
    (void)was;
}

void JdwpClient::readerLoop() {
    std::vector<uint8_t> packet;
    while (connected_.load()) {
        uint8_t header[kHeader];
        if (!socket_.recvAll(header, kHeader)) break;
        const uint32_t len = static_cast<uint32_t>(header[0]) << 24 | static_cast<uint32_t>(header[1]) << 16 | static_cast<uint32_t>(header[2]) << 8 | header[3];
        const uint32_t id = static_cast<uint32_t>(header[4]) << 24 | static_cast<uint32_t>(header[5]) << 16 | static_cast<uint32_t>(header[6]) << 8 | header[7];
        const uint8_t flags = header[8];
        if (len < kHeader || len > kMaxPacket) break;
        packet.resize(len - kHeader);
        if (!packet.empty() && !socket_.recvAll(packet.data(), packet.size())) break;
        if (flags & kReplyFlag) {
            const uint16_t err = static_cast<uint16_t>(header[9] << 8 | header[10]);
            std::lock_guard<std::mutex> lock(replyMutex_);
            auto it = replies_.find(id);
            if (it != replies_.end()) {  // late replies to timed-out commands are dropped
                it->second.done = true;
                it->second.error = err;
                it->second.data = packet;
            }
            replyCv_.notify_all();
        } else if (header[9] == 64 && header[10] == 100) {
            handleEventPacket(packet);
        }
    }
    const bool wasConnected = connected_.exchange(false);
    replyCv_.notify_all();
    if (wasConnected && onDisconnect_) onDisconnect_();
}

bool JdwpClient::command(uint8_t set, uint8_t cmd, const std::vector<uint8_t>& payload, std::vector<uint8_t>& reply,
                         std::string& error, int timeoutMs) {
    if (!connected_.load()) {
        error = "not connected";
        return false;
    }
    const uint32_t id = nextId_++;
    std::vector<uint8_t> pkt;
    pkt.reserve(kHeader + payload.size());
    putU32(pkt, static_cast<uint32_t>(kHeader + payload.size()));
    putU32(pkt, id);
    pkt.push_back(0);
    pkt.push_back(set);
    pkt.push_back(cmd);
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    {
        std::lock_guard<std::mutex> lock(replyMutex_);
        replies_[id] = Reply{};
    }
    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        if (!socket_.sendAll(pkt.data(), pkt.size())) {
            std::lock_guard<std::mutex> rl(replyMutex_);
            replies_.erase(id);
            error = "send failed";
            return false;
        }
    }
    std::unique_lock<std::mutex> lock(replyMutex_);
    const bool got = replyCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] {
        auto it = replies_.find(id);
        return !connected_.load() || (it != replies_.end() && it->second.done);
    });
    auto it = replies_.find(id);
    if (!got || it == replies_.end() || !it->second.done) {
        replies_.erase(id);
        error = connected_.load() ? "JDWP command timed out" : "debugger connection closed";
        return false;
    }
    Reply r = std::move(it->second);
    replies_.erase(it);
    if (r.error != 0) {
        const char* name = errorName(r.error);
        error = "JDWP error " + std::to_string(r.error) + (name ? std::string(" (") + name + ")" : "");
        return false;
    }
    reply = std::move(r.data);
    return true;
}

void JdwpClient::handleEventPacket(const std::vector<uint8_t>& data) {
    Reader r{data};
    r.u8();  // suspend policy
    const uint32_t count = r.u32();
    for (uint32_t i = 0; i < count && r.ok && i < 4096; ++i) {
        Event e;
        e.kind = r.u8();
        e.requestId = static_cast<int32_t>(r.u32());
        switch (e.kind) {
        case 90:  // VM_START
        case 6:   // THREAD_START
        case 7:   // THREAD_DEATH
            e.thread = r.id(objectIdSize_);
            break;
        case 1:   // SINGLE_STEP
        case 2:   // BREAKPOINT
        case 40:  // METHOD_ENTRY
        case 41:  // METHOD_EXIT
            e.thread = r.id(objectIdSize_);
            e.location = readLocation(r);
            break;
        case 4:  // EXCEPTION
            e.thread = r.id(objectIdSize_);
            e.location = readLocation(r);
            r.u8();  // tag of the exception object
            e.exception = r.id(objectIdSize_);
            e.catchLocation = readLocation(r);
            break;
        case 8:  // CLASS_PREPARE
            e.thread = r.id(objectIdSize_);
            r.u8();
            e.refType = r.id(refTypeIdSize_);
            e.signature = r.str();
            r.u32();
            break;
        case 9: e.signature = r.str(); break;  // CLASS_UNLOAD
        case 99: break;                        // VM_DEATH
        default: return;                       // unknown layout: stop parsing this packet
        }
        if (!r.ok) return;
        if (onEvent_) onEvent_(e);
    }
}

bool JdwpClient::version(std::string& description, std::string& vmName, std::string& error) {
    std::vector<uint8_t> r;
    if (!command(1, 1, {}, r, error)) return false;
    Reader rd{r};
    description = rd.str();
    rd.u32();
    rd.u32();
    rd.str();  // vmVersion
    vmName = rd.str();
    return rd.ok;
}

bool JdwpClient::allThreads(std::vector<Id>& out, std::string& error) {
    std::vector<uint8_t> r;
    if (!command(1, 4, {}, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 100000; ++i) out.push_back(rd.id(objectIdSize_));
    return rd.ok;
}

bool JdwpClient::threadName(Id thread, std::string& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    if (!command(11, 1, p, r, error)) return false;
    Reader rd{r};
    out = rd.str();
    return rd.ok;
}

bool JdwpClient::threadStatus(Id thread, int32_t& status, int32_t& suspendStatus, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    if (!command(11, 4, p, r, error)) return false;
    Reader rd{r};
    status = static_cast<int32_t>(rd.u32());
    suspendStatus = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::threadFrames(Id thread, std::vector<std::pair<Id, Location>>& out, std::string& error, int32_t max) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    // ART answers INVALID_LENGTH when the requested length exceeds the stack depth, so ask for the depth first.
    if (!command(11, 7, p, r, error)) return false;
    Reader countRd{r};
    const int32_t depth = static_cast<int32_t>(countRd.u32());
    if (!countRd.ok) {
        error = "malformed FrameCount reply";
        return false;
    }
    out.clear();
    if (depth <= 0) return true;
    putU32(p, 0);
    putU32(p, static_cast<uint32_t>(max > 0 && max < depth ? max : depth));
    if (!command(11, 6, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 4096; ++i) {
        const Id frame = rd.id(frameIdSize_);
        out.emplace_back(frame, readLocation(rd));
    }
    return rd.ok;
}

bool JdwpClient::suspendVm(std::string& error) {
    std::vector<uint8_t> r;
    return command(1, 8, {}, r, error);
}

bool JdwpClient::resumeVm(std::string& error) {
    std::vector<uint8_t> r;
    return command(1, 9, {}, r, error);
}

bool JdwpClient::suspendThread(Id thread, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    return command(11, 2, p, r, error);
}

bool JdwpClient::resumeThread(Id thread, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    return command(11, 3, p, r, error);
}

bool JdwpClient::classesBySignature(const std::string& sig, std::vector<std::pair<uint8_t, Id>>& out,
                                    std::string& error) {
    std::vector<uint8_t> p, r;
    putString(p, sig);
    if (!command(1, 2, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 4096; ++i) {
        const uint8_t tag = rd.u8();
        const Id type = rd.id(refTypeIdSize_);
        rd.u32();  // status
        out.emplace_back(tag, type);
    }
    return rd.ok;
}

bool JdwpClient::signature(Id refType, std::string& out, std::string& error) {
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = sigCache_.find(refType);
        if (it != sigCache_.end()) {
            out = it->second;
            return true;
        }
    }
    std::vector<uint8_t> p, r;
    putId(p, refType, refTypeIdSize_);
    if (!command(2, 1, p, r, error)) return false;
    Reader rd{r};
    out = rd.str();
    if (!rd.ok) return false;
    std::lock_guard<std::mutex> lock(cacheMutex_);
    sigCache_[refType] = out;
    return true;
}

bool JdwpClient::methods(Id refType, std::vector<MethodInfo>& out, std::string& error) {
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = methodCache_.find(refType);
        if (it != methodCache_.end()) {
            out = it->second;
            return true;
        }
    }
    std::vector<uint8_t> p, r;
    putId(p, refType, refTypeIdSize_);
    if (!command(2, 5, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) {
        MethodInfo m;
        m.id = rd.id(methodIdSize_);
        m.name = rd.str();
        m.signature = rd.str();
        m.modBits = static_cast<int32_t>(rd.u32());
        out.push_back(std::move(m));
    }
    if (!rd.ok) return false;
    std::lock_guard<std::mutex> lock(cacheMutex_);
    methodCache_[refType] = out;
    return true;
}

bool JdwpClient::lineTable(Id refType, Id method, std::vector<std::pair<uint64_t, int32_t>>& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, refType, refTypeIdSize_);
    putId(p, method, methodIdSize_);
    if (!command(6, 1, p, r, error)) return false;
    Reader rd{r};
    rd.u64();
    rd.u64();
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 1000000; ++i) {
        const uint64_t idx = rd.u64();
        out.emplace_back(idx, static_cast<int32_t>(rd.u32()));
    }
    return rd.ok;
}

bool JdwpClient::variableTable(Id refType, Id method, std::vector<Variable>& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, refType, refTypeIdSize_);
    putId(p, method, methodIdSize_);
    if (!command(6, 2, p, r, error)) return false;
    Reader rd{r};
    rd.u32();  // argCnt
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) {
        Variable v;
        v.codeIndex = rd.u64();
        v.name = rd.str();
        v.signature = rd.str();
        v.length = rd.u32();
        v.slot = static_cast<int32_t>(rd.u32());
        out.push_back(std::move(v));
    }
    return rd.ok;
}

std::string JdwpClient::tagName(uint8_t tag) {
    switch (tag) {
    case 'B': return "byte";
    case 'C': return "char";
    case 'D': return "double";
    case 'F': return "float";
    case 'I': return "int";
    case 'J': return "long";
    case 'S': return "short";
    case 'Z': return "boolean";
    case 'V': return "void";
    case 'L': return "object";
    case '[': return "array";
    case 's': return "String";
    case 't': return "Thread";
    case 'g': return "ThreadGroup";
    case 'l': return "ClassLoader";
    case 'c': return "Class";
    default: return std::string(1, static_cast<char>(tag));
    }
}

JdwpClient::Value JdwpClient::readTaggedValue(Reader& r) {
    const uint8_t tag = r.u8();
    return readValue(tag, r);
}

JdwpClient::Value JdwpClient::readValue(uint8_t tag, Reader& r) {
    Value v;
    v.tag = tag;
    char buf[64];
    switch (v.tag) {
    case 'B': v.raw = r.u8(); std::snprintf(buf, sizeof buf, "%d", static_cast<int>(static_cast<int8_t>(v.raw))); v.text = buf; break;
    case 'Z': v.raw = r.u8(); v.text = v.raw ? "true" : "false"; break;
    case 'C': {
        v.raw = r.id(2);
        std::snprintf(buf, sizeof buf, v.raw >= 32 && v.raw < 127 ? "'%c'" : "\\u%04x", static_cast<unsigned>(v.raw));
        v.text = buf;
        break;
    }
    case 'S': v.raw = r.id(2); std::snprintf(buf, sizeof buf, "%d", static_cast<int>(static_cast<int16_t>(v.raw))); v.text = buf; break;
    case 'I': v.raw = r.u32(); std::snprintf(buf, sizeof buf, "%d", static_cast<int32_t>(v.raw)); v.text = buf; break;
    case 'F': {
        v.raw = r.u32();
        float f;
        const uint32_t bits = static_cast<uint32_t>(v.raw);
        std::memcpy(&f, &bits, 4);
        std::snprintf(buf, sizeof buf, "%g", f);
        v.text = buf;
        break;
    }
    case 'J': v.raw = r.u64(); std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(v.raw)); v.text = buf; break;
    case 'D': {
        v.raw = r.u64();
        double d;
        std::memcpy(&d, &v.raw, 8);
        std::snprintf(buf, sizeof buf, "%g", d);
        v.text = buf;
        break;
    }
    case 'V': v.text = "void"; break;
    default:  // object-like
        v.raw = r.id(objectIdSize_);
        if (v.raw == 0) {
            v.text = "null";
        } else if (v.tag == 's') {
            std::string s, err;
            if (stringValue(v.raw, s, err)) {
                if (s.size() > 512) s = s.substr(0, 512) + "...";
                v.text = "\"" + s + "\"";
            } else {
                v.text = "String@" + std::to_string(v.raw);
            }
        } else {
            // Name objects by their runtime class ("MainActivity@22", "int[5]@40") instead of the bare tag.
            std::string sig, err;
            if (objectType(v.raw, sig, err)) {
                v.type = sig;
                if (sig.front() == '[') {
                    std::string elem = sig.substr(1);
                    elem = elem.size() == 1 ? tagName(static_cast<uint8_t>(elem[0])) : elem;
                    if (elem.size() > 2 && elem.front() == 'L') elem = elem.substr(1, elem.size() - 2);
                    elem = elem.substr(elem.find_last_of('/') + 1);
                    int32_t len = 0;
                    v.text = elem + "[" + (arrayLength(v.raw, len, err) ? std::to_string(len) : std::string()) + "]@" +
                             std::to_string(v.raw);
                } else {
                    std::string name = sig.size() > 2 ? sig.substr(1, sig.size() - 2) : sig;
                    v.text = name.substr(name.find_last_of('/') + 1) + "@" + std::to_string(v.raw);
                }
            } else {
                v.text = tagName(v.tag) + "@" + std::to_string(v.raw);
            }
        }
        break;
    }
    return v;
}

bool JdwpClient::objectRefType(Id object, Id& refType, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, object, objectIdSize_);
    if (!command(9, 1, p, r, error, 3000)) return false;
    Reader rd{r};
    rd.u8();  // refTypeTag
    refType = rd.id(refTypeIdSize_);
    return rd.ok;
}

bool JdwpClient::objectType(Id object, std::string& sig, std::string& error) {
    Id type = 0;
    return objectRefType(object, type, error) && signature(type, sig, error) && !sig.empty();
}

bool JdwpClient::superclass(Id classId, Id& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, classId, refTypeIdSize_);
    if (!command(3, 1, p, r, error, 3000)) return false;
    Reader rd{r};
    out = rd.id(refTypeIdSize_);
    return rd.ok;
}

bool JdwpClient::fields(Id refType, std::vector<FieldInfo>& out, std::string& error) {
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = fieldCache_.find(refType);
        if (it != fieldCache_.end()) {
            out = it->second;
            return true;
        }
    }
    std::vector<uint8_t> p, r;
    putId(p, refType, refTypeIdSize_);
    if (!command(2, 4, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) {
        FieldInfo f;
        f.id = rd.id(fieldIdSize_);
        f.name = rd.str();
        f.signature = rd.str();
        f.modBits = static_cast<int32_t>(rd.u32());
        out.push_back(std::move(f));
    }
    if (!rd.ok) return false;
    std::lock_guard<std::mutex> lock(cacheMutex_);
    fieldCache_[refType] = out;
    return true;
}

bool JdwpClient::objectValues(Id object, const std::vector<Id>& fieldIds, std::vector<Value>& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, object, objectIdSize_);
    putU32(p, static_cast<uint32_t>(fieldIds.size()));
    for (Id f : fieldIds) putId(p, f, fieldIdSize_);
    if (!command(9, 2, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) out.push_back(readTaggedValue(rd));
    return rd.ok;
}

bool JdwpClient::arrayValues(Id array, int32_t first, int32_t length, std::vector<Value>& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, array, objectIdSize_);
    putU32(p, static_cast<uint32_t>(first));
    putU32(p, static_cast<uint32_t>(length));
    if (!command(13, 2, p, r, error)) return false;
    Reader rd{r};
    const uint8_t tag = rd.u8();
    const uint32_t n = rd.u32();
    // Primitive regions carry untagged values; object regions are tagged per element.
    const bool primitive = tag == 'B' || tag == 'C' || tag == 'D' || tag == 'F' || tag == 'I' || tag == 'J' ||
                           tag == 'S' || tag == 'Z';
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) out.push_back(primitive ? readValue(tag, rd) : readTaggedValue(rd));
    return rd.ok;
}

bool JdwpClient::arrayLength(Id array, int32_t& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, array, objectIdSize_);
    if (!command(13, 1, p, r, error, 3000)) return false;
    Reader rd{r};
    out = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::frameValues(Id thread, Id frame, const std::vector<std::pair<int32_t, uint8_t>>& slots,
                             std::vector<Value>& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    putId(p, frame, frameIdSize_);
    putU32(p, static_cast<uint32_t>(slots.size()));
    for (const auto& s : slots) {
        putU32(p, static_cast<uint32_t>(s.first));
        p.push_back(s.second);
    }
    if (!command(16, 1, p, r, error)) return false;
    Reader rd{r};
    const uint32_t n = rd.u32();
    out.clear();
    for (uint32_t i = 0; i < n && rd.ok && i < 65536; ++i) out.push_back(readTaggedValue(rd));
    return rd.ok;
}

bool JdwpClient::thisObject(Id thread, Id frame, Value& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, thread, objectIdSize_);
    putId(p, frame, frameIdSize_);
    if (!command(16, 3, p, r, error)) return false;
    Reader rd{r};
    out = readTaggedValue(rd);
    return rd.ok;
}

bool JdwpClient::stringValue(Id object, std::string& out, std::string& error) {
    std::vector<uint8_t> p, r;
    putId(p, object, objectIdSize_);
    if (!command(10, 1, p, r, error, 3000)) return false;
    Reader rd{r};
    out = rd.str();
    return rd.ok;
}

bool JdwpClient::setBreakpoint(const Location& loc, int32_t& requestId, std::string& error) {
    std::vector<uint8_t> p, r;
    p.push_back(2);  // BREAKPOINT
    p.push_back(2);  // SUSPEND_ALL
    putU32(p, 1);
    p.push_back(7);  // LocationOnly
    putLocation(p, loc);
    if (!command(15, 1, p, r, error)) return false;
    Reader rd{r};
    requestId = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::setClassPrepare(const std::string& classPattern, int32_t& requestId, std::string& error) {
    std::vector<uint8_t> p, r;
    p.push_back(8);  // CLASS_PREPARE
    p.push_back(2);  // SUSPEND_ALL: lets us place breakpoints before the class runs
    putU32(p, 1);
    p.push_back(5);  // ClassMatch
    putString(p, classPattern);
    if (!command(15, 1, p, r, error)) return false;
    Reader rd{r};
    requestId = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::setExceptionBreak(Id refType, bool caught, bool uncaught, int32_t& requestId, std::string& error) {
    std::vector<uint8_t> p, r;
    p.push_back(4);  // EXCEPTION
    p.push_back(2);  // SUSPEND_ALL
    putU32(p, 1);
    p.push_back(8);  // ExceptionOnly
    putId(p, refType, refTypeIdSize_);
    p.push_back(caught ? 1 : 0);
    p.push_back(uncaught ? 1 : 0);
    if (!command(15, 1, p, r, error)) return false;
    Reader rd{r};
    requestId = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::setStep(Id thread, int32_t depth, int32_t& requestId, std::string& error) {
    std::vector<uint8_t> p, r;
    p.push_back(1);  // SINGLE_STEP
    p.push_back(2);  // SUSPEND_ALL
    putU32(p, 2);
    p.push_back(10);  // Step
    putId(p, thread, objectIdSize_);
    putU32(p, 1);  // StepSize.LINE
    putU32(p, static_cast<uint32_t>(depth));
    p.push_back(1);  // Count
    putU32(p, 1);
    if (!command(15, 1, p, r, error)) return false;
    Reader rd{r};
    requestId = static_cast<int32_t>(rd.u32());
    return rd.ok;
}

bool JdwpClient::clearRequest(uint8_t eventKind, int32_t requestId, std::string& error) {
    std::vector<uint8_t> p, r;
    p.push_back(eventKind);
    putU32(p, static_cast<uint32_t>(requestId));
    return command(15, 2, p, r, error);
}

std::string JdwpClient::describe(const Location& loc) {
    std::string sig, err;
    if (!signature(loc.classId, sig, err)) sig = "class@" + std::to_string(loc.classId);
    std::vector<MethodInfo> ms;
    std::string name = "method@" + std::to_string(loc.methodId), msig;
    if (methods(loc.classId, ms, err))
        for (const MethodInfo& m : ms)
            if (m.id == loc.methodId) {
                name = m.name;
                msig = m.signature;
            }
    return sig + "->" + name + msig;
}
