#include "debug/DeviceService.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include "core/TextUtils.hpp"

// ---------------------------------------------------------------------------
// JobQueue
// ---------------------------------------------------------------------------

void JobQueue::post(std::function<void()> job) {
    {
        std::lock_guard<std::mutex> lock(m_);
        if (stopping_) return;
        jobs_.push_back(std::move(job));
        if (!worker_.joinable()) worker_ = std::thread(&JobQueue::loop, this);
    }
    cv_.notify_one();
}

void JobQueue::stop() {
    {
        std::lock_guard<std::mutex> lock(m_);
        stopping_ = true;
        jobs_.clear();
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void JobQueue::loop() {
    for (;;) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(m_);
            cv_.wait(lock, [&] { return stopping_ || !jobs_.empty(); });
            if (stopping_) return;
            job = std::move(jobs_.front());
            jobs_.pop_front();
            busy_ = true;
        }
        job();
        busy_ = false;
    }
}

// ---------------------------------------------------------------------------
// DebugSession
// ---------------------------------------------------------------------------

namespace {

std::string descriptorOf(const std::string& name) {
    if (name.empty()) return name;
    if (name.front() == 'L' && name.back() == ';') return name;
    std::string d = "L" + name + ";";
    std::replace(d.begin(), d.end(), '.', '/');
    return d;
}

std::string javaOf(const std::string& descriptor) {
    size_t dims = 0;
    while (dims < descriptor.size() && descriptor[dims] == '[') ++dims;
    std::string s = descriptor.substr(dims);
    if (s.size() == 1) {
        switch (s[0]) {
        case 'B': s = "byte"; break;
        case 'C': s = "char"; break;
        case 'D': s = "double"; break;
        case 'F': s = "float"; break;
        case 'I': s = "int"; break;
        case 'J': s = "long"; break;
        case 'S': s = "short"; break;
        case 'Z': s = "boolean"; break;
        case 'V': s = "void"; break;
        default: break;
        }
    } else if (s.size() >= 2 && s.front() == 'L' && s.back() == ';') {
        s = s.substr(1, s.size() - 2);
    }
    std::replace(s.begin(), s.end(), '/', '.');
    for (size_t i = 0; i < dims; ++i) s += "[]";
    return s;
}

}  // namespace

DebugSession::~DebugSession() {
    jobs_.stop();
    jdwp_.setEventHandler(nullptr);
    jdwp_.setDisconnectHandler(nullptr);
    jdwp_.disconnect();
    std::lock_guard<std::mutex> lock(mutex_);
    if (snap_.localPort) adb_.removeForward(snap_.serial, snap_.localPort);
}

const char* DebugSession::stateName(State s) {
    switch (s) {
    case State::Detached: return "detached";
    case State::Attaching: return "attaching";
    case State::Running: return "running";
    case State::Suspended: return "suspended";
    case State::Failed: return "failed";
    }
    return "?";
}

const char* DebugSession::threadStatusName(int32_t status) {
    switch (status) {
    case 0: return "zombie";
    case 1: return "running";
    case 2: return "sleeping";
    case 3: return "monitor";
    case 4: return "wait";
    default: return "unknown";
    }
}

DebugSession::Snapshot DebugSession::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snap_;
}

DebugSession::State DebugSession::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snap_.state;
}

bool DebugSession::waitIdle(int timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (pending_.load() > 0) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return true;
}

void DebugSession::pushEvent(std::string text) {
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.events.push_back(std::move(text));
    if (snap_.events.size() > 200) snap_.events.erase(snap_.events.begin(), snap_.events.begin() + 50);
    bump();
}

#define DEBUG_JOB(body)                 \
    do {                                \
        ++pending_;                     \
        jobs_.post([this] {             \
            body;                       \
            --pending_;                 \
        });                             \
    } while (0)

void DebugSession::attach(const std::string& serial, int pid) {
    ++pending_;
    jobs_.post([this, serial, pid] {
        doAttach(serial, pid);
        --pending_;
    });
}

void DebugSession::doAttach(std::string serial, int pid) {
    if (jdwp_.connected()) doDetach(false);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snap_.state = State::Attaching;
        snap_.serial = serial;
        snap_.pid = pid;
        snap_.error.clear();
        snap_.threads.clear();
        snap_.frames.clear();
        snap_.locals.clear();
        bump();
    }
    std::string error;
    const int port = adb_.forwardJdwp(serial, pid, error);
    if (port <= 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        snap_.state = State::Failed;
        snap_.error = error.empty() ? "adb forward failed" : error;
        bump();
        return;
    }
    jdwp_.setEventHandler([this](const JdwpClient::Event& e) {
        ++pending_;
        jobs_.post([this, e] {
            onEvent(e);
            --pending_;
        });
    });
    jdwp_.setDisconnectHandler([this] {
        jobs_.post([this] {
            pushEvent("target disconnected");
            doDetach(true);
        });
    });
    if (!jdwp_.connect(port, error)) {
        adb_.removeForward(serial, port);
        std::lock_guard<std::mutex> lock(mutex_);
        snap_.state = State::Failed;
        snap_.error = error;
        bump();
        return;
    }
    std::string desc, vm;
    jdwp_.version(desc, vm, error);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snap_.state = State::Running;
        snap_.localPort = port;
        snap_.vm = vm.empty() ? desc : vm + " - " + desc.substr(0, desc.find('\n'));
        bump();
    }
    pushEvent("attached to pid " + std::to_string(pid) + " on " + serial);
    loadThreads();
    tryResolveAll();
}

void DebugSession::detach() { DEBUG_JOB(doDetach(false)); }

void DebugSession::doDetach(bool keepError) {
    std::string serial;
    int port = 0;
    bool wasSuspended = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        serial = snap_.serial;
        port = snap_.localPort;
        wasSuspended = snap_.state == State::Suspended;
    }
    if (jdwp_.connected()) {
        std::string e;
        // Leave the app running: clear our requests and resume before the
        // connection goes away.
        std::vector<Breakpoint> bps;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            bps = snap_.breakpoints;
        }
        for (const Breakpoint& bp : bps)
            for (int32_t r : bp.requests) jdwp_.clearRequest(2, r, e);
        for (int32_t r : classPrepareRequests_) jdwp_.clearRequest(8, r, e);
        if (wasSuspended) jdwp_.resumeVm(e);
    }
    // disconnect() first: it joins the reader thread (which would otherwise
    // still be able to invoke the handlers we reset below).
    jdwp_.disconnect();
    jdwp_.setDisconnectHandler(nullptr);
    jdwp_.setEventHandler(nullptr);
    classPrepareRequests_.clear();
    stepRequest_ = 0;
    if (port) adb_.removeForward(serial, port);
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string err = keepError ? snap_.error : std::string();
    const std::vector<Breakpoint> bps = snap_.breakpoints;
    const std::vector<std::string> events = snap_.events;
    const uint64_t rev = snap_.revision;
    snap_ = Snapshot();
    snap_.revision = rev + 1;
    snap_.error = err;
    snap_.events = events;
    snap_.breakpoints = bps;  // breakpoints survive for the next attach
    for (Breakpoint& bp : snap_.breakpoints) {
        bp.resolved = false;
        bp.requests.clear();
        bp.status = "pending";
    }
}

void DebugSession::loadThreads() {
    std::vector<Id> ids;
    std::string error;
    if (!jdwp_.allThreads(ids, error)) {
        std::lock_guard<std::mutex> lock(mutex_);
        snap_.error = error;
        bump();
        return;
    }
    std::vector<ThreadRow> rows;
    rows.reserve(ids.size());
    for (Id id : ids) {
        ThreadRow r;
        r.id = id;
        jdwp_.threadName(id, r.name, error);
        jdwp_.threadStatus(id, r.status, r.suspend, error);
        rows.push_back(std::move(r));
    }
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.threads = std::move(rows);
    bump();
}

void DebugSession::loadFrames(Id thread) {
    std::vector<std::pair<Id, JdwpClient::Location>> frames;
    std::string error;
    std::vector<FrameRow> rows;
    if (jdwp_.threadFrames(thread, frames, error, 64)) {
        for (const auto& f : frames) {
            FrameRow r;
            r.frameId = f.first;
            r.location = f.second;
            r.method = jdwp_.describe(f.second);
            std::vector<std::pair<uint64_t, int32_t>> lines;
            std::string e;
            if (jdwp_.lineTable(f.second.classId, f.second.methodId, lines, e)) {
                for (const auto& l : lines)
                    if (l.first <= f.second.index) r.line = l.second;
            }
            rows.push_back(std::move(r));
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.currentThread = thread;
    snap_.frames = std::move(rows);
    snap_.selectedFrame = 0;
    if (!error.empty()) snap_.error = error;
    bump();
}

void DebugSession::loadLocals() {
    Id thread = 0;
    FrameRow frame;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (snap_.frames.empty() || snap_.selectedFrame < 0 || snap_.selectedFrame >= (int)snap_.frames.size()) {
            snap_.locals.clear();
            bump();
            return;
        }
        thread = snap_.currentThread;
        frame = snap_.frames[(size_t)snap_.selectedFrame];
    }
    std::vector<Local> locals;
    std::string error;
    if (exceptionObject_) {
        JdwpClient::Value ex;
        ex.tag = 'L';
        ex.raw = exceptionObject_;
        std::string sig;
        ex.text = jdwp_.objectType(ex.raw, sig, error) ? javaOf(sig).substr(javaOf(sig).find_last_of('.') + 1) + "@" + std::to_string(ex.raw)
                                                       : "object@" + std::to_string(ex.raw);
        ex.type = sig;
        locals.push_back(makeLocal("$exception", "", ex));
    }
    JdwpClient::Value self;
    if (jdwp_.thisObject(thread, frame.frameId, self, error) && self.raw != 0) locals.push_back(makeLocal("this", "", self));
    std::vector<JdwpClient::Variable> vars;
    if (jdwp_.variableTable(frame.location.classId, frame.location.methodId, vars, error)) {
        std::vector<std::pair<int32_t, uint8_t>> slots;
        std::vector<const JdwpClient::Variable*> live;
        for (const auto& v : vars) {
            if (v.name == "this") continue;
            if (frame.location.index < v.codeIndex || frame.location.index >= v.codeIndex + v.length) continue;
            const uint8_t tag = v.signature.empty() ? 'I' : (uint8_t)v.signature[0];
            slots.emplace_back(v.slot, tag == 'L' && v.signature == "Ljava/lang/String;" ? (uint8_t)'L' : tag);
            live.push_back(&v);
        }
        std::vector<JdwpClient::Value> values;
        if (!slots.empty() && jdwp_.frameValues(thread, frame.frameId, slots, values, error)) {
            for (size_t i = 0; i < live.size() && i < values.size(); ++i)
                locals.push_back(makeLocal(live[i]->name, live[i]->signature, values[i]));
        }
    } else {
        locals.push_back({"(locals)", "", "not available: " + error + " (needs a debug build with local variable info)"});
    }
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.locals = std::move(locals);
    snap_.children.clear();
    bump();
}

DebugSession::Local DebugSession::makeLocal(const std::string& name, const std::string& declaredType,
                                            const JdwpClient::Value& v) {
    Local l;
    l.name = name;
    // Prefer the runtime class (a List local holding an ArrayList shows ArrayList).
    l.type = javaOf(!v.type.empty() ? v.type : declaredType);
    if (l.type.empty()) l.type = JdwpClient::tagName(v.tag);
    l.value = v.text;
    if (v.isObject() && v.tag != 's') l.objectId = v.raw;
    return l;
}

void DebugSession::expand(uint64_t objectId) {
    if (!objectId) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (snap_.children.count(objectId)) return;
        snap_.children[objectId] = {};  // placeholder: one request per object
    }
    ++pending_;
    jobs_.post([this, objectId] {
        loadChildren(objectId);
        --pending_;
    });
}

void DebugSession::loadChildren(uint64_t objectId) {
    constexpr int kMaxElements = 200;
    std::vector<Local> out;
    std::string error;
    Id type = 0;
    std::string sig;
    if (!jdwp_.objectRefType(objectId, type, error) || !jdwp_.signature(type, sig, error)) {
        out.push_back({"(error)", "", error});
    } else if (!sig.empty() && sig[0] == '[') {
        int32_t length = 0;
        jdwp_.arrayLength(objectId, length, error);
        std::vector<JdwpClient::Value> values;
        const int32_t n = std::min(length, kMaxElements);
        if (n > 0 && jdwp_.arrayValues(objectId, 0, n, values, error)) {
            const std::string elemType = sig.substr(1);
            for (size_t i = 0; i < values.size(); ++i) out.push_back(makeLocal("[" + std::to_string(i) + "]", elemType, values[i]));
        }
        if (length > n) out.push_back({"...", "", std::to_string(length - n) + " more element(s) of " + std::to_string(length)});
        if (length == 0) out.push_back({"(empty)", "", "length 0"});
    } else {
        // Instance fields along the class chain, most derived first; java.lang.Object has none.
        Id cls = type;
        for (int depth = 0; cls && depth < 16 && out.size() < 500; ++depth) {
            std::vector<JdwpClient::FieldInfo> fields;
            if (!jdwp_.fields(cls, fields, error)) break;
            std::vector<Id> ids;
            std::vector<const JdwpClient::FieldInfo*> inst;
            for (const auto& f : fields)
                if (!(f.modBits & 0x8) && f.name.rfind("shadow$_", 0) != 0) {  // ART runtime internals
                    ids.push_back(f.id);
                    inst.push_back(&f);
                }
            std::vector<JdwpClient::Value> values;
            if (!ids.empty() && jdwp_.objectValues(objectId, ids, values, error)) {
                std::string owner;
                if (depth > 0 && jdwp_.signature(cls, owner, error)) owner = javaOf(owner);
                for (size_t i = 0; i < inst.size() && i < values.size(); ++i) {
                    Local l = makeLocal(inst[i]->name, inst[i]->signature, values[i]);
                    if (depth > 0) l.name += "  (" + owner.substr(owner.find_last_of('.') + 1) + ")";
                    out.push_back(std::move(l));
                }
            }
            Id super = 0;
            if (!jdwp_.superclass(cls, super, error)) break;
            cls = super;
        }
        if (out.empty()) out.push_back({"(no instance fields)", "", ""});
    }
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.children[objectId] = std::move(out);
    bump();
}

void DebugSession::suspend() {
    DEBUG_JOB({
        std::string e;
        if (!jdwp_.suspendVm(e)) {
            pushEvent("suspend failed: " + e);
            return;
        }
        loadThreads();
        Id thread = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snap_.state = State::Suspended;
            for (const ThreadRow& t : snap_.threads)
                if (t.name == "main") thread = t.id;
            if (!thread && !snap_.threads.empty()) thread = snap_.threads.front().id;
            bump();
        }
        pushEvent("VM suspended");
        if (thread) {
            loadFrames(thread);
            loadLocals();
        }
    });
}

void DebugSession::resume() {
    DEBUG_JOB({
        std::string e;
        if (!jdwp_.resumeVm(e)) {
            pushEvent("resume failed: " + e);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snap_.state = State::Running;
            snap_.frames.clear();
            snap_.locals.clear();
            snap_.children.clear();
            snap_.exception.clear();
            snap_.exceptionType.clear();
            snap_.exceptionAt.clear();
            snap_.exceptionCatch.clear();
            bump();
        }
        exceptionObject_ = 0;
        pushEvent("VM resumed");
    });
}

void DebugSession::step(int depth) {
    ++pending_;
    jobs_.post([this, depth] {
        Id thread = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (snap_.state == State::Suspended) thread = snap_.currentThread;
        }
        std::string e;
        if (!thread) {
            pushEvent("step: no suspended thread selected");
        } else {
            if (stepRequest_) jdwp_.clearRequest(1, stepRequest_, e);
            if (!jdwp_.setStep(thread, depth, stepRequest_, e)) {
                pushEvent("step failed: " + e);
            } else if (jdwp_.resumeVm(e)) {
                std::lock_guard<std::mutex> lock(mutex_);
                snap_.state = State::Running;
                bump();
            }
        }
        --pending_;
    });
}

void DebugSession::refreshThreads() { DEBUG_JOB(loadThreads()); }

void DebugSession::selectThread(Id thread) {
    ++pending_;
    jobs_.post([this, thread] {
        loadFrames(thread);
        loadLocals();
        --pending_;
    });
}

void DebugSession::selectFrame(int index) {
    ++pending_;
    jobs_.post([this, index] {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snap_.selectedFrame = index;
            bump();
        }
        loadLocals();
        --pending_;
    });
}

int DebugSession::addBreakpoint(const std::string& cls, const std::string& method, int line) {
    int id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Breakpoint bp;
        bp.id = id = nextBreakpointId_++;
        bp.classDescriptor = descriptorOf(cls);
        bp.method = method;
        bp.line = line;
        bp.status = "pending";
        snap_.breakpoints.push_back(bp);
        bump();
    }
    DEBUG_JOB(tryResolveAll());
    return id;
}

int DebugSession::addExceptionBreakpoint(const std::string& cls, bool caught, bool uncaught) {
    int id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Breakpoint bp;
        bp.id = id = nextBreakpointId_++;
        bp.exception = true;
        bp.classDescriptor = cls.empty() ? std::string() : descriptorOf(cls);
        bp.caught = caught;
        bp.uncaught = uncaught;
        bp.status = "pending";
        snap_.breakpoints.push_back(bp);
        bump();
    }
    DEBUG_JOB(tryResolveAll());
    return id;
}

void DebugSession::removeBreakpoint(int id) {
    ++pending_;
    jobs_.post([this, id] {
        std::vector<int32_t> requests;
        uint8_t kind = 2;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = snap_.breakpoints.begin(); it != snap_.breakpoints.end(); ++it)
                if (it->id == id) {
                    requests = it->requests;
                    kind = it->exception ? 4 : 2;
                    snap_.breakpoints.erase(it);
                    break;
                }
            bump();
        }
        std::string e;
        if (jdwp_.connected())
            for (int32_t r : requests) jdwp_.clearRequest(kind, r, e);
        --pending_;
    });
}

void DebugSession::resolveBreakpoint(Breakpoint& bp, Id refType) {
    std::vector<JdwpClient::MethodInfo> methods;
    std::string error;
    if (bp.exception) {
        int32_t request = 0;
        if (jdwp_.setExceptionBreak(refType, bp.caught, bp.uncaught, request, error)) {
            bp.requests.push_back(request);
            bp.resolved = true;
            bp.status = std::string("active (") + (bp.caught && bp.uncaught ? "caught + uncaught" : bp.caught ? "caught" : "uncaught") + ")";
        } else {
            bp.status = "set: " + error;
        }
        return;
    }
    if (!jdwp_.methods(refType, methods, error)) {
        bp.status = "methods: " + error;
        return;
    }
    for (const JdwpClient::MethodInfo& m : methods) {
        if (m.name != bp.method) continue;
        JdwpClient::Location loc;
        loc.typeTag = 1;
        loc.classId = refType;
        loc.methodId = m.id;
        loc.index = 0;
        if (bp.line >= 0) {
            std::vector<std::pair<uint64_t, int32_t>> lines;
            bool found = false;
            if (jdwp_.lineTable(refType, m.id, lines, error)) {
                for (const auto& l : lines)
                    if (l.second == bp.line && (!found || l.first < loc.index)) {
                        loc.index = l.first;
                        found = true;
                    }
            }
            if (!found) continue;  // that overload does not contain the line
        }
        int32_t request = 0;
        if (jdwp_.setBreakpoint(loc, request, error)) bp.requests.push_back(request);
        else bp.status = "set: " + error;
    }
    bp.resolved = !bp.requests.empty();
    if (bp.resolved) bp.status = "active (" + std::to_string(bp.requests.size()) + " location(s))";
    else if (bp.status == "pending" || bp.status.empty()) bp.status = "no matching method/line in the loaded class";
}

void DebugSession::tryResolveAll() {
    if (!jdwp_.connected()) return;
    std::vector<Breakpoint> work;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Breakpoint& bp : snap_.breakpoints)
            if (!bp.resolved) work.push_back(bp);
    }
    for (Breakpoint& bp : work) {
        std::vector<std::pair<uint8_t, Id>> classes;
        std::string error;
        if (bp.exception && bp.classDescriptor.empty()) {
            resolveBreakpoint(bp, 0);  // any exception
        } else if (jdwp_.classesBySignature(bp.classDescriptor, classes, error) && !classes.empty()) {
            for (const auto& c : classes) resolveBreakpoint(bp, c.second);
        } else {
            // Not loaded yet: ask for a CLASS_PREPARE event and resolve then.
            int32_t request = 0;
            if (jdwp_.setClassPrepare(javaOf(bp.classDescriptor), request, error)) {
                classPrepareRequests_.push_back(request);
                bp.status = "waiting for class load";
            } else {
                bp.status = "class prepare: " + error;
            }
        }
        std::lock_guard<std::mutex> lock(mutex_);
        for (Breakpoint& live : snap_.breakpoints)
            if (live.id == bp.id) {
                live.requests = bp.requests;
                live.resolved = bp.resolved;
                live.status = bp.status;
            }
        bump();
    }
}

void DebugSession::onEvent(const JdwpClient::Event& e) {
    std::string error;
    switch (e.kind) {
    case 1:    // single step
    case 2:    // breakpoint
    case 4: {  // exception
        std::string where = jdwp_.describe(e.location);
        std::string description, type, caughtIn;
        if (e.kind == 4) {
            std::string sig;
            type = jdwp_.objectType(e.exception, sig, error) ? javaOf(sig) : "exception";
            if (e.catchLocation.classId) caughtIn = jdwp_.describe(e.catchLocation);
            description = type + " thrown at " + where + (caughtIn.empty() ? " (uncaught)" : " (caught in " + caughtIn + ")");
        }
        exceptionObject_ = e.kind == 4 ? e.exception : 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            snap_.state = State::Suspended;
            snap_.exception = description;
            snap_.exceptionType = type;
            snap_.exceptionAt = e.kind == 4 ? where : std::string();
            snap_.exceptionCatch = caughtIn;
            if (e.kind != 1)
                for (Breakpoint& bp : snap_.breakpoints)
                    if (std::find(bp.requests.begin(), bp.requests.end(), e.requestId) != bp.requests.end()) ++bp.hits;
            bump();
        }
        if (e.kind == 1 && stepRequest_) {
            jdwp_.clearRequest(1, stepRequest_, error);
            stepRequest_ = 0;
        }
        pushEvent(e.kind == 4 ? "exception: " + description : std::string(e.kind == 2 ? "breakpoint hit: " : "step: ") + where);
        loadThreads();
        loadFrames(e.thread);
        loadLocals();
        break;
    }
    case 8: {  // class prepare: resolve pending breakpoints of that class
        std::vector<Breakpoint> work;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const Breakpoint& bp : snap_.breakpoints)
                if (!bp.resolved && bp.classDescriptor == e.signature) work.push_back(bp);
        }
        for (Breakpoint& bp : work) {
            resolveBreakpoint(bp, e.refType);
            std::lock_guard<std::mutex> lock(mutex_);
            for (Breakpoint& live : snap_.breakpoints)
                if (live.id == bp.id) {
                    live.requests = bp.requests;
                    live.resolved = bp.resolved;
                    live.status = bp.status;
                }
            bump();
        }
        if (!work.empty()) pushEvent("class loaded: " + javaOf(e.signature));
        jdwp_.resumeVm(error);  // the prepare event suspended everything
        break;
    }
    case 99:
        pushEvent("VM died");
        doDetach(false);
        break;
    default: break;
    }
}

// ---------------------------------------------------------------------------
// DeviceService
// ---------------------------------------------------------------------------

DeviceService::DeviceService() : debugger_(adb_) {}

void DeviceService::stopTraffic() {
    // Never leave a device pointing at a proxy that no longer exists: its
    // apps would lose network access until the setting is cleared.
    const std::string routed = traffic_.routedSerial();
    if (!routed.empty()) {
        std::string error;
        traffic_.restoreDevice(adb_, routed, error);
    }
    traffic_.stop();
}

DeviceService::~DeviceService() {
    stopTraffic();
    stopLogcat();
    stopMonitor();
    jobs_.stop();
}

void DeviceService::setAdbPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    adb_.setPath(path.empty() ? "adb" : path);
}

std::string DeviceService::adbPath() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return adb_.path();
}

void DeviceService::refreshDevices() {
    jobs_.post([this] {
        std::string error;
        std::vector<adb::Device> list = adb_.devices(error);
        std::lock_guard<std::mutex> lock(mutex_);
        devices_ = std::move(list);
        error_ = error;
        // Keep the selection valid: default to the only/first online device.
        const bool stillThere = std::any_of(devices_.begin(), devices_.end(),
                                            [&](const adb::Device& d) { return d.serial == selected_; });
        if (!stillThere) {
            selected_.clear();
            for (const adb::Device& d : devices_)
                if (d.state == "device") {
                    selected_ = d.serial;
                    break;
                }
        }
    });
}

std::vector<adb::Device> DeviceService::devices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_;
}

std::string DeviceService::lastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return error_;
}

void DeviceService::select(const std::string& serial) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (serial != selected_) {
        selected_ = serial;
        processes_.clear();
        jdwpPids_.clear();
    }
}

std::string DeviceService::selected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return selected_;
}

void DeviceService::refreshProcesses() {
    jobs_.post([this] {
        const std::string serial = selected();
        if (serial.empty()) return;
        std::string error, jerr;
        std::vector<adb::ProcessInfo> list = adb_.processes(serial, error);
        std::vector<int> jdwp = adb_.jdwpPids(serial, 1200, jerr);
        std::sort(list.begin(), list.end(),
                  [](const adb::ProcessInfo& a, const adb::ProcessInfo& b) { return a.name < b.name; });
        std::lock_guard<std::mutex> lock(mutex_);
        if (serial != selected_) return;  // selection changed meanwhile
        processes_ = std::move(list);
        jdwpPids_ = std::move(jdwp);
        error_ = error;
    });
}

std::vector<adb::ProcessInfo> DeviceService::processes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return processes_;
}

std::vector<int> DeviceService::debuggablePids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return jdwpPids_;
}

DeviceService::LogEntry DeviceService::parseLogLine(const std::string& line) {
    LogEntry e;
    // "MM-DD HH:MM:SS.mmm  PID  TID L TAG: message"
    if (line.size() < 20 || line[2] != '-' || line[5] != ' ') {
        e.level = 'I';
        e.message = line;
        return e;
    }
    e.time = line.substr(0, 18);
    std::istringstream in(line.substr(18));
    std::string level;
    in >> e.pid >> e.tid >> level;
    e.level = level.empty() ? 'I' : level[0];
    std::string rest;
    std::getline(in, rest);
    const size_t start = rest.find_first_not_of(' ');
    rest = start == std::string::npos ? std::string() : rest.substr(start);
    const size_t colon = rest.find(": ");
    if (colon != std::string::npos) {
        e.tag = rest.substr(0, colon);
        while (!e.tag.empty() && e.tag.back() == ' ') e.tag.pop_back();
        e.message = rest.substr(colon + 2);
    } else {
        e.message = rest;
    }
    return e;
}

bool DeviceService::startLogcat(const std::string& serial, std::string& error) {
    if (!adb::validSerial(serial)) {
        error = "invalid device serial";
        return false;
    }
    stopLogcat();
    logcatSerial_ = serial;
    std::vector<std::string> argv{adbPath(), "-s", serial, "logcat", "-v", "threadtime", "-T", "2000"};
    ChildProcess child = ChildProcess::spawn(argv);
    if (!child.valid()) {
        error = "adb could not be started";
        return false;
    }
    logStop_ = false;
    logcatRunning_ = true;
    {
        std::lock_guard<std::mutex> lock(logHandleMutex_);
        logKill_ = child.killHandle();
    }
    logThread_ = std::thread([this, c = std::move(child)]() mutable {
        c.readAll(
            [this](std::string line) {
                if (line.empty() || line.rfind("--------- ", 0) == 0) return;
                LogEntry e = parseLogLine(line);
                std::lock_guard<std::mutex> lock(logMutex_);
                e.seq = ++logSeq_;
                log_.push_back(std::move(e));
                if (log_.size() > kLogCapacity) log_.pop_front();  // bounded: oldest entries go first
            },
            4096);
        c.waitForExit();
        {
            std::lock_guard<std::mutex> lock(logHandleMutex_);
            logKill_ = ChildProcess::Handle{};
        }
        logcatRunning_ = false;
    });
    return true;
}

void DeviceService::stopLogcat() {
    logStop_ = true;
    {
        std::lock_guard<std::mutex> lock(logHandleMutex_);
        if (logKill_) ChildProcess::killByHandle(logKill_);
    }
    if (logThread_.joinable()) logThread_.join();
    logcatRunning_ = false;
}

void DeviceService::clearLog() {
    std::lock_guard<std::mutex> lock(logMutex_);
    log_.clear();
    std::deque<LogEntry>().swap(log_);  // give the memory back
}

uint64_t DeviceService::logHead() const {
    std::lock_guard<std::mutex> lock(logMutex_);
    return logSeq_;
}

std::vector<DeviceService::LogEntry> DeviceService::logEntries(uint64_t since, const LogFilter& filter,
                                                               size_t maxEntries) const {
    static const std::string kLevels = "VDIWEF";
    const size_t minRank = kLevels.find(filter.minLevel) == std::string::npos ? 0 : kLevels.find(filter.minLevel);
    std::vector<LogEntry> out;
    std::lock_guard<std::mutex> lock(logMutex_);
    for (auto it = log_.rbegin(); it != log_.rend() && out.size() < maxEntries; ++it) {
        if (it->seq <= since) break;
        const size_t rank = kLevels.find(it->level);
        if (rank != std::string::npos && rank < minRank) continue;
        if (filter.pid && it->pid != filter.pid) continue;
        if (!filter.tag.empty() && tex::ciFind(it->tag, filter.tag) == std::string_view::npos) continue;
        if (!filter.text.empty() && tex::ciFind(it->message, filter.text) == std::string_view::npos &&
            tex::ciFind(it->tag, filter.text) == std::string_view::npos)
            continue;
        out.push_back(*it);
    }
    std::reverse(out.begin(), out.end());
    return out;
}

void DeviceService::startMonitor(const std::string& serial, int pid) {
    stopMonitor();
    {
        std::lock_guard<std::mutex> lock(sampleMutex_);
        samples_.clear();
    }
    monitorStop_ = false;
    monitorRunning_ = true;
    monitorPid_ = pid;
    monitorThread_ = std::thread([this, serial, pid] {
        const auto start = std::chrono::steady_clock::now();
        adb::ProcStat prev;
        while (!monitorStop_.load()) {
            std::string error;
            adb::ProcStat st = adb_.procStat(serial, pid, error);
            if (st.ok) {
                Sample s;
                s.t = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
                if (prev.ok && st.cpuTotalJiffies > prev.cpuTotalJiffies)
                    s.cpuPercent = 100.0 * (double)(st.procJiffies - prev.procJiffies) /
                                   (double)(st.cpuTotalJiffies - prev.cpuTotalJiffies);
                s.rssKb = st.rssKb;
                s.threads = st.threads;
                std::lock_guard<std::mutex> lock(sampleMutex_);
                samples_.push_back(s);
                if (samples_.size() > kSampleCapacity) samples_.pop_front();
                prev = st;
            } else if (!error.empty() || !st.ok) {
                break;  // process gone / device disconnected
            }
            std::unique_lock<std::mutex> lock(monitorWaitMutex_);
            monitorWait_.wait_for(lock, std::chrono::seconds(1), [&] { return monitorStop_.load(); });
        }
        monitorRunning_ = false;
    });
}

void DeviceService::stopMonitor() {
    monitorStop_ = true;
    monitorWait_.notify_all();
    if (monitorThread_.joinable()) monitorThread_.join();
    monitorRunning_ = false;
}

std::vector<DeviceService::Sample> DeviceService::samples() const {
    std::lock_guard<std::mutex> lock(sampleMutex_);
    return std::vector<Sample>(samples_.begin(), samples_.end());
}
