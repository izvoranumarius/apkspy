#include "analysis/ApkAnalysis.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include "analysis/Dalvik.hpp"
#include "core/TextUtils.hpp"

namespace {

using dalvik::Flow;
using dalvik::Insn;
using dalvik::RefKind;

bool startsWith(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }

std::string toDescriptor(std::string_view name) {
    if (name.empty()) return {};
    return DexFile::javaToDescriptor(name);
}

// Registers an instruction writes (first register for most formats).
bool writesFirstRegister(uint8_t op) {
    if (op >= 0x01 && op <= 0x0d) return true;            // moves, move-result, move-exception
    if (op >= 0x12 && op <= 0x1c) return true;            // consts
    if (op == 0x1f) return false;                         // check-cast keeps the value
    if (op >= 0x20 && op <= 0x23) return true;            // instance-of, array-length, new-*
    if (op >= 0x2d && op <= 0x31) return true;            // cmp*
    if (op >= 0x44 && op <= 0x4a) return true;            // aget*
    if (op >= 0x52 && op <= 0x58) return true;            // iget*
    if (op >= 0x60 && op <= 0x66) return true;            // sget*
    if (op >= 0x7b && op <= 0xe2) return true;            // arithmetic
    if (op == 0xfe || op == 0xff) return true;
    return false;
}

bool isWideWrite(uint8_t op) {
    return op == 0x04 || op == 0x05 || op == 0x06 || op == 0x0b || (op >= 0x16 && op <= 0x19) || op == 0x45 ||
           op == 0x53 || op == 0x61 || op == 0x7d || op == 0x7e || op == 0x80 || op == 0x81 || op == 0x83 ||
           op == 0x86 || op == 0x88 || op == 0x89 || op == 0x8b ||
           (op >= 0x9b && op <= 0xa5) || (op >= 0xab && op <= 0xaf) || (op >= 0xbb && op <= 0xc5) ||
           (op >= 0xcb && op <= 0xcf);
}

struct TryRange {
    uint32_t start, end;
    std::vector<uint32_t> handlers;
};

// Parses the try/catch tables that follow a code item's instructions.
std::vector<TryRange> parseTries(const DexFile& dex, const DexFile::CodeItem& code) {
    std::vector<TryRange> out;
    if (code.tries == 0) return out;
    const uint8_t* d = dex.data();
    const size_t size = dex.sizeBytes();
    size_t pos = static_cast<size_t>(code.offset) + 16 + static_cast<size_t>(code.insnsSize) * 2;
    if (code.insnsSize & 1) pos += 2;  // padding to 4 bytes
    const size_t triesAt = pos;
    const size_t handlersAt = triesAt + static_cast<size_t>(code.tries) * 8;
    if (handlersAt > size) return out;
    for (uint32_t t = 0; t < code.tries; ++t) {
        const uint8_t* p = d + triesAt + static_cast<size_t>(t) * 8;
        TryRange r;
        r.start = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
        const uint32_t count = static_cast<uint32_t>(p[4] | p[5] << 8);
        const uint32_t handlerOff = static_cast<uint32_t>(p[6] | p[7] << 8);
        r.end = r.start + count;
        size_t hp = handlersAt + handlerOff;
        int32_t n = 0;
        if (hp < size && leb::readSleb(d, size, hp, n)) {
            const int32_t pairs = n < 0 ? -n : n;
            for (int32_t k = 0; k < pairs && k < 4096; ++k) {
                uint32_t type = 0, addr = 0;
                if (!leb::readUleb(d, size, hp, type) || !leb::readUleb(d, size, hp, addr)) break;
                r.handlers.push_back(addr);
            }
            if (n <= 0) {
                uint32_t addr = 0;
                if (leb::readUleb(d, size, hp, addr)) r.handlers.push_back(addr);
            }
        }
        out.push_back(std::move(r));
    }
    return out;
}

double entropy(std::string_view s) {
    int counts[256] = {};
    for (unsigned char const c : s) counts[c]++;
    double h = 0;
    for (int const c : counts)
        if (c) {
            const double p = static_cast<double>(c) / static_cast<double>(s.size());
            h -= p * std::log2(p);
        }
    return h;
}

}  // namespace

std::shared_ptr<ApkAnalysis> ApkAnalysis::build(std::vector<std::shared_ptr<DexFile>> dexes,
                                                const std::atomic<bool>& stop, std::atomic<size_t>* progressDone,
                                                std::atomic<size_t>* progressTotal) {
    auto a = std::make_shared<ApkAnalysis>();
    a->dexes_ = std::move(dexes);
    size_t total = 0;
    for (const auto& d : a->dexes_) total += d->classes().size();
    if (progressTotal) *progressTotal = total;
    a->classes_.reserve(total);

    DexFile::ClassData data;
    size_t done = 0;
    for (uint16_t di = 0; di < static_cast<uint16_t>(a->dexes_.size()); ++di) {
        const DexFile& dex = *a->dexes_[di];
        for (uint32_t ci = 0; ci < static_cast<uint32_t>(dex.classes().size()); ++ci) {
            if (stop.load()) return nullptr;
            a->classes_.push_back({di, ci});
            if (progressDone) *progressDone = ++done;
            if (!dex.classData(dex.classes()[ci], data)) continue;
            for (const auto& m : data.methods) {
                ++a->stats_.methods;
                DexFile::CodeItem code;
                if (!m.codeOff || !dex.codeItem(m.codeOff, code)) continue;
                ++a->stats_.methodsWithCode;
                a->stats_.codeBytes += static_cast<size_t>(code.insnsSize) * 2;
                for (uint32_t pc = 0; pc < code.insnsSize;) {
                    const Insn in = dalvik::decode(code, pc);
                    pc += std::max<uint32_t>(in.size, 1);
                    if (!in.valid || in.payload) continue;
                    ++a->stats_.instructions;
                    const auto& info = dalvik::opInfo(in.opcode);
                    XrefKind kind;
                    switch (info.ref) {
                    case RefKind::Method: kind = XrefKind::Call; break;
                    case RefKind::String: kind = XrefKind::String; break;
                    case RefKind::Type: kind = XrefKind::Type; break;
                    case RefKind::Field:
                        kind = ((in.opcode >= 0x59 && in.opcode <= 0x5f) || in.opcode >= 0x67) ? XrefKind::FieldWrite
                                                                                                : XrefKind::FieldRead;
                        break;
                    default: continue;
                    }
                    if (in.index == DexFile::kNoIndex) continue;
                    a->xrefs_.push_back({in.index, m.methodIdx, in.pc, di, kind});
                }
            }
        }
    }
    std::sort(a->classes_.begin(), a->classes_.end(), [&](const ClassEntry& x, const ClassEntry& y) {
        return a->classDescriptor(x) < a->classDescriptor(y);
    });
    std::sort(a->xrefs_.begin(), a->xrefs_.end(), [](const Xref& x, const Xref& y) {
        if (x.kind != y.kind) return x.kind < y.kind;
        if (x.dex != y.dex) return x.dex < y.dex;
        if (x.target != y.target) return x.target < y.target;
        if (x.from != y.from) return x.from < y.from;
        return x.pc < y.pc;
    });
    a->xrefs_.shrink_to_fit();
    a->stats_.classes = a->classes_.size();
    a->stats_.xrefs = a->xrefs_.size();
    return a;
}

std::string_view ApkAnalysis::classDescriptor(const ClassEntry& c) const {
    const DexFile& dex = *dexes_[c.dex];
    return dex.typeDescriptor(dex.classes()[c.def].classIdx);
}

const DexFile::ClassDef& ApkAnalysis::classDef(const ClassEntry& c) const { return dexes_[c.dex]->classes()[c.def]; }

const ApkAnalysis::ClassEntry* ApkAnalysis::findClass(std::string_view name) const {
    const std::string desc = toDescriptor(name);
    auto it = std::lower_bound(classes_.begin(), classes_.end(), desc,
                               [&](const ClassEntry& c, const std::string& d) { return classDescriptor(c) < d; });
    if (it != classes_.end() && classDescriptor(*it) == desc) return &*it;
    return nullptr;
}

std::vector<const ApkAnalysis::ClassEntry*> ApkAnalysis::searchClasses(std::string_view needle, size_t limit) const {
    std::vector<const ClassEntry*> out;
    std::string n(needle);
    std::replace(n.begin(), n.end(), '.', '/');
    for (const ClassEntry& c : classes_) {
        if (out.size() >= limit) break;
        if (n.empty() || tex::ciFind(classDescriptor(c), n) != std::string_view::npos) out.push_back(&c);
    }
    return out;
}

std::string ApkAnalysis::renamesAsMapping(const std::vector<std::pair<std::string, std::string>>& symbols, size_t* matched,
                                          const mapping::Mapping* loaded) const {
    const std::map<std::string, std::string> renames(symbols.begin(), symbols.end());
    std::set<std::string> used;
    // The user's name for something shown as `shown` (the loaded mapping's name) and defined as `app`, else nullptr.
    const auto renamed = [&](const std::string& shown, const std::string& app) -> const std::string* {
        for (const std::string* key : {&shown, &app}) {
            const auto it = renames.find(*key);
            if (it == renames.end() || it->second.empty()) continue;
            used.insert(*key);
            return &it->second;
        }
        return nullptr;
    };
    // The dotted class name as the user sees it, renamed parts replaced: a simple name, or the pieces around '$'.
    const auto className = [&](const std::string& java) {
        const std::string base = loaded ? loaded->originalClass(java) : java;
        const size_t dot = base.find_last_of('.');
        const std::string package = dot == std::string::npos ? std::string() : base.substr(0, dot + 1);
        const std::string simple = base.substr(package.size());
        const std::string appSimple = java.substr(java.find_last_of('.') + 1);
        if (const std::string* whole = renamed(simple, appSimple)) return package + *whole;
        std::string out;
        size_t start = 0;
        while (true) {
            const size_t dollar = simple.find('$', start);
            const std::string part = simple.substr(start, dollar == std::string::npos ? std::string::npos : dollar - start);
            const std::string* r = renamed(part, part);
            out += r ? *r : part;
            if (dollar == std::string::npos) break;
            out += '$';
            start = dollar + 1;
        }
        return package + out;
    };
    // A type as a mapping file writes it ("int", "java.lang.String[]"): once with the new names, once as the loaded
    // mapping has it (to look members up).
    const auto typeName = [&](std::string_view descriptor, bool newNames) {
        size_t dimensions = 0;
        while (!descriptor.empty() && descriptor.front() == '[') descriptor.remove_prefix(1), ++dimensions;
        std::string name = DexFile::descriptorToJava(descriptor);
        if (!descriptor.empty() && descriptor.front() == 'L') name = newNames ? className(name) : loaded ? loaded->originalClass(name) : name;
        for (size_t i = 0; i < dimensions; ++i) name += "[]";
        return name;
    };

    std::string out;
    for (const ClassEntry& c : classes_) {
        const DexFile& dex = *dexes_[c.dex];
        const std::string java = DexFile::descriptorToJava(classDescriptor(c));
        const std::string original = className(java);
        std::string members;
        std::set<std::string> seen;
        DexFile::ClassData data;
        if (dex.classData(classDef(c), data)) {
            for (const DexFile::EncodedField& f : data.fields) {
                const std::string name(dex.fieldName(f.fieldIdx));
                const std::string_view type = dex.typeDescriptor(dex.fieldType(f.fieldIdx));
                std::string shown = loaded ? loaded->originalMember(java, name, typeName(type, false) + " ", false) : std::string();
                if (shown.empty()) shown = name;
                if (const std::string* r = renamed(shown, name)) {
                    const std::string line = "    " + typeName(type, true) + " " + *r + " -> " + name + "\n";
                    if (seen.insert(line).second) members += line;
                }
            }
            for (const DexFile::EncodedMethod& m : data.methods) {
                const std::string name(dex.methodName(m.methodIdx));
                if (name.empty() || name.front() == '<') continue;
                const uint32_t proto = dex.methodProto(m.methodIdx);
                std::string args, mappedArgs;
                for (uint32_t p : dex.protoParameters(proto)) {
                    args += (args.empty() ? "" : ",") + typeName(dex.typeDescriptor(p), true);
                    mappedArgs += (mappedArgs.empty() ? "" : ",") + typeName(dex.typeDescriptor(p), false);
                }
                std::string shown = loaded ? loaded->originalMember(java, name, "(" + mappedArgs + ")", true) : std::string();
                if (shown.empty()) shown = name;
                const std::string* r = renamed(shown, name);
                if (!r) continue;
                const std::string line = "    " + typeName(dex.typeDescriptor(dex.protoReturnType(proto)), true) + " " + *r + "(" + args +
                                         ") -> " + name + "\n";
                if (seen.insert(line).second) members += line;
            }
        }
        const std::string before = loaded ? loaded->originalClass(java) : java;
        if (original != before || !members.empty()) out += original + " -> " + java + ":\n" + members;
    }
    if (matched) *matched = used.size();
    if (out.empty()) return out;
    return "# Names chosen in ApkSpy. Variable renames and native-library names have no place in this format.\n" + out;
}

std::vector<ApkAnalysis::LogSite> ApkAnalysis::logSites(size_t limit) const {
    static const std::pair<const char*, const char*> logs[] = {
        {"Landroid/util/Log;", "d"}, {"Landroid/util/Log;", "v"},   {"Landroid/util/Log;", "i"},       {"Landroid/util/Log;", "w"},
        {"Landroid/util/Log;", "e"}, {"Landroid/util/Log;", "wtf"}, {"Ljava/io/PrintStream;", "println"}, {"Ljava/io/PrintStream;", "print"}};
    const auto isLog = [](const std::string& callee) {
        for (const auto& [cls, name] : logs)
            if (callee.rfind(std::string(cls) + "->" + name + "(", 0) == 0) return true;
        return false;
    };
    std::set<std::pair<uint16_t, uint32_t>> methods;  // (dex, method index) that call one of them
    for (const auto& [cls, name] : logs)
        for (const XrefHit& hit : callersOf(cls, name, {}, limit)) methods.insert({hit.from.dex, hit.from.method});

    std::vector<LogSite> out;
    for (const auto& [dexIndex, methodIdx] : methods) {
        if (out.size() >= limit) break;
        std::string cls, name, proto;
        const std::string signature = methodSignature(CodeRef{dexIndex, methodIdx, 0});
        if (!splitMethodRef(signature, cls, name, proto)) continue;
        for (const MethodDef& def : findMethodDefs(cls, name, proto)) {
            if (def.dex != dexIndex) continue;
            std::map<uint32_t, std::vector<std::pair<int, std::string>>> args;
            for (ConstArgCall& call : constantArguments(def)) {
                for (auto& a : call.args)  // string constants come quoted, as the listing shows them
                    if (a.second.size() >= 2 && a.second.front() == '"' && a.second.back() == '"') a.second = a.second.substr(1, a.second.size() - 2);
                args[call.pc] = std::move(call.args);
            }
            std::vector<std::string> appended, calls;
            for (const Callee& c : calleesOf(def)) {
                const auto constant = args.find(c.pc);
                if (!isLog(c.signature)) {
                    if (constant != args.end() && c.signature.find("Ljava/lang/String") == 0)
                        for (const auto& a : constant->second) appended.push_back(a.second);
                    else if (constant != args.end() && c.signature.find(";->append(") != std::string::npos)
                        for (const auto& a : constant->second) appended.push_back(a.second);
                    calls.push_back(c.signature);
                    continue;
                }
                LogSite site;
                site.ref = {dexIndex, methodIdx, c.pc};
                site.method = signature;
                site.callee = c.signature;
                // The message is the second argument of Log.x(tag, message) and of println(message) after its receiver.
                const bool oneString = c.signature.find(";->print") != std::string::npos;
                const bool noMessage = c.signature.find("println()V") != std::string::npos;
                if (constant != args.end())
                    for (const auto& a : constant->second) {
                        if (a.first == 0 && oneString) continue;  // the stream itself
                        site.constants.push_back(a.second);
                        if (a.first == 1) site.messageConstant = true;
                    }
                if (noMessage) site.messageConstant = true;
                site.appended = std::move(appended);
                site.calls = std::move(calls);
                appended.clear();
                calls.clear();
                out.push_back(std::move(site));
                if (out.size() >= limit) break;
            }
            break;
        }
    }
    return out;
}

namespace {

// Follows values that name something sensitive through one method's registers: a forward data-flow pass over its
// control-flow graph. App methods are summarised by what they can return and what they put into the objects they are
// given (a list or map passed in); a logged parameter is looked up at the method's callers. A field read brings what
// the app's code stores in that field anywhere (directly, or by adding to the collection the field holds), with the
// stored parameters looked up at the storing method's callers. Native code and reflection are not followed.
class Taint {
public:
    using Labels = std::set<std::string>;
    static constexpr const char* kParameter = "\x01";  // "\x01<n>": whatever the n-th declared argument register holds
    static constexpr uint32_t kParameterObject = 0x80000000u;  // object number of the n-th argument: this + n

    Taint(const ApkAnalysis& a, const ApkAnalysis::Classifier& classify) : A(a), classify_(classify) {}

    struct Result {
        std::map<uint32_t, Labels> arguments;  // invoke pc -> labels of the message argument(s) asked for
        Labels returned;
        std::map<uint32_t, Labels> intoParameters;  // argument register n -> what was put into the object passed there
        std::map<std::string, Labels> intoFields;   // "Lcls;->name" -> what was stored in the field or its object
    };
    struct Summary {
        Labels returned;
        std::map<uint32_t, Labels> intoParameters;
    };

    bool defOf(uint16_t dexIndex, uint32_t methodIdx, ApkAnalysis::MethodDef& out) const {
        std::string cls, name, proto;
        if (!ApkAnalysis::splitMethodRef(A.methodSignature(ApkAnalysis::CodeRef{dexIndex, methodIdx, 0}), cls, name, proto)) return false;
        for (const ApkAnalysis::MethodDef& d : A.findMethodDefs(cls, name, proto))
            if (d.dex == dexIndex) {
                out = d;
                return true;
            }
        return false;
    }

    // What the callers of `signature` pass as argument register `position`, each with `suffix(caller)` appended.
    Labels fromCallers(const std::string& signature, int position, const std::function<std::string(const std::string&)>& suffix, int depth) {
        Labels out;
        std::string cls, name, proto;
        if (!ApkAnalysis::splitMethodRef(signature, cls, name, proto) || ++callerLookups_ > 3000) return out;
        size_t looked = 0;
        for (const ApkAnalysis::XrefHit& hit : A.callersOf(cls, name, proto, 40)) {
            ApkAnalysis::MethodDef caller;
            if (!defOf(hit.from.dex, hit.from.method, caller) || ++looked > 20) continue;
            const Result c = run(
                caller, [&](uint32_t pc, const std::string&) { return pc == hit.from.pc ? std::vector<int>{position} : std::vector<int>(); }, depth + 1);
            const auto at = c.arguments.find(hit.from.pc);
            if (at == c.arguments.end()) continue;
            for (const std::string& l : at->second)
                if (!l.empty() && l[0] != kParameter[0]) out.insert(l + suffix(A.methodSignature(hit.from)));
        }
        return out;
    }

    // `wanted(callee signature)` gives the argument positions to record at an invoke (empty: none).
    Result run(const ApkAnalysis::MethodDef& m, const std::function<std::vector<int>(uint32_t pc, const std::string&)>& wanted, int depth) {
        Result result;
        const DexFile& dex = *A.dexes()[m.dex];
        DexFile::CodeItem code;
        if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code) || code.insnsSize > 20000 || code.registers > 1024) return result;
        const std::vector<ApkAnalysis::BasicBlock> blocks = A.controlFlowGraph(m);
        if (blocks.empty() || blocks.size() > 2000) return result;
        Result* const outer = result_;
        result_ = &result;
        struct Restore {
            Result*& at;
            Result* value;
            ~Restore() { at = value; }
        } restore{result_, outer};
        State entry;
        for (uint32_t i = 0; i < code.ins; ++i) {
            entry.labels[code.registers - code.ins + i] = {kParameter + std::to_string(i)};
            entry.object[code.registers - code.ins + i] = kParameterObject + i;
        }
        std::vector<State> in(blocks.size());
        std::vector<char> queued(blocks.size(), 0), reached(blocks.size(), 0);
        in[0] = entry;
        reached[0] = 1;
        std::vector<size_t> work{0};
        queued[0] = 1;
        for (size_t steps = 0; !work.empty() && steps < blocks.size() * 8 + 32; ++steps) {
            const size_t b = work.back();
            work.pop_back();
            queued[b] = 0;
            State state = in[b];
            Labels last;  // what the pending move-result receives
            for (uint32_t pc = blocks[b].startPc; pc < blocks[b].endPc && pc < code.insnsSize;) {
                const dalvik::Insn insn = dalvik::decode(code, pc);
                pc += std::max<uint32_t>(insn.size, 1);
                if (insn.valid && !insn.payload) step(dex, insn, state, last, wanted, result, depth);
            }
            const auto flow = [&](uint32_t to) {
                if (to >= blocks.size()) return;
                bool changed = false;
                if (!reached[to]) in[to] = state, reached[to] = 1, changed = true;  // the first path brings everything it knows
                else changed = merge(in[to], state);
                if (changed && !queued[to]) queued[to] = 1, work.push_back(to);
            };
            for (uint32_t s : blocks[b].successors) flow(s);
            for (uint32_t h : blocks[b].exceptional) flow(h);
        }
        return result;
    }

    // What `m` can return and put into its arguments' objects: sensitive names, and parameters it passes through.
    const Summary& summary(const ApkAnalysis::MethodDef& m, int depth) {
        const std::pair<uint16_t, uint32_t> key{m.dex, m.method.methodIdx};
        const auto found = summaries_.find(key);
        if (found != summaries_.end()) return found->second;
        static const Summary none;
        if (depth >= 3 || analysed_ >= 4000) return none;  // too deep here; a shallower call may still look
        ++analysed_;
        summaries_[key];  // recursion sees an empty summary
        Result r = run(m, [](uint32_t, const std::string&) { return std::vector<int>(); }, depth + 1);
        summaries_[key] = Summary{std::move(r.returned), std::move(r.intoParameters)};
        return summaries_[key];
    }

    // What the app stores in field `cls->name` anywhere: written to it, or put into the object it holds.
    const Labels& stored(const std::string& cls, const std::string& name, int depth) {
        const std::string key = cls + "->" + name;
        static const Labels none;
        const auto found = fields_.find(key);
        if (found != fields_.end()) return found->second;
        if (depth >= 2 || fieldLookups_ > 3000) return none;  // too deep here; a shallower read may still look
        ++fieldLookups_;
        fields_[key];  // recursion sees nothing stored
        Labels out;
        std::set<std::pair<uint16_t, uint32_t>> seen;
        size_t methods = 0;
        for (const ApkAnalysis::XrefHit& hit : A.fieldAccesses(cls, name, 80)) {
            if (!seen.insert({hit.from.dex, hit.from.method}).second || ++methods > 24) continue;
            ApkAnalysis::MethodDef def;
            if (!defOf(hit.from.dex, hit.from.method, def)) continue;
            const Result r = run(def, [](uint32_t, const std::string&) { return std::vector<int>(); }, depth + 1);
            const auto it = r.intoFields.find(key);
            if (it == r.intoFields.end()) continue;
            const std::string writer = A.methodSignature(hit.from);
            const auto suffix = [&](const std::string& by) { return ", kept in field " + name + " by " + by; };
            for (const std::string& label : it->second) {
                if (label.empty()) continue;
                if (label[0] != kParameter[0]) {
                    add(out, {label.find(", kept in field ") == std::string::npos ? label + suffix(writer) : label});
                } else {  // the method stores what it is given: what do its callers pass?
                    add(out, fromCallers(writer, std::atoi(label.c_str() + 1), suffix, depth + 1));
                }
            }
        }
        fields_[key] = std::move(out);
        return fields_[key];
    }

private:
    struct State {
        std::map<uint32_t, Labels> labels;
        std::map<uint32_t, std::string> text;  // registers holding a known string constant
        std::map<uint32_t, uint32_t> object;   // registers known to hold the same object share a number
        std::map<uint32_t, std::string> from;  // registers holding the object read from an app field ("Lcls;->name")
    };

    // The object in `reg` now holds `labels`: so does every register referring to it, the argument it came in as and
    // the field it was read from.
    void taint(State& st, uint32_t reg, const Labels& labels) {
        if (labels.empty()) return;
        add(st.labels[reg], labels);
        const auto field = st.from.find(reg);
        if (field != st.from.end() && result_) add(result_->intoFields[field->second], labels);
        const auto id = st.object.find(reg);
        if (id == st.object.end()) return;
        if (id->second >= kParameterObject && result_) add(result_->intoParameters[id->second - kParameterObject], labels);
        for (const auto& [other, number] : st.object) {
            if (number != id->second || other == reg) continue;
            add(st.labels[other], labels);
            const auto alias = st.from.find(other);
            if (alias != st.from.end() && result_) add(result_->intoFields[alias->second], labels);
        }
    }

    static bool add(Labels& to, const Labels& from) {
        bool changed = false;
        for (const std::string& l : from)
            if (to.size() < 8 && to.insert(l).second) changed = true;
        return changed;
    }

    static bool merge(State& to, const State& from) {
        bool changed = false;
        for (const auto& [reg, labels] : from.labels) changed = add(to.labels[reg], labels) || changed;
        for (auto it = to.text.begin(); it != to.text.end();) {  // a constant survives only when every path agrees
            const auto other = from.text.find(it->first);
            if (other == from.text.end() || other->second != it->second) it = to.text.erase(it), changed = true;
            else ++it;
        }
        for (auto it = to.object.begin(); it != to.object.end();) {
            const auto other = from.object.find(it->first);
            if (other == from.object.end() || other->second != it->second) it = to.object.erase(it), changed = true;
            else ++it;
        }
        for (auto it = to.from.begin(); it != to.from.end();) {
            const auto other = from.from.find(it->first);
            if (other == from.from.end() || other->second != it->second) it = to.from.erase(it), changed = true;
            else ++it;
        }
        return changed;
    }

    std::string sensitive(std::string_view name) const { return classify_ ? classify_(name) : std::string(); }

    void step(const DexFile& dex, const dalvik::Insn& in, State& st, Labels& last,
              const std::function<std::vector<int>(uint32_t, const std::string&)>& wanted, Result& result, int depth) {
        const uint8_t op = in.opcode;
        const auto& info = dalvik::opInfo(op);
        const auto labelsOf = [&](uint32_t r) {
            const auto it = st.labels.find(r);
            return it == st.labels.end() ? Labels() : it->second;
        };
        const auto set = [&](uint32_t r, Labels l) {
            st.text.erase(r);
            st.object.erase(r);
            st.from.erase(r);
            if (l.empty()) st.labels.erase(r);
            else st.labels[r] = std::move(l);
        };
        if (info.flow == dalvik::Flow::Invoke && info.ref == dalvik::RefKind::Method && in.index < dex.methodCount()) {
            std::vector<uint32_t> regs;
            for (uint32_t k = 0; k < in.regCount; ++k) regs.push_back(in.range ? in.regs[0] + k : in.regs[k]);
            const std::string sig = dex.methodSignature(in.index);
            for (int position : wanted(in.pc, sig))
                if (position >= 0 && static_cast<size_t>(position) < regs.size()) add(result.arguments[in.pc], labelsOf(regs[static_cast<size_t>(position)]));
            call(dex, in, sig, regs, st, last, depth);
            return;
        }
        if (op == 0x24 || op == 0x25) {  // filled-new-array
            last.clear();
            for (uint32_t k = 0; k < in.regCount; ++k) add(last, labelsOf(in.range ? in.regs[0] + k : in.regs[k]));
            return;
        }
        const uint32_t a = in.regCount ? in.regs[0] : 0;
        if (op >= 0x01 && op <= 0x09) {
            const uint32_t b = in.regs[1];
            const auto text = st.text.find(b);
            const bool known = text != st.text.end();
            const std::string value = known ? text->second : std::string();
            const auto object = st.object.find(b);
            const uint32_t number = object != st.object.end() ? object->second : 0;
            const auto field = st.from.find(b);
            const std::string source = field != st.from.end() ? field->second : std::string();
            set(a, labelsOf(b));
            if (known) st.text[a] = value;
            if (number) st.object[a] = number;
            if (!source.empty()) st.from[a] = source;
        } else if (op >= 0x0a && op <= 0x0c) {
            set(a, last);
            if (lastObject_) st.object[a] = lastObject_;
            lastObject_ = 0;
        } else if (op == 0x0f || op == 0x10 || op == 0x11) {
            add(result.returned, labelsOf(a));
        } else if (op == 0x1a || op == 0x1b) {
            set(a, {});
            st.text[a] = dex.string(in.index);
        } else if ((op >= 0x12 && op <= 0x19) || op == 0x1c) {
            set(a, {});
        } else if (op == 0x22 || op == 0x23) {  // a new object
            set(a, {});
            st.object[a] = in.pc + 1;
        } else if (op >= 0x44 && op <= 0x4a) {  // aget
            set(a, labelsOf(in.regs[1]));
        } else if (op >= 0x4b && op <= 0x51) {  // aput: the array now holds it
            taint(st, in.regs[1], labelsOf(a));
        } else if ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66)) {  // iget / sget
            Labels l;
            std::string key;
            if (in.index < dex.fieldCount()) {
                const std::string_view type = dex.typeDescriptor(dex.fieldType(in.index));
                const std::string name(dex.fieldName(in.index));
                // Only data-carrying fields: a View called "passwordInput" is not the password.
                // Not int: resource and styleable indices ("Fragment_android_id") are ints named after what they index.
                const bool data = type == "Ljava/lang/String;" || type == "[C" || type == "[B" || type == "J" || type == "D" ||
                                  type == "Ljava/lang/CharSequence;";
                if (data && !sensitive(name).empty()) l.insert("field " + name);
                const std::string cls(dex.typeDescriptor(dex.fieldClass(in.index)));
                // What the app stores there, for fields that can carry data: text, bytes, collections, JSON, bundles.
                const bool carrier = data || type == "Ljava/lang/Object;" || startsWith(type, "Ljava/util/") ||
                                     startsWith(type, "Lorg/json/") || type == "Landroid/os/Bundle;" || type == "[Ljava/lang/String;";
                if (carrier && A.findClass(cls)) {
                    key = cls + "->" + name;
                    add(l, stored(cls, name, depth));
                }
            }
            set(a, std::move(l));
            if (!key.empty()) st.from[a] = key;
        } else if ((op >= 0x59 && op <= 0x5f) || (op >= 0x67 && op <= 0x6d)) {  // iput / sput
            if (in.index < dex.fieldCount() && result_) {
                const std::string cls(dex.typeDescriptor(dex.fieldClass(in.index)));
                if (A.findClass(cls)) add(result_->intoFields[cls + "->" + std::string(dex.fieldName(in.index))], labelsOf(a));
            }
        } else if (info.flow == dalvik::Flow::Normal && in.regCount > 0 && ((op >= 0x7b && op <= 0xe2) || op == 0x20 || op == 0x21)) {
            Labels l;
            for (uint32_t k = in.regCount >= 3 || op < 0xb0 || op > 0xcf ? 1 : 0; k < in.regCount; ++k) add(l, labelsOf(in.regs[k]));
            set(a, std::move(l));
        } else if (op == 0x0d) {
            set(a, {});
        }
    }

    void call(const DexFile& dex, const dalvik::Insn& in, const std::string& sig, const std::vector<uint32_t>& regs, State& st, Labels& last,
              int depth) {
        const uint8_t op = in.opcode;
        const bool isStatic = op == 0x71 || op == 0x77;
        const std::string cls(dex.typeDescriptor(dex.methodClass(in.index)));
        const std::string name(dex.methodName(in.index));
        const auto labelsOf = [&](uint32_t r) {
            const auto it = st.labels.find(r);
            return it == st.labels.end() ? Labels() : it->second;
        };
        const auto textOf = [&](size_t k) {
            if (k >= regs.size()) return std::string();
            const auto it = st.text.find(regs[k]);
            return it == st.text.end() ? std::string() : it->second;
        };
        const std::string proto = dex.protoDescriptor(dex.methodProto(in.index));
        const bool returnsValue = proto.back() != 'V';
        last.clear();
        lastObject_ = 0;

        // Platform sources.
        static const std::pair<const char*, const char*> sources[] = {
            {";->getDeviceId(", "the device id"},    {";->getImei(", "the IMEI"},
            {";->getSubscriberId(", "the IMSI"},     {";->getSimSerialNumber(", "the SIM serial number"},
            {";->getLine1Number(", "the phone number"}, {";->getLatitude(", "the location latitude"},
            {";->getLongitude(", "the location longitude"}, {";->getAccounts(", "the device accounts"},
            {";->getAccountsByType(", "the device accounts"}, {"Landroid/webkit/CookieManager;->getCookie(", "cookies"},
            {"Landroid/content/ClipboardManager;->getPrimaryClip(", "the clipboard"}};
        for (const auto& [pattern, what] : sources)
            if (sig.find(pattern) != std::string::npos) {
                last.insert(what);
                return;
            }
        // Values looked up by a telling key: preferences, intent extras, bundles, JSON, maps.
        if (returnsValue && !isStatic && regs.size() >= 2 && (name.rfind("get", 0) == 0 || name.rfind("opt", 0) == 0)) {
            const std::string key = textOf(1);
            if (!key.empty() && !sensitive(key).empty()) last.insert("the value stored as \"" + key + "\"");
        }
        // Getters named after the data.
        if (returnsValue && name.size() > 3 && name.rfind("get", 0) == 0 && proto.back() == ';') {
            const std::string what = sensitive(name.substr(3));
            // "getLocation" is mostly a place on screen or in a file: only the platform's Location counts.
            if (!what.empty() && (what != "location" || proto.find(")Landroid/location/Location;") != std::string::npos))
                last.insert(name + "()");
        }

        const bool app = A.findClass(cls) != nullptr;
        if (app) {
            const auto defs = A.findMethodDefs(cls, name, proto);
            // A summary's labels in the caller's terms: an argument passed through becomes what the caller passed.
            const auto resolve = [&](const Labels& labels) {
                Labels out;
                for (const std::string& label : labels) {
                    if (!label.empty() && label[0] == kParameter[0]) {
                        const size_t k = static_cast<size_t>(std::atoi(label.c_str() + 1));
                        if (k < regs.size()) add(out, labelsOf(regs[k]));
                    } else {
                        add(out, {label});
                    }
                }
                return out;
            };
            for (const auto& d : defs) {
                if (!d.method.codeOff) continue;
                const Summary s = summary(d, depth);  // a copy: summaries of other methods may be added meanwhile
                add(last, resolve(s.returned));
                for (const auto& [k, labels] : s.intoParameters)  // e.g. a helper that adds the IMEI to the list it is given
                    if (k < regs.size()) taint(st, regs[k], resolve(labels));
                break;
            }
            if (defs.empty() || name == "<init>")
                for (size_t k = 1; !isStatic && k < regs.size(); ++k) taint(st, regs[0], labelsOf(regs[k]));
            return;
        }
        // Library calls: what goes in can come out, and objects collect what they are given (StringBuilder, List, Map).
        Labels all;
        for (uint32_t r : regs) add(all, labelsOf(r));
        static const char* const swallow[] = {"length", "isEmpty", "equals", "hashCode", "size", "indexOf", "contains", "startsWith",
                                              "endsWith", "compareTo", "matches"};
        const bool measured = std::find_if(std::begin(swallow), std::end(swallow), [&](const char* s) { return name == s; }) != std::end(swallow);
        if (returnsValue && !measured) add(last, all);
        static const char* const store[] = {"put", "add", "append", "insert", "offer", "push", "set", "write"};
        const bool stores = name == "<init>" ||
                            std::find_if(std::begin(store), std::end(store), [&](const char* s) { return name.rfind(s, 0) == 0; }) != std::end(store);
        if (!isStatic && !regs.empty() && !measured && stores) {
            for (size_t k = 1; k < regs.size(); ++k) taint(st, regs[0], labelsOf(regs[k]));
            if (name == "append") {  // returns the builder itself
                add(last, labelsOf(regs[0]));
                const auto object = st.object.find(regs[0]);
                if (object != st.object.end()) lastObject_ = object->second;
            }
        }
    }

    const ApkAnalysis& A;
    const ApkAnalysis::Classifier& classify_;
    std::map<std::pair<uint16_t, uint32_t>, Summary> summaries_;
    std::map<std::string, Labels> fields_;  // stored(): field -> what the app puts there
    Result* result_ = nullptr;              // the run in progress
    int analysed_ = 0, fieldLookups_ = 0, callerLookups_ = 0;
    uint32_t lastObject_ = 0;  // the object the pending move-result refers to
};

}  // namespace

void ApkAnalysis::traceLogs(std::vector<LogSite>& sites, const Classifier& classify) const {
    Taint taint(*this, classify);
    // Message positions of the log calls: Log.x(tag, message[, throwable]); print(ln)(message) after the stream.
    const auto isLog = [](const std::string& callee) {
        return callee.rfind("Landroid/util/Log;->", 0) == 0 || callee.rfind("Ljava/io/PrintStream;->print", 0) == 0;
    };
    std::map<std::pair<uint16_t, uint32_t>, std::vector<size_t>> byMethod;
    for (size_t i = 0; i < sites.size(); ++i) byMethod[{sites[i].ref.dex, sites[i].ref.method}].push_back(i);

    for (const auto& [key, indices] : byMethod) {
        MethodDef def;
        if (!taint.defOf(key.first, key.second, def)) continue;
        const Taint::Result r = taint.run(
            def, [&](uint32_t, const std::string& callee) { return isLog(callee) ? std::vector<int>{1, 2} : std::vector<int>(); }, 0);
        for (size_t i : indices) {
            LogSite& site = sites[i];
            site.traced = true;
            const auto found = r.arguments.find(site.ref.pc);
            if (found == r.arguments.end()) continue;
            for (const std::string& label : found->second) {
                if (label.empty() || label[0] != Taint::kParameter[0]) {
                    site.flows.push_back(label);
                    continue;
                }
                // The message came in as a parameter: what do the callers pass?
                for (const std::string& l : taint.fromCallers(site.method, std::atoi(label.c_str() + 1),
                                                              [](const std::string& by) { return ", passed in by " + by; }, 0))
                    site.flows.push_back(l);
            }
            std::sort(site.flows.begin(), site.flows.end());
            site.flows.erase(std::unique(site.flows.begin(), site.flows.end()), site.flows.end());
        }
    }
}

std::vector<ApkAnalysis::MethodDef> ApkAnalysis::methodsOf(const ClassEntry& c) const {
    std::vector<MethodDef> out;
    DexFile::ClassData data;
    if (!dexes_[c.dex]->classData(classDef(c), data)) return out;
    out.reserve(data.methods.size());
    for (const auto& m : data.methods) out.push_back({c.dex, m});
    return out;
}

bool ApkAnalysis::splitMethodRef(std::string_view ref, std::string& cls, std::string& name, std::string& proto) {
    cls.clear();
    name.clear();
    proto.clear();
    const size_t arrow = ref.find("->");
    if (arrow != std::string_view::npos) {
        cls.assign(ref.substr(0, arrow));
        std::string_view const rest = ref.substr(arrow + 2);
        const size_t paren = rest.find('(');
        if (paren == std::string_view::npos) {
            name.assign(rest);
        } else {
            name.assign(rest.substr(0, paren));
            proto.assign(rest.substr(paren));
        }
    } else {
        // Java style: com.a.B.method or com.a.B.method(...)
        std::string_view base = ref;
        const size_t paren = ref.find('(');
        if (paren != std::string_view::npos) base = ref.substr(0, paren);
        const size_t dot = base.rfind('.');
        if (dot == std::string_view::npos) return false;
        cls.assign(base.substr(0, dot));
        name.assign(base.substr(dot + 1));
    }
    cls = toDescriptor(cls);
    return !cls.empty() && !name.empty();
}

std::vector<ApkAnalysis::MethodDef> ApkAnalysis::findMethodDefs(std::string_view className, std::string_view methodName,
                                                                std::string_view proto) const {
    std::vector<MethodDef> out;
    const ClassEntry* c = findClass(className);
    if (!c) return out;
    const DexFile& dex = *dexes_[c->dex];
    for (const MethodDef& m : methodsOf(*c)) {
        if (!methodName.empty() && dex.methodName(m.method.methodIdx) != methodName) continue;
        if (!proto.empty() && dex.protoDescriptor(dex.methodProto(m.method.methodIdx)) != proto) continue;
        out.push_back(m);
    }
    return out;
}

std::string ApkAnalysis::methodSignature(const CodeRef& r) const {
    return r.dex < dexes_.size() ? dexes_[r.dex]->methodSignature(r.method) : std::string();
}

std::string ApkAnalysis::methodSignature(const MethodDef& m) const {
    return dexes_[m.dex]->methodSignature(m.method.methodIdx);
}

void ApkAnalysis::collect(XrefKind kind, uint16_t dex, uint32_t target, size_t limit, std::vector<XrefHit>& out) const {
    const Xref key{target, 0, 0, dex, kind};
    auto it = std::lower_bound(xrefs_.begin(), xrefs_.end(), key, [](const Xref& x, const Xref& k) {
        if (x.kind != k.kind) return x.kind < k.kind;
        if (x.dex != k.dex) return x.dex < k.dex;
        return x.target < k.target;
    });
    const DexFile& d = *dexes_[dex];
    std::string rendered;
    for (; it != xrefs_.end() && it->kind == kind && it->dex == dex && it->target == target; ++it) {
        if (out.size() >= limit) return;
        if (rendered.empty()) {
            switch (kind) {
            case XrefKind::Call: rendered = d.methodSignature(target); break;
            case XrefKind::FieldRead:
            case XrefKind::FieldWrite: rendered = d.fieldSignature(target); break;
            case XrefKind::String: rendered = d.string(target); break;
            case XrefKind::Type: rendered = std::string(d.typeDescriptor(target)); break;
            }
        }
        out.push_back({{it->dex, it->from, it->pc}, kind, rendered});
    }
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::callersOf(std::string_view cls, std::string_view name,
                                                         std::string_view proto, size_t limit) const {
    std::vector<XrefHit> out;
    const std::string desc = toDescriptor(cls);
    for (uint16_t di = 0; di < static_cast<uint16_t>(dexes_.size()); ++di)
        for (uint32_t const m : dexes_[di]->findMethods(desc, name, proto)) collect(XrefKind::Call, di, m, limit, out);
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::fieldAccesses(std::string_view cls, std::string_view name,
                                                             size_t limit) const {
    std::vector<XrefHit> out;
    const std::string desc = toDescriptor(cls);
    for (uint16_t di = 0; di < static_cast<uint16_t>(dexes_.size()); ++di)
        for (uint32_t const f : dexes_[di]->findFields(desc, name)) {
            collect(XrefKind::FieldRead, di, f, limit, out);
            collect(XrefKind::FieldWrite, di, f, limit, out);
        }
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::stringUses(std::string_view text, bool substring, size_t limit) const {
    std::vector<XrefHit> out;
    for (uint16_t di = 0; di < static_cast<uint16_t>(dexes_.size()) && out.size() < limit; ++di) {
        const DexFile& d = *dexes_[di];
        if (!substring) {
            const uint32_t idx = d.findString(text);
            if (idx != DexFile::kNoIndex) collect(XrefKind::String, di, idx, limit, out);
            continue;
        }
        for (uint32_t s = 0; s < d.stringCount() && out.size() < limit; ++s)
            if (tex::ciFind(d.stringView(s), text) != std::string_view::npos) collect(XrefKind::String, di, s, limit, out);
    }
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::stringUsesAt(uint16_t dex, uint32_t index, size_t limit) const {
    std::vector<XrefHit> out;
    if (dex < dexes_.size()) collect(XrefKind::String, dex, index, limit, out);
    return out;
}

std::vector<std::string> ApkAnalysis::extractUrls(std::string_view s) {
    static const char* kSchemes[] = {"https://", "http://", "wss://", "ws://", "ftp://", "content://", "file://"};
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t best = std::string_view::npos, schemeLen = 0;
        for (const char* sch : kSchemes) {
            const size_t at = tex::ciFind(s.substr(pos), sch);
            if (at != std::string_view::npos && pos + at < best) {
                best = pos + at;
                schemeLen = std::char_traits<char>::length(sch);
            }
        }
        if (best == std::string_view::npos) break;
        size_t end = best + schemeLen;
        while (end < s.size()) {
            const unsigned char c = static_cast<unsigned char>(s[end]);
            if (c <= ' ' || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == ')' || c == ']' ||
                c == '}' || c == '|' || c >= 0x7F)
                break;
            ++end;
        }
        std::string url(s.substr(best, end - best));
        while (!url.empty() && std::string_view(".,;:!?").find(url.back()) != std::string_view::npos) url.pop_back();
        if (url.size() > schemeLen + 1) out.push_back(std::move(url));
        pos = std::max(end, best + 1);
    }
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::typeUses(std::string_view cls, size_t limit) const {
    std::vector<XrefHit> out;
    const std::string desc = toDescriptor(cls);
    for (uint16_t di = 0; di < static_cast<uint16_t>(dexes_.size()); ++di) {
        const uint32_t t = dexes_[di]->findType(desc);
        if (t != DexFile::kNoIndex) collect(XrefKind::Type, di, t, limit, out);
    }
    return out;
}

std::vector<ApkAnalysis::Callee> ApkAnalysis::calleesOf(const MethodDef& m) const {
    std::vector<Callee> out;
    const DexFile& dex = *dexes_[m.dex];
    DexFile::CodeItem code;
    if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) return out;
    for (uint32_t pc = 0; pc < code.insnsSize;) {
        const Insn in = dalvik::decode(code, pc);
        pc += std::max<uint32_t>(in.size, 1);
        if (!in.valid || in.payload) continue;
        const auto& info = dalvik::opInfo(in.opcode);
        if (info.flow != Flow::Invoke || info.ref != RefKind::Method) continue;
        out.push_back({in.pc, dex.methodSignature(in.index), info.name});
    }
    return out;
}

std::vector<ApkAnalysis::ConstArgCall> ApkAnalysis::constantArguments(const MethodDef& m) const {
    std::vector<ConstArgCall> out;
    const DexFile& dex = *dexes_[m.dex];
    DexFile::CodeItem code;
    if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) return out;

    // Branch targets reset the tracked state: values may arrive from
    // several predecessors there (conservative, block-local propagation).
    std::set<uint32_t> joins;
    for (uint32_t pc = 0; pc < code.insnsSize;) {
        const Insn in = dalvik::decode(code, pc);
        pc += std::max<uint32_t>(in.size, 1);
        if (in.valid && !in.payload && in.hasBranch) joins.insert(static_cast<uint32_t>(static_cast<int64_t>(in.pc) + in.branch));
    }
    for (const TryRange& t : parseTries(dex, code))
        for (uint32_t const h : t.handlers) joins.insert(h);

    std::unordered_map<uint32_t, std::string> known;
    for (uint32_t pc = 0; pc < code.insnsSize;) {
        const Insn in = dalvik::decode(code, pc);
        pc += std::max<uint32_t>(in.size, 1);
        if (joins.count(in.pc)) known.clear();
        if (!in.valid || in.payload) continue;
        const auto& info = dalvik::opInfo(in.opcode);
        if (info.flow == Flow::Invoke && info.ref == RefKind::Method) {
            ConstArgCall call{in.pc, dex.methodSignature(in.index), {}};
            const uint32_t n = in.regCount;
            for (uint32_t k = 0; k < n; ++k) {
                const uint32_t reg = in.range ? in.regs[0] + k : in.regs[k];
                auto it = known.find(reg);
                if (it != known.end()) call.args.emplace_back(static_cast<int>(k), it->second);
            }
            if (!call.args.empty()) out.push_back(std::move(call));
            continue;
        }
        if (info.flow == Flow::Goto || info.flow == Flow::Return || info.flow == Flow::Throw) {
            known.clear();
            continue;
        }
        if (in.opcode == 0x1a || in.opcode == 0x1b) {  // const-string
            std::string v = dalvik::refToString(dex, RefKind::String, in.index);
            known[in.regs[0]] = std::move(v);
            continue;
        }
        if (in.opcode == 0x1c) {  // const-class
            known[in.regs[0]] = std::string(dex.typeDescriptor(in.index)) + ".class";
            continue;
        }
        if (in.opcode >= 0x12 && in.opcode <= 0x19 && in.hasLiteral) {
            known[in.regs[0]] = std::to_string(in.literal);
            if (in.opcode >= 0x16) known.erase(in.regs[0] + 1);
            continue;
        }
        if ((in.opcode == 0x07 || in.opcode == 0x08 || in.opcode == 0x09 || in.opcode == 0x01 || in.opcode == 0x02 ||
             in.opcode == 0x03) &&
            in.regCount == 2) {  // moves propagate
            auto it = known.find(in.regs[1]);
            if (it != known.end()) known[in.regs[0]] = it->second;
            else known.erase(in.regs[0]);
            continue;
        }
        if (writesFirstRegister(in.opcode) && in.regCount > 0) {
            known.erase(in.regs[0]);
            if (isWideWrite(in.opcode)) known.erase(in.regs[0] + 1);
        }
    }
    return out;
}

std::vector<ApkAnalysis::BasicBlock> ApkAnalysis::controlFlowGraph(const MethodDef& m) const {
    std::vector<BasicBlock> blocks;
    const DexFile& dex = *dexes_[m.dex];
    DexFile::CodeItem code;
    if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code) || code.insnsSize == 0) return blocks;

    std::vector<Insn> insns;
    std::set<uint32_t> leaders{0};
    const std::vector<TryRange> tries = parseTries(dex, code);
    for (const TryRange& t : tries) {
        leaders.insert(t.start);
        if (t.end < code.insnsSize) leaders.insert(t.end);
        for (uint32_t const h : t.handlers)
            if (h < code.insnsSize) leaders.insert(h);
    }
    for (uint32_t pc = 0; pc < code.insnsSize;) {
        Insn in = dalvik::decode(code, pc);
        pc += std::max<uint32_t>(in.size, 1);
        if (in.payload) continue;  // data, not code
        insns.push_back(in);
        if (!in.valid) continue;
        const Flow flow = dalvik::opInfo(in.opcode).flow;
        if (in.hasBranch && flow != Flow::Normal) {  // fill-array-data's offset is not a branch
            const int64_t t = static_cast<int64_t>(in.pc) + in.branch;
            if (flow == Flow::Switch) {
                for (uint32_t const st : dalvik::switchTargets(code, in.pc, static_cast<uint32_t>(t)))
                    if (st < code.insnsSize) leaders.insert(st);
            } else if (t >= 0 && t < code.insnsSize) {
                leaders.insert(static_cast<uint32_t>(t));
            }
        }
        if (flow == Flow::Goto || flow == Flow::Branch || flow == Flow::Switch || flow == Flow::Return ||
            flow == Flow::Throw)
            if (pc < code.insnsSize) leaders.insert(pc);
    }
    // Leaders inside payload data or mid-instruction are dropped.
    std::set<uint32_t> starts;
    for (const Insn& in : insns) starts.insert(in.pc);
    std::vector<uint32_t> ordered;
    for (uint32_t const l : leaders)
        if (starts.count(l)) ordered.push_back(l);
    std::map<uint32_t, uint32_t> blockAt;
    for (size_t i = 0; i < ordered.size(); ++i) {
        BasicBlock b;
        b.startPc = ordered[i];
        b.endPc = i + 1 < ordered.size() ? ordered[i + 1] : code.insnsSize;
        blockAt[b.startPc] = static_cast<uint32_t>(blocks.size());
        blocks.push_back(b);
    }
    const auto blockOf = [&](uint32_t pc) -> int64_t {
        auto it = blockAt.find(pc);
        return it == blockAt.end() ? -1 : static_cast<int64_t>(it->second);
    };
    size_t ii = 0;
    for (BasicBlock& b : blocks) {
        const Insn* last = nullptr;
        while (ii < insns.size() && insns[ii].pc < b.endPc) last = &insns[ii++];
        if (!last) continue;
        const Flow flow = last->valid ? dalvik::opInfo(last->opcode).flow : Flow::Normal;
        const uint32_t next = last->pc + std::max<uint32_t>(last->size, 1);
        const auto add = [&](int64_t blk) {
            if (blk >= 0 && std::find(b.successors.begin(), b.successors.end(), static_cast<uint32_t>(blk)) == b.successors.end())
                b.successors.push_back(static_cast<uint32_t>(blk));
        };
        if (flow == Flow::Return || flow == Flow::Throw) {
            b.exit = true;
        } else if (flow == Flow::Goto) {
            add(blockOf(static_cast<uint32_t>(static_cast<int64_t>(last->pc) + last->branch)));
        } else if (flow == Flow::Branch) {
            add(blockOf(static_cast<uint32_t>(static_cast<int64_t>(last->pc) + last->branch)));
            add(blockOf(next));
        } else if (flow == Flow::Switch) {
            add(blockOf(next));
            for (uint32_t const st : dalvik::switchTargets(code, last->pc, static_cast<uint32_t>(static_cast<int64_t>(last->pc) + last->branch)))
                add(blockOf(st));
        } else {
            add(blockOf(next));
        }
        for (const TryRange& t : tries) {
            if (b.startPc < t.end && b.endPc > t.start)
                for (uint32_t const h : t.handlers) {
                    const int64_t hb = blockOf(h);
                    if (hb >= 0 &&
                        std::find(b.exceptional.begin(), b.exceptional.end(), static_cast<uint32_t>(hb)) == b.exceptional.end())
                        b.exceptional.push_back(static_cast<uint32_t>(hb));
                }
        }
    }
    return blocks;
}

std::string ApkAnalysis::cfgToDot(const MethodDef& m, const std::vector<BasicBlock>& blocks) const {
    const DexFile& dex = *dexes_[m.dex];
    std::string listing;
    std::vector<int32_t> pcs;
    dalvik::ListingOptions opt;
    opt.showLines = false;
    dalvik::disassembleMethod(dex, m.method, opt, listing, &pcs);
    // Split the listing into lines keyed by pc.
    std::vector<std::pair<int32_t, std::string>> lines;
    size_t start = 0, li = 0;
    for (size_t i = 0; i <= listing.size(); ++i) {
        if (i == listing.size() || listing[i] == '\n') {
            if (li < pcs.size()) lines.emplace_back(pcs[li], listing.substr(start, i - start));
            ++li;
            start = i + 1;
        }
    }
    const auto esc = [](const std::string& s) {
        std::string o;
        for (char const c : s) {
            if (c == '"' || c == '\\' || c == '{' || c == '}' || c == '<' || c == '>' || c == '|') o += '\\';
            o += c;
        }
        return o;
    };
    std::string out = "digraph cfg {\n  node [shape=box, fontname=\"monospace\", fontsize=10];\n";
    out += "  label=\"" + esc(methodSignature(m)) + "\";\n";
    for (size_t i = 0; i < blocks.size(); ++i) {
        out += "  b" + std::to_string(i) + " [label=\"";
        for (const auto& l : lines)
            if (l.first >= static_cast<int32_t>(blocks[i].startPc) && l.first < static_cast<int32_t>(blocks[i].endPc)) out += esc(l.second) + "\\l";
        out += "\"];\n";
    }
    for (size_t i = 0; i < blocks.size(); ++i) {
        for (uint32_t const s : blocks[i].successors) out += "  b" + std::to_string(i) + " -> b" + std::to_string(s) + ";\n";
        for (uint32_t const s : blocks[i].exceptional)
            out += "  b" + std::to_string(i) + " -> b" + std::to_string(s) + " [style=dashed, color=red];\n";
    }
    out += "}\n";
    return out;
}

std::vector<std::string> ApkAnalysis::superChain(std::string_view cls) const {
    std::vector<std::string> out;
    std::string cur = toDescriptor(cls);
    for (int guard = 0; guard < 64 && !cur.empty(); ++guard) {
        out.push_back(DexFile::descriptorToJava(cur));
        const ClassEntry* c = findClass(cur);
        if (!c) break;  // framework class: no definition in the APK
        const DexFile::ClassDef& def = classDef(*c);
        if (def.superclassIdx == DexFile::kNoIndex) break;
        cur.assign(dexes_[c->dex]->typeDescriptor(def.superclassIdx));
    }
    return out;
}

std::vector<std::string> ApkAnalysis::subclassesOf(std::string_view cls, size_t limit) const {
    std::vector<std::string> out;
    const std::string desc = toDescriptor(cls);
    for (const ClassEntry& c : classes_) {
        if (out.size() >= limit) break;
        const DexFile::ClassDef& def = classDef(c);
        if (def.superclassIdx != DexFile::kNoIndex && dexes_[c.dex]->typeDescriptor(def.superclassIdx) == desc)
            out.push_back(DexFile::descriptorToJava(classDescriptor(c)));
    }
    return out;
}

std::vector<std::string> ApkAnalysis::implementersOf(std::string_view iface, size_t limit) const {
    std::vector<std::string> out;
    const std::string desc = toDescriptor(iface);
    for (const ClassEntry& c : classes_) {
        if (out.size() >= limit) break;
        for (uint32_t const t : dexes_[c.dex]->interfaces(classDef(c)))
            if (dexes_[c.dex]->typeDescriptor(t) == desc) {
                out.push_back(DexFile::descriptorToJava(classDescriptor(c)));
                break;
            }
    }
    return out;
}

ApkAnalysis::StringCategory ApkAnalysis::classify(std::string_view s) {
    if (s.size() < 4 || s.size() > 4096) return StringCategory::Any;
    static const char* kSchemes[] = {"http://", "https://", "ws://", "wss://", "ftp://", "content://", "file://"};
    for (const char* sch : kSchemes)
        if (tex::ciFind(s, sch) != std::string_view::npos) return StringCategory::Url;
    if (startsWith(s, "www.") && s.find('.', 4) != std::string_view::npos && s.find(' ') == std::string_view::npos)
        return StringCategory::Url;
    // Secrets / tokens.
    if ((startsWith(s, "AKIA") && s.size() >= 20) || (startsWith(s, "AIza") && s.size() >= 35) ||
        startsWith(s, "sk_live_") || startsWith(s, "pk_live_") || startsWith(s, "ghp_") || startsWith(s, "xox") ||
        startsWith(s, "-----BEGIN") ||
        (startsWith(s, "eyJ") && std::count(s.begin(), s.end(), '.') == 2 && s.size() > 30))
        return StringCategory::Secret;
    // IPv4 (optionally with port / path).
    {
        int parts = 0, digits = 0, value = 0;
        bool ok = true;
        size_t i = 0;
        for (; i < s.size(); ++i) {
            const char c = s[i];
            if (c >= '0' && c <= '9') {
                value = value * 10 + (c - '0');
                if (++digits > 3 || value > 255) {
                    ok = false;
                    break;
                }
            } else if (c == '.' && digits > 0 && parts < 3) {
                ++parts;
                digits = 0;
                value = 0;
            } else {
                break;
            }
        }
        if (ok && parts == 3 && digits > 0 && (i == s.size() || s[i] == ':' || s[i] == '/'))
            return StringCategory::Ip;
    }
    // E-mail.
    {
        const size_t at = s.find('@');
        if (at != std::string_view::npos && at > 0 && s.find(' ') == std::string_view::npos &&
            s.find('.', at) != std::string_view::npos && s.find('@', at + 1) == std::string_view::npos &&
            s.back() != '.' && std::isalpha(static_cast<unsigned char>(s.back())))
            return StringCategory::Email;
    }
    // API-like paths: "/api/v1/users", "/v2/login?x=1".
    if (s.front() == '/' && s.size() >= 4 && std::count(s.begin(), s.end(), '/') >= 2 && s.find(';') == std::string_view::npos) {
        bool clean = true;
        for (char const c : s)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || std::string_view("/_-.{}:?=&%").find(c) != std::string_view::npos)) {
                clean = false;
                break;
            }
        if (clean) return StringCategory::Path;
    }
    // Long, dense, high-entropy tokens (API keys, hex secrets).
    if (s.size() >= 32 && s.size() <= 256 && s.find(' ') == std::string_view::npos) {
        bool tokenChars = true;
        for (char const c : s)
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-')) {
                tokenChars = false;
                break;
            }
        if (tokenChars && entropy(s) > 4.2) return StringCategory::Secret;
    }
    return StringCategory::Any;
}

const char* ApkAnalysis::categoryName(StringCategory c) {
    switch (c) {
    case StringCategory::Any: return "string";
    case StringCategory::Url: return "url";
    case StringCategory::Ip: return "ip";
    case StringCategory::Path: return "path";
    case StringCategory::Secret: return "secret";
    case StringCategory::Email: return "email";
    }
    return "string";
}

bool ApkAnalysis::stringUsedInCode(uint16_t dex, uint32_t index) const {
    const Xref key{index, 0, 0, dex, XrefKind::String};
    const auto it = std::lower_bound(xrefs_.begin(), xrefs_.end(), key, [](const Xref& x, const Xref& k) {
        if (x.kind != k.kind) return x.kind < k.kind;
        if (x.dex != k.dex) return x.dex < k.dex;
        return x.target < k.target;
    });
    return it != xrefs_.end() && it->kind == XrefKind::String && it->dex == dex && it->target == index;
}

std::vector<ApkAnalysis::StringHit> ApkAnalysis::strings(std::string_view needle, StringCategory category,
                                                         size_t limit, bool codeOnly, bool readableOnly) const {
    // MUTF-8: a NUL is stored as C0 80, other control characters as themselves.
    const auto binary = [](std::string_view s) {
        for (size_t k = 0; k < s.size(); ++k) {
            const auto c = static_cast<unsigned char>(s[k]);
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return true;
            if (c == 0xC0 && k + 1 < s.size() && static_cast<unsigned char>(s[k + 1]) == 0x80) return true;
        }
        return false;
    };
    std::vector<StringHit> out;
    std::unordered_set<std::string_view> seen;
    std::unordered_set<std::string> urlSeen;
    for (uint16_t di = 0; di < static_cast<uint16_t>(dexes_.size()) && out.size() < limit; ++di) {
        const DexFile& d = *dexes_[di];
        for (uint32_t i = 0; i < d.stringCount() && out.size() < limit; ++i) {
            const std::string_view raw = d.stringView(i);
            if (raw.empty()) continue;
            if (!needle.empty() && tex::ciFind(raw, needle) == std::string_view::npos) continue;
            if (readableOnly && binary(raw)) continue;
            if (codeOnly && !stringUsedInCode(di, i)) continue;
            const StringCategory c = classify(raw);
            if (category != StringCategory::Any && c != category) continue;
            if (category == StringCategory::Url) {
                // The URL tokens, not the whole message around them.
                for (std::string& url : extractUrls(raw)) {
                    if (out.size() >= limit) break;
                    if (urlSeen.insert(url).second) out.push_back({di, i, std::move(url), c});
                }
                continue;
            }
            if (!seen.insert(raw).second) continue;  // same constant in several dex files
            out.push_back({di, i, d.string(i), c});
        }
    }
    return out;
}

std::string ApkAnalysis::disassemble(const MethodDef& m) const {
    std::string out;
    out += "# " + methodSignature(m) + "  (" + dexes_[m.dex]->name() + ")\n";
    dalvik::disassembleMethod(*dexes_[m.dex], m.method, dalvik::ListingOptions{}, out);
    return out;
}

std::string ApkAnalysis::disassembleClass(const ClassEntry& c) const {
    return disassembleClass(c, dalvik::ListingOptions{});
}

std::string ApkAnalysis::disassembleClass(const ClassEntry& c, const dalvik::ListingOptions& opt) const {
    std::string out;
    out += "# " + dexes_[c.dex]->name() + "\n";
    dalvik::disassembleClass(*dexes_[c.dex], classDef(c), opt, out);
    return out;
}
