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
           op == 0x84 || op == 0x86 || op == 0x88 || op == 0x89 || op == 0x8b || op == 0x8c ||
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
    size_t pos = (size_t)code.offset + 16 + (size_t)code.insnsSize * 2;
    if (code.insnsSize & 1) pos += 2;  // padding to 4 bytes
    const size_t triesAt = pos;
    const size_t handlersAt = triesAt + (size_t)code.tries * 8;
    if (handlersAt > size) return out;
    for (uint32_t t = 0; t < code.tries; ++t) {
        const uint8_t* p = d + triesAt + (size_t)t * 8;
        TryRange r;
        r.start = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        const uint32_t count = (uint32_t)(p[4] | p[5] << 8);
        const uint32_t handlerOff = (uint32_t)(p[6] | p[7] << 8);
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
    for (unsigned char c : s) counts[c]++;
    double h = 0;
    for (int c : counts)
        if (c) {
            const double p = (double)c / (double)s.size();
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
    for (uint16_t di = 0; di < (uint16_t)a->dexes_.size(); ++di) {
        const DexFile& dex = *a->dexes_[di];
        for (uint32_t ci = 0; ci < (uint32_t)dex.classes().size(); ++ci) {
            if (stop.load()) return nullptr;
            a->classes_.push_back({di, ci});
            if (progressDone) *progressDone = ++done;
            if (!dex.classData(dex.classes()[ci], data)) continue;
            for (const auto& m : data.methods) {
                ++a->stats_.methods;
                DexFile::CodeItem code;
                if (!m.codeOff || !dex.codeItem(m.codeOff, code)) continue;
                ++a->stats_.methodsWithCode;
                a->stats_.codeBytes += (size_t)code.insnsSize * 2;
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
        std::string_view rest = ref.substr(arrow + 2);
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
    for (uint16_t di = 0; di < (uint16_t)dexes_.size(); ++di)
        for (uint32_t m : dexes_[di]->findMethods(desc, name, proto)) collect(XrefKind::Call, di, m, limit, out);
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::fieldAccesses(std::string_view cls, std::string_view name,
                                                             size_t limit) const {
    std::vector<XrefHit> out;
    const std::string desc = toDescriptor(cls);
    for (uint16_t di = 0; di < (uint16_t)dexes_.size(); ++di)
        for (uint32_t f : dexes_[di]->findFields(desc, name)) {
            collect(XrefKind::FieldRead, di, f, limit, out);
            collect(XrefKind::FieldWrite, di, f, limit, out);
        }
    return out;
}

std::vector<ApkAnalysis::XrefHit> ApkAnalysis::stringUses(std::string_view text, bool substring, size_t limit) const {
    std::vector<XrefHit> out;
    for (uint16_t di = 0; di < (uint16_t)dexes_.size() && out.size() < limit; ++di) {
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
            const unsigned char c = (unsigned char)s[end];
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
    for (uint16_t di = 0; di < (uint16_t)dexes_.size(); ++di) {
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
        if (in.valid && !in.payload && in.hasBranch) joins.insert((uint32_t)((int64_t)in.pc + in.branch));
    }
    for (const TryRange& t : parseTries(dex, code))
        for (uint32_t h : t.handlers) joins.insert(h);

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
                if (it != known.end()) call.args.emplace_back((int)k, it->second);
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
        for (uint32_t h : t.handlers)
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
            const int64_t t = (int64_t)in.pc + in.branch;
            if (flow == Flow::Switch) {
                for (uint32_t st : dalvik::switchTargets(code, in.pc, (uint32_t)t))
                    if (st < code.insnsSize) leaders.insert(st);
            } else if (t >= 0 && t < code.insnsSize) {
                leaders.insert((uint32_t)t);
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
    for (uint32_t l : leaders)
        if (starts.count(l)) ordered.push_back(l);
    std::map<uint32_t, uint32_t> blockAt;
    for (size_t i = 0; i < ordered.size(); ++i) {
        BasicBlock b;
        b.startPc = ordered[i];
        b.endPc = i + 1 < ordered.size() ? ordered[i + 1] : code.insnsSize;
        blockAt[b.startPc] = (uint32_t)blocks.size();
        blocks.push_back(b);
    }
    const auto blockOf = [&](uint32_t pc) -> int64_t {
        auto it = blockAt.find(pc);
        return it == blockAt.end() ? -1 : (int64_t)it->second;
    };
    size_t ii = 0;
    for (BasicBlock& b : blocks) {
        const Insn* last = nullptr;
        while (ii < insns.size() && insns[ii].pc < b.endPc) last = &insns[ii++];
        if (!last) continue;
        const Flow flow = last->valid ? dalvik::opInfo(last->opcode).flow : Flow::Normal;
        const uint32_t next = last->pc + std::max<uint32_t>(last->size, 1);
        const auto add = [&](int64_t blk) {
            if (blk >= 0 && std::find(b.successors.begin(), b.successors.end(), (uint32_t)blk) == b.successors.end())
                b.successors.push_back((uint32_t)blk);
        };
        if (flow == Flow::Return || flow == Flow::Throw) {
            b.exit = true;
        } else if (flow == Flow::Goto) {
            add(blockOf((uint32_t)((int64_t)last->pc + last->branch)));
        } else if (flow == Flow::Branch) {
            add(blockOf((uint32_t)((int64_t)last->pc + last->branch)));
            add(blockOf(next));
        } else if (flow == Flow::Switch) {
            add(blockOf(next));
            for (uint32_t st : dalvik::switchTargets(code, last->pc, (uint32_t)((int64_t)last->pc + last->branch)))
                add(blockOf(st));
        } else {
            add(blockOf(next));
        }
        for (const TryRange& t : tries) {
            if (b.startPc < t.end && b.endPc > t.start)
                for (uint32_t h : t.handlers) {
                    const int64_t hb = blockOf(h);
                    if (hb >= 0 &&
                        std::find(b.exceptional.begin(), b.exceptional.end(), (uint32_t)hb) == b.exceptional.end())
                        b.exceptional.push_back((uint32_t)hb);
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
        for (char c : s) {
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
            if (l.first >= (int32_t)blocks[i].startPc && l.first < (int32_t)blocks[i].endPc) out += esc(l.second) + "\\l";
        out += "\"];\n";
    }
    for (size_t i = 0; i < blocks.size(); ++i) {
        for (uint32_t s : blocks[i].successors) out += "  b" + std::to_string(i) + " -> b" + std::to_string(s) + ";\n";
        for (uint32_t s : blocks[i].exceptional)
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
        for (uint32_t t : dexes_[c.dex]->interfaces(classDef(c)))
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
            s.back() != '.' && std::isalpha((unsigned char)s.back()))
            return StringCategory::Email;
    }
    // API-like paths: "/api/v1/users", "/v2/login?x=1".
    if (s.front() == '/' && s.size() >= 4 && std::count(s.begin(), s.end(), '/') >= 2 && s.find(';') == std::string_view::npos) {
        bool clean = true;
        for (char c : s)
            if (!(std::isalnum((unsigned char)c) || std::string_view("/_-.{}:?=&%").find(c) != std::string_view::npos)) {
                clean = false;
                break;
            }
        if (clean) return StringCategory::Path;
    }
    // Long, dense, high-entropy tokens (API keys, hex secrets).
    if (s.size() >= 32 && s.size() <= 256 && s.find(' ') == std::string_view::npos) {
        bool tokenChars = true;
        for (char c : s)
            if (!(std::isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-')) {
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

std::vector<ApkAnalysis::StringHit> ApkAnalysis::strings(std::string_view needle, StringCategory category,
                                                         size_t limit) const {
    std::vector<StringHit> out;
    std::unordered_set<std::string_view> seen;
    std::unordered_set<std::string> urlSeen;
    for (uint16_t di = 0; di < (uint16_t)dexes_.size() && out.size() < limit; ++di) {
        const DexFile& d = *dexes_[di];
        for (uint32_t i = 0; i < d.stringCount() && out.size() < limit; ++i) {
            const std::string_view raw = d.stringView(i);
            if (raw.empty()) continue;
            if (!needle.empty() && tex::ciFind(raw, needle) == std::string_view::npos) continue;
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
    std::string out;
    out += "# " + dexes_[c.dex]->name() + "\n";
    dalvik::disassembleClass(*dexes_[c.dex], classDef(c), dalvik::ListingOptions{}, out);
    return out;
}
