#pragma once
// Builds small but well-formed DEX files for the tests: classes, methods with
// bytecode, string / type / method references resolved to sorted id tables
// the way d8 lays them out (strings, types, protos and methods sorted).
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

class TestDex {
public:
    // One instruction: code units, plus at most one symbolic reference whose
    // index is patched into units[at] when the file is built.
    struct Ins {
        std::vector<uint16_t> units;
        char ref = 0;  // 's' string, 't' type, 'm' method
        std::string target;
        size_t at = 1;
    };
    struct Method {
        std::string cls, name, proto;
        uint32_t flags = 0x1;  // public
        std::vector<Ins> code;
        bool hasCode = true;
    };
    struct Class {
        std::string desc, super;
        uint32_t flags = 0x1;
        std::vector<std::string> interfaces;
    };

    void addClass(const std::string& desc, const std::string& super = "Ljava/lang/Object;",
                  std::vector<std::string> interfaces = {}, uint32_t flags = 0x1) {
        classes_.push_back({desc, super, flags, std::move(interfaces)});
    }
    // flags: 0x1 public, 0x8 static, 0x100 native, 0x10000 constructor.
    void addMethod(const std::string& cls, const std::string& name, const std::string& proto, uint32_t flags,
                   std::vector<Ins> code) {
        Method m{cls, name, proto, flags, std::move(code), true};
        if (flags & 0x100) m.hasCode = false;  // native
        if (m.hasCode && m.code.empty()) m.code.push_back(returnVoid());
        methods_.push_back(std::move(m));
    }

    static Ins constString(uint8_t reg, const std::string& s) { return {{static_cast<uint16_t>(0x1a | reg << 8), 0}, 's', s, 1}; }
    static Ins newInstance(uint8_t reg, const std::string& type) { return {{static_cast<uint16_t>(0x22 | reg << 8), 0}, 't', type, 1}; }
    static Ins returnVoid() { return {{0x000e}, 0, {}, 0}; }
    // invoke-virtual (0x6e), invoke-super (0x6f), invoke-direct (0x70), invoke-static (0x71), invoke-interface (0x72).
    static Ins invoke(uint8_t op, const std::string& sig, std::vector<uint8_t> regs = {}) {
        uint16_t argWord = 0;
        for (size_t i = 0; i < regs.size() && i < 4; ++i) argWord |= static_cast<uint16_t>((regs[i] & 0xF) << (4 * i));
        const uint16_t g = regs.size() == 5 ? regs[4] & 0xF : 0;
        return {{static_cast<uint16_t>(op | g << 8 | regs.size() << 12), 0, argWord}, 'm', sig, 1};
    }
    static Ins invokeStatic(const std::string& sig, std::vector<uint8_t> regs = {}) { return invoke(0x71, sig, std::move(regs)); }
    static Ins invokeVirtual(const std::string& sig, std::vector<uint8_t> regs = {}) { return invoke(0x6e, sig, std::move(regs)); }
    static Ins invokeDirect(const std::string& sig, std::vector<uint8_t> regs = {}) { return invoke(0x70, sig, std::move(regs)); }
    // const/4 vA, #lit (-8..7)
    static Ins const4(uint8_t reg, int lit) { return {{static_cast<uint16_t>(0x12 | (reg & 0xF) << 8 | (lit & 0xF) << 12)}, 0, {}, 0}; }
    static Ins raw(std::vector<uint16_t> units) { return {std::move(units), 0, {}, 0}; }

    std::vector<uint8_t> build() const {
        // --- collect every id ------------------------------------------------
        std::set<std::string> strings, types;
        std::set<std::string> protos;
        std::set<std::string> methodRefs;  // "Lc;->n(P)R"
        const auto addType = [&](const std::string& t) {
            types.insert(t);
            strings.insert(t);
        };
        const auto addProto = [&](const std::string& p) {
            protos.insert(p);
            strings.insert(shorty(p));
            const auto [params, ret] = splitProto(p);
            addType(ret);
            for (const std::string& t : params) addType(t);
        };
        const auto addMethodRef = [&](const std::string& sig) {
            const size_t arrow = sig.find("->"), open = sig.find('(');
            addType(sig.substr(0, arrow));
            strings.insert(sig.substr(arrow + 2, open - arrow - 2));
            addProto(sig.substr(open));
            methodRefs.insert(sig);
        };
        for (const Class& c : classes_) {
            addType(c.desc);
            if (!c.super.empty()) addType(c.super);
            for (const std::string& i : c.interfaces) addType(i);
        }
        for (const Method& m : methods_) {
            addMethodRef(m.cls + "->" + m.name + m.proto);
            for (const Ins& in : m.code) {
                if (in.ref == 's') strings.insert(in.target);
                else if (in.ref == 't') addType(in.target);
                else if (in.ref == 'm') addMethodRef(in.target);
            }
        }
        const std::vector<std::string> stringList(strings.begin(), strings.end());
        const auto sidx = [&](const std::string& s) {
            return static_cast<uint32_t>(std::lower_bound(stringList.begin(), stringList.end(), s) - stringList.begin());
        };
        std::vector<std::string> typeList(types.begin(), types.end());
        std::sort(typeList.begin(), typeList.end(), [&](const std::string& a, const std::string& b) { return sidx(a) < sidx(b); });
        const auto tidx = [&](const std::string& t) {
            return static_cast<uint32_t>(std::find(typeList.begin(), typeList.end(), t) - typeList.begin());
        };
        std::vector<std::string> protoList(protos.begin(), protos.end());
        const auto protoKey = [&](const std::string& p) {
            const auto [params, ret] = splitProto(p);
            std::vector<uint32_t> key = {tidx(ret)};
            for (const std::string& t : params) key.push_back(tidx(t));
            return key;
        };
        std::sort(protoList.begin(), protoList.end(), [&](const std::string& a, const std::string& b) {
            const auto ka = protoKey(a), kb = protoKey(b);
            if (ka[0] != kb[0]) return ka[0] < kb[0];
            return std::lexicographical_compare(ka.begin() + 1, ka.end(), kb.begin() + 1, kb.end());
        });
        const auto pidx = [&](const std::string& p) {
            return static_cast<uint32_t>(std::find(protoList.begin(), protoList.end(), p) - protoList.begin());
        };
        struct MRef {
            uint32_t cls, name, proto;
            std::string sig;
        };
        std::vector<MRef> methodList;
        for (const std::string& sig : methodRefs) {
            const size_t arrow = sig.find("->"), open = sig.find('(');
            methodList.push_back({tidx(sig.substr(0, arrow)), sidx(sig.substr(arrow + 2, open - arrow - 2)), pidx(sig.substr(open)), sig});
        }
        std::sort(methodList.begin(), methodList.end(), [](const MRef& a, const MRef& b) {
            if (a.cls != b.cls) return a.cls < b.cls;
            if (a.name != b.name) return a.name < b.name;
            return a.proto < b.proto;
        });
        const auto midx = [&](const std::string& sig) {
            for (size_t i = 0; i < methodList.size(); ++i)
                if (methodList[i].sig == sig) return static_cast<uint32_t>(i);
            return 0u;
        };

        // --- lay out the file ---------------------------------------------------
        std::vector<uint8_t> b(0x70, 0);
        std::memcpy(b.data(), "dex\n035\0", 8);
        put32(b, 0x24, 0x70);
        put32(b, 0x28, 0x12345678);
        const size_t stringIdsOff = b.size();
        b.resize(b.size() + 4 * stringList.size());
        const size_t typeIdsOff = b.size();
        for (const std::string& t : typeList) u32(b, sidx(t));
        const size_t protoIdsOff = b.size();
        std::vector<size_t> protoParamPatch;
        for (const std::string& p : protoList) {
            u32(b, sidx(shorty(p)));
            u32(b, tidx(splitProto(p).second));
            protoParamPatch.push_back(b.size());
            u32(b, 0);
        }
        const size_t methodIdsOff = b.size();
        for (const MRef& m : methodList) {
            u16(b, static_cast<uint16_t>(m.cls));
            u16(b, static_cast<uint16_t>(m.proto));
            u32(b, m.name);
        }
        const size_t classDefsOff = b.size();
        std::vector<size_t> classPatch;  // interfaces_off, class_data_off positions
        for (const Class& c : classes_) {
            u32(b, tidx(c.desc));
            u32(b, c.flags);
            u32(b, c.super.empty() ? 0xFFFFFFFFu : tidx(c.super));
            classPatch.push_back(b.size());
            u32(b, 0);            // interfaces_off
            u32(b, 0xFFFFFFFFu);  // source_file_idx
            u32(b, 0);            // annotations_off
            u32(b, 0);            // class_data_off
            u32(b, 0);            // static_values_off
        }
        // string data
        for (size_t i = 0; i < stringList.size(); ++i) {
            put32(b, stringIdsOff + 4 * i, static_cast<uint32_t>(b.size()));
            uleb(b, static_cast<uint32_t>(stringList[i].size()));
            b.insert(b.end(), stringList[i].begin(), stringList[i].end());
            b.push_back(0);
        }
        // type lists: proto parameters and interfaces
        const auto typeListAt = [&](const std::vector<std::string>& list) {
            align(b, 4);
            const auto off = static_cast<uint32_t>(b.size());
            u32(b, static_cast<uint32_t>(list.size()));
            for (const std::string& t : list) u16(b, static_cast<uint16_t>(tidx(t)));
            return off;
        };
        for (size_t i = 0; i < protoList.size(); ++i) {
            const auto params = splitProto(protoList[i]).first;
            if (!params.empty()) put32(b, protoParamPatch[i], typeListAt(params));
        }
        for (size_t i = 0; i < classes_.size(); ++i)
            if (!classes_[i].interfaces.empty()) put32(b, classPatch[i], typeListAt(classes_[i].interfaces));
        // code items
        std::map<size_t, uint32_t> codeOff;  // methods_ index -> offset
        for (size_t i = 0; i < methods_.size(); ++i) {
            const Method& m = methods_[i];
            if (!m.hasCode) continue;
            align(b, 4);
            codeOff[i] = static_cast<uint32_t>(b.size());
            std::vector<uint16_t> insns;
            for (const Ins& in : m.code) {
                std::vector<uint16_t> units = in.units;
                if (in.ref == 's') units[in.at] = static_cast<uint16_t>(sidx(in.target));
                else if (in.ref == 't') units[in.at] = static_cast<uint16_t>(tidx(in.target));
                else if (in.ref == 'm') units[in.at] = static_cast<uint16_t>(midx(in.target));
                insns.insert(insns.end(), units.begin(), units.end());
            }
            const uint16_t ins = static_cast<uint16_t>(splitProto(m.proto).first.size() + ((m.flags & 0x8) ? 0 : 1));
            u16(b, static_cast<uint16_t>(ins + 6));  // registers
            u16(b, ins);
            u16(b, 5);  // outs
            u16(b, 0);  // tries
            u32(b, 0);  // debug info
            u32(b, static_cast<uint32_t>(insns.size()));
            for (uint16_t u : insns) u16(b, u);
        }
        // class data
        for (size_t ci = 0; ci < classes_.size(); ++ci) {
            struct Enc {
                uint32_t idx, flags, code;
            };
            std::vector<Enc> direct, virt;
            for (size_t i = 0; i < methods_.size(); ++i) {
                const Method& m = methods_[i];
                if (m.cls != classes_[ci].desc) continue;
                const Enc e{midx(m.cls + "->" + m.name + m.proto), m.flags, codeOff.count(i) ? codeOff[i] : 0};
                const bool isDirect = (m.flags & (0x8 | 0x2 | 0x10000)) || m.name == "<init>" || m.name == "<clinit>";
                (isDirect ? direct : virt).push_back(e);
            }
            if (direct.empty() && virt.empty()) continue;
            const auto byIdx = [](const Enc& a, const Enc& c) { return a.idx < c.idx; };
            std::sort(direct.begin(), direct.end(), byIdx);
            std::sort(virt.begin(), virt.end(), byIdx);
            put32(b, classPatch[ci] + 12, static_cast<uint32_t>(b.size()));
            uleb(b, 0), uleb(b, 0), uleb(b, static_cast<uint32_t>(direct.size())), uleb(b, static_cast<uint32_t>(virt.size()));
            for (const auto* list : {&direct, &virt}) {
                uint32_t prev = 0;
                for (size_t k = 0; k < list->size(); ++k) {
                    const Enc& e = (*list)[k];
                    uleb(b, k == 0 ? e.idx : e.idx - prev);
                    uleb(b, e.flags);
                    uleb(b, e.code);
                    prev = e.idx;
                }
            }
        }
        put32(b, 0x20, static_cast<uint32_t>(b.size()));
        put32(b, 0x38, static_cast<uint32_t>(stringList.size())), put32(b, 0x3C, static_cast<uint32_t>(stringIdsOff));
        put32(b, 0x40, static_cast<uint32_t>(typeList.size())), put32(b, 0x44, static_cast<uint32_t>(typeIdsOff));
        put32(b, 0x48, static_cast<uint32_t>(protoList.size())), put32(b, 0x4C, static_cast<uint32_t>(protoIdsOff));
        put32(b, 0x58, static_cast<uint32_t>(methodList.size())), put32(b, 0x5C, static_cast<uint32_t>(methodIdsOff));
        put32(b, 0x60, static_cast<uint32_t>(classes_.size())), put32(b, 0x64, static_cast<uint32_t>(classDefsOff));
        return b;
    }

private:
    static std::pair<std::vector<std::string>, std::string> splitProto(const std::string& p) {
        std::vector<std::string> params;
        size_t i = 1;
        const size_t close = p.find(')');
        while (i < close) {
            size_t j = i;
            while (p[j] == '[') ++j;
            if (p[j] == 'L') j = p.find(';', j);
            params.push_back(p.substr(i, j - i + 1));
            i = j + 1;
        }
        return {params, p.substr(close + 1)};
    }
    static std::string shorty(const std::string& p) {
        const auto [params, ret] = splitProto(p);
        const auto letter = [](const std::string& t) { return (t[0] == 'L' || t[0] == '[') ? 'L' : t[0]; };
        std::string s(1, letter(ret));
        for (const std::string& t : params) s += letter(t);
        return s;
    }
    static void u16(std::vector<uint8_t>& b, uint16_t v) { b.push_back(static_cast<uint8_t>(v)), b.push_back(static_cast<uint8_t>(v >> 8)); }
    static void u32(std::vector<uint8_t>& b, uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
    static void put32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) b[at + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
    }
    static void uleb(std::vector<uint8_t>& b, uint32_t v) {
        do {
            uint8_t byte = v & 0x7F;
            v >>= 7;
            if (v) byte |= 0x80;
            b.push_back(byte);
        } while (v);
    }
    static void align(std::vector<uint8_t>& b, size_t a) {
        while (b.size() % a) b.push_back(0);
    }

    std::vector<Class> classes_;
    std::vector<Method> methods_;
};
