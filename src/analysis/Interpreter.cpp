#include "analysis/Interpreter.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include "analysis/Dalvik.hpp"
#include "analysis/EmuCrypto.hpp"

namespace emu {
namespace {

struct Stop {
    std::string why;
};

struct Value {
    int64_t n = 0;
    int ref = -1;  // heap index, -1 = null / not a reference
};

struct Obj {
    enum Kind : uint8_t { Str, Arr, Builder, Dummy, Cipher, KeySpec, IvSpec, Digest } kind = Dummy;
    std::u16string s;
    std::vector<int64_t> a;
    char elem = 'I';  // B, C, I, S, Z, J
    // javax.crypto / java.security state
    std::string text;               // transformation or digest algorithm
    std::vector<uint8_t> key, iv, data;
    int mode = 0;                   // Cipher.ENCRYPT_MODE = 1, DECRYPT_MODE = 2
};

std::u16string toU16(const std::string& s) {
    std::u16string out;
    for (size_t i = 0; i < s.size();) {
        const uint8_t c = static_cast<uint8_t>(s[i]);
        uint32_t cp = c;
        size_t len = 1;
        if (c >= 0xF0 && i + 3 < s.size()) cp = (c & 7u) << 18 | (s[i + 1] & 0x3Fu) << 12 | (s[i + 2] & 0x3Fu) << 6 | (s[i + 3] & 0x3Fu), len = 4;
        else if (c >= 0xE0 && i + 2 < s.size()) cp = (c & 15u) << 12 | (s[i + 1] & 0x3Fu) << 6 | (s[i + 2] & 0x3Fu), len = 3;
        else if (c >= 0xC0 && i + 1 < s.size()) cp = (c & 31u) << 6 | (s[i + 1] & 0x3Fu), len = 2;
        if (cp >= 0x10000) cp -= 0x10000, out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10))), out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
        else out.push_back(static_cast<char16_t>(cp));
        i += len;
    }
    return out;
}

std::string toU8(const std::u16string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) c = 0x10000 + ((c - 0xD800) << 10) + (s[++i] - 0xDC00);
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) out += static_cast<char>(0xC0 | (c >> 6)), out += static_cast<char>(0x80 | (c & 0x3F));
        else if (c < 0x10000) out += static_cast<char>(0xE0 | (c >> 12)), out += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), out += static_cast<char>(0x80 | (c & 0x3F));
        else out += static_cast<char>(0xF0 | (c >> 18)), out += static_cast<char>(0x80 | ((c >> 12) & 0x3F)), out += static_cast<char>(0x80 | ((c >> 6) & 0x3F)), out += static_cast<char>(0x80 | (c & 0x3F));
    }
    return out;
}

bool b64(const std::string& in, std::vector<uint8_t>& out) {
    uint32_t buf = 0;
    int bits = 0;
    out.clear();
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        else return false;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) bits -= 8, out.push_back(static_cast<uint8_t>(buf >> bits));
    }
    return true;
}

class Machine {
public:
    Machine(const ApkAnalysis& a, uint64_t maxSteps) : A(a), maxSteps_(maxSteps) {}
    uint64_t steps() const { return steps_; }

    int newStr(std::u16string s) {
        Obj o;
        o.kind = Obj::Str;
        o.s = std::move(s);
        return add(std::move(o));
    }
    int newArr(char elem, size_t n) {
        if (n > 1000000 || (cells_ += n) > 8000000) throw Stop{"memory limit"};
        Obj o;
        o.kind = Obj::Arr;
        o.elem = elem;
        o.a.assign(n, 0);
        return add(std::move(o));
    }
    Obj& obj(const Value& v) {
        if (v.ref < 0) throw Stop{"null pointer"};
        return heap_[static_cast<size_t>(v.ref)];
    }
    Value ref(int i) { return Value{0, i}; }
    std::u16string& str(const Value& v) {
        Obj& o = obj(v);
        if (o.kind != Obj::Str && o.kind != Obj::Builder) throw Stop{"not a string"};
        return o.s;
    }

    Value exec(const ApkAnalysis::MethodDef& m, const std::vector<Value>& args);
    void ensureInit(const std::string& cls);

private:
    int add(Obj o) {
        if (heap_.size() > 2000000) throw Stop{"memory limit"};
        heap_.push_back(std::move(o));
        return static_cast<int>(heap_.size()) - 1;
    }
    Value libCall(const std::string& sig, const std::vector<Value>& a, bool& hasResult);
    Value callApp(const DexFile& dex, uint32_t methodIdx, const std::vector<Value>& a, bool isStatic, bool& hasResult);
    Value sget(const DexFile& dex, uint32_t fieldIdx);
    void sput(const DexFile& dex, uint32_t fieldIdx, const Value& v);
    Value constant(const DexFile& dex, uint32_t strIdx) { return ref(newStr(toU16(dex.string(strIdx)))); }

    const ApkAnalysis& A;
    std::vector<Obj> heap_;
    std::map<std::string, Value> statics_;
    std::set<std::string> initialised_;
    uint64_t steps_ = 0, maxSteps_;
    size_t cells_ = 0;
    int depth_ = 0;
};

// Reads encoded_array static values of a class into the static-field table.
void readStaticValues(const DexFile& dex, uint32_t defIndex, const DexFile::ClassData& cd,
                      const std::function<void(uint32_t fieldIdx, int64_t value, int kind, uint32_t strIdx)>& set) {
    const uint8_t* d = dex.data();
    const size_t size = dex.sizeBytes();
    if (size < 0x70) return;
    const auto u32 = [&](size_t at) { return at + 4 <= size ? static_cast<uint32_t>(d[at] | d[at + 1] << 8 | d[at + 2] << 16 | static_cast<uint32_t>(d[at + 3]) << 24) : 0u; };
    const uint32_t defsOff = u32(0x64);
    const size_t at = static_cast<size_t>(defsOff) + static_cast<size_t>(defIndex) * 32 + 28;
    const uint32_t valuesOff = u32(at);
    if (!valuesOff || valuesOff >= size) return;
    size_t p = valuesOff;
    const auto uleb = [&]() {
        uint32_t v = 0;
        for (int shift = 0; shift < 35 && p < size; shift += 7) {
            const uint8_t b = d[p++];
            v |= static_cast<uint32_t>(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
        }
        return v;
    };
    const uint32_t count = uleb();
    std::vector<uint32_t> statics;
    for (const auto& f : cd.fields)
        if (f.isStatic) statics.push_back(f.fieldIdx);
    for (uint32_t i = 0; i < count && i < statics.size() && p < size; ++i) {
        const uint8_t hdr = d[p++];
        const int type = hdr & 0x1f, arg = hdr >> 5;
        const size_t len = static_cast<size_t>(arg) + 1;
        uint64_t raw = 0;
        if (type == 0x1e) { set(statics[i], 0, 1, 0); continue; }         // null
        if (type == 0x1f) { set(statics[i], arg, 0, 0); continue; }        // boolean
        if (type == 0x1c || type == 0x1d) return;                           // nested arrays / annotations: stop here
        if (p + len > size) return;
        for (size_t k = 0; k < len; ++k) raw |= static_cast<uint64_t>(d[p + k]) << (8 * k);
        p += len;
        if (type == 0x17) { set(statics[i], 0, 2, static_cast<uint32_t>(raw)); continue; }  // string
        int64_t v = static_cast<int64_t>(raw);
        if (type == 0x00 || type == 0x02 || type == 0x04 || type == 0x06) {  // sign-extended
            const unsigned bits = static_cast<unsigned>(len * 8);
            if (bits < 64 && (raw >> (bits - 1)) & 1) v = static_cast<int64_t>(raw | (~0ull << bits));
        }
        if (type == 0x00 || type == 0x02 || type == 0x03 || type == 0x04 || type == 0x06) set(statics[i], v, 0, 0);
    }
}

void Machine::ensureInit(const std::string& cls) {
    if (!initialised_.insert(cls).second) return;
    const ApkAnalysis::ClassEntry* ce = A.findClass(cls);
    if (!ce) return;
    const DexFile& dex = *A.dexes()[ce->dex];
    DexFile::ClassData cd;
    if (!dex.classData(A.classDef(*ce), cd)) return;
    readStaticValues(dex, ce->def, cd, [&](uint32_t fieldIdx, int64_t value, int kind, uint32_t strIdx) {
        Value v;
        if (kind == 2) v = constant(dex, strIdx);
        else if (kind == 1) v = Value{};
        else v.n = value;
        statics_[dex.fieldSignature(fieldIdx)] = v;
    });
    for (const auto& m : cd.methods)
        if (dex.methodName(m.methodIdx) == "<clinit>" && m.codeOff) {
            ApkAnalysis::MethodDef def;
            def.dex = ce->dex;
            def.method = m;
            exec(def, {});
        }
}

Value Machine::sget(const DexFile& dex, uint32_t fieldIdx) {
    const std::string cls(dex.typeDescriptor(dex.fieldClass(fieldIdx)));
    const std::string sig = dex.fieldSignature(fieldIdx);
    if (cls == "Ljava/nio/charset/StandardCharsets;") {
        Obj o;
        o.kind = Obj::Dummy;
        o.s = toU16(std::string(dex.fieldName(fieldIdx)));
        return ref(add(std::move(o)));
    }
    if (!A.findClass(cls)) throw Stop{"reads a field of " + cls + ", which is not emulated"};
    ensureInit(cls);
    auto it = statics_.find(sig);
    return it == statics_.end() ? Value{} : it->second;
}

void Machine::sput(const DexFile& dex, uint32_t fieldIdx, const Value& v) {
    const std::string cls(dex.typeDescriptor(dex.fieldClass(fieldIdx)));
    if (!A.findClass(cls)) throw Stop{"writes a field of " + cls + ", which is not emulated"};
    statics_[dex.fieldSignature(fieldIdx)] = v;
}

Value Machine::callApp(const DexFile& dex, uint32_t methodIdx, const std::vector<Value>& a, bool isStatic, bool& hasResult) {
    if (!isStatic) throw Stop{"calls the instance method " + dex.methodSignature(methodIdx) + ", which is not emulated"};
    const std::string cls(dex.typeDescriptor(dex.methodClass(methodIdx)));
    const std::string name(dex.methodName(methodIdx));
    const auto defs = A.findMethodDefs(cls, name, dex.protoDescriptor(dex.methodProto(methodIdx)));
    for (const auto& d : defs) {
        if (!d.method.codeOff) continue;
        ensureInit(cls);
        const std::string proto = dex.protoDescriptor(dex.methodProto(methodIdx));
        hasResult = !proto.empty() && proto.back() != 'V';
        return exec(d, a);
    }
    throw Stop{"calls " + dex.methodSignature(methodIdx) + ", which is not in the APK"};
}

Value Machine::libCall(const std::string& sig, const std::vector<Value>& a, bool& hasResult) {
    hasResult = true;
    const auto is = [&](const char* s) { return sig == s; };
    const auto strv = [&](size_t i) -> std::u16string& { return str(a.at(i)); };
    const auto mk = [&](std::u16string s) { return ref(newStr(std::move(s))); };
    const auto integer = [](int64_t n) { Value v; v.n = static_cast<int32_t>(n); return v; };
    const auto bytesOf = [&](const Value& v) {
        std::string s;
        for (int64_t b : obj(v).a) s.push_back(static_cast<char>(b));
        return s;
    };
    // java.lang.String
    if (is("Ljava/lang/String;->length()I")) return integer(static_cast<int64_t>(strv(0).size()));
    if (is("Ljava/lang/String;->charAt(I)C")) {
        const auto& s = strv(0);
        if (a[1].n < 0 || static_cast<size_t>(a[1].n) >= s.size()) throw Stop{"StringIndexOutOfBoundsException"};
        return integer(s[static_cast<size_t>(a[1].n)]);
    }
    if (is("Ljava/lang/String;->toCharArray()[C") || is("Ljava/lang/String;->valueOf([C)Ljava/lang/String;") || is("Ljava/lang/String;->copyValueOf([C)Ljava/lang/String;")) {
        if (sig.find("toCharArray") != std::string::npos) {
            const std::u16string s = strv(0);  // a copy: allocating the array may move the heap
            const int r = newArr('C', s.size());
            for (size_t i = 0; i < s.size(); ++i) heap_[static_cast<size_t>(r)].a[i] = s[i];
            return ref(r);
        }
        std::u16string s;
        for (int64_t c : obj(a.at(0)).a) s.push_back(static_cast<char16_t>(c));
        return mk(std::move(s));
    }
    if (is("Ljava/lang/String;->substring(I)Ljava/lang/String;")) {
        const auto& s = strv(0);
        if (a[1].n < 0 || static_cast<size_t>(a[1].n) > s.size()) throw Stop{"StringIndexOutOfBoundsException"};
        return mk(s.substr(static_cast<size_t>(a[1].n)));
    }
    if (is("Ljava/lang/String;->substring(II)Ljava/lang/String;")) {
        const auto& s = strv(0);
        if (a[1].n < 0 || a[2].n < a[1].n || static_cast<size_t>(a[2].n) > s.size()) throw Stop{"StringIndexOutOfBoundsException"};
        return mk(s.substr(static_cast<size_t>(a[1].n), static_cast<size_t>(a[2].n - a[1].n)));
    }
    if (is("Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;")) return mk(strv(0) + strv(1));
    if (is("Ljava/lang/String;->toString()Ljava/lang/String;") || is("Ljava/lang/String;->intern()Ljava/lang/String;") ||
        is("Ljava/lang/String;->trim()Ljava/lang/String;")) {
        std::u16string s = strv(0);
        if (sig.find("trim") != std::string::npos) {
            size_t b = 0, e = s.size();
            while (b < e && s[b] <= 0x20) ++b;
            while (e > b && s[e - 1] <= 0x20) --e;
            s = s.substr(b, e - b);
        }
        return mk(std::move(s));
    }
    if (is("Ljava/lang/String;->isEmpty()Z")) return integer(strv(0).empty());
    if (is("Ljava/lang/String;->equals(Ljava/lang/Object;)Z")) return integer(a[1].ref >= 0 && obj(a[1]).kind == Obj::Str && strv(0) == strv(1));
    if (is("Ljava/lang/String;->hashCode()I")) {
        int32_t h = 0;
        for (char16_t c : strv(0)) h = static_cast<int32_t>(31u * static_cast<uint32_t>(h) + c);
        return integer(h);
    }
    if (is("Ljava/lang/String;->indexOf(I)I")) {
        const auto p = strv(0).find(static_cast<char16_t>(a[1].n));
        return integer(p == std::u16string::npos ? -1 : static_cast<int64_t>(p));
    }
    if (is("Ljava/lang/String;->replace(CC)Ljava/lang/String;")) {
        std::u16string s = strv(0);
        for (char16_t& c : s)
            if (c == static_cast<char16_t>(a[1].n)) c = static_cast<char16_t>(a[2].n);
        return mk(std::move(s));
    }
    if (is("Ljava/lang/String;->toUpperCase()Ljava/lang/String;") || is("Ljava/lang/String;->toLowerCase()Ljava/lang/String;")) {
        std::u16string s = strv(0);
        const bool up = sig.find("Upper") != std::string::npos;
        for (char16_t& c : s)
            if (c < 128) c = static_cast<char16_t>(up ? std::toupper(c) : std::tolower(c));
        return mk(std::move(s));
    }
    if (is("Ljava/lang/String;->getBytes()[B") || is("Ljava/lang/String;->getBytes(Ljava/lang/String;)[B") || is("Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B")) {
        const std::string u8 = toU8(strv(0));
        const int r = newArr('B', u8.size());
        for (size_t i = 0; i < u8.size(); ++i) heap_[static_cast<size_t>(r)].a[i] = static_cast<int8_t>(u8[i]);
        return ref(r);
    }
    if (is("Ljava/lang/String;->valueOf(C)Ljava/lang/String;")) return mk(std::u16string(1, static_cast<char16_t>(a[0].n)));
    if (is("Ljava/lang/String;->valueOf(I)Ljava/lang/String;") || is("Ljava/lang/Integer;->toString(I)Ljava/lang/String;")) return mk(toU16(std::to_string(static_cast<int32_t>(a[0].n))));
    if (is("Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;")) return mk(strv(0));
    if (is("Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;")) {
        char b[16];
        std::snprintf(b, sizeof b, "%x", static_cast<uint32_t>(a[0].n));
        return mk(toU16(b));
    }
    if (is("Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I")) {
        const std::string s = toU8(strv(0));
        char* end = nullptr;
        const long v = std::strtol(s.c_str(), &end, 10);
        if (s.empty() || *end) throw Stop{"NumberFormatException"};
        return integer(v);
    }
    // constructors: the receiver (a[0]) was allocated by new-instance
    if (sig.rfind("Ljava/lang/String;-><init>", 0) == 0) {
        Obj& self = obj(a.at(0));
        if (is("Ljava/lang/String;-><init>()V")) self.s.clear();
        else if (is("Ljava/lang/String;-><init>(Ljava/lang/String;)V")) self.s = strv(1);
        else if (is("Ljava/lang/String;-><init>([C)V")) {
            self.s.clear();
            for (int64_t c : obj(a.at(1)).a) self.s.push_back(static_cast<char16_t>(c));
        } else if (is("Ljava/lang/String;-><init>([CII)V")) {
            self.s.clear();
            const auto& arr = obj(a.at(1)).a;
            if (a[2].n < 0 || a[3].n < 0 || static_cast<size_t>(a[2].n + a[3].n) > arr.size()) throw Stop{"IndexOutOfBoundsException"};
            for (int64_t i = a[2].n; i < a[2].n + a[3].n; ++i) self.s.push_back(static_cast<char16_t>(arr[static_cast<size_t>(i)]));
        } else if (is("Ljava/lang/String;-><init>([B)V") || is("Ljava/lang/String;-><init>([BLjava/lang/String;)V") || is("Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V")) {
            self.s = toU16(bytesOf(a.at(1)));
        } else {
            throw Stop{"String constructor " + sig + " is not emulated"};
        }
        hasResult = false;
        return {};
    }
    // StringBuilder / StringBuffer
    for (const char* cls : {"Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;"}) {
        const std::string c = cls;
        if (sig.compare(0, c.size(), c) != 0) continue;
        const std::string rest = sig.substr(c.size());
        if (rest == "-><init>()V" || rest == "-><init>(I)V") { obj(a.at(0)).kind = Obj::Builder; hasResult = false; return {}; }
        if (rest == "-><init>(Ljava/lang/String;)V") { Obj& o = obj(a.at(0)); o.kind = Obj::Builder; o.s = strv(1); hasResult = false; return {}; }
        std::u16string& s = str(a.at(0));
        if (rest == "->append(C)" + c || rest == "->append(C)" + c) { s.push_back(static_cast<char16_t>(a[1].n)); return a[0]; }
        if (rest == "->append(Ljava/lang/String;)" + c) { s += a[1].ref >= 0 ? str(a[1]) : u"null"; return a[0]; }
        if (rest == "->append(I)" + c) { s += toU16(std::to_string(static_cast<int32_t>(a[1].n))); return a[0]; }
        if (rest == "->toString()Ljava/lang/String;") return mk(s);
        if (rest == "->length()I") return integer(static_cast<int64_t>(s.size()));
        if (rest == "->charAt(I)C") {
            if (a[1].n < 0 || static_cast<size_t>(a[1].n) >= s.size()) throw Stop{"StringIndexOutOfBoundsException"};
            return integer(s[static_cast<size_t>(a[1].n)]);
        }
        if (rest == "->reverse()" + c) { std::reverse(s.begin(), s.end()); return a[0]; }
        if (rest == "->setCharAt(IC)V") {
            if (a[1].n < 0 || static_cast<size_t>(a[1].n) >= s.size()) throw Stop{"StringIndexOutOfBoundsException"};
            s[static_cast<size_t>(a[1].n)] = static_cast<char16_t>(a[2].n);
            hasResult = false;
            return {};
        }
        if (rest == "->setLength(I)V") { s.resize(static_cast<size_t>(std::max<int64_t>(0, a[1].n))); hasResult = false; return {}; }
        throw Stop{"StringBuilder method " + sig + " is not emulated"};
    }
    if (is("Ljava/lang/Object;-><init>()V")) { hasResult = false; return {}; }
    // javax.crypto and java.security (mbedTLS)
    {
        const auto bytesVec = [&](const Value& v) {
            std::vector<uint8_t> out;
            for (int64_t b : obj(v).a) out.push_back(static_cast<uint8_t>(b));
            return out;
        };
        const auto byteArray = [&](const std::vector<uint8_t>& b) {
            const int r = newArr('B', b.size());
            for (size_t i = 0; i < b.size(); ++i) heap_[static_cast<size_t>(r)].a[i] = static_cast<int8_t>(b[i]);
            return ref(r);
        };
        if (is("Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V") || is("Ljavax/crypto/spec/SecretKeySpec;-><init>([BIILjava/lang/String;)V")) {
            const bool ranged = sig.find("[BII") != std::string::npos;
            std::vector<uint8_t> k = bytesVec(a.at(1));
            if (ranged) {
                if (a[2].n < 0 || a[3].n < 0 || static_cast<size_t>(a[2].n + a[3].n) > k.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
                k = std::vector<uint8_t>(k.begin() + a[2].n, k.begin() + a[2].n + a[3].n);
            }
            Obj& self = obj(a.at(0));
            self.kind = Obj::KeySpec;
            self.key = std::move(k);
            self.text = toU8(strv(ranged ? 4 : 2));
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V")) {
            Obj& self = obj(a.at(0));
            self.kind = Obj::IvSpec;
            self.iv = bytesVec(a.at(1));
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")) {
            const std::string name = toU8(strv(0));
            if (!emu::crypto::parse(name).ok) throw Stop{"the cipher transformation " + name + " is not emulated (AES, DES and DESede in ECB / CBC, AES CTR)"};
            Obj o;
            o.kind = Obj::Cipher;
            o.text = name;
            return ref(add(std::move(o)));
        }
        if (is("Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V") || is("Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V")) {
            Obj& c = obj(a.at(0));
            c.mode = static_cast<int>(a.at(1).n);
            if (c.mode != 1 && c.mode != 2) throw Stop{"Cipher mode " + std::to_string(c.mode) + " is not emulated (encrypt and decrypt only)"};
            c.key = obj(a.at(2)).key;
            c.iv.clear();
            if (a.size() > 3 && a[3].ref >= 0) c.iv = obj(a[3]).iv;
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/Cipher;->doFinal([B)[B")) {
            Obj& c = obj(a.at(0));
            if (c.mode == 0) throw Stop{"IllegalStateException: the cipher was not initialised"};
            std::vector<uint8_t> out;
            std::string why;
            if (!emu::crypto::run(emu::crypto::parse(c.text), c.mode == 1, c.key, c.iv, bytesVec(a.at(1)), out, why)) throw Stop{why};
            return byteArray(out);
        }
        if (is("Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;")) {
            const std::string name = toU8(strv(0));
            std::vector<uint8_t> probe;
            if (!emu::crypto::digest(name, {}, probe)) throw Stop{"the digest " + name + " is not emulated (MD5, SHA-1, SHA-256, SHA-512)"};
            Obj o;
            o.kind = Obj::Digest;
            o.text = name;
            return ref(add(std::move(o)));
        }
        if (is("Ljava/security/MessageDigest;->update([B)V")) {
            const auto b = bytesVec(a.at(1));
            Obj& d = obj(a.at(0));
            d.data.insert(d.data.end(), b.begin(), b.end());
            hasResult = false;
            return {};
        }
        if (is("Ljava/security/MessageDigest;->digest([B)[B") || is("Ljava/security/MessageDigest;->digest()[B")) {
            Obj& d = obj(a.at(0));
            if (a.size() > 1) {
                const auto b = bytesVec(a[1]);
                d.data.insert(d.data.end(), b.begin(), b.end());
            }
            std::vector<uint8_t> out;
            emu::crypto::digest(d.text, d.data, out);
            d.data.clear();
            return byteArray(out);
        }
    }
    if (is("Ljava/lang/Math;->abs(I)I")) return integer(a[0].n < 0 ? -a[0].n : a[0].n);
    if (is("Ljava/lang/Math;->min(II)I")) return integer(std::min(a[0].n, a[1].n));
    if (is("Ljava/lang/Math;->max(II)I")) return integer(std::max(a[0].n, a[1].n));
    if (is("Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V")) {
        auto& src = obj(a.at(0)).a;
        auto& dst = obj(a.at(2)).a;
        const int64_t sp = a[1].n, dp = a[3].n, n = a[4].n;
        if (sp < 0 || dp < 0 || n < 0 || static_cast<size_t>(sp + n) > src.size() || static_cast<size_t>(dp + n) > dst.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
        std::vector<int64_t> tmp(src.begin() + sp, src.begin() + sp + n);
        std::copy(tmp.begin(), tmp.end(), dst.begin() + dp);
        hasResult = false;
        return {};
    }
    if (is("[B->clone()Ljava/lang/Object;") || is("[C->clone()Ljava/lang/Object;") || is("[I->clone()Ljava/lang/Object;") || is("[S->clone()Ljava/lang/Object;")) {
        Obj copy = obj(a.at(0));
        cells_ += copy.a.size();
        if (cells_ > 8000000) throw Stop{"memory limit"};
        return ref(add(std::move(copy)));
    }
    if (is("Landroid/util/Base64;->decode(Ljava/lang/String;I)[B") || is("Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B")) {
        std::vector<uint8_t> out;
        const Value& s = is("Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B") ? a.at(1) : a.at(0);
        if (!b64(toU8(str(s)), out)) throw Stop{"IllegalArgumentException (bad base64)"};
        const int r = newArr('B', out.size());
        for (size_t i = 0; i < out.size(); ++i) heap_[static_cast<size_t>(r)].a[i] = static_cast<int8_t>(out[i]);
        return ref(r);
    }
    if (is("Ljava/util/Base64;->getDecoder()Ljava/util/Base64$Decoder;")) {
        Obj o;
        return ref(add(std::move(o)));
    }
    const size_t arrow = sig.find("->");
    const std::string cls = arrow == std::string::npos ? sig : sig.substr(0, arrow);
    if (cls.rfind("Ljavax/crypto/", 0) == 0 || cls.rfind("Ljava/security/", 0) == 0) throw Stop{"the call " + sig + " is not emulated (supported: Cipher AES / DES / DESede with init and doFinal, MessageDigest, SecretKeySpec, IvParameterSpec)"};
    throw Stop{"the call " + sig + " is not emulated"};
}

Value Machine::exec(const ApkAnalysis::MethodDef& m, const std::vector<Value>& args) {
    const DexFile& dex = *A.dexes().at(m.dex);
    DexFile::CodeItem code;
    if (!m.method.codeOff || !dex.codeItem(m.method.codeOff, code)) throw Stop{"the method has no code"};
    if (++depth_ > 24) throw Stop{"call depth limit"};
    struct Guard {
        int& d;
        ~Guard() { --d; }
    } guard{depth_};
    std::vector<Value> r(code.registers);
    if (args.size() > code.ins || code.ins > code.registers) throw Stop{"argument count does not match the method"};
    const size_t base = code.registers - code.ins;
    for (size_t i = 0; i < args.size(); ++i) r[base + i] = args[i];
    Value last;           // move-result
    uint32_t pc = 0;
    const auto reg = [&](uint32_t i) -> Value& {
        if (i >= r.size()) throw Stop{"register out of range"};
        return r[i];
    };
    const auto binop = [&](uint8_t kind, int64_t x, int64_t y, bool wide) -> int64_t {
        const auto w32 = [](int64_t v) { return static_cast<int64_t>(static_cast<int32_t>(v)); };
        switch (kind) {
        case 0: return wide ? x + y : w32(x + y);
        case 1: return wide ? x - y : w32(x - y);
        case 2: return wide ? x * y : w32(static_cast<int64_t>(static_cast<uint32_t>(x) * static_cast<uint32_t>(y)));
        case 3: if (!y) throw Stop{"ArithmeticException (divide by zero)"}; return wide ? x / y : w32(x / y);
        case 4: if (!y) throw Stop{"ArithmeticException (divide by zero)"}; return wide ? x % y : w32(x % y);
        case 5: return x & y;
        case 6: return x | y;
        case 7: return x ^ y;
        case 8: return wide ? x << (y & 63) : w32(static_cast<int64_t>(static_cast<uint32_t>(x) << (y & 31)));
        case 9: return wide ? x >> (y & 63) : w32(static_cast<int32_t>(x) >> (y & 31));
        default: return wide ? static_cast<int64_t>(static_cast<uint64_t>(x) >> (y & 63)) : w32(static_cast<int64_t>(static_cast<uint32_t>(x) >> (y & 31)));
        }
    };
    while (true) {
        if (++steps_ > maxSteps_) throw Stop{"step limit reached"};
        if (pc >= code.insnsSize) throw Stop{"ran off the end of the method"};
        const dalvik::Insn in = dalvik::decode(code, pc);
        if (!in.valid || in.payload) throw Stop{"invalid instruction"};
        uint32_t next = pc + in.size;
        const uint8_t op = in.opcode;
        const auto A_ = [&]() -> Value& { return reg(in.regs[0]); };
        const auto B_ = [&]() -> Value& { return reg(in.regs[1]); };
        const auto C_ = [&]() -> Value& { return reg(in.regs[2]); };
        const auto jump = [&]() { next = static_cast<uint32_t>(static_cast<int64_t>(pc) + in.branch); };
        if (op == 0x00) {
        } else if (op >= 0x01 && op <= 0x09) {  // move family
            A_() = B_();
        } else if (op == 0x0a || op == 0x0b || op == 0x0c) {
            A_() = last;
        } else if (op == 0x0d) {
            throw Stop{"exception handling is not emulated"};
        } else if (op == 0x0e) {
            return {};
        } else if (op == 0x0f || op == 0x10 || op == 0x11) {
            return A_();
        } else if (op >= 0x12 && op <= 0x19) {  // const family
            Value v;
            v.n = op >= 0x16 ? in.literal : static_cast<int32_t>(in.literal);
            A_() = v;
        } else if (op == 0x1a || op == 0x1b) {
            A_() = constant(dex, in.index);
        } else if (op == 0x21) {
            Value v;
            v.n = static_cast<int64_t>(obj(B_()).a.size());
            A_() = v;
        } else if (op == 0x22) {
            const std::string t(dex.typeDescriptor(in.index));
            Obj o;
            if (t == "Ljava/lang/String;") o.kind = Obj::Str;
            else if (t == "Ljava/lang/StringBuilder;" || t == "Ljava/lang/StringBuffer;") o.kind = Obj::Builder;
            else if (t == "Ljava/lang/Object;") o.kind = Obj::Dummy;
            else if (t == "Ljavax/crypto/spec/SecretKeySpec;") o.kind = Obj::KeySpec;
            else if (t == "Ljavax/crypto/spec/IvParameterSpec;") o.kind = Obj::IvSpec;
            else throw Stop{"creates an instance of " + t + ", which is not emulated"};
            A_() = ref(add(std::move(o)));
        } else if (op == 0x23) {
            const std::string t(dex.typeDescriptor(in.index));
            const int64_t n = B_().n;
            if (t.size() != 2 || t[0] != '[' || n < 0) throw Stop{"array type " + t + " is not emulated"};
            A_() = ref(newArr(t[1], static_cast<size_t>(n)));
        } else if (op == 0x24 || op == 0x25) {
            const std::string t(dex.typeDescriptor(in.index));
            if (t.size() != 2 || t[0] != '[') throw Stop{"array type " + t + " is not emulated"};
            const int a = newArr(t[1], in.regCount);
            for (uint32_t k = 0; k < in.regCount; ++k) heap_[static_cast<size_t>(a)].a[k] = reg(in.range ? in.regs[0] + k : in.regs[k]).n;
            last = ref(a);
        } else if (op == 0x26) {
            const int64_t at = static_cast<int64_t>(pc) + in.branch;
            if (at < 0 || static_cast<uint64_t>(at) + 4 > code.insnsSize) throw Stop{"bad array payload"};
            const uint32_t width = code.unit(static_cast<uint32_t>(at) + 1);
            const uint32_t count = code.unit(static_cast<uint32_t>(at) + 2) | (static_cast<uint32_t>(code.unit(static_cast<uint32_t>(at) + 3)) << 16);
            auto& arr = obj(A_()).a;
            if (count > arr.size() || static_cast<uint64_t>(at) + 4 + (static_cast<uint64_t>(width) * count + 1) / 2 > code.insnsSize) throw Stop{"bad array payload"};
            const uint8_t* p = code.insns + 2 * (static_cast<size_t>(at) + 4);
            for (uint32_t k = 0; k < count; ++k) {
                int64_t v = 0;
                for (uint32_t b = 0; b < width; ++b) v |= static_cast<int64_t>(p[k * width + b]) << (8 * b);
                if (width < 8 && (v >> (width * 8 - 1)) & 1 && obj(A_()).elem != 'C') v |= ~0ll << (width * 8);
                arr[k] = v;
            }
        } else if (op == 0x27) {
            throw Stop{"the routine throws an exception"};
        } else if (op == 0x28 || op == 0x29 || op == 0x2a) {
            jump();
        } else if (op == 0x2b || op == 0x2c) {
            const int64_t at = static_cast<int64_t>(pc) + in.branch;
            if (at < 0 || static_cast<uint64_t>(at) + 2 > code.insnsSize) throw Stop{"bad switch payload"};
            const uint32_t p = static_cast<uint32_t>(at), n = code.unit(p + 1);
            const int64_t v = static_cast<int32_t>(A_().n);
            const auto rd32 = [&](uint32_t k) { return static_cast<int32_t>(code.unit(k) | (static_cast<uint32_t>(code.unit(k + 1)) << 16)); };
            if (static_cast<uint64_t>(p) + 4 + static_cast<uint64_t>(n) * 4 > code.insnsSize) throw Stop{"bad switch payload"};
            if (op == 0x2b) {
                const int64_t first = rd32(p + 2);
                if (v >= first && v < first + n) next = static_cast<uint32_t>(static_cast<int64_t>(pc) + rd32(p + 4 + 2 * static_cast<uint32_t>(v - first)));
            } else {
                for (uint32_t k = 0; k < n; ++k)
                    if (rd32(p + 2 + 2 * k) == v) {
                        next = static_cast<uint32_t>(static_cast<int64_t>(pc) + rd32(p + 2 + 2 * n + 2 * k));
                        break;
                    }
            }
        } else if (op >= 0x2d && op <= 0x31) {
            if (op != 0x31) throw Stop{"floating-point comparison is not emulated"};
            Value v;
            v.n = B_().n < C_().n ? -1 : B_().n > C_().n ? 1 : 0;
            A_() = v;
        } else if (op >= 0x32 && op <= 0x37) {
            const int64_t x = static_cast<int32_t>(A_().n), y = static_cast<int32_t>(B_().n);
            const bool refs = A_().ref >= 0 || B_().ref >= 0;
            const int64_t xx = refs ? A_().ref : x, yy = refs ? B_().ref : y;
            const bool t = op == 0x32 ? xx == yy : op == 0x33 ? xx != yy : op == 0x34 ? xx < yy : op == 0x35 ? xx >= yy : op == 0x36 ? xx > yy : xx <= yy;
            if (t) jump();
        } else if (op >= 0x38 && op <= 0x3d) {
            const bool isRef = A_().ref >= 0;
            const int64_t x = isRef ? A_().ref + 1 : static_cast<int32_t>(A_().n);  // null (ref -1) -> 0
            const bool t = op == 0x38 ? x == 0 : op == 0x39 ? x != 0 : op == 0x3a ? x < 0 : op == 0x3b ? x >= 0 : op == 0x3c ? x > 0 : x <= 0;
            if (t) jump();
        } else if (op >= 0x44 && op <= 0x4a) {
            const auto& arr = obj(B_()).a;
            const int64_t idx = static_cast<int32_t>(C_().n);
            if (idx < 0 || static_cast<size_t>(idx) >= arr.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
            Value v;
            v.n = arr[static_cast<size_t>(idx)];
            A_() = v;
        } else if (op >= 0x4b && op <= 0x51) {
            auto& o = obj(B_());
            const int64_t idx = static_cast<int32_t>(C_().n);
            if (idx < 0 || static_cast<size_t>(idx) >= o.a.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
            int64_t v = A_().n;
            if (op == 0x4f) v = static_cast<int8_t>(v);
            else if (op == 0x50) v = static_cast<char16_t>(v);
            else if (op == 0x51) v = static_cast<int16_t>(v);
            o.a[static_cast<size_t>(idx)] = v;
        } else if (op >= 0x60 && op <= 0x66) {
            A_() = sget(dex, in.index);
        } else if (op >= 0x67 && op <= 0x6d) {
            sput(dex, in.index, A_());
        } else if (op >= 0x52 && op <= 0x5f) {
            throw Stop{"instance fields are not emulated"};
        } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
            std::vector<Value> callArgs;
            for (uint32_t k = 0; k < in.regCount; ++k) callArgs.push_back(reg(in.range ? in.regs[0] + k : in.regs[k]));
            const std::string sig = dex.methodSignature(in.index);
            const bool isStatic = op == 0x71 || op == 0x77;
            bool hasResult = false;
            const std::string cls(dex.typeDescriptor(dex.methodClass(in.index)));
            Value res;
            if (A.findClass(cls)) res = callApp(dex, in.index, callArgs, isStatic, hasResult);
            else res = libCall(sig, callArgs, hasResult);
            if (hasResult) last = res;
        } else if (op == 0x7b || op == 0x7c || op == 0x7d || op == 0x7e) {
            Value v;
            v.n = (op == 0x7b || op == 0x7d) ? -B_().n : ~B_().n;
            if (op < 0x7d) v.n = static_cast<int32_t>(v.n);
            A_() = v;
        } else if (op == 0x81 || op == 0x84 || op == 0x8d || op == 0x8e || op == 0x8f || op == 0x82) {
            Value v;
            const int64_t x = B_().n;
            v.n = op == 0x81 ? static_cast<int32_t>(x) : op == 0x84 ? static_cast<int32_t>(x) : op == 0x8d ? static_cast<int8_t>(x) : op == 0x8e ? static_cast<char16_t>(x) : static_cast<int16_t>(x);
            A_() = v;
        } else if (op >= 0x90 && op <= 0xaf) {
            const bool wide = op >= 0x9b;
            const uint8_t kind = static_cast<uint8_t>((op - (wide ? 0x9b : 0x90)));
            if (op >= 0xa6) throw Stop{"floating-point arithmetic is not emulated"};
            Value v;
            v.n = binop(kind, B_().n, C_().n, wide);
            A_() = v;
        } else if (op >= 0xb0 && op <= 0xcf) {
            const bool wide = op >= 0xbb;
            const uint8_t kind = static_cast<uint8_t>((op - (wide ? 0xbb : 0xb0)));
            if (op >= 0xc6) throw Stop{"floating-point arithmetic is not emulated"};
            Value v;
            v.n = binop(kind, A_().n, B_().n, wide);
            A_() = v;
        } else if ((op >= 0xd0 && op <= 0xd7) || (op >= 0xd8 && op <= 0xe2)) {
            const bool lit8 = op >= 0xd8;
            const uint8_t k = lit8 ? static_cast<uint8_t>(op - 0xd8) : static_cast<uint8_t>(op - 0xd0);
            Value v;
            const int64_t x = B_().n;
            if (k == 1 && (op == 0xd1 || op == 0xd9)) v.n = static_cast<int32_t>(in.literal - x);  // rsub
            else {
                static const uint8_t map16[8] = {0, 255, 2, 3, 4, 5, 6, 7};
                const uint8_t kind = lit8 ? (k == 1 ? 255 : k < 8 ? map16[k] : static_cast<uint8_t>(k == 8 ? 8 : k == 9 ? 9 : 10)) : map16[k];
                v.n = binop(kind, x, in.literal, false);
            }
            A_() = v;
        } else {
            throw Stop{std::string("the instruction ") + dalvik::opInfo(op).name + " is not emulated"};
        }
        pc = next;
    }
}

std::string describeArgs(const std::vector<Arg>& a) {
    std::string s;
    for (const Arg& x : a) {
        if (!s.empty()) s += ", ";
        if (x.kind == Arg::Kind::Int) s += std::to_string(x.number);
        else if (x.kind == Arg::Kind::String) {
            s += '"';
            for (char c : x.text.substr(0, 60)) s += c == '\n' ? std::string("\\n") : std::string(1, c);
            s += '"';
        } else s += "byte[" + std::to_string(x.bytes.size()) + "]";
    }
    return s;
}

}  // namespace

Outcome runStatic(const ApkAnalysis& analysis, const ApkAnalysis::MethodDef& method, const std::vector<Arg>& args, uint64_t maxSteps) {
    Outcome out;
    Machine m(analysis, maxSteps);
    try {
        const DexFile& dex = *analysis.dexes().at(method.dex);
        const std::string cls(dex.typeDescriptor(dex.methodClass(method.method.methodIdx)));
        std::vector<Value> vals;
        for (const Arg& a : args) {
            if (a.kind == Arg::Kind::Int) vals.push_back(Value{a.number, -1});
            else if (a.kind == Arg::Kind::String) vals.push_back(m.ref(m.newStr(toU16(a.text))));
            else {
                const int r = m.newArr('B', a.bytes.size());
                for (size_t i = 0; i < a.bytes.size(); ++i) m.obj(m.ref(r)).a[i] = static_cast<int8_t>(a.bytes[i]);
                vals.push_back(m.ref(r));
            }
        }
        m.ensureInit(cls);  // the class's static initialiser: keys and tables live there
        const Value v = m.exec(method, vals);
        out.steps = m.steps();
        const std::string proto = dex.protoDescriptor(dex.methodProto(method.method.methodIdx));
        out.ok = true;
        if (proto.size() > 1 && proto.back() == ';' && proto.find(")Ljava/lang/String;") != std::string::npos) {
            if (v.ref < 0) out.text = "null";
            else out.text = toU8(m.str(v)), out.isString = true;
        } else if (proto.find(")[B") != std::string::npos && v.ref >= 0) {
            char b[4];
            for (int64_t x : m.obj(v).a) std::snprintf(b, sizeof b, "%02x", static_cast<unsigned>(x) & 0xff), out.text += b;
        } else {
            out.text = std::to_string(v.n);
        }
    } catch (const Stop& s) {
        out.error = s.why;
        out.steps = m.steps();
    } catch (const std::exception& e) {
        out.error = e.what();
    }
    return out;
}

std::vector<Decrypted> decryptCallSites(const ApkAnalysis& a, const std::atomic<bool>& stop, size_t limit, SweepStats* stats) {
    std::vector<Decrypted> out;
    SweepStats local;
    SweepStats& st = stats ? *stats : local;
    // Candidate decoders: static, String result, parameters limited to String and int.
    struct Candidate {
        ApkAnalysis::MethodDef def;
        std::string cls, name, proto, sig;
    };
    std::vector<Candidate> cands;
    for (const auto& c : a.classes()) {
        if (stop.load()) return out;
        for (const auto& m : a.methodsOf(c)) {
            if (!(m.method.accessFlags & 0x8) || !m.method.codeOff) continue;  // static with code
            const DexFile& dex = *a.dexes()[m.dex];
            const std::string proto = dex.protoDescriptor(dex.methodProto(m.method.methodIdx));
            const size_t close = proto.find(')');
            if (close == std::string::npos || proto.compare(close, std::string::npos, ")Ljava/lang/String;") != 0) continue;
            const std::string params = proto.substr(1, close - 1);
            if (params.empty()) continue;
            bool ok = true;
            for (size_t i = 0; i < params.size();) {
                if (params[i] == 'I') ++i;
                else if (params.compare(i, 18, "Ljava/lang/String;") == 0) i += 18;
                else { ok = false; break; }
            }
            if (!ok) continue;
            cands.push_back({m, std::string(dex.typeDescriptor(dex.methodClass(m.method.methodIdx))), std::string(dex.methodName(m.method.methodIdx)), proto,
                             dex.methodSignature(m.method.methodIdx)});
        }
    }
    st.decoders = cands.size();
    const auto start = std::chrono::steady_clock::now();
    for (const Candidate& cand : cands) {
        if (stop.load() || out.size() >= limit || std::chrono::steady_clock::now() - start > std::chrono::seconds(60)) break;
        const auto sites = a.callersOf(cand.cls, cand.name, cand.proto, 4000);
        if (sites.size() < 3) continue;  // a real decoder is called from many places
        bool worked = false;
        size_t candFailed = 0;
        std::map<uint64_t, std::vector<uint32_t>> pcCache;
        for (const auto& hit : sites) {
            if (stop.load() || out.size() >= limit) break;
            const DexFile& cdex = *a.dexes().at(hit.from.dex);
            DexFile::CodeItem code;
            // Find the method def of the caller to reach its code.
            const auto defs = a.findMethodDefs(cdex.typeDescriptor(cdex.methodClass(hit.from.method)), cdex.methodName(hit.from.method),
                                               cdex.protoDescriptor(cdex.methodProto(hit.from.method)));
            const ApkAnalysis::MethodDef* caller = nullptr;
            for (const auto& d : defs)
                if (d.dex == hit.from.dex && d.method.methodIdx == hit.from.method) caller = &d;
            if (!caller || !cdex.codeItem(caller->method.codeOff, code)) continue;
            const dalvik::Insn call = dalvik::decode(code, hit.from.pc);
            if (!call.valid || call.regCount == 0) continue;
            // Constant arguments: the nearest `const-string` / `const` writing each register, straight-line before the call.
            const uint64_t key = (static_cast<uint64_t>(hit.from.dex) << 32) | hit.from.method;
            auto cached = pcCache.find(key);
            if (cached == pcCache.end()) {
                if (pcCache.size() > 64) pcCache.clear();
                std::vector<uint32_t> all;
                for (uint32_t pc = 0; pc < code.insnsSize && all.size() < 200000;) {
                    const dalvik::Insn i = dalvik::decode(code, pc);
                    all.push_back(pc);
                    pc += i.valid ? i.size : 1;
                }
                cached = pcCache.emplace(key, std::move(all)).first;
            }
            std::vector<uint32_t> pcs;
            for (uint32_t pc : cached->second) {
                if (pc >= hit.from.pc) break;
                pcs.push_back(pc);
            }
            std::vector<Arg> args;
            bool constant = true;
            const std::string params = cand.proto.substr(1, cand.proto.find(')') - 1);
            size_t pi = 0;
            for (uint32_t k = 0; k < call.regCount && constant; ++k) {
                const uint32_t want = call.range ? call.regs[0] + k : call.regs[k];
                bool found = false;
                for (size_t back = 0; back < 40 && back < pcs.size() && !found; ++back) {
                    const dalvik::Insn i = dalvik::decode(code, pcs[pcs.size() - 1 - back]);
                    if (!i.valid) break;
                    const dalvik::OpInfo& info = dalvik::opInfo(i.opcode);
                    if (info.flow != dalvik::Flow::Normal && info.flow != dalvik::Flow::Invoke) break;  // leaves straight-line code
                    if (i.regCount == 0 || i.regs[0] != want) continue;
                    if (i.opcode == 0x1a || i.opcode == 0x1b) {
                        if (params.compare(pi, 18, "Ljava/lang/String;") != 0) { constant = false; break; }
                        args.push_back(Arg::string(cdex.string(i.index)));
                        pi += 18;
                        found = true;
                    } else if (i.opcode >= 0x12 && i.opcode <= 0x15) {
                        if (pi >= params.size() || params[pi] != 'I') { constant = false; break; }
                        args.push_back(Arg::integer(static_cast<int32_t>(i.literal)));
                        ++pi;
                        found = true;
                    } else {
                        constant = false;  // written by something else: not a constant
                        break;
                    }
                }
                if (!found) constant = false;
            }
            if (!constant || args.empty()) continue;
            ++st.callSites;
            const Outcome r = runStatic(a, cand.def, args);
            if (!r.ok) {
                ++st.failed;
                ++candFailed;
                if (st.firstError.empty()) st.firstError = cand.sig + ": " + r.error;
                if (!worked && candFailed > 6) break;  // this routine is not something the interpreter can run
                continue;
            }
            worked = true;
            Decrypted d;
            d.caller = cdex.methodSignature(hit.from.method);
            d.pc = hit.from.pc;
            d.decoder = cand.sig;
            d.args = describeArgs(args);
            d.result = r.text;
            out.push_back(std::move(d));
        }
        if (worked) ++st.working;
    }
    return out;
}

}  // namespace emu
