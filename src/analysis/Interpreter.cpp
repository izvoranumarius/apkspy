#include "analysis/Interpreter.hpp"
#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cwctype>
#include <limits>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstring>
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

// A Java exception on its way to a handler. `why` is what the run reports when nothing catches it.
struct Thrown {
    std::string type;  // "Ljava/lang/ArithmeticException;"
    int ref = -1;      // the exception object, -1 until a handler needs one
    std::string why;
};

// The superclass of the library exceptions a decoder can meet ("" for Object / unknown).
std::string librarySuper(const std::string& type) {
    static const std::pair<const char*, const char*> table[] = {
        {"java/lang/Exception", "java/lang/Throwable"},
        {"java/lang/Error", "java/lang/Throwable"},
        {"java/lang/Throwable", "java/lang/Object"},
        {"java/lang/RuntimeException", "java/lang/Exception"},
        {"java/lang/ArithmeticException", "java/lang/RuntimeException"},
        {"java/lang/NullPointerException", "java/lang/RuntimeException"},
        {"java/lang/ClassCastException", "java/lang/RuntimeException"},
        {"java/lang/IllegalArgumentException", "java/lang/RuntimeException"},
        {"java/lang/IllegalStateException", "java/lang/RuntimeException"},
        {"java/lang/UnsupportedOperationException", "java/lang/RuntimeException"},
        {"java/lang/NegativeArraySizeException", "java/lang/RuntimeException"},
        {"java/lang/SecurityException", "java/lang/RuntimeException"},
        {"java/lang/NumberFormatException", "java/lang/IllegalArgumentException"},
        {"java/lang/IndexOutOfBoundsException", "java/lang/RuntimeException"},
        {"java/lang/ArrayIndexOutOfBoundsException", "java/lang/IndexOutOfBoundsException"},
        {"java/lang/StringIndexOutOfBoundsException", "java/lang/IndexOutOfBoundsException"},
        {"java/lang/ReflectiveOperationException", "java/lang/Exception"},
        {"java/lang/ClassNotFoundException", "java/lang/ReflectiveOperationException"},
        {"java/lang/NoSuchMethodException", "java/lang/ReflectiveOperationException"},
        {"java/lang/IllegalAccessException", "java/lang/ReflectiveOperationException"},
        {"java/lang/reflect/InvocationTargetException", "java/lang/ReflectiveOperationException"},
        {"java/io/IOException", "java/lang/Exception"},
        {"java/io/UnsupportedEncodingException", "java/io/IOException"},
        {"java/security/GeneralSecurityException", "java/lang/Exception"},
        {"java/security/KeyException", "java/security/GeneralSecurityException"},
        {"java/security/InvalidKeyException", "java/security/KeyException"},
        {"java/security/NoSuchAlgorithmException", "java/security/GeneralSecurityException"},
        {"java/security/InvalidAlgorithmParameterException", "java/security/GeneralSecurityException"},
        {"java/security/spec/InvalidKeySpecException", "java/security/GeneralSecurityException"},
        {"javax/crypto/BadPaddingException", "java/security/GeneralSecurityException"},
        {"javax/crypto/AEADBadTagException", "javax/crypto/BadPaddingException"},
        {"javax/crypto/IllegalBlockSizeException", "java/security/GeneralSecurityException"},
        {"javax/crypto/NoSuchPaddingException", "java/security/GeneralSecurityException"},
        {"java/util/NoSuchElementException", "java/lang/RuntimeException"},
    };
    for (const auto& [sub, super] : table)
        if (type == std::string("L") + sub + ";") return std::string("L") + super + ";";
    return {};
}

// The exception a stop reason stands for ("ArrayIndexOutOfBoundsException", "null pointer"), "" for the interpreter's
// own limits and gaps, which no handler may catch.
std::string javaExceptionOf(const std::string& why) {
    if (why == "null pointer") return "Ljava/lang/NullPointerException;";
    const std::string word = why.substr(0, why.find_first_of(": ("));
    static const char* const known[] = {
        "java/lang/ArithmeticException",     "java/lang/ArrayIndexOutOfBoundsException", "java/lang/StringIndexOutOfBoundsException",
        "java/lang/IndexOutOfBoundsException", "java/lang/NumberFormatException",        "java/lang/IllegalArgumentException",
        "java/lang/IllegalStateException",   "java/lang/NegativeArraySizeException",     "java/lang/ClassNotFoundException",
        "java/lang/NoSuchMethodException",   "java/security/InvalidKeyException",        "java/security/InvalidAlgorithmParameterException",
        "java/security/spec/InvalidKeySpecException", "javax/crypto/BadPaddingException", "javax/crypto/AEADBadTagException",
        "javax/crypto/IllegalBlockSizeException", "java/util/NoSuchElementException"};
    for (const char* k : known)
        if (word == std::string(k).substr(std::string(k).rfind('/') + 1)) return std::string("L") + k + ";";
    return {};
}

struct Value {
    int64_t n = 0;
    int ref = -1;  // heap index, -1 = null / not a reference
};

struct Obj {
    // List: java.util lists, and snapshots of a map's keys, values or entries. Map: maps and sets (`isSet`).
    // Iter: an iterator over a snapshot. Entry: a map entry (a = {key, value}).
    enum Kind : uint8_t { Str, Arr, Builder, Dummy, Cipher, KeySpec, IvSpec, Digest, Error, Klass, Method, Box, Instance, OaepSpec, List, Map, Iter, Entry } kind = Dummy;
    std::u16string s;
    std::vector<int64_t> a;
    char elem = 'I';  // B, C, I, S, Z, J
    // javax.crypto / java.security state
    std::string text;               // transformation or digest algorithm; class descriptor (Error, Klass, Method)
    std::vector<uint8_t> key, iv, data;  // data: digest input, or GCM additional data
    int mode = 0;                   // Cipher.ENCRYPT_MODE = 1, DECRYPT_MODE = 2
    unsigned tagBits = 0;           // GCMParameterSpec
    bool privateKey = false;        // KeySpec: a private RSA key
    std::vector<std::string> params;  // Method: parameter descriptors
    std::map<std::string, Value> fields;  // Instance / Error: "Ldeclaring;->name:type" -> value
    std::string mgf;                 // OaepSpec / Cipher: the mask digest (text of an OaepSpec is its main digest)
    std::string oaepHash;            // Cipher: main digest from an OAEPParameterSpec
    // Collections hold references as ref + 1; a Map holds key, value pairs (a set: key, 0).
    enum Order : uint8_t { Insertion, Hashed, Unknown } order = Insertion;  // Hashed: java.util.HashMap's table order
    bool isSet = false;
    uint32_t capacity = 16;  // Hashed: the table size, which only grows
    size_t pos = 0;          // Iter
};

float asFloat(int64_t n) { return std::bit_cast<float>(static_cast<uint32_t>(n)); }
int64_t fromFloat(float f) { return static_cast<int32_t>(std::bit_cast<uint32_t>(f)); }
double asDouble(int64_t n) { return std::bit_cast<double>(n); }
int64_t fromDouble(double d) { return std::bit_cast<int64_t>(d); }

// Java's narrowing of a float or double: NaN is 0, out-of-range values saturate.
template <class I, class F>
I javaToInt(F v) {
    if (std::isnan(v)) return 0;
    if (v >= static_cast<F>(std::numeric_limits<I>::max())) return std::numeric_limits<I>::max();
    if (v <= static_cast<F>(std::numeric_limits<I>::min())) return std::numeric_limits<I>::min();
    return static_cast<I>(v);
}

// Float.toString / Double.toString: the shortest digits that read back, laid out as Java does ("1.0", "1.5E-4").
template <class F>
std::string javaNumber(F v) {
    if (std::isnan(v)) return "NaN";
    if (std::isinf(v)) return v > 0 ? "Infinity" : "-Infinity";
    if (v == 0) return std::signbit(v) ? "-0.0" : "0.0";
    char buf[64];
    const auto r = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::scientific);
    std::string s(buf, r.ptr);  // "-1.2345e+06"
    const bool neg = s[0] == '-';
    if (neg) s.erase(0, 1);
    const size_t e = s.find('e');
    const int exp = std::atoi(s.c_str() + e + 1);
    std::string digits = s.substr(0, e);
    digits.erase(std::remove(digits.begin(), digits.end(), '.'), digits.end());
    const F mag = neg ? -v : v;
    std::string out;
    if (mag >= static_cast<F>(1e-3) && mag < static_cast<F>(1e7)) {
        if (exp >= 0) {
            const size_t whole = static_cast<size_t>(exp) + 1;
            if (digits.size() < whole) digits.append(whole - digits.size(), '0');
            out = digits.substr(0, whole) + "." + (digits.size() > whole ? digits.substr(whole) : "0");
        } else {
            out = "0." + std::string(static_cast<size_t>(-exp - 1), '0') + digits;
        }
    } else {
        out = digits.substr(0, 1) + "." + (digits.size() > 1 ? digits.substr(1) : "0") + "E" + std::to_string(exp);
    }
    return neg ? "-" + out : out;
}

int digitOf(char16_t c, int radix) {
    int d = -1;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
    return d < radix ? d : -1;
}

// Integer.parseInt / Long.parseLong with a radix: false where Java throws NumberFormatException.
bool parseInteger(const std::u16string& s, int radix, int64_t lo, int64_t hi, int64_t& out) {
    if (s.empty() || radix < 2 || radix > 36) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-' || s[0] == '+') {
        neg = s[0] == '-';
        if (s.size() == 1) return false;
        i = 1;
    }
    const uint64_t limit = neg ? static_cast<uint64_t>(-(lo + 1)) + 1 : static_cast<uint64_t>(hi);
    uint64_t v = 0;
    for (; i < s.size(); ++i) {
        const int d = digitOf(s[i], radix);
        if (d < 0 || v > (limit - static_cast<uint64_t>(d)) / static_cast<uint64_t>(radix)) return false;
        v = v * static_cast<uint64_t>(radix) + static_cast<uint64_t>(d);
    }
    out = neg ? static_cast<int64_t>(0 - v) : static_cast<int64_t>(v);
    return true;
}

// Integer.toString(n, radix) and friends; `unsignedBits` > 0: toHexString-style unsigned text of that width.
std::string integerText(int64_t n, int radix, int unsignedBits = 0) {
    if (radix < 2 || radix > 36) radix = 10;
    uint64_t v = unsignedBits ? (unsignedBits == 64 ? static_cast<uint64_t>(n) : static_cast<uint64_t>(n) & ((1ull << unsignedBits) - 1))
                              : (n < 0 ? 0 - static_cast<uint64_t>(n) : static_cast<uint64_t>(n));
    std::string s;
    do {
        s.push_back("0123456789abcdefghijklmnopqrstuvwxyz"[v % static_cast<uint64_t>(radix)]);
        v /= static_cast<uint64_t>(radix);
    } while (v);
    if (!unsignedBits && n < 0) s.push_back('-');
    std::reverse(s.begin(), s.end());
    return s;
}

// Float.parseFloat / Double.parseDouble.
template <class F>
bool parseReal(std::string s, F& out) {
    while (!s.empty() && static_cast<unsigned char>(s.back()) <= ' ') s.pop_back();
    size_t b = 0;
    while (b < s.size() && static_cast<unsigned char>(s[b]) <= ' ') ++b;
    s = s.substr(b);
    if (!s.empty() && std::strchr("fFdD", s.back())) s.pop_back();
    bool neg = false;
    if (!s.empty() && (s[0] == '+' || s[0] == '-')) neg = s[0] == '-', s.erase(0, 1);
    if (s == "NaN") return out = std::numeric_limits<F>::quiet_NaN(), true;
    if (s == "Infinity") return out = neg ? -std::numeric_limits<F>::infinity() : std::numeric_limits<F>::infinity(), true;
    if (s.empty() || s[0] == '+' || s[0] == '-') return false;
    F v{};
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec == std::errc::invalid_argument || r.ptr != s.data() + s.size()) return false;
    if (r.ec == std::errc::result_out_of_range) {  // Java rounds to infinity or zero
        const size_t e = s.find_first_of("eE");
        v = e != std::string::npos && e + 1 < s.size() && s[e + 1] == '-' ? F(0) : std::numeric_limits<F>::infinity();
    }
    out = neg ? -v : v;
    return true;
}

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
    // The exception's text for the user: "IllegalStateException: boom".
    std::string describe(const Thrown& t);
    void ensureInit(const std::string& cls);

private:
    int add(Obj o) {
        if (heap_.size() > 2000000) throw Stop{"memory limit"};
        heap_.push_back(std::move(o));
        return static_cast<int>(heap_.size()) - 1;
    }
    Value libCall(const std::string& sig, const std::vector<Value>& a, bool& hasResult);
    bool throwableCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult);
    bool reflectionCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult);
    // Math, Float, Double, Long, Integer, Character and the boxes.
    bool numberCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult);
    // java.util lists, maps, sets and their iterators.
    bool collectionCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult);
    bool sameKey(const Value& x, const Value& y) const;
    int32_t hashOf(const Value& v) const;
    std::vector<int64_t> elementsOf(const Value& v) const;  // a collection's or array's references, in iteration order
    std::vector<size_t> mapOrder(const Obj& m) const;       // entry indexes in iteration order
    std::u16string textOf(const Value& v) const;            // String.valueOf(Object)
    Value newObj(Obj o) { cells_ += o.a.size(); if (cells_ > 8000000) throw Stop{"memory limit"}; return ref(add(std::move(o))); }
    Value invoke(const DexFile& dex, uint32_t methodIdx, const std::vector<Value>& a, uint8_t opcode, bool& hasResult);
    // The implementation of name + proto that class `from` has or inherits, with code. False when only a library
    // class (or nothing) provides it.
    bool findImplementation(const std::string& from, const std::string& name, const std::string& proto, ApkAnalysis::MethodDef& out) const;
    std::string fieldKey(const DexFile& dex, uint32_t fieldIdx) const;
    std::string superOf(const std::string& type) const;
    bool isSubtype(std::string type, const std::string& of) const;
    // Where the exception thrown at `pc` goes, if this method catches it.
    bool handlerFor(const DexFile& dex, const DexFile::CodeItem& code, uint32_t pc, const std::string& type, uint32_t& handler) const;
    Value classObject(const std::string& descriptor) {
        Obj o;
        o.kind = Obj::Klass;
        o.text = descriptor;
        return ref(add(std::move(o)));
    }
    static bool refElement(char elem) { return elem == 'L' || elem == '['; }  // arrays of references hold ref + 1
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
    int caught_ = -1;  // the exception move-exception hands to the handler
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
    ensureInit(superOf(cls));
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

std::string Machine::superOf(const std::string& type) const {
    if (const ApkAnalysis::ClassEntry* ce = A.findClass(type)) {
        const DexFile& dex = *A.dexes()[ce->dex];
        const uint32_t super = A.classDef(*ce).superclassIdx;
        return super == DexFile::kNoIndex ? std::string() : std::string(dex.typeDescriptor(super));
    }
    const std::string known = librarySuper(type);
    if (!known.empty()) return known;
    // Other library exceptions: close enough to be caught by "Exception" / "Error" / "Throwable".
    if (type.size() > 11 && type.compare(type.size() - 10, 10, "Exception;") == 0) return "Ljava/lang/Exception;";
    if (type.size() > 7 && type.compare(type.size() - 6, 6, "Error;") == 0) return "Ljava/lang/Error;";
    return {};
}

bool Machine::isSubtype(std::string type, const std::string& of) const {
    std::vector<std::string> work{std::move(type)};
    for (size_t i = 0; i < work.size() && i < 64; ++i) {
        const std::string t = work[i];
        if (t.empty()) continue;
        if (t == of) return true;
        work.push_back(superOf(t));
        if (const ApkAnalysis::ClassEntry* ce = A.findClass(t)) {
            const DexFile& dex = *A.dexes()[ce->dex];
            for (uint32_t itf : dex.interfaces(A.classDef(*ce))) work.push_back(std::string(dex.typeDescriptor(itf)));
        }
    }
    return false;
}

bool Machine::findImplementation(const std::string& from, const std::string& name, const std::string& proto, ApkAnalysis::MethodDef& out) const {
    std::vector<std::string> interfaces;
    const auto declaredBy = [&](const std::string& cls) {
        for (const auto& d : A.findMethodDefs(cls, name, proto))
            if (d.method.codeOff) {
                out = d;
                return true;
            }
        return false;
    };
    std::string cls = from;
    for (int i = 0; i < 32 && !cls.empty(); ++i) {
        const ApkAnalysis::ClassEntry* ce = A.findClass(cls);
        if (!ce) break;
        if (declaredBy(cls)) return true;
        const DexFile& dex = *A.dexes()[ce->dex];
        for (uint32_t itf : dex.interfaces(A.classDef(*ce))) interfaces.push_back(std::string(dex.typeDescriptor(itf)));
        cls = superOf(cls);
    }
    for (size_t i = 0; i < interfaces.size() && i < 32; ++i)  // default methods
        if (declaredBy(interfaces[i])) return true;
    return false;
}

std::string Machine::fieldKey(const DexFile& dex, uint32_t fieldIdx) const {
    const std::string name = std::string(dex.fieldName(fieldIdx)) + ":" + std::string(dex.typeDescriptor(dex.fieldType(fieldIdx)));
    std::string cls(dex.typeDescriptor(dex.fieldClass(fieldIdx)));
    for (int i = 0; i < 32; ++i) {  // the class that declares it: the reference may name a subclass
        const ApkAnalysis::ClassEntry* ce = A.findClass(cls);
        if (!ce) break;
        const DexFile& d = *A.dexes()[ce->dex];
        DexFile::ClassData data;
        if (d.classData(A.classDef(*ce), data))
            for (const auto& f : data.fields)
                if (std::string(d.fieldName(f.fieldIdx)) + ":" + std::string(d.typeDescriptor(d.fieldType(f.fieldIdx))) == name)
                    return cls + "->" + name;
        cls = superOf(cls);
    }
    return std::string(dex.typeDescriptor(dex.fieldClass(fieldIdx))) + "->" + name;
}

bool Machine::handlerFor(const DexFile& dex, const DexFile::CodeItem& code, uint32_t pc, const std::string& type, uint32_t& handler) const {
    if (!code.tries) return false;
    const uint8_t* d = dex.data();
    const size_t size = dex.sizeBytes();
    size_t pos = static_cast<size_t>(code.offset) + 16 + static_cast<size_t>(code.insnsSize) * 2;
    if (code.insnsSize & 1) pos += 2;
    const size_t handlers = pos + static_cast<size_t>(code.tries) * 8;
    if (handlers > size) return false;
    const auto leb = [&](size_t& p, bool sign) {
        int64_t v = 0;
        int shift = 0;
        uint8_t b = 0;
        while (p < size && shift < 35) {
            b = d[p++];
            v |= static_cast<int64_t>(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        if (sign && (b & 0x40)) v |= -(static_cast<int64_t>(1) << shift);
        return v;
    };
    for (uint32_t t = 0; t < code.tries; ++t) {
        const uint8_t* e = d + pos + static_cast<size_t>(t) * 8;
        const uint32_t start = static_cast<uint32_t>(e[0] | e[1] << 8 | e[2] << 16) | static_cast<uint32_t>(e[3]) << 24;
        const uint32_t count = static_cast<uint32_t>(e[4] | e[5] << 8);
        if (pc < start || pc >= start + count) continue;
        size_t p = handlers + static_cast<size_t>(e[6] | e[7] << 8);
        const int64_t n = leb(p, true);
        for (int64_t k = 0; k < (n < 0 ? -n : n) && k < 4096; ++k) {
            const uint32_t catchType = static_cast<uint32_t>(leb(p, false)), addr = static_cast<uint32_t>(leb(p, false));
            if (catchType < dex.typeCount() && isSubtype(type, std::string(dex.typeDescriptor(catchType)))) {
                handler = addr;
                return true;
            }
        }
        if (n <= 0) {  // catch-all
            handler = static_cast<uint32_t>(leb(p, false));
            return true;
        }
        return false;
    }
    return false;
}

std::string Machine::describe(const Thrown& t) {
    std::string name = t.type.size() > 2 ? t.type.substr(1, t.type.size() - 2) : t.type;
    name.erase(0, name.find_last_of('/') + 1);
    if (!t.why.empty()) return t.why;
    const std::string message = t.ref >= 0 ? toU8(heap_[static_cast<size_t>(t.ref)].s) : std::string();
    return "the routine throws " + name + (message.empty() ? std::string() : ": " + message);
}

std::u16string boxText(char type, int64_t n) {
    switch (type) {
    case 'J': return toU16(std::to_string(n));
    case 'Z': return n ? u"true" : u"false";
    case 'C': return std::u16string(1, static_cast<char16_t>(n));
    case 'F': return toU16(javaNumber(asFloat(n)));
    case 'D': return toU16(javaNumber(asDouble(n)));
    default: return toU16(std::to_string(static_cast<int32_t>(n)));
    }
}

std::u16string Machine::textOf(const Value& v) const {
    if (v.ref < 0) return u"null";
    const Obj& o = heap_[static_cast<size_t>(v.ref)];
    if (o.kind == Obj::Str || o.kind == Obj::Builder) return o.s;
    if (o.kind == Obj::Box) return boxText(o.text.at(0), o.a.at(0));
    if (o.kind == Obj::List || (o.kind == Obj::Map && o.isSet)) {  // AbstractCollection.toString
        std::u16string s = u"[";
        const std::vector<int64_t> items = elementsOf(v);
        for (size_t i = 0; i < items.size(); ++i) s += (i ? u", " : u"") + textOf(Value{0, static_cast<int>(items[i]) - 1});
        return s + u"]";
    }
    if (o.kind == Obj::Map) {
        std::u16string s = u"{";
        bool first = true;
        for (size_t k : mapOrder(o)) {
            s += (first ? u"" : u", ") + textOf(Value{0, static_cast<int>(o.a[2 * k]) - 1}) + u"=" + textOf(Value{0, static_cast<int>(o.a[2 * k + 1]) - 1});
            first = false;
        }
        return s + u"}";
    }
    throw Stop{"converting this object to a string is not emulated"};
}

bool Machine::sameKey(const Value& x, const Value& y) const {
    if (x.ref == y.ref) return true;
    if (x.ref < 0 || y.ref < 0) return false;
    const Obj& p = heap_[static_cast<size_t>(x.ref)];
    const Obj& q = heap_[static_cast<size_t>(y.ref)];
    if (p.kind == Obj::Str && q.kind == Obj::Str) return p.s == q.s;
    if (p.kind == Obj::Box && q.kind == Obj::Box) return p.text == q.text && p.a == q.a;
    return false;
}

int32_t Machine::hashOf(const Value& v) const {
    if (v.ref < 0) return 0;
    const Obj& o = heap_[static_cast<size_t>(v.ref)];
    if (o.kind == Obj::Str) {
        uint32_t h = 0;
        for (char16_t c : o.s) h = 31u * h + c;
        return static_cast<int32_t>(h);
    }
    if (o.kind == Obj::Box) {
        const int64_t n = o.a.at(0);
        switch (o.text.at(0)) {
        case 'Z': return n ? 1231 : 1237;
        case 'J': return static_cast<int32_t>(n ^ static_cast<int64_t>(static_cast<uint64_t>(n) >> 32));
        case 'F': return std::isnan(asFloat(n)) ? 0x7fc00000 : static_cast<int32_t>(n);
        case 'D': {
            const int64_t bits = std::isnan(asDouble(n)) ? 0x7ff8000000000000ll : n;
            return static_cast<int32_t>(bits ^ static_cast<int64_t>(static_cast<uint64_t>(bits) >> 32));
        }
        default: return static_cast<int32_t>(n);
        }
    }
    throw Stop{"the hash order of these map keys is not emulated"};
}

std::vector<size_t> Machine::mapOrder(const Obj& m) const {
    const size_t n = m.a.size() / 2;
    std::vector<size_t> order(n);
    for (size_t i = 0; i < n; ++i) order[i] = i;
    if (m.order == Obj::Unknown) throw Stop{"the iteration order of this map is not emulated (HashMap, LinkedHashMap, HashSet, LinkedHashSet)"};
    if (m.order == Obj::Hashed) {
        // java.util.HashMap: by bucket of the spread hash; within a bucket, in insertion order (resizing keeps it).
        std::vector<uint32_t> bucket(n);
        for (size_t i = 0; i < n; ++i) {
            const uint32_t h = static_cast<uint32_t>(hashOf(Value{0, static_cast<int>(m.a[2 * i]) - 1}));
            bucket[i] = (h ^ (h >> 16)) & (m.capacity - 1);
        }
        std::stable_sort(order.begin(), order.end(), [&](size_t x, size_t y) { return bucket[x] < bucket[y]; });
    }
    return order;
}

std::vector<int64_t> Machine::elementsOf(const Value& v) const {
    if (v.ref < 0) throw Stop{"null pointer"};
    const Obj& o = heap_[static_cast<size_t>(v.ref)];
    if (o.kind == Obj::List || (o.kind == Obj::Arr && refElement(o.elem))) return o.a;
    if (o.kind == Obj::Map && o.isSet) {
        std::vector<int64_t> keys;
        for (size_t k : mapOrder(o)) keys.push_back(o.a[2 * k]);
        return keys;
    }
    throw Stop{"this collection is not emulated"};
}

bool Machine::collectionCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult) {
    if (a.empty() || a[0].ref < 0) return false;
    const Obj::Kind kind = heap_[static_cast<size_t>(a[0].ref)].kind;
    if (kind != Obj::List && kind != Obj::Map && kind != Obj::Iter && kind != Obj::Entry) return false;
    const size_t arrow = sig.find("->");
    if (arrow == std::string::npos) return false;
    const std::string rest = sig.substr(arrow + 2);
    const std::string name = rest.substr(0, rest.find('('));
    hasResult = rest.back() != 'V';
    const auto at = [](int64_t cell) { return Value{0, static_cast<int>(cell) - 1}; };
    const auto cell = [](const Value& v) { return static_cast<int64_t>(v.ref) + 1; };
    const auto done = [&](Value v) { result = v; return true; };
    const auto number = [&](int64_t n) { return done(Value{static_cast<int32_t>(n), -1}); };
    const auto list = [&](std::vector<int64_t> cells) {
        Obj o;
        o.kind = Obj::List;
        o.a = std::move(cells);
        return newObj(std::move(o));
    };
    const auto iterator = [&](std::vector<int64_t> cells) {
        Obj o;
        o.kind = Obj::Iter;
        o.a = std::move(cells);
        return newObj(std::move(o));
    };
    const auto array = [&](const std::vector<int64_t>& cells) {
        const int r = newArr('L', cells.size());
        heap_[static_cast<size_t>(r)].a = cells;
        return ref(r);
    };
    const auto index = [&](size_t i, size_t size, bool inclusive) {
        const int64_t k = static_cast<int32_t>(a.at(i).n);
        if (k < 0 || static_cast<size_t>(k) > size || (!inclusive && static_cast<size_t>(k) == size))
            throw Stop{"IndexOutOfBoundsException: Index: " + std::to_string(k) + ", Size: " + std::to_string(size)};
        return static_cast<size_t>(k);
    };

    if (kind == Obj::Iter) {
        Obj& it = obj(a[0]);
        if (rest == "hasNext()Z") return number(it.pos < it.a.size());
        if (rest == "next()Ljava/lang/Object;") {
            if (it.pos >= it.a.size()) throw Stop{"NoSuchElementException"};
            return done(at(it.a[it.pos++]));
        }
        return false;
    }
    if (kind == Obj::Entry) {
        const Obj& e = obj(a[0]);
        if (rest == "getKey()Ljava/lang/Object;") return done(at(e.a.at(0)));
        if (rest == "getValue()Ljava/lang/Object;") return done(at(e.a.at(1)));
        return false;
    }
    if (rest == "toString()Ljava/lang/String;") return done(ref(newStr(textOf(a[0]))));
    if (rest == "hashCode()I" || rest == "equals(Ljava/lang/Object;)Z") return false;

    if (kind == Obj::List) {
        if (name == "<init>") {
            if (rest == "<init>(Ljava/util/Collection;)V") {
                std::vector<int64_t> items = elementsOf(a.at(1));
                obj(a[0]).a = std::move(items);
            }
            return true;
        }
        std::vector<int64_t>& v = obj(a[0]).a;
        if (rest == "size()I") return number(static_cast<int64_t>(v.size()));
        if (rest == "isEmpty()Z") return number(v.empty());
        if (rest == "add(Ljava/lang/Object;)Z" || rest == "addLast(Ljava/lang/Object;)V" || rest == "offer(Ljava/lang/Object;)Z") {
            v.push_back(cell(a.at(1)));
            ++cells_;
            return number(1);
        }
        if (rest == "add(ILjava/lang/Object;)V") {
            const size_t k = index(1, v.size(), true);
            v.insert(v.begin() + static_cast<ptrdiff_t>(k), cell(a.at(2)));
            return true;
        }
        if (rest == "addFirst(Ljava/lang/Object;)V" || rest == "push(Ljava/lang/Object;)V") {
            v.insert(v.begin(), cell(a.at(1)));
            return true;
        }
        if (rest == "get(I)Ljava/lang/Object;") return done(at(v[index(1, v.size(), false)]));
        if (rest == "set(ILjava/lang/Object;)Ljava/lang/Object;") {
            const size_t k = index(1, v.size(), false);
            const Value old = at(v[k]);
            v[k] = cell(a.at(2));
            return done(old);
        }
        if (rest == "remove(I)Ljava/lang/Object;") {
            const size_t k = index(1, v.size(), false);
            const Value old = at(v[k]);
            v.erase(v.begin() + static_cast<ptrdiff_t>(k));
            return done(old);
        }
        if (rest == "getFirst()Ljava/lang/Object;" || rest == "getLast()Ljava/lang/Object;" || rest == "removeFirst()Ljava/lang/Object;" ||
            rest == "removeLast()Ljava/lang/Object;" || rest == "pop()Ljava/lang/Object;" || rest == "poll()Ljava/lang/Object;" ||
            rest == "peek()Ljava/lang/Object;") {
            const bool last = name == "getLast" || name == "removeLast";
            if (v.empty()) {
                if (name == "poll" || name == "peek") return done(Value{});
                throw Stop{"NoSuchElementException"};
            }
            const Value item = at(last ? v.back() : v.front());
            if (name.rfind("remove", 0) == 0 || name == "pop" || name == "poll") {
                if (last) v.pop_back();
                else v.erase(v.begin());
            }
            return done(item);
        }
        if (rest == "clear()V") { v.clear(); return true; }
        if (rest == "contains(Ljava/lang/Object;)Z" || rest == "indexOf(Ljava/lang/Object;)I" || rest == "remove(Ljava/lang/Object;)Z") {
            const std::vector<int64_t> items = v;
            for (size_t k = 0; k < items.size(); ++k)
                if (sameKey(at(items[k]), a.at(1))) {
                    if (name == "remove") obj(a[0]).a.erase(obj(a[0]).a.begin() + static_cast<ptrdiff_t>(k));
                    return number(name == "indexOf" ? static_cast<int64_t>(k) : 1);
                }
            return number(name == "indexOf" ? -1 : 0);
        }
        if (rest == "addAll(Ljava/util/Collection;)Z") {
            const std::vector<int64_t> items = elementsOf(a.at(1));
            std::vector<int64_t>& target = obj(a[0]).a;
            target.insert(target.end(), items.begin(), items.end());
            cells_ += items.size();
            return number(!items.empty());
        }
        if (rest == "iterator()Ljava/util/Iterator;" || rest == "listIterator()Ljava/util/ListIterator;") return done(iterator(v));
        if (rest == "toArray()[Ljava/lang/Object;" || rest == "toArray([Ljava/lang/Object;)[Ljava/lang/Object;") {
            const std::vector<int64_t> items = v;
            return done(array(items));
        }
        if (rest == "subList(II)Ljava/util/List;") {
            const size_t from = index(1, v.size(), true), to = index(2, v.size(), true);
            if (from > to) throw Stop{"IllegalArgumentException: fromIndex > toIndex"};
            return done(list(std::vector<int64_t>(v.begin() + static_cast<ptrdiff_t>(from), v.begin() + static_cast<ptrdiff_t>(to))));
        }
        return false;
    }

    // Maps and sets: a holds key, value pairs.
    const auto find = [&](const Value& key) -> int64_t {
        const std::vector<int64_t>& v = obj(a[0]).a;
        for (size_t k = 0; k + 1 < v.size(); k += 2)
            if (sameKey(at(v[k]), key)) return static_cast<int64_t>(k);
        return -1;
    };
    const auto insert = [&](const Value& key, const Value& value) {
        Obj& m = obj(a[0]);
        m.a.push_back(cell(key));
        m.a.push_back(cell(value));
        cells_ += 2;
        if (cells_ > 8000000) throw Stop{"memory limit"};
        if (m.a.size() / 2 > static_cast<uint64_t>(m.capacity) * 3 / 4 && m.capacity < (1u << 30)) m.capacity *= 2;  // threshold: 0.75 of the table
    };
    const auto tableFor = [](int64_t wanted) {  // HashMap.tableSizeFor
        uint32_t c = 1;
        while (c < wanted && c < (1u << 30)) c <<= 1;
        return c;
    };
    const bool isSet = obj(a[0]).isSet;
    if (name == "<init>") {
        Obj& m = obj(a[0]);
        if (rest == "<init>(I)V" || rest == "<init>(IF)V") {
            if (a.at(1).n < 0) throw Stop{"IllegalArgumentException: Illegal initial capacity"};
            if (rest == "<init>(IF)V" && asFloat(a.at(2).n) != 0.75f && m.order == Obj::Hashed) m.order = Obj::Unknown;
            m.capacity = tableFor(a[1].n);
        } else if (rest == "<init>(Ljava/util/Collection;)V") {  // HashSet(Collection)
            const std::vector<int64_t> items = elementsOf(a.at(1));
            obj(a[0]).capacity = tableFor(std::max<int64_t>(static_cast<int64_t>(static_cast<float>(items.size()) / 0.75f) + 1, 16));
            for (int64_t item : items)
                if (find(at(item)) < 0) insert(at(item), Value{});
        } else if (rest == "<init>(Ljava/util/Map;)V") {
            const Obj source = obj(a.at(1));
            if (source.kind != Obj::Map || source.isSet) throw Stop{"copying this map is not emulated"};
            const size_t n = source.a.size() / 2;
            if (n) obj(a[0]).capacity = tableFor(static_cast<int64_t>(static_cast<float>(n) / 0.75f + 1.0f));
            for (size_t k : mapOrder(source)) insert(at(source.a[2 * k]), at(source.a[2 * k + 1]));
        } else if (rest != "<init>()V") {
            return false;
        }
        return true;
    }
    if (rest == "size()I") return number(static_cast<int64_t>(obj(a[0]).a.size() / 2));
    if (rest == "isEmpty()Z") return number(obj(a[0]).a.empty());
    if (rest == "clear()V") { obj(a[0]).a.clear(); return true; }
    if (isSet) {
        if (rest == "add(Ljava/lang/Object;)Z") {
            if (find(a.at(1)) >= 0) return number(0);
            insert(a[1], Value{});
            return number(1);
        }
        if (rest == "contains(Ljava/lang/Object;)Z") return number(find(a.at(1)) >= 0);
        if (rest == "remove(Ljava/lang/Object;)Z") {
            const int64_t k = find(a.at(1));
            if (k < 0) return number(0);
            auto& v = obj(a[0]).a;
            v.erase(v.begin() + k, v.begin() + k + 2);
            return number(1);
        }
        if (rest == "addAll(Ljava/util/Collection;)Z") {
            bool changed = false;
            for (int64_t item : elementsOf(a.at(1)))
                if (find(at(item)) < 0) insert(at(item), Value{}), changed = true;
            return number(changed);
        }
        if (rest == "iterator()Ljava/util/Iterator;") return done(iterator(elementsOf(a[0])));
        if (rest == "toArray()[Ljava/lang/Object;" || rest == "toArray([Ljava/lang/Object;)[Ljava/lang/Object;") return done(array(elementsOf(a[0])));
        return false;
    }
    if (rest == "put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" || rest == "putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") {
        const int64_t k = find(a.at(1));
        if (k < 0) {
            insert(a[1], a.at(2));
            return done(Value{});
        }
        auto& v = obj(a[0]).a;
        const Value old = at(v[static_cast<size_t>(k) + 1]);
        if (name == "put" || old.ref < 0) v[static_cast<size_t>(k) + 1] = cell(a.at(2));
        return done(old);
    }
    if (rest == "get(Ljava/lang/Object;)Ljava/lang/Object;" || rest == "getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") {
        const int64_t k = find(a.at(1));
        if (k < 0) return done(name == "get" ? Value{} : a.at(2));
        return done(at(obj(a[0]).a[static_cast<size_t>(k) + 1]));
    }
    if (rest == "containsKey(Ljava/lang/Object;)Z") return number(find(a.at(1)) >= 0);
    if (rest == "containsValue(Ljava/lang/Object;)Z") {
        const std::vector<int64_t> v = obj(a[0]).a;
        for (size_t k = 1; k < v.size(); k += 2)
            if (sameKey(at(v[k]), a.at(1))) return number(1);
        return number(0);
    }
    if (rest == "remove(Ljava/lang/Object;)Ljava/lang/Object;") {
        const int64_t k = find(a.at(1));
        if (k < 0) return done(Value{});
        auto& v = obj(a[0]).a;
        const Value old = at(v[static_cast<size_t>(k) + 1]);
        v.erase(v.begin() + k, v.begin() + k + 2);
        return done(old);
    }
    if (rest == "keySet()Ljava/util/Set;" || rest == "values()Ljava/util/Collection;" || rest == "entrySet()Ljava/util/Set;") {
        const Obj m = obj(a[0]);  // a copy: making entries grows the heap
        std::vector<int64_t> items;
        for (size_t k : mapOrder(m)) {
            if (name == "keySet") items.push_back(m.a[2 * k]);
            else if (name == "values") items.push_back(m.a[2 * k + 1]);
            else {
                Obj e;
                e.kind = Obj::Entry;
                e.a = {m.a[2 * k], m.a[2 * k + 1]};
                items.push_back(cell(newObj(std::move(e))));
            }
        }
        return done(list(std::move(items)));
    }
    return false;
}

bool Machine::numberCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult) {
    const size_t arrow = sig.find("->");
    if (arrow == std::string::npos) return false;
    const std::string cls = sig.substr(0, arrow), rest = sig.substr(arrow + 2);
    hasResult = true;
    const auto done = [&](Value v) { result = v; return true; };
    const auto wide = [&](int64_t n) { return done(Value{n, -1}); };
    const auto number = [&](int64_t n) { return wide(static_cast<int32_t>(n)); };
    const auto f32 = [&](float f) { return wide(fromFloat(f)); };
    const auto f64 = [&](double d) { return wide(fromDouble(d)); };
    const auto text = [&](const std::string& s) { return done(ref(newStr(toU16(s)))); };
    const auto box = [&](char type, int64_t n) {
        Obj o;
        o.kind = Obj::Box;
        o.text = std::string(1, type);
        o.a = {n};
        return done(newObj(std::move(o)));
    };
    const auto I = [&](size_t i) { return static_cast<int32_t>(a.at(i).n); };
    const auto J = [&](size_t i) { return a.at(i).n; };
    const auto F = [&](size_t i) { return asFloat(a.at(i).n); };
    const auto D = [&](size_t i) { return asDouble(a.at(i).n); };
    const auto S = [&](size_t i) -> const std::u16string& { return str(a.at(i)); };

    // Methods of a box: intValue() and friends with Java's conversions, toString, equals, hashCode, compareTo.
    if (!a.empty() && a[0].ref >= 0 && heap_[static_cast<size_t>(a[0].ref)].kind == Obj::Box && cls.rfind("Ljava/lang/", 0) == 0) {
        const Obj& b = heap_[static_cast<size_t>(a[0].ref)];
        const char t = b.text.at(0);
        const int64_t n = b.a.at(0);
        const bool fp = t == 'F' || t == 'D';
        const double d = t == 'F' ? asFloat(n) : t == 'D' ? asDouble(n) : static_cast<double>(n);
        if (rest.find("Value()") != std::string::npos && rest.size() > 8) {
            switch (rest.back()) {
            case 'I': return number(fp ? javaToInt<int32_t>(d) : n);
            case 'J': return wide(fp ? javaToInt<int64_t>(d) : n);
            case 'S': return number(static_cast<int16_t>(fp ? javaToInt<int32_t>(d) : n));
            case 'B': return number(static_cast<int8_t>(fp ? javaToInt<int32_t>(d) : n));
            case 'F': return f32(t == 'F' ? asFloat(n) : t == 'D' ? static_cast<float>(d) : static_cast<float>(n));
            case 'D': return f64(d);
            case 'C': case 'Z': return number(n);
            }
        }
        if (rest == "toString()Ljava/lang/String;") return done(ref(newStr(boxText(t, n))));
        if (rest == "equals(Ljava/lang/Object;)Z") {
            // Float / Double equality compares the bits (with NaN folded), as Java does.
            if (a.size() < 2 || a[1].ref < 0 || heap_[static_cast<size_t>(a[1].ref)].kind != Obj::Box) return number(0);
            const Obj& o = heap_[static_cast<size_t>(a[1].ref)];
            if (o.text != b.text) return number(0);
            if (t == 'F') return number(hashOf(a[0]) == hashOf(a[1]));
            if (t == 'D') {
                const auto bits = [&](int64_t x) { return std::isnan(asDouble(x)) ? 0x7ff8000000000000ll : x; };
                return number(bits(n) == bits(o.a.at(0)));
            }
            return number(n == o.a.at(0));
        }
        if (rest == "hashCode()I") return number(hashOf(a[0]));
        if (rest.rfind("compareTo(", 0) == 0) {
            const int64_t m = obj(a.at(1)).a.at(0);
            if (fp) {
                const double e = t == 'F' ? asFloat(m) : asDouble(m);
                return number(d < e ? -1 : d > e ? 1 : std::isnan(d) == std::isnan(e) ? 0 : std::isnan(d) ? 1 : -1);
            }
            return number(n < m ? -1 : n > m ? 1 : 0);
        }
    }
    const auto is = [&](const char* s) { return sig == s; };
    const bool math = cls == "Ljava/lang/Math;" || cls == "Ljava/lang/StrictMath;";
    if (math) {
        // Java's min / max: NaN wins, and -0.0 is below 0.0.
        const auto pick = [](double x, double y, bool max) {
            if (std::isnan(x) || std::isnan(y)) return std::numeric_limits<double>::quiet_NaN();
            if (x == y) return (std::signbit(x) != max) ? x : y;
            return (x < y) != max ? x : y;
        };
        const auto round = [](double x) { const double r = std::floor(x); return x - r >= 0.5 ? r + 1 : r; };
        if (rest == "abs(J)J") return wide(J(0) < 0 ? static_cast<int64_t>(0 - static_cast<uint64_t>(J(0))) : J(0));
        if (rest == "abs(F)F") return f32(std::fabs(F(0)));
        if (rest == "abs(D)D") return f64(std::fabs(D(0)));
        if (rest == "min(JJ)J") return wide(std::min(J(0), J(2)));
        if (rest == "max(JJ)J") return wide(std::max(J(0), J(2)));
        if (rest == "min(FF)F" || rest == "max(FF)F") return f32(static_cast<float>(pick(F(0), F(1), rest[1] == 'a')));
        if (rest == "min(DD)D" || rest == "max(DD)D") return f64(pick(D(0), D(2), rest[1] == 'a'));
        if (rest == "round(F)I") return number(std::isnan(F(0)) ? 0 : javaToInt<int32_t>(round(F(0))));
        if (rest == "round(D)J") return wide(std::isnan(D(0)) ? 0 : javaToInt<int64_t>(round(D(0))));
        if (rest == "floorDiv(II)I" || rest == "floorMod(II)I") {
            if (!I(1)) throw Stop{"ArithmeticException (divide by zero)"};
            const int64_t x = I(0), y = I(1);
            int64_t q = x / y;
            if ((x % y != 0) && ((x < 0) != (y < 0))) --q;
            return number(rest[5] == 'D' ? q : x - q * y);
        }
        if (rest == "signum(F)F") return f32(F(0) > 0 ? 1.0f : F(0) < 0 ? -1.0f : F(0));
        if (rest == "signum(D)D") return f64(D(0) > 0 ? 1.0 : D(0) < 0 ? -1.0 : D(0));
        static const std::pair<const char*, double (*)(double)> unary[] = {
            {"sqrt", [](double x) { return std::sqrt(x); }},   {"cbrt", [](double x) { return std::cbrt(x); }},
            {"floor", [](double x) { return std::floor(x); }}, {"ceil", [](double x) { return std::ceil(x); }},
            {"rint", [](double x) { return std::nearbyint(x); }}, {"exp", [](double x) { return std::exp(x); }},
            {"log", [](double x) { return std::log(x); }},     {"log10", [](double x) { return std::log10(x); }},
            {"sin", [](double x) { return std::sin(x); }},     {"cos", [](double x) { return std::cos(x); }},
            {"tan", [](double x) { return std::tan(x); }},     {"atan", [](double x) { return std::atan(x); }},
            {"toRadians", [](double x) { return x / 180.0 * 3.141592653589793; }},
            {"toDegrees", [](double x) { return x * 180.0 / 3.141592653589793; }}};
        for (const auto& [fn, f] : unary)
            if (rest == std::string(fn) + "(D)D") return f64(f(D(0)));
        if (rest == "pow(DD)D") return f64(std::pow(D(0), D(2)));
        if (rest == "atan2(DD)D") return f64(std::atan2(D(0), D(2)));
        if (rest == "hypot(DD)D") return f64(std::hypot(D(0), D(2)));
        return false;
    }
    if (cls == "Ljava/lang/Float;") {
        if (rest == "floatToIntBits(F)I") return number(std::isnan(F(0)) ? 0x7fc00000 : a.at(0).n);
        if (rest == "floatToRawIntBits(F)I" || rest == "intBitsToFloat(I)F") return number(a.at(0).n);
        if (rest == "toString(F)Ljava/lang/String;") return text(javaNumber(F(0)));
        if (rest == "isNaN(F)Z") return number(std::isnan(F(0)));
        if (rest == "isInfinite(F)Z") return number(std::isinf(F(0)));
        if (rest == "compare(FF)I") {
            const double x = F(0), y = F(1);
            return number(x < y ? -1 : x > y ? 1 : std::isnan(x) == std::isnan(y) ? 0 : std::isnan(x) ? 1 : -1);
        }
        if (rest == "parseFloat(Ljava/lang/String;)F" || rest == "valueOf(Ljava/lang/String;)Ljava/lang/Float;") {
            float v = 0;
            if (!parseReal(toU8(S(0)), v)) throw Stop{"NumberFormatException: For input string: \"" + toU8(S(0)) + "\""};
            return rest[0] == 'p' ? f32(v) : box('F', fromFloat(v));
        }
        if (rest == "valueOf(F)Ljava/lang/Float;") return box('F', a.at(0).n);
        return false;
    }
    if (cls == "Ljava/lang/Double;") {
        if (rest == "doubleToLongBits(D)J") return wide(std::isnan(D(0)) ? 0x7ff8000000000000ll : J(0));
        if (rest == "doubleToRawLongBits(D)J" || rest == "longBitsToDouble(J)D") return wide(J(0));
        if (rest == "toString(D)Ljava/lang/String;") return text(javaNumber(D(0)));
        if (rest == "isNaN(D)Z") return number(std::isnan(D(0)));
        if (rest == "isInfinite(D)Z") return number(std::isinf(D(0)));
        if (rest == "compare(DD)I") {
            const double x = D(0), y = D(2);
            return number(x < y ? -1 : x > y ? 1 : std::isnan(x) == std::isnan(y) ? 0 : std::isnan(x) ? 1 : -1);
        }
        if (rest == "parseDouble(Ljava/lang/String;)D" || rest == "valueOf(Ljava/lang/String;)Ljava/lang/Double;") {
            double v = 0;
            if (!parseReal(toU8(S(0)), v)) throw Stop{"NumberFormatException: For input string: \"" + toU8(S(0)) + "\""};
            return rest[0] == 'p' ? f64(v) : box('D', fromDouble(v));
        }
        if (rest == "valueOf(D)Ljava/lang/Double;") return box('D', J(0));
        return false;
    }
    if (cls == "Ljava/lang/Integer;" || cls == "Ljava/lang/Long;") {
        const bool isLong = cls == "Ljava/lang/Long;";
        const char p = isLong ? 'J' : 'I';
        const std::string P(1, p);
        const int bits = isLong ? 64 : 32;
        const int64_t lo = isLong ? std::numeric_limits<int64_t>::min() : std::numeric_limits<int32_t>::min();
        const int64_t hi = isLong ? std::numeric_limits<int64_t>::max() : std::numeric_limits<int32_t>::max();
        const auto result_ = [&](int64_t v) { return isLong ? wide(v) : number(v); };
        const uint64_t u = isLong ? static_cast<uint64_t>(J(0)) : static_cast<uint32_t>(a.empty() ? 0 : a[0].n);
        const size_t second = isLong ? 2 : 1;  // where an int after the value sits (a long takes two registers)
        const std::string parse = isLong ? "parseLong" : "parseInt";
        if (rest == parse + "(Ljava/lang/String;)" + P || rest == parse + "(Ljava/lang/String;I)" + P ||
            rest == "valueOf(Ljava/lang/String;)" + cls || rest == "valueOf(Ljava/lang/String;I)" + cls || rest == "decode(Ljava/lang/String;)" + cls) {
            std::u16string s = S(0);
            int radix = rest.find(";I)") != std::string::npos ? I(1) : 10;
            if (rest.rfind("decode", 0) == 0) {  // 0x / # / leading 0 prefixes
                const bool neg = !s.empty() && (s[0] == '-' || s[0] == '+');
                std::u16string digits = neg ? s.substr(1) : s;
                if (digits.rfind(u"0x", 0) == 0 || digits.rfind(u"0X", 0) == 0) radix = 16, digits = digits.substr(2);
                else if (digits.rfind(u"#", 0) == 0) radix = 16, digits = digits.substr(1);
                else if (digits.size() > 1 && digits[0] == '0') radix = 8, digits = digits.substr(1);
                s = (neg ? s.substr(0, 1) : std::u16string()) + digits;
            }
            int64_t v = 0;
            if (!parseInteger(s, radix, lo, hi, v)) throw Stop{"NumberFormatException: For input string: \"" + toU8(S(0)) + "\""};
            return rest[0] == 'p' ? result_(v) : box(p, v);
        }
        if (rest == "toString(" + P + ")Ljava/lang/String;") return text(integerText(isLong ? J(0) : I(0), 10));
        if (rest == "toString(" + P + "I)Ljava/lang/String;") return text(integerText(isLong ? J(0) : I(0), I(second)));
        if (rest == "toHexString(" + P + ")Ljava/lang/String;") return text(integerText(J(0), 16, bits));
        if (rest == "toBinaryString(" + P + ")Ljava/lang/String;") return text(integerText(J(0), 2, bits));
        if (rest == "toOctalString(" + P + ")Ljava/lang/String;") return text(integerText(J(0), 8, bits));
        if (rest == "bitCount(" + P + ")I") return number(std::popcount(u));
        if (rest == "numberOfLeadingZeros(" + P + ")I") return number(std::countl_zero(u) - (64 - bits));
        if (rest == "numberOfTrailingZeros(" + P + ")I") return number(u ? std::countr_zero(u) : bits);
        if (rest == "highestOneBit(" + P + ")" + P) return result_(u ? static_cast<int64_t>(std::bit_floor(u)) : 0);
        if (rest == "lowestOneBit(" + P + ")" + P) return result_(static_cast<int64_t>(u & (0 - u)));
        if (rest == "signum(" + P + ")I") return number((isLong ? J(0) : I(0)) > 0 ? 1 : (isLong ? J(0) : I(0)) < 0 ? -1 : 0);
        if (rest == "compare(" + P + P + ")I") {
            const int64_t x = isLong ? J(0) : I(0), y = isLong ? J(2) : I(1);
            return number(x < y ? -1 : x > y ? 1 : 0);
        }
        if (rest == "hashCode(" + P + ")I") return number(isLong ? static_cast<int32_t>(J(0) ^ static_cast<int64_t>(u >> 32)) : I(0));
        if (rest == "rotateLeft(" + P + "I)" + P || rest == "rotateRight(" + P + "I)" + P) {
            const int k = I(second) & (bits - 1);
            const bool left = rest[6] == 'L';
            if (isLong) return wide(static_cast<int64_t>(left ? std::rotl(u, k) : std::rotr(u, k)));
            const uint32_t w = static_cast<uint32_t>(u);
            return number(static_cast<int32_t>(left ? std::rotl(w, k) : std::rotr(w, k)));
        }
        if (rest == "reverse(" + P + ")" + P || rest == "reverseBytes(" + P + ")" + P) {
            uint64_t v = u, out = 0;
            const bool bytes = rest[7] == 'B';
            const int step = bytes ? 8 : 1, n = bits / step;
            for (int k = 0; k < n; ++k) out = (out << step) | ((v >> (k * step)) & ((1ull << step) - 1));
            return result_(isLong ? static_cast<int64_t>(out) : static_cast<int32_t>(out));
        }
        if (rest == "sum(" + P + P + ")" + P) return result_(isLong ? static_cast<int64_t>(u + static_cast<uint64_t>(J(2))) : static_cast<int32_t>(I(0) + static_cast<uint32_t>(I(1))));
        return false;
    }
    if (cls == "Ljava/lang/Character;") {
        const char16_t c = static_cast<char16_t>(a.empty() ? 0 : a[0].n);
        const wint_t w = static_cast<wint_t>(c);
        if (rest == "isDigit(C)Z") return number(std::iswdigit(w) != 0);
        if (rest == "isLetter(C)Z") return number(std::iswalpha(w) != 0);
        if (rest == "isLetterOrDigit(C)Z") return number(std::iswalnum(w) != 0);
        if (rest == "isUpperCase(C)Z") return number(std::iswupper(w) != 0);
        if (rest == "isLowerCase(C)Z") return number(std::iswlower(w) != 0);
        if (rest == "isWhitespace(C)Z") return number(c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f));
        if (rest == "toUpperCase(C)C") return number(static_cast<char16_t>(std::towupper(w)));
        if (rest == "toLowerCase(C)C") return number(static_cast<char16_t>(std::towlower(w)));
        if (rest == "digit(CI)I") return number(digitOf(c, I(1)));
        if (rest == "forDigit(II)C") {
            const int d = I(0), radix = I(1);
            return number(radix < 2 || radix > 36 || d < 0 || d >= radix ? 0 : "0123456789abcdefghijklmnopqrstuvwxyz"[d]);
        }
        if (rest == "toString(C)Ljava/lang/String;") return done(ref(newStr(std::u16string(1, c))));
        if (rest == "valueOf(C)Ljava/lang/Character;") return box('C', c);
        return false;
    }
    if (cls == "Ljava/lang/Boolean;") {
        if (rest == "parseBoolean(Ljava/lang/String;)Z") {
            std::u16string s = a.at(0).ref >= 0 ? S(0) : u"";
            for (char16_t& ch : s) ch = static_cast<char16_t>(std::towlower(static_cast<wint_t>(ch)));
            return number(s == u"true");
        }
        if (rest == "toString(Z)Ljava/lang/String;") return text(a.at(0).n ? "true" : "false");
        return false;
    }
    if (cls == "Ljava/lang/String;") {
        if (is("Ljava/lang/String;->valueOf(J)Ljava/lang/String;")) return text(std::to_string(J(0)));
        if (is("Ljava/lang/String;->valueOf(Z)Ljava/lang/String;")) return text(a.at(0).n ? "true" : "false");
        if (is("Ljava/lang/String;->valueOf(F)Ljava/lang/String;")) return text(javaNumber(F(0)));
        if (is("Ljava/lang/String;->valueOf(D)Ljava/lang/String;")) return text(javaNumber(D(0)));
        if (is("Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;")) return done(ref(newStr(textOf(a.at(0)))));
    }
    return false;
}

// Constructors and accessors of exception objects (library classes, and what app subclasses inherit).
bool Machine::throwableCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult) {
    if (a.empty() || a[0].ref < 0 || heap_[static_cast<size_t>(a[0].ref)].kind != Obj::Error) return false;
    const size_t arrow = sig.find("->");
    const std::string rest = arrow == std::string::npos ? std::string() : sig.substr(arrow + 2);
    hasResult = false;
    if (rest.rfind("<init>(", 0) == 0) {
        if (rest.rfind("<init>(Ljava/lang/String;", 0) == 0 && a.size() > 1 && a[1].ref >= 0) {
            const std::u16string message = str(a[1]);
            obj(a[0]).s = message;
        }
        return true;
    }
    if (rest == "printStackTrace()V" || rest.rfind("fillInStackTrace()", 0) == 0) return true;
    hasResult = true;
    if (rest == "getMessage()Ljava/lang/String;" || rest == "getLocalizedMessage()Ljava/lang/String;") {
        const std::u16string message = obj(a[0]).s;
        result = message.empty() ? Value{} : ref(newStr(message));
        return true;
    }
    if (rest == "toString()Ljava/lang/String;") {
        std::string name = obj(a[0]).text;
        name = name.size() > 2 ? name.substr(1, name.size() - 2) : name;
        std::replace(name.begin(), name.end(), '/', '.');
        std::u16string text = toU16(name);
        if (!obj(a[0]).s.empty()) text += u": " + obj(a[0]).s;
        result = ref(newStr(std::move(text)));
        return true;
    }
    return false;
}

// Boxing, Class and Method objects.
bool Machine::reflectionCall(const std::string& sig, const std::vector<Value>& a, Value& result, bool& hasResult) {
    hasResult = true;
    static const struct {
        const char* box;
        char type;
        const char* get;
    } boxes[] = {{"Ljava/lang/Integer;", 'I', "intValue"},   {"Ljava/lang/Long;", 'J', "longValue"},  {"Ljava/lang/Character;", 'C', "charValue"},
                 {"Ljava/lang/Boolean;", 'Z', "booleanValue"}, {"Ljava/lang/Byte;", 'B', "byteValue"}, {"Ljava/lang/Short;", 'S', "shortValue"},
                 {"Ljava/lang/Float;", 'F', "floatValue"},   {"Ljava/lang/Double;", 'D', "doubleValue"}};
    for (const auto& b : boxes) {
        const std::string cls = b.box;
        if (sig == cls + "->valueOf(" + b.type + ")" + cls) {
            Obj o;
            o.kind = Obj::Box;
            o.text = std::string(1, b.type);
            o.a = {a.at(0).n};
            result = ref(add(std::move(o)));
            return true;
        }
        if (sig == cls + "->" + b.get + "()" + b.type || sig == std::string("Ljava/lang/Number;->") + b.get + "()" + b.type) {
            const Obj& o = obj(a.at(0));
            if (o.kind != Obj::Box) return false;
            result = Value{o.a.at(0), -1};
            return true;
        }
    }
    if (sig == "Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;") {  // multi-dimensional arrays
        const std::string element = obj(a.at(0)).text;
        const std::vector<int64_t> dims = obj(a.at(1)).a;
        if (element.empty() || dims.empty() || dims.size() > 4) throw Stop{"that array shape is not emulated"};
        const std::function<int(size_t)> make = [&](size_t k) {
            if (dims[k] < 0) throw Stop{"NegativeArraySizeException"};
            const char elem = k + 1 < dims.size() ? '[' : element[0];
            const int r = newArr(elem, static_cast<size_t>(dims[k]));
            if (k + 1 < dims.size())
                for (int64_t i = 0; i < dims[k]; ++i) {
                    const int child = make(k + 1);  // may move the heap
                    heap_[static_cast<size_t>(r)].a[static_cast<size_t>(i)] = child + 1;
                }
            return r;
        };
        result = ref(make(0));
        return true;
    }
    const auto text = [&](const std::string& s) { return ref(newStr(toU16(s))); };
    if (sig == "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;") {
        std::string name = toU8(str(a.at(0)));
        std::replace(name.begin(), name.end(), '.', '/');
        const std::string d = !name.empty() && name[0] == '[' ? name : "L" + name + ";";
        if (!A.findClass(d) && d.rfind("Ljava/", 0) != 0 && d.rfind("Ljavax/", 0) != 0 && d.rfind("Landroid/", 0) != 0 && d[0] != '[')
            throw Stop{"ClassNotFoundException: " + name};
        result = classObject(d);
        return true;
    }
    if (sig == "Ljava/lang/Class;->getName()Ljava/lang/String;" || sig == "Ljava/lang/Class;->getSimpleName()Ljava/lang/String;") {
        std::string d = obj(a.at(0)).text;
        if (d.size() > 2 && d[0] == 'L') d = d.substr(1, d.size() - 2);
        std::replace(d.begin(), d.end(), '/', '.');
        if (sig.find("Simple") != std::string::npos) {
            d.erase(0, d.find_last_of('.') + 1);
            d.erase(0, d.find_last_of('$') + 1);
        }
        result = text(d);
        return true;
    }
    if (sig == "Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;" ||
        sig == "Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;") {
        Obj o;
        o.kind = Obj::Method;
        o.text = obj(a.at(0)).text;
        o.s = str(a.at(1));
        if (a.at(2).ref >= 0) {
            const std::vector<int64_t> types = obj(a[2]).a;
            for (int64_t t : types) o.params.push_back(obj(Value{0, static_cast<int>(t) - 1}).text);
        }
        result = ref(add(std::move(o)));
        return true;
    }
    if (sig == "Ljava/lang/reflect/Method;->setAccessible(Z)V" || sig == "Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V") {
        hasResult = false;
        return true;
    }
    if (sig != "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;") return false;

    const Obj method = obj(a.at(0));  // a copy: the calls below grow the heap
    if (method.kind != Obj::Method) throw Stop{"invoke() on something that is not a method"};
    const std::string name = toU8(method.s);
    std::string params = "(";
    for (const std::string& p : method.params) params += p;
    params += ")";
    const std::string full = method.text + "->" + name + params;

    std::vector<Value> boxed;
    if (a.at(2).ref >= 0) {
        const std::vector<int64_t> values = obj(a[2]).a;
        for (int64_t v : values) boxed.push_back(Value{0, static_cast<int>(v) - 1});
    }
    if (boxed.size() != method.params.size()) throw Stop{"IllegalArgumentException: wrong number of arguments for " + full};
    std::vector<Value> args;
    for (size_t i = 0; i < boxed.size(); ++i) {
        const std::string& p = method.params[i];
        const bool primitive = p.size() == 1;
        args.push_back(primitive ? Value{obj(boxed[i]).a.at(0), -1} : boxed[i]);
    }

    std::string returns;
    Value r;
    bool has = false;
    if (A.findClass(method.text)) {
        ensureInit(method.text);
        const ApkAnalysis::MethodDef* found = nullptr;
        std::vector<ApkAnalysis::MethodDef> defs = A.findMethodDefs(method.text, name);
        for (const auto& d : defs) {
            const DexFile& dex = *A.dexes()[d.dex];
            const std::string proto = dex.protoDescriptor(dex.methodProto(d.method.methodIdx));
            if (proto.rfind(params, 0) == 0) {
                found = &d;
                returns = proto.substr(params.size());
                break;
            }
        }
        if (!found) throw Stop{"NoSuchMethodException: " + full};
        if (!(found->method.accessFlags & 0x8)) {  // the receiver's own implementation runs
            if (a.at(1).ref < 0) throw Stop{"null pointer"};
            ApkAnalysis::MethodDef actual = *found;
            const std::string runtime = obj(a.at(1)).text;
            const std::string proto = params + returns;
            if (A.findClass(runtime)) findImplementation(runtime, name, proto, actual);
            args.insert(args.begin(), a.at(1));
            r = exec(actual, args);
        } else {
            r = exec(*found, args);
        }
        has = returns != "V";
    } else {
        // The library calls the interpreter has, by name and parameters: the table supplies the return type.
        static const char* const library[] = {
            "Ljava/lang/String;->length()I", "Ljava/lang/String;->charAt(I)C", "Ljava/lang/String;->toCharArray()[C",
            "Ljava/lang/String;->substring(I)Ljava/lang/String;", "Ljava/lang/String;->substring(II)Ljava/lang/String;",
            "Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;", "Ljava/lang/String;->trim()Ljava/lang/String;",
            "Ljava/lang/String;->intern()Ljava/lang/String;", "Ljava/lang/String;->hashCode()I", "Ljava/lang/String;->indexOf(I)I",
            "Ljava/lang/String;->replace(CC)Ljava/lang/String;", "Ljava/lang/String;->toUpperCase()Ljava/lang/String;",
            "Ljava/lang/String;->toLowerCase()Ljava/lang/String;", "Ljava/lang/String;->getBytes()[B",
            "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B", "Ljava/lang/String;->valueOf(C)Ljava/lang/String;",
            "Ljava/lang/String;->valueOf(I)Ljava/lang/String;", "Ljava/lang/String;->valueOf([C)Ljava/lang/String;",
            "Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;", "Ljava/lang/Integer;->toString(I)Ljava/lang/String;",
            "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I", "Ljava/lang/Math;->abs(I)I", "Ljava/lang/Math;->min(II)I",
            "Ljava/lang/Math;->max(II)I", "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B",
            "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;", "Ljavax/crypto/Cipher;->doFinal([B)[B",
            "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"};
        std::string signature;
        for (const char* candidate : library)
            if (std::string(candidate).rfind(full, 0) == 0) signature = candidate;
        if (signature.empty()) throw Stop{"the reflective call " + full + " is not emulated"};
        returns = signature.substr(full.size());
        const bool isStatic = method.text == "Ljava/lang/Math;" || method.text == "Ljava/lang/Integer;" || method.text == "Landroid/util/Base64;" ||
                              name == "valueOf" || name == "getInstance";
        if (!isStatic) args.insert(args.begin(), a.at(1));
        r = libCall(signature, args, has);
    }
    if (!has) {
        result = Value{};
        return true;
    }
    if (returns.size() == 1) {  // primitives come back boxed
        Obj o;
        o.kind = Obj::Box;
        o.text = returns;
        o.a = {r.n};
        result = ref(add(std::move(o)));
    } else {
        result = r;
    }
    return true;
}

// A call from bytecode: into the app, or one of the library calls.
Value Machine::invoke(const DexFile& dex, uint32_t methodIdx, const std::vector<Value>& a, uint8_t opcode, bool& hasResult) {
    const std::string cls(dex.typeDescriptor(dex.methodClass(methodIdx)));
    const std::string sig = dex.methodSignature(methodIdx);
    const bool isStatic = opcode == 0x71 || opcode == 0x77;
    if (isStatic) return A.findClass(cls) ? callApp(dex, methodIdx, a, true, hasResult) : libCall(sig, a, hasResult);
    if (a.empty() || a[0].ref < 0) throw Stop{"null pointer"};
    const Obj::Kind kind = heap_[static_cast<size_t>(a[0].ref)].kind;
    if (kind != Obj::Instance && kind != Obj::Error) {
        if (!A.findClass(cls)) return libCall(sig, a, hasResult);
        throw Stop{"calls " + sig + " on a library object, which is not emulated"};
    }
    // An object of an app class: constructors, private methods and super calls start where the bytecode says; virtual
    // and interface calls at the object's own class.
    const bool exact = opcode == 0x6f || opcode == 0x70 || opcode == 0x75 || opcode == 0x76;
    const std::string runtime = heap_[static_cast<size_t>(a[0].ref)].text;
    const std::string name(dex.methodName(methodIdx));
    const std::string proto = dex.protoDescriptor(dex.methodProto(methodIdx));
    ApkAnalysis::MethodDef found;
    const std::string start = exact ? cls : runtime;
    if (A.findClass(start) && (name != "<init>" || A.findClass(cls)) && findImplementation(start, name, proto, found)) {
        hasResult = proto.back() != 'V';
        return exec(found, a);
    }
    hasResult = false;
    if (kind == Obj::Error) {
        Value result;
        if (throwableCall(sig, a, result, hasResult)) return result;
    }
    // What java.lang.Object gives every instance.
    const std::string rest = sig.substr(sig.find("->") + 2);
    if (rest == "<init>()V") return {};
    hasResult = true;
    if (rest == "getClass()Ljava/lang/Class;") return classObject(runtime);
    if (rest == "hashCode()I") return Value{a[0].ref + 1, -1};
    if (rest == "equals(Ljava/lang/Object;)Z") return Value{a.size() > 1 && a[1].ref == a[0].ref, -1};
    throw Stop{"calls " + sig + ", which is not emulated"};
}

Value Machine::sget(const DexFile& dex, uint32_t fieldIdx) {
    const std::string cls(dex.typeDescriptor(dex.fieldClass(fieldIdx)));
    const std::string sig = dex.fieldSignature(fieldIdx);
    if (dex.fieldName(fieldIdx) == "TYPE") {  // int.class and friends
        static const std::pair<const char*, const char*> primitives[] = {
            {"Ljava/lang/Integer;", "I"}, {"Ljava/lang/Long;", "J"}, {"Ljava/lang/Character;", "C"},
            {"Ljava/lang/Boolean;", "Z"}, {"Ljava/lang/Byte;", "B"}, {"Ljava/lang/Short;", "S"},
            {"Ljava/lang/Float;", "F"},   {"Ljava/lang/Double;", "D"}};
        for (const auto& [box, type] : primitives)
            if (cls == box) return classObject(type);
    }
    if (cls == "Ljava/nio/charset/StandardCharsets;") {
        Obj o;
        o.kind = Obj::Dummy;
        o.s = toU16(std::string(dex.fieldName(fieldIdx)));
        return ref(add(std::move(o)));
    }
    if (cls == "Ljava/security/spec/MGF1ParameterSpec;" || cls == "Ljavax/crypto/spec/PSource$PSpecified;" || cls == "Ljavax/crypto/spec/OAEPParameterSpec;") {
        const std::string name(dex.fieldName(fieldIdx));
        Obj o;
        if (cls == "Ljavax/crypto/spec/OAEPParameterSpec;") o.kind = Obj::OaepSpec, o.text = "SHA-1", o.mgf = "SHA-1";
        else if (name.rfind("SHA", 0) == 0) o.text = "SHA-" + name.substr(3);  // MGF1ParameterSpec.SHA256
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
    {
        Value result;
        if (throwableCall(sig, a, result, hasResult) || collectionCall(sig, a, result, hasResult) || numberCall(sig, a, result, hasResult) ||
            reflectionCall(sig, a, result, hasResult))
            return result;
        hasResult = true;
    }
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
    if (is("Ljava/lang/String;->indexOf(II)I") || is("Ljava/lang/String;->lastIndexOf(I)I") || is("Ljava/lang/String;->indexOf(Ljava/lang/String;)I") ||
        is("Ljava/lang/String;->indexOf(Ljava/lang/String;I)I") || is("Ljava/lang/String;->lastIndexOf(Ljava/lang/String;)I")) {
        const std::u16string& s = strv(0);
        const bool last = sig.find("lastIndexOf") != std::string::npos;
        const std::u16string needle = sig.find("(Ljava/lang/String;") != std::string::npos ? strv(1) : std::u16string(1, static_cast<char16_t>(a[1].n));
        const bool from = sig.find("I)I") != std::string::npos && sig.find("(I)") == std::string::npos;
        const int64_t start = from ? std::clamp<int64_t>(static_cast<int32_t>(a.back().n), 0, static_cast<int64_t>(s.size())) : 0;
        const size_t p = last ? s.rfind(needle) : s.find(needle, static_cast<size_t>(start));
        return integer(p == std::u16string::npos ? -1 : static_cast<int64_t>(p));
    }
    if (is("Ljava/lang/String;->startsWith(Ljava/lang/String;)Z")) return integer(strv(0).rfind(strv(1), 0) == 0);
    if (is("Ljava/lang/String;->endsWith(Ljava/lang/String;)Z")) {
        const std::u16string &s = strv(0), &e = strv(1);
        return integer(s.size() >= e.size() && s.compare(s.size() - e.size(), e.size(), e) == 0);
    }
    if (is("Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z")) return integer(strv(0).find(strv(1)) != std::u16string::npos);
    if (is("Ljava/lang/String;->compareTo(Ljava/lang/String;)I")) {
        const std::u16string &x = strv(0), &y = strv(1);
        for (size_t i = 0; i < std::min(x.size(), y.size()); ++i)
            if (x[i] != y[i]) return integer(static_cast<int64_t>(x[i]) - y[i]);
        return integer(static_cast<int64_t>(x.size()) - static_cast<int64_t>(y.size()));
    }
    if (is("Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z")) {
        if (a[1].ref < 0) return integer(0);
        std::u16string x = strv(0), y = strv(1);
        for (auto* s : {&x, &y})
            for (char16_t& ch : *s) ch = static_cast<char16_t>(std::towlower(static_cast<wint_t>(std::towupper(static_cast<wint_t>(ch)))));
        return integer(x == y);
    }
    if (is("Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;")) {
        std::u16string s = strv(0);
        const std::u16string from = strv(1), to = strv(2);
        std::u16string out;
        if (from.empty()) {  // between every character, as Java does
            out = to;
            for (char16_t ch : s) out += ch, out += to;
        } else {
            size_t p = 0;
            for (size_t q; (q = s.find(from, p)) != std::u16string::npos; p = q + from.size()) out += s.substr(p, q - p) + to;
            out += s.substr(p);
        }
        return mk(std::move(out));
    }
    if (is("Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;")) {
        // Only patterns without regex syntax (or one escaped character): what decoders split on.
        std::u16string pattern = strv(1);
        if (pattern.size() == 2 && pattern[0] == '\\' && !std::iswalnum(static_cast<wint_t>(pattern[1]))) pattern = pattern.substr(1);
        else
            for (char16_t ch : pattern)
                if (ch < 128 && std::strchr(".$|()[{^?*+\\", static_cast<char>(ch))) throw Stop{"split with the regular expression " + toU8(pattern) + " is not emulated"};
        const std::u16string s = strv(0);
        std::vector<std::u16string> parts;
        if (pattern.empty()) {
            for (char16_t ch : s) parts.emplace_back(1, ch);
        } else {
            size_t p = 0;
            for (size_t q; (q = s.find(pattern, p)) != std::u16string::npos; p = q + pattern.size()) parts.push_back(s.substr(p, q - p));
            parts.push_back(s.substr(p));
        }
        while (parts.size() > 1 && parts.back().empty()) parts.pop_back();  // trailing empty strings are dropped
        if (parts.size() == 1 && parts[0].empty() && !s.empty()) parts.clear();
        const int r = newArr('L', parts.size());
        for (size_t i = 0; i < parts.size(); ++i) {
            const int item = newStr(parts[i]);
            heap_[static_cast<size_t>(r)].a[i] = item + 1;
        }
        return ref(r);
    }
    if (is("Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;")) {
        Obj o;
        o.kind = Obj::List;
        o.text = "Ljava/util/ArrayList;";
        o.a = obj(a.at(0)).a;
        return newObj(std::move(o));
    }
    if (sig.rfind("Ljava/util/Arrays;->copyOf(", 0) == 0 || sig.rfind("Ljava/util/Arrays;->copyOfRange(", 0) == 0) {
        const Obj source = obj(a.at(0));
        const bool range = sig.find("copyOfRange") != std::string::npos;
        const int64_t from = range ? static_cast<int32_t>(a.at(1).n) : 0, to = range ? static_cast<int32_t>(a.at(2).n) : static_cast<int32_t>(a.at(1).n);
        if (from < 0 || static_cast<size_t>(from) > source.a.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
        if (to < from) throw Stop{range ? "IllegalArgumentException: from > to" : "NegativeArraySizeException"};
        const int r = newArr(source.elem, static_cast<size_t>(to - from));
        for (int64_t i = from; i < to && static_cast<size_t>(i) < source.a.size(); ++i) heap_[static_cast<size_t>(r)].a[static_cast<size_t>(i - from)] = source.a[static_cast<size_t>(i)];
        return ref(r);
    }
    if (sig.rfind("Ljava/util/Arrays;->fill(", 0) == 0 && sig.find("II") == std::string::npos) {
        auto& arr = obj(a.at(0)).a;
        const int64_t v = refElement(obj(a[0]).elem) ? a.at(1).ref + 1 : a.at(1).n;
        std::fill(arr.begin(), arr.end(), v);
        hasResult = false;
        return {};
    }
    if (sig.rfind("Ljava/util/Arrays;->equals(", 0) == 0 && sig.find("[L") == std::string::npos) {
        if (a.at(0).ref < 0 || a.at(1).ref < 0) return integer(a[0].ref == a[1].ref);
        return integer(obj(a[0]).a == obj(a[1]).a);
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
        if (rest == "->append(J)" + c) { s += toU16(std::to_string(a[1].n)); return a[0]; }
        if (rest == "->append(Z)" + c) { s += a[1].n ? u"true" : u"false"; return a[0]; }
        if (rest == "->append(F)" + c) { s += toU16(javaNumber(asFloat(a[1].n))); return a[0]; }
        if (rest == "->append(D)" + c) { s += toU16(javaNumber(asDouble(a[1].n))); return a[0]; }
        if (rest == "->append(Ljava/lang/CharSequence;)" + c || rest == "->append(Ljava/lang/Object;)" + c ||
            rest == "->append(Ljava/lang/StringBuffer;)" + c) {
            const std::u16string text = textOf(a[1]);
            str(a[0]) += text;
            return a[0];
        }
        if (rest == "->insert(IC)" + c || rest == "->insert(ILjava/lang/String;)" + c || rest == "->insert(II)" + c) {
            const int64_t at = static_cast<int32_t>(a[1].n);
            if (at < 0 || static_cast<size_t>(at) > s.size()) throw Stop{"StringIndexOutOfBoundsException"};
            const std::u16string piece = rest.find("(IC)") != std::string::npos ? std::u16string(1, static_cast<char16_t>(a[2].n))
                                       : rest.find("(II)") != std::string::npos ? toU16(std::to_string(static_cast<int32_t>(a[2].n)))
                                                                                : textOf(a[2]);
            str(a[0]).insert(static_cast<size_t>(at), piece);
            return a[0];
        }
        if (rest == "->deleteCharAt(I)" + c) {
            if (a[1].n < 0 || static_cast<size_t>(a[1].n) >= s.size()) throw Stop{"StringIndexOutOfBoundsException"};
            s.erase(static_cast<size_t>(a[1].n), 1);
            return a[0];
        }
        if (rest == "->delete(II)" + c) {
            const int64_t from = static_cast<int32_t>(a[1].n), to = std::min<int64_t>(static_cast<int32_t>(a[2].n), static_cast<int64_t>(s.size()));
            if (from < 0 || from > to) throw Stop{"StringIndexOutOfBoundsException"};
            s.erase(static_cast<size_t>(from), static_cast<size_t>(to - from));
            return a[0];
        }
        if (rest == "->substring(I)Ljava/lang/String;" || rest == "->substring(II)Ljava/lang/String;") {
            const int64_t from = static_cast<int32_t>(a[1].n), to = rest.find("(II)") != std::string::npos ? static_cast<int32_t>(a[2].n) : static_cast<int64_t>(s.size());
            if (from < 0 || from > to || static_cast<size_t>(to) > s.size()) throw Stop{"StringIndexOutOfBoundsException"};
            return mk(s.substr(static_cast<size_t>(from), static_cast<size_t>(to - from)));
        }
        if (rest == "->indexOf(Ljava/lang/String;)I") {
            const size_t p = s.find(str(a[1]));
            return integer(p == std::u16string::npos ? -1 : static_cast<int64_t>(p));
        }
        if (rest == "->append([C)" + c) {
            for (int64_t ch : obj(a[1]).a) s.push_back(static_cast<char16_t>(ch));
            return a[0];
        }
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
        if (is("Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V")) {
            const std::vector<uint8_t> iv = bytesVec(a.at(2));
            Obj& self = obj(a.at(0));
            self.kind = Obj::IvSpec;
            self.iv = iv;
            self.tagBits = static_cast<unsigned>(a.at(1).n);
            hasResult = false;
            return {};
        }
        if (is("Ljava/security/spec/X509EncodedKeySpec;-><init>([B)V") || is("Ljava/security/spec/PKCS8EncodedKeySpec;-><init>([B)V")) {
            const std::vector<uint8_t> der = bytesVec(a.at(1));
            Obj& self = obj(a.at(0));
            self.kind = Obj::KeySpec;
            self.key = der;
            self.privateKey = sig.find("PKCS8") != std::string::npos;
            hasResult = false;
            return {};
        }
        if (is("Ljava/security/KeyFactory;->getInstance(Ljava/lang/String;)Ljava/security/KeyFactory;")) {
            const std::string name = toU8(strv(0));
            if (name != "RSA") throw Stop{"the key factory " + name + " is not emulated (RSA)"};
            Obj o;
            return ref(add(std::move(o)));
        }
        if (is("Ljava/security/KeyFactory;->generatePublic(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;") ||
            is("Ljava/security/KeyFactory;->generatePrivate(Ljava/security/spec/KeySpec;)Ljava/security/PrivateKey;")) {
            Obj key = obj(a.at(1));
            if (key.kind != Obj::KeySpec || key.privateKey != (sig.find("generatePrivate") != std::string::npos))
                throw Stop{"InvalidKeySpecException: the key spec does not match"};
            return ref(add(std::move(key)));
        }
        if (is("Ljava/security/spec/MGF1ParameterSpec;-><init>(Ljava/lang/String;)V")) {
            const std::string digestName = toU8(strv(1));
            obj(a.at(0)).text = digestName;
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/spec/PSource$PSpecified;-><init>([B)V")) {
            const std::vector<uint8_t> label = bytesVec(a.at(1));
            obj(a.at(0)).data = label;
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/spec/OAEPParameterSpec;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/security/spec/AlgorithmParameterSpec;Ljavax/crypto/spec/PSource;)V")) {
            const std::string main = toU8(strv(1));
            const std::string mask = a.at(3).ref >= 0 ? obj(a[3]).text : std::string("SHA-1");
            const std::vector<uint8_t> label = a.at(4).ref >= 0 ? obj(a[4]).data : std::vector<uint8_t>();
            Obj& self = obj(a.at(0));
            self.text = main;
            self.mgf = mask;
            self.data = label;
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/Cipher;->updateAAD([B)V")) {
            const std::vector<uint8_t> aad = bytesVec(a.at(1));
            Obj& c = obj(a.at(0));
            c.data.insert(c.data.end(), aad.begin(), aad.end());
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/Cipher;->doFinal([BII)[B")) {
            const std::vector<uint8_t> all = bytesVec(a.at(1));
            if (a.at(2).n < 0 || a.at(3).n < 0 || static_cast<size_t>(a[2].n + a[3].n) > all.size()) throw Stop{"IllegalArgumentException: bad range"};
            const Value part = byteArray(std::vector<uint8_t>(all.begin() + a[2].n, all.begin() + a[2].n + a[3].n));
            bool has = false;
            return libCall("Ljavax/crypto/Cipher;->doFinal([B)[B", {a[0], part}, has);
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
            if (!emu::crypto::parse(name).ok) throw Stop{"the cipher transformation " + name + " is not emulated (AES, DES, DESede in ECB / CBC; AES CTR, GCM; RSA PKCS1 / OAEP / NoPadding)"};
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
            c.privateKey = obj(a.at(2)).privateKey;
            c.iv.clear();
            c.data.clear();
            c.tagBits = 128;
            c.oaepHash.clear();
            c.mgf.clear();
            if (a.size() > 3 && a[3].ref >= 0) {
                const Obj& spec = obj(a[3]);
                c.iv = spec.iv;
                if (spec.tagBits) c.tagBits = spec.tagBits;
                if (spec.kind == Obj::OaepSpec) c.oaepHash = spec.text, c.mgf = spec.mgf, c.iv = spec.data;  // iv: the label
            }
            hasResult = false;
            return {};
        }
        if (is("Ljavax/crypto/Cipher;->doFinal([B)[B")) {
            Obj& c = obj(a.at(0));
            if (c.mode == 0) throw Stop{"IllegalStateException: the cipher was not initialised"};
            std::vector<uint8_t> out;
            std::string why;
            const emu::crypto::Transformation t = emu::crypto::parse(c.text);
            const std::vector<uint8_t> input = bytesVec(a.at(1));
            emu::crypto::RsaPadding padding;
            padding.kind = !t.oaep.empty() ? emu::crypto::RsaPadding::Oaep : t.pkcs5 ? emu::crypto::RsaPadding::Pkcs1 : emu::crypto::RsaPadding::None;
            if (!t.oaep.empty()) {
                padding.hash = c.oaepHash.empty() ? t.oaep : c.oaepHash;
                padding.mgfHash = c.mgf;
                padding.label = c.iv;
            }
            const bool ok = t.cipher == "RSA"  ? emu::crypto::rsa(c.mode == 1, c.privateKey, padding, c.key, input, out, why)
                            : t.mode == "GCM" ? emu::crypto::gcm(c.mode == 1, c.key, c.iv, c.data, c.tagBits, input, out, why)
                                              : emu::crypto::run(t, c.mode == 1, c.key, c.iv, input, out, why);
            if (!ok) throw Stop{why};
            c.data.clear();
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
    if (cls.rfind("Ljavax/crypto/", 0) == 0 || cls.rfind("Ljava/security/", 0) == 0) throw Stop{"the call " + sig + " is not emulated (supported: Cipher AES / DES / DESede / RSA with init and doFinal, GCM, KeyFactory RSA, MessageDigest, the key and IV specs)"};
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
      try {
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
            A_() = ref(caught_);
        } else if (op == 0x1c) {  // const-class
            A_() = classObject(std::string(dex.typeDescriptor(in.index)));
        } else if (op == 0x1d || op == 0x1e) {  // monitor-enter / exit: there is one thread
        } else if (op == 0x1f) {  // check-cast
        } else if (op == 0x20) {  // instance-of, for exceptions and strings
            const std::string t(dex.typeDescriptor(in.index));
            Value v;
            if (B_().ref >= 0) {
                const Obj& o = heap_[static_cast<size_t>(B_().ref)];
                if (t == "Ljava/lang/Object;") v.n = 1;
                else if (o.kind == Obj::Error || o.kind == Obj::Instance) v.n = isSubtype(o.text, t);
                else if (o.kind == Obj::Str) v.n = t == "Ljava/lang/String;" || t == "Ljava/lang/CharSequence;" || t == "Ljava/lang/Comparable;";
                else if (o.kind == Obj::Box) {
                    static const std::pair<char, const char*> names[] = {{'I', "Integer"}, {'J', "Long"}, {'S', "Short"}, {'B', "Byte"},
                                                                         {'C', "Character"}, {'Z', "Boolean"}, {'F', "Float"}, {'D', "Double"}};
                    for (const auto& [c, n] : names)
                        if (o.text[0] == c) v.n = t == std::string("Ljava/lang/") + n + ";" || t == "Ljava/lang/Comparable;" || (t == "Ljava/lang/Number;" && c != 'C' && c != 'Z');
                } else if (o.kind == Obj::List || o.kind == Obj::Map) {
                    const bool collection = o.kind == Obj::List || o.isSet;
                    v.n = t == o.text || (collection && (t == "Ljava/util/Collection;" || t == "Ljava/lang/Iterable;")) ||
                          (o.kind == Obj::List && t == "Ljava/util/List;" && o.text != "Ljava/util/ArrayDeque;") || (o.isSet && t == "Ljava/util/Set;") ||
                          (o.kind == Obj::Map && !o.isSet && t == "Ljava/util/Map;");
                } else if (o.kind == Obj::Arr) v.n = t.size() > 1 && t[0] == '[' && (t[1] == o.elem || (refElement(o.elem) && refElement(t[1])));
                else throw Stop{"instance-of " + t + " on this object is not emulated"};
            }
            A_() = v;
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
            else if (t == "Ljavax/crypto/spec/IvParameterSpec;" || t == "Ljavax/crypto/spec/GCMParameterSpec;") o.kind = Obj::IvSpec;
            else if (t == "Ljava/security/spec/X509EncodedKeySpec;" || t == "Ljava/security/spec/PKCS8EncodedKeySpec;") o.kind = Obj::KeySpec;
            else if (isSubtype(t, "Ljava/lang/Throwable;")) o.kind = Obj::Error, o.text = t, ensureInit(t);
            else if (A.findClass(t)) o.kind = Obj::Instance, o.text = t, ensureInit(t);
            else if (t == "Ljavax/crypto/spec/OAEPParameterSpec;") o.kind = Obj::OaepSpec;
            else if (t == "Ljava/security/spec/MGF1ParameterSpec;" || t == "Ljavax/crypto/spec/PSource$PSpecified;") o.kind = Obj::Dummy;
            else if (t == "Ljava/util/ArrayList;" || t == "Ljava/util/LinkedList;" || t == "Ljava/util/Vector;" || t == "Ljava/util/ArrayDeque;" ||
                     t == "Ljava/util/Stack;" || t == "Ljava/util/concurrent/CopyOnWriteArrayList;")
                o.kind = Obj::List, o.text = t;
            else if (t == "Ljava/util/HashMap;" || t == "Ljava/util/LinkedHashMap;" || t == "Ljava/util/HashSet;" || t == "Ljava/util/LinkedHashSet;" ||
                     t == "Ljava/util/Hashtable;" || t == "Ljava/util/concurrent/ConcurrentHashMap;" || t == "Ljava/util/TreeMap;" || t == "Ljava/util/TreeSet;") {
                o.kind = Obj::Map, o.text = t;
                o.isSet = t.size() > 4 && t.compare(t.size() - 4, 4, "Set;") == 0;
                o.order = t.find("Linked") != std::string::npos ? Obj::Insertion : (t == "Ljava/util/HashMap;" || t == "Ljava/util/HashSet;") ? Obj::Hashed : Obj::Unknown;
            }
            else throw Stop{"creates an instance of " + t + ", which is not emulated"};
            A_() = ref(add(std::move(o)));
        } else if (op == 0x23) {
            const std::string t(dex.typeDescriptor(in.index));
            const int64_t n = B_().n;
            if (t.size() < 2 || t[0] != '[') throw Stop{"array type " + t + " is not emulated"};
            if (n < 0) throw Stop{"NegativeArraySizeException"};
            A_() = ref(newArr(t[1], static_cast<size_t>(n)));
        } else if (op == 0x24 || op == 0x25) {
            const std::string t(dex.typeDescriptor(in.index));
            if (t.size() < 2 || t[0] != '[') throw Stop{"array type " + t + " is not emulated"};
            const int a = newArr(t[1], in.regCount);
            for (uint32_t k = 0; k < in.regCount; ++k) {
                const Value& v = reg(in.range ? in.regs[0] + k : in.regs[k]);
                heap_[static_cast<size_t>(a)].a[k] = refElement(t[1]) ? v.ref + 1 : v.n;
            }
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
            const Obj& e = obj(A_());
            if (e.kind != Obj::Error) throw Stop{"the routine throws something that is not an exception"};
            throw Thrown{e.text, A_().ref, std::string()};
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
            Value v;
            if (op == 0x31) {
                v.n = B_().n < C_().n ? -1 : B_().n > C_().n ? 1 : 0;
            } else {  // cmpl / cmpg: NaN gives -1 or 1
                const bool isDouble = op >= 0x2f;
                const double x = isDouble ? asDouble(B_().n) : asFloat(B_().n), y = isDouble ? asDouble(C_().n) : asFloat(C_().n);
                v.n = x < y ? -1 : x > y ? 1 : x == y ? 0 : (op == 0x2d || op == 0x2f) ? -1 : 1;
            }
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
            const Obj& o = obj(B_());
            const int64_t idx = static_cast<int32_t>(C_().n);
            if (idx < 0 || static_cast<size_t>(idx) >= o.a.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
            Value v;
            if (op == 0x46 && refElement(o.elem)) v.ref = static_cast<int>(o.a[static_cast<size_t>(idx)]) - 1;
            else v.n = o.a[static_cast<size_t>(idx)];
            A_() = v;
        } else if (op >= 0x4b && op <= 0x51) {
            auto& o = obj(B_());
            const int64_t idx = static_cast<int32_t>(C_().n);
            if (idx < 0 || static_cast<size_t>(idx) >= o.a.size()) throw Stop{"ArrayIndexOutOfBoundsException"};
            int64_t v = A_().n;
            if (op == 0x4f) v = static_cast<int8_t>(v);
            else if (op == 0x50) v = static_cast<char16_t>(v);
            else if (op == 0x51) v = static_cast<int16_t>(v);
            else if (op == 0x4d && refElement(o.elem)) v = A_().ref + 1;
            o.a[static_cast<size_t>(idx)] = v;
        } else if (op >= 0x60 && op <= 0x66) {
            A_() = sget(dex, in.index);
        } else if (op >= 0x67 && op <= 0x6d) {
            sput(dex, in.index, A_());
        } else if (op >= 0x52 && op <= 0x5f) {  // iget / iput: A is the value, B the object
            if (B_().ref < 0) throw Stop{"null pointer"};
            const std::string key = fieldKey(dex, in.index);
            Obj& target = obj(B_());
            if (target.kind != Obj::Instance && target.kind != Obj::Error) throw Stop{"reads a field of a library object, which is not emulated"};
            if (op <= 0x58) {
                const auto it = target.fields.find(key);
                A_() = it == target.fields.end() ? Value{} : it->second;
            } else {
                target.fields[key] = A_();
            }
        } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
            std::vector<Value> callArgs;
            for (uint32_t k = 0; k < in.regCount; ++k) callArgs.push_back(reg(in.range ? in.regs[0] + k : in.regs[k]));
            bool hasResult = false;
            const uint8_t kind = op >= 0x74 ? static_cast<uint8_t>(op - 6) : op;  // the /range forms
            const Value res = invoke(dex, in.index, callArgs, kind == op ? op : static_cast<uint8_t>(kind), hasResult);
            if (hasResult) last = res;
        } else if (op == 0x7b || op == 0x7c || op == 0x7d || op == 0x7e) {
            Value v;
            v.n = (op == 0x7b || op == 0x7d) ? -B_().n : ~B_().n;
            if (op < 0x7d) v.n = static_cast<int32_t>(v.n);
            A_() = v;
        } else if (op == 0x7f || op == 0x80) {  // neg-float / neg-double: flip the sign bit
            Value v;
            v.n = op == 0x7f ? fromFloat(-asFloat(B_().n)) : fromDouble(-asDouble(B_().n));
            A_() = v;
        } else if (op >= 0x81 && op <= 0x8f) {  // conversions
            Value v;
            const int64_t x = B_().n;
            const int32_t i = static_cast<int32_t>(x);
            switch (op) {
            case 0x81: v.n = i; break;                                          // int-to-long
            case 0x82: v.n = fromFloat(static_cast<float>(i)); break;           // int-to-float
            case 0x83: v.n = fromDouble(static_cast<double>(i)); break;         // int-to-double
            case 0x84: v.n = i; break;                                          // long-to-int
            case 0x85: v.n = fromFloat(static_cast<float>(x)); break;           // long-to-float
            case 0x86: v.n = fromDouble(static_cast<double>(x)); break;         // long-to-double
            case 0x87: v.n = javaToInt<int32_t>(asFloat(x)); break;             // float-to-int
            case 0x88: v.n = javaToInt<int64_t>(asFloat(x)); break;             // float-to-long
            case 0x89: v.n = fromDouble(static_cast<double>(asFloat(x))); break;  // float-to-double
            case 0x8a: v.n = javaToInt<int32_t>(asDouble(x)); break;            // double-to-int
            case 0x8b: v.n = javaToInt<int64_t>(asDouble(x)); break;            // double-to-long
            case 0x8c: v.n = fromFloat(static_cast<float>(asDouble(x))); break;  // double-to-float
            case 0x8d: v.n = static_cast<int8_t>(x); break;
            case 0x8e: v.n = static_cast<char16_t>(x); break;
            default: v.n = static_cast<int16_t>(x); break;
            }
            A_() = v;
        } else if ((op >= 0xa6 && op <= 0xaf) || (op >= 0xc6 && op <= 0xcf)) {  // float / double arithmetic
            const bool twoAddr = op >= 0xc6;
            const uint8_t group = twoAddr ? 0xc6 : 0xa6;
            const bool isDouble = op >= group + 5;
            const int kind = op - group - (isDouble ? 5 : 0);  // add, sub, mul, div, rem
            const int64_t xb = twoAddr ? A_().n : B_().n, yb = twoAddr ? B_().n : C_().n;
            const auto apply = [kind](auto x, auto y) -> decltype(x) {
                switch (kind) {
                case 0: return x + y;
                case 1: return x - y;
                case 2: return x * y;
                case 3: return x / y;
                default: return std::fmod(x, y);  // Java's % on floating point truncates like fmod
                }
            };
            Value v;
            v.n = isDouble ? fromDouble(apply(asDouble(xb), asDouble(yb))) : fromFloat(apply(asFloat(xb), asFloat(yb)));
            A_() = v;
        } else if (op >= 0x90 && op <= 0xa5) {
            const bool wide = op >= 0x9b;
            const uint8_t kind = static_cast<uint8_t>((op - (wide ? 0x9b : 0x90)));
            Value v;
            v.n = binop(kind, B_().n, C_().n, wide);
            A_() = v;
        } else if (op >= 0xb0 && op <= 0xc5) {
            const bool wide = op >= 0xbb;
            const uint8_t kind = static_cast<uint8_t>((op - (wide ? 0xbb : 0xb0)));
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
      } catch (const Thrown& t) {
        uint32_t handler = 0;
        if (!handlerFor(dex, code, pc, t.type, handler)) throw;
        if (t.ref < 0) {
            Obj o;
            o.kind = Obj::Error;
            o.text = t.type;
            const size_t colon = t.why.find(": ");
            if (colon != std::string::npos) o.s = toU16(t.why.substr(colon + 2));
            caught_ = add(std::move(o));
        } else {
            caught_ = t.ref;
        }
        pc = handler;
      } catch (const Stop& s) {
        // What would be a Java exception on a device can be caught by the routine; limits and gaps cannot.
        const std::string type = javaExceptionOf(s.why);
        if (type.empty()) throw;
        uint32_t handler = 0;
        if (!handlerFor(dex, code, pc, type, handler)) throw Thrown{type, -1, s.why};
        Obj o;
        o.kind = Obj::Error;
        o.text = type;
        const size_t colon = s.why.find(": ");
        if (colon != std::string::npos) o.s = toU16(s.why.substr(colon + 2));
        caught_ = add(std::move(o));
        pc = handler;
      }
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
    } catch (const Thrown& t) {
        out.error = m.describe(t);
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
