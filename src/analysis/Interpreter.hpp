#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"

// A small, sandboxed Dalvik interpreter for one purpose: running an app's own string-decoding routines (the static
// `String decode(String)` / `String d(int)` helpers obfuscators generate) on constant arguments, without a device.
//
// It executes the method's bytecode, the class's static initialiser (the keys and tables those routines read) and
// the app methods it calls, with try / catch / throw, and reflection over the app's static methods and the supported
// library calls. Objects of the app's own classes work: constructors, instance fields and virtual / interface / super
// calls. Floating point follows Java (NaN comparisons, saturating conversions, Float / Double text). Library calls are
// limited to a fixed list (String, StringBuilder, the boxes, Math, Integer / Long / Float / Double / Character helpers,
// java.util lists, maps and sets with HashMap's iteration order, Arrays, System.arraycopy, array clone, Base64,
// javax.crypto ciphers including AES-GCM and RSA (PKCS#1, OAEP), MessageDigest); anything else - I/O, other library
// classes - stops the run with an error that names it, so nothing outside the interpreter ever executes. Runs are
// bounded in steps, call depth and memory.
namespace emu {

struct Arg {
    enum class Kind : uint8_t { Int, String, Bytes } kind = Kind::Int;
    int64_t number = 0;
    std::string text;               // UTF-8
    std::vector<uint8_t> bytes;
    static Arg integer(int64_t v) { Arg a; a.kind = Kind::Int, a.number = v; return a; }
    static Arg string(std::string s) { Arg a; a.kind = Kind::String, a.text = std::move(s); return a; }
    static Arg byteArray(std::vector<uint8_t> b) { Arg a; a.kind = Kind::Bytes, a.bytes = std::move(b); return a; }
};

struct Outcome {
    bool ok = false;
    std::string text;         // the returned String (UTF-8), the integer as text, or the bytes as hex
    bool isString = false;
    std::string error;        // why it stopped ("the call ... is not emulated", "step limit", an uncaught exception)
    uint64_t steps = 0;
};

// Runs a static method with the given arguments (in order; `long` / `double` parameters are not supported).
Outcome runStatic(const ApkAnalysis& analysis, const ApkAnalysis::MethodDef& method, const std::vector<Arg>& args,
                  uint64_t maxSteps = 2000000);

// A decoded call site: `caller` invokes `decoder` with constant arguments, which produced `result`.
struct Decrypted {
    std::string caller;     // "Lcom/a/B;->m()V"
    uint32_t pc = 0;
    std::string decoder;    // "Lcom/a/C;->d(Ljava/lang/String;)Ljava/lang/String;"
    std::string args;       // "\"abc\", 3"
    std::string result;
};

struct SweepStats {
    size_t decoders = 0;      // candidate routines found (static, String / int parameters, String result)
    size_t working = 0;       // candidates that ran on at least one call site
    size_t callSites = 0;     // call sites with constant arguments
    size_t failed = 0;        // call sites the interpreter could not run
    std::string firstError;   // the first reason it stopped
};

// Finds string-decoding routines, evaluates every call site whose arguments are constants (straight-line
// `const-string` / `const` just before the call) and returns up to `limit` results.
std::vector<Decrypted> decryptCallSites(const ApkAnalysis& analysis, const std::atomic<bool>& stop, size_t limit, SweepStats* stats = nullptr);

}  // namespace emu
