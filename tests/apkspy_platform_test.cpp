// Portable headless tests (Windows / Linux / macOS) for the analysis engine,
// the MCP server and the device tooling:
//  - JSON, schema validation, JSON-RPC handling, owner-thread dispatch
//  - DEX parsing, Dalvik disassembly, xrefs, call graph, CFG, constant
//    argument flow, string classification - on a DEX built in memory
//  - robustness: thousands of mutated DEX/ELF inputs must not crash
//  - ELF parsing (symbols, JNI, DT_NEEDED) and demangling
//  - Document single-buffer line storage (+ the cancelEdit regression)
//  - end-to-end MCP tool calls against a real Workspace and APK
//  - HTTP transport security (token, Origin) and the JDWP client against a
//    fake JDWP peer; adb / logcat output parsers
#include <miniz.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include "core/LogSeverity.hpp"
#include "document/SyntaxHighlighter.hpp"
#include "core/VtScreen.hpp"
#include "analysis/ApkAnalysis.hpp"
#include "analysis/ApkDiff.hpp"
#include "analysis/Dalvik.hpp"
#include "analysis/Decompiler.hpp"
#include "core/Codec.hpp"
#include "core/TextDiff.hpp"
#include "debug/HttpClient.hpp"
#include "debug/MatchReplace.hpp"
#include "analysis/DexFile.hpp"
#include "analysis/Arm64.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/GraphLayout.hpp"
#include "analysis/NativeCode.hpp"
#include "debug/Emulator.hpp"
#include "core/ApkRepack.hpp"
#include "core/Process.hpp"
#include "core/Project.hpp"
#include "core/ScriptRunner.hpp"
#include "core/SearchService.hpp"
#include "core/TextSearch.hpp"
#include "core/Socket.hpp"
#include "core/Workspace.hpp"
#include "debug/Adb.hpp"
#include "debug/DeviceService.hpp"
#include "debug/Jdwp.hpp"
#include "debug/TrafficProxy.hpp"
#include "document/Document.hpp"
#include "image/ImageDecoder.hpp"
#include "image/Texture.hpp"
#include "mcp/Json.hpp"
#include "mcp/McpServer.hpp"
#include "mcp/McpTools.hpp"
#include "mcp/McpTransports.hpp"

namespace fs = std::filesystem;

// ---- stubs so we can link without OpenGL -----------------------------------
Texture::Texture(const uint8_t*, int, int) {}
Texture::~Texture() {}
int Texture::maxSize() { return 8192; }
std::string ImageDecoder::sniffFormat(const std::vector<uint8_t>&) { return {}; }
bool ImageDecoder::decode(const std::vector<uint8_t>&, DecodedImage&, std::string&) { return false; }

static int failures = 0;
static int passes = 0;
#define CHECK(cond, msg)                                     \
    do {                                                     \
        if (cond) {                                          \
            ++passes;                                        \
        } else {                                             \
            std::printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
            ++failures;                                      \
        }                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// In-memory DEX builder (one class LFoo; with bar()V and baz(String)V)
// ---------------------------------------------------------------------------

struct Buf {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { u8((uint8_t)v), u8((uint8_t)(v >> 8)); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) u8((uint8_t)(v >> (8 * i)));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) u8((uint8_t)(v >> (8 * i)));
    }
    void uleb(uint32_t v) {
        do {
            uint8_t byte = v & 0x7F;
            v >>= 7;
            if (v) byte |= 0x80;
            u8(byte);
        } while (v);
    }
    void align(size_t a) {
        while (b.size() % a) u8(0);
    }
    void put32(size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) b[at + i] = (uint8_t)(v >> (8 * i));
    }
};

static std::vector<uint8_t> buildDex() {
    const std::vector<std::string> strings = {"I",   "LFoo;", "Ljava/lang/String;", "V",
                                              "VL",  "bar",   "baz",                "count",
                                              "https://api.example.com/v1/login"};
    Buf d;
    d.b.resize(0x70, 0);
    std::memcpy(d.b.data(), "dex\n035\0", 8);
    d.put32(0x28, 0x12345678);
    const size_t stringIdsOff = d.b.size();
    for (size_t i = 0; i < strings.size(); ++i) d.u32(0);  // patched below
    const size_t typeIdsOff = d.b.size();
    for (uint32_t s : {0u, 1u, 2u, 3u}) d.u32(s);
    const size_t protoIdsOff = d.b.size();
    d.u32(3), d.u32(3), d.u32(0);      // p0: "V", returns V, no params
    d.u32(4), d.u32(3), d.u32(0);      // p1: "VL", returns V, params patched
    const size_t p1ParamsAt = protoIdsOff + 12 + 8;
    const size_t fieldIdsOff = d.b.size();
    d.u16(1), d.u16(0), d.u32(7);      // LFoo;->count:I
    const size_t methodIdsOff = d.b.size();
    d.u16(1), d.u16(0), d.u32(5);      // LFoo;->bar()V
    d.u16(1), d.u16(1), d.u32(6);      // LFoo;->baz(Ljava/lang/String;)V
    const size_t classDefsOff = d.b.size();
    d.u32(1), d.u32(1), d.u32(DexFile::kNoIndex), d.u32(0), d.u32(DexFile::kNoIndex), d.u32(0);
    const size_t classDataPatch = d.b.size();
    d.u32(0), d.u32(0);
    // string data
    for (size_t i = 0; i < strings.size(); ++i) {
        d.put32(stringIdsOff + 4 * i, (uint32_t)d.b.size());
        d.uleb((uint32_t)strings[i].size());
        for (char c : strings[i]) d.u8((uint8_t)c);
        d.u8(0);
    }
    d.align(4);
    d.put32(p1ParamsAt, (uint32_t)d.b.size());
    d.u32(1), d.u16(2), d.u16(0);  // type_list { Ljava/lang/String; }
    d.align(4);
    // code items
    const auto code = [&](uint16_t regs, uint16_t ins, uint16_t outs, std::vector<uint16_t> insns) {
        d.align(4);
        const uint32_t off = (uint32_t)d.b.size();
        d.u16(regs), d.u16(ins), d.u16(outs), d.u16(0), d.u32(0), d.u32((uint32_t)insns.size());
        for (uint16_t u : insns) d.u16(u);
        return off;
    };
    const uint32_t barCode = code(1, 0, 1,
                                  {0x001a, 0x0008,           // const-string v0, "https://..."
                                   0x1071, 0x0001, 0x0000,   // invoke-static {v0}, baz
                                   0x0038, 0x0004,           // if-eqz v0, :9
                                   0x0060, 0x0000,           // sget v0, count
                                   0x000e});                 // return-void
    const uint32_t bazCode = code(1, 1, 0, {0x000e});
    // class data
    d.put32(classDataPatch, (uint32_t)d.b.size());
    d.uleb(1), d.uleb(0), d.uleb(2), d.uleb(0);
    d.uleb(0), d.uleb(0x8);                     // static field count
    d.uleb(0), d.uleb(0x9), d.uleb(barCode);    // bar
    d.uleb(1), d.uleb(0x9), d.uleb(bazCode);    // baz
    d.put32(0x38, (uint32_t)strings.size()), d.put32(0x3C, (uint32_t)stringIdsOff);
    d.put32(0x40, 4), d.put32(0x44, (uint32_t)typeIdsOff);
    d.put32(0x48, 2), d.put32(0x4C, (uint32_t)protoIdsOff);
    d.put32(0x50, 1), d.put32(0x54, (uint32_t)fieldIdsOff);
    d.put32(0x58, 2), d.put32(0x5C, (uint32_t)methodIdsOff);
    d.put32(0x60, 1), d.put32(0x64, (uint32_t)classDefsOff);
    d.put32(0x20, (uint32_t)d.b.size());
    return d.b;
}

// Minimal ELF64 shared object: .dynstr, .dynsym (JNI export, import), .shstrtab.
static std::vector<uint8_t> buildElf() {
    Buf e;
    e.b.resize(64, 0);
    std::memcpy(e.b.data(), "\x7f" "ELF", 4);
    e.b[4] = 2, e.b[5] = 1, e.b[6] = 1;
    const std::string dynstr = std::string("\0Java_com_foo_Bar_baz\0JNI_OnLoad\0printf\0_ZN3foo3barEv\0", 54);
    const size_t dynstrOff = e.b.size();
    e.b.insert(e.b.end(), dynstr.begin(), dynstr.end());
    e.align(8);
    const size_t dynsymOff = e.b.size();
    const auto sym = [&](uint32_t name, uint8_t info, uint16_t shndx, uint64_t value) {
        e.u32(name), e.u8(info), e.u8(0), e.u16(shndx), e.u64(value), e.u64(16);
    };
    sym(0, 0, 0, 0);
    sym(1, 0x12, 1, 0x1000);   // GLOBAL FUNC Java_com_foo_Bar_baz
    sym(22, 0x12, 1, 0x1100);  // JNI_OnLoad
    sym(33, 0x12, 0, 0);       // printf (import)
    sym(40, 0x12, 1, 0x1200);  // _ZN3foo3barEv
    const size_t dynsymSize = e.b.size() - dynsymOff;
    const std::string shstr = std::string("\0.dynstr\0.dynsym\0.shstrtab\0", 27);
    const size_t shstrOff = e.b.size();
    e.b.insert(e.b.end(), shstr.begin(), shstr.end());
    e.align(8);
    const size_t shoff = e.b.size();
    const auto sh = [&](uint32_t name, uint32_t type, uint64_t off, uint64_t size, uint32_t link, uint64_t entsize) {
        e.u32(name), e.u32(type), e.u64(0), e.u64(0), e.u64(off), e.u64(size), e.u32(link), e.u32(0), e.u64(1),
            e.u64(entsize);
    };
    sh(0, 0, 0, 0, 0, 0);
    sh(1, 3, dynstrOff, dynstr.size(), 0, 0);    // .dynstr
    sh(9, 11, dynsymOff, dynsymSize, 1, 24);     // .dynsym -> link .dynstr
    sh(17, 3, shstrOff, shstr.size(), 0, 0);     // .shstrtab
    // header fields
    const auto put16 = [&](size_t at, uint16_t v) { e.b[at] = (uint8_t)v, e.b[at + 1] = (uint8_t)(v >> 8); };
    put16(16, 3);   // ET_DYN
    put16(18, 183); // AArch64
    for (int i = 0; i < 8; ++i) e.b[40 + i] = (uint8_t)(shoff >> (8 * i));
    put16(52, 64);
    put16(58, 64);
    put16(60, 4);
    put16(62, 3);
    return e.b;
}

static bool writeApk(const fs::path& path, const std::vector<std::pair<std::string, std::vector<uint8_t>>>& entries) {
    mz_zip_archive zip;
    mz_zip_zero_struct(&zip);
    if (!mz_zip_writer_init_file(&zip, path.string().c_str(), 0)) return false;
    for (const auto& e : entries)
        mz_zip_writer_add_mem(&zip, e.first.c_str(), e.second.data(), e.second.size(), MZ_DEFAULT_LEVEL);
    const bool ok = mz_zip_writer_finalize_archive(&zip);
    mz_zip_writer_end(&zip);
    return ok;
}

// ---------------------------------------------------------------------------

static void testJson() {
    std::printf("== json ==\n");
    Json v;
    std::string err;
    CHECK(Json::parse(R"({"a":[1,2.5,"xé😀",true,null],"b":{"c":-7}})", v, &err), "parse nested");
    CHECK(v.get("a").size() == 5 && v.get("a")[0].asInt() == 1 && v.get("a")[1].asNumber() == 2.5, "array values");
    CHECK(v.get("a")[2].asString() == "x\xC3\xA9\xF0\x9F\x98\x80", "unicode escapes + surrogate pair");
    CHECK(v.get("b").get("c").asInt() == -7, "nested object");
    Json back;
    CHECK(Json::parse(v.dump(), back) && back == v, "dump/parse round trip");
    CHECK(!Json::parse("{\"a\":}", v, &err) && !err.empty(), "syntax error reported");
    CHECK(!Json::parse("[1,2] x", v), "trailing garbage rejected");
    std::string deep(500, '[');
    CHECK(!Json::parse(deep, v), "nesting depth bounded");
    const std::string bad = std::string("ok\xC3(\xFF", 5);
    CHECK(Json(bad).dump() == "\"ok\xEF\xBF\xBD(\xEF\xBF\xBD\"", "invalid UTF-8 replaced by U+FFFD");
    CHECK(Json(std::string("\x01\n")).dump() == "\"\\u0001\\n\"", "control characters escaped");
    CHECK(Json((long long)9007199254740991LL).dump() == "9007199254740991", "large integers exact");

    // Regression: search_code read hits.size() after moving `hits` into its
    // result; the moved-from array had no storage and size() crashed.
    Json arr = Json::array();
    arr.push(1);
    Json obj = Json::obj({{"k", 1}});
    Json movedArr = std::move(arr);
    Json movedObj;
    movedObj = std::move(obj);
    // Using the moved-from values is the point of this test.
    CHECK(arr.isNull() && arr.size() == 0 && arr.dump() == "null", "moved-from array is a usable null");  // NOLINT(bugprone-use-after-move)
    CHECK(obj.isNull() && obj.size() == 0 && obj.items().empty(), "moved-from object is a usable null");  // NOLINT(bugprone-use-after-move)
    CHECK(movedArr.size() == 1 && movedObj.get("k").asInt() == 1, "move transfers the value");
}

static void testSchema() {
    std::printf("== schema validation ==\n");
    Json s = schema::object({{"name", schema::str("n")},
                             {"mode", schema::strEnum("m", {"a", "b"})},
                             {"limit", schema::integer("l", 1, 10)}},
                            {"name"});
    std::string err;
    CHECK(McpServer::validate(s, Json::obj({{"name", "x"}}), err), "minimal ok");
    CHECK(!McpServer::validate(s, Json::object(), err) && err.find("name") != std::string::npos, "required");
    CHECK(!McpServer::validate(s, Json::obj({{"name", "x"}, {"mode", "c"}}), err), "enum");
    CHECK(!McpServer::validate(s, Json::obj({{"name", "x"}, {"limit", 11}}), err), "maximum");
    CHECK(!McpServer::validate(s, Json::obj({{"name", "x"}, {"limit", 1.5}}), err), "integer type");
    CHECK(!McpServer::validate(s, Json::obj({{"name", "x"}, {"zzz", 1}}), err), "unknown property");
    CHECK(!McpServer::validate(s, Json::obj({{"name", 3}}), err), "type mismatch");
}

// Runs handleMessage on a transport thread while this (owner) thread pumps.
static Json rpc(McpServer& server, McpDispatcher& d, const std::string& msg, Workspace* ws = nullptr) {
    auto fut = std::async(std::launch::async, [&] { return server.handleMessage(msg, "test", nullptr); });
    while (fut.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
        d.pump();
        if (ws) ws->update();
    }
    const std::string out = fut.get();
    Json j;
    if (!out.empty()) Json::parse(out, j);
    return j;
}

static Json callTool(McpServer& server, McpDispatcher& d, Workspace* ws, const std::string& name, Json args) {
    static int id = 100;
    Json msg = Json::obj({{"jsonrpc", "2.0"}, {"id", ++id}, {"method", "tools/call"},
                          {"params", Json::obj({{"name", name}, {"arguments", std::move(args)}})}});
    return rpc(server, d, msg.dump(), ws);
}

static Json structured(const Json& r) { return r.get("result").get("structuredContent"); }
static std::string text(const Json& r) { return r.get("result").get("content")[0].get("text").asString(); }
static bool isError(const Json& r) { return r.get("result").get("isError").asBool() || r.has("error"); }

static void testMcpProtocol() {
    std::printf("== mcp protocol ==\n");
    McpDispatcher d;
    McpServer server(d, McpServer::Info{});
    std::atomic<int> ownerCalls{0};
    std::thread::id ownerId = std::this_thread::get_id();
    std::atomic<bool> onOwner{true};
    server.addTool({"echo", "Echo", "echo", schema::object({{"v", schema::str("value")}}, {"v"}), true, false,
                    [&](const Json& a, McpToolContext&) -> McpToolOutcome {
                        ++ownerCalls;
                        if (std::this_thread::get_id() != ownerId) onOwner = false;
                        return McpToolResult::ok(Json::obj({{"v", a.get("v")}}));
                    }});
    server.addTool({"slow", "Slow", "slow", schema::object({}), true, false, [&](const Json&, McpToolContext&) -> McpToolOutcome {
                        return McpToolOutcome::later([](McpToolContext& ctx) {
                            for (int i = 0; i < 400 && !ctx.cancelled(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                            return McpToolResult::ok(Json::obj({{"cancelled", ctx.cancelled()}}));
                        });
                    }});
    Json init = rpc(server, d, R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}})");
    CHECK(init.get("result").get("protocolVersion").asString() == "2025-03-26", "protocol version negotiated");
    CHECK(init.get("result").get("capabilities").has("tools"), "tools capability");
    CHECK(server.handleMessage(R"({"jsonrpc":"2.0","method":"notifications/initialized"})", "test", nullptr).empty(),
          "notifications get no response");
    Json list = rpc(server, d, R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    CHECK(list.get("result").get("tools").size() == 2, "tools/list");
    Json echo = callTool(server, d, nullptr, "echo", Json::obj({{"v", "hi"}}));
    CHECK(structured(echo).get("v").asString() == "hi" && !isError(echo), "tools/call result");
    CHECK(onOwner.load() && ownerCalls == 1, "handler ran on the owner thread");
    Json bad = callTool(server, d, nullptr, "echo", Json::object());
    CHECK(isError(bad) && text(bad).find("Invalid arguments") != std::string::npos, "argument validation error");
    Json unknown = rpc(server, d, R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}})");
    CHECK(unknown.get("error").get("code").asInt() == -32602, "unknown tool");
    Json nf = rpc(server, d, R"({"jsonrpc":"2.0","id":4,"method":"bogus"})");
    CHECK(nf.get("error").get("code").asInt() == -32601, "method not found");
    Json pe = rpc(server, d, "{not json");
    CHECK(pe.get("error").get("code").asInt() == -32700, "parse error");
    Json batch = rpc(server, d, R"([{"jsonrpc":"2.0","id":5,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"}])");
    CHECK(batch.isArray() && batch.size() == 1, "batch: notifications dropped from the response");

    // Cancellation of a long-running continuation.
    auto fut = std::async(std::launch::async, [&] {
        return server.handleMessage(R"({"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"slow"}})", "test", nullptr);
    });
    for (int i = 0; i < 50; ++i) {
        d.pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    server.handleMessage(R"({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":77}})", "test", nullptr);
    Json cancelled;
    Json::parse(fut.get(), cancelled);
    CHECK(cancelled.get("error").get("code").asInt() == -32800, "cancelled request answers with -32800");
    CHECK(server.inFlight() == 0, "in-flight registry cleaned up");

    // Owner never pumps -> timeout instead of hanging.
    server.setOwnerTimeoutMs(100);
    const std::string late = server.handleMessage(R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"v":"x"}}})", "test", nullptr);
    Json lj;
    Json::parse(late, lj);
    CHECK(isError(lj), "owner timeout reported as tool error");
    d.pump();  // the abandoned task must not run any more
    CHECK(ownerCalls == 1, "abandoned task skipped");
}

static void testDexAndAnalysis() {
    std::printf("== dex / dalvik / analysis ==\n");
    auto bytes = std::make_shared<std::vector<uint8_t>>(buildDex());
    std::string err;
    auto dex = DexFile::parse(bytes, "classes.dex", err);
    CHECK(dex != nullptr, ("dex parses: " + err).c_str());
    if (!dex) return;
    CHECK(dex->version() == 35 && dex->classes().size() == 1, "header + class defs");
    CHECK(dex->methodSignature(1) == "LFoo;->baz(Ljava/lang/String;)V", "method signature");
    CHECK(dex->fieldSignature(0) == "LFoo;->count:I", "field signature");
    CHECK(dex->findString("count") == 7 && dex->findString("zzz") == DexFile::kNoIndex, "string binary search");
    CHECK(dex->findType("LFoo;") == 1, "type lookup");
    CHECK(dex->findMethods("LFoo;", "baz").size() == 1, "method lookup");
    DexFile::ClassData data;
    CHECK(dex->classData(dex->classes()[0], data) && data.methods.size() == 2 && data.fields.size() == 1, "class data");

    std::string listing;
    dalvik::disassembleMethod(*dex, data.methods[0], dalvik::ListingOptions{}, listing);
    CHECK(listing.find("const-string v0, \"https://api.example.com/v1/login\"") != std::string::npos, "const-string rendered");
    CHECK(listing.find("invoke-static {v0}, LFoo;->baz(Ljava/lang/String;)V") != std::string::npos, "invoke rendered");
    CHECK(listing.find("if-eqz v0, :L0009") != std::string::npos && listing.find(":L0009") != std::string::npos,
          "branch target label");
    CHECK(listing.find("sget v0, LFoo;->count:I") != std::string::npos, "field reference");

    std::atomic<bool> stop{false};
    auto a = ApkAnalysis::build({dex}, stop);
    CHECK(a && a->classes().size() == 1 && a->stats().xrefs == 3, "analysis built (3 xrefs)");
    if (!a) return;
    auto callers = a->callersOf("LFoo;", "baz", "", 10);
    CHECK(callers.size() == 1 && a->methodSignature(callers[0].from) == "LFoo;->bar()V" && callers[0].from.pc == 2,
          "callers of baz");
    CHECK(a->stringUses("api.example", true, 10).size() == 1, "string xref by substring");
    CHECK(a->fieldAccesses("com.Foo", "count", 10).empty() && a->fieldAccesses("Foo", "count", 10).size() == 1,
          "field reads");
    auto defs = a->findMethodDefs("Foo", "bar");
    CHECK(defs.size() == 1, "method def by java name");
    auto blocks = a->controlFlowGraph(defs[0]);
    CHECK(blocks.size() == 3, "CFG has 3 blocks");
    if (blocks.size() == 3) {
        CHECK(blocks[0].successors.size() == 2 && blocks[2].exit, "branch block + exit block");
    }
    auto consts = a->constantArguments(defs[0]);
    CHECK(consts.size() == 1 && consts[0].args.size() == 1 &&
              consts[0].args[0].second.find("api.example.com") != std::string::npos,
          "constant argument flows into the call");
    CHECK(a->calleesOf(defs[0]).size() == 1, "callees");
    auto urls = a->strings({}, ApkAnalysis::StringCategory::Url, 10);
    CHECK(urls.size() == 1, "URL classification");
    {
        const auto spanAt = [](std::string_view line, bool& inBlock, size_t at) {
            std::vector<Span> spans;
            SyntaxHighlighter::tokenize(line, Language::Python, inBlock, spans);
            for (const Span& s : spans)
                if (at >= s.begin && at < s.end) return s;
            return Span{0, 0, SyntaxToken::Default};
        };
        bool inBlock = false;
        const SyntaxToken plain = spanAt("x", inBlock, 0).token;
        CHECK(spanAt("def x(): # note", inBlock, 0).token != plain, "python keyword is coloured");
        CHECK(spanAt("x = 1 # \"not a string", inBlock, 8).end == 21 && !inBlock, "python comment runs to the end");
        const Span prefixed = spanAt("x = rb'#a' + 1", inBlock, 4);
        CHECK(prefixed.begin == 4 && prefixed.end == 10, "python string prefix belongs to the string");
        spanAt("s = \"\"\"start", inBlock, 0);
        CHECK(inBlock, "triple quotes carry to the next line");
        const Span tail = spanAt("still # text", inBlock, 6);
        CHECK(inBlock && tail.begin == 0 && tail.end == 12, "no comments inside a triple-quoted string");
        spanAt("end\"\"\" + y", inBlock, 0);
        CHECK(!inBlock, "triple quotes close");
        spanAt("a = '''one''' + 2", inBlock, 0);
        CHECK(!inBlock, "triple quotes open and close on one line");
    }
    {
        // Terminal screen: text, wrapping, cursor moves, erase, colours, scrollback, replies.
        VtScreen vt(10, 3, 100);
        vt.feed("hello\r\nworld");
        CHECK(vt.lineText(0) == "hello" && vt.lineText(1) == "world" && vt.cursorX() == 5 && vt.cursorY() == 1, "vt text and newline");
        vt.feed("\x1b[1;1Hj\x1b[K");
        CHECK(vt.lineText(0) == "j", "vt cursor position and erase to end of line");
        vt.feed("\x1b[2J\x1b[H0123456789ab");
        CHECK(vt.lineText(0) == "0123456789" && vt.lineText(1) == "ab", "vt wraps at the right edge");
        vt.feed("\r\nx\r\ny\r\nz");  // one more row than the screen: the top goes to scrollback
        CHECK(vt.lineCount() == 5 && vt.lineText(0) == "0123456789" && vt.lineText(1) == "ab" && vt.lineText(4) == "z", "vt scrolls into scrollback");
        vt.feed("\x1b[31;1mR\x1b[0m");
        const VtScreen::Cell& red = vt.line(vt.lineCount() - 1)[1];
        CHECK(red.ch == U'R' && red.fg == VtScreen::paletteColor(1) && (red.flags & VtScreen::kBold), "vt colour and bold");
        vt.feed("\x1b[38;2;1;2;3mT");
        CHECK(vt.line(vt.lineCount() - 1)[2].fg == 0x010203, "vt 24-bit colour");
        std::string reply;
        vt.setReply([&](const std::string& r) { reply = r; });
        vt.feed("\x1b[6n");
        CHECK(reply == "\x1b[3;4R", "vt answers the cursor position request");
        vt.feed("\x1b]0;my title\x07\xC3\xA9");
        CHECK(vt.title() == "my title" && vt.line(vt.lineCount() - 1)[3].ch == U'é', "vt window title and UTF-8");
        vt.feed("\x1b[?1049h");
        CHECK(vt.altScreen() && vt.lineCount() == 3 && vt.lineText(0).empty(), "vt alternate screen");
        vt.feed("\x1b[?1049l");
        CHECK(!vt.altScreen() && vt.lineText(vt.lineCount() - 1).rfind("zR", 0) == 0, "vt main screen comes back");
        vt.resize(20, 5);
        CHECK(vt.cols() == 20 && vt.rows() == 5 && vt.line(vt.lineCount() - 1).size() == 20, "vt resize (screen rows take the new width)");
    }
    CHECK(logsev::sourceOf("[jadx] INFO - loading") == "jadx", "log line source");
    CHECK(logsev::messageOf("[jadx] INFO - loading") == "INFO - loading", "log line message");
    CHECK(logsev::sourceOf("no tag here").empty() && logsev::messageOf("no tag") == "no tag", "log line without a tag");
    CHECK(logsev::classify("[scripts] NameError: name 'x' is not defined") == LogSeverity::Error, "python failure is an error");
    CHECK(logsev::classify("[scripts] Traceback (most recent call last):") == LogSeverity::Error, "traceback is an error");
    CHECK(logsev::classify("[jadx] INFO - FooError: not ours") == LogSeverity::Info, "only scripts get the python rule");
    CHECK(logsev::classify("[jadx] ERROR - failed") == LogSeverity::Error, "tags keep the jadx severities");
    CHECK(ApkAnalysis::classify("192.168.1.20:8080") == ApkAnalysis::StringCategory::Ip, "IP classification");
    CHECK(ApkAnalysis::classify("/api/v2/users") == ApkAnalysis::StringCategory::Path, "path classification");
    CHECK(ApkAnalysis::classify("AKIAABCDEFGHIJKLMNOP") == ApkAnalysis::StringCategory::Secret, "secret classification");
    CHECK(ApkAnalysis::classify("hello world") == ApkAnalysis::StringCategory::Any, "plain string");
    {
        const auto extracted = ApkAnalysis::extractUrls("See https://goo.gle/admob-setup. Or (http://x.io/a?b=1), not ftp:/bad");
        CHECK(extracted.size() == 2 && extracted[0] == "https://goo.gle/admob-setup" && extracted[1] == "http://x.io/a?b=1",
              "URL tokens extracted from surrounding text");
    }
    CHECK(a->cfgToDot(defs[0], blocks).find("digraph") == 0, "DOT export");
    std::string cls, name, proto;
    CHECK(ApkAnalysis::splitMethodRef("Lcom/a/B;->m(I)V", cls, name, proto) && cls == "Lcom/a/B;" && name == "m" &&
              proto == "(I)V",
          "smali method ref");
    CHECK(ApkAnalysis::splitMethodRef("com.a.B.m", cls, name, proto) && cls == "Lcom/a/B;" && name == "m", "java ref");

    // Self-diff: nothing changed.
    ApkDiff diff;
    diff.compareCode(*a, *a, 100, nullptr);
    CHECK(diff.methodsChanged.empty() && diff.classesAdded.empty(), "self diff is empty");
}

static void testRobustness() {
    std::printf("== robustness (mutated inputs) ==\n");
    const std::vector<uint8_t> dexBase = buildDex();
    const std::vector<uint8_t> elfBase = buildElf();
    std::mt19937 rng(1234);
    int parsedDex = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        auto m = std::make_shared<std::vector<uint8_t>>(dexBase);
        const int flips = 1 + (int)(rng() % 8);
        for (int f = 0; f < flips; ++f) (*m)[8 + rng() % (m->size() - 8)] = (uint8_t)rng();
        if (iter % 7 == 0) m->resize(rng() % m->size());
        std::string err;
        auto dex = DexFile::parse(m, "fuzz.dex", err);
        if (!dex) continue;
        ++parsedDex;
        std::atomic<bool> stop{false};
        auto a = ApkAnalysis::build({dex}, stop);
        for (const auto& c : a->classes()) {
            a->disassembleClass(c);
            for (const auto& md : a->methodsOf(c)) {
                a->controlFlowGraph(md);
                a->constantArguments(md);
            }
        }
        a->strings({}, ApkAnalysis::StringCategory::Any, 100);
        a->callersOf("LFoo;", "baz", "", 10);
    }
    CHECK(parsedDex > 100, "many mutated DEX files still parsed and analysed without crashing");
    for (int iter = 0; iter < 3000; ++iter) {
        auto m = std::make_shared<std::vector<uint8_t>>(elfBase);
        for (int f = 0; f < 1 + (int)(rng() % 8); ++f) (*m)[4 + rng() % (m->size() - 4)] = (uint8_t)rng();
        std::string err;
        if (auto elf = ElfFile::parse(m, "fuzz.so", err)) {
            elf->exports();
            elf->strings(4, 100);
            uint64_t off;
            elf->vaddrToOffset(0x1000, off);
        }
    }
    CHECK(true, "mutated ELF files handled");
}

static void testElf() {
    std::printf("== elf ==\n");
    std::string err;
    auto elf = ElfFile::parse(std::make_shared<std::vector<uint8_t>>(buildElf()), "libfoo.so", err);
    CHECK(elf != nullptr, ("elf parses: " + err).c_str());
    if (!elf) return;
    CHECK(elf->is64() && elf->machineName() == "AArch64" && elf->typeName() == "shared object", "header");
    CHECK(elf->sections().size() == 4 && elf->sections()[2].name == ".dynsym", "section names");
    CHECK(elf->jniSymbols().size() == 2, "JNI symbols (Java_* + JNI_OnLoad)");
    CHECK(elf->imports().size() == 1 && elf->imports()[0]->name == "printf", "imports");
    CHECK(elf->exports().size() == 3, "exports");
    CHECK(ElfFile::demangle("_ZN3foo3barEv") == "foo::bar()", "demangle nested");
    CHECK(ElfFile::demangle("_ZN3foo3bazEiPKc") == "foo::baz(int, const char*)", "demangle params");
    CHECK(ElfFile::demangle("plain") == "plain", "non-mangled untouched");
    CHECK(ElfFile::demangle("_ZL14__libc_preinitv") == "__libc_preinit()", "internal-linkage names");
}

static void testArm64() {
    std::printf("== arm64 ==\n");
    struct Case {
        uint32_t word;
        uint64_t pc;
        const char* text;
    };
    const Case cases[] = {
        {0xa9bf7bfd, 0, "stp x29, x30, [sp, #-0x10]!"},
        {0x910003fd, 0, "mov x29, sp"},
        {0xa8c17bfd, 0, "ldp x29, x30, [sp], #0x10"},
        {0xd65f03c0, 0, "ret "},
        {0x94000000, 0x1000, "bl 0x1000"},
        {0x97ffffff, 0x1000, "bl 0xffc"},
        {0x90000008, 0x1234, "adrp x8, 0x1000"},
        {0xf9400100, 0, "ldr x0, [x8]"},
        {0x52800020, 0, "mov w0, #1"},
        {0x12800000, 0, "mov w0, #-1"},
        {0xd2800000, 0, "mov x0, #0"},
        {0xd503201f, 0, "nop "},
        {0xd503233f, 0, "paciasp "},
        {0xaa0103e0, 0, "mov x0, x1"},
        {0xeb01001f, 0, "cmp x0, x1"},
        {0x7100041f, 0, "cmp w0, #1"},
        {0x1a9f17e0, 0, "cset w0, eq"},
        {0x54000040, 0, "b.eq 0x8"},
        {0xb4000040, 0, "cbz x0, 0x8"},
        {0x36000040, 0, "tbz w0, #0, 0x8"},
        {0xd53bd040, 0, "mrs x0, tpidr_el0"},
        {0x9b027c20, 0, "mul x0, x1, x2"},
        {0x8b020020, 0, "add x0, x1, x2"},
        {0x53001c00, 0, "uxtb w0, w0"},
        {0x93407c00, 0, "sxtw x0, w0"},
        {0xd37ff800, 0, "lsl x0, x0, #1"},
        {0xf8696a6a, 0, "ldr x10, [x19, x9]"},
        {0xc85f7c20, 0, "ldxr x0, [x1]"},
        {0x1e222820, 0, "fadd s0, s1, s2"},
        {0x1e2e1000, 0, "fmov s0, #1.0"},
        {0x4e251c63, 0, "and v3.16b, v3.16b, v5.16b"},
        {0x4e24d442, 0, "fadd v2.4s, v2.4s, v4.4s"},
        {0x2f00e400, 0, "movi d0, #0x0"},
        {0x6e004001, 0, "ext v1.16b, v0.16b, v0.16b, #8"},
        {0x0e0c3c20, 0, "mov w0, v1.s[1]"},
        {0xd4000001, 0, "svc #0"},
    };
    int bad = 0;
    for (const auto& c : cases) {
        const arm64::Insn in = arm64::decode(c.word, c.pc);
        const std::string got = in.mnemonic + " " + in.operands;
        if (got != c.text) {
            ++bad;
            std::printf("    %08x: got '%s', want '%s'\n", c.word, got.c_str(), c.text);
        }
    }
    CHECK(bad == 0, "known encodings render like objdump/llvm");
    const arm64::Insn bl = arm64::decode(0x94000004, 0x100);
    CHECK(bl.flow == arm64::Flow::Call && bl.hasTarget && bl.target == 0x110, "bl target + call flow");
    CHECK(arm64::decode(0xd61f0200, 0).flow == arm64::Flow::IndirectJump, "br is an indirect jump");
    const arm64::Insn adrp = arm64::decode(0x90000008, 0x1234);
    CHECK(adrp.pageReg == 8 && adrp.target == 0x1000, "adrp exposes its page register");
    CHECK(!arm64::decode(0x0e20e000, 0).known, "unknown words become .inst");
}

// AArch64 shared object: f_entry (symbol) calls an unnamed function and forms
// the address of a string with adrp + add.
static std::vector<uint8_t> buildArm64Elf() {
    Buf e;
    e.b.resize(0x300, 0);
    std::memcpy(e.b.data(), "\x7f" "ELF", 4);
    e.b[4] = 2, e.b[5] = 1, e.b[6] = 1;
    const auto put = [&](size_t at, uint64_t v, int n) {
        for (int i = 0; i < n; ++i) e.b[at + i] = (uint8_t)(v >> (8 * i));
    };
    put(16, 3, 2), put(18, 183, 2), put(32, 64, 8), put(54, 56, 2), put(56, 1, 2);
    // PT_LOAD R+X covering the whole file at vaddr == offset
    put(64, 1, 4), put(68, 5, 4), put(72, 0, 8), put(80, 0, 8), put(96, 0x300, 8), put(104, 0x300, 8);
    const uint32_t code[] = {
        0xa9bf7bfd,  // 0x100 stp x29, x30, [sp, #-16]!
        0x94000007,  // 0x104 bl 0x120
        0x90000000,  // 0x108 adrp x0, 0x0
        0x91080000,  // 0x10c add x0, x0, #0x200
        0xa8c17bfd,  // 0x110 ldp x29, x30, [sp], #16
        0xd65f03c0,  // 0x114 ret
        0xd503201f,  // 0x118 nop
        0xd503201f,  // 0x11c nop
        0x52800020,  // 0x120 mov w0, #1
        0xd65f03c0,  // 0x124 ret
    };
    for (size_t i = 0; i < sizeof code / 4; ++i) put(0x100 + i * 4, code[i], 4);
    const char* str = "hello native";
    std::memcpy(e.b.data() + 0x200, str, std::strlen(str) + 1);
    // .strtab / .symtab / .shstrtab
    const std::string strtab = std::string("\0f_entry\0", 9);
    std::memcpy(e.b.data() + 0x220, strtab.data(), strtab.size());
    // symtab at 0x230: null + f_entry (GLOBAL FUNC, shndx 1, 0x100, size 0x18)
    put(0x248, 1, 4), e.b[0x24c] = 0x12, put(0x24e, 1, 2), put(0x250, 0x100, 8), put(0x258, 0x18, 8);
    const std::string shstr = std::string("\0.text\0.rodata\0.symtab\0.strtab\0.shstrtab\0", 41);
    std::memcpy(e.b.data() + 0x260, shstr.data(), shstr.size());
    e.b.resize(0x300);
    const size_t shoff = e.b.size();
    const auto sh = [&](uint32_t name, uint32_t type, uint64_t flags, uint64_t addr, uint64_t off, uint64_t size,
                        uint32_t link, uint64_t entsize) {
        e.u32(name), e.u32(type), e.u64(flags), e.u64(addr), e.u64(off), e.u64(size), e.u32(link), e.u32(0), e.u64(4),
            e.u64(entsize);
    };
    sh(0, 0, 0, 0, 0, 0, 0, 0);
    sh(1, 1, 6, 0x100, 0x100, 0x28, 0, 0);    // .text (AX)
    sh(7, 1, 2, 0x200, 0x200, 0x10, 0, 0);    // .rodata
    sh(15, 2, 0, 0, 0x230, 48, 4, 24);        // .symtab -> .strtab
    sh(23, 3, 0, 0, 0x220, strtab.size(), 0, 0);  // .strtab
    sh(31, 3, 0, 0, 0x260, shstr.size(), 0, 0);   // .shstrtab
    put(40, shoff, 8), put(58, 64, 2), put(60, 6, 2), put(62, 5, 2);
    return e.b;
}

static void testGraphLayout() {
    std::printf("== graph layout ==\n");
    using namespace graphlayout;
    const auto edge = [](int a, int b) {
        Edge e;
        e.from = a;
        e.to = b;
        return e;
    };
    // Diamond with a loop back to the top, a long edge and a self loop.
    std::vector<Node> nodes(6);
    for (auto& n : nodes) n.w = 120.f, n.h = 60.f;
    std::vector<Edge> edges = {edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3), edge(3, 0), edge(0, 3), edge(3, 4), edge(4, 5), edge(5, 5), edge(9, 1)};
    const Size size = layout(nodes, edges);
    CHECK(nodes[0].layer == 0 && nodes[1].layer == 1 && nodes[3].layer == 2 && nodes[5].layer == 4, "longest-path layers");
    CHECK(edges[4].back && !edges[0].back && edges[8].back, "back edges and self loops found");
    bool overlap = false, outside = false;
    for (size_t a = 0; a < nodes.size(); ++a) {
        const Node& x = nodes[a];
        outside = outside || x.x < 0.f || x.y < 0.f || x.x + x.w > size.width || x.y + x.h > size.height;
        for (size_t b = a + 1; b < nodes.size(); ++b) {
            const Node& y = nodes[b];
            overlap = overlap || (x.x < y.x + y.w && y.x < x.x + x.w && x.y < y.y + y.h && y.y < x.y + x.h);
        }
    }
    CHECK(!overlap, "nodes never overlap");
    CHECK(!outside, "nodes inside the extent");
    bool attached = true, orthogonal = true, routed = true;
    for (size_t i = 0; i + 1 < edges.size(); ++i) {
        const Edge& e = edges[i];
        routed = routed && e.points.size() >= 2;
        if (e.points.size() < 2 || e.from == e.to) continue;
        const Node& a = nodes[(size_t)e.from];
        const Node& b = nodes[(size_t)e.to];
        attached = attached && e.points.front().y == a.y + a.h && e.points.back().y == b.y;
        for (size_t k = 1; k < e.points.size(); ++k)
            orthogonal = orthogonal && (e.points[k].x == e.points[k - 1].x || e.points[k].y == e.points[k - 1].y);
    }
    CHECK(routed, "every valid edge routed");
    CHECK(attached, "edges leave the bottom and enter the top");
    CHECK(orthogonal, "edges are orthogonal");
    CHECK(edges.back().points.empty(), "out-of-range edge ignored");
    // Pure cycle: no node without an incoming edge; must terminate and place everything.
    std::vector<Node> ring(4);
    for (auto& n : ring) n.w = 50.f, n.h = 20.f;
    std::vector<Edge> ringEdges = {edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 0)};
    CHECK(layout(ring, ringEdges).height > 0.f && ring[3].layer == 3, "cycle laid out from the entry");
    // Left to right: one caller, a fan of callees stacked in the next column.
    std::vector<Node> fan(4);
    for (auto& n : fan) n.w = 200.f, n.h = 30.f;
    std::vector<Edge> fanEdges = {edge(0, 1), edge(0, 2), edge(0, 3)};
    Options sideways;
    sideways.leftToRight = true;
    const Size fanSize = layout(fan, fanEdges, sideways);
    CHECK(fan[1].x > fan[0].x + fan[0].w && fan[1].x == fan[2].x && fan[2].x == fan[3].x, "left to right: callees in a column");
    CHECK(fan[1].y != fan[2].y && fan[0].w == 200.f && fanSize.width > 400.f, "left to right: sizes kept, stacked vertically");
    CHECK(fanEdges[0].points.front().x == fan[0].x + fan[0].w && fanEdges[0].points.back().x == fan[1].x, "left to right: edges leave right, enter left");
    std::vector<Node> none;
    std::vector<Edge> noEdges;
    CHECK(layout(none, noEdges).width == 0.f, "empty graph");
    // Large method: stays quick and consistent.
    std::vector<Node> big(4000);
    std::vector<Edge> bigEdges;
    for (int i = 0; i < 4000; ++i) {
        big[(size_t)i].w = 200.f, big[(size_t)i].h = 80.f;
        if (i + 1 < 4000) bigEdges.push_back(edge(i, i + 1));
        if (i + 7 < 4000 && i % 3 == 0) bigEdges.push_back(edge(i, i + 7));
        if (i > 20 && i % 11 == 0) bigEdges.push_back(edge(i, i - 20));
    }
    const auto started = std::chrono::steady_clock::now();
    layout(big, bigEdges);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    CHECK(ms < 2000, ("4000-block graph laid out quickly: " + std::to_string(ms) + " ms").c_str());
}

static void testNativeCode() {
    std::printf("== native code ==\n");
    std::string err;
    auto elf = ElfFile::parse(std::make_shared<std::vector<uint8_t>>(buildArm64Elf()), "libnat.so", err);
    CHECK(elf != nullptr, ("arm64 elf parses: " + err).c_str());
    if (!elf) return;
    auto nc = NativeCode::build(elf, nullptr, err);
    CHECK(nc != nullptr, ("native code builds: " + err).c_str());
    if (!nc) return;
    const auto* entry = nc->findFunction("f_entry");
    CHECK(entry && entry->addr == 0x100 && entry->size == 0x18, "symbol function with size");
    const auto* sub = nc->findFunction("0x124");
    CHECK(sub && sub->addr == 0x120 && sub->name == "sub_120" && sub->kind == NativeCode::FunctionKind::Discovered,
          "call target discovered as sub_<addr>");
    const auto callers = nc->refsTo(0x120, 10);
    CHECK(callers.size() == 1 && callers[0].from == 0x104 && callers[0].kind == NativeCode::RefKind::Call, "xref to callee");
    const auto lines = entry ? nc->disassembleFunction(*entry, 100) : std::vector<NativeCode::Line>{};
    CHECK(lines.size() == 6, "function listing length");
    if (lines.size() == 6) {
        CHECK(lines[1].targetName == "sub_120", "call target named");
        CHECK(lines[3].comment == "\"hello native\"" && lines[3].dataAddr == 0x200, "adrp + add resolved to the string");
    }
    const auto strs = nc->stringRefs("native", 10);
    CHECK(strs.size() == 1 && strs[0].from == 0x10c && strs[0].text == "hello native", "string references");
    CHECK(nc->symbolize(0x108) == "f_entry+0x8", "symbolize inside a function");
    if (entry) {
        const auto cfg = nc->controlFlow(*entry, 100);
        CHECK(cfg.blocks.size() == 1 && cfg.blocks[0].exit && cfg.blocks[0].lineCount == 6, "straight-line function is one block");
    }
    {
        // Hand-assembled: cbz x0, +8 ; mov ; ret  (taken and fall-through both reach the ret block).
        const auto assemble = [](std::vector<uint32_t> code) {
            auto bytes = buildArm64Elf();
            for (size_t i = 0; i < code.size(); ++i)
                for (int k = 0; k < 4; ++k) bytes[0x100 + i * 4 + (size_t)k] = (uint8_t)(code[i] >> (8 * k));
            return std::make_shared<std::vector<uint8_t>>(std::move(bytes));
        };
        std::string e2;
        auto loopElf = ElfFile::parse(assemble({0xb4000040, 0x52800020, 0xd65f03c0, 0xd503201f, 0xd503201f, 0xd503201f}), "c.so", e2);
        auto loopCode = loopElf ? NativeCode::build(loopElf, nullptr, e2) : nullptr;
        const auto* fn = loopCode ? loopCode->findFunction("f_entry") : nullptr;
        if (fn) {
            const auto cfg = loopCode->controlFlow(*fn, 3);
            CHECK(cfg.blocks.size() == 3 && cfg.blocks[0].conditional && cfg.blocks[0].successors == std::vector<int>({2, 1}),
                  "conditional branch: taken then fall-through");
            CHECK(cfg.blocks[1].successors == std::vector<int>({2}) && cfg.blocks[2].exit, "fall-through and return blocks");
        }
        CHECK(fn != nullptr, "branching function built");
    }
    // Non-AArch64 libraries are refused with a hint instead of garbage.
    auto bytes = std::make_shared<std::vector<uint8_t>>(buildArm64Elf());
    (*bytes)[18] = 40;  // EM_ARM
    auto armElf = ElfFile::parse(bytes, "libarm.so", err);
    std::string armErr;
    CHECK(armElf && !NativeCode::build(armElf, nullptr, armErr) && armErr.find("arm64-v8a") != std::string::npos,
          "32-bit ARM refused with a hint");
    std::atomic<bool> cancel{true};
    std::string cancelErr;
    CHECK(!NativeCode::build(elf, &cancel, cancelErr), "cancellation honoured");
}

static void testAnnotations() {
    std::printf("== annotations ==\n");
    Annotations notes;
    Annotation line;
    line.group = "app";
    line.root = RootKind::Decompiled;
    line.path = "sources/a/B.java";
    line.line = 41;
    line.context = "int x = 1;";
    Annotation comment = line;
    comment.kind = Annotation::Kind::Comment;
    comment.text = "first\nsecond \\ line";
    const int id = notes.set(comment);
    CHECK(id > 0 && notes.all().size() == 1, "comment added");
    comment.text = "replaced";
    CHECK(notes.set(comment) == id && notes.all().size() == 1 && notes.find(id)->text == "replaced",
          "same kind + location replaces the text");
    CHECK(notes.toggleBookmark(line) && notes.all().size() == 2, "bookmark added beside the comment");
    CHECK(!notes.toggleBookmark(line) && notes.all().size() == 1, "bookmark toggled off");
    Annotation native;
    native.kind = Annotation::Kind::Comment;
    native.target = Annotation::Target::Native;
    native.group = "app";
    native.path = "lib/arm64-v8a/libfoo.so";
    native.addr = 0x1234abcdef;
    native.text = "decrypts the config";
    const int nativeId = notes.set(native);
    CHECK(nativeId > 0 && notes.at(Annotation::Kind::Comment, native)->id == nativeId, "native annotation");
    Annotation bad = line;
    bad.root = RootKind::Virtual;
    CHECK(notes.set(bad) == 0, "generated listings refused");
    bad = line;
    bad.path.clear();
    CHECK(notes.set(bad) == 0, "empty path refused");
    CHECK(Annotations::unescape(Annotations::escape("a\\n\nb\r\\")) == "a\\n\nb\r\\", "escape round trip");
    const uint64_t before = notes.version();
    CHECK(notes.updateText(id, "first\nsecond \\ line") && notes.version() != before, "version bumped");

    // Project file round trip, including a hostile count and bad kinds.
    const fs::path dir = fs::temp_directory_path() / "apkspy_annotations_test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const std::string file = (dir / "p.apkspy").string();
    Project out;
    out.reset();
    out.setAnnotations(notes.all());
    CHECK(out.save(file), "project with annotations saved");
    Project in;
    CHECK(in.load(file) && in.annotations().size() == 2, "annotations loaded");
    Annotations restored;
    restored.replaceAll(in.annotations());
    const Annotation* c = restored.at(Annotation::Kind::Comment, line);
    CHECK(c && c->text == "first\nsecond \\ line" && c->line == 41 && c->root == RootKind::Decompiled && c->context == "int x = 1;",
          "file comment survives with newlines");
    const Annotation* n = restored.at(Annotation::Kind::Comment, native);
    CHECK(n && n->addr == 0x1234abcdef, "64-bit native address survives");
    {
        std::ofstream f(file, std::ios::app);
        f << "note.count=2147483647\n";
    }
    Project hostile;
    CHECK(!hostile.load(file), "absurd note.count rejected");
    {
        std::ofstream f(file, std::ios::trunc);
        f << "format=apkspy-project-1\nnote.count=1\nnote.0.kind=9\nnote.0.group=a\nnote.0.path=b\n";
    }
    Project badKind;
    CHECK(badKind.load(file) && badKind.annotations().empty(), "invalid entries skipped");
    fs::remove_all(dir);
}

static void testDocument() {
    std::printf("== document line storage ==\n");
    TreeNode node("a.java", "", NodeKind::Java);
    std::string src = "class A {\r\n  int x;\r\n}\r\n";
    Document doc("a.java", &node, std::vector<uint8_t>(src.begin(), src.end()), RootKind::Apk);
    CHECK(doc.mode() == Document::Mode::Code, "text detected");
    CHECK(doc.lineCount() == 4 && doc.line(1) == "  int x;" && doc.line(3).empty(), "lines from one buffer, CR stripped");
    CHECK(doc.text() == "class A {\n  int x;\n}\n", "normalized text");
    bool truncated = false;
    auto matches = textsearch::findAll(doc.lines(), "x", textsearch::Options{}, 100, truncated);
    CHECK(matches.size() == 1 && matches[0].line == 1, "findAll over Document lines");

    // Media files get their own viewers: by extension, or by content when the name says nothing.
    {
        const auto modeOf = [](const char* name, std::string content) {
            TreeNode n(name, "", TreeNode::classify(name));
            Document d(name, &n, std::vector<uint8_t>(content.begin(), content.end()), RootKind::Apk);
            return d.mode();
        };
        CHECK(modeOf("click.ogg", "OggS rest") == Document::Mode::Audio, "ogg is audio");
        CHECK(modeOf("tone.wav", std::string("RIFF\x10\0\0\0WAVEfmt ", 16)) == Document::Mode::Audio, "wav is audio");
        CHECK(modeOf("data.bin", "OggS rest") == Document::Mode::Audio, "audio found by content");
        CHECK(modeOf("Roboto.ttf", std::string("\0\x01\0\0\0\x0c", 6)) == Document::Mode::Font, "ttf is a font");
        CHECK(modeOf("glyphs", "OTTO....") == Document::Mode::Font, "font found by content");
        CHECK(modeOf("blob.bin", std::string("\x01\x02\x03\0", 4)) == Document::Mode::Hex, "other binaries stay hex");
        CHECK(modeOf("intro.mp4", "....ftypisom") == Document::Mode::Video, "mp4 is video");
        CHECK(modeOf("clip", std::string("\0\0\0\x18" "ftypmp42", 12)) == Document::Mode::Video, "mp4 found by content");
        CHECK(modeOf("page.webm", "\x1A\x45\xDF\xA3....") == Document::Mode::Video, "webm is video");
        CHECK(modeOf("voice.m4a", "....ftypM4A ") == Document::Mode::Video, "m4a goes to the media player (AAC)");
    }

    // Editing a decompiled file: Don't Save restores the original (this
    // used to blank the document).
    const fs::path tmp = fs::temp_directory_path() / "apkspy_doc_test.java";
    {
        std::ofstream(tmp, std::ios::binary) << "line1\nline2";
    }
    TreeNode disk("x.java", tmp.string(), NodeKind::Java);
    std::vector<uint8_t> b;
    DiskSource::readFile(tmp.string(), b);
    Document ed("x.java", &disk, b, RootKind::Decompiled);
    ed.beginEdit();
    ed.editBuffer() += "\nline3";
    ed.markDirty();
    CHECK(ed.lineCount() == 3 && ed.line(2) == "line3", "edit buffer visible");
    ed.cancelEdit();
    CHECK(ed.lineCount() == 2 && ed.line(1) == "line2", "cancelEdit restores the original text");
    ed.beginEdit();
    ed.editBuffer() = "new";
    ed.markDirty();
    CHECK(ed.save() && ed.lineCount() == 1 && ed.line(0) == "new" && !ed.isDirty(), "save adopts the edit buffer");
    fs::remove(tmp);
}

static void testSearchMatcher() {
    std::printf("== search line matcher ==\n");
    using M = SearchService::Mode;
    CHECK(SearchService::lineMatches(M::Classes, "public final class FooBar extends X {", "foobar"), "class decl");
    CHECK(!SearchService::lineMatches(M::Classes, "FooBar x = new FooBar();", "foobar"), "not a class decl");
    CHECK(SearchService::lineMatches(M::Fields, "private static int counter = 0;", "counter"), "field decl");
    CHECK(!SearchService::lineMatches(M::Fields, "private void counter() {", "counter"), "method is not a field");
    CHECK(SearchService::lineMatches(M::Methods, "  void run(int a) {", "run"), "method");
}

static void testAdbParsers() {
    std::printf("== adb / logcat parsers ==\n");
    auto devs = adb::Adb::parseDevices("List of devices attached\nemulator-5554 device product:sdk model:Pixel_7 transport_id:1\n"
                                       "R58M123 unauthorized usb:1-1 transport_id:2\n\n");
    CHECK(devs.size() == 2 && devs[0].model == "Pixel_7" && devs[0].emulator() && devs[1].state == "unauthorized", "devices -l");
    auto procs = adb::Adb::parseProcesses("PID PPID USER RSS NAME\n1 0 root 1234 init\n4321 600 u0_a77 98765 com.example.app\n");
    CHECK(procs.size() == 2 && procs[1].pid == 4321 && procs[1].name == "com.example.app" && procs[1].rssKb == 98765, "ps");
    auto threads = adb::Adb::parseThreads("TID S CMD\n4321 S com.example.app\n4330 R RenderThread\n");
    CHECK(threads.size() == 2 && threads[1].name == "RenderThread" && threads[1].state == "R", "ps -T");
    auto st = adb::Adb::parseProcStat("cpu  100 0 50 1000 0 0 0 0 0 0\n"
                                      "4321 (com.example (x)) S 600 600 0 0 -1 0 1 0 0 0 30 12 0 0 20 0 42\n"
                                      "Name: x\nVmSize:  1000 kB\nVmRSS:\t 2048 kB\nThreads:\t42\n");
    CHECK(st.ok && st.cpuTotalJiffies == 1150 && st.procJiffies == 42 && st.rssKb == 2048 && st.threads == 42,
          "/proc stat + status (comm with spaces)");
    auto mem = adb::Adb::parseMemInfo("App Summary\n  Java Heap:     12000 \n  Native Heap:   34000\n TOTAL PSS:   99999 TOTAL RSS: 1\n");
    CHECK(mem.ok && mem.totalPssKb == 99999 && mem.javaHeapKb == 12000 && mem.nativeHeapKb == 34000, "dumpsys meminfo");
    auto e = DeviceService::parseLogLine("11-03 20:15:42.123  1234  5678 W ActivityManager: Slow operation: 120ms");
    CHECK(e.pid == 1234 && e.tid == 5678 && e.level == 'W' && e.tag == "ActivityManager" && e.message == "Slow operation: 120ms",
          "logcat threadtime line");
    CHECK(adb::validSerial("emulator-5554") && adb::validSerial("192.168.0.5:5555") && !adb::validSerial("a;rm -rf /") &&
              !adb::validSerial("a b"),
          "serial whitelist");
    CHECK(adb::validPackage("com.example.app:remote") && !adb::validPackage("com.x;reboot") && !adb::validPackage("$(id)"),
          "package whitelist");
}

static void testProcess() {
    std::printf("== process runner ==\n");
#ifdef _WIN32
    auto r = proc::run({"cmd.exe", "/c", "echo", "hello"}, 10000);
    auto slow = proc::run({"cmd.exe", "/c", "ping", "-n", "30", "127.0.0.1"}, 300);
#else
    auto r = proc::run({"sh", "-c", "echo hello"}, 10000);
    auto slow = proc::run({"sh", "-c", "sleep 30"}, 300);
#endif
    CHECK(r.started && r.exitCode == 0 && r.output.find("hello") != std::string::npos, "captured output");
    CHECK(slow.started && slow.timedOut, "timeout kills the process tree");
    auto missing = proc::run({"definitely-not-a-real-binary-apkspy"}, 2000);
    CHECK(!missing.started || missing.exitCode != 0, "missing executable reported");
}

// Simple HTTP/1.1 client for the transport test.
static std::string httpPost(int port, const std::string& body, const std::string& headers) {
    Socket s;
    std::string err;
    if (!s.connectLoopback(port, 2000, err)) return "connect failed";
    const std::string req = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\n" +
                            headers + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    s.sendAll(req);
    std::string out;
    char buf[4096];
    while (s.waitReadable(3000)) {
        const long n = s.recvSome(buf, sizeof buf);
        if (n <= 0) break;
        out.append(buf, (size_t)n);
    }
    return out;
}

static void testHttpTransport() {
    std::printf("== mcp http transport ==\n");
    McpDispatcher d;
    McpServer server(d, McpServer::Info{});
    server.addTool({"ping_tool", "", "p", schema::object({}), true, false,
                    [](const Json&, McpToolContext&) -> McpToolOutcome { return McpToolResult::ok(Json::obj({{"pong", true}})); }});
    McpHttpServer http;
    std::string err;
    CHECK(http.start(server, 0, "secret-token", err), ("http listens: " + err).c_str());
    std::atomic<bool> stop{false};
    std::thread owner([&] {
        while (!stop) {
            d.pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
    const std::string init = R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})";
    const std::string noAuth = httpPost(http.port(), init, "");
    CHECK(noAuth.find("401") != std::string::npos, "missing token -> 401");
    const std::string badOrigin = httpPost(http.port(), init, "Authorization: Bearer secret-token\r\nOrigin: http://evil.example\r\n");
    CHECK(badOrigin.find("403") != std::string::npos, "foreign Origin -> 403 (DNS rebinding)");
    const std::string ok = httpPost(http.port(), init, "Authorization: Bearer secret-token\r\nOrigin: http://localhost:3000\r\n");
    CHECK(ok.find("200 OK") != std::string::npos && ok.find("Mcp-Session-Id") != std::string::npos &&
              ok.find("\"protocolVersion\":\"2025-06-18\"") != std::string::npos,
          "initialize over HTTP with session id");
    const std::string call = httpPost(http.port(), R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping_tool"}})",
                                      "Authorization: Bearer secret-token\r\n");
    CHECK(call.find("\"pong\":true") != std::string::npos, "tool call over HTTP");
    const std::string note = httpPost(http.port(), R"({"jsonrpc":"2.0","method":"notifications/initialized"})",
                                      "Authorization: Bearer secret-token\r\n");
    CHECK(note.find("202") != std::string::npos, "notification -> 202 Accepted");
    http.stop();
    stop = true;
    owner.join();
    CHECK(!http.running(), "http stopped");
}

// Fake JDWP peer: handshake + IDSizes / Version / AllThreads / Name.

// Reads from a socket until the peer closes (or timeout).
static std::string readAllFrom(Socket& s, int timeoutMs = 3000) {
    std::string out;
    char buf[4096];
    while (s.waitReadable(timeoutMs)) {
        const long n = s.recvSome(buf, sizeof buf);
        if (n <= 0) break;
        out.append(buf, (size_t)n);
    }
    return out;
}

static std::string clientHello(const std::string& host) {
    std::vector<uint8_t> ext;
    const auto u16 = [](std::vector<uint8_t>& v, size_t x) { v.push_back((uint8_t)(x >> 8)), v.push_back((uint8_t)x); };
    // server_name extension
    std::vector<uint8_t> sni;
    u16(sni, host.size() + 3);
    sni.push_back(0);
    u16(sni, host.size());
    sni.insert(sni.end(), host.begin(), host.end());
    u16(ext, 0);
    u16(ext, sni.size());
    ext.insert(ext.end(), sni.begin(), sni.end());
    std::vector<uint8_t> body{0x03, 0x03};
    body.insert(body.end(), 32, 0);  // random
    body.push_back(0);               // session id
    u16(body, 2), body.push_back(0x13), body.push_back(0x01);
    body.push_back(1), body.push_back(0);
    u16(body, ext.size());
    body.insert(body.end(), ext.begin(), ext.end());
    std::vector<uint8_t> hs{0x01, 0, (uint8_t)(body.size() >> 8), (uint8_t)body.size()};
    hs.insert(hs.end(), body.begin(), body.end());
    std::vector<uint8_t> rec{0x16, 0x03, 0x01};
    u16(rec, hs.size());
    rec.insert(rec.end(), hs.begin(), hs.end());
    return std::string(rec.begin(), rec.end());
}

// Needs a Python on PATH; reported, not failed, without one.
static void testScriptRunner() {
    std::printf("== script runner ==\n");
    ScriptRunner runner;
    std::string error;
    CHECK(!runner.start({"apkspy-no-such-interpreter"}, error) && !error.empty(), "missing interpreter reported");
    const auto wait = [&] {
        for (int i = 0; i < 1000 && runner.running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    };
    if (!runner.start({"python", "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"}, error)) {
        std::printf("  (no python on PATH: skipped)\n");
        return;
    }
    wait();
    std::vector<std::string> lines = runner.takeOutput();
    CHECK(!runner.running() && runner.exitCode() == 3, "exit code reported");
    CHECK(std::find(lines.begin(), lines.end(), "out") != lines.end() && std::find(lines.begin(), lines.end(), "err") != lines.end(),
          "stdout and stderr collected");
    CHECK(runner.start({"python", "-c", "import time; print('started', flush=True); time.sleep(60)"}, error), "long script started");
    for (int i = 0; i < 500 && runner.takeOutput().empty(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(runner.running(), "still running");
    runner.stop();
    wait();
    CHECK(!runner.running(), "stop kills the script");

    // The Python API against a stub of the MCP endpoint's reply format is covered by the
    // app-level script; here: the files it needs land where the command expects them.
    const fs::path dir = fs::temp_directory_path() / "apkspy_script_test";
    fs::remove_all(dir);
    CHECK(scripting::writeSupport(dir.string(), "http://127.0.0.1:1/mcp", "t\"ok", error), "support files written");
    const fs::path script = dir / "probe.py";
    {
        std::ofstream f(script);
        f << "import apkspy, json\n"
             "print(json.load(open(apkspy.__file__.replace('apkspy.py', 'session.json')))['token'])\n"
             "print(callable(apkspy.some_tool))\n"
             "try:\n    apkspy.some_tool(class_='x')\nexcept apkspy.ApkSpyError as e:\n    print('error reported')\n";
    }
    CHECK(runner.start(scripting::command("python", dir.string(), script.string()), error), "module imported by a script");
    wait();
    lines = runner.takeOutput();
    CHECK(runner.exitCode() == 0 && lines.size() >= 3 && lines[0] == "t\"ok" && lines[1] == "True" && lines[2] == "error reported",
          "apkspy module: session, dynamic tools, errors");
    fs::remove_all(dir);
}

static void testTrafficProxy() {
    std::printf("== traffic proxy ==\n");
    CHECK(TrafficProxy::pathTemplate("/api/users/123/orders?page=2") == "/api/users/{id}/orders", "numeric id template");
    CHECK(TrafficProxy::pathTemplate("/v1/items/550e8400-e29b-41d4-a716-446655440000/details") == "/v1/items/{id}/details",
          "uuid template");
    CHECK(TrafficProxy::pathTemplate("/login") == "/login", "plain path kept");
    CHECK(TrafficProxy::parseSni((const uint8_t*)clientHello("api.example.com").data(), clientHello("api.example.com").size()) ==
              "api.example.com",
          "SNI from ClientHello");

    // gzip + chunked decoding.
    {
        const std::string plain = "{\"user\":\"alice\",\"token\":\"abc\"}";
        size_t outLen = 0;
        void* deflated = tdefl_compress_mem_to_heap(plain.data(), plain.size(), &outLen, 0);
        std::string gz = std::string("\x1f\x8b\x08\0\0\0\0\0\0\x03", 10) + std::string((const char*)deflated, outLen) +
                         std::string(8, '\0');
        mz_free(deflated);
        TrafficProxy::Message m;
        m.headers = {{"Content-Encoding", "gzip"}};
        m.body = gz;
        std::string note;
        CHECK(TrafficProxy::decodeBody(m, &note) == plain, "gzip body decoded");
        TrafficProxy::Message c;
        c.headers = {{"Transfer-Encoding", "chunked"}};
        c.body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        CHECK(TrafficProxy::decodeBody(c, nullptr) == "hello world", "chunked body decoded");
    }

    // Origin server: answers one request with a JSON body.
    Socket origin;
    std::string err;
    CHECK(origin.listenLoopback(0, err), "origin listens");
    const int originPort = origin.localPort();
    std::string seenByOrigin;
    std::thread originThread([&] {
        Socket c = origin.accept(5000);
        if (!c.valid()) return;
        std::string req;
        char buf[4096];
        while (req.find("hello") == std::string::npos && c.waitReadable(3000)) {
            const long n = c.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            req.append(buf, (size_t)n);
        }
        seenByOrigin = req;
        const std::string body = "{\"id\":123,\"ok\":true}";
        c.sendAll("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
                  "\r\n\r\n" + body);
    });
    TrafficProxy proxy;
    CHECK(proxy.start(0, err), ("proxy starts: " + err).c_str());
    {
        Socket client;
        client.connectLoopback(proxy.port(), 2000, err);
        client.sendAll("POST http://127.0.0.1:" + std::to_string(originPort) +
                       "/api/users/123?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Connection: keep-alive\r\n"
                       "Content-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
        const std::string resp = readAllFrom(client);
        CHECK(resp.find("200 OK") != std::string::npos && resp.find("\"ok\":true") != std::string::npos,
              "response relayed to the client");
    }
    originThread.join();
    CHECK(seenByOrigin.rfind("POST /api/users/123?x=1 HTTP/1.1", 0) == 0, "origin-form request line upstream");
    CHECK(seenByOrigin.find("Proxy-Connection") == std::string::npos, "proxy headers stripped");
    for (int i = 0; i < 100 && (proxy.flows().empty() || !proxy.flows().back().complete); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto flows = proxy.flows();
    CHECK(flows.size() == 1 && flows[0].method == "POST" && flows[0].status == 200 && flows[0].path == "/api/users/123?x=1",
          "flow recorded");
    TrafficProxy::Flow full;
    CHECK(!flows.empty() && proxy.flow(flows[0].id, full) && full.request.body == "hello" &&
              TrafficProxy::decodeBody(full.response, nullptr) == "{\"id\":123,\"ok\":true}",
          "request and response bodies captured");
    CHECK(TrafficProxy::curl(full).find("--data-binary 'hello'") != std::string::npos, "copy as cURL");
    CHECK(proxy.searchFlows("\"OK\":TRUE").size() == 1 && proxy.searchFlows("content-type: text/plain").size() == 1 &&
              proxy.searchFlows("users/123").size() == 1 && proxy.searchFlows("not-in-any-flow").empty() &&
              proxy.searchFlows("hello", flows[0].id).empty(),
          "search in bodies, headers and URLs (case-insensitive, after an id)");
    auto eps = proxy.endpoints();
    CHECK(eps.size() == 1 && eps[0].pathTemplate == "/api/users/{id}" && eps[0].count == 1, "endpoint map");

    // CONNECT tunnel against an echo server, with a TLS ClientHello.
    Socket echo;
    echo.listenLoopback(0, err);
    const int echoPort = echo.localPort();
    std::thread echoThread([&] {
        Socket c = echo.accept(5000);
        if (!c.valid()) return;
        char buf[4096];
        while (c.waitReadable(2000)) {
            const long n = c.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            c.sendAll(buf, (size_t)n);
        }
    });
    {
        Socket client;
        client.connectLoopback(proxy.port(), 2000, err);
        client.sendAll("CONNECT 127.0.0.1:" + std::to_string(echoPort) + " HTTP/1.1\r\nHost: x\r\n\r\n");
        char buf[256];
        long n = client.waitReadable(3000) ? client.recvSome(buf, sizeof buf) : 0;
        CHECK(n > 0 && std::string(buf, (size_t)n).find("200 Connection Established") != std::string::npos,
              "CONNECT established");
        const std::string hello = clientHello("secure.example.org");
        client.sendAll(hello);
        std::string echoed;
        while (echoed.size() < hello.size() && client.waitReadable(3000)) {
            n = client.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            echoed.append(buf, (size_t)n);
        }
        CHECK(echoed == hello, "tunnel relays bytes untouched");
    }
    echoThread.join();
    for (int i = 0; i < 200 && (proxy.flows().size() < 2 || !proxy.flows().back().complete); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    flows = proxy.flows();
    CHECK(flows.size() == 2 && flows[1].tunnel && flows[1].sni == "secure.example.org" && flows[1].bytesUp >= 40,
          "tunnel recorded with SNI and byte counts");
    proxy.stop();
    CHECK(!proxy.running(), "proxy stops");
}

static void testCodec() {
    using codec::Op;
    const auto run = [](Op op, std::string_view in, std::string_view arg = {}) { return codec::apply(op, in, arg).out; };
    // Base64 / Base32 / hex, both ways (RFC 4648 vectors).
    CHECK(run(Op::Base64Encode, "foobar") == "Zm9vYmFy" && run(Op::Base64Encode, "fo") == "Zm8=" && run(Op::Base64UrlEncode, "\xfb\xff") == "-_8",
          "base64 encode");
    CHECK(run(Op::Base64Decode, "Zm9v\nYmE=\n") == "fooba" && run(Op::Base64Decode, "Zm8") == "fo" && run(Op::Base64Decode, "-_8") == "\xfb\xff",
          "base64 decode: whitespace, no padding, url alphabet");
    CHECK(!codec::apply(Op::Base64Decode, "Zm9v!").ok, "base64 rejects other characters");
    CHECK(run(Op::Base32Encode, "foobar") == "MZXW6YTBOI======" && run(Op::Base32Decode, "MZXW6YTBOI======") == "foobar", "base32");
    CHECK(run(Op::HexDecode, "48 65 0x6c \\x6c 6f") == "Hello" && run(Op::HexEncode, "Hi") == "4869" && !codec::apply(Op::HexDecode, "486").ok,
          "hex");
    CHECK(run(Op::UrlDecode, "a%20b+c%2F") == "a b c/" && run(Op::UrlEncode, "a b/") == "a%20b%2F", "url");
    CHECK(run(Op::HtmlDecode, "&lt;a&gt; &amp; &#65;&#x42;") == "<a> & AB", "html entities");
    CHECK(run(Op::Unescape, "a\\nb\\x41\\u00e9\\ud83d\\ude00") == "a\nbA\xc3\xa9\xf0\x9f\x98\x80", "unescape incl. surrogate pairs");
    CHECK(run(Op::Escape, "a\n\"\xc3\xa9") == "a\\n\\\"\\u00e9", "escape");
    CHECK(run(Op::Xor, run(Op::Xor, "secret", "k3y"), "k3y") == "secret" && run(Op::Xor, "A", "0x01") == "@", "xor");
    CHECK(run(Op::Rot13, "Hello") == "Uryyb", "rot13");
    // Hashes ("abc" test vectors).
    CHECK(run(Op::Md5, "abc") == "900150983cd24fb0d6963f7d28e17f72" && run(Op::Md5, "") == "d41d8cd98f00b204e9800998ecf8427e", "md5");
    CHECK(run(Op::Sha1, "abc") == "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1");
    CHECK(run(Op::Sha256, "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256");
    // Compression round trips.
    const std::string text(500, 'x');
    CHECK(run(Op::Inflate, run(Op::ZlibCompress, text)) == text && run(Op::Inflate, run(Op::GzipCompress, text)) == text, "zlib and gzip");
    // Text encodings.
    std::string bytes, back, error;
    CHECK(codec::encodeText("h\xc3\xa9\xf0\x9f\x98\x80", "UTF-16LE", bytes, error) && bytes == std::string("h\0\xe9\0\x3d\xd8\x00\xde", 8) &&
              codec::decodeText(bytes, "UTF-16LE", back, error) && back == "h\xc3\xa9\xf0\x9f\x98\x80",
          "UTF-16LE with a surrogate pair");
    CHECK(codec::encodeText("hi", "UTF-16BE", bytes, error) && bytes == std::string("\0h\0i", 4), "UTF-16BE");
    CHECK(codec::encodeText("A", "UTF-32LE", bytes, error) && bytes == std::string("A\0\0\0", 4) && codec::decodeText(bytes, "UTF-32LE", back, error) &&
              back == "A",
          "UTF-32");
    CHECK(codec::decodeText("\xe9\x80", "Windows-1252", back, error) && back == "\xc3\xa9\xe2\x82\xac" &&
              codec::encodeText("\xe2\x82\xac", "Windows-1252", bytes, error) && bytes == "\x80",
          "Windows-1252 (euro sign)");
    CHECK(codec::decodeText("\xe9", "Latin-1", back, error) && back == "\xc3\xa9" && !codec::encodeText("\xe2\x82\xac", "Latin-1", bytes, error),
          "Latin-1, and characters it cannot hold");
    CHECK(!codec::decodeText("\xe9", "ASCII", back, error), "ASCII refuses 8-bit bytes");
    CHECK(codec::encodeText(std::string("a\0", 2), "Modified UTF-8 (Java / DEX)", bytes, error) && bytes == "a\xc0\x80" &&
              codec::decodeText("a\xc0\x80\xed\xa0\xbd\xed\xb8\x80", "Modified UTF-8 (Java / DEX)", back, error) &&
              back == std::string("a\0\xf0\x9f\x98\x80", 6),
          "modified UTF-8: NUL and surrogate pairs");
    // Smart decode: layers peel off, plain text is left alone.
    const std::string layered = run(Op::UrlEncode, run(Op::Base64Encode, run(Op::GzipCompress, "{\"token\":\"abc\"}")));
    std::vector<Op> chain = codec::smartDecode(layered);
    CHECK(chain.size() == 3 && chain[0] == Op::UrlDecode && chain[1] == Op::Base64Decode && chain[2] == Op::Inflate,
          "smart decode: URL > Base64 > gzip");
    CHECK(codec::smartDecode("hello world").empty() && codec::smartDecode("username").empty(), "smart decode leaves words alone");
    std::string decoded, steps;
    CHECK(codec::decodePreview("aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20v", decoded, steps) && decoded == "https://api.example.com/",
          "decode preview of a Base64 URL");
    CHECK(!codec::decodePreview("Hello, world", decoded, steps), "no preview for plain text");
    CHECK(codec::smartDecode(std::string("h\0i\0!\0", 6)).size() == 1, "UTF-16LE bytes are recognised");
    const std::string jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig";
    CHECK(run(Op::JwtDecode, jwt) == "{\"alg\":\"HS256\"}\n{\"sub\":\"123\"}", "jwt");
    // String literals in code.
    const auto lits = codec::stringLiterals("s = \"a\\\"b\" + 'x' + \"c\"; // \"no\"");
    CHECK(lits.size() == 2 && lits[0].text == "a\"b" && lits[1].text == "c" && codec::literalAt(lits, lits[1].begin + 1) == &lits[1],
          "string literals: escapes, char literals and comments");
}

static void testHttpClient() {
    // A request as typed in the Repeater: LF lines, a body, a stale Content-Length.
    const std::string prepared = httpclient::prepare("POST /api HTTP/1.1\nHost: h:8080\nContent-Length: 99\n\n{\"a\":1}", true);
    CHECK(prepared == "POST /api HTTP/1.1\r\nHost: h:8080\r\nContent-Length: 7\r\n\r\n{\"a\":1}", ("prepare: " + prepared).c_str());
    CHECK(httpclient::prepare("GET / HTTP/1.1\nHost: x\n", true) == "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "prepare: no body, no length added");
    CHECK(httpclient::prepare("PUT /p HTTP/1.1\r\nHost: x\r\n\r\nab\ncd", true) == "PUT /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nab\ncd",
          "prepare: the body is kept byte for byte");
    httpclient::Target t;
    CHECK(httpclient::targetFromRequest("GET / HTTP/1.1\nHost: api.test:8443\n\n", t) && t.host == "api.test" && t.port == 8443,
          "target from the Host header");
    TrafficProxy::Flow f;
    f.method = "GET";
    f.host = "example.org";
    f.port = 80;
    f.path = "/a?b=1";
    f.request.startLine = "GET http://example.org/a?b=1 HTTP/1.1";
    f.request.headers = {{"Host", "example.org"}, {"Proxy-Connection", "keep-alive"}, {"Accept", "*/*"}};
    CHECK(httpclient::editableRequest(f) == "GET /a?b=1 HTTP/1.1\nHost: example.org\nAccept: */*\n\n",
          ("editable request: " + httpclient::editableRequest(f)).c_str());

    // Real sends to a local server: Content-Length, chunked and close-delimited bodies.
    const char* answers[] = {
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\nmissing",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    };
    for (int k = 0; k < 4; ++k) {
        Socket server;
        std::string err;
        if (!Socket::initNetworking() || !server.listenLoopback(0, err)) {
            CHECK(false, ("listen: " + err).c_str());
            return;
        }
        const int port = server.localPort();
        std::string received;
        std::thread peer([&] {
            Socket c = server.accept(5000);
            if (!c.valid()) return;
            char buf[4096];
            while (received.find("\r\n\r\n") == std::string::npos) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0) return;
                received.append(buf, static_cast<size_t>(n));
            }
            const size_t cl = received.find("Content-Length: ");
            if (cl != std::string::npos) {
                const size_t want = received.find("\r\n\r\n") + 4 + static_cast<size_t>(std::atoi(received.c_str() + cl + 16));
                while (received.size() < want) {
                    const long n = c.recvSome(buf, sizeof buf);
                    if (n <= 0) break;
                    received.append(buf, static_cast<size_t>(n));
                }
            }
            c.sendAll(std::string(answers[k]));
            if (k == 2) c.close();  // HTTP/1.0 without a length: the body ends with the connection
            else std::this_thread::sleep_for(std::chrono::milliseconds(300));
        });
        httpclient::Options o;
        o.timeoutMs = 4000;
        const auto r = httpclient::send({"127.0.0.1", port, false}, "POST /x HTTP/1.1\nHost: 127.0.0.1\n\nbody!", o);
        peer.join();
        CHECK(received.find("POST /x HTTP/1.1\r\n") == 0 && received.find("Content-Length: 5\r\n") != std::string::npos &&
                  received.size() >= 5 && received.compare(received.size() - 5, 5, "body!") == 0,
              ("the server got the request as typed (" + std::to_string(k) + ")").c_str());
        std::string note;
        const std::string body = TrafficProxy::decodeBody(r.response, &note);
        if (k == 0) CHECK(r.ok && r.status == 200 && body == "hello", ("content-length response: " + r.error).c_str());
        if (k == 1) CHECK(r.ok && r.status == 201 && body == "abcde", ("chunked response: " + r.error + " " + body).c_str());
        if (k == 2) CHECK(r.ok && r.status == 404 && body == "missing", ("close-delimited response: " + r.error).c_str());
        if (k == 3) CHECK(r.ok && r.status == 204 && body.empty(), ("interim 100 skipped: " + r.error).c_str());
    }
    httpclient::Options quick;
    quick.timeoutMs = 2000;
    const auto refused = httpclient::send({"127.0.0.1", 1, false}, "GET / HTTP/1.1\nHost: x\n\n", quick);
    CHECK(!refused.ok && refused.error.find("could not connect") != std::string::npos, ("refused: " + refused.error).c_str());
    CHECK(!httpclient::send({"", 80, false}, "GET / HTTP/1.1\n\n", quick).ok, "no host");
}

static void testIntercept() {
    std::printf("== intercept ==\n");
    // Origin: records the request it gets, answers with a short JSON body.
    const auto runOrigin = [](Socket& origin, std::string& seen) {
        return std::thread([&origin, &seen] {
            Socket c = origin.accept(5000);
            if (!c.valid()) return;
            char buf[4096];
            while (seen.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                seen.append(buf, static_cast<size_t>(n));
            }
            const size_t cl = seen.find("Content-Length: ");
            if (cl != std::string::npos) {
                const size_t want = seen.find("\r\n\r\n") + 4 + static_cast<size_t>(std::atoi(seen.c_str() + cl + 16));
                while (seen.size() < want && c.waitReadable(3000)) {
                    const long n = c.recvSome(buf, sizeof buf);
                    if (n <= 0) break;
                    seen.append(buf, static_cast<size_t>(n));
                }
            }
            c.sendAll(std::string("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        });
    };
    const auto waitHeld = [](TrafficProxy& p, bool response) {
        for (int i = 0; i < 300; ++i) {
            for (const auto& h : p.held())
                if (h.response == response) return h;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return TrafficProxy::Held{};
    };
    std::string err;
    TrafficProxy proxy;
    CHECK(proxy.start(0, err), ("proxy starts: " + err).c_str());

    // 1. A held request, edited (path, header, body), then forwarded.
    {
        Socket origin;
        origin.listenLoopback(0, err);
        std::string seen;
        std::thread o = runOrigin(origin, seen);
        proxy.setIntercept(true, false, "");
        std::string resp;
        std::thread client([&] {
            Socket c;
            c.connectLoopback(proxy.port(), 2000, err);
            c.sendAll("POST http://127.0.0.1:" + std::to_string(origin.localPort()) +
                      "/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nuser");
            resp = readAllFrom(c);
        });
        const TrafficProxy::Held h = waitHeld(proxy, false);
        CHECK(h.id != 0 && h.raw.rfind("POST /login HTTP/1.1\r\n", 0) == 0 && h.raw.find("\r\n\r\nuser") != std::string::npos,
              "the request waits at the intercept");
        CHECK(proxy.heldCount() == 1, "one message waiting");
        proxy.forward(h.id, "POST /login?edited=1 HTTP/1.1\nHost: 127.0.0.1\nX-Test: yes\nContent-Length: 4\n\nadmin");
        client.join();
        o.join();
        CHECK(seen.rfind("POST /login?edited=1 HTTP/1.1\r\n", 0) == 0 && seen.find("X-Test: yes\r\n") != std::string::npos &&
                  seen.find("Content-Length: 5\r\n") != std::string::npos && seen.find("Connection: close\r\n") != std::string::npos &&
                  seen.size() >= 5 && seen.compare(seen.size() - 5, 5, "admin") == 0,
              ("the server got the edited request: " + seen).c_str());
        CHECK(resp.find("{\"ok\":true}") != std::string::npos, "the app got the response");
        for (int i = 0; i < 100 && !proxy.flows().back().complete; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        const auto flows = proxy.flows();
        CHECK(!flows.empty() && flows.back().edited && flows.back().path == "/login?edited=1", "the flow is marked edited");
    }
    // 2. A held response, edited, then forwarded: the app gets the new body with a matching length.
    {
        Socket origin;
        origin.listenLoopback(0, err);
        std::string seen;
        std::thread o = runOrigin(origin, seen);
        proxy.setIntercept(false, true, "127.0.0.1");
        std::string resp;
        std::thread client([&] {
            Socket c;
            c.connectLoopback(proxy.port(), 2000, err);
            c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.localPort()) + "/me HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            resp = readAllFrom(c);
        });
        const TrafficProxy::Held h = waitHeld(proxy, true);
        CHECK(h.id != 0 && h.raw.rfind("HTTP/1.1 200 OK\r\n", 0) == 0 && h.raw.find("{\"ok\":true}") != std::string::npos,
              "the response waits at the intercept");
        proxy.forward(h.id, "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 11\n\n{\"ok\":true,\"admin\":true}");
        client.join();
        o.join();
        CHECK(resp.find("Content-Length: 24\r\n") != std::string::npos && resp.find("{\"ok\":true,\"admin\":true}") != std::string::npos,
              ("the app got the edited response: " + resp).c_str());
    }
    // 3. Dropped request: the server never sees it, the app's connection closes.
    {
        proxy.setIntercept(true, false, "");
        std::string resp = "x";
        std::thread client([&] {
            Socket c;
            c.connectLoopback(proxy.port(), 2000, err);
            c.sendAll(std::string("GET http://127.0.0.1:1/never HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
            resp = readAllFrom(c);
        });
        const TrafficProxy::Held h = waitHeld(proxy, false);
        proxy.drop(h.id);
        client.join();
        CHECK(h.id != 0 && resp.empty(), "a dropped request gets no answer");
        for (int i = 0; i < 100 && !proxy.flows().back().complete; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        TrafficProxy::Flow f;
        CHECK(proxy.flow(proxy.flows().back().id, f) && f.error == "request dropped at the intercept", "the flow says it was dropped");
    }
    // 4. Turning intercept off releases what waits, unchanged; a filter that does not match holds nothing.
    {
        Socket origin;
        origin.listenLoopback(0, err);
        std::string seen;
        std::thread o = runOrigin(origin, seen);
        proxy.setIntercept(true, false, "");
        std::string resp;
        std::thread client([&] {
            Socket c;
            c.connectLoopback(proxy.port(), 2000, err);
            c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.localPort()) + "/a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            resp = readAllFrom(c);
        });
        const TrafficProxy::Held h = waitHeld(proxy, false);
        proxy.setIntercept(false, false, "");
        client.join();
        o.join();
        CHECK(h.id != 0 && seen.rfind("GET /a HTTP/1.1\r\n", 0) == 0 && resp.find("200 OK") != std::string::npos,
              "intercept off: the held request goes on unchanged");
        proxy.setIntercept(true, true, "only-this-host.test");
        Socket origin2;
        origin2.listenLoopback(0, err);
        std::string seen2;
        std::thread o2 = runOrigin(origin2, seen2);
        Socket c;
        c.connectLoopback(proxy.port(), 2000, err);
        c.sendAll("GET http://127.0.0.1:" + std::to_string(origin2.localPort()) + "/b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        const std::string r2 = readAllFrom(c);
        o2.join();
        CHECK(r2.find("200 OK") != std::string::npos && proxy.heldCount() == 0, "the URL filter lets other traffic through");
    }
    // 5. Stopping the proxy releases a held request.
    {
        proxy.setIntercept(true, false, "");
        std::thread client([&] {
            Socket c;
            c.connectLoopback(proxy.port(), 2000, err);
            c.sendAll(std::string("GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
            readAllFrom(c);
        });
        waitHeld(proxy, false);
        proxy.stop();  // must not hang
        client.join();
        CHECK(proxy.heldCount() == 0, "stop releases held messages");
    }
}

static void testMatchReplace() {
    std::printf("== match & replace ==\n");
    using matchreplace::Rule;
    using matchreplace::Where;
    const std::string request = "GET /api/v1/me?debug=0 HTTP/1.1\r\nHost: api.test\r\nUser-Agent: okhttp/4.9\r\nIf-None-Match: \"abc\"\r\n\r\n";
    matchreplace::RuleSet rules({
        {true, Where::RequestLine, "debug=0", "debug=1", false, ""},
        {true, Where::RequestHeader, "^User-Agent:.*$", "User-Agent: ApkSpy", true, ""},
        {true, Where::RequestHeader, "^If-None-Match:.*$", "", true, ""},
        {true, Where::RequestHeader, "", "X-Debug: 1", false, ""},
        {false, Where::RequestHeader, "Host", "Nope", false, "disabled"},
        {true, Where::ResponseBody, "false", "true", false, "a response rule leaves requests alone"},
    });
    std::string raw = request;
    std::vector<int> hits;
    const int n = rules.apply(false, raw, &hits);
    CHECK(n == 4 && raw == "GET /api/v1/me?debug=1 HTTP/1.1\r\nHost: api.test\r\nUser-Agent: ApkSpy\r\nX-Debug: 1\r\n\r\n",
          ("request rules: " + raw).c_str());
    CHECK(hits.size() == 6 && hits[0] == 1 && hits[1] == 1 && hits[2] == 1 && hits[3] == 1 && hits[4] == 0 && hits[5] == 0, "hit counts");

    // Body rules see through chunking and gzip, and fix the framing headers.
    const std::string json = "{\"isPremium\":false,\"name\":\"x\"}";
    const std::string gz = codec::apply(codec::Op::GzipCompress, json).out;
    std::string chunked;
    char size[16];
    std::snprintf(size, sizeof size, "%zx", gz.size());
    chunked = std::string(size) + "\r\n" + gz + "\r\n0\r\n\r\n";
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked;
    matchreplace::RuleSet body({{true, Where::ResponseBody, "\"isPremium\":false", "\"isPremium\":true", false, ""},
                                {true, Where::ResponseHeader, "", "Access-Control-Allow-Origin: *", false, ""}});
    CHECK(body.apply(true, resp) == 2, "response rules applied");
    const std::string expectBody = "{\"isPremium\":true,\"name\":\"x\"}";
    CHECK(resp == "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: " +
                      std::to_string(expectBody.size()) + "\r\n\r\n" + expectBody,
          ("decoded, replaced, reframed: " + resp).c_str());
    // A body rule that does not match keeps the original bytes (and framing).
    std::string untouched = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + std::to_string(gz.size()) + "\r\n\r\n" + gz;
    const std::string before = untouched;
    CHECK(matchreplace::RuleSet({{true, Where::ResponseBody, "nothing-like-this", "x", false, ""}}).apply(true, untouched) == 0 &&
              untouched == before,
          "no match, no change");
    // Regex groups, bad regexes, saving.
    std::string line = "GET /users/42/profile HTTP/1.1\r\nHost: h\r\n\r\n";
    CHECK(matchreplace::RuleSet({{true, Where::RequestLine, "/users/(\\d+)/", "/users/1/", true, ""}}).apply(false, line) == 1 &&
              line.rfind("GET /users/1/profile", 0) == 0,
          "regex replacement");
    std::string groups = "GET /a?x=1&y=2 HTTP/1.1\r\n\r\n";
    matchreplace::RuleSet({{true, Where::RequestLine, "x=(\\d)&y=(\\d)", "x=$2&y=$1", true, ""}}).apply(false, groups);
    CHECK(groups.rfind("GET /a?x=2&y=1", 0) == 0, "regex groups");
    matchreplace::RuleSet bad({{true, Where::RequestLine, "([", "x", true, ""}});
    CHECK(!bad.error(0).empty() && !bad.appliesTo(false), "an invalid regex is reported and skipped");
    const auto back = matchreplace::fromJson(matchreplace::toJson(matchreplace::presets()));
    CHECK(back.size() == matchreplace::presets().size() && back[0].match == "^User-Agent:.*$" && back[0].regex && !back[0].enabled &&
              back.back().where == Where::ResponseBody,
          "rules survive saving");

    // Through the proxy: a request rule rewrites what the server sees, a response rule what the app gets.
    Socket origin;
    std::string err;
    origin.listenLoopback(0, err);
    std::string seen;
    std::thread o([&] {
        Socket c = origin.accept(5000);
        if (!c.valid()) return;
        char buf[4096];
        while (seen.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
            const long k = c.recvSome(buf, sizeof buf);
            if (k <= 0) break;
            seen.append(buf, static_cast<size_t>(k));
        }
        c.sendAll(std::string("HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"isPremium\":false"));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
    TrafficProxy proxy;
    proxy.start(0, err);
    proxy.setRules(matchreplace::RuleSet({{true, Where::RequestHeader, "", "X-Debug: 1", false, ""},
                                          {true, Where::ResponseBody, "false", "true", false, ""}}));
    Socket c;
    c.connectLoopback(proxy.port(), 2000, err);
    c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.localPort()) + "/me HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    const std::string got = readAllFrom(c);
    o.join();
    CHECK(seen.find("X-Debug: 1\r\n") != std::string::npos, ("the server got the added header: " + seen).c_str());
    CHECK(got.find("Content-Length: 17\r\n") != std::string::npos && got.find("{\"isPremium\":true") != std::string::npos,
          ("the app got the replaced body: " + got).c_str());
    for (int i = 0; i < 100 && !proxy.flows().back().complete; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(proxy.flows().back().edited && proxy.ruleHits().size() == 2 && proxy.ruleHits()[0] == 1 && proxy.ruleHits()[1] == 1,
          "the flow is marked edited and the rules counted");
    proxy.stop();
}

static void testTextDiff() {
    std::printf("== text diff ==\n");
    using textdiff::Kind;
    const std::string a = "HTTP/1.1 200 OK\nDate: Mon\nContent-Length: 10\n\n{\"user\":\"alice\",\"admin\":false}\nend\n";
    const std::string b = "HTTP/1.1 200 OK\nDate: Tue\nContent-Length: 10\nX-New: 1\n\n{\"user\":\"alice\",\"admin\":true}\nend\n";
    const auto r = textdiff::diff(a, b);
    CHECK(!r.identical() && r.changed == 2 && r.added == 1 && r.removed == 0 && !r.approximate,
          ("counts: changed " + std::to_string(r.changed) + " added " + std::to_string(r.added)).c_str());
    int same = 0;
    for (const auto& row : r.rows) same += row.kind == Kind::Same;
    CHECK(same == 4 && r.rows.size() == 7, "rows line up side by side");
    const textdiff::Row* date = nullptr;
    for (const auto& row : r.rows)
        if (row.kind == Kind::Changed && r.a[static_cast<size_t>(row.left)].rfind("Date", 0) == 0) date = &row;
    CHECK(date && date->leftSpans.size() == 1 && r.a[static_cast<size_t>(date->left)].substr(date->leftSpans[0].begin, 3) == "Mon" &&
              date->rightSpans.size() == 1 && r.b[static_cast<size_t>(date->right)].substr(date->rightSpans[0].begin, 3) == "Tue",
          "the changed word is highlighted, not the line");
    CHECK(textdiff::diff("x\ny\n", "x\ny\n").identical(), "identical texts");
    const auto onlyAdded = textdiff::diff("", "a\nb");
    CHECK(onlyAdded.added == 2 && onlyAdded.rows.size() == 2 && onlyAdded.rows[0].kind == Kind::Added, "everything added");
    // Moved block: the classic Myers case.
    const auto moved = textdiff::diff("a\nb\nc\nd\n", "c\nd\na\nb\n");
    int unchanged = 0;
    for (const auto& row : moved.rows) unchanged += row.kind == Kind::Same;
    CHECK(unchanged == 2 && moved.changed + moved.removed + moved.added >= 2, "a moved block keeps the longest common run");
    // Too many differences: a coarse answer instead of an endless one.
    std::string big1, big2;
    for (int i = 0; i < 3000; ++i) big1 += "line " + std::to_string(i) + "\n", big2 += "other " + std::to_string(i) + "\n";
    const auto coarse = textdiff::diff(big1, big2, 200);
    CHECK(coarse.approximate && coarse.removed == 3000 && coarse.added == 3000, "coarse diff past the edit limit");
}

static void testLineSplitting() {
    std::printf("== process line splitting (CR progress output) ==\n");
    const fs::path f = fs::temp_directory_path() / "apkspy_cr_test.txt";
    {
        std::ofstream(f, std::ios::binary) << "p1\rp2   \rp3\r\nline\nlast";
    }
#ifdef _WIN32
    ChildProcess c = ChildProcess::spawn({"cmd.exe", "/c", "type", f.string()});
#else
    ChildProcess c = ChildProcess::spawn({"cat", f.string()});
#endif
    std::vector<std::string> lines;
    c.readAll([&](std::string l) { lines.push_back(std::move(l)); });
    c.waitForExit();
    fs::remove(f);
    CHECK(lines.size() == 5 && lines[0] == "p1" && lines[1] == "p2" && lines[2] == "p3" && lines[3] == "line" &&
              lines[4] == "last",
          "CR, CRLF and LF all end lines; progress padding trimmed");
}

static void testJdwp() {
    std::printf("== jdwp client ==\n");
    Socket listener;
    std::string err;
    if (!listener.listenLoopback(0, err)) {
        CHECK(false, "listen for fake JDWP");
        return;
    }
    const int port = listener.localPort();
    std::vector<uint8_t> lastEventRequest;  // payload of the last EventRequest.Set (checked after join)
    std::thread peer([&] {
        Socket c = listener.accept(5000);
        if (!c.valid()) return;
        char hs[14];
        if (!c.recvAll(hs, 14)) return;
        c.sendAll("JDWP-Handshake", 14);
        for (;;) {
            uint8_t h[11];
            if (!c.recvAll(h, 11)) return;
            const uint32_t len = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
            std::vector<uint8_t> payload(len - 11);
            if (!payload.empty() && !c.recvAll(payload.data(), payload.size())) return;
            std::vector<uint8_t> r;
            const auto u32 = [&](uint32_t v) {
                for (int i = 3; i >= 0; --i) r.push_back((uint8_t)(v >> (8 * i)));
            };
            const auto str = [&](const std::string& s) {
                u32((uint32_t)s.size());
                r.insert(r.end(), s.begin(), s.end());
            };
            const uint8_t set = h[9], cmd = h[10];
            if (set == 1 && cmd == 7) {
                for (int i = 0; i < 5; ++i) u32(8);
            } else if (set == 1 && cmd == 1) {
                str("Fake VM 1.0"), u32(1), u32(8), str("1.8"), str("FakeVM");
            } else if (set == 1 && cmd == 4) {
                u32(2);
                for (uint64_t id : {1ull, 2ull}) u32(0), u32((uint32_t)id);
            } else if (set == 11 && cmd == 1) {
                const uint8_t id = payload.empty() ? 0 : payload.back();
                str(id == 1 ? "main" : "worker");
            } else if (set == 2 && cmd == 4) {  // ReferenceType.Fields
                u32(2);
                u32(0), u32(11), str("count"), str("I"), u32(0);
                u32(0), u32(12), str("CONST"), str("I"), u32(8);
            } else if (set == 9 && cmd == 2) {  // ObjectReference.GetValues
                const uint32_t n = payload.size() >= 12 ? (uint32_t)payload[8] << 24 | payload[9] << 16 | payload[10] << 8 | payload[11] : 0;
                u32(n);
                for (uint32_t i = 0; i < n; ++i) r.push_back('I'), u32(42 + i);
            } else if (set == 13 && cmd == 2) {  // ArrayReference.GetValues: primitive region, untagged
                r.push_back('I'), u32(3), u32(7), u32(8), u32(9);
            } else if (set == 15 && cmd == 1) {  // EventRequest.Set
                lastEventRequest = payload;
                u32(77);
            }
            std::vector<uint8_t> pkt;
            const uint32_t total = (uint32_t)(11 + r.size());
            for (int i = 3; i >= 0; --i) pkt.push_back((uint8_t)(total >> (8 * i)));
            pkt.insert(pkt.end(), h + 4, h + 8);  // same id
            pkt.push_back(0x80);
            pkt.push_back(0), pkt.push_back(0);
            pkt.insert(pkt.end(), r.begin(), r.end());
            if (!c.sendAll(pkt.data(), pkt.size())) return;
        }
    });
    JdwpClient client;
    CHECK(client.connect(port, err), ("jdwp connect: " + err).c_str());
    std::string desc, vm;
    CHECK(client.version(desc, vm, err) && vm == "FakeVM" && desc == "Fake VM 1.0", "VirtualMachine.Version");
    std::vector<JdwpClient::Id> threads;
    CHECK(client.allThreads(threads, err) && threads.size() == 2 && threads[1] == 2, "AllThreads");
    std::string name;
    CHECK(client.threadName(1, name, err) && name == "main", "ThreadReference.Name");
    std::vector<JdwpClient::FieldInfo> fields;
    CHECK(client.fields(5, fields, err) && fields.size() == 2 && fields[0].name == "count" && (fields[1].modBits & 8),
          "ReferenceType.Fields");
    std::vector<JdwpClient::Value> values;
    CHECK(client.objectValues(9, {11}, values, err) && values.size() == 1 && values[0].text == "42",
          "ObjectReference.GetValues");
    CHECK(client.arrayValues(9, 0, 3, values, err) && values.size() == 3 && values[2].text == "9" && values[0].tag == 'I',
          "ArrayReference.GetValues (untagged primitives)");
    int32_t request = 0;
    CHECK(client.setExceptionBreak(0, false, true, request, err) && request == 77, "exception request id");
    client.disconnect();
    peer.join();
    // kind EXCEPTION, suspend all, 1 modifier: ExceptionOnly(refType 0, caught=false, uncaught=true)
    CHECK(lastEventRequest.size() == 6 + 1 + 8 + 2 && lastEventRequest[0] == 4 && lastEventRequest[6] == 8 &&
              lastEventRequest[15] == 0 && lastEventRequest[16] == 1,
          "exception request encoding");
    CHECK(!client.connected(), "disconnect");
}

// End to end: a real Workspace with a synthetic APK, driven through MCP.
static void testMcpToolsEndToEnd() {
    std::printf("== mcp tools end to end ==\n");
    const fs::path dir = fs::temp_directory_path() / "apkspy_platform_test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const fs::path apkPath = dir / "sample.apk";
    CHECK(writeApk(apkPath, {{"classes.dex", buildDex()},
                             {"lib/arm64-v8a/libfoo.so", buildElf()},
                             {"lib/arm64-v8a/libnat.so", buildArm64Elf()},
                             {"res/raw/config.json", std::vector<uint8_t>({'{', '"', 'k', '"', ':', '1', '}'})}}),
          "write synthetic apk");
    Workspace ws;
    ws.setJadxPath("");  // no jadx in this test
    CHECK(ws.addApk(apkPath.string(), "sample"), "add apk");
    McpDispatcher d;
    McpServer server(d, McpServer::Info{});
    McpToolEnv env;
    env.workspace = &ws;
    registerApkSpyTools(server, env);
    CHECK(server.tools().size() >= 20, "tool set registered");

    Json apks = callTool(server, d, &ws, "list_apks", Json::object());
    CHECK(structured(apks).get("apks").size() == 1, "list_apks");
    Json notReady = callTool(server, d, &ws, "list_classes", Json::object());
    CHECK(isError(notReady) && text(notReady).find("run_analysis") != std::string::npos, "analysis-required error");
    Json run = callTool(server, d, &ws, "run_analysis", Json::obj({{"wait", true}}));
    CHECK(structured(run).get("state").asString() == "ready", ("run_analysis: " + text(run)).c_str());
    Json classes = callTool(server, d, &ws, "list_classes", Json::obj({{"filter", "foo"}}));
    CHECK(structured(classes).get("classes").size() == 1 &&
              structured(classes).get("classes")[0].get("class").asString() == "Foo",
          "list_classes");
    Json cls = callTool(server, d, &ws, "get_class", Json::obj({{"class", "Foo"}, {"smali", true}}));
    CHECK(structured(cls).get("methods").size() == 2 && structured(cls).get("smali").asString().find(".method") != std::string::npos,
          "get_class");
    Json method = callTool(server, d, &ws, "get_method", Json::obj({{"method", "LFoo;->bar()V"}}));
    const Json& m0 = structured(method).get("methods")[0];
    CHECK(m0.get("smali").asString().find("invoke-static") != std::string::npos && m0.get("callees").size() == 1 &&
              m0.get("constant_arguments").size() == 1,
          "get_method");
    Json dec = callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}, {"with_pcs", true}}));
    const Json& dm = structured(dec).get("methods")[0];
    const std::string decCode = dm.get("code").asString();
    CHECK(decCode.find("public static void bar() {") != std::string::npos &&
              decCode.find("v0 = \"https://api.example.com/v1/login\";") != std::string::npos &&
              decCode.find("baz(v0);") != std::string::npos &&
              decCode.find("return;") == std::string::npos &&  // a void method's final return is implied
              decCode.find("if (") == std::string::npos,       // the branch only guards dead code
          ("decompile_method: " + decCode).c_str());
    bool callAtPc2 = false;
    for (size_t i = 0; i < dm.get("lines").size(); ++i) {
        const Json& l = dm.get("lines")[i];
        if (l.get("text").asString().find("baz(v0)") != std::string::npos)
            callAtPc2 = l.get("pcs").size() == 1 && l.get("pcs")[0].asInt() == 2;
    }
    CHECK(callAtPc2, "decompile_method maps lines to pcs");
    // Any other name: renamed in every function of the APK.
    Json sym = callTool(server, d, &ws, "rename_symbol", Json::obj({{"symbol", "baz"}, {"name", "sendLogin"}}));
    CHECK(!isError(sym) && structured(sym).get("scope").asString() == "apk", ("rename_symbol: " + text(sym)).c_str());
    CHECK(structured(callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}}))).get("methods")[0]
                  .get("code").asString().find("sendLogin(v0);") != std::string::npos,
          "a renamed method shows in its callers");
    CHECK(isError(callTool(server, d, &ws, "rename_symbol", Json::obj({{"symbol", "int"}, {"name", "x"}}))), "keywords are not renamed");
    CHECK(isError(callTool(server, d, &ws, "rename_symbol", Json::obj({{"symbol", "v0"}, {"name", "x"}}))),
          "variables go through rename_variable");
    CHECK(structured(callTool(server, d, &ws, "list_annotations", Json::obj({{"kind", "symbol"}}))).get("annotations").size() == 1,
          "list_annotations lists symbol renames");
    CHECK(structured(callTool(server, d, &ws, "rename_symbol", Json::obj({{"symbol", "baz"}, {"name", ""}}))).get("restored").asBool(),
          "an empty name restores the symbol");
    // Declarations with inferred types, as in IDA's pseudocode.
    CHECK(decCode.find("public static void bar() {\n    String v0;\n\n") != std::string::npos &&
              dm.get("variables").size() == 1 && dm.get("variables")[0].get("type").asString() == "String" &&
              !dm.get("variables")[0].get("parameter").asBool(),
          ("locals declared with their type: " + decCode).c_str());
    Json retype = callTool(server, d, &ws, "rename_variable",
                           Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"type", "CharSequence"}}));
    CHECK(!isError(retype) && structured(retype).get("current_type").asString() == "CharSequence", ("set type: " + text(retype)).c_str());
    CHECK(structured(callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}}))).get("methods")[0]
                  .get("code").asString().find("    CharSequence v0;") != std::string::npos,
          "the declaration shows the user's type");
    // Pseudocode: any one-line text is a type.
    CHECK(!isError(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"type", "struct conn *"}}))) &&
              structured(callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}}))).get("methods")[0]
                      .get("code").asString().find("    struct conn *v0;") != std::string::npos,
          "a free-form type is accepted and declared");
    CHECK(isError(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"type", "int\nx"}}))),
          "a type of several lines is refused");
    {
        // The return type is retyped through its own key (Y on the signature line).
        decompiler::Output o;
        o.lines = {{"", 0, {}}};
        o.headerLine = 0;
        o.headerPrefix = "int64_t sub_10(";
        o.headerSuffix = ") {";
        o.returnType = "int64_t";
        o.returnAt = 0;
        o.vars.push_back({"x0", "int64_t", "", true});
        decompiler::applyUserNames(o, {}, {{std::string(decompiler::kReturnKey), "char *"}, {"x0", "struct ctx *"}}, true);
        CHECK(o.lines[0].text == "char *sub_10(struct ctx *x0) {", ("return and parameter types: " + o.lines[0].text).c_str());
        CHECK(decompiler::typeOf(o, decompiler::kReturnKey, {}) == "int64_t", "the inferred return type");
        CHECK(decompiler::checkTypeName("unsigned long long (*)(void *)").empty() && !decompiler::checkTypeName("a\nb").empty(),
              "type text: anything on one line");
    }
    CHECK(structured(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"type", ""}})))
                  .get("type_restored").asBool() &&
              structured(callTool(server, d, &ws, "list_annotations", Json::obj({{"kind", "type"}}))).get("annotations").size() == 0,
          "an empty type restores the inferred one");
    // Variable renames (IDA's N), shared by the Decompiler panel and MCP.
    Json ren = callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"name", "url"}}));
    CHECK(!isError(ren) && structured(ren).get("name").asString() == "url", ("rename_variable: " + text(ren)).c_str());
    const Json renamedBar = structured(callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}}))).get("methods")[0];
    const std::string renamedCode = renamedBar.get("code").asString();
    CHECK(renamedCode.find("url = \"https://api.example.com/v1/login\";") != std::string::npos &&
              renamedCode.find("baz(url);") != std::string::npos && renamedCode.find("v0") == std::string::npos &&
              renamedBar.get("renamed").get("v0").asString() == "url",
          ("decompile_method shows the new name: " + renamedCode).c_str());
    CHECK(isError(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"name", "baz"}}))),
          "rename to a name already used is refused");
    CHECK(isError(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"name", "int"}}))),
          "rename to a keyword is refused");
    CHECK(isError(callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v9"}, {"name", "x"}}))),
          "rename of a variable the method does not have is refused");
    Json renList = callTool(server, d, &ws, "list_annotations", Json::obj({{"kind", "rename"}}));
    CHECK(structured(renList).get("annotations").size() == 1 &&
              structured(renList).get("annotations")[0].get("variable").asString() == "v0" &&
              structured(renList).get("annotations")[0].get("method").asString() == "LFoo;->bar()V",
          "list_annotations lists renames");
    CHECK(structured(callTool(server, d, &ws, "list_annotations", Json::obj({{"kind", "comment"}}))).get("annotations").size() == 0,
          "renames are not comments");
    Json restore = callTool(server, d, &ws, "rename_variable", Json::obj({{"method", "LFoo;->bar()V"}, {"variable", "v0"}, {"name", ""}}));
    CHECK(structured(restore).get("restored").asBool() &&
              structured(callTool(server, d, &ws, "decompile_method", Json::obj({{"method", "LFoo;->bar()V"}}))).get("methods")[0]
                      .get("code").asString().find("baz(v0);") != std::string::npos,
          "an empty name restores the original");
    Json xr = callTool(server, d, &ws, "xrefs", Json::obj({{"kind", "method"}, {"target", "LFoo;->baz(Ljava/lang/String;)V"}}));
    CHECK(structured(xr).get("count").asInt() == 1 &&
              structured(xr).get("xrefs")[0].get("from").asString() == "LFoo;->bar()V",
          "xrefs method");
    Json xs = callTool(server, d, &ws, "xrefs", Json::obj({{"kind", "string"}, {"target", "example"}, {"substring", true}}));
    CHECK(structured(xs).get("count").asInt() == 1, "xrefs string");
    Json cg = callTool(server, d, &ws, "call_graph", Json::obj({{"method", "Foo.baz"}, {"direction", "callers"}}));
    CHECK(structured(cg).get("edges").size() == 1, "call_graph callers");
    Json cfg = callTool(server, d, &ws, "control_flow_graph", Json::obj({{"method", "LFoo;->bar()V"}}));
    CHECK(structured(cfg).get("blocks").size() == 3, "control_flow_graph");
    Json eps = callTool(server, d, &ws, "find_endpoints", Json::object());
    CHECK(structured(eps).get("urls").size() == 1 &&
              structured(eps).get("urls")[0].get("used_by")[0].asString() == "LFoo;->bar()V",
          "find_endpoints with xrefs");
    Json files = callTool(server, d, &ws, "list_files", Json::obj({{"recursive", true}}));
    CHECK(structured(files).get("total").asInt() == 4, "list_files recursive");
    Json read = callTool(server, d, &ws, "read_file", Json::obj({{"path", "res/raw/config.json"}}));
    CHECK(structured(read).get("content").asString().find("\"k\"") != std::string::npos, "read_file text");
    Json readBin = callTool(server, d, &ws, "read_file", Json::obj({{"path", "classes.dex"}}));
    CHECK(structured(readBin).get("format").asString() == "binary", "read_file binary -> hexdump");
    Json escape = callTool(server, d, &ws, "read_file", Json::obj({{"path", "../../etc/passwd"}}));
    CHECK(isError(escape), "paths outside the project tree are not reachable");
    Json hex = callTool(server, d, &ws, "hexdump", Json::obj({{"path", "classes.dex"}, {"length", 16}}));
    CHECK(text(hex).find("64 65 78 0a") != std::string::npos, "hexdump");
    Json libs = callTool(server, d, &ws, "list_native_libs", Json::object());
    CHECK(structured(libs).get("libraries").size() == 2, "list_native_libs");
    Json elf = callTool(server, d, &ws, "inspect_native_lib", Json::obj({{"path", "lib/arm64-v8a/libfoo.so"}}));
    CHECK(structured(elf).get("jni").size() == 2 && structured(elf).get("machine").asString() == "AArch64",
          "inspect_native_lib");
    Json fns = callTool(server, d, &ws, "native_functions", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}}));
    CHECK(structured(fns).get("total_functions").asInt() == 2, "native_functions");
    Json dis = callTool(server, d, &ws, "disassemble_native",
                        Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}}));
    const std::string listing = structured(dis).get("listing").asString();
    CHECK(listing.find("bl       0x120 <sub_120>") != std::string::npos && listing.find("\"hello native\"") != std::string::npos,
          "disassemble_native names calls and strings");
    Json ndec = callTool(server, d, &ws, "decompile_native", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}}));
    const std::string ncode = structured(ndec).get("code").asString();
    CHECK(ncode.find("int64_t f_entry(int64_t x0) {") != std::string::npos && ncode.find("    sub_120(x0);") != std::string::npos &&
              ncode.find("    return \"hello native\";") != std::string::npos && ncode.find("x29") == std::string::npos,
          ("decompile_native: " + ncode).c_str());
    Json nleaf = callTool(server, d, &ws, "decompile_native", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "sub_120"}}));
    CHECK(structured(nleaf).get("code").asString().find("return 1;") != std::string::npos,
          ("decompile_native leaf: " + structured(nleaf).get("code").asString()).c_str());
    Json nren = callTool(server, d, &ws, "rename_variable",
                         Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}, {"variable", "w0"}, {"name", "ctx"}}));
    CHECK(!isError(nren) && structured(nren).get("variable").asString() == "x0", ("rename_variable native: " + text(nren)).c_str());
    const std::string nrenamed = structured(callTool(server, d, &ws, "decompile_native",
                                                     Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}})))
                                     .get("code").asString();
    CHECK(nrenamed.find("int64_t f_entry(int64_t ctx) {") != std::string::npos && nrenamed.find("sub_120(ctx);") != std::string::npos,
          ("w0 / x0 renamed together: " + nrenamed).c_str());
    callTool(server, d, &ws, "rename_variable",
             Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "0x100"}, {"variable", "x0"}, {"type", "char *"}}));
    const std::string ntyped = structured(callTool(server, d, &ws, "decompile_native",
                                                   Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}})))
                                   .get("code").asString();
    CHECK(ntyped.find("int64_t f_entry(char *ctx) {") != std::string::npos, ("parameter type: " + ntyped).c_str());
    callTool(server, d, &ws, "rename_variable",
             Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "0x100"}, {"variable", "x0"}, {"type", ""}}));
    callTool(server, d, &ws, "rename_symbol", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"symbol", "sub_120"}, {"name", "helper"}}));
    const std::string nsym = structured(callTool(server, d, &ws, "decompile_native",
                                                 Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}})))
                                 .get("code").asString();
    const std::string nhelper = structured(callTool(server, d, &ws, "decompile_native",
                                                    Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "sub_120"}})))
                                    .get("code").asString();
    CHECK(nsym.find("helper(ctx);") != std::string::npos && nhelper.find("int64_t helper() {") != std::string::npos,
          ("a function renamed in its callers and its own signature: " + nsym + nhelper).c_str());
    callTool(server, d, &ws, "rename_symbol", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"symbol", "sub_120"}, {"name", ""}}));
    CHECK(structured(callTool(server, d, &ws, "decompile_native", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "sub_120"}})))
                  .get("code").asString().find("ctx") == std::string::npos,
          "renames belong to one function");
    CHECK(isError(callTool(server, d, &ws, "rename_variable",
                           Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}, {"variable", "foo"}, {"name", "a"}}))),
          "only registers / stack slots are variables");
    CHECK(structured(callTool(server, d, &ws, "rename_variable",
                              Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "0x100"}, {"variable", "x0"}, {"name", ""}})))
                  .get("restored").asBool() &&
              ws.annotations().all().empty(),
          "native rename restored by address");
    Json nx = callTool(server, d, &ws, "native_xrefs", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"target", "sub_120"}}));
    CHECK(structured(nx).get("references").size() == 1 &&
              structured(nx).get("references")[0].get("from_function").asString() == "f_entry+0x4",
          "native_xrefs callers");
    Json nativeCfg = callTool(server, d, &ws, "native_cfg", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}, {"function", "f_entry"}}));
    CHECK(structured(nativeCfg).get("blocks").size() == 1, "native_cfg");
    Json ns = callTool(server, d, &ws, "native_strings", Json::obj({{"path", "lib/arm64-v8a/libnat.so"}}));
    CHECK(structured(ns).get("strings").size() == 1, "native_strings");
    Json bad = callTool(server, d, &ws, "disassemble_native", Json::obj({{"path", "lib/arm64-v8a/libfoo.so"}, {"function", "nope"}}));
    CHECK(isError(bad), "disassemble_native unknown function is an error");
    Json note = callTool(server, d, &ws, "add_annotation",
                         Json::obj({{"kind", "comment"}, {"path", "lib/arm64-v8a/libnat.so"}, {"address", "0x104"}, {"text", "calls the helper"}}));
    CHECK(structured(note).get("address").asString() == "0x104", "add_annotation on a native address");
    Json fileNote = callTool(server, d, &ws, "add_annotation",
                             Json::obj({{"kind", "bookmark"}, {"path", "res/raw/config.json"}, {"line", 3}, {"text", "config"}}));
    CHECK(structured(fileNote).get("line").asInt() == 3, "add_annotation on a file line");
    CHECK(isError(callTool(server, d, &ws, "add_annotation", Json::obj({{"kind", "comment"}, {"path", "res/raw/config.json"}}))),
          "comment without text refused");
    CHECK(isError(callTool(server, d, &ws, "add_annotation",
                           Json::obj({{"kind", "bookmark"}, {"path", "../../etc/passwd"}}))),
          "add_annotation rejects unknown paths");
    Json listed = callTool(server, d, &ws, "list_annotations", Json::obj({{"kind", "comment"}}));
    CHECK(structured(listed).get("annotations").size() == 1 && structured(listed).get("total").asInt() == 2, "list_annotations");
    const long long noteId = structured(note).get("id").asInt();
    CHECK(!isError(callTool(server, d, &ws, "remove_annotation", Json::obj({{"id", noteId}}))) && ws.annotations().all().size() == 1,
          "remove_annotation");
    Json dexInfo = callTool(server, d, &ws, "dex_info", Json::object());
    CHECK(structured(dexInfo).get("dex_files").size() == 1, "dex_info");

    ws.openByPath(RootKind::Apk, "sample", "res/raw/config.json", Workspace::OpenMode::Permanent);
    CHECK(!ws.documents().empty() && !ws.documents().back()->isPreview(), "permanent open is not a preview tab");

    // Removing the APK releases its analysis (and its annotations, checked below).
    const size_t notesBeforeRemoval = ws.annotations().all().size();
    std::weak_ptr<const ApkAnalysis> weak = ws.analysis().get("sample");
    ws.removeApk(ws.apkRoots().front());
    CHECK(weak.expired(), "analysis memory released on Remove from Project");
    CHECK(notesBeforeRemoval == 1 && ws.annotations().all().empty(), "annotations removed with their APK");
    ws.closeAll();
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ---------------------------------------------------------------------------
// HTTPS interception (mbedTLS): CA management, TLS handshakes, the proxy
// decrypting CONNECT tunnels, intercept / match & replace over TLS, WebSocket
// capture, and the Repeater's HTTPS send.
// ---------------------------------------------------------------------------

#include <cctype>
#include <cmath>
#include "core/Paths.hpp"
#include "debug/CaStore.hpp"
#include "debug/CertInstaller.hpp"
#include "debug/Stream.hpp"
#include "debug/Tls.hpp"

namespace {

// A local HTTPS origin: accepts connections until stopped, terminates TLS
// with `cert`, answers every request through `respond`.
struct TlsOrigin {
    std::shared_ptr<const tls::Identity> cert;
    std::function<std::string(const std::string& request)> respond = [](const std::string&) { return std::string(); };
    std::string lastRequest;
    std::atomic<int> served{0};
    std::atomic<bool> stopping{false};
    int port = 0;

    void run(Socket& listener) {
        port = listener.localPort();
        while (!stopping.load()) {
            Socket c = listener.accept(250);
            if (!c.valid()) continue;
            tls::Connection tls;
            std::string error, note;
            if (!tls.accept(c, *cert, 10000, error, note)) continue;
            net::TlsStream stream(c, tls);
            std::string req;
            char buf[8192];
            while (req.find("\r\n\r\n") == std::string::npos && stream.waitReadable(3000)) {
                const long n = stream.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            // The body (Content-Length) when there is one.
            const size_t headEnd = req.find("\r\n\r\n");
            if (headEnd != std::string::npos) {
                const size_t colon = req.find("Content-Length:");
                if (colon != std::string::npos && colon < headEnd) {
                    const size_t want = static_cast<size_t>(std::strtoull(req.c_str() + colon + 15, nullptr, 10));
                    while (req.size() < headEnd + 4 + want && stream.waitReadable(3000)) {
                        const long n = stream.recvSome(buf, sizeof buf);
                        if (n <= 0) break;
                        req.append(buf, static_cast<size_t>(n));
                    }
                }
            }
            lastRequest = req;
            stream.sendAll(respond(req));
            ++served;
            tls.close();
            c.shutdownBoth();
        }
    }
};

// A client that goes through the proxy: CONNECT + TLS (trusting `roots`).
struct ProxyTlsClient {
    Socket sock;
    tls::Connection tls;
    std::unique_ptr<net::TlsStream> stream;

    bool connect(int proxyPort, const std::string& connectHost, int port, const std::string& sni,
                 tls::TrustStore* roots, std::string& error, bool tls12Only = false) {
        if (!sock.connectLoopback(proxyPort, 3000, error)) return false;
        sock.sendAll("CONNECT " + connectHost + ":" + std::to_string(port) + " HTTP/1.1\r\nHost: x\r\n\r\n");
        char buf[256];
        const long n = sock.waitReadable(3000) ? sock.recvSome(buf, sizeof buf) : 0;
        if (n <= 0 || std::string(buf, static_cast<size_t>(n)).find("200") == std::string::npos) {
            error = "CONNECT failed";
            return false;
        }
        if (tls12Only) tls.setMaxTls12();
        if (!tls.connect(sock, sni, roots, true, 10000, error)) return false;
        stream = std::make_unique<net::TlsStream>(sock, tls);
        return true;
    }
    std::string exchange(const std::string& raw) {
        if (!stream || !stream->sendAll(raw)) return {};
        std::string resp;
        char buf[8192];
        while (stream->waitReadable(3000)) {
            const long n = stream->recvSome(buf, sizeof buf);
            if (n <= 0) break;
            resp.append(buf, static_cast<size_t>(n));
        }
        return resp;
    }
};

void waitFlows(const TrafficProxy& proxy, size_t count, int tries = 300) {
    for (int i = 0; i < tries && proxy.flows().size() < count; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

std::string gzipBytes(const std::string& plain) {
    size_t outLen = 0;
    void* deflated = tdefl_compress_mem_to_heap(plain.data(), plain.size(), &outLen, 0);
    std::string gz = std::string("\x1f\x8b\x08\0\0\0\0\0\0\x03", 10) + std::string((const char*)deflated, outLen) +
                     std::string(8, '\0');
    mz_free(deflated);
    return gz;
}

}  // namespace

static void testCaAndCertificates() {
    std::printf("== CA and certificates ==\n");
    CHECK(tls::init(), "TLS subsystem initialises");
    const fs::path dir = fs::temp_directory_path() / "apkspy-test-ca";
    fs::remove_all(dir);
    fs::create_directories(dir);

    // Generation, persistence, reload.
    {
        ca::Store store;
        std::string error;
        CHECK(store.loadOrGenerate(dir.string(), error), ("CA generates: " + error).c_str());
        CHECK(store.ready() && store.ca()->isCa(), "the CA is a CA");
        CHECK(store.ca()->secondsUntilExpiry() > 9ll * 365 * 24 * 3600, "10 year validity");
        const std::string fp = store.ca()->sha256Fingerprint();
        CHECK(fp.size() == 95 && fp.find(':') != std::string::npos, "SHA-256 fingerprint format");
        CHECK(store.ca()->subject().find("CN=ApkSpy CA") == 0, "subject name");
        CHECK(fs::exists(dir / "apkspy-ca.pem") && fs::exists(dir / "apkspy-ca.key"), "CA files on disk");
        ca::Store reloaded;
        CHECK(reloaded.loadOrGenerate(dir.string(), error) && reloaded.ca()->sha256Fingerprint() == fp,
              "CA reloads with the same fingerprint");
        // The PEM on disk must not contain any private key block.
        std::ifstream pem(dir / "apkspy-ca.pem");
        std::string pemText((std::istreambuf_iterator<char>(pem)), std::istreambuf_iterator<char>());
        CHECK(pemText.find("PRIVATE KEY") == std::string::npos, "the exported PEM has no private key");

        // Leaf signing + verification, cached per host.
        std::shared_ptr<const tls::Identity> leaf = store.leafFor("api.example.com", error);
        CHECK(leaf != nullptr, ("leaf signs: " + error).c_str());
        CHECK(!leaf->isCa(), "the leaf is not a CA");
        CHECK(store.leafFor("api.example.com", error).get() == leaf.get(), "leaf cached per host");
        CHECK(store.leafCount() == 1, "leaf count");

        // A certificate for an IP literal (SAN iPAddress).
        std::shared_ptr<const tls::Identity> ipLeaf = store.leafFor("10.1.2.3", error);
        CHECK(ipLeaf != nullptr, ("leaf for an IP: " + error).c_str());

        // An expired leaf (years = -1): verification rejects it downstream.
        tls::Identity expired;
        CHECK(tls::makeLeaf(*store.ca(), "expired.test", -1, expired, error), ("expired leaf signs: " + error).c_str());
        CHECK(expired.secondsUntilExpiry() < 0, "the leaf is expired");

        // Regeneration: a new key, a new fingerprint, an empty leaf cache.
        const std::string oldFp = store.ca()->sha256Fingerprint();
        CHECK(store.regenerate(error), ("regenerate: " + error).c_str());
        CHECK(store.ca()->sha256Fingerprint() != oldFp, "regeneration makes a new CA");
        CHECK(store.leafCount() == 0, "leaf cache cleared on regeneration");

        // The Android store file name: 8 hex digits + ".0".
        const std::string name = store.androidFileName();
        CHECK(name.size() == 10 && name[8] == '.' && name[9] == '0', "Android file name shape");
        for (int i = 0; i < 8; ++i) CHECK(isxdigit((unsigned char)name[i]), "Android file name is hex");
    }

    // TrustStore: parse the bundled PEM bundle, reject garbage.
    {
        tls::TrustStore roots;
        std::string error;
        std::string anyCert;
        {
            ca::Store store;
            store.loadOrGenerate((fs::temp_directory_path() / "apkspy-test-ca2").string(), error);
            anyCert = store.caPem();
        }
        CHECK(roots.loadPem(anyCert, error) && roots.count() >= 1, "trust store loads a PEM");
        CHECK(!roots.loadPem("not a certificate", error) || roots.count() == 0, "trust store rejects garbage");
        std::string rootsErr;
        const std::string bundle = pathutil::assetsFile("cacert.pem");
        if (!bundle.empty()) {
            tls::TrustStore mozilla;
            CHECK(mozilla.loadPemFile(bundle, error) && mozilla.count() >= 100, "bundled Mozilla roots parse");
        }
    }
}

static void testTlsHandshake() {
    std::printf("== TLS handshakes ==\n");
    std::string error;
    ca::Store store;
    const fs::path dir = fs::temp_directory_path() / "apkspy-test-ca3";
    fs::remove_all(dir);
    store.loadOrGenerate(dir.string(), error);
    auto cert = store.leafFor("handshake.test", error);
    CHECK(cert != nullptr, "handshake leaf");

    tls::TrustStore roots;
    std::string anyCert = store.caPem();
    roots.loadPem(anyCert, error);

    for (int mode = 0; mode < 2; ++mode) {
        Socket listener;
        CHECK(listener.listenLoopback(0, error), "listener");
        std::thread server([&] {
            Socket c = listener.accept(5000);
            if (!c.valid()) return;
            tls::Connection tls;
            if (mode == 1) tls.setMaxTls12();
            std::string err, note;
            if (tls.accept(c, *cert, 10000, err, note)) {
                net::TlsStream stream(c, tls);
                char buf[64];
                const int n = stream.recvSome(buf, sizeof buf);
                if (n > 0) stream.sendAll(std::string(buf, static_cast<size_t>(n)));
                tls.close();
            }
            c.shutdownBoth();
        });
        Socket s;
        CHECK(s.connectLoopback(listener.localPort(), 3000, error), "client connects");
        tls::Connection tls;
        if (mode == 1) tls.setMaxTls12();
        CHECK(tls.connect(s, "handshake.test", &roots, true, 10000, error), ("client handshake: " + error).c_str());
        CHECK(std::string(tls.version()) == (mode == 1 ? "TLSv1.2" : "TLSv1.3"),
              ("negotiated version is " + std::string(tls.version())).c_str());
        CHECK(std::string(tls.alpn()) == "http/1.1", "ALPN always offers http/1.1");
        net::TlsStream stream(s, tls);
        CHECK(stream.sendAll("ping"), "send");
        char buf[64] = {};
        const long n = stream.recvSome(buf, sizeof buf);
        CHECK(n == 4 && std::string(buf, 4) == "ping", "echo round trip");
        tls.close();
        s.shutdownBoth();
        server.join();
    }

    // Hostname mismatch: the certificate is for handshake.test.
    {
        Socket listener;
        listener.listenLoopback(0, error);
        std::thread server([&] {
            Socket c = listener.accept(5000);
            if (c.valid()) {
                tls::Connection tls;
                std::string err, note;
                tls.accept(c, *cert, 10000, err, note);
                c.shutdownBoth();
            }
        });
        Socket s;
        s.connectLoopback(listener.localPort(), 3000, error);
        tls::Connection tls;
        const bool ok = tls.connect(s, "other.test", &roots, true, 10000, error);
        CHECK(!ok && error.find("host name") != std::string::npos,
              ("wrong host rejected: " + error).c_str());
        s.shutdownBoth();
        server.join();
    }
}

static void testHttpsInterception() {
    std::printf("== HTTPS interception ==\n");
    std::string error;
    const fs::path caDir = fs::temp_directory_path() / "apkspy-test-ca4";
    fs::remove_all(caDir);
    auto caStore = std::make_shared<ca::Store>();
    CHECK(caStore->loadOrGenerate(caDir.string(), error), "proxy CA");

    // The origin's certificate is signed by the same CA (it plays the real
    // server); the proxy verifies upstreams against it.
    tls::TrustStore roots;
    roots.loadPem(caStore->caPem(), error);

    TrafficProxy proxy;
    proxy.setCa(caStore);
    auto proxyRoots = std::make_shared<tls::TrustStore>();
    proxyRoots->loadPem(caStore->caPem(), error);
    proxy.setUpstreamTrust(proxyRoots, true);
    CHECK(proxy.start(0, error) && proxy.interceptingHttps(), "proxy starts with interception");

    TlsOrigin origin;
    origin.cert = caStore->leafFor("origin.test", error);
    origin.respond = [](const std::string& req) {
        const std::string body = "{\"hello\":\"world\"}";
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\n\r\n" + body;
    };
    Socket originListener;
    originListener.listenLoopback(0, error);
    std::thread originThread([&] { origin.run(originListener); });
    while (origin.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // GET over TLS 1.3 through the proxy.
    {
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &roots, error),
              ("CONNECT + TLS: " + error).c_str());
        const std::string resp = client.exchange("GET /api/data?x=1 HTTP/1.1\r\nHost: origin.test\r\n\r\n");
        CHECK(resp.find("200 OK") != std::string::npos && resp.find("{\"hello\":\"world\"}") != std::string::npos,
              "HTTPS GET relayed");
        client.tls.close();
        client.sock.shutdownBoth();
    }
    waitFlows(proxy, 1);
    {
        auto flows = proxy.flows();
        CHECK(flows.size() == 1, "one flow");
        TrafficProxy::Flow full;
        CHECK(proxy.flow(flows[0].id, full), "flow detail");
        CHECK(full.https && !full.tunnel && full.sni == "origin.test" && full.method == "GET" &&
                  full.path == "/api/data?x=1" && full.status == 200,
              "the flow is decrypted: method, path, status");
        CHECK(full.url().rfind("https://origin.test", 0) == 0, "https url");
        CHECK(full.request.header("host") == "origin.test", "request headers captured");
        CHECK(TrafficProxy::decodeBody(full.response, nullptr) == "{\"hello\":\"world\"}", "response body captured");
        CHECK(std::string(full.tlsVersion) == "TLSv1.3" || std::string(full.tlsVersion) == "TLSv1.2", "tls version");
        CHECK(full.alpn == "http/1.1", "alpn negotiated");
        CHECK(origin.lastRequest.rfind("GET /api/data?x=1 HTTP/1.1", 0) == 0, "origin saw the request");
    }

    // POST with a body, over TLS 1.2.
    const std::string body = "name=alice&token=abc";
    {
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &roots, error, true),
              ("TLS 1.2 client: " + error).c_str());
        const std::string resp = client.exchange("POST /api/login HTTP/1.1\r\nHost: origin.test\r\n"
                                                 "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
                                                 std::to_string(body.size()) + "\r\n\r\n" + body);
        CHECK(resp.find("200 OK") != std::string::npos, "HTTPS POST relayed");
        client.tls.close();
        client.sock.shutdownBoth();
    }
    waitFlows(proxy, 2);
    {
        TrafficProxy::Flow full;
        CHECK(proxy.flow(proxy.flows()[1].id, full) && full.method == "POST" && full.request.body == body,
              "POST body captured");
        CHECK(std::string(full.tlsVersion) == "TLSv1.2", "TLS 1.2 negotiated when capped");
    }

    // Two requests over one persistent TLS session.
    {
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &roots, error),
              "persistent session opens");
        const std::string first = client.exchange("GET /one HTTP/1.1\r\nHost: origin.test\r\n\r\n");
        const std::string second = client.exchange("GET /two HTTP/1.1\r\nHost: origin.test\r\n\r\n");
        CHECK(first.find("200") != std::string::npos && second.find("200") != std::string::npos,
              "both requests on one session answered");
        client.tls.close();
        client.sock.shutdownBoth();
    }
    waitFlows(proxy, 4);
    {
        auto flows = proxy.flows();
        CHECK(flows.size() == 4 && flows[2].path == "/one" && flows[3].path == "/two",
              "each request is its own flow");
    }

    // gzip and chunked responses through TLS.
    {
        TlsOrigin coded;
        coded.cert = caStore->leafFor("coded.test", error);
        const std::string plain = "{\"gzip\":true,\"chunked\":false}";
        coded.respond = [&](const std::string& req) {
            if (req.find("/gz") != std::string::npos) {
                const std::string gz = gzipBytes(plain);
                return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                       "Content-Length: " +
                       std::to_string(gz.size()) + "\r\n\r\n" + gz;
            }
            return std::string("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n") +
                   "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        };
        Socket codedListener;
        codedListener.listenLoopback(0, error);
        std::thread codedThread([&] { coded.run(codedListener); });
        while (coded.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ProxyTlsClient gz, chunked;
        CHECK(gz.connect(proxy.port(), "127.0.0.1", coded.port, "coded.test", &roots, error), "gzip client");
        const std::string gzResp = gz.exchange("GET /gz HTTP/1.1\r\nHost: coded.test\r\n\r\n");
        CHECK(gzResp.find("200") != std::string::npos, "gzip response relayed");
        CHECK(chunked.connect(proxy.port(), "127.0.0.1", coded.port, "coded.test", &roots, error), "chunked client");
        const std::string chResp = chunked.exchange("GET /chunked HTTP/1.1\r\nHost: coded.test\r\n\r\n");
        CHECK(chResp.find("hello") != std::string::npos && chResp.find(" world") != std::string::npos &&
                  chResp.find("5\r\n") != std::string::npos,
              "chunked response relayed (framing preserved)");
        gz.tls.close(), gz.sock.shutdownBoth();
        chunked.tls.close(), chunked.sock.shutdownBoth();
        coded.stopping = true;
        codedThread.join();
        waitFlows(proxy, 6);
        TrafficProxy::Flow gzFlow, chFlow;
        CHECK(proxy.flow(proxy.flows()[4].id, gzFlow) && TrafficProxy::decodeBody(gzFlow.response, nullptr) == plain,
              "gzip body decoded in the flow");
        CHECK(proxy.flow(proxy.flows()[5].id, chFlow) && TrafficProxy::decodeBody(chFlow.response, nullptr) == "hello world",
              "chunked body decoded in the flow");
    }

    // Concurrency: several HTTPS clients at once.
    {
        std::vector<std::thread> clients;
        std::atomic<int> okCount{0};
        for (int i = 0; i < 6; ++i) {
            clients.emplace_back([&, i] {
                ProxyTlsClient client;
                if (!client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &roots, error)) return;
                const std::string resp = client.exchange("GET /c" + std::to_string(i) + " HTTP/1.1\r\nHost: origin.test\r\n\r\n");
                if (resp.find("200") != std::string::npos) ++okCount;
                client.tls.close();
                client.sock.shutdownBoth();
            });
        }
        for (auto& t : clients) t.join();
        CHECK(okCount == 6, "concurrent HTTPS exchanges");
    }

    // An app that does not trust the CA: the handshake fails and the flow
    // explains why instead of silently "succeeding".
    {
        ca::Store otherCa;
        otherCa.loadOrGenerate((fs::temp_directory_path() / "apkspy-test-other").string(), error);
        tls::TrustStore otherRoots;
        otherRoots.loadPem(otherCa.caPem(), error);
        ProxyTlsClient client;
        std::string err;
        const bool ok = client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &otherRoots, err);
        CHECK(!ok, "untrusting client cannot complete the handshake");
        waitFlows(proxy, proxy.flows().size() + 1);
        TrafficProxy::Flow rejection;
        bool found = false;
        for (const auto& f : proxy.flows())
            if (f.https && !f.tlsError.empty() && f.error.find("handshake with the app") != std::string::npos)
                rejection = f, found = true;
        CHECK(found && (rejection.tlsError.find("alert") != std::string::npos ||
                    rejection.tlsError.find("rejected the TLS handshake") != std::string::npos),
              "the rejection is recorded with its reason");
    }

    // Upstream with an untrusted certificate: the proxy refuses and says so.
    {
        ca::Store evilCa;
        evilCa.loadOrGenerate((fs::temp_directory_path() / "apkspy-test-evil").string(), error);
        TlsOrigin evil;
        evil.cert = evilCa.leafFor("origin.test", error);
        evil.respond = [](const std::string&) { return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"; };
        Socket evilListener;
        evilListener.listenLoopback(0, error);
        std::thread evilThread([&] { evil.run(evilListener); });
        while (evil.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", evil.port, "origin.test", &roots, error), "client side ok");
        const std::string resp = client.exchange("GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n");
        CHECK(resp.find("502") != std::string::npos, "untrusted upstream: 502 to the client");
        waitFlows(proxy, proxy.flows().size() + 1);
        bool explained = false;
        for (const auto& f : proxy.flows())
            if (f.status == 502 && f.error.find("upstream TLS") != std::string::npos &&
                f.error.find("not signed by a root") != std::string::npos)
                explained = true;
        CHECK(explained, "the flow explains the verification failure");
        client.tls.close();
        client.sock.shutdownBoth();
        evil.stopping = true;
        evilThread.join();
    }

    // Upstream with an expired certificate.
    {
        tls::Identity expiredCert;
        CHECK(tls::makeLeaf(*caStore->ca(), "origin.test", -1, expiredCert, error), "expired upstream cert");
        TlsOrigin expired;
        expired.cert = std::make_shared<tls::Identity>(std::move(expiredCert));
        expired.respond = [](const std::string&) { return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"; };
        Socket expiredListener;
        expiredListener.listenLoopback(0, error);
        std::thread expiredThread([&] { expired.run(expiredListener); });
        while (expired.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", expired.port, "origin.test", &roots, error), "client side ok");
        const std::string resp = client.exchange("GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n");
        CHECK(resp.find("502") != std::string::npos, "expired upstream: 502 to the client");
        waitFlows(proxy, proxy.flows().size() + 1);
        bool explained = false;
        for (const auto& f : proxy.flows())
            if (f.status == 502 && f.error.find("expired") != std::string::npos) explained = true;
        CHECK(explained, "the flow explains the expired certificate");
        client.tls.close();
        client.sock.shutdownBoth();
        expired.stopping = true;
        expiredThread.join();
    }

    // The HTTP/2 preface through an intercepted session is decoded, not hung.
    {
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", origin.port, "origin.test", &roots, error), "h2 client opens");
        client.exchange("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        client.tls.close();
        client.sock.shutdownBoth();
        waitFlows(proxy, proxy.flows().size() + 1);
        // h2 is relayed and decoded passively now (it used to be diagnosed as
        // unsupported): the connection flow exists with the h2 marker and no error.
        bool decoded = false;
        for (const auto& f : proxy.flows())
            if ((f.alpn == "h2" || f.alpn == "h2c") && f.error.empty() && f.method == "PRI") decoded = true;
        CHECK(decoded, "HTTP/2 preface decoded");
    }

    origin.stopping = true;
    originThread.join();
    proxy.stop();

    // Without a CA, CONNECTs go back to blind tunnels.
    {
        TrafficProxy plain;
        CHECK(plain.start(0, error) && !plain.interceptingHttps(), "proxy without a CA");
        Socket echo;
        echo.listenLoopback(0, error);
        std::thread echoThread([&] {
            Socket c = echo.accept(5000);
            if (!c.valid()) return;
            char buf[4096];
            while (c.waitReadable(2000)) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0 || !c.sendAll(buf, static_cast<size_t>(n))) break;
            }
        });
        Socket client;
        client.connectLoopback(plain.port(), 2000, error);
        client.sendAll("CONNECT 127.0.0.1:" + std::to_string(echo.localPort()) + " HTTP/1.1\r\nHost: x\r\n\r\n");
        char buf[256];
        const long n = client.waitReadable(3000) ? client.recvSome(buf, sizeof buf) : 0;
        const std::string hello = clientHello("tunnel.example.org");
        client.sendAll(hello);
        std::string echoed;
        while (echoed.size() < hello.size() && client.waitReadable(3000)) {
            const long r = client.recvSome(buf, sizeof buf);
            if (r <= 0) break;
            echoed.append(buf, static_cast<size_t>(r));
        }
        CHECK(n > 0 && echoed == hello, "without a CA the tunnel relays blindly");
        waitFlows(plain, 1);
        CHECK(plain.flows().size() == 1 && plain.flows()[0].tunnel && !plain.flows()[0].https,
              "the flow is a tunnel again");
        client.shutdownBoth();
        echoThread.join();
        plain.stop();
    }
}

static void testHttpsInterceptAndRules() {
    std::printf("== intercept and match & replace over HTTPS ==\n");
    std::string error;
    const fs::path caDir = fs::temp_directory_path() / "apkspy-test-ca5";
    fs::remove_all(caDir);
    auto caStore = std::make_shared<ca::Store>();
    caStore->loadOrGenerate(caDir.string(), error);
    tls::TrustStore roots;
    roots.loadPem(caStore->caPem(), error);

    TlsOrigin origin;
    origin.cert = caStore->leafFor("edit.test", error);
    origin.respond = [](const std::string&) {
        const std::string body = "{\"role\":\"user\"}";
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\n\r\n" + body;
    };
    Socket originListener;
    originListener.listenLoopback(0, error);
    std::thread originThread([&] { origin.run(originListener); });
    while (origin.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));

    TrafficProxy proxy;
    proxy.setCa(caStore);
    auto rootCopy = std::make_shared<tls::TrustStore>();
    std::string anyPem = caStore->caPem();
    rootCopy->loadPem(anyPem, error);
    proxy.setUpstreamTrust(rootCopy, true);
    proxy.start(0, error);

    // Intercept: the request is held, edited, forwarded; the response too.
    proxy.setIntercept(true, true, "");
    ProxyTlsClient client;
    CHECK(client.connect(proxy.port(), "127.0.0.1", origin.port, "edit.test", &roots, error), "intercept client");
    // The exchange runs on its own thread: it blocks while the message waits.
    std::thread exchange([&] {
        client.exchange("GET /api/profile?id=7 HTTP/1.1\r\nHost: edit.test\r\n\r\n");
    });
    auto heldWait = [&] {
        for (int i = 0; i < 300 && proxy.heldCount() == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
    };
    heldWait();
    {
        auto held = proxy.held();
        CHECK(held.size() == 1 && !held[0].response && held[0].url.find("https://") == 0,
              "the HTTPS request is held");
        // Edit: change the path (Content-Length is fixed by forward()).
        std::string edited = held[0].raw;
        edited.replace(edited.find("/api/profile?id=7"), strlen("/api/profile?id=7"), "/api/profile?id=8");
        proxy.forward(held[0].id, edited);
    }
    heldWait();
    {
        auto held = proxy.held();
        CHECK(held.size() == 1 && held[0].response, "the HTTPS response is held");
        std::string edited = held[0].raw;
        CHECK(edited.find("\"role\":\"user\"") != std::string::npos, "held response is decrypted");
        edited.replace(edited.find("\"user\""), 6, "\"admin\"");
        proxy.forward(held[0].id, edited);
    }
    exchange.join();
    {
        auto flows = proxy.flows();
        TrafficProxy::Flow full;
        CHECK(!flows.empty() && proxy.flow(flows.back().id, full), "edited flow");
        CHECK(full.edited && full.path == "/api/profile?id=8", "the request edit went through");
        CHECK(TrafficProxy::decodeBody(full.response, nullptr).find("admin") != std::string::npos,
              "the response edit went through");
        CHECK(origin.lastRequest.find("/api/profile?id=8") != std::string::npos, "the origin saw the edited path");
    }
    client.tls.close();
    client.sock.shutdownBoth();

    // Match & replace over HTTPS: one rule each for request and response.
    {
        std::vector<matchreplace::Rule> rules;
        matchreplace::Rule r1;
        r1.where = matchreplace::Where::RequestLine;
        r1.match = "/api/";
        r1.replace = "/v2/";
        rules.push_back(r1);
        matchreplace::Rule r2;
        r2.where = matchreplace::Where::ResponseBody;
        r2.match = "user";
        r2.replace = "REDACTED";
        rules.push_back(r2);
        proxy.setRules(matchreplace::RuleSet(rules));
        proxy.setIntercept(false, false, "");
        ProxyTlsClient c2;
        CHECK(c2.connect(proxy.port(), "127.0.0.1", origin.port, "edit.test", &roots, error), "rules client");
        const std::string resp = c2.exchange("GET /api/profile HTTP/1.1\r\nHost: edit.test\r\n\r\n");
        CHECK(resp.find("REDACTED") != std::string::npos, "response rule applied inside TLS");
        CHECK(origin.lastRequest.find("GET /v2/profile") == 0, "request rule applied inside TLS");
        TrafficProxy::Flow full;
        proxy.flow(proxy.flows().back().id, full);
        CHECK(full.edited && TrafficProxy::decodeBody(full.response, nullptr).find("REDACTED") != std::string::npos,
              "rewritten response recorded as edited");
        c2.tls.close();
        c2.sock.shutdownBoth();
    }

    origin.stopping = true;
    originThread.join();
    proxy.stop();
}

static void testWebSocketCapture() {
    std::printf("== WebSocket capture ==\n");
    std::string error;

    // A WebSocket-capable origin over TLS (wss through the proxy) and plain.
    auto wsHandshake = [](const std::string& req, const std::string& acceptKey) {
        return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
               acceptKey + "\r\n\r\n";
    };
    TlsOrigin origin;
    const fs::path caDir = fs::temp_directory_path() / "apkspy-test-ca6";
    fs::remove_all(caDir);
    auto caStore = std::make_shared<ca::Store>();
    caStore->loadOrGenerate(caDir.string(), error);
    origin.cert = caStore->leafFor("ws.test", error);
    std::atomic<bool> wsDone{false};
    origin.respond = [&](const std::string&) { return wsHandshake("", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="); };

    // The wss case: after the 101 the origin speaks frames.
    Socket originListener;
    originListener.listenLoopback(0, error);
    // Serve one connection manually: 101, then echo frames until close.
    int port = 0;
    std::thread originThread([&] {
        port = originListener.localPort();
        while (!wsDone.load()) {
            Socket c = originListener.accept(250);
            if (!c.valid()) continue;
            tls::Connection tls;
            std::string err, note;
            if (!tls.accept(c, *origin.cert, 10000, err, note)) continue;
            net::TlsStream stream(c, tls);
            std::string req;
            char buf[4096];
            while (req.find("\r\n\r\n") == std::string::npos && stream.waitReadable(3000)) {
                const long n = stream.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            stream.sendAll(wsHandshake(req, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
            // Server greeting, then echo until the client closes.
            const std::string greeting = "\x81\x0dHello, client";  // text, 12 bytes, unmasked
            stream.sendAll(greeting);
            for (;;) {
                if (!stream.waitReadable(5000)) break;
                const long n = stream.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                if (!stream.sendAll(buf, static_cast<size_t>(n))) break;
            }
            tls.close();
            c.shutdownBoth();
        }
    });

    TrafficProxy proxy;
    proxy.setCa(caStore);
    tls::TrustStore roots;
    roots.loadPem(caStore->caPem(), error);
    auto rootsCopy = std::make_shared<tls::TrustStore>();
    rootsCopy->loadPem(caStore->caPem(), error);
    proxy.setUpstreamTrust(rootsCopy, true);
    proxy.start(0, error);

    {
        ProxyTlsClient client;
        CHECK(client.connect(proxy.port(), "127.0.0.1", port, "ws.test", &roots, error), "wss client");
        const std::string resp = client.exchange("GET /chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n"
                                                 "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                                 "Sec-WebSocket-Version: 13\r\n\r\n");
        CHECK(resp.find("101") != std::string::npos, "upgrade relayed");
        // The greeting frame arrives together with the 101.
        CHECK(resp.find("Hello, client") != std::string::npos, "server greeting received");
        // Two masked client frames + a close.
        const std::string hello = std::string("\x81\x85\x01\x02\x03\x04", 6) + std::string("hello", 5);
        const std::string binary = std::string("\x82\x83\x00\x00\x00\x00", 6) + std::string("abc", 3);
        client.stream->sendAll(hello);
        client.stream->sendAll(binary);
        client.stream->sendAll(std::string("\x88\x80\x01\x02\x03\x04", 6));  // close
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        client.tls.close();
        client.sock.shutdownBoth();

        waitFlows(proxy, 1);
        TrafficProxy::Flow full;
        CHECK(proxy.flow(proxy.flows()[0].id, full), "ws flow");
        CHECK(full.websocket && full.status == 101, "the flow is a WebSocket upgrade");
        CHECK(full.wsFrames.size() >= 4, "frames recorded (greeting, hello, binary, close)");
        bool sawText = false, sawBinary = false, sawClose = false;
        for (const auto& f : full.wsFrames) {
            if (f.opcode == 1 && !f.fromClient && f.preview.find("Hello, client") != std::string::npos) sawText = true;
            if (f.opcode == 2 && f.fromClient && f.preview == "abc") sawBinary = true;
            if (f.opcode == 8) sawClose = true;
        }
        CHECK(sawText, "server text frame captured with payload");
        CHECK(sawBinary, "client binary frame captured, unmasked");
        CHECK(sawClose, "close frame captured");
    }
    wsDone = true;
    originThread.join();
    proxy.stop();

    // The plain ws case over HTTP.
    {
        TrafficProxy plain;
        plain.start(0, error);
        Socket wsListener;
        wsListener.listenLoopback(0, error);
        std::thread wsThread([&] {
            Socket c = wsListener.accept(5000);
            if (!c.valid()) return;
            std::string req;
            char buf[4096];
            while (req.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            c.sendAll("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
            c.sendAll(std::string("\x81\x05ready", 7));
            // Longer than the client's 3 s read: the server must not close before the client's frame arrives.
            while (c.waitReadable(6000)) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0 || !c.sendAll(buf, static_cast<size_t>(n))) break;
            }
        });
        Socket client;
        client.connectLoopback(plain.port(), 2000, error);
        client.sendAll("GET http://127.0.0.1:" + std::to_string(wsListener.localPort()) +
                       "/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        const std::string resp = readAllFrom(client);
        CHECK(resp.find("101") != std::string::npos && resp.find("ready") != std::string::npos, "plain ws upgraded");
        client.sendAll(std::string("\x81\x83\x01\x02\x03\x04", 6) + std::string("abc", 3));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        client.shutdownBoth();
        wsThread.join();
        waitFlows(plain, 1);
        TrafficProxy::Flow full;
        CHECK(plain.flow(plain.flows()[0].id, full) && full.websocket && full.wsFrames.size() >= 2,
              "plain ws frames recorded");
        plain.stop();
    }
}

static void testRepeaterHttps() {
    std::printf("== Repeater HTTPS (httpclient) ==\n");
    std::string error;
    const fs::path caDir = fs::temp_directory_path() / "apkspy-test-ca7";
    fs::remove_all(caDir);
    auto caStore = std::make_shared<ca::Store>();
    caStore->loadOrGenerate(caDir.string(), error);
    TlsOrigin origin;
    origin.cert = caStore->leafFor("127.0.0.1", error);  // an iPAddress SAN
    origin.respond = [](const std::string&) {
        const std::string body = "{\"ok\":true}";
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
               "\r\n\r\n" + body;
    };
    Socket originListener;
    originListener.listenLoopback(0, error);
    std::thread originThread([&] { origin.run(originListener); });
    while (origin.port == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));

    tls::TrustStore roots;
    roots.loadPem(caStore->caPem(), error);
    httpclient::Options o;
    o.roots = &roots;
    httpclient::Target t;
    t.host = "127.0.0.1";
    t.port = origin.port;
    t.https = true;

    // A verified send.
    httpclient::Result r = httpclient::send(t, "POST /api/x HTTP/1.1\nHost: 127.0.0.1\nContent-Length: 3\n\nabc", o);
    CHECK(r.ok && r.status == 200 && TrafficProxy::decodeBody(r.response, nullptr) == "{\"ok\":true}",
          "Repeater sends HTTPS and reads the response");
    CHECK(r.response.header("content-type").find("json") != std::string::npos, "response headers parsed");

    // A wrong host name must fail verification, and the ignore flag (scoped to
    // this one send) must make it pass. "localhost" resolves to the same
    // loopback but matches neither the IP SAN nor the CN.
    httpclient::Target wrong;
    wrong.host = "localhost";
    wrong.port = origin.port;
    wrong.https = true;
    httpclient::Result rejected = httpclient::send(wrong, "GET / HTTP/1.1\nHost: localhost\n\n", o);
    CHECK(!rejected.ok && rejected.error.find("host name") != std::string::npos,
          ("certificate mismatch rejected: " + rejected.error).c_str());
    httpclient::Options ignoring;
    ignoring.ignoreCertErrors = true;
    httpclient::Result forced = httpclient::send(wrong, "GET / HTTP/1.1\nHost: localhost\n\n", ignoring);
    CHECK(forced.ok && forced.status == 200, "ignore-certificate-errors is scoped to the single send");

    origin.stopping = true;
    originThread.join();
}

// ---------------------------------------------------------------------------
// Proxy tools: content views, filter expressions, HAR, modes, hooks, scripts
// ---------------------------------------------------------------------------
#include "debug/ContentView.hpp"
#include "debug/FlowArchive.hpp"
#include "debug/FlowFilter.hpp"
#include "debug/TrafficScript.hpp"
namespace {

static void testContentViews() {
    std::printf("== content views ==\n");
    using contentview::View;
    // protobuf: 1: 150, 2: "testing", 3: {1: 1}
    const std::string pb("\x08\x96\x01\x12\x07testing\x1a\x02\x08\x01", 16);
    std::string out;
    CHECK(contentview::protobuf(pb, out) && out.find("1: 150") != std::string::npos &&
              out.find("2: \"testing\"") != std::string::npos && out.find("3: {") != std::string::npos &&
              out.find("  1: 1") != std::string::npos,
          ("schema-less protobuf: " + out).c_str());
    CHECK(!contentview::protobuf("not protobuf at all \xff\xff", out), "garbage is not protobuf");
    // gRPC: one uncompressed message.
    std::string grpc = std::string("\x00\x00\x00\x00", 4) + static_cast<char>(pb.size()) + pb;
    CHECK(contentview::grpc(grpc, out) && out.find("message 1") != std::string::npos && out.find("1: 150") != std::string::npos,
          "gRPC framing decoded");
    // MessagePack: {"a": 1, "b": [true, null], "c": -3, "d": 1.5}
    const std::string mp("\x84\xa1" "a\x01\xa1" "b\x92\xc3\xc0\xa1" "c\xfd\xa1" "d\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00", 23);
    CHECK(contentview::msgpack(mp, out) && out.find("\"a\": 1") != std::string::npos && out.find("true") != std::string::npos &&
              out.find("null") != std::string::npos && out.find("\"c\": -3") != std::string::npos && out.find("1.5") != std::string::npos,
          ("msgpack decoded: " + out).c_str());
    CHECK(!contentview::msgpack(std::string("\xc1", 1), out), "invalid msgpack rejected");
    CHECK(contentview::formFields("a=1&b=hello+world%21&empty=", out) && out.find("b: hello world!") != std::string::npos &&
              out.find("empty: ") != std::string::npos,
          "url-encoded form");
    const std::string mpBody = "--XyZ\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue1\r\n--XyZ\r\n"
                               "Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                               "\x01\x02\x03\x00\x05\x06\x07\x08\x09\r\n--XyZ--\r\n";
    CHECK(contentview::multipart(mpBody, "multipart/form-data; boundary=XyZ", out) && out.find("part 1") != std::string::npos &&
              out.find("value1") != std::string::npos && out.find("filename=\"a.bin\"") != std::string::npos,
          ("multipart parts: " + out).c_str());
    CHECK(contentview::prettyXml("<a><b>x</b><c/><d k=\"1>2\"><e/></d></a>") ==
              "<a>\n  <b>x</b>\n  <c/>\n  <d k=\"1>2\">\n    <e/>\n  </d>\n</a>\n",
          ("xml indented: " + contentview::prettyXml("<a><b>x</b><c/><d k=\"1>2\"><e/></d></a>")).c_str());
    const std::string png = std::string("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x02\x80\x00\x00\x01\xe0\x08\x06", 26);
    CHECK(contentview::imageInfo(png, out) && out.find("640 x 480") != std::string::npos, "PNG dimensions");
    CHECK(contentview::detect(grpc, "application/grpc+proto") == View::Grpc, "gRPC detected by type");
    CHECK(contentview::detect("{\"x\":1}", "text/plain") == View::Json, "JSON sniffed");
    CHECK(contentview::detect(pb, "application/octet-stream") == View::Protobuf, "protobuf sniffed in binary");
    CHECK(contentview::detect("<html><body>x</body></html>", "") == View::Xml, "markup sniffed");
    const auto r = contentview::render(View::Json, "not json", "");
    CHECK(r.view == View::Hex && r.note.find("not readable as JSON") != std::string::npos, "failed view falls back to hex");
    CHECK(contentview::hexDump("ABC").find("41 42 43") != std::string::npos, "hex dump");
}

static TrafficProxy::Flow makeFlow(uint64_t id, const std::string& method, const std::string& host, const std::string& path,
                                   int status, const std::string& respType, const std::string& respBody) {
    TrafficProxy::Flow f;
    f.id = id;
    f.method = method;
    f.host = host;
    f.port = 80;
    f.path = path;
    f.status = status;
    f.complete = true;
    f.request.startLine = method + " " + path + " HTTP/1.1";
    f.request.headers = {{"Host", host}, {"Authorization", "Bearer x"}};
    if (status) {
        f.response.startLine = "HTTP/1.1 " + std::to_string(status) + " X";
        f.response.headers = {{"Content-Type", respType}};
        f.response.body = respBody;
        f.response.bodySize = respBody.size();
    }
    return f;
}

static void testFlowFilters() {
    std::printf("== flow filter expressions ==\n");
    const auto f1 = makeFlow(1, "GET", "api.example.com", "/users/7", 200, "application/json", "{\"token\":\"abc\"}");
    auto f2 = makeFlow(2, "POST", "auth.example.org", "/login", 500, "text/html", "<b>oops</b>");
    f2.error = "boom";
    TrafficProxy::Flow f3;
    f3.id = 3;
    f3.tunnel = true;
    f3.method = "CONNECT";
    f3.host = "1.2.3.4";
    f3.sni = "cdn.example.net";
    const auto m = [](const std::string& expr, const TrafficProxy::Flow& f, const flowfilter::Context* ctx = nullptr) {
        std::string err;
        auto filter = flowfilter::Filter::parse(expr, err);
        return filter && filter->match(f, ctx);
    };
    CHECK(m("~d api & ~m GET", f1) && !m("~d api & ~m GET", f2), "domain and method");
    CHECK(m("~d api ~m GET", f1), "juxtaposition means and");
    CHECK(m("~c 500 | ~e", f2) && !m("~c 500 | ~e", f1), "status or error");
    CHECK(!m("!~tcp", f3) && m("!~tcp", f1) && m("~tcp", f3), "not / tunnels");
    CHECK(m("~d cdn.example", f3), "domain matches the TLS server name");
    CHECK(m("~u \"/users/[0-9]+$\"", f1) && !m("~u \"/users/[0-9]+$\"", f2), "quoted regex");
    CHECK(m("login", f2) && !m("login", f1), "a bare word matches the URL");
    CHECK(m("~ts json & !~a", f1) && m("~t HTML", f2), "content types, case-insensitive");
    CHECK(m("~bs token", f1) && !m("~bq token", f1) && m("~hq \"^authorization: bearer\"", f1), "bodies and headers");
    CHECK(m("(~m POST | ~m PUT) & ~d example.org", f2) && !m("(~m POST | ~m PUT) & ~d example.org", f1), "grouping");
    std::string err;
    CHECK(flowfilter::Filter::parse("~bs token", err)->needsContent() && !flowfilter::Filter::parse("~d x & ~c 200", err)->needsContent(),
          "content filters are flagged");
    CHECK(!flowfilter::Filter::parse("~zz x", err) && err.find("unknown filter") != std::string::npos, "unknown filter reported");
    CHECK(!flowfilter::Filter::parse("(~m GET", err) && err.find(")") != std::string::npos, "missing parenthesis reported");
    CHECK(!flowfilter::Filter::parse("~c abc", err), "status code must be a number");
    CHECK(!flowfilter::Filter::parse("~u \"(\"", err) && err.find("regex") != std::string::npos, "bad regex reported");
    CHECK(flowfilter::looksLikeExpression("~d x") && flowfilter::looksLikeExpression("!~a") &&
              !flowfilter::looksLikeExpression("a~b") && !flowfilter::looksLikeExpression("plain text"),
          "expression detection");
    flowfilter::Context ctx;
    ctx.marked = [](uint64_t id) { return id == 2; };
    ctx.comment = [](uint64_t id) { return id == 2 ? std::string("check later") : std::string(); };
    CHECK(m("~marked", f2, &ctx) && !m("~marked", f1, &ctx) && m("~comment later", f2, &ctx), "marks and comments");
}

static void testFlowArchive() {
    std::printf("== HAR sessions ==\n");
    CHECK(flowarchive::isoTime(1700000000.25) == "2023-11-14T22:13:20.250Z", "ISO time written");
    CHECK(std::fabs(flowarchive::parseIsoTime("2023-11-14T22:13:20.250Z") - 1700000000.25) < 0.001 &&
              std::fabs(flowarchive::parseIsoTime("2023-11-15T00:13:20.250+02:00") - 1700000000.25) < 0.001,
          "ISO time read (with zone offsets)");
    // A gzip response must survive the round trip byte for byte.
    std::string gz;
    {
        size_t n = 0;
        const std::string plain = "{\"hello\":\"world\"}";
        void* c = tdefl_compress_mem_to_heap(plain.data(), plain.size(), &n, TDEFL_WRITE_ZLIB_HEADER);
        gz.assign(static_cast<const char*>(c), n);
        mz_free(c);
    }
    auto f = makeFlow(9, "POST", "api.example.com", "/v1/x?q=1&r=two%20words", 201, "application/json", gz);
    f.response.headers.push_back({"Content-Encoding", "deflate"});
    f.request.body = "a=1";
    f.request.bodySize = 3;
    f.durationMs = 42.5;
    f.startedAt = 1700000000.0;
    f.websocket = true;
    f.wsFrames.push_back({true, 1, 5, "hello", 1700000001.0});
    f.wsFrames.push_back({false, 2, 3, std::string("\x00\x01\x02", 3), 1700000002.0});
    TrafficProxy::Flow t;
    t.id = 10;
    t.tunnel = true;
    t.method = "CONNECT";
    t.host = "10.0.0.1";
    t.port = 443;
    t.sni = "secure.example.com";
    t.tlsError = "pinned";
    t.complete = true;
    const std::string har = flowarchive::toHar({f, t});
    Json parsed;
    CHECK(Json::parse(har, parsed) && parsed.get("log").get("version").asString("") == "1.2" &&
              parsed.get("log").get("entries").size() == 2,
          "HAR 1.2 written");
    const Json& e0 = parsed.get("log").get("entries")[0];
    CHECK(e0.get("response").get("content").get("text").asString("") == "{\"hello\":\"world\"}",
          "standard content.text is the decoded body");
    CHECK(e0.get("request").get("queryString").size() == 2 &&
              e0.get("request").get("queryString")[1].get("value").asString("") == "two words",
          "query string listed");
    std::vector<TrafficProxy::Flow> back;
    std::string err;
    CHECK(flowarchive::fromHar(har, back, err) && back.size() == 2, ("HAR read back: " + err).c_str());
    if (back.size() == 2) {
        const auto& b = back[0];
        CHECK(b.method == "POST" && b.host == "api.example.com" && b.path == "/v1/x?q=1&r=two%20words" && b.status == 201 &&
                  b.response.body == gz && b.response.header("content-encoding") == "deflate" && b.request.body == "a=1" &&
                  std::fabs(b.durationMs - 42.5) < 0.01 && std::fabs(b.startedAt - 1700000000.0) < 0.01,
              "ApkSpy flows round-trip unchanged (raw bodies kept)");
        CHECK(b.websocket && b.wsFrames.size() == 2 && b.wsFrames[0].preview == "hello" && b.wsFrames[0].fromClient &&
                  b.wsFrames[1].preview == std::string("\x00\x01\x02", 3) && !b.wsFrames[1].fromClient,
              "WebSocket frames round-trip");
        CHECK(back[1].tunnel && back[1].sni == "secure.example.com" && back[1].tlsError == "pinned" && back[1].port == 443,
              "tunnel details round-trip");
    }
    // A HAR from another tool: decoded bodies, so encodings are dropped.
    const std::string foreign = R"({"log":{"version":"1.2","entries":[{"startedDateTime":"2024-01-02T03:04:05.000Z","time":12,
        "request":{"method":"GET","url":"https://shop.example.com:8443/api?id=3","httpVersion":"HTTP/2","headers":[
          {"name":":authority","value":"shop.example.com"},{"name":"Accept","value":"*/*"}]},
        "response":{"status":200,"statusText":"OK","httpVersion":"HTTP/2","headers":[{"name":"Content-Encoding","value":"br"},
          {"name":"Content-Type","value":"application/json"}],"content":{"size":9,"mimeType":"application/json","text":"eyJhIjoxfQ==","encoding":"base64"}}}]}})";
    back.clear();
    CHECK(flowarchive::fromHar(foreign, back, err) && back.size() == 1, "foreign HAR read");
    if (back.size() == 1) {
        const auto& b = back[0];
        CHECK(b.https && b.host == "shop.example.com" && b.port == 8443 && b.path == "/api?id=3" &&
                  b.response.header("content-encoding").empty() && b.response.body == "{\"a\":1}" &&
                  b.request.header(":authority").empty() && b.request.header("accept") == "*/*",
              "foreign bodies readable; encodings and pseudo-headers dropped");
        CHECK(TrafficProxy::decodeBody(b.response, nullptr) == "{\"a\":1}", "imported body decodes as is");
    }
    CHECK(!flowarchive::fromHar("{\"nope\":1}", back, err) && err.find("HAR") != std::string::npos, "non-HAR rejected");
    // Imported flows join the proxy's list with fresh ids.
    TrafficProxy proxy;
    std::vector<TrafficProxy::Flow> two = {f, t};
    CHECK(proxy.importFlows(two) == 2 && proxy.flows().size() == 2 && proxy.flows()[0].id == 1 && proxy.flows()[1].id == 2,
          "flows imported with fresh ids");
    CHECK(proxy.selectFlows([](const TrafficProxy::Flow& x) { return x.tunnel; }).size() == 1 &&
              proxy.fullFlows({1, 2, 99}).size() == 2,
          "select / full copies of flows");
}

// A tiny HTTP origin: answers `count` requests (one per connection) with
// "ok:<path>" and records each request head.
struct MiniOrigin {
    Socket listener;
    int port = 0;
    std::vector<std::string> seen;
    std::thread thread;
    void start(int count) {
        std::string err;
        listener.listenLoopback(0, err);
        port = listener.localPort();
        thread = std::thread([this, count] {
            for (int i = 0; i < count; ++i) {
                Socket c = listener.accept(5000);
                if (!c.valid()) return;
                std::string req;
                char buf[4096];
                while (req.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
                    const long n = c.recvSome(buf, sizeof buf);
                    if (n <= 0) break;
                    req.append(buf, (size_t)n);
                }
                seen.push_back(req);
                const size_t sp1 = req.find(' '), sp2 = req.find(' ', sp1 + 1);
                const std::string body = "ok:" + (sp1 == std::string::npos ? std::string() : req.substr(sp1 + 1, sp2 - sp1 - 1));
                c.sendAll("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +
                          "\r\n\r\n" + body);
            }
        });
    }
    void join() {
        if (thread.joinable()) thread.join();
    }
};

static bool waitFlows(TrafficProxy& p, size_t n) {
    for (int i = 0; i < 300; ++i) {
        auto fl = p.flows();
        if (fl.size() >= n && fl.back().complete) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

static void testProxyModes() {
    std::printf("== proxy modes: SOCKS5, upstream, reverse ==\n");
    std::string err;
    TrafficProxy::Mode mode;
    CHECK(TrafficProxy::parseReverseTarget("https://api.example.com:8443/", mode, err) && mode.reverse() && mode.reverseTls &&
              mode.reverseHost == "api.example.com" && mode.reversePort == 8443,
          "reverse target parsed");
    CHECK(!TrafficProxy::parseReverseTarget("api.example.com", mode, err) && !TrafficProxy::parseReverseTarget("http://x/path", mode, err),
          "bad reverse targets rejected");
    CHECK(TrafficProxy::parseUpstream("http://10.0.0.2:3128", mode, err) && mode.chained() && mode.upstreamPort == 3128 &&
              TrafficProxy::parseUpstream("", mode, err) && !mode.chained() && !TrafficProxy::parseUpstream("nohost", mode, err),
          "upstream proxy parsed");

    // SOCKS5 -> plain HTTP request.
    {
        MiniOrigin origin;
        origin.start(1);
        TrafficProxy proxy;
        CHECK(proxy.start(0, err), "proxy starts");
        Socket c;
        c.connectLoopback(proxy.port(), 2000, err);
        c.sendAll(std::string("\x05\x01\x00", 3));
        char buf[64];
        long n = c.waitReadable(3000) ? c.recvSome(buf, 2) : 0;
        CHECK(n == 2 && buf[0] == 5 && buf[1] == 0, "SOCKS5 greeting accepted (no auth)");
        std::string req("\x05\x01\x00\x01\x7f\x00\x00\x01", 8);
        req += static_cast<char>(origin.port >> 8);
        req += static_cast<char>(origin.port & 0xff);
        c.sendAll(req);
        std::string rep;
        while (rep.size() < 10 && c.waitReadable(3000)) {
            n = c.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            rep.append(buf, (size_t)n);
        }
        CHECK(rep.size() == 10 && rep[1] == 0, "SOCKS5 CONNECT succeeded");
        c.sendAll("GET /via-socks HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(origin.port) + "\r\n\r\n");
        const std::string resp = readAllFrom(c);
        CHECK(resp.find("ok:/via-socks") != std::string::npos, "HTTP over SOCKS5 relayed");
        origin.join();
        CHECK(waitFlows(proxy, 1) && proxy.flows()[0].path == "/via-socks" && proxy.flows()[0].status == 200,
              "HTTP over SOCKS5 recorded as a flow");
        // SOCKS5 with a domain name, carrying a non-HTTP protocol: blind relay.
        Socket echo;
        echo.listenLoopback(0, err);
        const int echoPort = echo.localPort();
        std::thread echoThread([&] {
            Socket e = echo.accept(5000);
            char b[256];
            if (e.valid() && e.waitReadable(3000)) {
                const long k = e.recvSome(b, sizeof b);
                if (k > 0) e.sendAll(b, (size_t)k);
            }
        });
        Socket d;
        d.connectLoopback(proxy.port(), 2000, err);
        std::string hello("\x05\x01\x00", 3);
        std::string r2("\x05\x01\x00\x03\x09" "127.0.0.1", 14);
        r2 += static_cast<char>(echoPort >> 8);
        r2 += static_cast<char>(echoPort & 0xff);
        d.sendAll(hello + r2);  // greeting and request in one write
        std::string got;
        while (got.size() < 12 && d.waitReadable(3000)) {
            n = d.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            got.append(buf, (size_t)n);
        }
        CHECK(got.size() == 12 && got[3] == 0, "SOCKS5 domain CONNECT (pipelined) succeeded");
        d.sendAll(std::string("\x01\x02raw", 5));
        got.clear();
        while (got.size() < 5 && d.waitReadable(3000)) {
            n = d.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            got.append(buf, (size_t)n);
        }
        CHECK(got == std::string("\x01\x02raw", 5), "non-HTTP SOCKS traffic relayed blind");
        d.shutdownBoth();
        echoThread.join();
        CHECK(waitFlows(proxy, 2) && proxy.flows()[1].method == "SOCKS" && proxy.flows()[1].tunnel, "SOCKS tunnel recorded");
        proxy.stop();
    }

    // Upstream chaining: client -> A -> B -> origin (plain HTTP and CONNECT).
    {
        MiniOrigin origin;
        origin.start(1);
        TrafficProxy b, a;
        CHECK(b.start(0, err) && a.start(0, err), "both proxies start");
        TrafficProxy::Mode chain;
        TrafficProxy::parseUpstream("127.0.0.1:" + std::to_string(b.port()), chain, err);
        a.setMode(chain);
        Socket c;
        c.connectLoopback(a.port(), 2000, err);
        c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.port) + "/chained HTTP/1.1\r\nHost: 127.0.0.1:" +
                  std::to_string(origin.port) + "\r\n\r\n");
        const std::string resp = readAllFrom(c);
        origin.join();
        CHECK(resp.find("ok:/chained") != std::string::npos, "plain HTTP through an upstream proxy");
        CHECK(waitFlows(a, 1) && waitFlows(b, 1) && b.flows()[0].path == "/chained", "both proxies recorded the request");
        CHECK(!origin.seen.empty() && origin.seen[0].rfind("GET /chained HTTP/1.1", 0) == 0, "origin got origin-form");
        // CONNECT through the chain: B sees the tunnel.
        Socket echo;
        echo.listenLoopback(0, err);
        const int echoPort = echo.localPort();
        std::thread echoThread([&] {
            Socket e = echo.accept(5000);
            char buf2[256];
            if (e.valid() && e.waitReadable(3000)) {
                const long k = e.recvSome(buf2, sizeof buf2);
                if (k > 0) e.sendAll(buf2, (size_t)k);
            }
        });
        Socket t;
        t.connectLoopback(a.port(), 2000, err);
        t.sendAll("CONNECT 127.0.0.1:" + std::to_string(echoPort) + " HTTP/1.1\r\nHost: x\r\n\r\n");
        char buf[256];
        long n = t.waitReadable(3000) ? t.recvSome(buf, sizeof buf) : 0;
        CHECK(n > 0 && std::string(buf, (size_t)n).find("200") != std::string::npos, "CONNECT through the chain");
        t.sendAll("ping!");
        std::string got;
        while (got.size() < 5 && t.waitReadable(3000)) {
            n = t.recvSome(buf, sizeof buf);
            if (n <= 0) break;
            got.append(buf, (size_t)n);
        }
        CHECK(got == "ping!", "tunnel bytes pass the chain");
        t.shutdownBoth();
        echoThread.join();
        CHECK(waitFlows(b, 2) && b.flows()[1].tunnel && b.flows()[1].port == echoPort, "upstream saw the CONNECT");
        a.stop();
        b.stop();
    }

    // Upstream credentials and absolute-form, seen by a fake upstream proxy.
    {
        Socket fake;
        fake.listenLoopback(0, err);
        const int fakePort = fake.localPort();
        std::string seen;
        std::thread fakeThread([&] {
            Socket c = fake.accept(5000);
            char buf[4096];
            while (c.valid() && seen.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
                const long n = c.recvSome(buf, sizeof buf);
                if (n <= 0) break;
                seen.append(buf, (size_t)n);
            }
            c.sendAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        });
        TrafficProxy a;
        a.start(0, err);
        TrafficProxy::Mode m2;
        TrafficProxy::parseUpstream("127.0.0.1:" + std::to_string(fakePort), m2, err);
        m2.upstreamAuth = "user:pass";
        a.setMode(m2);
        Socket c;
        c.connectLoopback(a.port(), 2000, err);
        c.sendAll("GET http://example.invalid:8080/x?y=1 HTTP/1.1\r\nHost: example.invalid:8080\r\n\r\n");
        const std::string resp = readAllFrom(c);
        fakeThread.join();
        CHECK(resp.find("hi") != std::string::npos, "answer from the upstream proxy relayed");
        CHECK(seen.rfind("GET http://example.invalid:8080/x?y=1 HTTP/1.1\r\n", 0) == 0 &&
                  seen.find("Proxy-Authorization: Basic dXNlcjpwYXNz") != std::string::npos,
              ("absolute form + credentials sent upstream: " + seen.substr(0, 120)).c_str());
        a.stop();
    }

    // Reverse proxy: the request goes to the fixed target, Host rewritten.
    {
        MiniOrigin origin;
        origin.start(1);
        TrafficProxy r;
        r.start(0, err);
        TrafficProxy::Mode rev;
        CHECK(TrafficProxy::parseReverseTarget("http://127.0.0.1:" + std::to_string(origin.port), rev, err), "reverse mode set");
        r.setMode(rev);
        Socket c;
        c.connectLoopback(r.port(), 2000, err);
        c.sendAll("GET /rev?x=1 HTTP/1.1\r\nHost: localhost:" + std::to_string(r.port()) + "\r\n\r\n");
        const std::string resp = readAllFrom(c);
        origin.join();
        CHECK(resp.find("ok:/rev?x=1") != std::string::npos, "reverse proxy relays to the target");
        CHECK(!origin.seen.empty() && origin.seen[0].find("Host: 127.0.0.1:" + std::to_string(origin.port)) != std::string::npos,
              "Host header rewritten to the target");
        CHECK(waitFlows(r, 1) && r.flows()[0].host == "127.0.0.1" && r.flows()[0].port == origin.port, "reverse flow recorded");
        r.stop();
    }
}

// Hooks without Python: answer, rewrite, kill.
struct FakeHooks : TrafficProxy::Hooks {
    Verdict onRequest(const TrafficProxy::Flow&, std::string& raw, std::string& reply) override {
        if (raw.find("/local") != std::string::npos) {
            reply = "HTTP/1.1 203 Local\r\nContent-Type: text/plain\r\n\r\nfrom hook";
            return Verdict::Respond;
        }
        if (raw.find("/kill") != std::string::npos) return Verdict::Kill;
        const size_t at = raw.find("/rewrite");
        if (at != std::string::npos) {
            raw.replace(at, 8, "/rewritten");
            return Verdict::Modified;
        }
        return Verdict::Continue;
    }
    Verdict onResponse(const TrafficProxy::Flow&, const std::string&, std::string& raw) override {
        const size_t at = raw.find("ok:");
        if (at == std::string::npos) return Verdict::Continue;
        raw = raw.substr(0, raw.find("\r\n\r\n") + 4) + "OK!" + raw.substr(at + 3);
        return Verdict::Modified;
    }
    bool wantsResponses() const override { return true; }
};

static void testProxyHooks() {
    std::printf("== proxy hooks ==\n");
    std::string err;
    TrafficProxy proxy;
    proxy.start(0, err);
    proxy.setHooks(std::make_shared<FakeHooks>());
    const auto get = [&](int port, const std::string& path) {
        Socket c;
        c.connectLoopback(proxy.port(), 2000, err);
        c.sendAll("GET http://127.0.0.1:" + std::to_string(port) + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) + "\r\n\r\n");
        return readAllFrom(c);
    };
    std::string resp = get(9, "/local");  // port 9: nothing listens - the hook answers
    CHECK(resp.find("203 Local") != std::string::npos && resp.find("from hook") != std::string::npos &&
              resp.find("Content-Length: 9") != std::string::npos,
          "a hook answers without the server");
    resp = get(9, "/kill");
    CHECK(resp.empty(), "a killed request gets no answer");
    MiniOrigin origin;
    origin.start(1);
    resp = get(origin.port, "/rewrite");
    origin.join();
    CHECK(!origin.seen.empty() && origin.seen[0].rfind("GET /rewritten", 0) == 0, "the hook's rewritten request went out");
    CHECK(resp.find("OK!/rewritten") != std::string::npos && resp.find("Content-Length: 13") != std::string::npos,
          ("the hook's rewritten response reached the client: " + resp).c_str());
    CHECK(waitFlows(proxy, 3), "hook flows complete");
    auto flows = proxy.flows();
    CHECK(flows.size() == 3 && flows[0].status == 203 && flows[0].edited && flows[1].error == "killed by a script" &&
              flows[2].edited && flows[2].path == "/rewritten",
          "hook outcomes recorded on the flows");
    proxy.stop();
}

static void testTrafficScripts() {
    std::printf("== traffic scripts (Python) ==\n");
    // Message <-> JSON, no Python needed.
    const std::string raw = "POST /a?b=1 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    Json j;
    CHECK(Json::parse(trafficscript::Host::messageJson(raw, false), j) && j.get("method").asString("") == "POST" &&
              j.get("path").asString("") == "/a?b=1" && j.get("content_decoded").asBool(false),
          "request to script JSON (body dechunked)");
    std::string out;
    CHECK(codec::base64Decode(j.get("body_b64").asString(""), out) && out == "hello", "decoded body handed to the script");
    std::string err;
    const std::string rebuilt = trafficscript::Host::rebuild(j.dump(), false, err);
    CHECK(rebuilt == "POST /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", ("rebuilt request: " + rebuilt).c_str());
    CHECK(trafficscript::Host::rebuild("{\"method\":\"GET\",\"path\":\"/x y\"}", false, err).empty(), "invalid start line refused");

    trafficscript::Host probe;
    const fs::path dir = fs::temp_directory_path() / "apkspy-script-test";
    fs::create_directories(dir);
    const fs::path script = dir / "hooks.py";
    {
        std::ofstream s(script, std::ios::binary);
        s << "from apkspy_addon import Response, ctx\n"
             "def request(flow):\n"
             "    if flow.request.path == '/local':\n"
             "        flow.response = Response.make(200, b'scripted', {'Content-Type': 'text/plain'})\n"
             "        return\n"
             "    flow.request.headers['X-Script'] = 'yes'\n"
             "    q = flow.request.query\n"
             "    q['added'] = '1'\n"
             "    flow.request.query = q\n"
             "def response(flow):\n"
             "    ctx.log('saw', flow.request.path, flow.response.status_code)\n"
             "    flow.response.text = flow.response.text.upper()\n"
             "    flow.response.headers['X-Seen'] = flow.request.headers.get('x-script', '')\n";
    }
    if (proc::run({"python", "--version"}, 10000).exitCode != 0) {
        std::printf("  (no python on PATH: script host skipped)\n");
        return;
    }
    auto host = std::make_shared<trafficscript::Host>();
    const bool started = host->start("python", {pathutil::toUtf8(script)}, pathutil::toUtf8(dir / "support"), err);
    CHECK(started && host->hasRequestHook() && host->hasResponseHook(), ("script loaded: " + err).c_str());
    if (!started) {
        for (const auto& l : host->takeLog()) std::printf("    %s\n", l.c_str());
        return;
    }
    TrafficProxy proxy;
    proxy.start(0, err);
    proxy.setHooks(host);
    MiniOrigin origin;
    origin.start(1);
    Socket c;
    c.connectLoopback(proxy.port(), 2000, err);
    c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.port) + "/p?x=2 HTTP/1.1\r\nHost: 127.0.0.1:" +
              std::to_string(origin.port) + "\r\n\r\n");
    std::string resp = readAllFrom(c, 8000);
    origin.join();
    CHECK(!origin.seen.empty() && origin.seen[0].rfind("GET /p?x=2&added=1 HTTP/1.1", 0) == 0 &&
              origin.seen[0].find("X-Script: yes") != std::string::npos,
          ("request changed by the script: " + (origin.seen.empty() ? std::string() : origin.seen[0].substr(0, 80))).c_str());
    CHECK(resp.find("OK:/P?X=2&ADDED=1") != std::string::npos && resp.find("X-Seen: yes") != std::string::npos,
          ("response changed by the script: " + resp).c_str());
    Socket d;
    d.connectLoopback(proxy.port(), 2000, err);
    d.sendAll("GET http://127.0.0.1:9/local HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n");
    resp = readAllFrom(d, 8000);
    CHECK(resp.find("200 OK") != std::string::npos && resp.find("scripted") != std::string::npos, "script answered a request itself");
    bool logged = false;
    for (int i = 0; i < 100 && !logged; ++i) {
        for (const auto& l : host->takeLog()) logged |= l.find("saw /p") != std::string::npos;
        if (!logged) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(logged, "ctx.log output reaches the log");
    // A broken script: the error is reported, the proxy is unaffected.
    {
        std::ofstream s(dir / "broken.py", std::ios::binary);
        s << "def request(flow)\n    return\n";  // missing colon: a SyntaxError on load
    }
    trafficscript::Host broken;
    CHECK(!broken.start("python", {pathutil::toUtf8(dir / "broken.py")}, pathutil::toUtf8(dir / "support"), err) &&
              err.find("failed to load") != std::string::npos,
          ("a script that does not load is reported: " + err).c_str());
    proxy.stop();
    host->stop();
    CHECK(!host->running(), "script host stops");
    std::error_code ec;
    fs::remove_all(dir, ec);
}

}  // namespace

// ---------------------------------------------------------------------------
// Proxy tools, round 2: decoders, WebSocket, routing, replay, exports,
// content views, conditions, limits, raw TCP / UDP / DNS, h2c, scripts
// ---------------------------------------------------------------------------
#include "debug/Http2.hpp"
#include "debug/ProtoSchema.hpp"
namespace {

static std::string unhex(const std::string& h) {
    std::string out;
    codec::hexDecode(h, out);
    return out;
}

static void testBodyDecoders() {
    std::printf("== brotli / zstd bodies ==\n");
    TrafficProxy::Message m;
    m.headers = {{"Content-Encoding", "br"}};
    m.body = unhex("1b760000144aac9b7abde1979d7f8ec282360e9ce09003f78b9e38e6b600abc3caa0c2da6636dccd808d2e21d76ee3ea4cb8f0d2b8c7c2704d3af0697ea1b84573abc4571e");
    std::string note;
    const std::string plain = TrafficProxy::decodeBody(m, &note);
    CHECK(plain.rfind("ukko nooa, ukko nooa oli kunnon mies", 0) == 0 && plain.size() == 119 && note.find("decoded from br") != std::string::npos,
          ("brotli body decoded: " + note).c_str());
    TrafficProxy::Message z;
    z.headers = {{"Content-Encoding", "zstd"}};
    z.body = unhex("28b52ffd201081000068656c6c6f207a73746420776f726c64");
    CHECK(TrafficProxy::decodeBody(z, &note) == "hello zstd world", "zstd body decoded");
    z.body = "garbage";
    TrafficProxy::decodeBody(z, &note);
    CHECK(note.find("could not decode") != std::string::npos, "bad zstd reported");
}

// A WebSocket origin: answers the upgrade, then echoes each client message
// as "echo:<payload>" until the client closes.
struct WsOrigin {
    Socket listener;
    int port = 0;
    std::string upgradeRequest;
    std::vector<std::string> received;
    std::thread thread;
    void start() {
        std::string err;
        listener.listenLoopback(0, err);
        port = listener.localPort();
        thread = std::thread([this] {
            Socket c = listener.accept(5000);
            if (!c.valid()) return;
            std::string buf;
            char chunk[65536];
            while (buf.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
                const long n = c.recvSome(chunk, sizeof chunk);
                if (n <= 0) return;
                buf.append(chunk, (size_t)n);
            }
            upgradeRequest = buf.substr(0, buf.find("\r\n\r\n") + 4);
            buf.erase(0, upgradeRequest.size());
            c.sendAll("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n");
            for (;;) {
                while (buf.size() < 2 || buf.size() < 2 + 4 + (size_t)((unsigned char)buf[1] & 0x7f) +
                                                           (((unsigned char)buf[1] & 0x7f) == 126 ? 2 : 0)) {
                    if (!c.waitReadable(3000)) return;
                    const long n = c.recvSome(chunk, sizeof chunk);
                    if (n <= 0) return;
                    buf.append(chunk, (size_t)n);
                }
                const int op = buf[0] & 0x0f;
                size_t len = (unsigned char)buf[1] & 0x7f, at = 2;
                if (len == 126) len = ((unsigned char)buf[2] << 8) | (unsigned char)buf[3], at = 4;
                while (buf.size() < at + 4 + len) {
                    if (!c.waitReadable(3000)) return;
                    const long n = c.recvSome(chunk, sizeof chunk);
                    if (n <= 0) return;
                    buf.append(chunk, (size_t)n);
                }
                std::string payload = buf.substr(at + 4, len);
                for (size_t i = 0; i < payload.size(); ++i) payload[i] = (char)(payload[i] ^ buf[at + (i % 4)]);
                buf.erase(0, at + 4 + len);
                if (op == 8) return;
                received.push_back(payload);
                c.sendAll(TrafficProxy::wsFrame(1, "echo:" + payload, false));
            }
        });
    }
    void join() {
        if (thread.joinable()) thread.join();
    }
};

// Reads one unmasked server frame from the client side.
static bool readServerFrame(Socket& s, std::string& buf, std::string& payload) {
    char chunk[65536];
    for (;;) {
        if (buf.size() >= 2) {
            size_t len = (unsigned char)buf[1] & 0x7f, at = 2;
            if (len == 126 && buf.size() >= 4) len = ((unsigned char)buf[2] << 8) | (unsigned char)buf[3], at = 4;
            if (len != 126 && buf.size() >= at + len) {
                payload = buf.substr(at, len);
                buf.erase(0, at + len);
                return true;
            }
        }
        if (!s.waitReadable(3000)) return false;
        const long n = s.recvSome(chunk, sizeof chunk);
        if (n <= 0) return false;
        buf.append(chunk, (size_t)n);
    }
}

struct WsHooks : TrafficProxy::Hooks {
    Verdict onRequest(const TrafficProxy::Flow&, std::string&, std::string&) override { return Verdict::Continue; }
    Verdict onResponse(const TrafficProxy::Flow&, const std::string&, std::string&) override { return Verdict::Continue; }
    bool wantsResponses() const override { return false; }
    Verdict onWebSocket(const TrafficProxy::Flow&, bool fromClient, int, std::string& payload) override {
        if (fromClient && payload == "drop me") return Verdict::Kill;
        if (fromClient && payload == "rewrite me") {
            payload = "rewritten";
            return Verdict::Modified;
        }
        return Verdict::Continue;
    }
    bool wantsWebSocket() const override { return true; }
};

static void testWebSocketTools() {
    std::printf("== WebSocket: payloads, hooks, injection, intercept ==\n");
    const std::string f = TrafficProxy::wsFrame(1, std::string(300, 'x'), false);
    CHECK(f.size() == 4 + 300 && (unsigned char)f[0] == 0x81 && (unsigned char)f[1] == 126, "frame header with 16-bit length");
    std::string err;
    WsOrigin origin;
    origin.start();
    TrafficProxy proxy;
    proxy.start(0, err);
    proxy.setHooks(std::make_shared<WsHooks>());
    Socket c;
    c.connectLoopback(proxy.port(), 2000, err);
    c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.port) + "/ws HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(origin.port) +
              "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n"
              "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n");
    std::string buf;
    char chunk[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
        const long n = c.recvSome(chunk, sizeof chunk);
        if (n <= 0) break;
        buf.append(chunk, (size_t)n);
    }
    CHECK(buf.find("101") != std::string::npos, "upgrade relayed");
    buf.erase(0, buf.find("\r\n\r\n") + 4);
    CHECK(origin.upgradeRequest.find("Connection: Upgrade") != std::string::npos &&
              origin.upgradeRequest.find("permessage-deflate") == std::string::npos,
          "upstream gets Connection: Upgrade and no compression offer");
    std::string payload;
    const std::string big(3000, 'b');
    c.sendAll(TrafficProxy::wsFrame(1, big, true));
    CHECK(readServerFrame(c, buf, payload) && payload == "echo:" + big, "a message round-trips");
    c.sendAll(TrafficProxy::wsFrame(1, "rewrite me", true));
    CHECK(readServerFrame(c, buf, payload) && payload == "echo:rewritten", "a hook rewrote a message");
    c.sendAll(TrafficProxy::wsFrame(1, "drop me", true));
    c.sendAll(TrafficProxy::wsFrame(1, "after", true));
    CHECK(readServerFrame(c, buf, payload) && payload == "echo:after", "a hook dropped a message");
    // Injection both ways.
    uint64_t wsId = 0;
    for (int i = 0; i < 100 && !wsId; ++i) {
        for (const auto& fl : proxy.flows())
            if (fl.websocket) wsId = fl.id;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(proxy.webSocketLive(wsId), "connection live");
    CHECK(proxy.injectWebSocket(wsId, false, 1, "to the app", err) && readServerFrame(c, buf, payload) && payload == "to the app",
          "message injected to the app");
    CHECK(proxy.injectWebSocket(wsId, true, 1, "to the server", err) && readServerFrame(c, buf, payload) && payload == "echo:to the server",
          "message injected to the server");
    // Intercept: hold the next client message, edit it, forward it.
    proxy.setIntercept(false, false, "", true);
    c.sendAll(TrafficProxy::wsFrame(1, "hold me", true));
    TrafficProxy::Held held;
    for (int i = 0; i < 300 && held.id == 0; ++i) {
        for (const auto& h : proxy.held())
            if (h.websocket) held = h;
        if (!held.id) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(held.id && held.raw == "hold me" && !held.response, "client message held at the intercept");
    proxy.forward(held.id, "edited at intercept");
    // The server's echo is held too (both directions are intercepted): forward it unchanged.
    held = {};
    for (int i = 0; i < 300 && held.id == 0; ++i) {
        for (const auto& h : proxy.held())
            if (h.websocket && h.response) held = h;
        if (!held.id) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(held.id && held.raw == "echo:edited at intercept", "server message held at the intercept");
    if (held.id) proxy.forward(held.id);
    CHECK(readServerFrame(c, buf, payload) && payload == "echo:edited at intercept", "edited message forwarded");
    proxy.setIntercept(false, false, "", false);
    c.sendAll(TrafficProxy::wsFrame(8, "", true));
    c.shutdownBoth();
    origin.join();
    TrafficProxy::Flow full;
    for (int i = 0; i < 300 && !(proxy.flow(wsId, full) && full.complete); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    bool sawBig = false, sawDropped = false, sawEdited = false, sawInjected = false;
    for (const auto& fr : full.wsFrames) {
        sawBig |= fr.preview == big;
        sawDropped |= fr.dropped && fr.preview == "drop me";
        sawEdited |= fr.edited && fr.preview == "rewritten";
        sawInjected |= fr.injected;
    }
    CHECK(sawBig && sawDropped && sawEdited && sawInjected, "frames recorded whole, with dropped / edited / injected marks");
    CHECK(origin.received.size() >= 5 && std::find(origin.received.begin(), origin.received.end(), "drop me") == origin.received.end(),
          "the dropped message never reached the server");
    proxy.stop();
}

static void testRoutingAndReplay() {
    std::printf("== routing: hosts, map local / remote, server replay ==\n");
    CHECK(TrafficProxy::globMatch("https://api.*.com/v1/*", "https://api.example.com/v1/users?x=1") &&
              !TrafficProxy::globMatch("https://api.*.com/v2/*", "https://api.example.com/v1/users"),
          "URL globs");
    CHECK(TrafficProxy::hostMatches("googleapis.com", "firebase.googleapis.com") && TrafficProxy::hostMatches("googleapis.com", "googleapis.com") &&
              !TrafficProxy::hostMatches("googleapis.com", "notgoogleapis.com") && TrafficProxy::hostMatches("*.cdn.net", "a.b.cdn.net"),
          "host patterns cover subdomains");
    TrafficProxy::Routing r;
    r.ignoreHosts = {"google.com"};
    CHECK(!r.intercepts("www.google.com") && r.intercepts("api.example.com"), "ignore list");
    r.allowHosts = {"example.com"};
    CHECK(r.intercepts("api.example.com") && !r.intercepts("other.org"), "allow list");

    std::string err;
    const fs::path dir = fs::temp_directory_path() / "apkspy-maplocal";
    fs::create_directories(dir / "static");
    {
        std::ofstream(dir / "config.json", std::ios::binary) << "{\"mocked\":true}";
        std::ofstream(dir / "static" / "app.js", std::ios::binary) << "console.log(1)";
    }
    TrafficProxy proxy;
    proxy.start(0, err);
    TrafficProxy::Routing routing;
    routing.mapLocal.push_back({true, "http://mock.invalid/config*", pathutil::toUtf8(dir / "config.json"), ""});
    routing.mapLocal.push_back({true, "http://mock.invalid/static/*", pathutil::toUtf8(dir / "static"), ""});
    MiniOrigin origin;
    origin.start(1);
    routing.mapRemote.push_back({true, "http://remote.invalid/api", "http://127.0.0.1:" + std::to_string(origin.port) + "/v2"});
    proxy.setRouting(routing);
    const auto get = [&](const std::string& url, const std::string& host) {
        Socket c;
        c.connectLoopback(proxy.port(), 2000, err);
        c.sendAll("GET " + url + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
        return readAllFrom(c);
    };
    std::string resp = get("http://mock.invalid/config?v=1", "mock.invalid");
    CHECK(resp.find("200 OK") != std::string::npos && resp.find("{\"mocked\":true}") != std::string::npos &&
              resp.find("application/json") != std::string::npos,
          "map local answers from a file");
    resp = get("http://mock.invalid/static/app.js", "mock.invalid");
    CHECK(resp.find("console.log(1)") != std::string::npos && resp.find("javascript") != std::string::npos, "map local from a directory");
    resp = get("http://mock.invalid/static/missing.js", "mock.invalid");
    CHECK(resp.find("404") != std::string::npos, "missing mapped file: 404");
    resp = get("http://remote.invalid/api/users", "remote.invalid");
    origin.join();
    CHECK(resp.find("ok:/v2/users") != std::string::npos && !origin.seen.empty() &&
              origin.seen[0].find("Host: 127.0.0.1:" + std::to_string(origin.port)) != std::string::npos,
          "map remote rewrote the target, path and Host");
    CHECK(waitFlows(proxy, 4) && proxy.flows()[3].note.find("map remote") != std::string::npos && proxy.flows()[0].note.find("map local") != std::string::npos,
          "mapped flows say what happened");

    // Server replay: the recorded response answers; unmatched ones are refused.
    proxy.setRouting({});
    TrafficProxy::Flow rec;
    rec.method = "GET";
    rec.host = "replay.invalid";
    rec.port = 80;
    rec.path = "/data?x=1";
    rec.status = 200;
    rec.response.startLine = "HTTP/1.1 200 OK";
    rec.response.headers = {{"Content-Type", "text/plain"}, {"Content-Length", "8"}};
    rec.response.body = "recorded";
    TrafficProxy::ReplayOptions opts;
    opts.refuseUnmatched = true;
    proxy.setServerReplay({rec}, opts);
    CHECK(proxy.serverReplayLeft() == 1, "one recorded response loaded");
    resp = get("http://replay.invalid/data?x=1", "replay.invalid");
    CHECK(resp.find("recorded") != std::string::npos && proxy.serverReplayLeft() == 0, "recorded response replayed (and used up)");
    resp = get("http://replay.invalid/data?x=1", "replay.invalid");
    CHECK(resp.find("404") != std::string::npos, "used response not reused; unmatched refused");
    opts.reuse = true;
    opts.ignoreQuery = true;
    proxy.setServerReplay({rec}, opts);
    resp = get("http://replay.invalid/data?other=2", "replay.invalid");
    std::string resp2 = get("http://replay.invalid/data", "replay.invalid");
    CHECK(resp.find("recorded") != std::string::npos && resp2.find("recorded") != std::string::npos, "reuse + ignore query");
    proxy.clearServerReplay();
    proxy.stop();
    std::error_code ec;
    fs::remove_all(dir, ec);
}

static void testExportsAndMarks() {
    std::printf("== copy as / HAR marks ==\n");
    auto f = makeFlow(5, "POST", "api.example.com", "/v1/login?x=1", 200, "application/json", "{}");
    f.request.headers = {{"Host", "api.example.com"}, {"Content-Type", "application/json"}, {"Content-Length", "13"}, {"X-Key", "it's"}};
    f.request.body = "{\"user\":\"a\"}";
    f.request.bodySize = f.request.body.size();
    using flowexport::Format;
    const std::string curl = flowexport::render(Format::Curl, f);
    CHECK(curl.find("curl -X POST 'http://api.example.com/v1/login?x=1'") == 0 && curl.find("'X-Key: it'\\''s'") != std::string::npos &&
              curl.find("Content-Length") == std::string::npos && curl.find("--data-binary") != std::string::npos,
          ("cURL: " + curl).c_str());
    const std::string py = flowexport::render(Format::PythonRequests, f);
    CHECK(py.find("requests.request(") != std::string::npos && py.find("\"X-Key\": \"it's\"") != std::string::npos &&
              py.find("data=\"{\\\"user\\\":\\\"a\\\"}\".encode()") != std::string::npos,
          ("python: " + py).c_str());
    const std::string js = flowexport::render(Format::Fetch, f);
    CHECK(js.find("await fetch(\"http://api.example.com/v1/login?x=1\"") != std::string::npos && js.find("method: \"POST\"") != std::string::npos,
          "fetch");
    const std::string ps = flowexport::render(Format::PowerShell, f);
    CHECK(ps.find("Invoke-WebRequest -Uri 'http://api.example.com/v1/login?x=1' -Method POST") != std::string::npos &&
              ps.find("'it''s'") != std::string::npos && ps.find("-ContentType 'application/json'") != std::string::npos,
          ("powershell: " + ps).c_str());
    CHECK(flowexport::render(Format::Httpie, f).find("http POST") != std::string::npos &&
              flowexport::render(Format::Raw, f).rfind("POST /v1/login?x=1 HTTP/1.1\r\n", 0) == 0,
          "httpie / raw");
    flowarchive::Marks marks;
    marks[5] = {3, "check this"};
    const std::string har = flowarchive::toHar({f}, &marks);
    std::vector<TrafficProxy::Flow> back;
    std::vector<flowarchive::Mark> got;
    std::string err;
    CHECK(flowarchive::fromHar(har, back, err, &got) && got.size() == 1 && got[0].color == 3 && got[0].comment == "check this",
          "highlight and comment saved in HAR");
}

static void testContentViews2() {
    std::printf("== content views: JWT, GraphQL, CBOR, DNS, .proto ==\n");
    // {"alg":"HS256","typ":"JWT"} . {"sub":"42","exp":1700000000}
    const std::string jwtTok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImV4cCI6MTcwMDAwMDAwMH0.c2lnbmF0dXJl";
    std::string out;
    CHECK(contentview::jwt("Bearer " + jwtTok, out) && out.find("\"sub\": \"42\"") != std::string::npos &&
              out.find("exp = 2023-11-14 22:13:20 UTC  (expired)") != std::string::npos,
          ("JWT decoded: " + out).c_str());
    CHECK(contentview::detect(jwtTok, "text/plain") == contentview::View::Jwt, "a bare JWT body is detected");
    const std::string gql = "{\"operationName\":\"Me\",\"query\":\"query Me { me { id name } }\",\"variables\":{\"a\":1}}";
    CHECK(contentview::graphql(gql, out) && out.find("operation: Me") != std::string::npos && out.find("me {") != std::string::npos &&
              out.find("variables:") != std::string::npos && contentview::detect(gql, "application/json") == contentview::View::GraphQL,
          ("GraphQL: " + out).c_str());
    // CBOR {"a": [1, -2, "x"], "b": true, "c": 1.5 (half)}
    const std::string cb = unhex("a3616183012161786162f56163f93e00");
    CHECK(contentview::cbor(cb, out) && out.find("\"a\": [") != std::string::npos && out.find("-2") != std::string::npos &&
              out.find("\"x\"") != std::string::npos && out.find("true") != std::string::npos && out.find("1.5") != std::string::npos,
          ("CBOR: " + out).c_str());
    // DNS: a query for example.com A, and an answer 93.184.216.34.
    const std::string q = unhex("abcd01000001000000000000076578616d706c6503636f6d0000010001");
    const std::string a = unhex("abcd81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d822");
    CHECK(contentview::dnsName(q) == "example.com" && contentview::dnsSummary(q) == "A? example.com", "DNS query summary");
    CHECK(contentview::dnsSummary(a) == "A 93.184.216.34" && contentview::dns(a, out) && out.find("answer: example.com A 93.184.216.34") != std::string::npos,
          ("DNS answer: " + out).c_str());
    // AAAA 2606:4700::6810:84e5 (zero groups compressed)
    const std::string aaaa = unhex("abcd81800001000100000000076578616d706c6503636f6d00001c0001c00c001c00010000012c0010260647000000000000000000681084e5");
    CHECK(contentview::dnsSummary(aaaa) == "AAAA 2606:4700::6810:84e5", ("IPv6 compressed: " + contentview::dnsSummary(aaaa)).c_str());
    CHECK(contentview::graphql("{\"query\":\"query { me { id name friends(first: 2) { id } } }\"}", out) &&
              out.find("    id\n    name\n    friends(first: 2) {") != std::string::npos,
          ("GraphQL fields one per line: " + out).c_str());
    TrafficProxy::Flow dnsFlow;
    dnsFlow.method = "DNS";
    dnsFlow.transport = "udp";
    dnsFlow.host = "1.1.1.1";
    dnsFlow.port = 53;
    dnsFlow.path = "example.com";
    CHECK(dnsFlow.url() == "dns://1.1.1.1:53 example.com", ("raw flow URL: " + dnsFlow.url()).c_str());
    // .proto schema
    protoschema::Schema schema;
    std::string err;
    const std::string proto = R"(syntax = "proto3";
package shop;
// a comment
message Order {
  enum Status { UNKNOWN = 0; PAID = 2; }
  message Item { string sku = 1; uint32 qty = 2; }
  int64 id = 1;
  Status status = 2;
  repeated Item items = 3;
  repeated int32 codes = 4;
  map<string, int32> tags = 5;
  oneof payment { string card = 6; sint32 credit = 7; }
}
service Shop { rpc Get (Order) returns (Order); }
)";
    CHECK(schema.addSource(proto, "shop.proto", err), ("proto parsed: " + err).c_str());
    CHECK(schema.message("shop.Order") && schema.message("shop.Order.Item") && schema.messageNames().size() == 2, "messages named");
    // id=5, status=PAID, items {sku:"A1" qty:3}, codes packed [1,2], tags {"k":7}, credit=-3
    const std::string bytes = unhex("0805" "1002" "1a060a0241311003" "22020102" "2a050a016b1007" "3805");
    std::string decoded;
    CHECK(schema.decode(bytes, "shop.Order", decoded) && decoded.find("id: 5") != std::string::npos &&
              decoded.find("status: PAID") != std::string::npos && decoded.find("sku: \"A1\"") != std::string::npos &&
              decoded.find("codes: [1, 2]") != std::string::npos && decoded.find("tags[\"k\"]: 7") != std::string::npos &&
              decoded.find("credit: -3") != std::string::npos,
          ("schema decode: " + decoded).c_str());
    const auto rendered = contentview::render(contentview::View::Protobuf, bytes, "application/x-protobuf", &schema, "shop.Order");
    CHECK(rendered.text.find("status: PAID") != std::string::npos, "the protobuf view uses the schema");
    CHECK(!schema.addSource("message Broken { int32 x = ", "bad.proto", err) && err.find("bad.proto") != std::string::npos, "proto errors named");
}

static void testConditionsAndLimits() {
    std::printf("== network conditions / capture limits ==\n");
    std::string err;
    TrafficProxy proxy;
    proxy.start(0, err);
    TrafficProxy::Conditions c;
    c.latencyMs = 300;
    proxy.setConditions(c);
    CHECK(proxy.conditions().latencyMs == 300 && proxy.conditions().active(), "conditions set");
    MiniOrigin origin;
    origin.start(1);
    const auto t0 = std::chrono::steady_clock::now();
    {
        Socket s;
        s.connectLoopback(proxy.port(), 2000, err);
        s.sendAll("GET http://127.0.0.1:" + std::to_string(origin.port) + "/slow HTTP/1.1\r\nHost: x\r\n\r\n");
        readAllFrom(s);
    }
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    origin.join();
    CHECK(ms >= 280, ("latency added: " + std::to_string(ms) + " ms").c_str());
    c = {};
    c.failPercent = 100;
    proxy.setConditions(c);
    {
        Socket s;
        s.connectLoopback(proxy.port(), 2000, err);
        s.sendAll("GET http://127.0.0.1:9/x HTTP/1.1\r\nHost: x\r\n\r\n");
        CHECK(readAllFrom(s).find("502") != std::string::npos, "dropped connections answer 502");
    }
    proxy.setConditions({});
    // Limits: bodies capped, history trimmed.
    proxy.setLimits(100, 1024);
    CHECK(TrafficProxy::maxBody() == 1024 && proxy.maxFlows() == 100, "limits set");
    std::vector<TrafficProxy::Flow> many(150);
    proxy.importFlows(many);
    CHECK(proxy.flows().size() == 100, "history trimmed to the limit");
    proxy.setLimits(TrafficProxy::kMaxFlows, TrafficProxy::kMaxBody);
    proxy.stop();
}

static void testRawStreams() {
    std::printf("== raw TCP, SOCKS5 UDP, DNS ==\n");
    std::string err;
    TrafficProxy proxy;
    proxy.start(0, err);
    // A non-TLS protocol through CONNECT: its bytes are kept.
    Socket echo;
    echo.listenLoopback(0, err);
    const int echoPort = echo.localPort();
    std::thread echoThread([&] {
        Socket e = echo.accept(5000);
        char b[256];
        while (e.valid() && e.waitReadable(2000)) {
            const long k = e.recvSome(b, sizeof b);
            if (k <= 0) break;
            e.sendAll(b, (size_t)k);
        }
    });
    {
        Socket t;
        t.connectLoopback(proxy.port(), 2000, err);
        t.sendAll("CONNECT 127.0.0.1:" + std::to_string(echoPort) + " HTTP/1.1\r\nHost: x\r\n\r\n");
        char b[256];
        t.waitReadable(3000) && t.recvSome(b, sizeof b);
        t.sendAll("HELLO SMTP\r\n");
        std::string got;
        while (got.size() < 12 && t.waitReadable(3000)) {
            const long n = t.recvSome(b, sizeof b);
            if (n <= 0) break;
            got.append(b, (size_t)n);
        }
        CHECK(got == "HELLO SMTP\r\n", "raw TCP relayed");
    }
    echoThread.join();
    CHECK(waitFlows(proxy, 1), "tcp flow complete");
    TrafficProxy::Flow tcp;
    proxy.flow(proxy.flows()[0].id, tcp);
    CHECK(tcp.transport == "tcp" && tcp.wsFrames.size() >= 2 && tcp.wsFrames[0].preview == "HELLO SMTP\r\n" && !tcp.wsFrames[1].fromClient,
          "raw TCP bytes kept both ways");

    // SOCKS5 UDP ASSOCIATE to a fake DNS server.
    UdpSocket dnsServer;
    CHECK(dnsServer.bind(true, 0, err), "fake DNS server binds");
    const int dnsPort = dnsServer.localPort();
    const std::string query = unhex("abcd01000001000000000000076578616d706c6503636f6d0000010001");
    const std::string answer = unhex("abcd81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d822");
    std::thread dnsThread([&] {
        char b[512];
        std::string from;
        int fromPort = 0;
        if (dnsServer.waitReadable(5000) && dnsServer.recvFrom(b, sizeof b, from, fromPort) > 0) {
            std::string e;
            dnsServer.sendTo(from, fromPort, answer.data(), answer.size(), e);
        }
    });
    Socket control;
    control.connectLoopback(proxy.port(), 2000, err);
    control.sendAll(std::string("\x05\x01\x00", 3));
    char b[64];
    control.waitReadable(3000) && control.recvSome(b, 2);
    control.sendAll(std::string("\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10));
    std::string rep;
    while (rep.size() < 10 && control.waitReadable(3000)) {
        const long n = control.recvSome(b, sizeof b);
        if (n <= 0) break;
        rep.append(b, (size_t)n);
    }
    CHECK(rep.size() == 10 && rep[1] == 0, "UDP ASSOCIATE accepted");
    const int relayPort = ((unsigned char)rep[8] << 8) | (unsigned char)rep[9];
    UdpSocket client;
    client.bind(true, 0, err);
    std::string pkt("\x00\x00\x00\x01\x7f\x00\x00\x01", 8);
    pkt += (char)(dnsPort >> 8);
    pkt += (char)(dnsPort & 0xff);
    pkt += query;
    CHECK(client.sendTo("127.0.0.1", relayPort, pkt.data(), pkt.size(), err), "datagram sent to the relay");
    char rb[1024];
    std::string from;
    int fromPort = 0;
    long n = client.waitReadable(3000) ? client.recvFrom(rb, sizeof rb, from, fromPort) : -1;
    CHECK(n == (long)(10 + answer.size()) && std::string(rb + 10, (size_t)n - 10) == answer, "DNS answer relayed back with the SOCKS header");
    dnsThread.join();
    control.shutdownBoth();
    for (int i = 0; i < 300 && !(proxy.flows().size() >= 2 && proxy.flows().back().complete); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    TrafficProxy::Flow udp;
    if (proxy.flows().size() >= 2) proxy.flow(proxy.flows()[1].id, udp);
    // (the fake server is on a non-53 port: a UDP flow; the DNS view still reads it)
    CHECK(udp.transport == "udp" && udp.wsFrames.size() == 2 && contentview::dnsSummary(udp.wsFrames[1].preview) == "A 93.184.216.34",
          "UDP flow with both datagrams");
    proxy.stop();
}

static std::string h2frame(uint8_t type, uint8_t flags, uint32_t stream, const std::string& payload) {
    std::string f;
    f += (char)(payload.size() >> 16), f += (char)(payload.size() >> 8), f += (char)payload.size();
    f += (char)type, f += (char)flags;
    f += (char)(stream >> 24), f += (char)(stream >> 16), f += (char)(stream >> 8), f += (char)stream;
    return f + payload;
}

static void testH2c() {
    std::printf("== plain-text HTTP/2 (h2c) ==\n");
    std::string out;
    CHECK(http2::huffmanDecode(unhex("f1e3c2e5f23a6ba0ab90f4ff"), out) && out == "www.example.com", "HPACK Huffman (RFC 7541 C.4.1)");
    http2::HpackDecoder d;
    http2::Headers h;
    std::string err;
    CHECK(d.decode(unhex("828684410f7777772e6578616d706c652e636f6d"), h, err) && h.size() == 4 && h[0].second == "GET" &&
              h[1].second == "http" && h[2].second == "/" && h[3] == std::make_pair(std::string(":authority"), std::string("www.example.com")),
          "HPACK request (RFC 7541 C.3.1)");
    h.clear();
    // C.3.2: uses the dynamic table entry added above.
    CHECK(d.decode(unhex("828684be58086e6f2d6361636865"), h, err) && h.size() == 5 && h[3].second == "www.example.com" &&
              h[4] == std::make_pair(std::string("cache-control"), std::string("no-cache")),
          "HPACK dynamic table (RFC 7541 C.3.2)");

    // Reverse mode to a fake h2c server.
    Socket server;
    server.listenLoopback(0, err);
    const int serverPort = server.localPort();
    std::string serverGot;
    std::thread st([&] {
        Socket c = server.accept(5000);
        char b[4096];
        while (c.valid() && serverGot.find("/grpc.Svc/Call") == std::string::npos && c.waitReadable(3000)) {
            const long n = c.recvSome(b, sizeof b);
            if (n <= 0) return;
            serverGot.append(b, (size_t)n);
        }
        // SETTINGS, HEADERS (:status 200, content-type literal), DATA "hello" END_STREAM.
        std::string hdr = "\x88";  // :status 200 (static 8)
        hdr += std::string("\x0f\x10", 2) + (char)16 + "application/grpc";  // content-type (31), no indexing
        c.sendAll(h2frame(4, 0, 0, "") + h2frame(1, 0x4, 1, hdr) + h2frame(0, 0x1, 1, "hello"));
        c.waitReadable(1000);
    });
    TrafficProxy proxy;
    proxy.start(0, err);
    TrafficProxy::Mode rev;
    TrafficProxy::parseReverseTarget("http://127.0.0.1:" + std::to_string(serverPort), rev, err);
    proxy.setMode(rev);
    Socket c;
    c.connectLoopback(proxy.port(), 2000, err);
    // :method POST (3), :scheme http (6), :path literal, content-type literal; END_HEADERS; then DATA END_STREAM.
    std::string req = "\x83\x86";
    req += std::string("\x04", 1) + (char)14 + "/grpc.Svc/Call";
    std::string body = std::string("\x00\x00\x00\x00\x02\x08\x01", 7);
    c.sendAll(std::string(http2::kPreface, http2::kPrefaceLen) + h2frame(4, 0, 0, "") + h2frame(1, 0x4, 1, req) + h2frame(0, 0x1, 1, body));
    std::string got;
    char b[4096];
    while (got.find("hello") == std::string::npos && c.waitReadable(3000)) {
        const long n = c.recvSome(b, sizeof b);
        if (n <= 0) break;
        got.append(b, (size_t)n);
    }
    CHECK(got.find("hello") != std::string::npos, "h2c relayed both ways");
    CHECK(serverGot.rfind(std::string(http2::kPreface, http2::kPrefaceLen), 0) == 0, "the preface reached the server unchanged");
    c.shutdownBoth();
    st.join();
    TrafficProxy::Flow stream;
    for (int i = 0; i < 300; ++i) {
        for (const auto& f : proxy.flows())
            if (f.alpn == "h2c" && f.method == "POST" && f.complete) proxy.flow(f.id, stream);
        if (stream.id) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(stream.id && stream.path == "/grpc.Svc/Call" && stream.status == 200 && stream.response.body == "hello" &&
              stream.request.body == body && stream.response.header("content-type") == "application/grpc",
          "the h2c stream is listed as a request with its bodies");
    proxy.stop();
}

static void testScripts2() {
    std::printf("== traffic scripts: several, websocket_message, error ==\n");
    if (proc::run({"python", "--version"}, 10000).exitCode != 0) {
        std::printf("  (no python on PATH: skipped)\n");
        return;
    }
    const fs::path dir = fs::temp_directory_path() / "apkspy-scripts2";
    fs::create_directories(dir);
    std::ofstream(dir / "a.py", std::ios::binary) << "def request(flow):\n    flow.request.headers['X-Order'] = 'a'\n";
    std::ofstream(dir / "b.py", std::ios::binary)
        << "from apkspy_addon import ctx\n"
           "def request(flow):\n    flow.request.headers['X-Order'] = flow.request.headers.get('X-Order', '') + 'b'\n"
           "def websocket_message(flow):\n    m = flow.websocket.messages[-1]\n"
           "    if m.from_client and m.text == 'py':\n        m.text = 'from python'\n"
           "def error(flow):\n    ctx.log('failed:', flow.request.path, flow.error)\n";
    auto host = std::make_shared<trafficscript::Host>();
    std::string err;
    CHECK(host->start("python", {pathutil::toUtf8(dir / "a.py"), pathutil::toUtf8(dir / "b.py")}, pathutil::toUtf8(dir / "support"), err) &&
              host->hasRequestHook() && host->hasWebSocketHook() && host->hasErrorHook(),
          ("two scripts loaded: " + err).c_str());
    TrafficProxy proxy;
    proxy.start(0, err);
    proxy.setHooks(host);
    MiniOrigin origin;
    origin.start(1);
    {
        Socket c;
        c.connectLoopback(proxy.port(), 2000, err);
        c.sendAll("GET http://127.0.0.1:" + std::to_string(origin.port) + "/x HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(origin.port) + "\r\n\r\n");
        readAllFrom(c, 8000);
    }
    origin.join();
    CHECK(!origin.seen.empty() && origin.seen[0].find("X-Order: ab") != std::string::npos, "hooks ran in script order");
    // websocket_message
    WsOrigin ws;
    ws.start();
    Socket c;
    c.connectLoopback(proxy.port(), 2000, err);
    c.sendAll("GET http://127.0.0.1:" + std::to_string(ws.port) + "/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    std::string buf;
    char chunk[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && c.waitReadable(3000)) {
        const long n = c.recvSome(chunk, sizeof chunk);
        if (n <= 0) break;
        buf.append(chunk, (size_t)n);
    }
    buf.erase(0, buf.find("\r\n\r\n") + 4);
    c.sendAll(TrafficProxy::wsFrame(1, "py", true));
    std::string payload;
    CHECK(readServerFrame(c, buf, payload) && payload == "echo:from python", "websocket_message() rewrote a message");
    c.sendAll(TrafficProxy::wsFrame(8, "", true));
    c.shutdownBoth();
    ws.join();
    // error()
    {
        Socket e;
        e.connectLoopback(proxy.port(), 2000, err);
        e.sendAll("GET http://127.0.0.1:9/nowhere HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n");
        readAllFrom(e, 8000);
    }
    bool logged = false;
    for (int i = 0; i < 150 && !logged; ++i) {
        for (const auto& l : host->takeLog()) logged |= l.find("failed: /nowhere") != std::string::npos;
        if (!logged) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(logged, "error() called for a failed flow");
    proxy.stop();
    host->stop();
    std::error_code ec;
    fs::remove_all(dir, ec);
}

}  // namespace

// ---------------------------------------------------------------------------
// ARM32 decoding and Kotlin metadata
// ---------------------------------------------------------------------------
#include "analysis/Arm32.hpp"
#include "analysis/KotlinMetadata.hpp"
namespace {

static arm32::Insn a32(uint32_t w, uint64_t addr = 0x2000) {
    const uint8_t b[4] = {(uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16), (uint8_t)(w >> 24)};
    return arm32::decode(b, 4, addr, false);
}

static arm32::Insn t16(uint16_t h, uint64_t addr = 0x1000) {
    const uint8_t b[2] = {(uint8_t)h, (uint8_t)(h >> 8)};
    return arm32::decode(b, 2, addr, true);
}

static arm32::Insn t32(uint16_t h1, uint16_t h2, uint64_t addr = 0x1000) {
    const uint8_t b[4] = {(uint8_t)h1, (uint8_t)(h1 >> 8), (uint8_t)h2, (uint8_t)(h2 >> 8)};
    return arm32::decode(b, 4, addr, true);
}

static void testArm32() {
    std::printf("== arm32 / thumb decoding ==\n");
    using arm32::Flow;
    auto i = t32(0xF7FF, 0xFBFE);  // bl backward: 0x1000 -> 0x800 (S = 1, offset -0x804)
    CHECK(i.mnemonic == "bl" && i.hasTarget && i.target == 0x800 && i.flow == Flow::Call && i.size == 4,
          ("thumb bl backward: " + i.mnemonic + " " + i.operands).c_str());
    i = t32(0xF000, 0xF802);  // bl forward +4: 0x1000 -> 0x1008
    CHECK(i.mnemonic == "bl" && i.target == 0x1008, ("thumb bl forward: " + i.operands).c_str());
    i = t32(0xF000, 0xE802, 0x1002);  // blx forward: target from the word-aligned PC
    CHECK(i.mnemonic == "blx" && i.target == 0x1008, ("thumb blx: " + i.operands).c_str());
    i = t32(0xF000, 0xB802);  // b.w forward
    CHECK(i.mnemonic == "b.w" && i.flow == Flow::Jump && i.target == 0x1008, ("thumb b.w: " + i.operands).c_str());
    i = t32(0xF040, 0x8002);  // bne.w forward
    CHECK(i.mnemonic == "bne.w" && i.flow == Flow::CondJump && i.target == 0x1008, ("thumb bne.w: " + i.mnemonic).c_str());
    i = t32(0xE8BD, 0x8010);  // pop.w {r4, pc}
    CHECK(i.mnemonic == "pop.w" && i.operands == "{r4, pc}" && i.flow == Flow::Return, "thumb pop.w returns");
    i = t16(0xBD10);
    CHECK(i.mnemonic == "pop" && i.operands == "{r4, pc}" && i.flow == Flow::Return && i.size == 2, "thumb pop {r4, pc}");
    i = t16(0xB510);
    CHECK(i.mnemonic == "push" && i.operands == "{r4, lr}", "thumb push {r4, lr}");
    i = t16(0x4798);
    CHECK(i.mnemonic == "blx" && i.operands == "r3" && i.flow == Flow::IndirectCall, "thumb blx r3");
    i = t16(0x4770);
    CHECK(i.mnemonic == "bx" && i.flow == Flow::Return, "thumb bx lr");
    i = t16(0xD1FE, 0x100);
    CHECK(i.mnemonic == "bne" && i.target == 0x100 && i.flow == Flow::CondJump, "thumb bne to itself");
    i = t16(0xDF00);
    CHECK(i.mnemonic == "svc" && i.flow == Flow::Normal, "thumb svc is not a branch");
    i = t16(0x0089);  // lsls r1, r1, #2
    CHECK(i.mnemonic == "lsls" && i.operands == "r1, r1, #2", ("thumb lsls: " + i.mnemonic + " " + i.operands).c_str());
    i = t16(0x4801, 0x1002);  // ldr r0, [pc, #4] from an unaligned pc
    CHECK(i.target == 0x1008, "thumb literal load target");

    i = a32(0xE3010234);
    CHECK(i.mnemonic == "movw" && i.operands == "r0, #0x1234", ("a32 movw: " + i.mnemonic + " " + i.operands).c_str());
    i = a32(0xE3450678);
    CHECK(i.mnemonic == "movt" && i.operands == "r0, #0x5678", "a32 movt");
    i = a32(0xE10F0000);  // mrs r0, apsr - not movw
    CHECK(i.mnemonic != "movw", "a32 mrs is not decoded as movw");
    i = a32(0xE2810B01);
    CHECK(i.mnemonic == "add" && i.operands == "r0, r1, #0x400", ("a32 add rotated imm: " + i.operands).c_str());
    i = a32(0xE0A10002);  // adc r0, r1, r2 - not "sub #imm"
    CHECK(i.mnemonic.rfind("sub", 0) != 0 && i.mnemonic.rfind("add", 0) != 0, "a32 adc register is not add/sub immediate");
    i = a32(0xE1A04007);
    CHECK(i.mnemonic == "mov" && i.operands == "r4, r7", "a32 mov r4, r7");
    i = a32(0xE1A0F00E);
    CHECK(i.flow == Flow::Return, "a32 mov pc, lr returns");
    i = a32(0xE49DF004);
    CHECK(i.flow == Flow::Return && i.mnemonic == "ldr", "a32 ldr pc, [sp], #4 returns");
    i = a32(0xE5112004);
    CHECK(i.operands == "r2, [r1, #-4]", ("a32 negative offset: " + i.operands).c_str());
    i = a32(0xEBFFFBFE);  // bl backward: 0x2000 -> 0x1000
    CHECK(i.mnemonic == "bl" && i.target == 0x1000 && i.flow == Flow::Call, "a32 bl backward");
    i = a32(0xFA000000);  // blx #imm to Thumb: 0x2000 + 8
    CHECK(i.mnemonic == "blx" && i.target == 0x2008 && i.flow == Flow::Call, "a32 blx immediate");
    i = a32(0xE92D4010);
    CHECK(i.mnemonic == "push" && i.operands == "{r4, lr}", "a32 push");
    i = a32(0xE8BD8010);
    CHECK(i.mnemonic == "pop" && i.flow == Flow::Return, "a32 pop {.., pc} returns");
    const uint8_t three[3] = {1, 2, 3};
    i = arm32::decode(three, 3, 0, false);
    CHECK(!i.known && i.size == 3, "truncated input consumes what is left");
}

// d1 in the current encoding: '\0', then one character per protobuf byte.
static std::vector<std::string> d1Of(const std::string& bytes) {
    std::string s(1, '\0');
    for (unsigned char c : bytes) {
        if (c < 0x80) s += static_cast<char>(c);
        else s += static_cast<char>(0xC0 | (c >> 6)), s += static_cast<char>(0x80 | (c & 0x3F));
    }
    return {s};
}

static void testKotlinMetadata() {
    std::printf("== kotlin metadata ==\n");
    uint32_t flags = 0;
    // StringTableTypes (empty), then Class field 1 = flags.
    CHECK(kotlinmeta::classFlagsFromD1(d1Of(std::string("\x00\x08\x86\x08", 4)), flags) && flags == 1030, "data class flags");
    kotlinmeta::Metadata m;
    m.present = true;
    m.kind = kotlinmeta::Kind::Class;
    m.flagsKnown = true;
    const auto show = [&](uint32_t f) {
        m.classFlags = f;
        m.classKind = static_cast<kotlinmeta::ClassKind>((f >> 6) & 7);
        m.isSealed = ((f >> 4) & 3) == 3;
        m.isInner = (f >> 9) & 1;
        m.isData = (f >> 10) & 1;
        m.isValue = (f >> 13) & 1;
        return m.displayKind();
    };
    CHECK(show(flags) == "data class", "data class shown");
    CHECK(kotlinmeta::classFlagsFromD1(d1Of(std::string("\x00\x08\x86\x03", 4)), flags) && show(flags) == "companion object",
          "companion object");
    CHECK(kotlinmeta::classFlagsFromD1(d1Of(std::string("\x00\x08\x36", 3)), flags) && show(flags) == "sealed class", "sealed class");
    // Other fields before flags are skipped; a missing flags field means the default (6).
    CHECK(kotlinmeta::classFlagsFromD1(d1Of(std::string("\x02\x0a\x00\x18\x05\x08\x46", 7)), flags) && show(flags) == "interface",
          "fields skipped, interface");
    CHECK(kotlinmeta::classFlagsFromD1(d1Of(std::string("\x00\x18\x05", 3)), flags) && flags == 6, "default flags");
    CHECK(!kotlinmeta::classFlagsFromD1({std::string("\xEF\xBF\xBF abc")}, flags), "old 8-to-7 encoding is not guessed");
    CHECK(!kotlinmeta::classFlagsFromD1(d1Of(std::string("\x05\x01", 2)), flags), "truncated protobuf rejected");
    kotlinmeta::Metadata facade;
    facade.present = true;
    facade.kind = kotlinmeta::Kind::File;
    CHECK(facade.displayKind() == "file facade", "file facade kind");
}

static void testEmulator() {
    std::printf("== emulator ==\n");
    using namespace emulator;
    CHECK(validAvdName("Pixel_6_API_34") && validAvdName("a.b-c_1"), "valid AVD names");
    CHECK(!validAvdName("") && !validAvdName("-x") && !validAvdName(".x") && !validAvdName("has space") && !validAvdName("semi;colon"),
          "invalid AVD names rejected");
    CHECK(validSystemImage("system-images;android-34;google_apis;x86_64"), "valid system image");
    CHECK(!validSystemImage("android-34;google_apis;x86_64") && !validSystemImage("system-images;a;b") &&
              !validSystemImage("system-images;a;b;c;d"),
          "invalid system images rejected");
    CHECK(validProxy("127.0.0.1:8899") && validProxy("http://10.0.2.2:8080") && validProxy("proxy.local:3128"), "valid proxies");
    CHECK(!validProxy("127.0.0.1") && !validProxy(":8899") && !validProxy("127.0.0.1:") && !validProxy("127.0.0.1:70000") &&
              !validProxy("127.0.0.1:0"),
          "invalid proxies rejected");

    Tools t;
    t.emulator = "emulator";
    LaunchOptions opts;
    auto argv = launchArgv(t, "Pixel_6_API_34", opts);
    CHECK(argv.size() >= 3 && argv[0] == "emulator" && argv[1] == "-avd" && argv[2] == "Pixel_6_API_34", "base argv");
    const auto has = [](const std::vector<std::string>& v, const std::string& flag) {
        return std::find(v.begin(), v.end(), flag) != v.end();
    };
    const auto valAfter = [](const std::vector<std::string>& v, const std::string& flag) -> std::string {
        auto it = std::find(v.begin(), v.end(), flag);
        return it != v.end() && std::next(it) != v.end() ? *std::next(it) : std::string();
    };
    CHECK(!has(argv, "-http-proxy") && !has(argv, "-writable-system") && !has(argv, "-wipe-data"), "plain boot: no extra flags");
    CHECK(has(argv, "-netdelay") && valAfter(argv, "-netdelay") == "none", "netdelay set");

    opts.httpProxy = "127.0.0.1:8899";
    opts.writableSystem = true;
    opts.coldBoot = true;
    opts.wipeData = true;
    opts.noSnapshotSave = true;
    argv = launchArgv(t, "Pixel_6_API_34", opts);
    CHECK(valAfter(argv, "-http-proxy") == "127.0.0.1:8899", "proxy flag + value");
    CHECK(has(argv, "-writable-system") && has(argv, "-wipe-data") && has(argv, "-no-snapshot-load") && has(argv, "-no-snapshot-save"),
          "all options present");

    // An invalid proxy is dropped from the argv (launch() rejects it outright).
    opts = LaunchOptions{};
    opts.httpProxy = "not a proxy";
    CHECK(!has(launchArgv(t, "x", opts), "-http-proxy"), "invalid proxy not added to argv");
}

static void testRepack() {
    std::printf("== repack ==\n");
    repack::Tools t;
    t.apksigner = "apksigner";
    const auto has = [](const std::vector<std::string>& v, const std::string& x) {
        return std::find(v.begin(), v.end(), x) != v.end();
    };
    const auto valAfter = [](const std::vector<std::string>& v, const std::string& flag) -> std::string {
        auto it = std::find(v.begin(), v.end(), flag);
        return it != v.end() && std::next(it) != v.end() ? *std::next(it) : std::string();
    };

    // Default (debug) keystore: fixed android/androiddebugkey credentials.
    repack::Options dbg;
    auto a = repack::signArgv(t, dbg, "in.apk", "out.apk");
    CHECK(a[0] == "apksigner" && a[1] == "sign", "apksigner sign");
    CHECK(valAfter(a, "--ks-pass") == "pass:android" && valAfter(a, "--ks-key-alias") == "androiddebugkey", "debug key creds");
    CHECK(valAfter(a, "--out") == "out.apk" && a.back() == "in.apk", "in/out ordering");
    CHECK(valAfter(a, "--ks") == repack::debugKeystorePath(), "debug keystore path");

    // Custom keystore: credentials flow through; key password defaults to store.
    repack::Options cst;
    cst.keystorePath = "my.jks";
    cst.keystorePassword = "s3cret";
    cst.keyAlias = "release";
    a = repack::signArgv(t, cst, "in.apk", "out.apk");
    CHECK(valAfter(a, "--ks") == "my.jks" && valAfter(a, "--ks-pass") == "pass:s3cret", "custom keystore");
    CHECK(valAfter(a, "--ks-key-alias") == "release" && valAfter(a, "--key-pass") == "pass:s3cret", "alias + key pass defaults to store");
    cst.keyPassword = "keypw";
    CHECK(valAfter(repack::signArgv(t, cst, "i", "o"), "--key-pass") == "pass:keypw", "explicit key password");
    CHECK(!repack::debugKeystorePath().empty(), "debug keystore path resolves");
    (void)has;
}

}  // namespace

int main(int argc, char** argv) {
    // `--write-sample <dir>`: writes sample.apk + sample.apkspy (the
    // synthetic inputs used above) for manual / smoke testing of the app.
    if (argc == 3 && std::string(argv[1]) == "--write-sample") {
        const fs::path dir = argv[2];
        fs::create_directories(dir);
        const fs::path apk = fs::absolute(dir / "sample.apk");
        if (!writeApk(apk, {{"classes.dex", buildDex()}, {"lib/arm64-v8a/libfoo.so", buildElf()}})) return 1;
        Project project;
        project.reset();
        project.addApk(apk.string(), "sample");
        return project.save((dir / "sample.apkspy").string()) ? 0 : 1;
    }
    Socket::initNetworking();
    testJson();
    testSchema();
    testMcpProtocol();
    testDexAndAnalysis();
    testRobustness();
    testElf();
    testArm64();
    testGraphLayout();
    testNativeCode();
    testAnnotations();
    testDocument();
    testSearchMatcher();
    testAdbParsers();
    testProcess();
    testHttpTransport();
    testJdwp();
    testScriptRunner();
    testTrafficProxy();
    testLineSplitting();
    testCodec();
    testHttpClient();
    testIntercept();
    testMatchReplace();
    testCaAndCertificates();
    testTlsHandshake();
    testHttpsInterception();
    testHttpsInterceptAndRules();
    testWebSocketCapture();
    testRepeaterHttps();
    testTextDiff();
    testContentViews();
    testFlowFilters();
    testFlowArchive();
    testProxyModes();
    testProxyHooks();
    testTrafficScripts();
    testBodyDecoders();
    testWebSocketTools();
    testRoutingAndReplay();
    testExportsAndMarks();
    testContentViews2();
    testConditionsAndLimits();
    testRawStreams();
    testH2c();
    testScripts2();
    testArm32();
    testKotlinMetadata();
    testEmulator();
    testRepack();
    testMcpToolsEndToEnd();
    std::printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
