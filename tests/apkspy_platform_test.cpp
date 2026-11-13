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
#include "analysis/DexFile.hpp"
#include "analysis/Arm64.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/GraphLayout.hpp"
#include "analysis/NativeCode.hpp"
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
    testMcpToolsEndToEnd();
    std::printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
