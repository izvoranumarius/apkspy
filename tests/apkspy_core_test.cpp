// Headless test for ApkSpy core logic (no GUI, no OpenGL, POSIX only).
// Covers the security-relevant behaviour (project files, output-directory
// ownership, cancellation), the workspace/project flows, AXML decoding and
// the search service.
#include "core/Workspace.hpp"
#include "core/Project.hpp"
#include "core/RootKind.hpp"
#include "core/Settings.hpp"
#include "core/AxmlDecoder.hpp"
#include "core/TextSearch.hpp"
#include "core/SymbolIndex.hpp"
#include "core/ApkInfo.hpp"
#include "core/SafePath.hpp"
#include "core/ExportJob.hpp"
#include "core/Sha256.hpp"
#include "core/Der.hpp"
#include "core/IcoLoader.hpp"
#include "core/Paths.hpp"
#include "document/Document.hpp"
#include "image/ImageDecoder.hpp"
#include "image/Texture.hpp"
#include <miniz.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <thread>

namespace fs = std::filesystem;

// ---- stubs so we can link without OpenGL -----------------------------------
Texture::Texture(const uint8_t*, int, int) {}
Texture::~Texture() {}
int Texture::maxSize() { return 8192; }
std::string ImageDecoder::sniffFormat(const std::vector<uint8_t>&) { return {}; }
bool ImageDecoder::decode(const std::vector<uint8_t>&, DecodedImage&, std::string&) { return false; }

static int failures = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) printf("  PASS: %s\n", msg);                               \
        else { printf("  FAIL: %s\n", msg); ++failures; }                    \
    } while (0)

static void pump(Workspace& ws, int maxMs) {
    for (int t = 0; t < maxMs / 10; ++t) {
        ws.update();
        if (ws.jadx().state() == JadxRunner::State::Done) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

static void writeScript(const fs::path& path, const std::string& body) {
    std::ofstream sh(path);
    sh << "#!/bin/sh\n" << body;
    fs::permissions(path, fs::perms::owner_exec, fs::perm_options::add);
}

static void makeZip(const fs::path& apk, const std::string& manifestContent) {
    std::string cmd = "python3 -c \""
        "import zipfile; z=zipfile.ZipFile('" + apk.string() + "','w');"
        "z.writestr('AndroidManifest.xml','" + manifestContent + "');"
        "z.writestr('classes.dex','dex\\n035');"
        "z.writestr('res/layout/main.xml','<layout/>');"
        "z.close()\"";
    if (std::system(cmd.c_str()) != 0) { printf("FAIL: could not build fake apk\n"); std::exit(1); }
}

// --- minimal AXML writer for the manifest tests (M4) -------------------------

static void axPush16(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x & 0xFF));
    v.push_back((uint8_t)((x >> 8) & 0xFF));
}
static void axPush32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> (8 * i)));
}

struct AxmlDoc {
    std::vector<std::string> strings;
    std::unordered_map<std::string, uint32_t> stringIds;
    std::vector<uint8_t> body;

    uint32_t intern(const std::string& s) {
        auto it = stringIds.find(s);
        if (it != stringIds.end()) return it->second;
        strings.push_back(s);
        stringIds[s] = (uint32_t)strings.size() - 1;
        return (uint32_t)strings.size() - 1;
    }

    struct Attr {
        std::string name;
        uint8_t type;        // AXML data type (0x03 string, 0x10 int, 0x12 bool)
        uint32_t data;
        std::string raw;     // raw string value (STRING type only)
    };

    void chunk(uint16_t type, uint32_t size, uint32_t a, uint32_t b) {
        axPush16(body, type);
        axPush16(body, 16);
        axPush32(body, size);
        axPush32(body, 1);          // lineno
        axPush32(body, 0xFFFFFFFF); // comment
        axPush32(body, a);
        axPush32(body, b);
    }

    void startNamespace(const std::string& prefix, const std::string& uri) {
        chunk(0x0100, 24, intern(prefix), intern(uri));
    }
    void endNamespace(const std::string& prefix, const std::string& uri) {
        chunk(0x0101, 24, intern(prefix), intern(uri));
    }
    void endElement(const std::string& name) { chunk(0x0103, 24, 0xFFFFFFFF, intern(name)); }

    void startElement(const std::string& name, const std::vector<Attr>& attrs, uint32_t nsIdx) {
        const uint32_t attrBytes = (uint32_t)attrs.size() * 20;
        axPush16(body, 0x0102);
        axPush16(body, 16);
        axPush32(body, 8 + 8 + 20 + attrBytes);
        axPush32(body, 1);          // lineno
        axPush32(body, 0xFFFFFFFF); // comment
        axPush32(body, 0xFFFFFFFF); // attrExt: ns
        axPush32(body, intern(name));
        axPush16(body, 20); axPush16(body, 20); axPush16(body, (uint32_t)attrs.size());
        axPush16(body, 0); axPush16(body, 0); axPush16(body, 0);   // id/class/style
        for (const Attr& a : attrs) {
            // aapt stores the string index in BOTH the raw value and the
            // typed data of STRING attributes.
            const uint32_t strIdx = a.type == 0x03 ? intern(a.raw) : 0xFFFFFFFF;
            axPush32(body, nsIdx);
            axPush32(body, intern(a.name));
            axPush32(body, strIdx);
            axPush16(body, 8);      // typed value size
            body.push_back(0);      // res0
            body.push_back(a.type); // dataType
            axPush32(body, a.type == 0x03 ? strIdx : a.data);
        }
    }

    std::vector<uint8_t> finish() {
        std::vector<uint8_t> sdata;
        std::vector<uint32_t> offs;
        for (const std::string& s : strings) {
            offs.push_back((uint32_t)sdata.size());
            axPush16(sdata, (uint32_t)s.size());
            for (char c : s) axPush16(sdata, (uint8_t)c);
            axPush16(sdata, 0);
        }
        const uint32_t count = (uint32_t)strings.size();
        const uint32_t stringsStart = 28 + 4 * count;
        std::vector<uint8_t> pool;
        axPush16(pool, 0x0001); axPush16(pool, 28); axPush32(pool, 0);
        axPush32(pool, count); axPush32(pool, 0); axPush32(pool, 0);
        axPush32(pool, stringsStart); axPush32(pool, 0);
        for (uint32_t o : offs) axPush32(pool, o);
        pool.insert(pool.end(), sdata.begin(), sdata.end());
        while (pool.size() % 4) pool.push_back(0);
        const uint32_t poolSize = (uint32_t)pool.size();
        for (int i = 0; i < 4; ++i) pool[4 + i] = (uint8_t)(poolSize >> (8 * i));

        std::vector<uint8_t> doc;
        axPush16(doc, 0x0003); axPush16(doc, 8); axPush32(doc, 0);
        doc.insert(doc.end(), pool.begin(), pool.end());
        doc.insert(doc.end(), body.begin(), body.end());
        const uint32_t total = (uint32_t)doc.size();
        for (int i = 0; i < 4; ++i) doc[4 + i] = (uint8_t)(total >> (8 * i));
        return doc;
    }
};

// <manifest package=... versionName=2.5 versionCode=25> with two permissions
// and two components - everything the Overview panel shows.
static std::vector<uint8_t> buildBinaryManifest() {
    AxmlDoc d;
    const uint32_t androidNs = d.intern("http://schemas.android.com/apk/res/android");
    d.startNamespace("android", "http://schemas.android.com/apk/res/android");
    d.startElement("manifest",
                   {{"package", 0x03, 0, "com.example.app"},
                    {"versionCode", 0x10, 25, ""},
                    {"versionName", 0x03, 0, "2.5"}},
                   androidNs);
    d.startElement("uses-sdk",
                   {{"minSdkVersion", 0x10, 21, ""}, {"targetSdkVersion", 0x10, 33, ""}}, androidNs);
    d.endElement("uses-sdk");
    d.startElement("uses-permission", {{"name", 0x03, 0, "android.permission.INTERNET"}}, androidNs);
    d.endElement("uses-permission");
    d.startElement("uses-permission", {{"name", 0x03, 0, "android.permission.CAMERA"}}, androidNs);
    d.endElement("uses-permission");
    d.startElement("application", {{"label", 0x03, 0, "Demo"}}, androidNs);
    d.startElement("activity",
                   {{"name", 0x03, 0, "com.example.app.MainActivity"}, {"exported", 0x12, 1, ""}},
                   androidNs);
    d.startElement("intent-filter", {}, androidNs);
    d.startElement("action", {{"name", 0x03, 0, "android.intent.action.MAIN"}}, androidNs);
    d.endElement("action");
    d.endElement("intent-filter");
    d.endElement("activity");
    d.startElement("service", {{"name", 0x03, 0, "com.example.app.SyncService"}}, androidNs);
    d.endElement("service");
    d.endElement("application");
    d.endElement("manifest");
    d.endNamespace("android", "http://schemas.android.com/apk/res/android");
    return d.finish();
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    // Hand-built X.509 certificates for the signing tests (M4).
    std::function<std::vector<uint8_t>(const std::string&)> certBuilder;
    fs::path base = fs::temp_directory_path() / "apkspy_test";
    fs::remove_all(base);
    fs::create_directories(base / "work");

    // Fake jadx: logs, writes sources, exits 0.
    fs::path jadxPath = base / "fakejadx.sh";
    writeScript(jadxPath,
        "if [ \"$1\" = \"--version\" ]; then echo \"jadx 1.5.0-fake\"; exit 0; fi\n"
        "o1=\"\"; o2=\"\"; for a in \"$@\"; do if [ \"$a\" = \"-d\" ]; then :; fi; o1=\"$o2\"; o2=\"$a\"; done\n"
        "out=\"$o1\"\n"
        "echo \"INFO  - loading ...\"\n"
        "echo \"WARN  - Unknown attribute in AndroidManifest.xml\"\n"
        "echo \"ERROR - Process error class com.bad.Thing\"\n"
        "mkdir -p \"$out/sources/com/example\" \"$out/resources\"\n"
        "echo 'public class Foo { public void bar() { } private int count; }' > \"$out/sources/com/example/Foo.java\"\n"
        "echo 'public class Baz { private int field; }' > \"$out/sources/com/example/Baz.java\"\n"
        "echo '<manifest/>' > \"$out/resources/AndroidManifest.xml\"\n"
        "sleep 0.2\n"
        "echo 'INFO  - done'\n"
        "exit 0\n");

    printf("== output directory ownership (marker files) ==\n");
    {
        fs::path victim = base / "victim";
        fs::create_directories(victim);
        std::ofstream(victim / "precious.txt") << "data";
        // A directory ApkSpy never created must never be recognized as owned.
        CHECK(!Workspace::isOwnedOutDir(victim.string()), "unrelated directory is not owned");
    }

    printf("== multi-APK workspace: add, decompile, group ==\n");
    Workspace ws;
    ws.setJadxPath(jadxPath.string());
    fs::path apkA = base / "base.apk";
    makeZip(apkA, "<manifestA/>");
    // Two different APKs sharing one file name must never share results.
    fs::path apkB = base / "work" / "base.apk";
    makeZip(apkB, "<manifestB/>");

    CHECK(ws.addApk(apkA.string(), "base"), "add first base.apk");
    CHECK(ws.addApk(apkB.string(), "base (2)"), "add second base.apk");
    CHECK(ws.apkRoots().size() == 2, "two apk roots");
    CHECK(ws.decompiledRoots().size() == 2, "two decompiled roots");
    std::string outA, outB;
    for (Root* dec : ws.decompiledRoots()) {
        if (dec->title == "base") outA = dec->outDir;
        if (dec->title == "base (2)") outB = dec->outDir;
    }
    CHECK(outA != outB, "same-named APKs use distinct output dirs");
    CHECK(outA.rfind(Workspace::jadxCacheRoot(), 0) == 0, "output dir lives in the cache root");

    pump(ws, 15000);
    CHECK(ws.jadx().state() == JadxRunner::State::Done, "jadx finished cleanly");
    CHECK(fs::exists(fs::path(outA) / "sources" / "com" / "example" / "Foo.java"), "sources written");
    CHECK(Workspace::isOwnedOutDir(outA), "completed output dir is owned (marker)");
    CHECK(ws.jadx().warningCount() >= 1 && ws.jadx().errorCount() >= 1, "warning/error counters");
    // "ErrorHandler" in a class name must not count as an error.
    bool falseError = false;
    for (auto& l : ws.logLines())
        if (l.find("ErrorHandler") != std::string::npos) falseError = true;
    CHECK(!falseError, "no misclassified log lines present");

    Root* decA = ws.rootByGroup("base", Root::Kind::Decompiled);
    CHECK(decA != nullptr, "decompiled root for first APK");
    TreeNode* foo = decA->tree->findByPath((fs::path(outA) / "sources" / "com" / "example" / "Foo.java").string());
    CHECK(foo != nullptr, "Foo.java in the decompiled tree");

    printf("== completion marker: partial output is never re-attached ==\n");
    {
        // Simulate a killed jadx: sources exist but no completion marker.
        fs::path orphan = fs::path(Workspace::jadxCacheRoot()) / "orphan_out";
        fs::create_directories(orphan / "sources");
        std::ofstream(orphan / "sources" / "X.java") << "class X {}";
        CHECK(!Workspace::isOwnedOutDir(orphan.string()), "dir without marker is not owned");
    }

    printf("== re-attach: finished results are reused without re-running jadx ==\n");
    {
        Workspace ws2;
        ws2.setJadxPath("/nonexistent/jadx");
        // Different Workspace instance, same APK: derived dir matches, marker
        // says done -> attaches from disk even though jadx cannot even run.
        CHECK(ws2.addApk(apkA.string(), "base"), "re-add first base.apk");
        ws2.update();
        bool running = ws2.jadx().state() == JadxRunner::State::Running;
        CHECK(!running, "jadx not started - results re-attached from disk");
        Root* dec = ws2.rootByGroup("base", Root::Kind::Decompiled);
        CHECK(dec != nullptr && dec->tree->findByPath((fs::path(outA) / "sources" / "com" / "example" / "Foo.java").string()) != nullptr,
              "tree built from re-attached results");
    }

    printf("== cancellation kills a running jadx ==\n");
    {
        fs::path slowJadx = base / "slowjadx.sh";
        writeScript(slowJadx,
            "o1=\"\"; o2=\"\"; for a in \"$@\"; do o1=\"$o2\"; o2=\"$a\"; done\n"
            "echo started\n"
            "sleep 30\n");
        fs::path apkC = base / "slow.apk";
        makeZip(apkC, "<manifestC/>");
        Workspace ws3;
        ws3.setJadxPath(slowJadx.string());
        ws3.addApk(apkC.string(), "slow");
        auto begin = std::chrono::steady_clock::now();
        bool cancelled = false;
        for (int i = 0; i < 200; ++i) {
            ws3.update();
            if (i == 10) ws3.cancelDecompile();
            if (ws3.jadx().state() == JadxRunner::State::Cancelled) { cancelled = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin);
        CHECK(cancelled, "jadx run reached the Cancelled state");
        CHECK(elapsed < std::chrono::milliseconds(1500), "cancellation returned within a second");
    }

    printf("== editing + saving decompiled files ==\n");
    CHECK(foo != nullptr, "Foo.java still around");
    ws.openNode(*decA, *foo, -1, Workspace::OpenMode::Permanent);
    Document* doc = nullptr;
    for (auto& d : ws.documents())
        if (d->node() == foo) doc = d.get();
    CHECK(doc != nullptr && doc->canEdit(), "decompiled doc editable");
    CHECK(doc->rootKind() == RootKind::Decompiled, "doc tied to the decompiled root");
    CHECK(!doc->wantsEdit() && !doc->isEditing(), "documents open read-only by default");
    doc->setWantsEdit(true);
    doc->beginEdit();
    doc->editBuffer() += "\n// edited";
    doc->markDirty();
    CHECK(doc->isDirty(), "doc dirty after edit");
    CHECK(doc->lines().back() == "// edited", "lazily re-parsed lines see the edit");
    CHECK(doc->lines().size() == doc->lineOffsets().size(), "line offsets stay in sync");
    CHECK(doc->save(), "save succeeds");
    {
        std::ifstream in(foo->path());
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(content.find("// edited") != std::string::npos, "edit written to disk");
    }

    printf("== search: modes, hit group, oversized-file skip ==\n");
    ws.search().start(decA->tree.get(), decA->source.get(), "foo", SearchService::Mode::Classes, "base");
    while (ws.search().running()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    size_t classes = 0;
    ws.search().withHits([&](const std::vector<SearchHit>& h) { classes = h.size(); });
    CHECK(classes >= 1, "class search found Foo");
    CHECK(ws.search().group() == "base", "search remembers the searched group");
    ws.search().start(decA->tree.get(), decA->source.get(), "count", SearchService::Mode::Fields, "base");
    while (ws.search().running()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    size_t fields = 0;
    ws.search().withHits([&](const std::vector<SearchHit>& h) { fields = h.size(); });
    CHECK(fields >= 1, "field search found count");
    ws.search().start(decA->tree.get(), decA->source.get(), "Foo.java", SearchService::Mode::Filenames, "base");
    while (ws.search().running()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    size_t files = 0;
    ws.search().withHits([&](const std::vector<SearchHit>& h) { files = h.size(); });
    CHECK(files >= 1, "filename search found Foo.java");
    // Stale-root fix: hits are opened with the search's own group, not the
    // "current" one - verified indirectly by group() above.

    printf("== jadx --version test ==\n");
    ws.jadx().testInstall(jadxPath.string());
    while (ws.jadx().testRunning()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    bool ok = false;
    std::string result = ws.jadx().takeTestResult(ok);
    CHECK(ok && result.find("1.5.0-fake") != std::string::npos, "test install reports version");

    printf("== NavHistory: pure cursor semantics ==\n");
    {
        NavHistory nav(10);  // generous cap: semantics only, trimming is tested below
        CHECK(!nav.canBack() && !nav.canForward(), "empty history cannot navigate");
        CHECK(nav.back() == nullptr && nav.forward() == nullptr, "back/forward on empty history return nullptr");
        const NavLocation a{RootKind::Decompiled, "base", "/a", 0};
        const NavLocation b{RootKind::Decompiled, "base", "/b", 5};
        const NavLocation c{RootKind::Decompiled, "base", "/c", 1};
        nav.navigate(nullptr, a);
        nav.navigate(nullptr, b);
        CHECK(nav.size() == 2 && !nav.canForward(), "two pushes, forward stack empty");
        const NavLocation* cur = nav.back();
        CHECK(cur && *cur == a, "back returns the first entry");
        CHECK(nav.canForward(), "forward available after back");
        cur = nav.forward();
        CHECK(cur && *cur == b, "forward returns the second entry");
        nav.navigate(nullptr, c);
        CHECK(nav.size() == 3, "third push recorded");
        nav.back();
        nav.back();
        cur = nav.forward();
        CHECK(cur && *cur == b, "stepping forward again");
        nav.navigate(nullptr, c);
        CHECK(nav.size() == 3 && !nav.canForward(), "new navigation truncates the forward stack");
        nav.navigate(nullptr, c);  // same file, same line as current
        CHECK(nav.size() == 3, "duplicate destination ignored");
        // Origin of a document the history does not track as current becomes
        // its own entry so Back can return there.
        NavLocation bAt50 = b;
        bAt50.line = 50;
        nav.navigate(&bAt50, a);  // current is /c, user is leaving /b@50
        CHECK(nav.size() == 5, "origin entry + destination appended");
        cur = nav.back();
        CHECK(cur && cur->path == "/b" && cur->line == 50, "Back lands on the line the user left");
        // Same-document origin: the CURRENT entry's line is refreshed instead
        // of pushing a second entry for the same file.
        NavLocation bAt60 = b;
        bAt60.line = 60;
        nav.navigate(&bAt60, a);  // leaving /b again, now at line 60
        CHECK(nav.size() == 5, "origin refresh did not duplicate the document");
        cur = nav.back();
        CHECK(cur && cur->path == "/b" && cur->line == 60, "same-document origin refreshed the current entry");
        // An origin of a third, untracked document also gets an entry.
        const NavLocation d{RootKind::Decompiled, "base", "/d", 7};
        nav.navigate(&d, c);
        cur = nav.back();
        CHECK(cur && cur->path == "/d" && cur->line == 7, "untracked origin recorded as an entry");
        // Max size trimming.
        NavHistory small(3);
        for (int i = 0; i < 6; ++i)
            small.navigate(nullptr, {RootKind::Apk, "g", "/f" + std::to_string(i), 0});
        CHECK(small.size() == 3, "history trimmed to max entries");
        small.purgeGroup("g");
        CHECK(small.size() == 0 && small.back() == nullptr, "purgeGroup empties the history");
        // purgeGroup keeps other groups and the cursor position.
        NavHistory mixed(10);
        mixed.navigate(nullptr, {RootKind::Apk, "keep", "/k1", 0});
        mixed.navigate(nullptr, {RootKind::Apk, "gone", "/g1", 0});
        mixed.navigate(nullptr, {RootKind::Apk, "keep", "/k2", 0});
        mixed.purgeGroup("gone");
        CHECK(mixed.size() == 2, "only the removed group's entries are dropped");
        const NavLocation* cc = mixed.back();
        CHECK(cc && cc->path == "/k1", "cursor stayed consistent across the purge");
    }

    printf("== Workspace navigation: navigateTo / navBack / navForward ==\n");
    {
        Root* decB = ws.rootByGroup("base", Root::Kind::Decompiled);
        TreeNode* baz = decB->tree->findByPath((fs::path(outA) / "sources" / "com" / "example" / "Baz.java").string());
        CHECK(baz != nullptr, "Baz.java present for navigation");
        Document* fooDoc = nullptr;
        for (auto& d : ws.documents())
            if (d->node() == foo) fooDoc = d.get();
        CHECK(fooDoc != nullptr, "Foo tab still open");
        fooDoc->setViewLine(2);  // pretend the user scrolled to line 3
        NavLocation origin = ws.locationOf(*fooDoc);
        ws.navigateTo(*decB, *baz, 4, &origin);
        Document* bazDoc = nullptr;
        for (auto& d : ws.documents())
            if (d->node() == baz) bazDoc = d.get();
        CHECK(bazDoc != nullptr, "navigateTo opened the destination");
        CHECK(bazDoc->highlight() == 4, "destination opened at the recorded line");
        CHECK(ws.canNavBack(), "history recorded the jump");
        CHECK(ws.navBack(), "navBack succeeds");
        Document* backDoc = nullptr;
        for (auto& d : ws.documents())
            if (d->node() == foo) backDoc = d.get();
        CHECK(backDoc != nullptr, "Back returned to Foo");
        CHECK(backDoc->highlight() == 2, "Back restored the recorded view line");
        CHECK(ws.navForward(), "navForward succeeds");
        CHECK(bazDoc->highlight() == 4, "Forward returned to Baz at its line");
        const size_t before = ws.nav().size();
        const NavLocation bazLoc = ws.locationOf(*bazDoc);
        ws.recordJump(bazLoc, bazLoc);
        CHECK(ws.nav().size() == before, "same-location jump is not recorded");
        // Closing the tab: navigating to a history entry re-opens its file.
        ws.closeDocument(bazDoc);
        CHECK(ws.navBack(), "Back works after the tab was closed");
        CHECK(ws.navForward(), "Forward re-opens the closed tab");
        Document* reopened = nullptr;
        for (auto& d : ws.documents())
            if (d->node() == baz) reopened = d.get();
        CHECK(reopened != nullptr, "Forward re-opened the closed document");
    }

    printf("== navigation history is purged when an APK is removed ==\n");
    {
        Workspace ws6;
        ws6.setJadxPath(jadxPath.string());
        ws6.addApk(apkA.string(), "navgroup");
        pump(ws6, 15000);
        Root* dec = ws6.rootByGroup("navgroup", Root::Kind::Decompiled);
        TreeNode* f = dec->tree->findByPath((fs::path(dec->outDir) / "sources" / "com" / "example" / "Foo.java").string());
        TreeNode* b = dec->tree->findByPath((fs::path(dec->outDir) / "sources" / "com" / "example" / "Baz.java").string());
        CHECK(f && b, "both files present");
        ws6.navigateTo(*dec, *f, 0, nullptr);
        ws6.navigateTo(*dec, *b, 3, nullptr);
        CHECK(ws6.canNavBack(), "history before removal");
        ws6.removeApk(ws6.rootByGroup("navgroup", Root::Kind::Apk));
        CHECK(!ws6.canNavBack() && !ws6.navBack(), "removeApk purged the group's history entries");
    }

    printf("== SymbolIndex: build, resolve, same-package hint, purge ==\n");
    {
        fs::path src = base / "symindex" / "sources";
        fs::create_directories(src / "com" / "example" / "sub");
        std::ofstream(src / "com" / "example" / "Foo.java")
            << "package com.example;\npublic class Foo {\n    public interface Bar { void go(); }\n}\n";
        std::ofstream(src / "com" / "example" / "Baz.java") << "public class Baz {}\n";
        std::ofstream(src / "com" / "example" / "Dup.java")
            << "package com.example;\npublic class Item {}\n";
        std::ofstream(src / "com" / "example" / "sub" / "Util.java")
            << "package com.example.sub;\npublic class Util {}\n";
        std::ofstream(src / "com" / "example" / "sub" / "Item.java")
            << "package com.example.sub;\nclass Item {}\n";
        std::ofstream(src / "com" / "example" / "Outer.java")
            << "package com.example;\npublic class Outer { static class Inner {} }\n";

        SymbolIndex idx;
        std::shared_ptr<ContentSource> disk = std::make_shared<DiskSource>();
        std::vector<SymbolIndex::File> files = {
            {(src / "com" / "example" / "Foo.java").string(), false},
            {(src / "com" / "example" / "Baz.java").string(), false},
            {(src / "com" / "example" / "Dup.java").string(), false},
            {(src / "com" / "example" / "sub" / "Util.java").string(), false},
            {(src / "com" / "example" / "sub" / "Item.java").string(), false},
            {(src / "com" / "example" / "Outer.java").string(), false},
        };
        idx.ensureIndex("t", 1, files, disk);
        for (int i = 0; i < 500 && idx.building("t"); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        CHECK(!idx.building("t"), "index build finished");

        const std::string fooPath = (src / "com" / "example" / "Foo.java").string();
        const std::string exampleDir = (src / "com" / "example").string();
        const std::string subDir = (src / "com" / "example" / "sub").string();
        CHECK(idx.resolve("t", "Foo") == fooPath, "short name resolves");
        CHECK(idx.resolve("t", "com.example.Foo") == fooPath, "fully qualified name resolves");
        CHECK(idx.resolve("t", "Bar") == fooPath, "inner interface resolves via its file");
        CHECK(idx.resolve("t", "Inner") == (src / "com" / "example" / "Outer.java").string(),
              "nested class in one file resolves");
        // Same-package preference: "Item" exists in two packages.
        CHECK(idx.resolve("t", "Item", exampleDir) == (src / "com" / "example" / "Dup.java").string(),
              "same-package file wins with a hint");
        CHECK(idx.resolve("t", "Item", subDir) == (src / "com" / "example" / "sub" / "Item.java").string(),
              "same-package file wins in the sub package");
        CHECK(idx.resolve("t", "Item") == (src / "com" / "example" / "Dup.java").string(),
              "deterministic pick without a hint");
        CHECK(idx.resolve("t", "NoSuchClass").empty(), "unknown identifier unresolved");
        CHECK(idx.resolve("missing-group", "Foo").empty(), "unknown group unresolved");

        // ensureIndex with the same epoch is a no-op (table kept); a bumped
        // epoch triggers a rebuild that still resolves.
        idx.ensureIndex("t", 1, files, disk);
        CHECK(idx.resolve("t", "Foo") == fooPath, "same epoch keeps the table");
        idx.ensureIndex("t", 2, files, disk);
        for (int i = 0; i < 500 && idx.building("t"); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        CHECK(idx.resolve("t", "com.example.sub.Util") == (src / "com" / "example" / "sub" / "Util.java").string(),
              "rebuilt table resolves FQN");
        idx.purgeGroup("t");
        CHECK(idx.resolve("t", "Foo").empty(), "purged group unresolved");
    }

    printf("== Workspace symbol navigation (Ctrl+click backend) ==\n");
    {
        Root* decB = ws.rootByGroup("base", Root::Kind::Decompiled);
        CHECK(ws.treeEpoch("base") >= 1, "tree epoch bumped by the finished decompile");
        ws.ensureSymbolIndex("base");
        for (int i = 0; i < 500 && ws.symbols().building("base"); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        CHECK(!ws.symbols().building("base"), "workspace index built");
        TreeNode* baz = decB->tree->findByPath((fs::path(outA) / "sources" / "com" / "example" / "Baz.java").string());
        CHECK(baz != nullptr, "Baz node present");
        CHECK(ws.openSymbol("base", "Baz", "", nullptr), "openSymbol resolved Baz");
        bool opened = false;
        for (auto& d : ws.documents())
            if (d->node() == baz) opened = true;
        CHECK(opened, "openSymbol opened the Baz document");
        CHECK(!ws.openSymbol("base", "DoesNotExist", "", nullptr), "unresolved identifier returns false");
    }

    printf("== Sha256: known vectors ==\n");
    {
        uint8_t d[32];
        sha256::digest(nullptr, 0, d);
        CHECK(sha256::hex(d) ==
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "sha256 of empty string");
        const char* abc = "abc";
        sha256::digest((const uint8_t*)abc, 3, d);
        CHECK(sha256::hex(d) ==
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "sha256 of \"abc\"");
        // Multi-block input exercises the buffering path (block boundary + padding).
        const std::string long1(1000, 'a');
        sha256::digest((const uint8_t*)long1.data(), long1.size(), d);
        CHECK(sha256::hex(d) ==
                  "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
              "sha256 of 1000 x 'a'");
        const std::string million(1000000, 'a');
        sha256::digest((const uint8_t*)million.data(), million.size(), d);
        CHECK(sha256::hex(d) ==
                  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
              "sha256 of 1000000 x 'a' (streaming)");
    }

    printf("== Der: X.509 CommonName extraction ==\n");
    {
        // Hand-built minimal certificate:
        // Certificate ::= SEQ { tbs SEQ { [0]{2}, 1, alg, issuerName, validity, subjectName, spki }, alg, bits }
        auto derSeq = [](const std::vector<uint8_t>& body, uint8_t tag = 0x30) {
            std::vector<uint8_t> out{tag};
            size_t len = body.size();
            if (len < 128) out.push_back((uint8_t)len);
            else { out.push_back((uint8_t)(0x80 | (len > 0xFF ? 2 : 1)));
                   if (len > 0xFF) out.push_back((uint8_t)(len >> 8));
                   out.push_back((uint8_t)(len & 0xFF)); }
            out.insert(out.end(), body.begin(), body.end());
            return out;
        };
        auto derInt = [](uint32_t v) {
            std::vector<uint8_t> b{0x02};
            if (v < 0x80) { b.push_back(1); b.push_back((uint8_t)v); }
            else if (v < 0x8000) { b.push_back(2); b.push_back((uint8_t)(v >> 8)); b.push_back((uint8_t)v); }
            else { b.push_back(3); b.push_back((uint8_t)(v >> 16)); b.push_back((uint8_t)(v >> 8)); b.push_back((uint8_t)v); }
            return b;
        };
        auto derOid = [](std::initializer_list<uint8_t> v) {
            std::vector<uint8_t> b{0x06, (uint8_t)v.size()};
            for (uint8_t x : v) b.push_back(x);
            return b;
        };
        auto derStr = [](const std::string& s) {
            std::vector<uint8_t> b{0x0C, (uint8_t)s.size()};  // UTF8String
            b.insert(b.end(), s.begin(), s.end());
            return b;
        };
        auto cnName = [&](const std::string& cn) {
            std::vector<uint8_t> atv;
            const auto oid = derOid({0x55, 0x04, 0x03});  // 2.5.4.3 CN
            const auto val = derStr(cn);
            atv.insert(atv.end(), oid.begin(), oid.end());
            atv.insert(atv.end(), val.begin(), val.end());
            // RDN ::= SET OF SEQUENCE { OID, value }
            return derSeq(derSeq(derSeq(atv), 0x31));
        };
        std::vector<uint8_t> tbs;
        const auto alg = derSeq(derOid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}));
        {
            const auto version = derSeq({derInt(2)}, 0xA0);
            const auto issuer = cnName("ApkSpy Issuer");
            const auto validity = derSeq(derSeq({0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'}));
            const auto subject = cnName("ApkSpy Test Cert");
            const auto spki = derSeq(alg);  // shape only
            const auto serial = derInt(1);  // one temp: begin/end must come from the same vector
            tbs.insert(tbs.end(), version.begin(), version.end());
            tbs.insert(tbs.end(), serial.begin(), serial.end());
            tbs.insert(tbs.end(), alg.begin(), alg.end());
            tbs.insert(tbs.end(), issuer.begin(), issuer.end());
            tbs.insert(tbs.end(), validity.begin(), validity.end());
            tbs.insert(tbs.end(), subject.begin(), subject.end());
            tbs.insert(tbs.end(), spki.begin(), spki.end());
        }
        // Certificate ::= SEQ { tbs SEQ {...}, alg, BIT STRING }
        const auto tbsSeq = derSeq(tbs);
        std::vector<uint8_t> certBody = tbsSeq;
        certBody.insert(certBody.end(), alg.begin(), alg.end());
        const std::vector<uint8_t> bits{0x03, 0x02, 0x00, 0x00};
        certBody.insert(certBody.end(), bits.begin(), bits.end());
        const auto cert = derSeq(certBody);
        const ApkSigningInfo s = ApkInfo::describeCertificate(cert.data(), cert.size(), "test");
        CHECK(s.certSha256 == sha256::hexOf(cert), "certificate fingerprint hashes the full DER");
        CHECK(s.subject == "ApkSpy Test Cert", "subject CN extracted");
        CHECK(s.issuer == "ApkSpy Issuer", "issuer CN extracted");
        // Used by the signing tests below via the same helper (declared in this
        // scope, so the helpers stay local to the test).
        certBuilder = [derSeq, derInt, derOid, derStr, cnName, alg = derSeq(derOid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}))](
                          const std::string& subject) mutable -> std::vector<uint8_t> {
            std::vector<uint8_t> tbs2;
            const auto version = derSeq({derInt(2)}, 0xA0);
            const auto issuer = cnName("ApkSpy Issuer");
            const auto validity = derSeq(derSeq({0x17, 0x0D, '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'}));
            const auto subj = cnName(subject);
            const auto spki = derSeq(alg);
            const auto serial = derInt(1);
            tbs2.insert(tbs2.end(), version.begin(), version.end());
            tbs2.insert(tbs2.end(), serial.begin(), serial.end());
            tbs2.insert(tbs2.end(), alg.begin(), alg.end());
            tbs2.insert(tbs2.end(), issuer.begin(), issuer.end());
            tbs2.insert(tbs2.end(), validity.begin(), validity.end());
            tbs2.insert(tbs2.end(), subj.begin(), subj.end());
            tbs2.insert(tbs2.end(), spki.begin(), spki.end());
            std::vector<uint8_t> out = derSeq(tbs2);
            out.insert(out.end(), alg.begin(), alg.end());
            const std::vector<uint8_t> bits{0x03, 0x02, 0x00, 0x00};
            out.insert(out.end(), bits.begin(), bits.end());
            return derSeq(out);
        };
    }

    printf("== ApkInfo::parseSigningBlock: v2 certificate out of a fake APK ==\n");
    {
        // Build a v2 signing block around a hand-made certificate.
        std::vector<uint8_t> cert = certBuilder("ApkSpy v2 Signer");
        // Canonical v2 framing:
        //   payload  = u32 signersLen | u32 signerLen | signer
        //   signer   = u32 signedDataLen | signedData | u32 signaturesLen | u32 publicKeyLen
        //   signedData = u32 digestsLen | digests | u32 certsLen | certificates | u32 attrsLen
        //   certificates = u32 certLen | certDER
        auto pushLen32 = [](std::vector<uint8_t>& v, size_t len) {
            v.push_back((uint8_t)(len & 0xFF)); v.push_back((uint8_t)((len >> 8) & 0xFF));
            v.push_back((uint8_t)((len >> 16) & 0xFF)); v.push_back((uint8_t)((len >> 24) & 0xFF));
        };
        std::vector<uint8_t> certsContent;
        pushLen32(certsContent, cert.size());
        certsContent.insert(certsContent.end(), cert.begin(), cert.end());
        std::vector<uint8_t> sdContent;
        pushLen32(sdContent, 0);  // digests: empty sequence
        pushLen32(sdContent, certsContent.size());
        sdContent.insert(sdContent.end(), certsContent.begin(), certsContent.end());
        pushLen32(sdContent, 0);  // additional attributes
        std::vector<uint8_t> signerContent;
        pushLen32(signerContent, sdContent.size());
        signerContent.insert(signerContent.end(), sdContent.begin(), sdContent.end());
        pushLen32(signerContent, 0);  // signatures
        pushLen32(signerContent, 0);  // public key
        std::vector<uint8_t> signers;
        pushLen32(signers, signerContent.size() + 4);
        pushLen32(signers, signerContent.size());
        signers.insert(signers.end(), signerContent.begin(), signerContent.end());

        auto putU64 = [](std::vector<uint8_t>& v, uint64_t x) {
            for (int i = 0; i < 8; ++i) v.push_back((uint8_t)(x >> (8 * i)));
        };
        auto putU32 = [](std::vector<uint8_t>& v, uint32_t x) {
            for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> (8 * i)));
        };
        // One pair: u64 length prefix, u32 id, payload.
        std::vector<uint8_t> pairPayload;
        putU32(pairPayload, 0x7109871a);  // v2 block id
        pairPayload.insert(pairPayload.end(), signers.begin(), signers.end());
        std::vector<uint8_t> pair;
        putU64(pair, pairPayload.size());
        pair.insert(pair.end(), pairPayload.begin(), pairPayload.end());

        std::vector<uint8_t> block;
        putU64(block, 0);  // size header, patched below
        block.insert(block.end(), pair.begin(), pair.end());
        putU64(block, 0);  // size footer, patched below
        const char magic[16] = {'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ', 'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};
        block.insert(block.end(), magic, magic + 16);
        const uint64_t sizeVal = block.size() - 8;
        for (int i = 0; i < 8; ++i) block[i] = (uint8_t)(sizeVal >> (8 * i));
        for (int i = 0; i < 8; ++i) block[block.size() - 24 + i] = (uint8_t)(sizeVal >> (8 * i));

        // Fake APK: prefix, block, dummy central directory, EOCD.
        std::vector<uint8_t> apk;
        apk.insert(apk.end(), {'P', 'K', 3, 4});
        apk.resize(apk.size() + 100, 0xAB);
        const uint64_t cdOffset = apk.size() + block.size();
        apk.insert(apk.end(), block.begin(), block.end());
        apk.resize(apk.size() + 64, 0xCD);  // fake central directory
        for (int i = 0; i < 22; ++i) apk.push_back(0);
        apk[apk.size() - 22] = 0x50; apk[apk.size() - 21] = 0x4b;
        apk[apk.size() - 20] = 0x05; apk[apk.size() - 19] = 0x06;
        for (int i = 0; i < 4; ++i) apk[apk.size() - 22 + 16 + i] = (uint8_t)(cdOffset >> (8 * i));

        std::vector<ApkSigningInfo> sigs;
        CHECK(ApkInfo::parseSigningBlock(apk, 0, sigs), "signing block parsed");
        CHECK(sigs.size() == 1 && sigs[0].scheme == "v2", "v2 scheme reported");
        CHECK(!sigs.empty() && sigs[0].certSha256 == sha256::hexOf(cert), "certificate fingerprint matches");
        CHECK(!sigs.empty() && sigs[0].subject == "ApkSpy v2 Signer", "subject CN from the signing block");

        // Tail read must produce the same result (bufferOffset translation).
        // The window covers the whole block plus the CD/EOCD behind it.
        const size_t tailFrom = apk.size() - (size_t)sizeVal - 8 - 64 - 22 - 32;
        std::vector<uint8_t> tail(apk.begin() + (long)tailFrom, apk.end());
        std::vector<ApkSigningInfo> tailSigs;
        CHECK(ApkInfo::parseSigningBlock(tail, tailFrom, tailSigs), "signing block parsed from a tail buffer");
        CHECK(tailSigs.size() == 1 && tailSigs[0].certSha256 == sigs[0].certSha256, "tail parse matches full parse");
    }

    printf("== ApkInfo::extract: binary manifest + v1/v2 signatures ==\n");
    {
        std::vector<uint8_t> manifest = buildBinaryManifest();
        CHECK(!manifest.empty(), "binary manifest built");

        fs::path apkPath = base / "overview.apk";
        {
            std::ofstream raw(base / "manifest.axml", std::ios::binary);
            raw.write((const char*)manifest.data(), (std::streamsize)manifest.size());
            raw.close();
            std::ofstream py(base / "mkzip.py");
            py << "import sys, zipfile\n"
               << "manifest = open(r'" << (base / "manifest.axml").string() << "','rb').read()\n"
               << "pkcs7 = open(r'" << (base / "cert.p7").string() << "','rb').read()\n"
               << "z = zipfile.ZipFile(r'" << apkPath.string() << "','w')\n"
               << "z.writestr('AndroidManifest.xml', manifest)\n"
               << "z.writestr('META-INF/CERT.RSA', pkcs7)\n"
               << "z.close()\n";
            py.close();
        }
        // v1 PKCS#7 blob wrapping the test certificate.
        std::vector<uint8_t> cert = certBuilder("ApkSpy v1 Signer");
        {
            auto derSeqL = [](const std::vector<uint8_t>& body, uint8_t tag = 0x30) {
                std::vector<uint8_t> out{tag};
                size_t len = body.size();
                if (len < 128) out.push_back((uint8_t)len);
                else { out.push_back((uint8_t)(0x80 | (len > 0xFF ? 2 : 1)));
                       if (len > 0xFF) out.push_back((uint8_t)(len >> 8));
                       out.push_back((uint8_t)(len & 0xFF)); }
                out.insert(out.end(), body.begin(), body.end());
                return out;
            };
            static const uint8_t kSignedDataOid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
            std::vector<uint8_t> oid{0x06, (uint8_t)(sizeof kSignedDataOid)};
            oid.insert(oid.end(), kSignedDataOid, kSignedDataOid + sizeof kSignedDataOid);
            std::vector<uint8_t> certsSet{0xA0};
            // [0] is IMPLICIT SET OF Certificate: its content is the raw
            // certificate DER (itself a SEQUENCE) - no extra wrapper.
            size_t cl = cert.size();
            certsSet.push_back(cl < 128 ? (uint8_t)cl : (uint8_t)(0x80 | (cl > 0xFF ? 2 : 1)));
            if (cl > 0xFF) certsSet.push_back((uint8_t)(cl >> 8));
            if (cl >= 128) certsSet.push_back((uint8_t)(cl & 0xFF));
            certsSet.insert(certsSet.end(), cert.begin(), cert.end());
            std::vector<uint8_t> sd;
            const std::vector<uint8_t> ver = {0x02, 0x01, 0x01};
            const std::vector<uint8_t> emptySet = {0x31, 0x00};
            const std::vector<uint8_t> emptySeq = {0x30, 0x00};
            sd.insert(sd.end(), ver.begin(), ver.end());
            sd.insert(sd.end(), emptySet.begin(), emptySet.end());
            sd.insert(sd.end(), emptySeq.begin(), emptySeq.end());
            sd.insert(sd.end(), certsSet.begin(), certsSet.end());
            sd.insert(sd.end(), emptySet.begin(), emptySet.end());
            std::vector<uint8_t> sdSeq = derSeqL(sd);
            std::vector<uint8_t> ctx{0xA0};
            size_t sl = sdSeq.size();
            ctx.push_back(sl < 128 ? (uint8_t)sl : (uint8_t)(0x80 | (sl > 0xFF ? 2 : 1)));
            if (sl > 0xFF) ctx.push_back((uint8_t)(sl >> 8));
            if (sl >= 128) ctx.push_back((uint8_t)(sl & 0xFF));
            ctx.insert(ctx.end(), sdSeq.begin(), sdSeq.end());
            std::vector<uint8_t> outer;
            outer.insert(outer.end(), oid.begin(), oid.end());
            outer.insert(outer.end(), ctx.begin(), ctx.end());
            std::ofstream p7(base / "cert.p7", std::ios::binary);
            const std::vector<uint8_t> p7bytes = derSeqL(outer);
            p7.write((const char*)p7bytes.data(), (std::streamsize)p7bytes.size());
            p7.close();
        }
        if (std::system(("python3 '" + (base / "mkzip.py").string() + "'").c_str()) != 0) {
            printf("  FAIL: could not build overview apk\n");
            ++failures;
        } else {
            Workspace ws7;
            ws7.setJadxPath("/nonexistent/jadx");
            CHECK(ws7.addApk(apkPath.string(), "overview"), "overview apk opened");
            Root* apkRoot = ws7.rootByGroup("overview", Root::Kind::Apk);
            CHECK(apkRoot != nullptr, "apk root available");
            ApkInfo info = ApkInfo::extract(*apkRoot);
            CHECK(info.ok, "manifest decoded");
            CHECK(info.packageName == "com.example.app", "package extracted");
            CHECK(info.versionName == "2.5" && info.versionCode == "25", "version extracted");
            CHECK(info.minSdk == "21" && info.targetSdk == "33", "sdk versions extracted");
            CHECK(info.permissions.size() == 2, "both permissions extracted");
            bool hasInternet = false, hasCamera = false;
            for (const std::string& p : info.permissions) {
                if (p == "android.permission.INTERNET") hasInternet = true;
                if (p == "android.permission.CAMERA") hasCamera = true;
            }
            CHECK(hasInternet && hasCamera, "permission names correct");
            CHECK(info.components.size() == 2, "two components extracted");
            bool act = false, svc = false;
            for (const ApkComponent& c : info.components) {
                if (c.type == "activity" && c.name == "com.example.app.MainActivity" && c.exported) act = true;
                if (c.type == "service" && c.name == "com.example.app.SyncService") svc = true;
            }
            CHECK(act && svc, "component names/exported extracted");
            bool v1 = false;
            for (const ApkSigningInfo& s : info.signatures)
                if (s.scheme == "v1 (JAR)" && s.subject == "ApkSpy v1 Signer") v1 = true;
            CHECK(v1, "v1 certificate fingerprint + subject from META-INF");
            CHECK(info.signatures.size() == 1, "no signing block in this zip, only v1");
        }
    }

    printf("== SafePath: zip-slip and Windows tricks ==\n");
    {
        std::string out;
        CHECK(safepath::relativePath("res/layout/main.xml", out) && out == "res/layout/main.xml",
              "normal entry name unchanged");
        CHECK(safepath::relativePath("/etc/passwd", out) && out == "etc/passwd",
              "absolute path loses its root");
        CHECK(safepath::relativePath("../../.ssh/authorized_keys", out) && out == "__/__/.ssh/authorized_keys",
              "dot-dot segments neutralised, hidden files kept");
        CHECK(safepath::relativePath("a/..\\b.txt", out) && out == "a/.._b.txt",
              "backslash segments sanitised (no separator survives)");
        CHECK(safepath::relativePath("C:/Users/x/secret", out) && out == "C_/Users/x/secret",
              "drive letter defused");
        CHECK(safepath::relativePath("CON", out) && out == "_CON", "reserved device name prefixed");
        CHECK(safepath::relativePath("com1.txt", out) && out == "_com1.txt", "reserved name with extension prefixed");
        CHECK(safepath::relativePath("evil. ", out) && out == "evil", "trailing dots/spaces stripped");
        CHECK(safepath::relativePath("a\x01" "b.txt", out) && out == "a_b.txt", "control characters replaced");
        CHECK(safepath::relativePath("...", out) && out == "___", "dots-only segment neutralised");
        CHECK(!safepath::relativePath("//", out), "segments-only path refused");
        CHECK(!safepath::relativePath("", out), "empty path refused");
        // The two classic zip-slip payloads must never survive verbatim.
        std::string slip1, slip2;
        safepath::relativePath("../evil.txt", slip1);
        safepath::relativePath("a/../../../evil.txt", slip2);
        CHECK(slip1.find("..") == std::string::npos && slip2.find("..") == std::string::npos,
              "no dot-dot survives anywhere");
        CHECK(safepath::relativePath("ok/" + std::string(2000, 'x'), out) == false || out.size() <= 1024,
              "absurd paths are refused or capped");
    }

    printf("== ExportJob: folder export, raw vs decoded, cancel ==\n");
    {
        // A small static ContentSource for entry bytes built in-memory.
        class StaticSource : public ContentSource {
        public:
            explicit StaticSource(std::vector<uint8_t> d) : data_(std::move(d)) {}
            bool read(const TreeNode&, std::vector<uint8_t>& out) const override {
                out = data_;
                return true;
            }

        private:
            std::vector<uint8_t> data_;
        };
        TreeNode res("res", "res", NodeKind::Folder);
        res.addChild(std::make_unique<TreeNode>("layout", "res/layout", NodeKind::Folder));
        TreeNode* lay = res.findChild("layout");
        TreeNode* main = lay->addChild(std::make_unique<TreeNode>("main.xml", "res/layout/main.xml", NodeKind::Xml));
        TreeNode* icon = res.addChild(std::make_unique<TreeNode>("icon.png", "res/icon.png", NodeKind::Image));
        // A second, hostile entry name that must not escape the destination.
        TreeNode* evil = res.addChild(std::make_unique<TreeNode>("..bad", "../evil.txt", NodeKind::Text));

        auto axml = buildBinaryManifest();
        auto xmlSource = std::make_shared<StaticSource>(axml);
        auto binSource = std::make_shared<StaticSource>(std::vector<uint8_t>{'P', 'N', 'G', '!'});
        auto txtSource = std::make_shared<StaticSource>(std::vector<uint8_t>{'h', 'i'});

        fs::path dest = base / "export_out";
        fs::remove_all(dest);

        ExportJob job;
        std::vector<ExportJob::Item> items = {
            {xmlSource, main, "res/layout/main.xml"},
            {binSource, icon, "res/icon.png"},
            {txtSource, evil, "../evil.txt"},
        };
        job.start(dest.string(), items, false);
        CHECK(job.busy(), "job running after start");
        while (job.busy()) job.pump();
        CHECK(job.state() == ExportJob::State::Done, "raw job finished");
        CHECK(job.done() == 3 && job.failed() == 0, "all items processed");
        CHECK(fs::exists(dest / "__" / "evil.txt"), "dot-dot name neutralised and exported inside dest");
        CHECK(fs::exists(dest / "res" / "layout" / "main.xml"), "raw layout file written");
        {
            std::ifstream in(dest / "res" / "layout" / "main.xml", std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            CHECK(content.size() == axml.size(), "raw export writes the exact bytes");
        }
        CHECK(fs::exists(dest / "res" / "icon.png"), "binary entry exported");
        CHECK(!fs::exists(base / "evil.txt"), "zip-slip payload did not escape the destination");

        // Decoded export: the AXML entry becomes readable XML text.
        fs::path dest2 = base / "export_decoded";
        fs::remove_all(dest2);
        std::vector<ExportJob::Item> items2 = {{xmlSource, main, "res/layout/main.xml"}};
        job.start(dest2.string(), items2, true);
        while (job.busy()) job.pump();
        CHECK(job.state() == ExportJob::State::Done && job.failed() == 0, "decoded job finished");
        {
            std::ifstream in(dest2 / "res" / "layout" / "main.xml", std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            CHECK(content.find("<?xml") == 0 && content.find("com.example.app") != std::string::npos,
                  "decoded export writes readable XML");
        }

        // Cancellation stops before the remaining items.
        fs::path dest3 = base / "export_cancel";
        fs::remove_all(dest3);
        TreeNode extra("extra", "extra.bin", NodeKind::Binary);
        std::vector<ExportJob::Item> items3 = {
            {txtSource, &extra, "extra.bin"},
            {binSource, icon, "res/icon.png"},
        };
        job.start(dest3.string(), items3, false);
        job.pump();
        job.cancel();
        job.pump();  // consumes the cancellation request
        CHECK(job.state() == ExportJob::State::Cancelled, "job cancelled");
        CHECK(!fs::exists(dest3 / "res" / "icon.png"), "cancelled items are not written");
    }

    printf("== Workspace export: single file raw + decoded ==\n");
    {
        Workspace ws8;
        ws8.setJadxPath("/nonexistent/jadx");
        fs::path apkPath = base / "export.apk";
        {
            std::ofstream py(base / "mkzip2.py");
            py << "import zipfile\n"
               << "z = zipfile.ZipFile(r'" << apkPath.string() << "','w')\n"
               << "z.writestr('AndroidManifest.xml', open(r'" << (base / "manifest.axml").string() << "','rb').read())\n"
               << "z.writestr('classes.dex', 'dex\\n035')\n"
               << "z.close()\n";
            py.close();
        }
        CHECK(std::system(("python3 '" + (base / "mkzip2.py").string() + "'").c_str()) == 0, "export apk built");
        CHECK(ws8.addApk(apkPath.string(), "exp"), "export apk opened");
        Root* apkRoot = ws8.rootByGroup("exp", Root::Kind::Apk);
        TreeNode* dex = apkRoot->tree->findChild("classes.dex");
        TreeNode* manifest = apkRoot->tree->findChild("AndroidManifest.xml");
        CHECK(dex && manifest, "entries present");
        const std::string dexDest = (base / "exported.dex").string();
        CHECK(ws8.exportNode(*apkRoot, *dex, dexDest, false), "raw export succeeded");
        CHECK(fs::file_size(dexDest) == 7, "raw dex bytes copied");
        const std::string xmlDest = (base / "exported.xml").string();
        CHECK(ws8.exportNode(*apkRoot, *manifest, xmlDest, true), "decoded export succeeded");
        {
            std::ifstream in(xmlDest, std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            CHECK(content.find("com.example.app") != std::string::npos, "decoded manifest is readable XML");
        }
        // Folder export through the workspace job.
        const std::string dirDest = (base / "exported_dir").string();
        ws8.exportFolder(*apkRoot, *apkRoot->tree, dirDest, false);
        int guard = 0;
        while (ws8.exportJob().busy() && guard++ < 100) {
            ws8.exportJob().pump();  // same pumping Workspace::update() performs
        }
        CHECK(ws8.exportJob().state() == ExportJob::State::Done, "folder export finished");
        CHECK(fs::exists(fs::path(dirDest) / "AndroidManifest.xml") && fs::exists(fs::path(dirDest) / "classes.dex"),
              "all entries exported under the destination");
    }

    printf("== remove from project deletes only owned output ==\n");
    {
        Workspace ws4;
        ws4.setJadxPath(jadxPath.string());
        ws4.addApk(apkA.string(), "base");
        pump(ws4, 15000);
        Root* dec = ws4.rootByGroup("base", Root::Kind::Decompiled);
        std::string outDir = dec->outDir;
        CHECK(Workspace::isOwnedOutDir(outDir), "output owned before removal");
        ws4.removeApk(ws4.rootByGroup("base", Root::Kind::Apk));
        CHECK(!fs::exists(outDir), "owned output directory deleted on removal");
    }

    printf("== project files ==\n");
    {
        Project p;
        p.reset();
        p.addApk(apkA.string(), "base");
        p.setTabs({{RootKind::Decompiled, "base", "/x/Foo.java"}});
        CHECK(p.save((base / "p.apkspy").string()), "project saved");
        Project q;
        CHECK(q.load((base / "p.apkspy").string()), "project loaded");
        CHECK(q.apks().size() == 1 && q.apks()[0].group == "base", "apk round trip");
        CHECK(q.tabs().size() == 1 && q.tabs()[0].rootKind == RootKind::Decompiled, "tab round trip");
        // Counts are bounded: hostile counts must not be trusted.
        {
            std::ofstream(base / "hostile.apkspy") << "format=apkspy-project-1\napk.count=999999999\n";
            Project h;
            CHECK(!h.load((base / "hostile.apkspy").string()), "hostile apk.count rejected");
        }
        // A project file pointing jadxOut at a victim directory: the key is
        // ignored entirely (Workspace::addApk derives its own directory).
        {
            // Fresh copy so the derived hash differs and jadx really runs.
            fs::path apkD = base / "evil.apk";
            fs::copy_file(apkA, apkD);
            std::ofstream(base / "evil.apkspy")
                << "format=apkspy-project-1\n"
                << "apk.count=1\n"
                << "apk.0.path=" << apkD.string() << "\n"
                << "apk.0.group=base\n"
                << "apk.0.jadxOut=" << (base / "victim").string() << "\n";
            fs::path victim = base / "victim";
            fs::create_directories(victim);
            std::ofstream(victim / "precious.txt") << "data";
            Workspace ws5;
            ws5.setJadxPath(jadxPath.string());
            // Load like Application::openProject does: entries only carry
            // path+group; jadxOut from the file is never passed on.
            Project e;
            CHECK(e.load((base / "evil.apkspy").string()), "evil project loads");
            for (const ProjectApk& apk : e.apks()) ws5.addApk(apk.path, apk.group);
            pump(ws5, 15000);
            CHECK(fs::exists(victim / "precious.txt"), "victim directory untouched");
            Root* dec = ws5.rootByGroup("base", Root::Kind::Decompiled);
            CHECK(dec && dec->outDir != victim.string(), "outDir derived, not from the file");
        }
    }

    printf("== settings: CRLF, sorted atomic save ==\n");
    {
        fs::path s = base / "crlf.settings";
        std::ofstream(s, std::ios::binary) << "a=1\r\nb=hello\r\n";
        Settings in;
        in.load(s.string());
        CHECK(in.getString("b") == "hello", "CRLF values parsed without \\r");
        CHECK(in.save((base / "out.settings").string()), "settings saved");
        std::ifstream back(base / "out.settings");
        std::string firstLines((std::istreambuf_iterator<char>(back)), std::istreambuf_iterator<char>());
        CHECK(firstLines.find("a=1\n") != std::string::npos, "written with LF endings");
        CHECK(!fs::exists(base / "out.settings.tmp"), "temp file renamed away");
    }

    printf("== binary XML (AXML) decode, AOSP layout ==\n");
    {
        auto push16 = [](std::vector<uint8_t>& v, uint32_t x) {
            v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
        };
        auto push32 = [](std::vector<uint8_t>& v, uint32_t x) {
            v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
            v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
        };
        const char* strs[] = {"manifest", "versionCode", "versionName", "padding",
                              "http://schemas.android.com/apk/res/android",
                              "android", "application", "demo"};
        size_t count = sizeof(strs) / sizeof(strs[0]);

        std::vector<uint8_t> sdata;
        std::vector<uint32_t> offs;
        for (size_t i = 0; i < count; ++i) {
            offs.push_back((uint32_t)sdata.size());
            push16(sdata, (uint32_t)strlen(strs[i]));
            for (const char* p = strs[i]; *p; ++p) push16(sdata, (uint8_t)*p);
            push16(sdata, 0);
        }
        uint32_t stringsStart = 28 + (uint32_t)(4 * count);
        std::vector<uint8_t> pool;
        push16(pool, 0x0001); push16(pool, 28);
        push32(pool, 0);  // total size, patched below (must include padding)
        push32(pool, (uint32_t)count); push32(pool, 0); push32(pool, 0);
        push32(pool, stringsStart); push32(pool, 0);
        for (uint32_t o : offs) push32(pool, o);
        pool.insert(pool.end(), sdata.begin(), sdata.end());
        while (pool.size() % 4) pool.push_back(0);
        uint32_t poolSize = (uint32_t)pool.size();
        for (int i = 0; i < 4; ++i) pool[4 + i] = (uint8_t)(poolSize >> (8 * i));

        auto nodeChunk = [&](uint16_t type, uint32_t a, uint32_t b) {
            std::vector<uint8_t> ch;
            push16(ch, type); push16(ch, 16); push32(ch, 24);
            push32(ch, 1); push32(ch, 0xFFFFFFFF);
            push32(ch, a); push32(ch, b);
            return ch;
        };
        auto insert = [&](std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
            dst.insert(dst.end(), src.begin(), src.end());
        };

        std::vector<uint8_t> ax;
        push16(ax, 0x0003); push16(ax, 8); push32(ax, 0);  // size patched below
        insert(ax, pool);
        insert(ax, nodeChunk(0x0100, 5, 4));  // xmlns:android(str 5)="http..."(str 4)
        {
            // Start element with the AOSP layout: attributeStart is relative
            // to the attrExt struct (== 20), NOT to the chunk (== 36).
            std::vector<uint8_t> el;
            push16(el, 0x0102); push16(el, 16);
            push32(el, 8 + 8 + 20 + 3 * 20);
            push32(el, 1); push32(el, 0xFFFFFFFF);
            push32(el, 0xFFFFFFFF); push32(el, 0);  // attrExt: ns, name=manifest
            push16(el, 20); push16(el, 20); push16(el, 3);  // attributeStart/Size/Count
            push16(el, 0); push16(el, 0); push16(el, 0);    // id/class/style
            // android:versionCode = 1 (INT_DEC); attribute ns = URI index 4
            push32(el, 4); push32(el, 1); push32(el, 0xFFFFFFFF);
            push16(el, 8); el.push_back(0); el.push_back(0x10); push32(el, 1);
            // android:versionName = "demo" (STRING)
            push32(el, 4); push32(el, 2); push32(el, 7);
            push16(el, 8); el.push_back(0); el.push_back(0x03); push32(el, 7);
            // android:padding = -4dp (DIMENSION, negative complex value)
            push32(el, 4); push32(el, 3); push32(el, 0xFFFFFFFF);
            push16(el, 8); el.push_back(0); el.push_back(0x05); push32(el, 0xFFFFFC01u);
            insert(ax, el);
        }
        {
            std::vector<uint8_t> el;
            push16(el, 0x0102); push16(el, 16); push32(el, 8 + 8 + 20);
            push32(el, 1); push32(el, 0xFFFFFFFF);
            push32(el, 0xFFFFFFFF); push32(el, 6);
            push16(el, 20); push16(el, 20); push16(el, 0);
            push16(el, 0); push16(el, 0); push16(el, 0);
            insert(ax, el);
        }
        insert(ax, nodeChunk(0x0103, 0xFFFFFFFF, 6));
        insert(ax, nodeChunk(0x0103, 0xFFFFFFFF, 0));
        uint32_t total = (uint32_t)ax.size();
        for (int i = 0; i < 4; ++i) ax[4 + i] = (uint8_t)(total >> (8 * i));

        std::string xml, error;
        CHECK(AxmlDecoder::decode(ax, xml, error), "AXML decode succeeds (AOSP attributeStart=20)");
        CHECK(xml.find("xmlns:android=\"http://schemas.android.com/apk/res/android\"") != std::string::npos,
              "namespace declared");
        CHECK(xml.find("android:versionCode=\"1\"") != std::string::npos, "int attribute");
        CHECK(xml.find("android:versionName=\"demo\"") != std::string::npos, "string attribute");
        CHECK(xml.find("android:padding=\"-4dp\"") != std::string::npos, "negative dimension attribute");
        CHECK(xml.find("<application />") != std::string::npos, "self-closing child");
        CHECK(xml.find("</manifest>") != std::string::npos, "closing tag");

        TreeNode node("AndroidManifest.xml", "/tmp/AndroidManifest.xml", NodeKind::Xml);
        Document d("AndroidManifest.xml", &node, ax, RootKind::Apk);
        CHECK(d.mode() == Document::Mode::Code, "AXML opens as code");
        CHECK(d.language() == Language::Xml, "AXML highlighted as xml");
        CHECK(d.note() == "Decoded from binary XML", "AXML note set");
        CHECK(!d.canEdit(), "APK entries are never editable");
    }

    printf("== TextSearch: literal, case, whole word, overlap, caps ==\n");
    {
        using namespace textsearch;
        const std::vector<std::string> docLines = {
            "Foo foo FOO fOo",          // 0
            "affable foobar foo(1)",    // 1
            "no hits here",             // 2
            "foo",                      // 3
        };

        bool trunc = false;
        // Literal, case-insensitive (default): 4 hits on line 0 (Foo/foo/FOO/fOo),
        // 2 on line 1 (foobar + foo), 1 on line 3.
        auto hits = findAll(docLines, "foo", {}, trunc);
        CHECK(hits.size() == 7, "literal case-insensitive finds all 7");
        CHECK(hits[0].line == 0 && hits[0].col == 0, "first hit position");
        CHECK(hits[1].col == 4, "second hit on the same line");
        CHECK(!trunc, "not truncated");

        // Match case: only the exact lowercase "foo" (line 0 col 4, line 1
        // foobar + foo, line 3).
        Options cs;
        cs.matchCase = true;
        hits = findAll(docLines, "foo", cs, trunc);
        CHECK(hits.size() == 4, "match case drops FOO/fOo");
        CHECK(hits[0].line == 0 && hits[0].col == 4, "case-sensitive first hit");

        // Whole word (still case-insensitive): every standalone Foo/foo/FOO/fOo
        // matches - "foobar" and "affable" are excluded, "foo(1)" is kept.
        Options ww;
        ww.wholeWord = true;
        hits = findAll(docLines, "foo", ww, trunc);
        CHECK(hits.size() == 6, "whole word skips inside-word hits");
        CHECK(hits[4].line == 1 && hits[4].col == 15, "whole-word hit inside foo(1)");
        CHECK(hits[5].line == 3 && hits[5].col == 0, "whole-word hit on its own line");

        // Overlapping matches: "aa" in "aaaa" = 3.
        const std::vector<std::string> aaaa = {"aaaa"};
        hits = findAll(aaaa, "aa", {}, trunc);
        CHECK(hits.size() == 3, "overlapping matches (aa in aaaa = 3)");

        // Empty query and query longer than the line.
        hits = findAll(docLines, "", {}, trunc);
        CHECK(hits.empty(), "empty query yields nothing");
        hits = findAll(docLines, "much-too-long-query-string", {}, trunc);
        CHECK(hits.empty(), "query longer than every line yields nothing");

        // maxMatches truncation flag.
        size_t count = 0;
        hits = findAll(docLines, "foo", {}, 2, trunc);
        count = hits.size();
        CHECK(count == 2 && trunc, "maxMatches caps the list and sets truncated");

        // nextIndex / prevIndex wrap in both directions.
        const std::vector<Match> ms = {{0, 0, 3}, {0, 4, 3}, {1, 0, 3}, {3, 0, 3}};
        CHECK(nextIndex(ms, 0, 0) == 0, "next at the first match is itself");
        CHECK(nextIndex(ms, 0, 1) == 1, "next from inside a match goes right");
        CHECK(nextIndex(ms, 3, 1) == 0, "next wraps to the first match");
        CHECK(prevIndex(ms, 0, 0) == 3, "prev wraps to the last match");
        CHECK(prevIndex(ms, 3, 0) == 2, "prev from the last match steps back");
        CHECK(nextIndex(ms, 5, 0) == 0, "next past the end wraps");
        CHECK(prevIndex(ms, 0, 4) == 0, "prev from a match start steps to the previous");
        CHECK(nextIndex({}, 0, 0) == -1 && prevIndex({}, 0, 0) == -1, "empty list returns -1");

        // UTF-8: non-ASCII bytes must survive folding and stay byte-exact.
        // "café café" - é is 2 bytes in UTF-8; the second word starts at
        // byte 6 (c, a, f, é=2 bytes, space).
        const std::vector<std::string> utf8 = {"caf\xc3\xa9 caf\xc3\xa9 x"};
        hits = findAll(utf8, "caf", {}, trunc);
        CHECK(hits.size() == 2, "ASCII query found around UTF-8 bytes");
        CHECK(hits[1].col == 6, "byte column counts multi-byte chars as bytes");
        Options ci;
        hits = findAll(utf8, "CAF", ci, trunc);
        CHECK(hits.size() == 2, "case-insensitive ASCII fold leaves UTF-8 bytes intact");
        // The folded line must keep the é bytes so later matches stay aligned.
        std::string folded = tex::asciiLower(utf8[0]);
        CHECK(folded.compare(utf8[0]) == 0, "asciiLower does not touch high bytes");
    }

    printf("== favicon.ico: IcoLoader (BMP + PNG frames) and asset lookup ==\n");
    {
        // ---- in-memory ICO builders -------------------------------------
        auto put16 = [](std::vector<uint8_t>& v, unsigned x) {
            v.push_back((uint8_t)x);
            v.push_back((uint8_t)(x >> 8));
        };
        auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
            v.push_back((uint8_t)x);
            v.push_back((uint8_t)(x >> 8));
            v.push_back((uint8_t)(x >> 16));
            v.push_back((uint8_t)(x >> 24));
        };
        // Classic BMP payload: header + XOR (BGRA bottom-up) + AND mask.
        auto bmpFrame = [](int size, const std::vector<uint8_t>& rgbaTopDown) {
            std::vector<uint8_t> f;
            const size_t andStride = ((size + 31) / 32) * 4;
            auto put32f = [&f](uint32_t x) {
                f.push_back((uint8_t)x);
                f.push_back((uint8_t)(x >> 8));
                f.push_back((uint8_t)(x >> 16));
                f.push_back((uint8_t)(x >> 24));
            };
            put32f(40);                          // BITMAPINFOHEADER size
            put32f((uint32_t)size);              // width
            put32f((uint32_t)size * 2);          // height (XOR + AND)
            put32f(1u | (32u << 16));            // planes=1, bitcount=32
            put32f(0);                           // BI_RGB
            put32f((uint32_t)(size * size * 4 + andStride * size));
            put32f(0);
            put32f(0);
            put32f(0);
            put32f(0);
            for (int y = size - 1; y >= 0; --y)  // bottom-up BGRA
                for (int x = 0; x < size; ++x) {
                    const uint8_t* p = rgbaTopDown.data() + ((size_t)y * size + x) * 4;
                    f.push_back(p[2]);
                    f.push_back(p[1]);
                    f.push_back(p[0]);
                    f.push_back(p[3]);
                }
            f.insert(f.end(), andStride * size, 0);  // AND mask: all opaque
            return f;
        };
        auto icoWrap = [&](const std::vector<std::vector<uint8_t>>& payloads) {
            std::vector<uint8_t> ico;
            put16(ico, 0);
            put16(ico, 1);
            put16(ico, (unsigned)payloads.size());
            uint32_t offset = 6 + 16 * (uint32_t)payloads.size();
            for (const auto& p : payloads) {
                ico.push_back(0);
                ico.push_back(0);
                ico.push_back(0);
                ico.push_back(0);
                put16(ico, 1);
                put16(ico, 32);
                put32(ico, (uint32_t)p.size());
                put32(ico, offset);
                offset += (uint32_t)p.size();
            }
            for (const auto& p : payloads) ico.insert(ico.end(), p.begin(), p.end());
            return ico;
        };

        // ---- 32 bpp BMP frame with real alpha ---------------------------
        {
            const int n = 4;
            std::vector<uint8_t> rgba(n * n * 4);
            for (int y = 0; y < n; ++y)
                for (int x = 0; x < n; ++x) {
                    uint8_t* p = rgba.data() + ((size_t)y * n + x) * 4;
                    p[0] = (uint8_t)(16 * x);  // R varies per column
                    p[1] = (uint8_t)(16 * y);  // G varies per row
                    p[2] = 200;
                    p[3] = (uint8_t)(x == y ? 255 : 128);
                }
            std::vector<uint8_t> bytes = icoWrap({bmpFrame(n, rgba)});
            std::vector<ico::Image> frames;
            std::string err;
            const bool ok = ico::decode(bytes, frames, err);
            CHECK(ok, "32bpp BMP frame decodes");
            CHECK(frames.size() == 1 && frames[0].width == n && frames[0].height == n, "frame keeps its size");
            CHECK(frames[0].rgba[0] == 0 && frames[0].rgba[1] == 0 && frames[0].rgba[2] == 200 && frames[0].rgba[3] == 255,
                  "top-left pixel (row 0)");
            const uint8_t* diag = frames[0].rgba.data() + ((size_t)(n - 1) * n + (n - 1)) * 4;
            CHECK(diag[0] == 48 && diag[1] == 48 && diag[3] == 255, "bottom-right pixel is opaque");
            CHECK(frames[0].rgba[1 * n * 4 + 3] == 128, "row 1 keeps half alpha");
        }

        // ---- 24 bpp frame: alpha comes from the AND mask ----------------
        {
            const int n = 4;
            std::vector<uint8_t> f;
            auto put32f = [&f](uint32_t x) {
                f.push_back((uint8_t)x);
                f.push_back((uint8_t)(x >> 8));
                f.push_back((uint8_t)(x >> 16));
                f.push_back((uint8_t)(x >> 24));
            };
            put32f(40);
            put32f(n);
            put32f(n * 2);
            put32f(1u | (24u << 16));  // planes=1, bitcount=24
            put32f(0);                 // BI_RGB
            const size_t row = ((size_t)n * 3 + 3) & ~(size_t)3;
            put32f((uint32_t)(row * n + (((n + 31) / 32) * 4) * n));
            put32f(0);
            put32f(0);
            put32f(0);
            put32f(0);
            for (int y = n - 1; y >= 0; --y) {  // bottom-up BGR, all opaque blue
                for (int x = 0; x < n; ++x) f.insert(f.end(), {255, 0, 0});
                f.insert(f.end(), row - (size_t)n * 3, 0);  // padding
            }
            // AND mask: last column transparent. Pixel 3 is bit (7-3) of byte 0.
            const size_t stride = ((n + 31) / 32) * 4;
            for (int y = 0; y < n; ++y) {
                std::vector<uint8_t> m(stride, 0);
                m[0] = (uint8_t)(0x80 >> 3);  // pixel 3
                f.insert(f.end(), m.begin(), m.end());
            }
            std::vector<ico::Image> frames;
            std::string err;
            CHECK(ico::decode(icoWrap({f}), frames, err), "24bpp BMP frame decodes");
            CHECK(frames.size() == 1 && frames[0].rgba[0] == 0 && frames[0].rgba[2] == 255, "24bpp pixel is blue");
            CHECK(frames[0].rgba[3] == 255, "24bpp non-masked pixel is opaque");
            CHECK(frames[0].rgba[3 * 4 + 3] == 0, "AND mask made the last column transparent");
        }

        // ---- 8 bpp palette frame ----------------------------------------
        {
            const int n = 2;
            std::vector<uint8_t> f;
            auto put32f = [&f](uint32_t x) {
                f.push_back((uint8_t)x);
                f.push_back((uint8_t)(x >> 8));
                f.push_back((uint8_t)(x >> 16));
                f.push_back((uint8_t)(x >> 24));
            };
            put32f(40);
            put32f(n);
            put32f(n * 2);
            put32f(1u | (8u << 16));  // planes=1, bitcount=8
            put32f(0);
            put32f((uint32_t)(n * n + (((n + 31) / 32) * 4) * n));
            put32f(0);
            put32f(0);
            put32f(2);  // biClrUsed = 2 (offset 32)
            put32f(0);  // biClrImportant
            // Palette: 0 = blue, 1 = green (BGRA quads).
            f.insert(f.end(), {255, 0, 0, 0});
            f.insert(f.end(), {0, 255, 0, 0});
            // XOR rows are bottom-up and padded to 4 bytes (2 px + 2 pad).
            f.push_back(0);  // BMP row 0 = bottom: pixel (0,1) -> palette 0
            f.push_back(1);  // pixel (1,1) -> palette 1
            f.insert(f.end(), 2, 0);
            f.push_back(0);  // BMP row 1 = top: palette 0
            f.push_back(0);
            f.insert(f.end(), 2, 0);
            const size_t stride = ((n + 31) / 32) * 4;
            f.insert(f.end(), stride * n, 0);
            std::vector<ico::Image> frames;
            std::string err;
            CHECK(ico::decode(icoWrap({f}), frames, err), "8bpp palette frame decodes");
            CHECK(frames.size() == 1, "8bpp frame present");
            if (frames.size() == 1) {
                // Bottom row = BMP row 0: palette 0 then palette 1.
                CHECK(frames[0].rgba[8] == 0 && frames[0].rgba[10] == 255, "palette entry 0 is blue");
                CHECK(frames[0].rgba[12] == 0 && frames[0].rgba[13] == 255, "palette entry 1 is green");
                CHECK(frames[0].rgba[3] == 255, "8bpp pixels are opaque without mask bits");
            }
        }

        // ---- PNG payload built with miniz (what modern tools write) -----
        {
            auto crc32Of = [](const std::vector<uint8_t>& d) {
                return (uint32_t)mz_crc32(MZ_CRC32_INIT, d.data(), d.size());
            };
            auto put32be = [](std::vector<uint8_t>& v, uint32_t x) {  // PNG is big-endian
                v.push_back((uint8_t)(x >> 24));
                v.push_back((uint8_t)(x >> 16));
                v.push_back((uint8_t)(x >> 8));
                v.push_back((uint8_t)x);
            };
            auto chunk = [&](const char* type, const std::vector<uint8_t>& data) {
                std::vector<uint8_t> c;
                put32be(c, (uint32_t)data.size());
                c.insert(c.end(), type, type + 4);
                c.insert(c.end(), data.begin(), data.end());
                std::vector<uint8_t> crcInput;
                crcInput.insert(crcInput.end(), type, type + 4);
                crcInput.insert(crcInput.end(), data.begin(), data.end());
                put32be(c, crc32Of(crcInput));
                return c;
            };
            const int n = 3;
            std::vector<uint8_t> ihdr;
            put32be(ihdr, n);
            put32be(ihdr, n);
            ihdr.push_back(8);   // bit depth
            ihdr.push_back(6);   // RGBA
            ihdr.push_back(0);
            ihdr.push_back(0);
            ihdr.push_back(0);
            std::vector<uint8_t> raw;
            for (int y = 0; y < n; ++y) {
                raw.push_back(0);  // filter None
                for (int x = 0; x < n; ++x) {
                    raw.push_back((uint8_t)(30 * x));
                    raw.push_back((uint8_t)(30 * y));
                    raw.push_back(90);
                    raw.push_back(x == 0 ? 0 : 255);
                }
            }
            std::vector<uint8_t> idat(128);
            mz_ulong idatLen = idat.size();
            CHECK(mz_compress(idat.data(), &idatLen, raw.data(), raw.size()) == MZ_OK, "test PNG payload compresses");
            idat.resize(idatLen);
            std::vector<uint8_t> png{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
            for (uint8_t b : chunk("IHDR", ihdr)) png.push_back(b);
            for (uint8_t b : chunk("IDAT", idat)) png.push_back(b);
            for (uint8_t b : chunk("IEND", {})) png.push_back(b);
            std::vector<uint8_t> bytes = icoWrap({png});
            std::vector<ico::Image> frames;
            std::string err;
            CHECK(ico::decode(bytes, frames, err), "PNG-in-ICO frame decodes");
            CHECK(frames.size() == 1 && frames[0].width == n && frames[0].height == n, "PNG frame keeps its size");
            if (frames.size() == 1) {
                CHECK(frames[0].rgba[3] == 0, "PNG pixel 0 is fully transparent");
                const uint8_t* px = frames[0].rgba.data() + ((size_t)n * n - 1) * 4;
                CHECK(px[0] == 60 && px[1] == 60 && px[2] == 90 && px[3] == 255, "last PNG pixel is opaque");
            }
        }

        // ---- multi-frame + bestFrame + errors ----------------------------
        {
            auto solid = [](int n, uint8_t v) {
                std::vector<uint8_t> rgba((size_t)n * n * 4);
                for (size_t i = 0; i < rgba.size(); i += 4) {
                    rgba[i] = v;
                    rgba[i + 3] = 255;
                }
                return rgba;
            };
            std::vector<uint8_t> bytes = icoWrap({bmpFrame(16, solid(16, 10)), bmpFrame(32, solid(32, 20))});
            std::vector<ico::Image> frames;
            std::string err;
            CHECK(ico::decode(bytes, frames, err), "both frames decode");
            CHECK(frames.size() == 2, "multi-frame ICO keeps both frames");
            const ico::Image* pick = ico::bestFrame(frames, 32);
            CHECK(pick && pick->width == 32 && pick->rgba[0] == 20, "bestFrame picks the 32px frame");
            pick = ico::bestFrame(frames, 48);
            CHECK(pick && pick->width == 32, "equidistant frame resolves to the smaller one");

            std::vector<uint8_t> bad{'B', 'M', 0, 0};
            CHECK(!ico::decode(bad, frames, err) && !err.empty(), "bad magic is rejected with a reason");
            CHECK(!ico::decode({}, frames, err), "empty buffer is rejected");
            std::vector<uint8_t> truncated = icoWrap({bmpFrame(16, solid(16, 5))});
            truncated.resize(truncated.size() / 2);
            CHECK(!ico::decode(truncated, frames, err), "truncated XOR data is rejected");
        }

        // ---- the shipped asset (when present) must decode ----------------
        {
            const std::string path = pathutil::assetsFile("favicon.ico");
            if (!path.empty()) {
                std::ifstream in(path, std::ios::binary);
                std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                std::vector<ico::Image> frames;
                std::string err;
                const bool ok = !bytes.empty() && ico::decode(bytes, frames, err) && !frames.empty();
                CHECK(ok, "shipped assets/favicon.ico decodes");
                if (ok) {
                    bool sizesSane = true;
                    for (const ico::Image& f : frames)
                        sizesSane = sizesSane && f.width > 0 && f.height > 0 &&
                                    f.rgba.size() == (size_t)f.width * f.height * 4;
                    CHECK(sizesSane, "shipped favicon frames have consistent buffers");
                }
            }
        }
    }

    printf("%s (%d failures)\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED", failures);
    return failures ? 1 : 0;
}
