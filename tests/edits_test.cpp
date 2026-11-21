// Tests for src/edit/Edits.hpp: export of edited files, unified diffs, the
// per-file edit report and smali method splicing. In-memory fixtures; the
// export tests write into a fresh directory under the system temp folder.
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "edit/Edits.hpp"

static int failures = 0;
static int passes = 0;
#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (cond) {                                               \
            ++passes;                                             \
        } else {                                                  \
            std::printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
            ++failures;                                           \
        }                                                         \
    } while (0)

namespace fs = std::filesystem;
using edits::EditedFile;
using edits::ExportItem;

namespace {

fs::path freshDir(const char* tag) {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path p = fs::temp_directory_path() / ("apkspy_edits_" + std::string(tag) + "_" + std::to_string(stamp));
    std::error_code ec;
    fs::remove_all(p, ec);
    return p;
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

bool contains(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }

// Everything Unknown except Lcom/missing/... (Missing) and Lcom/app/... (Found, no members known).
class Universe final : public smali::ClassUniverse {
public:
    Lookup findClass(std::string_view d) const override {
        if (d.rfind("Lcom/missing/", 0) == 0) return Lookup::Missing;
        if (d.rfind("Lcom/app/", 0) == 0 || d == "Ljava/lang/Object;") return Lookup::Found;
        return Lookup::Unknown;
    }
    Lookup findMethod(std::string_view, std::string_view, std::string_view) const override { return Lookup::Unknown; }
    Lookup findField(std::string_view, std::string_view, std::string_view) const override { return Lookup::Unknown; }
};

const char* kClass =
    ".class public Lcom/app/Main;\n"          // 0
    ".super Ljava/lang/Object;\n"             // 1
    "\n"                                      // 2
    "# direct methods\n"                      // 3
    ".method public constructor <init>()V\n"  // 4
    "    .registers 1\n"                      // 5
    "    return-void\n"                       // 6
    ".end method\n"                           // 7
    "\n"                                      // 8
    ".method public run(I)V\n"                // 9
    "    .registers 2\n"                      // 10
    "    return-void\n"                       // 11
    ".end method\n"                           // 12
    "\n"                                      // 13
    ".method public run()V\n"                 // 14
    "    .registers 1\n"                      // 15
    "    return-void\n"                       // 16
    ".end method\n";                          // 17

void testExport() {
    const fs::path dir = freshDir("export");
    std::vector<EditedFile> files = {
        {"smali/com/app/Main.smali", "a\nb\n", "a\nB\n"},
        {"sources/com/app/Same.java", "same\n", "same\n"},
        {"sources/com/app/deep/More.java", "x", "x\r\ny"},
    };
    auto r = edits::exportEdits(files, dir);
    CHECK(r.error.empty() && r.written == 2 && r.failed == 0, "changed files are written, unchanged skipped");
    CHECK(slurp(dir / "smali/com/app/Main.smali") == "a\nB\n", "edited text written byte for byte");
    CHECK(slurp(dir / "sources/com/app/deep/More.java") == "x\r\ny", "nested directories created, CRs kept");
    CHECK(!fs::exists(dir / "sources/com/app/Same.java") && r.items[1].status == ExportItem::Status::Unchanged,
          "unchanged file reported, not written");
    CHECK(r.patchWritten && contains(slurp(dir / "edits.patch"), "+++ b/smali/com/app/Main.smali") &&
              !contains(slurp(dir / "edits.patch"), "Same.java"),
          "edits.patch holds the diff of exported files only");

    // Second export into the same directory: existing files are not replaced.
    files[0].edited = "a\nC\n";
    r = edits::exportEdits(files, dir);
    CHECK(r.items[0].status == ExportItem::Status::Exists && r.failed >= 1 && slurp(dir / "smali/com/app/Main.smali") == "a\nB\n",
          "existing file kept without overwrite");
    edits::ExportOptions o;
    o.overwrite = true;
    o.includeUnchanged = true;
    r = edits::exportEdits(files, dir, o);
    CHECK(r.ok() && slurp(dir / "smali/com/app/Main.smali") == "a\nC\n" && slurp(dir / "sources/com/app/Same.java") == "same\n",
          "overwrite + includeUnchanged");

    std::error_code ec;
    fs::remove_all(dir, ec);
}

void testExportSafety() {
    const fs::path dir = freshDir("safety");
    std::vector<EditedFile> files = {
        {"../../escape.smali", "", "evil"},
        {"/abs/x.smali", "", "abs"},
        {"", "", "nothing"},
    };
    edits::ExportOptions o;
    o.writePatch = false;
    const auto r = edits::exportEdits(files, dir, o);
    CHECK(!fs::exists(dir.parent_path() / "escape.smali") && !fs::exists(dir.parent_path().parent_path() / "escape.smali"),
          "'..' cannot escape the destination");
    bool inside = true;
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        const auto rel = fs::relative(e.path(), dir).generic_string();
        if (rel.rfind("..", 0) == 0) inside = false;
    }
    CHECK(inside && r.written == 2, "sanitised files land inside the destination");
    CHECK(r.items[2].status == ExportItem::Status::InvalidPath && !r.patchWritten, "empty path rejected, no patch");

    // Destination is an existing file.
    const fs::path file = freshDir("file");
    { std::ofstream(file) << "x"; }
    const auto bad = edits::exportEdits(files, file);
    CHECK(!bad.error.empty() && bad.written == 0, "destination that is a file is an error");
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::remove(file, ec);
}

void testUnifiedDiff() {
    CHECK(edits::unifiedDiff("f", "a\nb\n", "a\nb\n").empty(), "equal texts: empty diff");
    const std::string d = edits::unifiedDiff("f.txt", "1\n2\n3\n4\n5\n", "1\n2\nthree\n4\n5\n");
    CHECK(d == "--- a/f.txt\n+++ b/f.txt\n@@ -1,5 +1,5 @@\n 1\n 2\n-3\n+three\n 4\n 5\n", "single change, full context");

    std::string a, b;
    for (int i = 1; i <= 30; ++i) a += std::to_string(i) + "\n";
    b = a;
    b.replace(b.find("\n2\n") + 1, 1, "X");    // line 2
    b.replace(b.find("\n28\n") + 1, 2, "Y");   // line 28
    const std::string two = edits::unifiedDiff("n", a, b, 3);
    CHECK(contains(two, "@@ -1,5 +1,5 @@") && contains(two, "@@ -25,6 +25,6 @@"), "far-apart changes: two hunks");
    std::string c = a;
    c.replace(c.find("\n5\n") + 1, 1, "Z");     // line 5, 3 lines after line 2
    c.replace(c.find("\n2\n") + 1, 1, "X");
    const std::string one = edits::unifiedDiff("n", a, c, 3);
    CHECK(contains(one, "@@ -1,8 +1,8 @@") && one.find("@@", 3) == one.rfind("@@ "), "nearby changes merge into one hunk");

    const std::string nl = edits::unifiedDiff("e", "a\nb", "a\nc");
    CHECK(contains(nl, "-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"), "missing final newline marked");
    CHECK(contains(edits::unifiedDiff("new", "", "x\ny\n"), "@@ -0,0 +1,2 @@\n+x\n+y\n"), "file created from empty");
}

void testSplice() {
    const char* frag =
        "# Lcom/app/Main;->run(I)V  (classes.dex)\n"
        ".method public run(I)V\n"
        "    .registers 2\n"
        "    const/4 v0, 0x1\n"
        "    return-void\n"
        ".end method\n";
    const auto s = edits::spliceMethod(kClass, frag);
    CHECK(s.has_value(), "fragment splices");
    if (s) {
        CHECK(contains(s->text, "const/4 v0, 0x1") && contains(s->text, ".method public run()V\n    .registers 1"),
              "overload with the other prototype kept");
        CHECK(s->lineOffset == 8 && s->fragmentLines == 6, "fragment line 1 (.method) maps to class line 9");
        CHECK(s->text.find(".method public run(I)V") == std::string(kClass).find(".method public run(I)V"),
              "method stays in place");
    }
    CHECK(!edits::spliceMethod(kClass, ".method public gone()V\n.end method\n").has_value(), "unknown method: nullopt");
    CHECK(!edits::spliceMethod(kClass, "# just text\n").has_value(), "no method block: nullopt");
}

void testReport() {
    const Universe u;
    std::vector<EditedFile> files;
    files.push_back({"smali/com/app/Main.smali", kClass,
                     std::string(kClass).replace(std::string(kClass).find("    return-void\n.end method\n\n.method public run(I)V"), 16,
                                                 "    new-instance v0, Lcom/missing/Gone;\n    return-void\n")});
    files.push_back({"sources/com/app/A.java", "class A {}\n", "class A { int x; }\n"});
    files.push_back({"sources/com/app/B.java", "same\n", "same\n"});
    // Method fragment with a register error at fragment line 3 (0-based).
    EditedFile frag{"smali/Lcom_app_Main;->run(I)V.smali",
                    "# Lcom/app/Main;->run(I)V  (classes.dex)\n.method public run(I)V\n    .registers 2\n    return-void\n.end method\n",
                    "# Lcom/app/Main;->run(I)V  (classes.dex)\n.method public run(I)V\n    .registers 2\n    const/4 v7, 0x0\n    return-void\n.end method\n"};
    const auto s = edits::spliceMethod(kClass, frag.edited);
    CHECK(s.has_value(), "fixture fragment splices");
    if (s) {
        frag.validationText = s->text;
        frag.validationLineOffset = s->lineOffset;
        frag.fragmentLines = s->fragmentLines;
    }
    files.push_back(frag);

    const auto r = edits::buildReport(files, &u);
    CHECK(r.files.size() == 4 && r.changedFiles == 3, "changed file count");
    CHECK(r.files[0].added == 1 && r.files[0].removed == 0 && r.files[0].hunks == 1, "line counts of the smali edit");
    CHECK(r.files[0].validated && r.files[0].warnings.size() == 1 &&
              r.files[0].warnings[0].check == smali::Check::UnresolvedType && r.files[0].warnings[0].line == 7,
          "smali file validated: dangling type warning");
    CHECK(!r.files[1].validated && r.files[1].errors.empty(), "java file diffed, not validated");
    CHECK(!r.files[2].changed && r.files[2].diff.empty(), "unchanged file");
    CHECK(r.files[3].errors.size() == 1 && r.files[3].errors[0].check == smali::Check::RegisterBounds &&
              r.files[3].errors[0].line == 4 && r.files[3].errors[0].file == frag.path,
          "fragment diagnostic mapped back to the fragment's line and path");
    CHECK(r.errors == 1 && r.warnings == 1, "totals");

    const auto nov = edits::buildReport(files, nullptr);
    CHECK(!nov.files[0].validated && nov.errors == 0, "no universe: no validation");

    const std::string t = edits::renderText(r);
    CHECK(contains(t, "3 changed file(s), +3 -1, 1 error(s), 1 warning(s)") && contains(t, "smali/com/app/Main.smali") &&
              contains(t, "register-bounds") && contains(t, "@@ ") && !contains(t, "B.java"),
          "text rendering: summary, diagnostics, diffs, unchanged omitted");
}

}  // namespace

int main() {
    std::printf("edits tests\n");
    testExport();
    testExportSafety();
    testUnifiedDiff();
    testSplice();
    testReport();
    std::printf("%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
