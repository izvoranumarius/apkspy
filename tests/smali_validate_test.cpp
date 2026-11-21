// Tests for smali::validate (src/smali/Validate.hpp). Pure fixtures: smali
// source built in code, a map-backed ClassUniverse; no APK, no file system.
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "smali/Validate.hpp"

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

namespace {

using smali::Check;
using smali::ClassUniverse;
using smali::Diagnostic;
using smali::Severity;
using smali::SourceFile;
using smali::ValidationResult;

// A small class world: com.app classes are "the APK", java/ and android/
// are the platform (Unknown, as with no android.jar loaded).
class FakeUniverse final : public ClassUniverse {
public:
    struct Cls {
        std::string super;
        std::set<std::string> methods;  // "name(proto)ret"
        std::set<std::string> fields;   // "name:type"
    };
    std::map<std::string, Cls> classes;

    FakeUniverse() {
        classes["Lcom/app/Base;"] = {"Ljava/lang/Object;", {"<init>()V", "baseMethod()V"}, {"baseField:I"}};
        classes["Lcom/app/Known;"] = {"Lcom/app/Base;", {"<init>()V", "work(I)Ljava/lang/String;", "run()V"},
                                      {"count:I", "name:Ljava/lang/String;"}};
        classes["Lcom/app/Util;"] = {"Ljava/lang/Object;", {"helper(JD)V"}, {}};
    }
    static bool platform(std::string_view d) { return d.rfind("Ljava/", 0) == 0 || d.rfind("Landroid/", 0) == 0; }
    // As in DexUniverse: Ljava/lang/Object; alone is known exactly (its JLS
    // members, no fields); every other platform class stays Unknown.
    static bool objectHas(const std::string& key) {
        static const std::set<std::string> m = {"<init>()V", "equals(Ljava/lang/Object;)Z", "hashCode()I",
                                                "toString()Ljava/lang/String;", "getClass()Ljava/lang/Class;", "notify()V",
                                                "notifyAll()V", "wait()V", "wait(J)V", "wait(JI)V",
                                                "clone()Ljava/lang/Object;", "finalize()V"};
        return m.count(key) != 0;
    }
    Lookup findClass(std::string_view d) const override {
        if (classes.count(std::string(d)) || d == "Ljava/lang/Object;") return Lookup::Found;
        return platform(d) ? Lookup::Unknown : Lookup::Missing;
    }
    Lookup member(std::string_view owner, const std::string& key, bool method) const {
        std::string cur(owner);
        for (int guard = 0; guard < 16; ++guard) {
            if (cur == "Ljava/lang/Object;") return method && objectHas(key) ? Lookup::Found : Lookup::Missing;
            auto it = classes.find(cur);
            if (it == classes.end()) return platform(cur) ? Lookup::Unknown : Lookup::Missing;
            if ((method ? it->second.methods : it->second.fields).count(key)) return Lookup::Found;
            cur = it->second.super;
        }
        return Lookup::Missing;
    }
    Lookup findMethod(std::string_view owner, std::string_view name, std::string_view proto) const override {
        return member(owner, std::string(name) + std::string(proto), true);
    }
    Lookup findField(std::string_view owner, std::string_view name, std::string_view type) const override {
        return member(owner, std::string(name) + ":" + std::string(type), false);
    }
};

const FakeUniverse& world() {
    static const FakeUniverse u;
    return u;
}

// A class wrapper around a method body.
std::string classWith(const std::string& methods, const std::string& cls = "Lcom/app/Edited;") {
    return ".class public " + cls + "\n.super Ljava/lang/Object;\n.source \"Edited.java\"\n\n" + methods;
}

ValidationResult run(const std::string& text, const std::string& path = "smali/com/app/Edited.smali") {
    return smali::validate(SourceFile{path, text}, world());
}

size_t count(const std::vector<Diagnostic>& ds, Check c) {
    return static_cast<size_t>(std::count_if(ds.begin(), ds.end(), [c](const Diagnostic& d) { return d.check == c; }));
}

const Diagnostic* first(const std::vector<Diagnostic>& ds, Check c) {
    for (const auto& d : ds)
        if (d.check == c) return &d;
    return nullptr;
}

std::string dump(const ValidationResult& r) {
    std::string out;
    for (const auto* list : {&r.errors, &r.warnings})
        for (const auto& d : *list)
            out += "\n    " + std::string(d.severity == Severity::Error ? "E " : "W ") + smali::checkName(d.check) + " " +
                   std::to_string(d.line) + ":" + std::to_string(d.column) + " " + d.message;
    return out;
}

// ---------------------------------------------------------------------------

void testClean() {
    std::printf("== clean code ==\n");
    // Lines:                                          1 .class 2 .super 3 .source 4 blank 5..
    const auto r = run(classWith(
        ".field private count:I\n"
        "\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n"
        "    return-void\n"
        ".end method\n"
        "\n"
        ".method public static greet(Lcom/app/Known;I)Ljava/lang/String;\n"
        "    .locals 2\n"
        "    .param p0, \"k\"    # Lcom/app/Known;\n"
        "    .line 12\n"
        "    if-lez p1, :skip\n"
        "    invoke-virtual {p0, p1}, Lcom/app/Known;->work(I)Ljava/lang/String;\n"
        "    move-result-object v0\n"
        "    return-object v0\n"
        "    :skip\n"
        "    iget v1, p0, Lcom/app/Known;->count:I\n"
        "    invoke-virtual {p0}, Lcom/app/Known;->baseMethod()V\n"  // inherited from Base
        "    const-string v0, \"Lcom/missing/OnlyInAString;\"\n"   // a string, not a type
        "    # new-instance v0, Lcom/missing/InAComment;\n"
        "    return-object v0\n"
        ".end method\n"));
    CHECK(r.clean(), ("valid edited class has no diagnostics" + dump(r)).c_str());
}

void testSyntax() {
    std::printf("== syntax ==\n");
    {
        const auto r = run(classWith(".method public static f()V\n    .registers 1\n    return-void\n"));  // no .end method
        CHECK(r.hasErrors() && count(r.errors, Check::Syntax) >= 1, ("missing .end method" + dump(r)).c_str());
    }
    {
        const auto r = run(classWith(".method public static f()V\n    .registers 1\n    frobnicate v0\n    return-void\n.end method\n"));
        const Diagnostic* d = first(r.errors, Check::Syntax);
        CHECK(d && d->line == 7 && d->column == 5 && d->length == 10 && d->message.find("frobnicate") != std::string::npos,
              ("unknown opcode, with its span" + dump(r)).c_str());
    }
    {
        const auto r = run(classWith(".method public static f()V\n    .registers 1\n    move vx, v0\n    return-void\n.end method\n"));
        const Diagnostic* d = first(r.errors, Check::Syntax);
        CHECK(d && d->line == 7 && d->column == 10, ("malformed register" + dump(r)).c_str());
    }
    {
        const auto r = run(classWith(".method public static f()V\n    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::Syntax) == 1, ("instructions without .registers / .locals" + dump(r)).c_str());
    }
    {
        const auto r = run(classWith(".method public static f()V\n    .registers 1\n"
                                     "    invoke-static {}, Lcom/app/Util;->helper(JD\n    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::Syntax) == 1, ("unterminated method prototype" + dump(r)).c_str());
    }
    {
        const auto r = run(".super Ljava/lang/Object;\n");
        CHECK(count(r.errors, Check::Syntax) == 1 && r.errors[0].line == 1, ("missing .class" + dump(r)).c_str());
    }
    {
        // Parsing continues after an error: both bad lines are reported.
        const auto r = run(classWith(".method public static f()V\n    .registers 1\n    bogus1\n    bogus2\n    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::Syntax) == 2 && r.errors[0].line == 7 && r.errors[1].line == 8,
              ("recovers and reports each bad line" + dump(r)).c_str());
    }
}

void testRegisterBounds() {
    std::printf("== register bounds ==\n");
    {
        // .registers 2, static (I)V: p0 == v1; v2 and p1 are out of range.
        const auto r = run(classWith(".method public static f(I)V\n    .registers 2\n"
                                     "    move v0, p0\n"      // line 7: ok
                                     "    move v2, v0\n"      // line 8: v2 out
                                     "    move v0, p1\n"      // line 9: p1 out
                                     "    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 2, ("two out-of-range registers" + dump(r)).c_str());
        const Diagnostic* d = first(r.errors, Check::RegisterBounds);
        CHECK(d && d->line == 8 && d->column == 10 && d->length == 2 && d->severity == Severity::Error,
              ("v2 reported at its span" + dump(r)).c_str());
    }
    {
        // .locals 1, non-static (I)V: this + int -> 3 registers; v2 ok (== p1), v3 out.
        const auto r = run(classWith(".method public g(I)V\n    .locals 1\n"
                                     "    move v2, v0\n"
                                     "    move v3, v0\n"
                                     "    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 1 && r.errors[0].line == 8, (".locals + implicit this" + dump(r)).c_str());
    }
    {
        // Wide parameters take two registers: static (JD)V .locals 0 -> p0..p3.
        const auto r = run(classWith(".method public static h(JD)V\n    .locals 0\n"
                                     "    move-wide p0, p2\n"   // ok: p2,p3
                                     "    move-wide v0, p3\n"   // p3 + its pair p4: out
                                     "    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 1 && r.errors[0].line == 8, ("wide parameters and pairs" + dump(r)).c_str());
    }
    {
        // The second half of a wide destination counts.
        const auto r = run(classWith(".method public static w()V\n    .registers 2\n"
                                     "    const-wide v1, 0x1L\n"  // v1,v2: v2 out
                                     "    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 1, ("wide pair upper half" + dump(r)).c_str());
    }
    {
        // Ranges: every register in {v0 .. v3} must fit.
        const auto r = run(classWith(".method public static r()V\n    .registers 3\n"
                                     "    invoke-static/range {v0 .. v3}, Lcom/app/Util;->helper(JD)V\n"
                                     "    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 1, ("register range end" + dump(r)).c_str());
    }
    {
        // Each method has its own count.
        const auto r = run(classWith(".method public static a()V\n    .registers 5\n    move v4, v0\n    return-void\n.end method\n"
                                     ".method public static b()V\n    .registers 1\n    move v4, v0\n    return-void\n.end method\n"));
        CHECK(count(r.errors, Check::RegisterBounds) == 1 && r.errors[0].line == 12, ("per-method counts" + dump(r)).c_str());
    }
}

void testUnresolvedTypes() {
    std::printf("== unresolved types ==\n");
    const auto r = run(classWith(".method public static t()V\n    .registers 2\n"
                                 "    new-instance v0, Lcom/missing/Thing;\n"          // line 7: warning
                                 "    check-cast v0, Lcom/app/Known;\n"                 // ok
                                 "    const-class v1, [Lcom/missing/Elem;\n"            // line 9: element type
                                 "    const-class v1, [I\n"                             // primitive array: ok
                                 "    const-class v1, Ljava/lang/String;\n"             // platform: Unknown, silent
                                 "    instance-of v1, v0, Lcom/missing/Thing;\n"        // line 12: reported again
                                 "    return-void\n.end method\n"));
    CHECK(r.errors.empty(), ("unresolved types are not errors" + dump(r)).c_str());
    CHECK(count(r.warnings, Check::UnresolvedType) == 3, ("three unresolved type uses" + dump(r)).c_str());
    const Diagnostic* d = first(r.warnings, Check::UnresolvedType);
    CHECK(d && d->line == 7 && d->column == 22 && d->message.find("Lcom/missing/Thing;") != std::string::npos &&
              d->severity == Severity::Warning,
          ("warning names the type at its span" + dump(r)).c_str());

    // Types in declarations count too: .super, .implements, field types, method signatures, catch.
    const auto decl = run(".class public Lcom/app/E2;\n.super Lcom/missing/Parent;\n.implements Lcom/missing/Iface;\n"
                          ".field private f:Lcom/missing/FieldType;\n"
                          ".method public static m(Lcom/missing/Arg;)Lcom/missing/Ret;\n    .registers 2\n"
                          "    :try_start\n    const/4 v0, 0x0\n    :try_end\n"
                          "    .catch Lcom/missing/Ex; {:try_start .. :try_end} :handler\n"
                          "    :handler\n    const/4 v0, 0x0\n    return-object v0\n.end method\n");
    CHECK(count(decl.warnings, Check::UnresolvedType) == 6, ("declaration and catch types" + dump(decl)).c_str());

    // Annotation contents are skipped (Signature strings look like types).
    const auto ann = run(classWith(".annotation system Ldalvik/annotation/Signature;\n"
                                   "    value = {\n        \"Ljava/util/List<\",\n        \"Lcom/missing/Generic;\",\n        \">;\"\n    }\n"
                                   ".end annotation\n"));
    CHECK(ann.clean(), ("annotation values not checked" + dump(ann)).c_str());
}

void testUnresolvedMembers() {
    std::printf("== unresolved members ==\n");
    const auto r = run(classWith(".method public static m(Lcom/app/Known;)V\n    .registers 3\n"
                                 "    invoke-virtual {p0}, Lcom/app/Known;->missing()V\n"            // line 7: method warning
                                 "    invoke-virtual {p0}, Lcom/app/Known;->run()V\n"                // ok
                                 "    invoke-virtual {p0, v0}, Lcom/app/Known;->work(J)Ljava/lang/String;\n"  // line 9: wrong proto
                                 "    iget v0, p0, Lcom/app/Known;->count:I\n"                      // ok
                                 "    iget v0, p0, Lcom/app/Known;->baseField:I\n"                  // inherited: ok
                                 "    iget v0, p0, Lcom/app/Known;->nope:I\n"                       // line 12: field warning
                                 "    iget-object v0, p0, Lcom/app/Known;->count:Ljava/lang/String;\n"  // line 13: wrong type
                                 "    invoke-static {}, Lcom/missing/Owner;->x()V\n"                // line 14: type only
                                 "    invoke-virtual {v1}, Ljava/lang/String;->anything()V\n"      // platform: silent
                                 "    return-void\n.end method\n"));
    CHECK(r.errors.empty(), ("unresolved members are not errors" + dump(r)).c_str());
    CHECK(count(r.warnings, Check::UnresolvedMethod) == 2, ("missing method and wrong prototype" + dump(r)).c_str());
    CHECK(count(r.warnings, Check::UnresolvedField) == 2, ("missing field and wrong field type" + dump(r)).c_str());
    CHECK(count(r.warnings, Check::UnresolvedType) == 1 && first(r.warnings, Check::UnresolvedType)->line == 14,
          ("unresolved owner: one type warning, no member warning" + dump(r)).c_str());
    const Diagnostic* m = first(r.warnings, Check::UnresolvedMethod);
    CHECK(m && m->line == 7 && m->message.find("missing()V") != std::string::npos, ("method warning text and line" + dump(r)).c_str());
}

void testArrayOwners() {
    std::printf("== array-typed member owners ==\n");
    // Members of array types (clone, length) are never looked up; the element
    // type of an object array is still a type use, and signature types after
    // a primitive-array owner keep their own columns (a regression: they were
    // placed as if the owner had contributed a type).
    const auto r = run(classWith(".method public static a()V\n    .registers 1\n"
                                 "    invoke-virtual {v0}, [I->clone()Lcom/missing/Ret;\n"                // line 7
                                 "    invoke-virtual {v0}, [Lcom/app/Known;->clone()Ljava/lang/Object;\n"  // line 8: clean
                                 "    invoke-virtual {v0}, [Lcom/missing/Elem;->clone()Ljava/lang/Object;\n"  // line 9
                                 "    return-void\n.end method\n"));
    CHECK(r.errors.empty() && count(r.warnings, Check::UnresolvedMethod) == 0, ("array members are not looked up" + dump(r)).c_str());
    CHECK(r.warnings.size() == 2 && r.warnings[0].check == Check::UnresolvedType && r.warnings[0].line == 7 &&
              r.warnings[0].column == 37 && r.warnings[0].length == 17 && r.warnings[0].message.find("Lcom/missing/Ret;") != std::string::npos,
          ("signature type after a primitive-array owner at its own column" + dump(r)).c_str());
    CHECK(r.warnings.size() == 2 && r.warnings[1].line == 9 && r.warnings[1].column == 27 &&
              r.warnings[1].message.find("Lcom/missing/Elem;") != std::string::npos,
          ("object-array owner: the element type is checked" + dump(r)).c_str());
}

void testListingFormat() {
    std::printf("== ApkSpy listing format (/* offset */ prefixes) ==\n");
    // As ApkSpy's own method listings print it: each instruction after its
    // code-unit offset in a block comment.
    const auto clean = run(classWith(".method public final clear()V\n"
                                     "    .registers 3\n"
                                     "    .line 1116\n"
                                     "    /* 0000 */ invoke-virtual {v2}, Lcom/app/Known;->run()V\n"
                                     "    /* 0003 */ move-result-wide v0\n"
                                     "    /* 0004 */ invoke-virtual {v2}, Lcom/app/Known;->run()V\n"
                                     "    /* 0007 */ return-void\n"
                                     ".end method\n"));
    CHECK(clean.clean(), ("listing with offset comments validates" + dump(clean)).c_str());

    const auto r = run(classWith(".method public static f()V\n    .registers 3\n"
                                 "    /* 0000 */ move v5, v0\n"                                       // line 7: v5 at column 21
                                 "    /* Lcom/missing/InBlock; */ const/4 v0, 0x0\n"                 // a type in a comment: ignored
                                 "    const-string v0, \"/* not a comment */\"\n"                     // inside a string: kept
                                 "    /* never closed\n"                                             // line 10
                                 "    return-void\n.end method\n"));
    CHECK(count(r.errors, Check::RegisterBounds) == 1 && first(r.errors, Check::RegisterBounds)->line == 7 &&
              first(r.errors, Check::RegisterBounds)->column == 21,
          ("columns are exact after an offset comment" + dump(r)).c_str());
    CHECK(r.warnings.empty(), ("types inside /* */ are not references" + dump(r)).c_str());
    CHECK(count(r.errors, Check::Syntax) == 1 && first(r.errors, Check::Syntax)->line == 10 &&
              first(r.errors, Check::Syntax)->column == 5,
          ("unterminated /* is a syntax error" + dump(r)).c_str());
}

void testEditedSet() {
    std::printf("== files validated together ==\n");
    // A new class defined in one edited file resolves from another; a method
    // the edits added to an existing class resolves; one they removed does not.
    const SourceFile added{"smali/com/app/Added.smali",
                           ".class public Lcom/app/Added;\n.super Ljava/lang/Object;\n"
                           ".field public static flag:Z\n"
                           ".method public static make()Lcom/app/Added;\n    .registers 1\n    const/4 v0, 0x0\n    return-object v0\n.end method\n"};
    const SourceFile known{"smali/com/app/Known.smali",  // an edited copy of an APK class: run() removed, extra() added
                           ".class public Lcom/app/Known;\n.super Lcom/app/Base;\n"
                           ".method public extra()V\n    .registers 1\n    return-void\n.end method\n"};
    const SourceFile user{"smali/com/app/User.smali",
                          ".class public Lcom/app/User;\n.super Ljava/lang/Object;\n"
                          ".method public static u(Lcom/app/Known;)V\n    .registers 2\n"
                          "    invoke-static {}, Lcom/app/Added;->make()Lcom/app/Added;\n"
                          "    sget-boolean v0, Lcom/app/Added;->flag:Z\n"
                          "    invoke-virtual {p0}, Lcom/app/Known;->extra()V\n"
                          "    invoke-virtual {p0}, Lcom/app/Known;->run()V\n"        // line 8: removed by the edit
                          "    invoke-virtual {p0}, Lcom/app/Known;->baseMethod()V\n"  // still inherited from Base
                          "    return-void\n.end method\n"};
    const std::vector<SourceFile> files = {added, known, user};
    const auto r = smali::validate(files, world());
    CHECK(r.errors.empty(), ("no errors across the set" + dump(r)).c_str());
    CHECK(r.warnings.size() == 1 && r.warnings[0].check == Check::UnresolvedMethod && r.warnings[0].file == user.path &&
              r.warnings[0].line == 8,
          ("only the removed method is reported, in the right file" + dump(r)).c_str());
}

void testOrderingAndFields() {
    std::printf("== result shape ==\n");
    const std::vector<SourceFile> files = {
        {"smali/b/B.smali", classWith(".method public static f()V\n    .registers 1\n    move v3, v0\n    return-void\n.end method\n",
                                      "Lb/B;")},
        {"smali/a/A.smali", classWith(".method public static f()V\n    .registers 1\n    move v5, v0\n    move v6, v0\n    return-void\n.end method\n",
                                      "La/A;")},
    };
    const auto r = smali::validate(files, world());
    CHECK(r.errors.size() == 3 && r.errors[0].file == "smali/a/A.smali" && r.errors[0].line == 7 && r.errors[1].line == 8 &&
              r.errors[2].file == "smali/b/B.smali",
          ("errors ordered by file, line, column" + dump(r)).c_str());
    CHECK(std::string(smali::checkName(Check::RegisterBounds)) == "register-bounds" &&
              std::string(smali::checkName(Check::UnresolvedType)) == "unresolved-type",
          "stable check names");
    const auto empty = smali::validate(std::span<const SourceFile>{}, world());
    CHECK(empty.clean(), "no files: clean");
}

}  // namespace

int main() {
    testClean();
    testSyntax();
    testRegisterBounds();
    testUnresolvedTypes();
    testUnresolvedMembers();
    testArrayOwners();
    testListingFormat();
    testEditedSet();
    testOrderingAndFields();
    std::printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
