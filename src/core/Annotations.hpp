#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "core/RootKind.hpp"

// User annotations (IDA-style): bookmarks and comments attached either to a
// line of a file of the APK / decompiled trees, or to an address of a native
// library; and decompiler variable renames, per Dalvik method or native function. Owned by the Workspace (shared by the editor, the native listing,
// the Bookmarks panel and MCP) and saved inside the project file.
//
// At most one bookmark and one comment exist per location: adding again
// replaces the text. Owner thread only (UI thread / MCP dispatcher).
struct Annotation {
    // Rename / Retype: a decompiler variable's name / type (IDA's N / Y), per function.
    // Symbol: any other name of the decompiled code (function, method, field, class, label,
    // global), renamed in every function of the APK (Method target, path "*") or of a native
    // library (Native target, addr 0).
    enum class Kind : uint8_t { Bookmark = 0, Comment = 1, Rename = 2, Retype = 3, Symbol = 4 };
    // Method: a Dalvik method, path = its signature (Lcom/a/B;->m(I)V).
    enum class Target : uint8_t { File = 0, Native = 1, Method = 2 };

    int id = 0;
    Kind kind = Kind::Bookmark;
    Target target = Target::File;
    std::string group;             // APK group
    RootKind root = RootKind::Apk; // File: Apk or Decompiled tree
    std::string path;              // File: node path; Native: library entry (lib/arm64-v8a/libfoo.so)
    int line = 0;                  // File: 0-based line
    uint64_t addr = 0;             // Native: virtual address (Rename / Retype: the function's entry)
    std::string text;              // comment text / optional bookmark label (may be multi-line) / new name / type
    std::string context;           // the annotated line / instruction when it was created (for lists);
                                   // Rename / Retype: the variable's original name (v3, arg0, x19)

    bool sameLocation(const Annotation& o) const {
        if (target != o.target || group != o.group || path != o.path) return false;
        if (target == Target::File) return root == o.root && line == o.line;
        return target == Target::Method || addr == o.addr;
    }
    // A name / type note of the decompiler (keyed by `context`, not shown as a bookmark or comment).
    bool variableNote() const { return kind == Kind::Rename || kind == Kind::Retype || kind == Kind::Symbol; }
    // Same annotation slot: one bookmark / comment per location, one name and one type per variable.
    bool sameSlot(const Annotation& o) const {
        return kind == o.kind && sameLocation(o) && (!variableNote() || context == o.context);
    }
};

class Annotations {
public:
    const std::vector<Annotation>& all() const { return items_; }
    // Bumped on every change (dirty tracking, UI caches).
    uint64_t version() const { return version_; }

    // Adds, or replaces the text of the existing annotation of the same kind at
    // the same location. Returns its id (0 when the annotation is invalid).
    int set(Annotation a);
    bool remove(int id);
    bool updateText(int id, const std::string& text);
    const Annotation* find(int id) const;
    const Annotation* at(Annotation::Kind kind, const Annotation& location) const;
    // Toggles a bookmark at a location; returns true when one now exists.
    bool toggleBookmark(const Annotation& location);
    // Variable names / types of a decompiled function (location: Method / Native target): original name -> value.
    std::vector<std::pair<std::string, std::string>> renames(const Annotation& location) const {
        return variableNotes(location, Annotation::Kind::Rename);
    }
    std::vector<std::pair<std::string, std::string>> retypes(const Annotation& location) const {
        return variableNotes(location, Annotation::Kind::Retype);
    }
    std::vector<std::pair<std::string, std::string>> variableNotes(const Annotation& location, Annotation::Kind kind) const;

    void removeGroup(const std::string& group);
    void clear();
    void replaceAll(std::vector<Annotation> items);

    // Text escaping for the one-line key=value project format.
    static std::string escape(const std::string& s);
    static std::string unescape(const std::string& s);
    static constexpr size_t kMaxItems = 100000;
    static constexpr size_t kMaxText = 16384;

private:
    std::vector<Annotation> items_;
    int nextId_ = 1;
    uint64_t version_ = 1;
};
