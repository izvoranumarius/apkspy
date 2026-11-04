#pragma once

// Which workspace root a document / tab belongs to. Stored as 0/1 in project
// files; defined once here so Document, Project, PendingTab and Root all
// share it instead of magic ints.
enum class RootKind {
    Apk = 0,
    Decompiled = 1,
    // Generated listings (smali disassembly, CFG text, ...) held in memory.
    // Never written to project files: the content is derived data.
    Virtual = 2,
};
