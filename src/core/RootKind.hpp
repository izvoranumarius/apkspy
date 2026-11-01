#pragma once

// Which workspace root a document / tab belongs to. Stored as 0/1 in project
// files; defined once here so Document, Project, PendingTab and Root all
// share it instead of magic ints.
enum class RootKind {
    Apk = 0,
    Decompiled = 1,
};
