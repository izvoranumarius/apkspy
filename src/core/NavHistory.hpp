#pragma once
#include <cstddef>
#include <string>
#include <vector>
#include "core/RootKind.hpp"

// One navigable location: the owning group + kind select the root, `path`
// selects the node (zip entry path for APK roots, absolute disk path for
// decompiled roots) and `line` is the 0-based line to land on.
struct NavLocation {
    RootKind kind = RootKind::Apk;
    std::string group;
    std::string path;
    int line = 0;

    bool operator==(const NavLocation& o) const {
        return kind == o.kind && group == o.group && path == o.path && line == o.line;
    }
    bool operator!=(const NavLocation& o) const { return !(*this == o); }
    // Same document, ignoring the line (used to decide whether an origin
    // refreshes the current entry or has to be recorded as its own entry).
    bool sameDocument(const NavLocation& o) const {
        return kind == o.kind && group == o.group && path == o.path;
    }
};

// Editor-wide navigation history for Back/Forward (M2). Pure logic, no
// Workspace/UI dependencies, so the cursor semantics are unit-testable.
//
// A vector + cursor: `navigate` drops everything after the cursor, appends
// and trims the front once more than `maxEntries` items are stored.
// `back()`/`forward()` only MOVE the cursor and return the new current entry
// (or nullptr at either end) - resolving and opening the location is the
// caller's job, so unresolvable entries can be skipped one by one.
class NavHistory {
public:
    explicit NavHistory(size_t maxEntries = 100) : maxEntries_(maxEntries) {}

    // Records a jump (M2.2: "record the origin, then record/replace the
    // destination").
    //  - `origin` (the active document + its top visible line) refreshes the
    //    CURRENT entry's line when it is the same document, so Back returns
    //    exactly where the user was. When the user is leaving a document the
    //    history does not track as current (tab clicks create no entries),
    //    the origin becomes its own entry instead.
    //  - `dest` is appended after dropping the forward stack. A `dest` equal
    //    to the current entry is ignored (duplicate suppression).
    //  - nullptr origin: only the destination is recorded.
    void navigate(const NavLocation* origin, const NavLocation& dest) {
        if (origin) {
            if (!entries_.empty() && origin->sameDocument(entries_[cursor_])) {
                entries_[cursor_].line = origin->line;  // Back lands on the line the user left
                if (dest == entries_[cursor_]) return;
            } else if (entries_.empty() || *origin != entries_[cursor_]) {
                truncateForward();
                entries_.push_back(*origin);
                cursor_ = entries_.size() - 1;
                if (dest == *origin) return;
            }
        }
        if (!entries_.empty() && dest == entries_[cursor_]) return;
        truncateForward();
        entries_.push_back(dest);
        cursor_ = entries_.size() - 1;
        trimFront();
    }

    bool canBack() const { return cursor_ > 0; }
    bool canForward() const { return !entries_.empty() && cursor_ + 1 < entries_.size(); }

    // Moves the cursor back and returns the new current entry, or nullptr
    // when there is nothing to go back to.
    const NavLocation* back() {
        if (!canBack()) return nullptr;
        --cursor_;
        return &entries_[cursor_];
    }

    const NavLocation* forward() {
        if (!canForward()) return nullptr;
        ++cursor_;
        return &entries_[cursor_];
    }

    // Drops every entry of one APK group (Remove from Project). The cursor
    // stays on the same location when it survives, otherwise it lands on the
    // last remaining entry.
    void purgeGroup(const std::string& group) {
        if (entries_.empty()) return;
        const NavLocation currentNow = entries_[cursor_];
        size_t kept = 0;
        for (size_t i = 0; i < entries_.size(); ++i) {
            if (entries_[i].group == group) continue;
            if (kept != i) entries_[kept] = std::move(entries_[i]);
            ++kept;
        }
        if (kept == entries_.size()) return;  // nothing belonged to the group
        entries_.resize(kept);
        cursor_ = 0;
        for (size_t i = entries_.size(); i-- > 0;)
            if (entries_[i] == currentNow) { cursor_ = i; break; }
    }

    void clear() {
        entries_.clear();
        cursor_ = 0;
    }

    size_t size() const { return entries_.size(); }

private:
    void truncateForward() {
        if (cursor_ + 1 < entries_.size()) entries_.resize(cursor_ + 1);
    }

    void trimFront() {
        if (entries_.size() <= maxEntries_) return;
        const size_t drop = entries_.size() - maxEntries_;
        entries_.erase(entries_.begin(), entries_.begin() + drop);
        cursor_ = entries_.size() - 1;
    }

    std::vector<NavLocation> entries_;
    size_t cursor_ = 0;
    size_t maxEntries_;
};
