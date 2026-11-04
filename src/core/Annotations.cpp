#include "core/Annotations.hpp"
#include <algorithm>

namespace {
bool valid(const Annotation& a) {
    if (a.group.empty() || a.path.empty()) return false;
    if (a.target == Annotation::Target::File)
        return (a.root == RootKind::Apk || a.root == RootKind::Decompiled) && a.line >= 0;
    return a.target == Annotation::Target::Native;
}
}  // namespace

int Annotations::set(Annotation a) {
    if (!valid(a)) return 0;
    if (a.text.size() > kMaxText) a.text.resize(kMaxText);
    if (a.context.size() > 300) a.context.resize(300);
    for (Annotation& existing : items_)
        if (existing.kind == a.kind && existing.sameLocation(a)) {
            existing.text = std::move(a.text);
            if (!a.context.empty()) existing.context = std::move(a.context);
            ++version_;
            return existing.id;
        }
    if (items_.size() >= kMaxItems) return 0;
    a.id = nextId_++;
    items_.push_back(std::move(a));
    ++version_;
    return items_.back().id;
}

bool Annotations::remove(int id) {
    auto it = std::find_if(items_.begin(), items_.end(), [id](const Annotation& a) { return a.id == id; });
    if (it == items_.end()) return false;
    items_.erase(it);
    ++version_;
    return true;
}

bool Annotations::updateText(int id, const std::string& text) {
    for (Annotation& a : items_)
        if (a.id == id) {
            a.text = text.size() > kMaxText ? text.substr(0, kMaxText) : text;
            ++version_;
            return true;
        }
    return false;
}

const Annotation* Annotations::find(int id) const {
    for (const Annotation& a : items_)
        if (a.id == id) return &a;
    return nullptr;
}

const Annotation* Annotations::at(Annotation::Kind kind, const Annotation& location) const {
    for (const Annotation& a : items_)
        if (a.kind == kind && a.sameLocation(location)) return &a;
    return nullptr;
}

bool Annotations::toggleBookmark(const Annotation& location) {
    if (const Annotation* existing = at(Annotation::Kind::Bookmark, location)) {
        remove(existing->id);
        return false;
    }
    Annotation b = location;
    b.kind = Annotation::Kind::Bookmark;
    return set(std::move(b)) != 0;
}

void Annotations::removeGroup(const std::string& group) {
    const size_t before = items_.size();
    items_.erase(std::remove_if(items_.begin(), items_.end(), [&](const Annotation& a) { return a.group == group; }),
                 items_.end());
    if (items_.size() != before) ++version_;
}

void Annotations::clear() {
    if (items_.empty()) return;
    items_.clear();
    ++version_;
}

void Annotations::replaceAll(std::vector<Annotation> items) {
    items_.clear();
    for (Annotation& a : items) {
        a.id = 0;
        set(std::move(a));  // validates, dedupes and assigns fresh ids
    }
    ++version_;
}

std::string Annotations::escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out.push_back(c);
    }
    return out;
}

std::string Annotations::unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 == s.size()) {
            out.push_back(s[i]);
            continue;
        }
        const char n = s[++i];
        out.push_back(n == 'n' ? '\n' : n == 'r' ? '\r' : n);
    }
    return out;
}
