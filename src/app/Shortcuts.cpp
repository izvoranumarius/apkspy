#include "app/Shortcuts.hpp"
#include <algorithm>
#include <cctype>
#include "core/Settings.hpp"

namespace shortcuts {

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Display symbol <-> canonical name for punctuation keys.
struct Punct {
    const char* name;
    const char* symbol;
};
const Punct kPunct[] = {{"Comma", ","},      {"Period", "."},      {"Minus", "-"},     {"Equal", "="},         {"GraveAccent", "`"},
                        {"Slash", "/"},      {"Backslash", "\\"},  {"Semicolon", ";"}, {"Apostrophe", "'"},    {"LeftBracket", "["},
                        {"RightBracket", "]"}};

const char* const kNamed[] = {"Space", "Enter", "Tab", "Left", "Right", "Up", "Down", "Home", "End", "PageUp", "PageDown",
                              "Insert", "Delete", "Backspace", "Escape"};

std::vector<std::string> buildKeyNames() {
    std::vector<std::string> out;
    for (char c = 'A'; c <= 'Z'; ++c) out.emplace_back(1, c);
    for (char c = '0'; c <= '9'; ++c) out.emplace_back(1, c);
    for (int i = 1; i <= 12; ++i) out.push_back("F" + std::to_string(i));
    for (const Punct& p : kPunct) out.emplace_back(p.name);
    for (const char* n : kNamed) out.emplace_back(n);
    return out;
}

// Canonical name for user text ("p", "f5", ",", "grave", "left"), or "".
std::string canonicalKey(const std::string& text) {
    if (text.empty()) return {};
    for (const Punct& p : kPunct)
        if (text == p.symbol) return p.name;
    const std::string l = lower(text);
    for (const std::string& n : keyNames())
        if (lower(n) == l) return n;
    if (l == "grave" || l == "backtick") return "GraveAccent";
    if (l == "esc") return "Escape";
    if (l == "return") return "Enter";
    if (l == "del") return "Delete";
    if (l == "pgup") return "PageUp";
    if (l == "pgdn" || l == "pgdown") return "PageDown";
    return {};
}

bool isFunctionKey(const std::string& key) { return key.size() >= 2 && key[0] == 'F' && std::isdigit(static_cast<unsigned char>(key[1])); }

}  // namespace

const std::vector<std::string>& keyNames() {
    static const std::vector<std::string> names = buildKeyNames();
    return names;
}

bool validKey(const std::string& key) {
    const auto& n = keyNames();
    return std::find(n.begin(), n.end(), key) != n.end();
}

bool parse(const std::string& text, Chord& out) {
    Chord c;
    std::string rest = text;
    // Split on '+', but a trailing "+" key ("Ctrl++") is the plus sign itself (not offered as a key, so reject).
    size_t start = 0;
    std::vector<std::string> parts;
    for (size_t i = 0; i <= rest.size(); ++i) {
        if (i == rest.size() || rest[i] == '+') {
            std::string p = rest.substr(start, i - start);
            while (!p.empty() && (p.front() == ' ' || p.front() == '\t')) p.erase(p.begin());
            while (!p.empty() && (p.back() == ' ' || p.back() == '\t')) p.pop_back();
            parts.push_back(p);
            start = i + 1;
        }
    }
    if (parts.empty()) return false;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        const std::string m = lower(parts[i]);
        if (m == "ctrl" || m == "control") c.ctrl = true;
        else if (m == "shift") c.shift = true;
        else if (m == "alt" || m == "option") c.alt = true;
        else return false;
    }
    c.key = canonicalKey(parts.back());
    if (c.key.empty()) return false;
    if (!c.ctrl && !c.shift && !c.alt && !isFunctionKey(c.key)) return false;  // a bare letter would steal typing
    out = c;
    return true;
}

std::string format(const Chord& c) {
    if (!c.valid()) return {};
    std::string out;
    if (c.ctrl) out += "Ctrl+";
    if (c.shift) out += "Shift+";
    if (c.alt) out += "Alt+";
    std::string key = c.key;
    for (const Punct& p : kPunct)
        if (key == p.name) key = p.symbol;
    return out + key;
}

const std::vector<Action>& actions() {
    static const std::vector<Action> k = {
        {"open-project", "Open project", "Ctrl+O"},
        {"save-project", "Save project", "Ctrl+S"},
        {"settings", "Settings", "Ctrl+,"},
        {"quick-open", "Quick open (file / class)", "Ctrl+P"},
        {"command-palette", "Command palette", "Ctrl+Shift+P"},
        {"find-in-project", "Find in project", "Ctrl+Shift+F"},
        {"toggle-terminal", "Show / hide the terminal", "Ctrl+`"},
        {"new-terminal", "New terminal", "Ctrl+Shift+`"},
        {"nav-back", "Navigate back", "Alt+Left"},
        {"nav-forward", "Navigate forward", "Alt+Right"},
    };
    return k;
}

namespace {
const Action* findAction(const std::string& id) {
    for (const Action& a : actions())
        if (id == a.id) return &a;
    return nullptr;
}
Chord defaultChord(const Action& a) {
    Chord c;
    parse(a.defaultChord, c);
    return c;
}
}  // namespace

Map::Map() = default;

void Map::load(const Settings& settings) {
    custom_.clear();
    for (const Action& a : actions()) {
        const std::string v = settings.getString(settingsKey(a.id), "");
        if (v.empty()) continue;
        if (lower(v) == "none") {
            custom_[a.id] = Chord{};
            continue;
        }
        Chord c;
        if (parse(v, c) && !(c == defaultChord(a))) custom_[a.id] = c;
    }
    // A file edited by hand can put two actions on one chord: an override that collides with a
    // default or with an override of an earlier action (by id) is dropped.
    for (const Action& a : actions()) {
        const auto it = custom_.find(a.id);
        if (it == custom_.end() || !it->second.valid()) continue;
        const Chord mine = it->second;
        for (const Action& b : actions())
            if (b.id != std::string(a.id) && chord(b.id) == mine && (!custom_.count(b.id) || std::string(b.id) < std::string(a.id))) {
                custom_.erase(a.id);
                break;
            }
    }
}

void Map::save(Settings& settings) const {
    for (const Action& a : actions()) {
        const auto it = custom_.find(a.id);
        if (it == custom_.end()) settings.remove(settingsKey(a.id));
        else settings.set(settingsKey(a.id), it->second.valid() ? format(it->second) : std::string("none"));
    }
}

Chord Map::chord(const std::string& id) const {
    const auto it = custom_.find(id);
    if (it != custom_.end()) return it->second;
    const Action* a = findAction(id);
    return a ? defaultChord(*a) : Chord{};
}

std::string Map::label(const std::string& id) const { return format(chord(id)); }

bool Map::isCustom(const std::string& id) const { return custom_.count(id) != 0; }

bool Map::set(const std::string& id, const Chord& c, std::string& conflict) {
    conflict.clear();
    if (!findAction(id) || !c.valid()) return false;
    for (const Action& a : actions())
        if (id != a.id && chord(a.id) == c) {
            conflict = a.id;
            return false;
        }
    if (c == defaultChord(*findAction(id))) custom_.erase(id);
    else custom_[id] = c;
    return true;
}

void Map::disable(const std::string& id) {
    if (findAction(id)) custom_[id] = Chord{};
}

void Map::reset(const std::string& id) { custom_.erase(id); }

void Map::resetAll() { custom_.clear(); }

}  // namespace shortcuts
