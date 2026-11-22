#pragma once
#include <map>
#include <string>
#include <vector>

class Settings;

// Customisable global keyboard shortcuts. The model here is pure (no ImGui):
// chords are parsed from / formatted to text ("Ctrl+Shift+P"), every action
// has a default chord, and a user override is stored in the settings file as
// "shortcut.<action id>" (an empty value means the default; "none" disables
// the action). Editor-local keys (find, go to line, bookmarks, debugger F-keys)
// and the fixed zoom / workspace-switch keys are not part of this table.
namespace shortcuts {

struct Chord {
    bool ctrl = false, shift = false, alt = false;
    std::string key;  // canonical key name: "P", "5", "F5", "Comma", "GraveAccent", "Left", ...
    bool valid() const { return !key.empty(); }
    bool operator==(const Chord& o) const { return ctrl == o.ctrl && shift == o.shift && alt == o.alt && key == o.key; }
};

// Accepts "ctrl+shift+p", "Alt+Left", "Ctrl+,", "Ctrl+`" ... Returns false for
// an unknown key or an empty string. A chord needs at least one modifier
// unless the key is a function key (a bare letter would steal typing).
bool parse(const std::string& text, Chord& out);
// "Ctrl+Shift+P", "Ctrl+,", "Alt+Left" - what the menus show.
std::string format(const Chord& c);
// True when `key` is a canonical key name this model knows.
bool validKey(const std::string& key);
// All canonical key names (for the UI's key capture).
const std::vector<std::string>& keyNames();

struct Action {
    const char* id;            // stable: "quick-open"
    const char* label;         // "Quick open file / class"
    const char* defaultChord;  // "Ctrl+P"
};
const std::vector<Action>& actions();

class Map {
public:
    Map();
    // Reads "shortcut.<id>" overrides; unknown or invalid values fall back to the default.
    void load(const Settings& settings);
    // Writes only the overrides (defaults are not stored).
    void save(Settings& settings) const;

    // The effective chord (override or default). Invalid = the action is disabled.
    Chord chord(const std::string& id) const;
    std::string label(const std::string& id) const;  // format(chord(id)), "" when disabled
    bool isCustom(const std::string& id) const;
    // Sets an override. False (and `conflict` = the other action's id) when the
    // chord is already used by another action; the map is left unchanged.
    bool set(const std::string& id, const Chord& chord, std::string& conflict);
    void disable(const std::string& id);
    void reset(const std::string& id);
    void resetAll();
    static std::string settingsKey(const std::string& id) { return "shortcut." + id; }

private:
    std::map<std::string, Chord> custom_;     // id -> chord (invalid chord = disabled)
};

}  // namespace shortcuts
