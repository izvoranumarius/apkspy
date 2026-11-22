#pragma once
#include <string>
#include "app/Shortcuts.hpp"
#include "imgui.h"

// ImGui side of the shortcut model: key names -> ImGuiKey, "was this chord
// pressed this frame", and key capture for the rebinding UI.
namespace shortcuts {

// ImGuiKey_None for a name this model does not know.
ImGuiKey toImGuiKey(const std::string& name);

// True on the frame the chord's key goes down with exactly its modifiers held
// (no auto-repeat). An invalid chord (a disabled action) never fires.
bool pressed(const Chord& c);

// While the user is rebinding: the chord pressed this frame (any known key
// except Escape, with the modifiers held), if one was.
bool captureChord(Chord& out);

}  // namespace shortcuts
