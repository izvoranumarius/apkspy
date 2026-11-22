#pragma once

// The operating system's light / dark preference.
namespace systemtheme {

// 1 = the system uses a dark app theme, 0 = light, -1 = unknown (this
// platform exposes no setting, or it could not be read).
int prefersDark();

// The preset id to use for the system preference ("dark-modern" or "light"),
// or an empty string when the preference is unknown.
const char* presetFor(int prefersDark);

}  // namespace systemtheme
