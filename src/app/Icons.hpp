#pragma once
// Icons from the Windows icon font (Segoe Fluent Icons on Windows 11, Segoe
// MDL2 Assets on Windows 10), merged into the UI font by Theme::loadFonts.
// Every code point here was checked to exist in both fonts. Use ui::icon()
// so text stays readable where the font is missing (other platforms).
#include "imgui.h"

namespace icons {

constexpr const char* FOLDER = "\xEE\xA2\xB7";  // U+E8B7 folder
constexpr const char* FOLDER_OPEN = "\xEE\xA0\xB8";  // U+E838 open folder
constexpr const char* FILE = "\xEE\xA2\xA5";  // U+E8A5 document
constexpr const char* SEARCH = "\xEE\x9C\xA1";  // U+E721 search
constexpr const char* SETTINGS = "\xEE\x9C\x93";  // U+E713 gear
constexpr const char* TERMINAL = "\xEE\x9D\x96";  // U+E756 command prompt
constexpr const char* PLAY = "\xEE\x9D\xA8";  // U+E768 play
constexpr const char* PAUSE = "\xEE\x9D\xA9";  // U+E769 pause
constexpr const char* STOP = "\xEE\x9C\x9A";  // U+E71A stop
constexpr const char* CODE = "\xEE\xA5\x83";  // U+E943 code
constexpr const char* BUG = "\xEE\xAF\xA8";  // U+EBE8 bug
constexpr const char* GLOBE = "\xEE\x9D\xB4";  // U+E774 globe
constexpr const char* HISTORY = "\xEE\xA0\x9C";  // U+E81C history
constexpr const char* COPY = "\xEE\xA3\x88";  // U+E8C8 copy
constexpr const char* CLOSE = "\xEE\x9C\x91";  // U+E711 cancel
constexpr const char* ADD = "\xEE\x9C\x90";  // U+E710 add
constexpr const char* BACK = "\xEE\x9C\xAB";  // U+E72B back
constexpr const char* FORWARD = "\xEE\x9C\xAA";  // U+E72A forward
constexpr const char* OPEN = "\xEE\xA3\xA5";  // U+E8E5 open file
constexpr const char* SAVE = "\xEE\x9D\x8E";  // U+E74E save
constexpr const char* INFO = "\xEE\xA5\x86";  // U+E946 info
constexpr const char* ERROR = "\xEE\x9E\x83";  // U+E783 error
constexpr const char* WARNING = "\xEE\x9E\xBA";  // U+E7BA warning
constexpr const char* AUDIO = "\xEE\xA3\x96";  // U+E8D6 audio
constexpr const char* VIDEO = "\xEE\x9C\x94";  // U+E714 video
constexpr const char* FONT = "\xEE\xA3\x92";  // U+E8D2 font
constexpr const char* FILTER = "\xEE\x9C\x9C";  // U+E71C filter
constexpr const char* EDIT = "\xEE\x9C\x8F";  // U+E70F edit
constexpr const char* CHEVRON_RIGHT = "\xEE\x9D\xAC";  // U+E76C chevron right
constexpr const char* CHEVRON_DOWN = "\xEE\x9C\x8D";  // U+E70D chevron down
constexpr const char* PHONE = "\xEE\xA3\xAA";  // U+E8EA cellphone
constexpr const char* ANALYSIS = "\xEE\xA7\x99";  // U+E9D9 diagnostic
constexpr const char* PAGE = "\xEE\x9F\x83";  // U+E7C3 page
constexpr const char* LIBRARY = "\xEE\xA3\xB1";  // U+E8F1 library
constexpr const char* LIST = "\xEE\xA3\xBD";  // U+E8FD bulleted list
constexpr const char* CHART = "\xEE\xA7\xB9";  // U+E9F9 chart
constexpr const char* PACKAGE = "\xEE\x9E\xB8";  // U+E7B8 package
constexpr const char* BOOKMARK = "\xEE\x9C\xB4";  // U+E734 star
constexpr const char* PIN = "\xEE\x9C\x98";  // U+E718 pin
constexpr const char* LINK = "\xEE\x9C\x9B";  // U+E71B link
constexpr const char* FLAG = "\xEE\x9F\x81";  // U+E7C1 flag
constexpr const char* REFRESH = "\xEE\x9C\xAC";  // U+E72C refresh

// The code points above, as an ImGui glyph range list (pairs, 0-terminated).
inline const ImWchar* glyphRanges() {
    static const ImWchar ranges[] = {
        0xE70D, 0xE70D, 0xE70F, 0xE70F, 0xE710, 0xE710, 0xE711, 0xE711, 0xE713, 0xE713, 0xE714, 0xE714,
        0xE718, 0xE718, 0xE71A, 0xE71A, 0xE71B, 0xE71B, 0xE71C, 0xE71C, 0xE721, 0xE721, 0xE72A, 0xE72A,
        0xE72B, 0xE72B, 0xE72C, 0xE72C, 0xE734, 0xE734, 0xE74E, 0xE74E, 0xE756, 0xE756, 0xE768, 0xE768,
        0xE769, 0xE769, 0xE76C, 0xE76C, 0xE774, 0xE774, 0xE783, 0xE783, 0xE7B8, 0xE7B8, 0xE7BA, 0xE7BA,
        0xE7C1, 0xE7C1, 0xE7C3, 0xE7C3, 0xE81C, 0xE81C, 0xE838, 0xE838, 0xE8A5, 0xE8A5, 0xE8B7, 0xE8B7,
        0xE8C8, 0xE8C8, 0xE8D2, 0xE8D2, 0xE8D6, 0xE8D6, 0xE8E5, 0xE8E5, 0xE8EA, 0xE8EA, 0xE8F1, 0xE8F1,
        0xE8FD, 0xE8FD, 0xE943, 0xE943, 0xE946, 0xE946, 0xE9D9, 0xE9D9, 0xE9F9, 0xE9F9, 0xEBE8, 0xEBE8,
        0,
    };
    return ranges;
}

}  // namespace icons
