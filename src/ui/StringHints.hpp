#pragma once
#include <string>
#include <string_view>
#include "core/Codec.hpp"
#include "imgui.h"
#include "ui/TextSelect.hpp"
#include "ui/UiUtil.hpp"

// Encoded strings in code (Base64, hex, URL, JWT, UTF-16, gzip...): what they
// decode to, as a tooltip over the literal and for "Send string to Decoder".
namespace ui {

// The decoded text with how it was decoded, as a tooltip.
inline void decodedTooltip(const std::string& steps, const std::string& decoded) {
    ImGui::BeginTooltip();
    ImGui::TextDisabled("Decodes as: %s", steps.c_str());
    ImGui::PushTextWrapPos(em(40.f));
    if (decoded.size() > 2000) ImGui::TextUnformatted((decoded.substr(0, 2000) + "...").c_str());
    else ImGui::TextUnformatted(decoded.c_str());
    ImGui::PopTextWrapPos();
    ImGui::TextDisabled("Right-click: Send to Decoder");
    ImGui::EndTooltip();
}

// Tooltip for an encoded string itself (Strings lists). True when it decodes.
inline bool encodedStringTooltip(std::string_view s) {
    std::string decoded, steps;
    if (!codec::decodePreview(s, decoded, steps)) return false;
    decodedTooltip(steps, decoded);
    return true;
}

// Tooltip for the encoded literal of `line` (drawn from screen x `x0`) under mouse x `mx`.
inline bool literalTooltip(std::string_view line, float x0, float mx) {
    if (line.find('"') == std::string_view::npos) return false;
    const auto lits = codec::stringLiterals(line);
    const codec::Literal* lit = codec::literalAt(lits, static_cast<size_t>(TextSelect::colAt(line, x0, mx)));
    return lit && encodedStringTooltip(lit->text);
}

// The literal at byte `col` of `line`, else the line's first one: for "Send string to Decoder".
inline bool literalForMenu(std::string_view line, size_t col, std::string& text) {
    if (line.find('"') == std::string_view::npos) return false;
    const auto lits = codec::stringLiterals(line);
    if (lits.empty()) return false;
    const codec::Literal* lit = codec::literalAt(lits, col);
    text = (lit ? *lit : lits.front()).text;
    return true;
}

// A short inline note for a line holding an encoded literal ("" when none).
inline std::string decodedNote(std::string_view line) {
    if (line.find('"') == std::string_view::npos) return {};
    for (const codec::Literal& lit : codec::stringLiterals(line)) {
        std::string decoded, steps;
        if (!codec::decodePreview(lit.text, decoded, steps)) continue;
        for (char& c : decoded)
            if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (decoded.size() > 90) decoded = decoded.substr(0, 90) + "...";
        return "// decoded: \"" + decoded + "\"";
    }
    return {};
}

}  // namespace ui
