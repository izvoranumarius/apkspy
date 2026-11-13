// Built-in colour themes. Each preset lists its base colours; the status,
// editor-overlay and graph tokens it leaves out are derived from them (see
// finish()). The palettes of the named schemes follow their published
// definitions (Solarized, Nord, Dracula, Gruvbox, One Dark - all MIT).
#include <initializer_list>
#include <utility>
#include <vector>
#include "app/Theme.hpp"

namespace {

using Entry = std::pair<Col, const char*>;

ImVec4 hex(const char* s) {
    ImVec4 c;
    Theme::fromHex(s, c);
    return c;
}

ImVec4 withAlpha(ImVec4 c, float a) {
    c.w = a;
    return c;
}

ThemePreset make(const char* id, const char* name, bool dark, std::initializer_list<Entry> entries) {
    ThemePreset p;
    p.id = id;
    p.name = name;
    p.dark = dark;
    std::array<bool, kColCount> set{};
    for (const auto& [c, value] : entries) {
        p.colors[static_cast<size_t>(c)] = hex(value);
        set[static_cast<size_t>(c)] = true;
    }
    const auto derive = [&](Col c, const ImVec4& v) {
        if (!set[static_cast<size_t>(c)]) p.colors[static_cast<size_t>(c)] = v;
    };
    const auto at = [&](Col c) { return p.colors[static_cast<size_t>(c)]; };
    derive(Col::Success, at(Col::Green));
    derive(Col::Warning, at(Col::Orange));
    derive(Col::Error, at(Col::Red));
    derive(Col::Info, at(Col::Blue));
    derive(Col::LineHighlight, withAlpha(at(Col::Text), dark ? 0.06f : 0.07f));
    derive(Col::FindMatch, withAlpha(at(Col::Yellow), dark ? 0.18f : 0.30f));
    derive(Col::FindMatchCurrent, withAlpha(at(Col::Orange), dark ? 0.40f : 0.45f));
    derive(Col::SymbolLink, withAlpha(at(Col::Blue), 0.85f));
    derive(Col::Caret, at(Col::Text));
    derive(Col::StatusBar, at(Col::Background));
    derive(Col::StatusBarText, at(Col::TextMuted));
    return p;
}

}  // namespace

std::vector<ThemePreset> buildThemePresets() {
    std::vector<ThemePreset> out;

    // The original ApkSpy look (VS Code "Dark Modern"); the title bar now
    // matches the window instead of the older Visual Studio grey.
    out.push_back(make("dark-modern", "Dark Modern", true, {
        {Col::Background, "#181818"}, {Col::EditorBackground, "#1F1F1F"}, {Col::PopupBackground, "#1F1F1F"},
        {Col::TitleBar, "#181818"}, {Col::Border, "#2B2B2B"},
        {Col::Control, "#313131"}, {Col::ControlHover, "#3C3C3C"}, {Col::RowHover, "#2A2D2E"},
        {Col::RowSelected, "#04395E"}, {Col::TextSelection, "#264F78"}, {Col::Text, "#CCCCCC"},
        {Col::TextMuted, "#9D9D9D"}, {Col::TextOnAccent, "#FFFFFF"}, {Col::Accent, "#0078D4"},
        {Col::Red, "#F07878"}, {Col::Orange, "#F2A659"}, {Col::Yellow, "#EBC46E"}, {Col::Green, "#73C991"},
        {Col::Cyan, "#64C8D7"}, {Col::Blue, "#8CBFF2"}, {Col::Purple, "#BE96EB"}, {Col::Pink, "#E07AB8"},
        {Col::SynDefault, "#DCDCDC"}, {Col::SynKeyword, "#569CD6"}, {Col::SynString, "#D69D85"},
        {Col::SynComment, "#57A64A"}, {Col::SynNumber, "#B5CEA8"}, {Col::SynType, "#4EC9B0"},
        {Col::SynPunctuation, "#B4B4B4"}, {Col::SynAttribute, "#9CDCFE"}, {Col::SynDirective, "#C586C0"},
        {Col::LineNumber, "#6E7681"}, {Col::LineNumberActive, "#CCCCCC"},
        {Col::GraphNode, "#252526"}, {Col::GraphNodeBorder, "#6B6B74"},
        {Col::Ansi0, "#0C0C0C"}, {Col::Ansi1, "#C50F1F"}, {Col::Ansi2, "#13A10E"}, {Col::Ansi3, "#C19C00"},
        {Col::Ansi4, "#0037DA"}, {Col::Ansi5, "#881798"}, {Col::Ansi6, "#3A96DD"}, {Col::Ansi7, "#CCCCCC"},
        {Col::Ansi8, "#767676"}, {Col::Ansi9, "#E74856"}, {Col::Ansi10, "#16C60C"}, {Col::Ansi11, "#F9F1A5"},
        {Col::Ansi12, "#3B78FF"}, {Col::Ansi13, "#B4009E"}, {Col::Ansi14, "#61D6D6"}, {Col::Ansi15, "#F2F2F2"},
    }));

    out.push_back(make("light", "Light", false, {
        {Col::Background, "#F3F3F3"}, {Col::EditorBackground, "#FFFFFF"}, {Col::PopupBackground, "#FFFFFF"},
        {Col::TitleBar, "#F3F3F3"}, {Col::Border, "#DDDDDD"},
        {Col::Control, "#E4E4E4"}, {Col::ControlHover, "#D6D6D6"}, {Col::RowHover, "#E8E8E8"},
        {Col::RowSelected, "#CDE3F7"}, {Col::TextSelection, "#ADD6FF"}, {Col::Text, "#2B2B2B"},
        {Col::TextMuted, "#6C6C6C"}, {Col::TextOnAccent, "#FFFFFF"}, {Col::Accent, "#005FB8"},
        {Col::Red, "#C42B1C"}, {Col::Orange, "#B35900"}, {Col::Yellow, "#8A6A00"}, {Col::Green, "#2E7D32"},
        {Col::Cyan, "#00838F"}, {Col::Blue, "#0451A5"}, {Col::Purple, "#7B3FB0"}, {Col::Pink, "#C2185B"},
        {Col::SynDefault, "#1F1F1F"}, {Col::SynKeyword, "#0000FF"}, {Col::SynString, "#A31515"},
        {Col::SynComment, "#008000"}, {Col::SynNumber, "#098658"}, {Col::SynType, "#267F99"},
        {Col::SynPunctuation, "#505050"}, {Col::SynAttribute, "#E50000"}, {Col::SynDirective, "#AF00DB"},
        {Col::LineNumber, "#919191"}, {Col::LineNumberActive, "#1F1F1F"}, {Col::Caret, "#000000"},
        {Col::GraphNode, "#FFFFFF"}, {Col::GraphNodeBorder, "#939393"},
        {Col::Ansi0, "#000000"}, {Col::Ansi1, "#CD3131"}, {Col::Ansi2, "#00BC00"}, {Col::Ansi3, "#949800"},
        {Col::Ansi4, "#0451A5"}, {Col::Ansi5, "#BC05BC"}, {Col::Ansi6, "#0598BC"}, {Col::Ansi7, "#555555"},
        {Col::Ansi8, "#666666"}, {Col::Ansi9, "#CD3131"}, {Col::Ansi10, "#14CE14"}, {Col::Ansi11, "#B5BA00"},
        {Col::Ansi12, "#0451A5"}, {Col::Ansi13, "#BC05BC"}, {Col::Ansi14, "#0598BC"}, {Col::Ansi15, "#A5A5A5"},
    }));

    out.push_back(make("high-contrast", "High Contrast", true, {
        {Col::Background, "#000000"}, {Col::EditorBackground, "#000000"}, {Col::PopupBackground, "#0C0C0C"},
        {Col::TitleBar, "#000000"}, 
        {Col::Border, "#6FC3DF"}, {Col::Control, "#1A1A1A"}, {Col::ControlHover, "#333333"},
        {Col::RowHover, "#1F1F1F"}, {Col::RowSelected, "#0F4A85"}, {Col::TextSelection, "#264F78"},
        {Col::Text, "#FFFFFF"}, {Col::TextMuted, "#D0D0D0"}, {Col::TextOnAccent, "#000000"}, {Col::Accent, "#F38518"},
        {Col::Red, "#F48771"}, {Col::Orange, "#F38518"}, {Col::Yellow, "#FFD700"}, {Col::Green, "#89D185"},
        {Col::Cyan, "#4EE6E6"}, {Col::Blue, "#75BEFF"}, {Col::Purple, "#D670D6"}, {Col::Pink, "#FF69B4"},
        {Col::SynDefault, "#FFFFFF"}, {Col::SynKeyword, "#569CD6"}, {Col::SynString, "#CE9178"},
        {Col::SynComment, "#7CA668"}, {Col::SynNumber, "#B5CEA8"}, {Col::SynType, "#4EC9B0"},
        {Col::SynPunctuation, "#FFFFFF"}, {Col::SynAttribute, "#9CDCFE"}, {Col::SynDirective, "#C586C0"},
        {Col::LineHighlight, "#FFFFFF1F"}, {Col::LineNumber, "#AAAAAA"}, {Col::LineNumberActive, "#FFFFFF"},
        {Col::GraphNode, "#000000"}, {Col::GraphNodeBorder, "#6FC3DF"},
        {Col::Ansi0, "#000000"}, {Col::Ansi1, "#CD0000"}, {Col::Ansi2, "#00CD00"}, {Col::Ansi3, "#CDCD00"},
        {Col::Ansi4, "#3B78FF"}, {Col::Ansi5, "#CD00CD"}, {Col::Ansi6, "#00CDCD"}, {Col::Ansi7, "#E5E5E5"},
        {Col::Ansi8, "#7F7F7F"}, {Col::Ansi9, "#FF0000"}, {Col::Ansi10, "#00FF00"}, {Col::Ansi11, "#FFFF00"},
        {Col::Ansi12, "#5C5CFF"}, {Col::Ansi13, "#FF00FF"}, {Col::Ansi14, "#00FFFF"}, {Col::Ansi15, "#FFFFFF"},
    }));

    out.push_back(make("solarized-dark", "Solarized Dark", true, {
        {Col::Background, "#00212B"}, {Col::EditorBackground, "#002B36"}, {Col::PopupBackground, "#073642"},
        {Col::TitleBar, "#00212B"}, 
        {Col::Border, "#0B3F4C"}, {Col::Control, "#073642"}, {Col::ControlHover, "#0B4A59"},
        {Col::RowHover, "#073642"}, {Col::RowSelected, "#093848"}, {Col::TextSelection, "#274642"},
        {Col::Text, "#93A1A1"}, {Col::TextMuted, "#8D9DA3"}, {Col::TextOnAccent, "#000000"}, {Col::Accent, "#268BD2"},
        {Col::Red, "#DC322F"}, {Col::Orange, "#CB4B16"}, {Col::Yellow, "#B58900"}, {Col::Green, "#859900"},
        {Col::Cyan, "#2AA198"}, {Col::Blue, "#268BD2"}, {Col::Purple, "#6C71C4"}, {Col::Pink, "#D33682"},
        {Col::SynDefault, "#839496"}, {Col::SynKeyword, "#859900"}, {Col::SynString, "#2AA198"},
        {Col::SynComment, "#62777D"}, {Col::SynNumber, "#D33682"}, {Col::SynType, "#B58900"},
        {Col::SynPunctuation, "#839496"}, {Col::SynAttribute, "#268BD2"}, {Col::SynDirective, "#CB4B16"},
        {Col::LineNumber, "#62777D"}, {Col::LineNumberActive, "#93A1A1"},
        {Col::GraphNode, "#073642"}, {Col::GraphNodeBorder, "#62777D"},
        {Col::Ansi0, "#073642"}, {Col::Ansi1, "#DC322F"}, {Col::Ansi2, "#859900"}, {Col::Ansi3, "#B58900"},
        {Col::Ansi4, "#268BD2"}, {Col::Ansi5, "#D33682"}, {Col::Ansi6, "#2AA198"}, {Col::Ansi7, "#EEE8D5"},
        {Col::Ansi8, "#586E75"}, {Col::Ansi9, "#CB4B16"}, {Col::Ansi10, "#859900"}, {Col::Ansi11, "#B58900"},
        {Col::Ansi12, "#268BD2"}, {Col::Ansi13, "#6C71C4"}, {Col::Ansi14, "#2AA198"}, {Col::Ansi15, "#FDF6E3"},
    }));

    out.push_back(make("solarized-light", "Solarized Light", false, {
        {Col::Background, "#EEE8D5"}, {Col::EditorBackground, "#FDF6E3"}, {Col::PopupBackground, "#FDF6E3"},
        {Col::TitleBar, "#EEE8D5"}, {Col::Border, "#DDD6C1"},
        {Col::Control, "#E3DCC8"}, {Col::ControlHover, "#D8D0B9"}, {Col::RowHover, "#E6DFCB"},
        {Col::RowSelected, "#D3E3EE"}, {Col::TextSelection, "#E5DFCB"}, {Col::Text, "#4F6369"},
        {Col::TextMuted, "#5C6869"}, {Col::TextOnAccent, "#000000"}, {Col::Accent, "#268BD2"},
        {Col::Red, "#DC322F"}, {Col::Orange, "#CB4B16"}, {Col::Yellow, "#B58900"}, {Col::Green, "#788A00"},
        {Col::Cyan, "#2AA198"}, {Col::Blue, "#2588CE"}, {Col::Purple, "#6C71C4"}, {Col::Pink, "#D33682"},
        {Col::SynDefault, "#5D7179"}, {Col::SynKeyword, "#859900"}, {Col::SynString, "#2AA198"},
        {Col::SynComment, "#818E8E"}, {Col::SynNumber, "#D33682"}, {Col::SynType, "#B58900"},
        {Col::SynPunctuation, "#657B83"}, {Col::SynAttribute, "#268BD2"}, {Col::SynDirective, "#CB4B16"},
        {Col::LineNumber, "#818E8E"}, {Col::LineNumberActive, "#586E75"},
        {Col::GraphNode, "#FDF6E3"}, {Col::GraphNodeBorder, "#818E8E"},
        {Col::Ansi0, "#073642"}, {Col::Ansi1, "#DC322F"}, {Col::Ansi2, "#859900"}, {Col::Ansi3, "#B58900"},
        {Col::Ansi4, "#268BD2"}, {Col::Ansi5, "#D33682"}, {Col::Ansi6, "#2AA198"}, {Col::Ansi7, "#657B83"},
        {Col::Ansi8, "#586E75"}, {Col::Ansi9, "#CB4B16"}, {Col::Ansi10, "#859900"}, {Col::Ansi11, "#B58900"},
        {Col::Ansi12, "#268BD2"}, {Col::Ansi13, "#6C71C4"}, {Col::Ansi14, "#2AA198"}, {Col::Ansi15, "#002B36"},
    }));

    out.push_back(make("nord", "Nord", true, {
        {Col::Background, "#2B303B"}, {Col::EditorBackground, "#2E3440"}, {Col::PopupBackground, "#3B4252"},
        {Col::TitleBar, "#2B303B"}, 
        {Col::Border, "#3B4252"}, {Col::Control, "#3B4252"}, {Col::ControlHover, "#434C5E"},
        {Col::RowHover, "#353B49"}, {Col::RowSelected, "#434C5E"}, {Col::TextSelection, "#4C566A"},
        {Col::Text, "#D8DEE9"}, {Col::TextMuted, "#AAB1BF"}, {Col::TextOnAccent, "#2E3440"}, {Col::Accent, "#88C0D0"},
        {Col::Red, "#BF616A"}, {Col::Orange, "#D08770"}, {Col::Yellow, "#EBCB8B"}, {Col::Green, "#A3BE8C"},
        {Col::Cyan, "#8FBCBB"}, {Col::Blue, "#81A1C1"}, {Col::Purple, "#B48EAD"}, {Col::Pink, "#D4A5C0"},
        {Col::SynDefault, "#D8DEE9"}, {Col::SynKeyword, "#81A1C1"}, {Col::SynString, "#A3BE8C"},
        {Col::SynComment, "#747F96"}, {Col::SynNumber, "#B48EAD"}, {Col::SynType, "#8FBCBB"},
        {Col::SynPunctuation, "#ECEFF4"}, {Col::SynAttribute, "#8FBCBB"}, {Col::SynDirective, "#5E81AC"},
        {Col::LineNumber, "#777F8E"}, {Col::LineNumberActive, "#D8DEE9"},
        {Col::GraphNode, "#3B4252"}, {Col::GraphNodeBorder, "#777F8E"},
        {Col::Ansi0, "#3B4252"}, {Col::Ansi1, "#BF616A"}, {Col::Ansi2, "#A3BE8C"}, {Col::Ansi3, "#EBCB8B"},
        {Col::Ansi4, "#81A1C1"}, {Col::Ansi5, "#B48EAD"}, {Col::Ansi6, "#88C0D0"}, {Col::Ansi7, "#E5E9F0"},
        {Col::Ansi8, "#4C566A"}, {Col::Ansi9, "#BF616A"}, {Col::Ansi10, "#A3BE8C"}, {Col::Ansi11, "#EBCB8B"},
        {Col::Ansi12, "#81A1C1"}, {Col::Ansi13, "#B48EAD"}, {Col::Ansi14, "#8FBCBB"}, {Col::Ansi15, "#ECEFF4"},
    }));

    out.push_back(make("dracula", "Dracula", true, {
        {Col::Background, "#21222C"}, {Col::EditorBackground, "#282A36"}, {Col::PopupBackground, "#343746"},
        {Col::TitleBar, "#21222C"}, 
        {Col::Border, "#343746"}, {Col::Control, "#44475A"}, {Col::ControlHover, "#545770"},
        {Col::RowHover, "#2E303E"}, {Col::RowSelected, "#44475A"}, {Col::TextSelection, "#44475A"},
        {Col::Text, "#F8F8F2"}, {Col::TextMuted, "#9AA2C9"}, {Col::TextOnAccent, "#282A36"}, {Col::Accent, "#BD93F9"},
        {Col::Red, "#FF5555"}, {Col::Orange, "#FFB86C"}, {Col::Yellow, "#F1FA8C"}, {Col::Green, "#50FA7B"},
        {Col::Cyan, "#8BE9FD"}, {Col::Blue, "#82AAFF"}, {Col::Purple, "#BD93F9"}, {Col::Pink, "#FF79C6"},
        {Col::SynDefault, "#F8F8F2"}, {Col::SynKeyword, "#FF79C6"}, {Col::SynString, "#F1FA8C"},
        {Col::SynComment, "#6575A6"}, {Col::SynNumber, "#BD93F9"}, {Col::SynType, "#8BE9FD"},
        {Col::SynPunctuation, "#F8F8F2"}, {Col::SynAttribute, "#50FA7B"}, {Col::SynDirective, "#FFB86C"},
        {Col::LineNumber, "#6575A6"}, {Col::LineNumberActive, "#F8F8F2"},
        {Col::GraphNode, "#2D2F3D"}, {Col::GraphNodeBorder, "#717487"},
        {Col::Ansi0, "#21222C"}, {Col::Ansi1, "#FF5555"}, {Col::Ansi2, "#50FA7B"}, {Col::Ansi3, "#F1FA8C"},
        {Col::Ansi4, "#BD93F9"}, {Col::Ansi5, "#FF79C6"}, {Col::Ansi6, "#8BE9FD"}, {Col::Ansi7, "#F8F8F2"},
        {Col::Ansi8, "#6272A4"}, {Col::Ansi9, "#FF6E6E"}, {Col::Ansi10, "#69FF94"}, {Col::Ansi11, "#FFFFA5"},
        {Col::Ansi12, "#D6ACFF"}, {Col::Ansi13, "#FF92DF"}, {Col::Ansi14, "#A4FFFF"}, {Col::Ansi15, "#FFFFFF"},
    }));

    out.push_back(make("gruvbox-dark", "Gruvbox Dark", true, {
        {Col::Background, "#1D2021"}, {Col::EditorBackground, "#282828"}, {Col::PopupBackground, "#32302F"},
        {Col::TitleBar, "#1D2021"}, 
        {Col::Border, "#3C3836"}, {Col::Control, "#3C3836"}, {Col::ControlHover, "#504945"},
        {Col::RowHover, "#32302F"}, {Col::RowSelected, "#504945"}, {Col::TextSelection, "#504945"},
        {Col::Text, "#EBDBB2"}, {Col::TextMuted, "#A89984"}, {Col::TextOnAccent, "#1D2021"}, {Col::Accent, "#D79921"},
        {Col::Red, "#FB4934"}, {Col::Orange, "#FE8019"}, {Col::Yellow, "#FABD2F"}, {Col::Green, "#B8BB26"},
        {Col::Cyan, "#8EC07C"}, {Col::Blue, "#83A598"}, {Col::Purple, "#D3869B"}, {Col::Pink, "#E78AA6"},
        {Col::SynDefault, "#EBDBB2"}, {Col::SynKeyword, "#FB4934"}, {Col::SynString, "#B8BB26"},
        {Col::SynComment, "#928374"}, {Col::SynNumber, "#D3869B"}, {Col::SynType, "#FABD2F"},
        {Col::SynPunctuation, "#A89984"}, {Col::SynAttribute, "#8EC07C"}, {Col::SynDirective, "#FE8019"},
        {Col::LineNumber, "#7F7267"}, {Col::LineNumberActive, "#EBDBB2"},
        {Col::GraphNode, "#32302F"}, {Col::GraphNodeBorder, "#7B736C"},
        {Col::Ansi0, "#282828"}, {Col::Ansi1, "#CC241D"}, {Col::Ansi2, "#98971A"}, {Col::Ansi3, "#D79921"},
        {Col::Ansi4, "#458588"}, {Col::Ansi5, "#B16286"}, {Col::Ansi6, "#689D6A"}, {Col::Ansi7, "#A89984"},
        {Col::Ansi8, "#928374"}, {Col::Ansi9, "#FB4934"}, {Col::Ansi10, "#B8BB26"}, {Col::Ansi11, "#FABD2F"},
        {Col::Ansi12, "#83A598"}, {Col::Ansi13, "#D3869B"}, {Col::Ansi14, "#8EC07C"}, {Col::Ansi15, "#EBDBB2"},
    }));

    out.push_back(make("one-dark", "One Dark", true, {
        {Col::Background, "#21252B"}, {Col::EditorBackground, "#282C34"}, {Col::PopupBackground, "#2C313A"},
        {Col::TitleBar, "#21252B"}, 
        {Col::Border, "#181A1F"}, {Col::Control, "#2C313A"}, {Col::ControlHover, "#3A3F4B"},
        {Col::RowHover, "#2C313A"}, {Col::RowSelected, "#3D424F"}, {Col::TextSelection, "#3E4451"},
        {Col::Text, "#ABB2BF"}, {Col::TextMuted, "#979BA4"}, {Col::TextOnAccent, "#FFFFFF"}, {Col::Accent, "#4A73C4"},
        {Col::Red, "#E06C75"}, {Col::Orange, "#D19A66"}, {Col::Yellow, "#E5C07B"}, {Col::Green, "#98C379"},
        {Col::Cyan, "#56B6C2"}, {Col::Blue, "#61AFEF"}, {Col::Purple, "#C678DD"}, {Col::Pink, "#DE73A8"},
        {Col::SynDefault, "#ABB2BF"}, {Col::SynKeyword, "#C678DD"}, {Col::SynString, "#98C379"},
        {Col::SynComment, "#707681"}, {Col::SynNumber, "#D19A66"}, {Col::SynType, "#E5C07B"},
        {Col::SynPunctuation, "#ABB2BF"}, {Col::SynAttribute, "#D19A66"}, {Col::SynDirective, "#E06C75"},
        {Col::LineNumber, "#717785"}, {Col::LineNumberActive, "#ABB2BF"}, {Col::Caret, "#528BFF"},
        {Col::GraphNode, "#2C313A"}, {Col::GraphNodeBorder, "#747882"},
        {Col::Ansi0, "#282C34"}, {Col::Ansi1, "#E06C75"}, {Col::Ansi2, "#98C379"}, {Col::Ansi3, "#E5C07B"},
        {Col::Ansi4, "#61AFEF"}, {Col::Ansi5, "#C678DD"}, {Col::Ansi6, "#56B6C2"}, {Col::Ansi7, "#ABB2BF"},
        {Col::Ansi8, "#5C6370"}, {Col::Ansi9, "#E06C75"}, {Col::Ansi10, "#98C379"}, {Col::Ansi11, "#E5C07B"},
        {Col::Ansi12, "#61AFEF"}, {Col::Ansi13, "#C678DD"}, {Col::Ansi14, "#56B6C2"}, {Col::Ansi15, "#FFFFFF"},
    }));

    return out;
}
