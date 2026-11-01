// Headless ImGui regression tests (no backend, no GLFW/OpenGL).
// Pins two behaviours ApkSpy relies on against the bundled ImGui 1.91.9:
//  1. the multiline editor's internal child window is found by its exact
//     generated name and the caret overlay matches ImGui's own caret
//     geometry to the pixel (regression guard for the invisible-caret fix),
//  2. "###id" suffixes keep a tab's id (and therefore its position in the
//     bar) stable while its visible label changes (regression guard for
//     tabs jumping to the end when their marker changes).
#include "imgui.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
namespace ImStb {
#include "imstb_textedit.h"
}

static int failures = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) printf("  PASS: %s\n", msg);                               \
        else { printf("  FAIL: %s\n", msg); ++failures; }                    \
    } while (0)

static int resizeCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* s = static_cast<std::string*>(data->UserData);
        s->resize(data->BufTextLen);
        data->Buf = &(*s)[0];
    }
    return 0;
}

static void testCaretOverlay() {
    printf("== editor caret overlay ==\n");
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2(1280, 800);
    io.DeltaTime = 1.0f / 60.0f;
    io.IniFilename = nullptr;
    io.ConfigInputTextCursorBlink = false;  // caret drawn every frame -> scannable
    io.Fonts->AddFontDefault();
    io.Fonts->Build();

    std::string text = "line one\nline two\nline three";
    bool active = false, gotState = false, gotWindow = false;
    ImVec2 itemMin(0, 0), itemMax(0, 0);
    int cursor = -1;
    float cx = 0, cy = 0, fontSize = 0;
    float gtX = 0, gtY = 0;
    bool gotGeometry = false;
    bool gotGroundTruth = false;

    for (int frame = 0; frame < 8; ++frame) {
        if (frame == 1) {
            io.MousePos = ImVec2(300, 120);
            io.MouseDown[0] = true;
        }
        if (frame == 2) io.MouseDown[0] = false;
        if (frame == 4) io.AddInputCharacter('X');
        if (frame == 5) io.AddInputCharacter('Y');

        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(800, 600));
        ImGui::Begin("w");
        const ImGuiStyle& style = ImGui::GetStyle();

        const ImGuiID editId = ImGui::GetID("##edit");
        fontSize = ImGui::GetFontSize();
        // NOTE: the real editor renders the widget's own text transparent and
        // draws a highlighted overlay instead. ImDrawList skips fully
        // transparent primitives, so for this ground-truth test the default
        // (visible) colour is used: ImGui then draws its own caret, whose
        // vertices give the exact position our overlay formula must match.
        ImGui::InputTextMultiline("##edit", &text[0], text.capacity() + 1, ImVec2(-FLT_MIN, -FLT_MIN),
                                  ImGuiInputTextFlags_CallbackResize, &resizeCallback, &text);

        active = ImGui::IsItemActive();
        itemMin = ImGui::GetItemRectMin();
        itemMax = ImGui::GetItemRectMax();
        // Same lookup as EditorPanel::drawEditable: the multiline widget's
        // child window is named "<parent>/##edit_<widget id>".
        char nameBuf[256];
        std::snprintf(nameBuf, sizeof nameBuf, "%s/##edit_%08X", ImGui::GetCurrentWindow()->Name, editId);
        ImGuiWindow* inputWindow = ImGui::FindWindowByName(nameBuf);
        const ImGuiInputTextState* state = ImGui::GetInputTextState(editId);
        gotState = state != nullptr;
        gotWindow = inputWindow != nullptr;
        const float scrollX = state ? state->Scroll.x : 0.f;
        const float scrollY = inputWindow ? inputWindow->Scroll.y : 0.f;

        if (frame >= 3) {
            const ImVec2 textOrigin(itemMin.x + style.FramePadding.x, itemMin.y + style.FramePadding.y);
            const int cursorLocal = state ? state->Stb->cursor : -1;
            cursor = cursorLocal;
            if (cursorLocal >= 0 && cursorLocal <= (int)text.size()) {
                std::vector<size_t> offsets;
                offsets.push_back(0);
                for (size_t i = 0; i < text.size(); ++i)
                    if (text[i] == '\n') offsets.push_back(i + 1);
                auto it = std::upper_bound(offsets.begin(), offsets.end(), (size_t)cursorLocal);
                size_t lineIdx = it == offsets.begin() ? 0 : (size_t)(it - offsets.begin()) - 1;
                const char* lineStart = text.c_str() + offsets[lineIdx];
                cx = textOrigin.x - scrollX +
                     ImGui::CalcTextSize(lineStart, lineStart + (cursorLocal - (int)offsets[lineIdx])).x;
                cy = textOrigin.y + (float)lineIdx * fontSize - scrollY;
                gotGeometry = true;
            }
            // Ground truth: ImGui itself draws the caret as a thin AddLine
            // quad (~1px wide, ~fontSize tall) into the child window's draw
            // list. Scan for the LAST such quad - that is exactly where the
            // overlay caret must land. (The child's border, drawn later, is
            // thin but window-height tall; glyphs are ~fontSize wide.)
            if (inputWindow && inputWindow->DrawList) {
                const ImVector<ImDrawVert>& vtx = inputWindow->DrawList->VtxBuffer;
                bool found = false;
                // Indexed rendering: every quad (glyphs, rects, lines) is 4
                // vertices + 6 indices, so quads start every 4 vertices.
                for (int i = 0; i + 4 <= vtx.Size; i += 4) {
                    float minX = vtx[i].pos.x, minY = vtx[i].pos.y, maxX = minX, maxY = minY;
                    for (int k = i + 1; k < i + 4; ++k) {
                        minX = ImMin(minX, vtx[k].pos.x);
                        minY = ImMin(minY, vtx[k].pos.y);
                        maxX = ImMax(maxX, vtx[k].pos.x);
                        maxY = ImMax(maxY, vtx[k].pos.y);
                    }
                    const float w = maxX - minX, h = maxY - minY;
                    // The caret quad is ~1-3px wide (AA widens the line) and
                    // fontSize-2 tall; glyphs are wider and shorter, borders
                    // are window-height tall.
                    if (w <= 4.5f && h >= fontSize - 3.f && h <= fontSize + 1.f) {
                        found = true;
                        gtX = minX;
                        gtY = minY;
                    }
                }
                gotGroundTruth = found;
            }
        }
        ImGui::End();
        ImGui::Render();
    }

    CHECK(gotState, "input text state resolved via GetInputTextState(id)");
    CHECK(gotWindow, "internal child window found by its generated name");
    CHECK(active, "editor is active after the simulated click");
    CHECK(text.find("XY") != std::string::npos, "keyboard input reached the buffer");
    CHECK(gotGeometry, "caret geometry computed for the typed cursor position");
    CHECK(gotGroundTruth, "ImGui's own caret quad found in the draw list");
    CHECK(gtX >= cx - 1.5f && gtX <= cx + 1.5f, "caret X matches ImGui's own placement");
    CHECK(gtY >= cy - 1.5f && gtY <= cy + 1.5f, "caret Y matches ImGui's own placement");
    CHECK(cx >= itemMin.x && cx <= itemMax.x && cy >= itemMin.y && cy + fontSize <= itemMax.y,
          "caret sits inside the editor frame");
    ImGui::DestroyContext();
}

static void testStableTabIds() {
    printf("== stable tab ids (### suffix) ==\n");
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2(1280, 800);
    io.DeltaTime = 1.0f / 60.0f;
    io.IniFilename = nullptr;
    io.Fonts->AddFontDefault();
    io.Fonts->Build();

    // Labels whose visible part changes (dirty marker) but whose id suffix
    // stays fixed - exactly what EditorPanel builds for its document tabs.
    auto frame = [&](const char* b) {
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(800, 600));
        ImGui::Begin("tabs");
        std::vector<ImGuiID> ids;
        if (ImGui::BeginTabBar("##documents", ImGuiTabBarFlags_Reorderable)) {
            if (ImGui::BeginTabItem("A###doc1", nullptr, 0)) ImGui::EndTabItem();
            if (ImGui::BeginTabItem(b, nullptr, 0)) ImGui::EndTabItem();
            if (ImGui::BeginTabItem("C###doc3", nullptr, 0)) ImGui::EndTabItem();
            if (ImGuiTabBar* bar = ImGui::GetCurrentTabBar())
                for (const ImGuiTabItem& tab : bar->Tabs) ids.push_back(tab.ID);
            ImGui::EndTabBar();
        }
        ImGui::End();
        ImGui::Render();
        return ids;
    };

    std::vector<ImGuiID> before = frame("B###doc2");
    std::vector<ImGuiID> after = frame("B *###doc2");

    CHECK(before.size() == 3 && after.size() == 3, "three tabs in the bar");
    bool sameOrder = before.size() == after.size() &&
                     std::equal(before.begin(), before.end(), after.begin());
    CHECK(sameOrder, "tab order unchanged when a label grows a marker");
    ImGuiID idA = 0, idB = 0;
    {
        // Compare the ids ImGui derived for the two labels: hashing ignores
        // everything before "###".
        ImGui::NewFrame();
        ImGui::Begin("tabs");
        ImGui::PushID("##documents_scope");
        idA = ImGui::GetID("B###doc2");
        idB = ImGui::GetID("B *###doc2");
        ImGui::PopID();
        ImGui::End();
        ImGui::Render();
    }
    CHECK(idA != 0 && idA == idB, "labels differing before ### hash to the same id");
    ImGui::DestroyContext();
}

// Find-match overlay geometry (M1): the byte-column -> pixel-x formula used
// by EditorPanel (CalcTextSize(line, line+col) on the active font) must
// produce rects that line up with the actual glyph quads on screen. The
// window is stripped of background/border so every primitive in the draw
// list is a 4-vertex quad and the scan stays stride-aligned.
static void testMatchRectAlignment() {
    printf("== find-match rect alignment ==\n");
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2(1280, 800);
    io.DeltaTime = 1.0f / 60.0f;
    io.IniFilename = nullptr;
    io.Fonts->AddFontDefault();
    io.Fonts->Build();

    const std::string line = "alpha beta gamma";
    const int matchCol = 6, matchLen = 4;  // "beta"

    ImGui::NewFrame();
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(800, 600));
    ImGui::Begin("w", nullptr,
                 ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);
    const ImVec2 textPos = ImGui::GetCursorScreenPos();
    // Exactly what EditorPanel::columnToX does with the active font.
    const float rx0 = textPos.x + ImGui::CalcTextSize(line.c_str(), line.c_str() + matchCol).x;
    const float rx1 = textPos.x + ImGui::CalcTextSize(line.c_str(), line.c_str() + matchCol + matchLen).x;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(ImVec2(rx0, textPos.y), ImVec2(rx1, textPos.y + ImGui::GetTextLineHeight()),
                      IM_COL32(255, 145, 0, 95));
    ImGui::TextUnformatted(line.c_str(), line.c_str() + line.size());
    ImGui::End();
    ImGui::PopStyleVar(2);
    ImGui::Render();

    bool foundRect = false;
    bool cleanBanding = true;  // every glyph is fully left of, inside, or right of the rect
    bool glyphInside = false;
    const ImVector<ImDrawVert>& vtx = dl->VtxBuffer;
    for (int i = 0; i + 4 <= vtx.Size; i += 4) {  // quad 0 is the match rect
        float minX = vtx[i].pos.x, maxX = minX;
        for (int k = 1; k < 4; ++k) {
            minX = ImMin(minX, vtx[i + k].pos.x);
            maxX = ImMax(maxX, vtx[i + k].pos.x);
        }
        if (fabsf(minX - rx0) < 1.0f && fabsf(maxX - rx1) < 1.0f) foundRect = true;
        if (minX >= rx0 - 1.0f && maxX <= rx1 + 1.0f) glyphInside = true;
        const bool left = maxX < rx0 - 1.0f, right = minX > rx1 + 1.0f;
        const bool inside = minX >= rx0 - 1.0f && maxX <= rx1 + 1.0f;
        if (!left && !right && !inside) cleanBanding = false;
    }
    CHECK(foundRect, "match rect found with the expected x extent");
    CHECK(glyphInside, "glyphs of the match word sit within the rect span");
    CHECK(cleanBanding, "no glyph straddles the rect edges");
    ImGui::DestroyContext();
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    testCaretOverlay();
    testStableTabIds();
    testMatchRectAlignment();
    printf("%s (%d failures)\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED", failures);
    return failures ? 1 : 0;
}
