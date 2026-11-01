#pragma once
#include "ui/ImageViewer.hpp"
#include "ui/Panel.hpp"
#include "core/TextSearch.hpp"
#include "ui/FileBrowser.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class Settings;

// Per-tab find state (M1): every open document remembers its own query,
// options and match list. Matches are recomputed only when the query, the
// options or the document's text changed (textRevision), never per frame.
struct FindState {
    bool open = false;
    char query[256] = "";
    textsearch::Options opt;
    std::vector<textsearch::Match> matches;
    // line -> (first match index, count); findAll yields matches ordered by
    // (line, col), so per-line lookups while drawing are O(log n).
    std::unordered_map<int, std::pair<int, int>> byLine;
    int current = -1;         // index into matches
    bool truncated = false;
    uint32_t docSerial = 0;   // Document::textRevision() the matches were built for
    bool focusInput = false;  // focus the query field on the next bar draw
    std::string lastQuery;    // query the matches were computed for
    bool lastCase = false;    // options the matches were computed for
    bool lastWord = false;
    int pendingJump = -1;     // match index to scroll to in the content views
};

// Document tab bar with dnSpy/VS behaviour:
//  - single click in the explorer opens a preview tab (marked "(preview)",
//    replaced by the next preview),
//  - double click promotes it to a permanent tab,
//  - tabs close via the X button, middle click or the context menu,
//  - documents open in a fast read-only viewer by default; the Edit toggle
//    switches to the in-place editor (syntax colours kept while typing),
//    saving happens through File > Save Project (Ctrl+S), which persists
//    the edited files together with the project.
class EditorPanel : public Panel {
public:
    EditorPanel(Workspace& workspace, Settings& settings) : Panel(workspace, "Editor"), settings_(settings) {}

    // Entry points for the shared View menu (both menu bars): open the find
    // bar / the go-to-line popup for the active document on the next frame.
    void requestFind() { findRequest_ = true; }
    void requestGoToLine() { goToRequest_ = true; }

protected:
    void drawContents() override;

private:
    void drawDocument(Document& doc);
    void drawToolbar(Document& doc);
    void drawScrollable(Document& doc);
    void drawCode(Document& doc);
    void drawEditable(Document& doc);
    void drawHex(const Document& doc);
    void requestClose(Document* doc);
    void processCloses();
    void drawConfirmModal();
    bool lineNumbers() const;

    // Find in file (M1) ----------------------------------------------------
    FindState* findState(const Document& doc);
    void processShortcuts(Document& doc);
    void openFind(Document& doc, FindState& f);
    void openGoTo(Document& doc);
    void recomputeMatches(Document& doc, FindState& f);
    void moveMatch(FindState& f, int dir);
    void drawFindBar(Document& doc, FindState& f);
    void drawGoToModal();
    void sweepFindStates();
    // Export of the active document (M5): raw bytes, or decoded text for
    // code documents. Destination is picked in a SaveFile browser.
    void drawExportBrowser();
    void openExport(Document& doc);
    // Ctrl+click navigation (M3).
    void symbolNavigate(Document& doc, const std::string& line, int a, int b);
    // Byte column -> pixel x inside the monospace line, for match overlays.
    float columnToX(const std::string& line, int col) const;

    ImageViewer viewer_;
    Settings& settings_;

    Document* closingDoc_ = nullptr;      // single tab awaiting confirmation
    std::vector<Document*> batchClose_;   // Close All / Close Others
    std::vector<Document*> closeNow_;     // non-dirty closes deferred to end of frame

    // Find state per open document; entries are swept when their document is
    // gone (closed tab, replaced preview).
    std::unordered_map<const Document*, FindState> find_;
    bool findRequest_ = false;   // View > Find... / Ctrl+F from the menu
    bool goToRequest_ = false;   // View > Go to Line... / Ctrl+G from the menu
    bool gotoOpenRequest_ = false;
    bool gotoFocus_ = false;
    int gotoValue_ = 1;
    bool refocusEdit_ = false;   // give keyboard focus back after Esc in the find bar
    std::string selSnippet_;     // last single-line selection in the editor (prefill for Ctrl+F)
    FileBrowser exportBrowser_;  // Export... destination (M5)
    Document* exportDoc_ = nullptr;  // document awaiting the export destination
};
