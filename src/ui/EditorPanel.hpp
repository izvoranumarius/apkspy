#pragma once
#include "ui/ImageViewer.hpp"
#include "ui/Panel.hpp"
#include <vector>

class Settings;

// Document tab bar with dnSpy/VS behaviour:
//  - single click in the explorer opens a preview tab (italic-style marker,
//    replaced by the next preview),
//  - double click promotes it to a permanent tab,
//  - tabs close via the X button, middle click or the context menu,
//  - files are editable in place (syntax colours kept while typing);
//    saving happens through File > Save Project (Ctrl+S), which persists
//    the edited files together with the project.
class EditorPanel : public Panel {
public:
    EditorPanel(Workspace& workspace, Settings& settings) : Panel(workspace, "Editor"), settings_(settings) {}

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
    void closeMany(std::vector<Document*> docs);
    void processCloses();
    void drawConfirmModal();
    const char* tabLabel(const Document& doc);
    bool lineNumbers() const;

    ImageViewer viewer_;
    Settings& settings_;

    Document* closingDoc_ = nullptr;              // single tab awaiting confirmation
    std::vector<Document*> batchClose_;           // Close All / Close Others
    std::vector<Document*> closeNow_;             // non-dirty closes deferred to end of frame
    bool saveOnConfirm_ = false;
};
