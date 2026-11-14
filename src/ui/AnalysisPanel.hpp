#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/ApkDiff.hpp"
#include "analysis/Decompiler.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/NativeCode.hpp"
#include "core/ResourceTable.hpp"
#include "ui/AnnotationUi.hpp"
#include "ui/GraphView.hpp"
#include "ui/Panel.hpp"

// Analysis workspace, in the layout of JADX, Ghidra and Binary Ninja:
//  - Analysis (this panel): the navigator. Classes as a package tree with
//    their methods, Strings, Native libraries, Resources and Compare.
//  - Function: the selected method or native function as a listing, a
//    control-flow graph or a call graph.
//  - References: what calls the selection and what it calls, or the
//    results of the last query (string uses, type uses, resource ids).
//  - Decompiler: the selection as Java-like (Dalvik) or C-like (AArch64)
//    code, synced with the listing in both directions (as in Cutter).
// Selecting a class or method also opens jadx's Java in the Editor.
//
// The panel never keeps an analysis alive: it holds a weak_ptr and drops its
// caches when the analysis is replaced or the APK is removed.
class AnalysisPanel : public Panel {
public:
    AnalysisPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Analysis"), showPanel_(std::move(showPanel)) {}
    ~AnalysisPanel() override;

    // Contents of the Function, References and Decompiler panels (state lives here).
    void drawFunctionView();
    void drawReferences();
    void drawDecompiler();

protected:
    void drawContents() override;

private:
    enum class Nav { Classes, Strings, Native, Resources, Compare };
    enum class Selection { None, Class, Method, Native };

    void drawHeader(Root& apk, const AnalysisService::Status& st);
    void drawClassTree(const ApkAnalysis& a, Root& apk);
    void buildPackageTree(const ApkAnalysis& a);
    void flattenTree(const ApkAnalysis& a);
    const std::vector<ApkAnalysis::MethodDef>& methodsOfClass(const ApkAnalysis& a, uint32_t cls);
    void selectClass(const ApkAnalysis& a, uint32_t cls, const std::string& group, bool keep);
    void selectMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group, bool openSource,
                      bool keep = false);
    void drawMethodView(const ApkAnalysis& a, Root& apk);
    void drawMethodListing(const ApkAnalysis& a, Root& apk);
    void drawQueryResults(const ApkAnalysis& a, Root& apk);
    void showQuery();
    void showFunction(int mode);
    void drawStrings(const ApkAnalysis& a, Root& apk);
    void drawGraph(const ApkAnalysis& a, Root& apk);
    void drawNative(Root& apk);
    void drawCompare(Root& apk);
    void drawResources(Root& apk);
    void drawNativeCode(Root& apk);
    void drawNativeListing(const NativeCode& nc);
    void drawNativeStrings(Root& apk);
    void ensureNativeCode(Root& apk);
    void resetNative();
    void gotoNative(uint64_t addr, bool record = true);
    void selectLib(Root& apk, int index);
    void drawNativeGraph(const NativeCode& nc, const NativeCode::Function& f);
    void buildNativeCfg(const NativeCode& nc, const NativeCode::Function& f);
    void buildNativeCalls(const NativeCode& nc, const NativeCode::Function& f);
    void nativeShortcuts(const NativeCode& nc, const std::vector<NativeCode::Line>& lines);
    Annotation nativeLocation(const NativeCode& nc, const NativeCode::Line& line) const;

    void openClass(const ApkAnalysis& a, const ApkAnalysis::ClassEntry& c, const std::string& group);
    void openMethod(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m, const std::string& group,
                    uint32_t pc = UINT32_MAX);
    void openCodeRef(const ApkAnalysis& a, const ApkAnalysis::CodeRef& r, const std::string& group);
    void showCallers(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
    void showCallees(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
    void showGraph(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
    void showCallGraph(const ApkAnalysis& a, const ApkAnalysis::MethodDef& m);
    void resetCaches(bool keepNative = false);

    std::function<void(const std::string&)> showPanel_;
    int apkIdx_ = 0;
    Nav nav_ = Nav::Classes;
    const ApkAnalysis* cacheOwner_ = nullptr;  // identity only, never dereferenced when stale
    std::weak_ptr<const ApkAnalysis> current_;  // what the Function / References panels show
    std::string currentGroup_;

    // Class tree: packages (compacted like "com.google.android") > classes > methods.
    struct PackageNode {
        std::string name;
        std::vector<uint32_t> packages;  // child package nodes
        std::vector<uint32_t> classes;   // indices into classes()
    };
    struct TreeRow {
        enum Kind : uint8_t { Package, Class, Method } kind;
        uint8_t depth;
        uint32_t index;   // package node / class index
        uint32_t method;  // index into methodsOfClass(index)
        std::string label;
    };
    std::vector<PackageNode> packages_;  // [0] is the root
    std::vector<char> packageOpen_;
    std::unordered_set<uint32_t> classOpen_;
    std::unordered_map<uint32_t, std::vector<ApkAnalysis::MethodDef>> classMethods_;
    std::vector<TreeRow> rows_;
    bool rowsDirty_ = true;
    char classFilter_[256] = {};
    std::string appliedFilter_ = "\x01";
    bool scrollToSelection_ = false;

    // Selection, shown by the Function and References panels.
    Selection sel_ = Selection::None;
    uint32_t selClass_ = UINT32_MAX;
    ApkAnalysis::MethodDef selMethod_{};
    std::vector<ApkAnalysis::XrefHit> selCallers_;
    std::vector<ApkAnalysis::Callee> selCallees_;
    int functionMode_ = 0;  // 0 listing, 1 control-flow graph, 2 call graph
    struct ListingLine {
        std::string text;
        int32_t pc;
    };
    std::vector<ListingLine> methodListing_;
    int32_t listingPc_ = -1;  // highlighted instruction
    bool listingScroll_ = false;
    bool refsQuery_ = false;  // References shows xrefs_ rather than the selection

    // Xrefs (rendered rows + navigation targets)
    struct XrefRow {
        std::string from;
        std::string what;
        bool hasRef = false;
        ApkAnalysis::CodeRef ref;
        std::string targetMethod;  // callee rows: open this method instead
    };
    std::string xrefTitle_;
    std::vector<XrefRow> xrefs_;
    // Background xref query (resource id uses scan every method).
    std::future<std::vector<XrefRow>> xrefJob_;

    // Strings
    char stringFilter_[256] = {};
    int stringCategory_ = 0;
    std::vector<ApkAnalysis::StringHit> strings_;
    bool stringsLoaded_ = false;

    // Graph
    bool graphValid_ = false;
    bool graphIsCalls_ = false;           // a call graph rather than a CFG
    std::vector<std::string> graphRefs_;  // call graph: the method of each block
    GraphView graph_;
    std::string graphTitle_;
    ApkAnalysis::MethodDef graphMethod_;
    std::vector<ApkAnalysis::BasicBlock> graphBlocks_;

    // Native
    struct LibRow {
        std::string path;
        std::string abi;
        uint64_t size = 0;
    };
    std::vector<LibRow> libs_;
    std::string libsGroup_;
    int selectedLib_ = -1;
    std::future<std::pair<std::shared_ptr<const ElfFile>, std::string>> elfLoad_;
    std::shared_ptr<const ElfFile> elf_;
    std::string elfError_;
    char symbolFilter_[128] = {};
    int symbolView_ = 5;  // 0-2 JNI / exports / imports, 3-4 sections / segments, 5 functions, 6 strings

    // Native code (AArch64): built on a worker, shared with MCP through AnalysisService.
    std::future<std::pair<std::shared_ptr<const NativeCode>, std::string>> nativeLoad_;
    std::shared_ptr<std::atomic<bool>> nativeCancel_;
    std::shared_ptr<const NativeCode> native_;
    std::string nativeError_;
    char funcFilter_[128] = {};
    std::string funcFilterApplied_ = "\x01";
    std::vector<uint32_t> funcRows_;  // indices into functions()
    uint64_t funcAddr_ = UINT64_MAX;  // selected function
    uint64_t focusAddr_ = 0;          // highlighted instruction
    bool scrollToFocus_ = false;
    uint64_t pendingGoto_ = 0;        // requested before the code was ready
    std::string pendingLib_;          // MCP show_native: library to select
    std::string pendingTarget_;       // MCP show_native: function name or 0x address
    std::vector<uint64_t> nativeBack_;
    std::vector<NativeCode::Line> listing_;
    std::vector<NativeCode::Ref> funcCallers_;
    std::vector<NativeCode::Ref> nativeCallees_;
    uint64_t nativeCalleesOf_ = UINT64_MAX;
    char nstrFilter_[128] = {};
    std::string nstrApplied_ = "\x01";
    std::vector<NativeCode::StringRef> nstrRows_;
    ui::CommentPopup nativeComment_;
    int nativeMode_ = 0;  // 0 listing, 1 control-flow graph, 2 call graph
    GraphView nativeGraph_;
    NativeCode::ControlFlow nativeCfg_;
    std::vector<uint64_t> nativeCallNodes_;  // call graph: the function of each block
    uint64_t nativeGraphFunc_ = UINT64_MAX;
    int nativeGraphMode_ = 0;
    uint64_t nativeGraphNotes_ = 0;

    // Decompiler (see AnalysisDecompiler.cpp)
    void decompilerFollowCall(const decompiler::Line& line);
    void decompilerRenamePopup();
    decompiler::Output decompRaw_;        // as decompiled
    decompiler::Output decomp_;           // with the user's variable names
    uint64_t decompNotesVersion_ = 0;     // annotations version the names come from
    Annotation decompLoc_;                // where its renames are stored (Method / Native target)
    std::string decompToken_;             // highlighted identifier, IDA style
    size_t decompCol_ = 0;                // keyboard cursor: byte column in the current line
    bool decompRenameOpen_ = false;
    bool decompEditType_ = false;         // the popup sets the type (Y) instead of the name (N)
    bool decompEditSymbol_ = false;       // the popup renames a symbol (function, field, class...) everywhere
    Annotation decompSymLoc_;             // where symbol renames are stored: the whole APK / native library
    std::string decompRenameKey_;         // variable being renamed / retyped (v3, x19)
    char decompRenameBuf_[96] = {};
    std::string decompRenameError_;
    std::string decompStatus_;            // hint in the bottom bar (N / Y without a variable under the cursor)
    int decompKind_ = 0;                  // 0 nothing, 1 Dalvik method, 2 native function
    uint64_t decompKey_ = UINT64_MAX;     // dex << 32 | method id, or the function address
    const void* decompOwner_ = nullptr;   // analysis / native code it came from (identity only)
    std::string decompTitle_;
    bool decompAuto_ = true;              // follow the selection
    bool decompRefresh_ = false;
    uint64_t decompSynced_ = UINT64_MAX;  // last listing address followed
    bool decompScroll_ = false;
    int decompLine_ = -1;

    // Resources
    int resType_ = 0;  // index into resTypes_ (0 = all)
    char resFilter_[128] = {};
    std::vector<std::string> resTypes_;
    std::vector<ResourceTable::Item> resItems_;
    std::string resKey_;
    const ResourceTable* resOwner_ = nullptr;

    // Compare
    int compareWith_ = -1;
    std::future<ApkDiff> diffJob_;
    bool diffValid_ = false;
    ApkDiff diff_;
    std::string diffTitle_;
    std::vector<std::string> permAdded_, permRemoved_;
};

// The selected method or native function: listing, control-flow graph, call graph.
class FunctionPanel : public Panel {
public:
    FunctionPanel(Workspace& workspace, AnalysisPanel& analysis) : Panel(workspace, "Function"), analysis_(analysis) {}

protected:
    void drawContents() override { analysis_.drawFunctionView(); }

private:
    AnalysisPanel& analysis_;
};

// The selection as decompiled code (Cutter's Decompiler pane).
class DecompilerPanel : public Panel {
public:
    DecompilerPanel(Workspace& workspace, AnalysisPanel& analysis) : Panel(workspace, "Decompiler"), analysis_(analysis) {}

protected:
    void drawContents() override { analysis_.drawDecompiler(); }

private:
    AnalysisPanel& analysis_;
};

// Callers and callees of the selection, or the results of the last query.
class ReferencesPanel : public Panel {
public:
    ReferencesPanel(Workspace& workspace, AnalysisPanel& analysis) : Panel(workspace, "References"), analysis_(analysis) {}

protected:
    void drawContents() override { analysis_.drawReferences(); }

private:
    AnalysisPanel& analysis_;
};
