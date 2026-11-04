#pragma once
#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/ApkDiff.hpp"
#include "analysis/ElfFile.hpp"
#include "analysis/NativeCode.hpp"
#include "core/ResourceTable.hpp"
#include "ui/AnnotationUi.hpp"
#include "ui/GraphView.hpp"
#include "ui/Panel.hpp"

// Bytecode analysis workbench (IDA/Ghidra-style views over the DEX code):
//  - Classes:  every class of the APK (filterable, virtualized), its methods
//              with smali / callers / callees / CFG actions.
//  - Xrefs:    results of the last cross-reference query; click to jump.
//  - Strings:  DEX string tables with URL / IP / path / secret heuristics.
//  - Graph:    control-flow graph of the selected method (IDA-like colors:
//              green = branch taken, red = fall-through, blue = jump,
//              dashed orange = exception handler).
//  - Native:   ELF view of lib/<abi>/*.so (sections, JNI, exports, imports)
//              and, for arm64 libraries, functions with AArch64 disassembly,
//              callers and the string literals the code references.
//  - Compare:  APK version diff (entries, permissions, classes, methods).
//
// The panel never keeps an analysis alive: it holds a weak_ptr and drops its
// caches when the analysis is replaced or the APK is removed.
class AnalysisPanel : public Panel {
public:
    explicit AnalysisPanel(Workspace& workspace) : Panel(workspace, "Analysis") {}
    ~AnalysisPanel() override;

    // Requests from other panels / menus.
    void focusXrefsTab() { requestTab_ = 1; }

protected:
    void drawContents() override;

private:
    void drawHeader(Root& apk, const AnalysisService::Status& st);
    void drawClasses(const ApkAnalysis& a, Root& apk);
    void drawMethods(const ApkAnalysis& a, Root& apk, const ApkAnalysis::ClassEntry& c);
    void drawXrefs(const ApkAnalysis& a, Root& apk);
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
    void resetCaches();

    int apkIdx_ = 0;
    int requestTab_ = -1;
    const ApkAnalysis* cacheOwner_ = nullptr;  // identity only, never dereferenced when stale

    // Classes
    char classFilter_[256] = {};
    std::string appliedFilter_;
    std::vector<uint32_t> filtered_;  // indices into classes()
    int selectedClass_ = -1;

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
    char nstrFilter_[128] = {};
    std::string nstrApplied_ = "\x01";
    std::vector<NativeCode::StringRef> nstrRows_;
    ui::CommentPopup nativeComment_;
    int nativeMode_ = 0;  // 0 listing, 1 control-flow graph, 2 call graph
    bool graphFunctionList_ = false;  // function list beside a graph (it needs the width)
    GraphView nativeGraph_;
    NativeCode::ControlFlow nativeCfg_;
    std::vector<uint64_t> nativeCallNodes_;  // call graph: the function of each block
    uint64_t nativeGraphFunc_ = UINT64_MAX;
    int nativeGraphMode_ = 0;
    uint64_t nativeGraphNotes_ = 0;

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
