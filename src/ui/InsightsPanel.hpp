#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "analysis/ApkAnalysis.hpp"
#include "analysis/Insights.hpp"
#include "analysis/ManifestAudit.hpp"
#include "analysis/Mapping.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

// Static triage of the APK: frameworks and packers (detection only), SDKs
// and trackers, hard-coded secrets, code-risk rules with their callers, the
// manifest audit, JSON / SARIF / Markdown export, and a ProGuard / R8
// stack-trace retracer. Read-only: nothing is executed or modified.
class InsightsPanel : public Panel {
public:
    InsightsPanel(Workspace& workspace, std::function<void(const std::string&)> showPanel)
        : Panel(workspace, "Insights"), showPanel_(std::move(showPanel)) {}

protected:
    void drawContents() override;

private:
    void runScan();
    void drawOverview();
    void drawSecrets();
    void drawSdks();
    void drawRules();
    void drawManifest();
    void drawRetrace();
    // `callee`: the called signature, to show the call's constant arguments.
    void drawXrefs(const std::vector<ApkAnalysis::XrefHit>& hits, const std::string& callee = {});
    std::string constArgs(const ApkAnalysis::XrefHit& hit, const std::string& callee);
    void openRef(const ApkAnalysis::CodeRef& ref);
    void saveExport(const std::string& file);

    std::function<void(const std::string&)> showPanel_;
    std::string group_;
    std::shared_ptr<const ApkAnalysis> analysis_;
    bool scanned_ = false;
    bool selectOverview_ = false;  // switch to Overview after a scan
    insights::Result result_;
    std::vector<std::string> strings_;  // Inputs::strings, for secret xrefs
    bool haveAudit_ = false;
    manifestaudit::Audit audit_;
    std::string auditError_;
    bool showValues_ = false;
    std::map<std::string, std::vector<ApkAnalysis::XrefHit>> callers_;  // signature / string -> uses
    std::string status_;
    std::map<std::string, std::string> constArgs_;  // per call site

    enum class ExportKind { Json, Sarif, Markdown };
    ExportKind exportKind_ = ExportKind::Json;
    FileBrowser exportBrowser_, mappingBrowser_;

    // Retrace
    std::string mappingText_, mappingFile_;
    mapping::Mapping mapping_;
    std::vector<char> traceBuf_ = std::vector<char>(64 * 1024, '\0');
    std::string retraced_;
};
