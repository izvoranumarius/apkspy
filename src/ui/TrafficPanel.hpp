#pragma once
#include <atomic>
#include <chrono>
#include <memory>
#include <future>
#include <string>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include "core/Settings.hpp"
#include "debug/DeviceService.hpp"
#include "debug/HttpClient.hpp"
#include "core/TextDiff.hpp"
#include "debug/FlowFilter.hpp"
#include "debug/MatchReplace.hpp"
#include "debug/TrafficScript.hpp"
#include "ui/FileBrowser.hpp"
#include "ui/Panel.hpp"

// "Traffic": network sniffer. Starts the local proxy, routes the selected
// device through it, and lists every request (method, host, path, status,
// size, time) with full headers / bodies for plain HTTP and host / SNI /
// byte counts for HTTPS tunnels. The Endpoints view groups requests into an
// API map (host + method + path template) and marks endpoints whose host or
// path also appears in the APK's bytecode strings. The Repeater (as in Burp)
// edits a request and sends it again, one numbered tab per request; Intercept
// holds plain-HTTP requests and responses to edit, forward or drop; Match &
// replace rewrites them automatically with saved rules; Comparer shows what
// differs between two requests or responses.
class TrafficPanel : public Panel {
public:
    TrafficPanel(Workspace& workspace, DeviceService& devices, Settings& settings)
        : Panel(workspace, "Traffic"), devices_(devices), settings_(settings) {}
    ~TrafficPanel() override;

    // A captured request in a new Repeater tab (HTTPS connections get a request to fill in).
    void sendToRepeater(const TrafficProxy::Flow& flow);
    // An item for the Comparer; the two newest items are compared.
    void sendToComparer(std::string label, std::string text);

protected:
    void drawContents() override;

private:
    struct Exchange {  // one send of a Repeater tab
        httpclient::Target target;
        std::string request;
        httpclient::Result result;
    };
    struct RepeaterTab {
        int id = 0;
        std::string title;
        httpclient::Target target;
        std::string request;     // as edited (LF lines)
        std::string hostEdit;    // the target's host as typed
        bool fixLength = true;
        bool ignoreCert = false;
        std::future<httpclient::Result> pending;
        std::shared_ptr<std::atomic<bool>> cancel;
        std::string pendingRequest;
        std::chrono::steady_clock::time_point sentAt;
        std::vector<Exchange> history;
        int shown = -1;          // index into history
        int view = 1;            // response view: 0 raw, 1 pretty body, 2 headers
        std::string rawCache;    // the shown response as raw text (for the read-only box)
        int rawFor = -1;
    };
    void drawIntercept();
    void drawRules();
    void drawComparer();
    void loadRules();
    void applyRules(bool save);
    void applyIntercept();
    void drawRepeater();
    void drawRepeaterTab(RepeaterTab& tab);
    void sendRepeater(RepeaterTab& tab);
    RepeaterTab& newRepeaterTab(const httpclient::Target& target, std::string request);

    void drawToolbar();
    void drawSessionDialogs();  // HAR save / open (file browsers)
    void drawScripts();         // the Scripts tab
    void drawRouting();         // the Map & Replay tab
    // Batch replay: sends the requests again (Repeater engine); the answers
    // join the list as new flows.
    void startBatchReplay(const std::vector<uint64_t>& ids);
    void pollBatchReplay();
    void copyAsMenu(uint64_t flowId);  // "Copy as" submenu items
    void loadRouting();         // from the settings, once (applied to the proxy)
    void applyRouting();        // to the proxy and the settings
    void pollScript();          // start job, log, auto-reload
    void loadScripts(std::vector<std::string> paths);  // by value: a reload passes the running host's own list
    std::vector<std::string> scriptPathList() const;   // the enabled scripts (lines not starting with #)
    std::vector<std::string> scriptLines() const;      // every script line, disabled ones keep their leading #
    // Filter expressions (mitmproxy syntax) typed into the filter box.
    void updateExpression(const std::string& text);
    void drawFilterHelp();
    void drawRequests();
    void drawFilterPopup();
    void updateBodySearch(const std::string& text);
    bool passes(const TrafficProxy::Flow& f) const;
    void drawDetail();
    void drawDetailTls(const TrafficProxy::Flow& f);   // version / cipher / cert failure line
    void drawDetailWebSockets(const TrafficProxy::Flow& f);  // recorded frames
    void drawEndpoints();
    bool inCode(const std::string& host, const std::string& path);
    void refreshCodeStrings();

    // The "HTTPS & certificates" dialog: ApkSpy's CA, exporting it, and
    // installing / checking it on the connected device.
    void drawCertDialog();
    void refreshCertInfo();

    DeviceService& devices_;
    Settings& settings_;
    char filter_[256] = {};
    bool hideTunnels_ = false;
    // Certificates dialog state
    bool showCerts_ = false;
    bool certInfoBusy_ = false;                  // an inspect job is running
    std::string certStatus_;                     // last action's outcome
    std::string certExportPath_;                 // where the CA was exported last
    struct CertInfo {
        bool valid = false;
        std::string subject, issuer, serial, fingerprint, notBefore, notAfter;
        long long secondsLeft = 0;
        // device side (filled by the async inspect)
        bool ran = false;
        std::string deviceSerial, deviceModel, androidRelease;
        int sdk = 0;
        bool adbdRoot = false, suAvailable = false;
        bool userStoreReadable = false, caUserInstalled = false, caSystemInstalled = false, overlayMounted = false;
        std::string notes;
    };
    CertInfo certInfo_;
    std::future<CertInfo> certInfoJob_;
    bool devicesRequested_ = false;
    std::vector<TrafficProxy::Flow> rows_;
    uint64_t rowsHead_ = 0;
    uint64_t selected_ = 0;
    TrafficProxy::Flow detail_;
    uint64_t detailId_ = 0;
    std::string status_;
    // Lower-cased URL / path strings from the bytecode analyses.
    std::vector<std::string> codeStrings_;
    std::future<std::vector<std::string>> codeStringsJob_;
    std::unordered_map<std::string, bool> inCodeCache_;
    const void* codeStringsOwner_ = nullptr;
    std::vector<std::unique_ptr<RepeaterTab>> repeater_;
    int repeaterNext_ = 1;
    int repeaterSelect_ = -1;  // tab to bring forward on the next frame
    bool showRepeater_ = false;
    std::vector<std::future<httpclient::Result>> abandoned_;
    // Intercept
    bool interceptRequests_ = false;
    bool interceptResponses_ = false;
    bool interceptWs_ = false;
    // WebSocket tab: the selected frame, and the Send message box.
    int wsSelected_ = -1;
    uint64_t wsSelectedFlow_ = 0;
    std::string wsSendText_;
    int wsSendToServer_ = 1;
    bool wsSendHex_ = false;
    std::string wsStatus_;
    char interceptFilter_[256] = {};
    uint64_t selectedHeld_ = 0;
    std::map<uint64_t, std::string> heldEdits_;  // held id -> the text being edited
    // Match & replace
    std::vector<matchreplace::Rule> rules_;
    matchreplace::RuleSet ruleSet_;  // compiled (regex errors per rule)
    bool rulesLoaded_ = false;
    // History filters, highlights and comments (Requests tab)
    struct HistoryFilter {
        bool methods[6] = {true, true, true, true, true, true};  // GET POST PUT PATCH DELETE other
        bool statuses[5] = {true, true, true, true, true};        // 2xx 3xx 4xx 5xx none
        bool types[6] = {true, true, true, true, true, true};     // JSON HTML XML script/css media other
        bool hideStatic = false;
        bool onlyEdited = false;
        bool onlyParams = false;
        bool onlyMarked = false;
        std::vector<std::string> hiddenHosts;
        std::string onlyHost;
        bool active() const;
    };
    HistoryFilter filter2_;
    struct Mark {
        int color = 0;  // 0 none, else 1 + palette index
        std::string comment;
    };
    std::unordered_map<uint64_t, Mark> marks_;  // by flow id
    uint64_t commentFor_ = 0;
    char commentBuf_[256] = {};
    bool openComment_ = false;
    // Filter expression state: parsed from filter_ when it uses ~filters.
    std::shared_ptr<const flowfilter::Filter> expr_;
    std::string exprText_;
    std::string exprError_;
    std::future<std::vector<uint64_t>> exprJob_;  // content filters run on full flows off the UI thread
    std::unordered_set<uint64_t> exprHits_;
    uint64_t exprHead_ = 0;
    std::string exprJobFor_;  // the expression the running job evaluates
    // Sessions (HAR)
    FileBrowser harSaver_;
    FileBrowser harOpener_;
    FileBrowser protoOpener_;
    bool protoLoaded_ = false;
    void loadProtoDir(const std::string& dir, bool report);
    bool harSaveFiltered_ = false;
    std::vector<uint64_t> shownIds_;  // what the Requests table shows (for "save filtered")
    struct BatchReplay {
        std::future<std::vector<TrafficProxy::Flow>> job;
        std::shared_ptr<std::atomic<bool>> cancel;
        std::shared_ptr<std::atomic<int>> done;
        int total = 0;
    };
    BatchReplay batch_;
    // Map & Replay
    TrafficProxy::Routing routing_;
    bool routingLoaded_ = false;
    char ignoreHosts_[4096] = {};
    char allowHosts_[4096] = {};
    TrafficProxy::ReplayOptions replayOptions_;
    TrafficProxy::Conditions conditions_;
    std::string replayStatus_;
    FileBrowser replayOpener_;
    FileBrowser mapLocalBrowser_;
    int mapLocalBrowseRow_ = -1;
    // Scripts
    std::shared_ptr<trafficscript::Host> script_;
    std::future<std::pair<std::shared_ptr<trafficscript::Host>, std::string>> scriptJob_;
    char scriptPaths_[4096] = {};  // one script per line
    std::vector<std::string> scriptLog_;
    bool scriptAutoReload_ = true;
    long long scriptMtime_ = 0;
    int scriptCheckFrame_ = 0;
    FileBrowser scriptOpener_;
    FileBrowser scriptSaver_;
    bool searchBodies_ = false;
    std::future<std::vector<uint64_t>> bodySearchJob_;
    std::string bodySearchText_;
    uint64_t bodySearchHead_ = 0;
    std::unordered_set<uint64_t> bodyHits_;
    // Comparer
    struct CompareItem {
        std::string label;
        std::string text;
    };
    std::vector<CompareItem> compareItems_;
    int compareNext_ = 1;
    int compareA_ = -1, compareB_ = -1;
    bool compareDirty_ = false;
    bool showComparer_ = false;
    std::string compareTextA_, compareTextB_;          // what the result refers into
    std::unique_ptr<textdiff::Result> compareResult_;
    std::vector<int> compareHunks_;                    // first row of each difference
    int compareHunk_ = -1;
    bool compareScroll_ = false;  // sends of closed tabs, dropped once they end
};
