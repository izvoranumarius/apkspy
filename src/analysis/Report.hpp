#pragma once
#include <string>
#include <vector>

namespace manifestaudit {
struct Audit;
}  // namespace manifestaudit

// Exports what a session found as a report you can hand to someone:
// Markdown (readable, paste into a ticket) or a self-contained HTML file
// (openable without ApkSpy). Everything is plain text - no UI, no ImGui -
// so it works headless and over MCP.
//
// The report is assembled from the individual sections' own renderers
// (manifestaudit::toMarkdown / toJson, ...), so a section can never drift
// from what the panel shows.
namespace report {

struct Options {
    std::string title = "ApkSpy report";
    std::string subtitle;  // e.g. the project name or the APK path
    bool includeFindings = true;
    bool includeComponents = true;
    bool includePermissions = true;
    bool includeTraffic = false;  // traffic summary (hosts, endpoints), when provided
};

// Traffic summary for the report: what the capture saw.
struct TrafficSection {
    struct Endpoint {
        std::string method;
        std::string url;
        int status = 0;
        std::string note;
    };
    std::vector<Endpoint> endpoints;
    std::vector<std::string> hosts;
};

// Markdown report. `audit` may be null (skipped).
std::string toMarkdown(const Options& options, const manifestaudit::Audit* audit,
                       const TrafficSection* traffic = nullptr);

// Self-contained HTML (inline CSS, no scripts, no external assets), escaped.
std::string toHtml(const Options& options, const manifestaudit::Audit* audit,
                   const TrafficSection* traffic = nullptr);

}  // namespace report
