#include "analysis/Report.hpp"
#include <algorithm>
#include "analysis/ManifestAudit.hpp"

namespace report {
namespace {

std::string escapeHtml(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
        }
    }
    return o;
}

int severityRank(manifestaudit::Severity s) {
    return static_cast<int>(s);
}

std::string trafficMarkdown(const TrafficSection& t) {
    std::string o = "## Traffic\n\n";
    if (!t.hosts.empty()) {
        o += "Hosts: ";
        for (size_t i = 0; i < t.hosts.size(); ++i) o += (i ? ", " : "") + t.hosts[i];
        o += "\n\n";
    }
    if (t.endpoints.empty()) return o + "No requests recorded.\n";
    o += "| Method | Endpoint | Status |\n|---|---|---|\n";
    for (const auto& e : t.endpoints)
        o += "| " + e.method + " | `" + e.url + "` | " + (e.status ? std::to_string(e.status) : "—") + " |\n";
    return o;
}

std::string trafficHtml(const TrafficSection& t) {
    std::string o = "<h2>Traffic</h2>";
    if (!t.hosts.empty()) {
        o += "<p>Hosts: ";
        for (size_t i = 0; i < t.hosts.size(); ++i) o += (i ? ", " : "") + escapeHtml(t.hosts[i]);
        o += "</p>";
    }
    if (t.endpoints.empty()) return o + "<p>No requests recorded.</p>";
    o += "<table><tr><th>Method</th><th>Endpoint</th><th>Status</th></tr>";
    for (const auto& e : t.endpoints)
        o += "<tr><td>" + escapeHtml(e.method) + "</td><td><code>" + escapeHtml(e.url) + "</code></td><td>" +
             (e.status ? std::to_string(e.status) : "—") + "</td></tr>";
    return o + "</table>";
}

}  // namespace

std::string toMarkdown(const Options& opt, const manifestaudit::Audit* audit, const TrafficSection* traffic) {
    std::string o = "# " + opt.title + "\n\n";
    if (!opt.subtitle.empty()) o += opt.subtitle + "\n\n";
    if (audit && (opt.includeFindings || opt.includeComponents || opt.includePermissions)) {
        // The audit's own renderer produces the whole document; reuse it and
        // drop the parts that were filtered out by trimming sections.
        manifestaudit::Audit filtered = *audit;
        if (!opt.includeFindings) filtered.findings.clear();
        if (!opt.includeComponents) filtered.components.clear();
        if (!opt.includePermissions) {
            filtered.permissions.clear();
            filtered.dangerousPermissions.clear();
        }
        // Skip the audit's own H1: the report has one title.
        std::string md = manifestaudit::toMarkdown(filtered);
        const size_t firstLine = md.find('\n');
        if (!md.empty() && md[0] == '#' && firstLine != std::string::npos) md = md.substr(firstLine + 1);
        o += md;
    }
    if (traffic && opt.includeTraffic) o += trafficMarkdown(*traffic);
    return o;
}

std::string toHtml(const Options& opt, const manifestaudit::Audit* audit, const TrafficSection* traffic) {
    std::string o = "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + escapeHtml(opt.title) +
                    "</title><style>"
                    "body{font:14px/1.5 system-ui,sans-serif;max-width:60em;margin:2em auto;padding:0 1em;color:#222}"
                    "h1,h2{border-bottom:1px solid #ddd;padding-bottom:.2em}"
                    "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.3em .6em;text-align:left}"
                    "th{background:#f5f5f5}code{font:13px monospace;background:#f3f3f3;padding:.1em .3em;border-radius:3px}"
                    ".sev{display:inline-block;min-width:5em;text-align:center;border-radius:3px;padding:0 .4em;color:#fff}"
                    ".sev-critical,.sev-high{background:#c62828}.sev-medium{background:#ef6c00}"
                    ".sev-low{background:#1565c0}.sev-info{background:#616161}"
                    "</style></head><body>";
    o += "<h1>" + escapeHtml(opt.title) + "</h1>";
    if (!opt.subtitle.empty()) o += "<p>" + escapeHtml(opt.subtitle) + "</p>";

    if (audit) {
        o += "<h2>" + escapeHtml(std::string("Security audit: ") +
                                (audit->appLabel.empty() ? audit->package : audit->appLabel)) + "</h2><table>";
        auto row = [&o](const char* k, const std::string& v) {
            o += std::string("<tr><th>") + k + "</th><td>" + escapeHtml(v) + "</td></tr>";
        };
        row("Package", audit->package);
        row("Version", audit->versionName + " (" + std::to_string(audit->versionCode) + ")");
        row("SDK", "min " + std::to_string(audit->minSdk) + " / target " + std::to_string(audit->targetSdk));
        row("Debuggable", audit->debuggable ? "yes" : "no");
        row("Backup allowed", audit->allowBackup ? "yes" : "no");
        row("Cleartext", audit->usesCleartext ? "allowed" : "blocked");
        o += "</table>";

        if (opt.includeFindings) {
            std::vector<manifestaudit::Finding> findings = audit->findings;
            std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
                return severityRank(a.severity) > severityRank(b.severity);
            });
            o += "<h2>Findings</h2>";
            if (findings.empty()) o += "<p>No findings.</p>";
            for (const auto& f : findings) {
                const std::string sev = manifestaudit::severityName(f.severity);
                o += "<p><span class=\"sev sev-" + sev + "\">" + sev + "</span> <strong>" +
                     escapeHtml(f.title) + "</strong> (" + escapeHtml(f.masvsId) + ")<br>" + escapeHtml(f.detail) +
                     " <code>" + escapeHtml(f.location) + "</code></p>";
            }
        }
        if (opt.includeComponents) {
            o += "<h2>Components</h2><table><tr><th>Kind</th><th>Name</th><th>Exported</th><th>Permission</th></tr>";
            for (const auto& c : audit->components)
                o += std::string("<tr><td>") + manifestaudit::Component::kindName(c.kind) + "</td><td><code>" +
                     escapeHtml(c.name) + "</code></td><td>" + (c.exported ? "yes" : "no") + "</td><td>" +
                     (c.permission.empty() ? "—" : escapeHtml(c.permission)) + "</td></tr>";
            o += "</table>";
        }
        if (opt.includePermissions && !audit->permissions.empty()) {
            o += "<h2>Permissions</h2><ul>";
            for (const auto& p : audit->permissions) {
                const bool danger = std::find(audit->dangerousPermissions.begin(),
                                              audit->dangerousPermissions.end(),
                                              p) != audit->dangerousPermissions.end();
                o += "<li><code>" + escapeHtml(p) + "</code>" + (danger ? " <strong>dangerous</strong>" : "") + "</li>";
            }
            o += "</ul>";
        }
    }
    if (traffic && opt.includeTraffic) o += trafficHtml(*traffic);
    return o + "</body></html>";
}

}  // namespace report
