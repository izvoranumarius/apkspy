// Requests tab of the Traffic panel, as in Burp's HTTP history: filters (method,
// status, type, static files, hosts, edited, parameters, highlighted, a search
// that can look inside bodies), sortable columns, highlights and comments.
#include <algorithm>
#include <cstdio>
#include "core/TextUtils.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

namespace {

const char* kMethods[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "Other"};
const char* kStatuses[] = {"2xx", "3xx", "4xx", "5xx", "No answer / error"};
const char* kTypes[] = {"JSON", "HTML", "XML", "Script / CSS", "Images / media / fonts", "Other"};
const Col kMarkColors[] = {Col::Red, Col::Orange, Col::Yellow, Col::Green, Col::Cyan, Col::Blue, Col::Purple, Col::Pink};
const char* kMarkNames[] = {"Red", "Orange", "Yellow", "Green", "Cyan", "Blue", "Purple", "Pink"};

std::string extensionOf(const std::string& path) {
    std::string p = path.substr(0, path.find_first_of("?#"));
    const size_t slash = p.rfind('/'), dot = p.rfind('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return {};
    return tex::asciiLower(p.substr(dot + 1));
}

bool staticFile(const std::string& path) {
    static const char* kStatic[] = {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "woff", "woff2",
                                    "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "map"};
    const std::string ext = extensionOf(path);
    return std::any_of(std::begin(kStatic), std::end(kStatic), [&](const char* e) { return ext == e; });
}

int methodIndex(const std::string& m) {
    for (int i = 0; i < 5; ++i)
        if (m == kMethods[i]) return i;
    return 5;
}

int statusIndex(const TrafficProxy::Flow& f) {
    if (f.status >= 200 && f.status < 300) return 0;
    if (f.status >= 300 && f.status < 400) return 1;
    if (f.status >= 400 && f.status < 500) return 2;
    if (f.status >= 500 && f.status < 600) return 3;
    return 4;
}

int typeIndex(const TrafficProxy::Flow& f) {
    const std::string ct = tex::asciiLower(f.contentType());
    const std::string ext = extensionOf(f.path);
    if (ct.find("json") != std::string::npos || ext == "json") return 0;
    if (ct.find("html") != std::string::npos || ext == "html" || ext == "htm") return 1;
    if (ct.find("xml") != std::string::npos || ext == "xml") return 2;
    if (ct.find("javascript") != std::string::npos || ct.find("css") != std::string::npos || ext == "js" || ext == "css") return 3;
    if (ct.rfind("image/", 0) == 0 || ct.rfind("video/", 0) == 0 || ct.rfind("audio/", 0) == 0 || ct.find("font") != std::string::npos ||
        staticFile(f.path))
        return 4;
    return 5;
}

bool hasParams(const TrafficProxy::Flow& f) { return f.path.find('?') != std::string::npos || f.request.bodySize > 0; }

}  // namespace

bool TrafficPanel::HistoryFilter::active() const {
    for (bool b : methods)
        if (!b) return true;
    for (bool b : statuses)
        if (!b) return true;
    for (bool b : types)
        if (!b) return true;
    return hideStatic || onlyEdited || onlyParams || onlyMarked || !hiddenHosts.empty() || !onlyHost.empty();
}

bool TrafficPanel::passes(const TrafficProxy::Flow& f) const {
    const HistoryFilter& h = filter2_;
    if (hideTunnels_ && f.tunnel) return false;
    const std::string host = f.tunnel && !f.sni.empty() ? f.sni : f.host;
    if (!h.onlyHost.empty() && !tex::asciiIEqual(host, h.onlyHost)) return false;
    for (const std::string& hidden : h.hiddenHosts)
        if (tex::asciiIEqual(host, hidden)) return false;
    if (f.tunnel) return !h.onlyEdited && !h.onlyParams && (!h.onlyMarked || marks_.count(f.id));  // nothing more is known
    if (!h.methods[methodIndex(f.method)]) return false;
    if (f.complete && !h.statuses[statusIndex(f)]) return false;
    if (!h.types[typeIndex(f)]) return false;
    if (h.hideStatic && staticFile(f.path)) return false;
    if (h.onlyEdited && !f.edited) return false;
    if (h.onlyParams && !hasParams(f)) return false;
    if (h.onlyMarked && !marks_.count(f.id)) return false;
    return true;
}

void TrafficPanel::drawFilterPopup() {
    HistoryFilter& h = filter2_;
    ImGui::SeparatorText("Method");
    for (int i = 0; i < 6; ++i) {
        if (i) ImGui::SameLine();
        ImGui::Checkbox(kMethods[i], &h.methods[i]);
    }
    ImGui::SeparatorText("Status");
    for (int i = 0; i < 5; ++i) {
        if (i) ImGui::SameLine();
        ImGui::Checkbox(kStatuses[i], &h.statuses[i]);
    }
    ImGui::SeparatorText("Type");
    for (int i = 0; i < 6; ++i) {
        if (i % 3) ImGui::SameLine();
        ImGui::Checkbox(kTypes[i], &h.types[i]);
    }
    ImGui::Checkbox("Hide static files (scripts, styles, images, fonts)", &h.hideStatic);
    ImGui::SeparatorText("Show only");
    ImGui::Checkbox("Edited (intercept, match & replace)", &h.onlyEdited);
    ImGui::Checkbox("With parameters (query or body)", &h.onlyParams);
    ImGui::Checkbox("Highlighted or commented", &h.onlyMarked);
    ImGui::Checkbox("Hide un-decrypted tunnels", &hideTunnels_);
    ImGui::SeparatorText("Search");
    ImGui::Checkbox("Search inside bodies and headers too", &searchBodies_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("The filter text also matches decoded request and response bodies");
    if (!h.onlyHost.empty() || !h.hiddenHosts.empty()) {
        ImGui::SeparatorText("Hosts");
        if (!h.onlyHost.empty()) {
            ImGui::Text("Only %s", h.onlyHost.c_str());
            ImGui::SameLine();
            if (ui::smallButton("Show all hosts")) h.onlyHost.clear();
        }
        for (size_t i = 0; i < h.hiddenHosts.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            ImGui::Text("Hidden: %s", h.hiddenHosts[i].c_str());
            ImGui::SameLine();
            if (ui::smallButton("Show")) {
                h.hiddenHosts.erase(h.hiddenHosts.begin() + static_cast<std::ptrdiff_t>(i));
                ImGui::PopID();
                break;
            }
            ImGui::PopID();
        }
    }
    ImGui::Separator();
    if (ui::smallButton("Reset filters")) {
        filter2_ = HistoryFilter{};
        hideTunnels_ = false;
    }
}

void TrafficPanel::updateBodySearch(const std::string& text) {
    // The body search runs off the UI thread: once for a new text, then for new flows only.
    if (bodySearchJob_.valid() && bodySearchJob_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        for (uint64_t id : bodySearchJob_.get()) bodyHits_.insert(id);
    }
    if (!searchBodies_ || text.empty()) {
        bodySearchText_.clear();
        bodyHits_.clear();
        return;
    }
    if (bodySearchJob_.valid()) return;
    TrafficProxy& proxy = devices_.traffic();
    if (text != bodySearchText_) {
        bodySearchText_ = text;
        bodyHits_.clear();
        bodySearchHead_ = 0;
    }
    if (proxy.lastId() == bodySearchHead_) return;
    const uint64_t since = bodySearchHead_;
    bodySearchHead_ = proxy.lastId();
    bodySearchJob_ = std::async(std::launch::async, [&proxy, text, since] { return proxy.searchFlows(text, since); });
}

void TrafficPanel::drawRequests() {
    const std::string filter = filter_;
    // Text with a ~filter is an expression; anything else is a plain search.
    const bool isExpr = flowfilter::looksLikeExpression(filter);
    updateExpression(isExpr ? filter : std::string());
    updateBodySearch(isExpr ? std::string() : filter);
    flowfilter::Context ctx;
    ctx.marked = [this](uint64_t id) { return marks_.count(id) > 0; };
    ctx.comment = [this](uint64_t id) {
        const auto it = marks_.find(id);
        return it == marks_.end() ? std::string() : it->second.comment;
    };
    std::vector<const TrafficProxy::Flow*> shown;
    shown.reserve(rows_.size());
    for (const auto& f : rows_) {
        if (!passes(f)) continue;
        if (isExpr) {
            // An expression that does not parse filters nothing (the box turns red).
            if (expr_ && expr_->needsContent() && !exprHits_.count(f.id)) continue;
            if (expr_ && !expr_->needsContent() && !expr_->match(f, &ctx)) continue;
        } else if (!filter.empty()) {
            const auto mark = marks_.find(f.id);
            const std::string hay = f.method + " " + f.host + " " + f.sni + " " + f.path + " " + std::to_string(f.status) + " " +
                                    (mark == marks_.end() ? std::string() : mark->second.comment);
            if (tex::ciFind(hay, filter) == std::string_view::npos && !bodyHits_.count(f.id)) continue;
        }
        shown.push_back(&f);
    }
    shownIds_.clear();
    for (const auto* f : shown) shownIds_.push_back(f->id);
    if (rows_.empty()) {
        ui::emptyState("No requests captured",
                       "Start the proxy, then use the app. HTTP and decrypted HTTPS requests appear here with headers and bodies; "
                       "connections the proxy cannot decrypt show as tunnels.\n"
                       "For HTTPS, install ApkSpy's CA on the device (HTTPS & certificates).");
        return;
    }

    // What is shown, and the filters.
    const bool filtered = filter2_.active() || hideTunnels_ || !filter.empty();
    if (ui::smallButton(filter2_.active() || hideTunnels_ ? "Filter (on)" : "Filter")) ImGui::OpenPopup("##histFilter");
    if (ImGui::BeginPopup("##histFilter")) {
        drawFilterPopup();
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    if (filtered) ImGui::TextColored(kWarn, "Showing %zu of %zu", shown.size(), rows_.size());
    else ImGui::TextDisabled("%zu requests", rows_.size());
    if (bodySearchJob_.valid() || exprJob_.valid()) {
        ImGui::SameLine();
        ImGui::TextDisabled("searching bodies...");
    }
    if (isExpr && !exprError_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(kError, "expression: %s", exprError_.c_str());
    }
    if (filtered) {
        ImGui::SameLine();
        if (ui::smallButton("Clear filters")) {
            filter2_ = HistoryFilter{};
            hideTunnels_ = false;
            filter_[0] = 0;
        }
    }

    const bool hasDetail = selected_ != 0;
    // With a request open, the list takes what its rows need (at least six,
    // at most half the height): a few requests no longer leave the headers
    // and body of the open one below the fold.
    float tableH = 0.f;
    if (hasDetail) {
        const float rowH = ImGui::GetTextLineHeight() + ImGui::GetStyle().CellPadding.y * 2.f;
        const float rows = static_cast<float>(std::max<size_t>(shown.size(), 6)) + 1.f;  // + the header row
        tableH = std::min(ImGui::GetContentRegionAvail().y * 0.5f, rows * rowH + ImGui::GetStyle().ItemSpacing.y);
    }
    // The URL is what matters: secondary columns only when there is room for them next to a readable URL.
    const bool wide = ImGui::GetContentRegionAvail().x > ui::em(60.f);
    enum ColumnId { kTime, kMethod, kProto, kUrl, kStatus, kType, kSize, kMs, kNote };
    const int cols = wide ? 9 : 4;
    if (ImGui::BeginTable("##flows", cols, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                               ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Sortable |
                                               ImGuiTableFlags_SortTristate,
                          ImVec2(0, tableH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        if (wide) ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, ui::em(5.5f), kTime);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f), kMethod);
        if (wide) ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, ui::em(3.6f), kProto);
        ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch, 1.f, kUrl);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f), kStatus);
        if (wide) ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, ui::em(8.f), kType);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f), kSize);
        if (wide) ImGui::TableSetupColumn("ms", ImGuiTableColumnFlags_WidthFixed, ui::em(3.5f), kMs);
        if (wide) ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthFixed, ui::em(10.f), kNote);
        ImGui::TableHeadersRow();

        // Sorting (time, i.e. arrival, when none is chosen).
        bool byArrival = true;
        if (const ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& s = specs->Specs[0];
            const bool desc = s.SortDirection == ImGuiSortDirection_Descending;
            byArrival = s.ColumnUserID == kTime && !desc;
            const auto size = [](const TrafficProxy::Flow* f) { return f->tunnel || !f->transport.empty() ? f->bytesUp + f->bytesDown : f->response.bodySize; };
            const auto note = [&](const TrafficProxy::Flow* f) {
                auto it = marks_.find(f->id);
                return it == marks_.end() ? std::string() : it->second.comment;
            };
            std::stable_sort(shown.begin(), shown.end(), [&](const TrafficProxy::Flow* a, const TrafficProxy::Flow* b) {
                int c = 0;
                switch (s.ColumnUserID) {
                case kMethod: c = a->method.compare(b->method); break;
                case kUrl: c = a->url().compare(b->url()); break;
                case kStatus: c = (a->status > b->status) - (a->status < b->status); break;
                case kType: c = a->contentType().compare(b->contentType()); break;
                case kSize: c = (size(a) > size(b)) - (size(a) < size(b)); break;
                case kMs: c = (a->durationMs > b->durationMs) - (a->durationMs < b->durationMs); break;
                case kNote: c = note(a).compare(note(b)); break;
                default: c = (a->id > b->id) - (a->id < b->id); break;
                }
                return desc ? c > 0 : c < 0;
            });
        }

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(shown.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const TrafficProxy::Flow& f = *shown[static_cast<size_t>(i)];
                ImGui::PushID(static_cast<int>(f.id));
                ImGui::TableNextRow();
                const auto mark = marks_.find(f.id);
                if (mark != marks_.end() && mark->second.color > 0)
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, theme::u32(kMarkColors[mark->second.color - 1], 0.28f));
                if (wide) {
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", clock(f.startedAt).c_str());
                }
                ImGui::TableNextColumn();
                if (ImGui::Selectable(f.method.c_str(), selected_ == f.id, ImGuiSelectableFlags_SpanAllColumns)) selected_ = f.id;
                if (ImGui::BeginPopupContextItem("##flowctx")) {
                    selected_ = f.id;
                    TrafficProxy::Flow full;
                    if (ImGui::MenuItem("Send to Repeater", "Ctrl+R") && devices_.traffic().flow(f.id, full)) sendToRepeater(full);
                    if (!f.tunnel && ImGui::MenuItem("Send request to Comparer") && devices_.traffic().flow(f.id, full))
                        sendToComparer(full.method + " " + full.url(), messageText(full.request));
                    if (!f.tunnel && ImGui::MenuItem("Send response to Comparer") && devices_.traffic().flow(f.id, full))
                        sendToComparer(std::to_string(full.status) + " " + full.url(), messageText(full.response));
                    ImGui::Separator();
                    if (ImGui::BeginMenu("Highlight")) {
                        for (int c = 0; c < 8; ++c) {
                            ImGui::PushStyleColor(ImGuiCol_Text, theme::vec(kMarkColors[c]));
                            if (ImGui::MenuItem(kMarkNames[c])) marks_[f.id].color = c + 1;
                            ImGui::PopStyleColor();
                        }
                        if (ImGui::MenuItem("None") && mark != marks_.end()) {
                            marks_[f.id].color = 0;
                            if (marks_[f.id].comment.empty()) marks_.erase(f.id);
                        }
                        ImGui::EndMenu();
                    }
                    if (ImGui::MenuItem(mark != marks_.end() && !mark->second.comment.empty() ? "Edit comment..." : "Add comment...")) {
                        commentFor_ = f.id;
                        std::snprintf(commentBuf_, sizeof commentBuf_, "%s", mark == marks_.end() ? "" : mark->second.comment.c_str());
                        openComment_ = true;
                    }
                    ImGui::Separator();
                    const std::string host = f.tunnel && !f.sni.empty() ? f.sni : f.host;
                    if (ImGui::MenuItem(("Show only " + host).c_str())) filter2_.onlyHost = host;
                    if (ImGui::MenuItem(("Hide " + host).c_str())) filter2_.hiddenHosts.push_back(host);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Copy URL")) ImGui::SetClipboardText(f.url().c_str());
                    if (!f.tunnel && ImGui::BeginMenu("Copy as")) {
                        copyAsMenu(f.id);
                        ImGui::EndMenu();
                    }
                    if (!f.tunnel && ImGui::MenuItem("Replay")) startBatchReplay({f.id});
                    ImGui::EndPopup();
                }
                if (wide) {
                    ImGui::TableNextColumn();
                    const char* proto = f.method == "DNS" ? "dns"
                                       : !f.transport.empty() ? f.transport.c_str()
                                       : f.alpn == "h2c" ? "h2c"
                                       : f.tunnel ? "(tunnel)"
                                       : f.websocket ? (f.https ? "wss" : "ws")
                                       : f.https ? "https" : "http";
                    ImGui::TextDisabled("%s", proto);
                }
                ImGui::TableNextColumn();
                const std::string url = f.url();
                if (f.tunnel) ImGui::TextColored(kDim, "%s  (tunnel)", url.c_str());
                else if (f.edited) ImGui::TextColored(kWarn, "%s  (edited)", url.c_str());
                else ImGui::TextUnformatted(url.c_str());
                if (ImGui::IsItemHovered()) {
                    std::string type = f.tunnel ? "TLS tunnel" : f.contentType();
                    std::string note = mark == marks_.end() || mark->second.comment.empty() ? std::string() : "\n" + mark->second.comment;
                    ImGui::SetTooltip("%s\n%s  %s  %.0f ms%s", url.c_str(), clock(f.startedAt).c_str(), type.c_str(), f.durationMs, note.c_str());
                }
                ImGui::TableNextColumn();
                if (!f.complete && f.status == 0) ImGui::TextDisabled("...");
                else if (f.status) ImGui::TextColored(statusColor(f.status), "%d", f.status);
                else if (!f.error.empty() || !f.tlsError.empty()) ImGui::TextColored(kError, "err");
                else ImGui::TextDisabled("-");  // no HTTP status (raw TCP / UDP, an h2c connection)
                if (wide) {
                    ImGui::TableNextColumn();
                    std::string type = f.tunnel ? "tunnel" : f.contentType();
                    type = type.substr(0, type.find(';'));
                    ImGui::TextDisabled("%s", type.c_str());
                }
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", humanBytes(f.tunnel || !f.transport.empty() ? f.bytesUp + f.bytesDown : f.response.bodySize).c_str());
                if (wide) {
                    ImGui::TableNextColumn();
                    if (f.complete) ImGui::TextDisabled("%.0f", f.durationMs);
                    ImGui::TableNextColumn();
                    if (mark != marks_.end()) ImGui::TextUnformatted(mark->second.comment.c_str());
                }
                ImGui::PopID();
            }
        }
        // Follow new requests while sorted by arrival and scrolled to the end.
        if (byArrival && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - ui::em(2.f)) ImGui::SetScrollHereY(1.f);
        ImGui::EndTable();
    }
    // Comment editor.
    if (openComment_) ImGui::OpenPopup("Comment"), openComment_ = false;
    if (ImGui::BeginPopup("Comment")) {
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        ImGui::SetNextItemWidth(ui::em(22.f));
        const bool enter = ImGui::InputTextWithHint("##comment", "a note on this request", commentBuf_, sizeof commentBuf_,
                                                    ImGuiInputTextFlags_EnterReturnsTrue);
        if (enter || ui::smallButton("OK")) {
            Mark& m = marks_[commentFor_];
            m.comment = commentBuf_;
            if (m.comment.empty() && m.color == 0) marks_.erase(commentFor_);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ui::smallButton("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape, false)) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    // Ctrl+R, as in Burp: the selected request to the Repeater.
    if (selected_ && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput &&
        ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_R, false)) {
        TrafficProxy::Flow full;
        if (devices_.traffic().flow(selected_, full)) sendToRepeater(full);
    }
    if (hasDetail) drawDetail();
}
