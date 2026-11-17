// Match & replace tab of the Traffic panel, as in Burp: rules that rewrite
// plain-HTTP requests and responses as they pass through the proxy.
#include "app/Icons.hpp"
#include "core/Settings.hpp"
#include "ui/TrafficCommon.hpp"
#include "ui/TrafficPanel.hpp"
#include "ui/UiUtil.hpp"

using namespace trafficui;

namespace {

int resizeText(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<size_t>(data->BufTextLen));
        data->Buf = text->data();
    }
    return 0;
}

bool inputString(const char* id, const char* hint, std::string& s) {
    return ImGui::InputTextWithHint(id, hint, s.data(), s.capacity() + 1, ImGuiInputTextFlags_CallbackResize, resizeText, &s);
}

}  // namespace

void TrafficPanel::loadRules() {
    if (rulesLoaded_) return;
    rulesLoaded_ = true;
    rules_ = matchreplace::fromJson(settings_.getString(Settings::kTrafficRules, ""));
    applyRules(false);
}

void TrafficPanel::applyRules(bool save) {
    ruleSet_ = matchreplace::RuleSet(rules_);
    devices_.traffic().setRules(ruleSet_);
    if (save) settings_.set(Settings::kTrafficRules, matchreplace::toJson(rules_));
}

void TrafficPanel::drawRules() {
    loadRules();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("Rules rewrite plain-HTTP requests and responses as they pass through the proxy, top to bottom. "
                        "Header rules: an empty match adds the replacement as a header, an empty replacement removes "
                        "matching headers. Body rules see the body decoded (chunked, gzip). HTTPS connections pass untouched.");
    ImGui::PopTextWrapPos();
    if (ui::smallButton(ui::icon(icons::ADD, "Add rule").c_str())) {
        rules_.push_back({true, matchreplace::Where::RequestHeader, "", "", false, ""});
        applyRules(true);
    }
    ImGui::SameLine();
    if (ui::smallButton("Presets")) ImGui::OpenPopup("##presets");
    if (ImGui::BeginPopup("##presets")) {
        for (const matchreplace::Rule& p : matchreplace::presets()) {
            const std::string label = p.comment + "  (" + matchreplace::whereName(p.where) + ")";
            if (ImGui::MenuItem(label.c_str())) {
                matchreplace::Rule r = p;
                r.enabled = true;
                rules_.push_back(r);
                applyRules(true);
            }
        }
        ImGui::EndPopup();
    }
    if (rules_.empty()) {
        ImGui::TextDisabled("No rules yet.");
        return;
    }

    const std::vector<int> hits = devices_.traffic().ruleHits();
    bool changed = false;
    int remove = -1, up = -1;
    if (ImGui::BeginTable("##rules", 8, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable |
                                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, ui::em(1.8f));
        ImGui::TableSetupColumn("Where", ImGuiTableColumnFlags_WidthFixed, ui::em(10.f));
        ImGui::TableSetupColumn("Match", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Replace", ImGuiTableColumnFlags_WidthStretch, 1.f);
        ImGui::TableSetupColumn("Regex", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
        ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch, 0.8f);
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, ui::em(3.f));
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, ui::em(4.5f));
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < rules_.size(); ++i) {
            matchreplace::Rule& r = rules_[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            changed |= ImGui::Checkbox("##on", &r.enabled);
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::BeginCombo("##where", matchreplace::whereName(r.where))) {
                for (int w = 0; w < matchreplace::kWhereCount; ++w)
                    if (ImGui::Selectable(matchreplace::whereName(static_cast<matchreplace::Where>(w)), static_cast<int>(r.where) == w)) {
                        r.where = static_cast<matchreplace::Where>(w);
                        changed = true;
                    }
                ImGui::EndCombo();
            }
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            const bool header = r.where == matchreplace::Where::RequestHeader || r.where == matchreplace::Where::ResponseHeader;
            ImGui::PushFont(Theme::monoFont());
            changed |= inputString("##match", header ? "(empty: add a header)" : "text to find", r.match);
            ImGui::PopFont();
            if (i < rules_.size() && !ruleSet_.rules().empty() && i < ruleSet_.rules().size() && !ruleSet_.error(i).empty()) {
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", ruleSet_.error(i).c_str());
                ImGui::GetWindowDrawList()->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), theme::u32(Col::Error));
            }
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::PushFont(Theme::monoFont());
            changed |= inputString("##replace", header ? "(empty: remove the header)" : "replacement", r.replace);
            ImGui::PopFont();
            ImGui::TableNextColumn();
            changed |= ImGui::Checkbox("##regex", &r.regex);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Regular expression (ECMAScript); $1, $2 in the replacement");
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-FLT_MIN);
            changed |= inputString("##comment", "", r.comment);
            ImGui::TableNextColumn();
            const int h = i < hits.size() ? hits[i] : 0;
            if (h) ImGui::TextColored(kGood, "%d", h);
            else ImGui::TextDisabled("0");
            ImGui::TableNextColumn();
            if (ImGui::ArrowButton("##up", ImGuiDir_Up) && i > 0) up = static_cast<int>(i);
            ImGui::SameLine(0.f, 2.f);
            if (ui::smallButton(Theme::hasIcons() ? icons::CLOSE : "x")) remove = static_cast<int>(i);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Remove the rule");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (remove >= 0) rules_.erase(rules_.begin() + remove), changed = true;
    if (up > 0) std::swap(rules_[static_cast<size_t>(up)], rules_[static_cast<size_t>(up) - 1]), changed = true;
    if (changed) applyRules(true);
}
