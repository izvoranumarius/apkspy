#include "ui/DecoderPanel.hpp"
#include <algorithm>
#include <cstring>
#include "app/Icons.hpp"
#include "app/Theme.hpp"
#include "ui/UiUtil.hpp"

namespace {

int resizeText(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<size_t>(data->BufTextLen));
        data->Buf = text->data();
    }
    return 0;
}

bool inputText(const char* id, std::string& s, ImGuiInputTextFlags flags = 0) {
    return ImGui::InputText(id, s.data(), s.capacity() + 1, flags | ImGuiInputTextFlags_CallbackResize, resizeText, &s);
}

std::string sizeText(size_t n) { return std::to_string(n) + (n == 1 ? " byte" : " bytes"); }

// The default argument of a new step.
std::string defaultArg(codec::Op op) {
    if (op == codec::Op::DecodeText) return "UTF-16LE";
    if (op == codec::Op::EncodeText) return "UTF-16LE";
    return {};
}

}  // namespace

void DecoderPanel::setInput(std::string text, bool smart) {
    input_ = std::move(text);
    if (smart) smartDecode();
    dirty_ = true;
}

void DecoderPanel::smartDecode() {
    steps_.clear();
    std::string chain;
    for (codec::Op op : codec::smartDecode(input_)) {
        steps_.push_back({op, defaultArg(op), true});
        chain += (chain.empty() ? "" : " > ") + std::string(codec::info(op).name);
    }
    note_ = chain.empty() ? "Smart decode found no encoding: the input reads as it is." : "Smart decode: " + chain;
    dirty_ = true;
}

void DecoderPanel::recompute() {
    dirty_ = false;
    results_.clear();
    failed_ = -1;
    std::string cur = input_;
    for (size_t i = 0; i < steps_.size(); ++i) {
        const Step& s = steps_[i];
        if (!s.enabled) {
            results_.push_back({true, cur, {}});
            continue;
        }
        codec::Result r = codec::apply(s.op, cur, s.arg);
        if (!r.ok && failed_ < 0) failed_ = static_cast<int>(i);
        if (r.ok) cur = r.out;
        results_.push_back(std::move(r));
        if (failed_ >= 0) break;
    }
    output_ = failed_ >= 0 ? std::string() : cur;
    guesses_ = input_.size() <= (4u << 20) ? codec::guess(input_) : std::vector<codec::Op>{};
    const bool text = view_ == 1 || (view_ == 0 && codec::isReadableText(output_));
    shown_ = text ? output_ : codec::hexDump(output_);
    std::replace(shown_.begin(), shown_.end(), '\0', '.');  // a text box ends at NUL
}

bool DecoderPanel::opMenu(codec::Op& chosen) {
    bool picked = false;
    const char* group = nullptr;
    for (const codec::OpInfo& o : codec::ops()) {
        if (!group || std::strcmp(group, o.group) != 0) {
            group = o.group;
            ImGui::SeparatorText(group);
        }
        if (ImGui::Selectable(o.name, chosen == o.op && false)) {
            chosen = o.op;
            picked = true;
        }
    }
    return picked;
}

void DecoderPanel::drawContents() {
    if (dirty_) recompute();
    // A short, wide dock (the bottom panel) puts input, steps and output side by side;
    // a tall one stacks them.
    const ImVec2 area = ImGui::GetContentRegionAvail();
    if (area.y < ui::em(26.f) && area.x > ui::em(55.f)) {
        const float gap = ImGui::GetStyle().ItemSpacing.x;
        const float col = (area.x - gap * 2.f) / 3.f;
        ImGui::BeginChild("##inCol", ImVec2(col, 0.f));
        drawInput(-FLT_MIN);
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("##stepsCol", ImVec2(col, 0.f), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
        drawSteps();
        ImGui::EndChild();
        ImGui::SameLine();
        ImGui::BeginChild("##outCol", ImVec2(0.f, 0.f));
        if (dirty_) recompute();
        drawOutput();
        ImGui::EndChild();
        return;
    }
    drawInput(std::max(ui::em(4.f), area.y * 0.26f));
    drawSteps();
    if (dirty_) recompute();  // a step changed: the output below is already current
    drawOutput();
}

void DecoderPanel::drawInput(float height) {
    // Input ---------------------------------------------------------------
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Input");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", sizeText(input_.size()).c_str());
    ImGui::SameLine();
    if (ui::smallButton("Paste"))
        if (const char* clip = ImGui::GetClipboardText()) setInput(clip, steps_.empty());
    ImGui::SameLine();
    if (ui::smallButton("Clear")) input_.clear(), note_.clear(), dirty_ = true;
    ImGui::SameLine();
    if (ui::smallButton("Smart decode")) smartDecode();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Peel off encodings one by one (URL, hex, Base64, JWT, escapes, gzip / zlib, UTF-16)\nwhile each step gives readable text");
    if (!guesses_.empty()) {
        ImGui::TextDisabled("Looks like:");
        for (codec::Op op : guesses_) {
            ImGui::PushID(static_cast<int>(op));
            if (ui::flowSmallButton(codec::info(op).name)) {
                steps_.push_back({op, defaultArg(op), true});
                dirty_ = true;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Add this step");
            ImGui::PopID();
        }
    }
    if (!note_.empty()) ImGui::TextDisabled("%s", note_.c_str());
    ImGui::PushFont(Theme::monoFont());
    if (ImGui::InputTextMultiline("##in", input_.data(), input_.capacity() + 1, ImVec2(-FLT_MIN, height),
                                  ImGuiInputTextFlags_CallbackResize | ImGuiInputTextFlags_AllowTabInput, resizeText, &input_))
        dirty_ = true;
    ImGui::PopFont();
}

void DecoderPanel::drawSteps() {
    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Steps");
    ImGui::SameLine();
    if (ui::smallButton(ui::icon(icons::ADD, "Add step").c_str())) ImGui::OpenPopup("##addstep");
    if (ImGui::BeginPopup("##addstep")) {
        codec::Op op = codec::Op::Base64Decode;
        if (opMenu(op)) {
            steps_.push_back({op, defaultArg(op), true});
            dirty_ = true;
        }
        ImGui::EndPopup();
    }
    if (!steps_.empty()) {
        ImGui::SameLine();
        if (ui::smallButton("Clear steps")) steps_.clear(), note_.clear(), dirty_ = true;
    }
    if (steps_.empty()) ImGui::TextDisabled("No steps: the output is the input. Add one, or use Smart decode.");

    int remove = -1, up = -1;
    for (size_t i = 0; i < steps_.size(); ++i) {
        Step& s = steps_[i];
        const codec::OpInfo& info = codec::info(s.op);
        ImGui::PushID(static_cast<int>(i));
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%zu.", i + 1);
        ImGui::SameLine();
        if (ImGui::Checkbox("##on", &s.enabled)) dirty_ = true;
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Turn this step off without removing it");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ui::em(15.f));
        if (ImGui::BeginCombo("##op", info.name, ImGuiComboFlags_HeightLarge)) {
            codec::Op op = s.op;
            if (opMenu(op) && op != s.op) {
                s.op = op;
                s.arg = defaultArg(op);
                dirty_ = true;
            }
            ImGui::EndCombo();
        }
        if (info.arg == codec::Arg::Text) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(ui::em(12.f));
            if (ImGui::InputTextWithHint("##arg", info.hint, s.arg.data(), s.arg.capacity() + 1, ImGuiInputTextFlags_CallbackResize,
                                         resizeText, &s.arg))
                dirty_ = true;
        } else if (info.arg == codec::Arg::Charset) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(ui::em(12.f));
            if (ImGui::BeginCombo("##cs", s.arg.c_str())) {
                for (const char* cs : codec::charsets())
                    if (ImGui::Selectable(cs, s.arg == cs)) s.arg = cs, dirty_ = true;
                ImGui::EndCombo();
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", info.hint);
        }
        ImGui::SameLine();
        if (ImGui::ArrowButton("##up", ImGuiDir_Up) && i > 0) up = static_cast<int>(i);
        ImGui::SameLine();
        if (ImGui::ArrowButton("##down", ImGuiDir_Down) && i + 1 < steps_.size()) up = static_cast<int>(i) + 1;
        ImGui::SameLine();
        if (ui::smallButton(Theme::hasIcons() ? icons::CLOSE : "x")) remove = static_cast<int>(i);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Remove the step");
        if (i < results_.size()) {
            ImGui::SameLine();
            const codec::Result& r = results_[i];
            if (!r.ok) ImGui::TextColored(theme::vec(Col::Error), "%s", r.error.c_str());
            else if (!s.enabled) ImGui::TextDisabled("off");
            else ImGui::TextDisabled("%s", sizeText(r.out.size()).c_str());
        }
        ImGui::PopID();
    }
    if (remove >= 0) {
        steps_.erase(steps_.begin() + remove);
        dirty_ = true;
    }
    if (up > 0) {
        std::swap(steps_[static_cast<size_t>(up)], steps_[static_cast<size_t>(up) - 1]);
        dirty_ = true;
    }
}

void DecoderPanel::drawOutput() {
    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Output");
    ImGui::SameLine();
    if (failed_ >= 0) ImGui::TextColored(theme::vec(Col::Error), "step %d failed", failed_ + 1);
    else ImGui::TextDisabled("%s%s", sizeText(output_.size()).c_str(), codec::isReadableText(output_) ? "" : ", binary");
    ImGui::SameLine();
    static const char* kViews[] = {"Auto", "Text", "Hex"};
    if (ui::segmented(kViews, 3, view_)) dirty_ = true;
    ImGui::SameLine();
    if (ui::smallButton(ui::icon(icons::COPY, "Copy").c_str())) ImGui::SetClipboardText(output_.c_str());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Copy the output (bytes after a NUL are left out: use Hex)");
    ImGui::SameLine();
    if (ui::smallButton("Copy as hex")) ImGui::SetClipboardText(codec::hexEncode(output_).c_str());
    ImGui::SameLine();
    if (ui::smallButton("To Comparer")) workspace_.sendToComparer("Decoder output", output_);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Compare this output with another (Network > Traffic > Comparer)");
    ImGui::SameLine();
    if (ui::smallButton("Use as input")) {
        input_ = output_;
        steps_.clear();
        note_.clear();
        dirty_ = true;
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Continue from here: the output becomes the input, the steps are cleared");
    if (dirty_) recompute();
    ImGui::PushFont(Theme::monoFont());
    ImGui::InputTextMultiline("##out", shown_.data(), shown_.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopFont();
}
