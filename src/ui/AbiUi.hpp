#pragma once
#include <string>
#include <vector>
#include "analysis/Abi.hpp"
#include "app/Theme.hpp"
#include "core/Workspace.hpp"
#include "imgui.h"
#include "ui/UiUtil.hpp"

// How native-code architecture is shown: one set of labels for the Overview, the Native view and the Devices panel.
namespace abiui {

// "arm64-v8a  (AArch64, 64-bit)".
inline std::string abiLabel(const std::string& dirName) {
    const abi::Info i = abi::fromName(dirName);
    if (i.id == abi::Id::Unknown) return dirName + "  (unrecognised)";
    std::string s = dirName + "  (" + i.arch + ", " + std::to_string(i.bits) + "-bit";
    if (i.legacy) s += ", legacy";
    return s + ")";
}

// The architecture an entry was built for, as its ELF header says ("AArch64", "unreadable").
inline std::string libArch(const abi::NativeLib& l) {
    if (!l.validElf) return "not an ELF file";
    return l.elf.id == abi::Id::Unknown ? abi::machineName(l.ident.machine) + (l.ident.is64 ? " (64-bit)" : " (32-bit)") + ", unsupported"
                                        : std::string(l.elf.arch);
}

inline ImVec4 compatColor(abi::Compatibility::Kind k) {
    switch (k) {
    case abi::Compatibility::Kind::Compatible: return theme::vec(Col::Success);
    case abi::Compatibility::Kind::Incompatible: return theme::vec(Col::Warning);
    default: return theme::vec(Col::TextMuted);
    }
}

// The one-line summary: which ABIs an APK ships and how wide its native code is.
inline std::string shipsLine(const abi::ApkNative& n) {
    if (n.empty()) return "No native libraries";
    return abi::join(n.dirs) + "  |  " + abi::widthLabel(n.has32(), n.has64()) + " native code";
}

// The device line: what the selected device runs and whether this APK's libraries fit.
inline void drawDeviceCompat(const abi::ApkNative& n, const Workspace::DeviceAbiState& device) {
    if (device.label.empty()) {
        ImGui::PushTextWrapPos(0.f);
        ImGui::TextDisabled("No device selected: connect one in the Devices panel to check compatibility");
        ImGui::PopTextWrapPos();
        return;
    }
    if (!device.abis.known()) {
        ImGui::TextDisabled("%s: reading ABIs...", device.label.c_str());
        return;
    }
    const abi::Compatibility c = abi::check(n, device.abis);
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextColored(compatColor(c.kind), "%s", c.summary.c_str());
    ImGui::PopTextWrapPos();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextDisabled("%s runs %s", device.label.c_str(), abi::join(device.abis.list).c_str());
    ImGui::PopTextWrapPos();
}

// ABI table + libraries whose header disagrees with their directory + the device line. For the Overview panel.
inline void drawNativeSummary(const abi::ApkNative& n, const Workspace::DeviceAbiState& device) {
    if (n.empty()) {
        ImGui::TextDisabled("This APK ships no native libraries (lib/<abi>/*.so); it runs on any ABI");
        return;
    }
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(shipsLine(n).c_str());
    ImGui::PopTextWrapPos();
    if (ImGui::BeginTable("##abis", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("ABI", ImGuiTableColumnFlags_WidthStretch, 2.f);
        ImGui::TableSetupColumn("Architecture", ImGuiTableColumnFlags_WidthStretch, 3.f);
        ImGui::TableSetupColumn("Libs", ImGuiTableColumnFlags_WidthFixed, ui::em(2.5f));
        ImGui::TableHeadersRow();
        for (const std::string& d : n.dirs) {
            const abi::Info info = abi::fromName(d);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(d.c_str());
            ImGui::TableNextColumn();
            if (info.id == abi::Id::Unknown) ImGui::TextDisabled("unrecognised directory");
            else ImGui::TextDisabled("%s%s", info.arch, info.legacy ? "  (legacy)" : "");
            if (ImGui::IsItemHovered() && info.id != abi::Id::Unknown) ImGui::SetTooltip("%s%s", info.arch, info.legacy ? "  (legacy)" : "");
            ImGui::TableNextColumn();
            ImGui::Text("%zu", n.countIn(d));
        }
        ImGui::EndTable();
    }
    for (const abi::NativeLib& l : n.libs)
        if (l.mismatch()) {
            ImGui::PushTextWrapPos(0.f);
            ImGui::TextColored(theme::vec(Col::Warning), "%s is %s, not %s", l.path.c_str(), l.elf.arch, l.dir.arch);
            ImGui::PopTextWrapPos();
        }
    drawDeviceCompat(n, device);
}

}  // namespace abiui
