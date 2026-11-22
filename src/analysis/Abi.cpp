#include "analysis/Abi.hpp"
#include <algorithm>

namespace abi {
namespace {

constexpr Info kArm64{Id::Arm64, "arm64-v8a", "AArch64", 64, true, false, true};
constexpr Info kArm32{Id::Arm32, "armeabi-v7a", "ARM (32-bit)", 32, true, false, true};
constexpr Info kX86_64{Id::X86_64, "x86_64", "x86-64", 64, true, false, true};
constexpr Info kX86{Id::X86, "x86", "x86 (IA-32)", 32, true, false, true};
constexpr Info kArmLegacy{Id::ArmLegacy, "armeabi", "ARM (32-bit, ARMv5/v6)", 32, false, true, true};
constexpr Info kMips{Id::Mips, "mips", "MIPS (32-bit)", 32, false, true, false};
constexpr Info kMips64{Id::Mips64, "mips64", "MIPS64", 64, false, true, false};
constexpr Info kRiscv64{Id::Riscv64, "riscv64", "RISC-V (64-bit)", 64, false, false, false};

uint32_t u32(const uint8_t* d, bool le) {
    return le ? static_cast<uint32_t>(d[0]) | static_cast<uint32_t>(d[1]) << 8 | static_cast<uint32_t>(d[2]) << 16 | static_cast<uint32_t>(d[3]) << 24
              : static_cast<uint32_t>(d[3]) | static_cast<uint32_t>(d[2]) << 8 | static_cast<uint32_t>(d[1]) << 16 | static_cast<uint32_t>(d[0]) << 24;
}
uint16_t u16(const uint8_t* d, bool le) {
    return le ? static_cast<uint16_t>(d[0] | d[1] << 8) : static_cast<uint16_t>(d[1] | d[0] << 8);
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (!cur.empty()) out.push_back(std::move(cur)), cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

void addUnique(std::vector<std::string>& v, const std::string& s) {
    if (!s.empty() && std::find(v.begin(), v.end(), s) == v.end()) v.push_back(s);
}

bool sameFamily(Id a, Id b) {
    const auto arm32 = [](Id i) { return i == Id::Arm32 || i == Id::ArmLegacy; };
    return a == b || (arm32(a) && arm32(b));
}

}  // namespace

Info fromName(std::string_view name) {
    for (const Info* i : {&kArm64, &kArm32, &kX86_64, &kX86, &kArmLegacy, &kMips, &kMips64, &kRiscv64})
        if (name == i->name) return *i;
    return {};
}

ElfIdent peekElf(const uint8_t* d, size_t size) {
    ElfIdent e;
    if (!d || size < 20 || d[0] != 0x7f || d[1] != 'E' || d[2] != 'L' || d[3] != 'F') return e;
    if ((d[4] != 1 && d[4] != 2) || (d[5] != 1 && d[5] != 2)) return e;
    e.is64 = d[4] == 2;
    e.littleEndian = d[5] == 1;
    if (size < (e.is64 ? 64u : 52u)) return e;
    e.type = u16(d + 16, e.littleEndian);
    e.machine = u16(d + 18, e.littleEndian);
    e.flags = u32(d + (e.is64 ? 48 : 36), e.littleEndian);
    e.valid = true;
    return e;
}

Info fromElf(const ElfIdent& e) {
    if (!e.valid) return {};
    switch (e.machine) {
    case 183: return e.is64 && e.littleEndian ? kArm64 : Info{};
    case 40: return !e.is64 && e.littleEndian ? kArm32 : Info{};
    case 62: return e.is64 && e.littleEndian ? kX86_64 : Info{};
    case 3: return !e.is64 && e.littleEndian ? kX86 : Info{};
    case 8: return e.is64 ? kMips64 : kMips;
    case 243: return e.is64 ? kRiscv64 : Info{};
    default: return {};
    }
}

std::string machineName(uint16_t machine) {
    switch (machine) {
    case 3: return "x86";
    case 8: return "MIPS";
    case 20: return "PowerPC";
    case 21: return "PowerPC64";
    case 40: return "ARM";
    case 62: return "x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    default: return "machine " + std::to_string(machine);
    }
}

bool NativeLib::mismatch() const {
    if (!validElf) return false;
    if (dir.id == Id::Unknown) return false;  // a directory name nobody uses: nothing to contradict
    return !sameFamily(dir.id, elf.id);
}

bool ApkNative::hasDir(std::string_view name) const {
    return std::find(dirs.begin(), dirs.end(), name) != dirs.end();
}
bool ApkNative::has32() const {
    return std::any_of(libs.begin(), libs.end(), [](const NativeLib& l) { return l.effective().bits == 32; });
}
bool ApkNative::has64() const {
    return std::any_of(libs.begin(), libs.end(), [](const NativeLib& l) { return l.effective().bits == 64; });
}
size_t ApkNative::countIn(std::string_view dirName) const {
    return static_cast<size_t>(std::count_if(libs.begin(), libs.end(), [&](const NativeLib& l) { return l.dirName == dirName; }));
}

ApkNative inventory(const std::vector<LibEntry>& entries) {
    ApkNative out;
    for (const LibEntry& e : entries) {
        if (e.path.rfind("lib/", 0) != 0) continue;
        const size_t slash = e.path.find('/', 4);
        if (slash == std::string::npos || e.path.find('/', slash + 1) != std::string::npos) continue;
        const std::string file = e.path.substr(slash + 1);
        if (file.size() < 4 || file.compare(file.size() - 3, 3, ".so") != 0) continue;
        NativeLib l;
        l.path = e.path;
        l.dirName = e.path.substr(4, slash - 4);
        l.dir = fromName(l.dirName);
        l.ident = e.ident;
        l.validElf = e.ident.valid;
        l.elf = fromElf(e.ident);
        l.size = e.size;
        addUnique(out.dirs, l.dirName);
        out.libs.push_back(std::move(l));
    }
    return out;
}

bool DeviceAbis::supports(std::string_view name) const {
    return std::find(list.begin(), list.end(), name) != list.end();
}

DeviceAbis deviceAbis(const std::string& abiProp, const std::string& abi2Prop, const std::string& abilist,
                      const std::string& abilist32, const std::string& abilist64) {
    DeviceAbis d;
    d.primary = split(abiProp).empty() ? std::string() : split(abiProp).front();
    d.secondary = split(abi2Prop).empty() ? std::string() : split(abi2Prop).front();
    d.list = split(abilist);
    d.list32 = split(abilist32);
    d.list64 = split(abilist64);
    if (d.list.empty()) {  // very old devices have no abilist
        addUnique(d.list, d.primary);
        addUnique(d.list, d.secondary);
    }
    if (d.list32.empty() && d.list64.empty())
        for (const std::string& a : d.list) {
            const Info i = fromName(a);
            if (i.bits == 32) d.list32.push_back(a);
            else if (i.bits == 64) d.list64.push_back(a);
        }
    // The lists the device reports may leave out an ABI its other lists contain.
    for (const std::string& a : d.list32) addUnique(d.list, a);
    for (const std::string& a : d.list64) addUnique(d.list, a);
    return d;
}

namespace {
const char* codeWidth(bool has32, bool has64) {
    if (has32 && has64) return "32-bit and 64-bit";
    if (has64) return "64-bit only";
    if (has32) return "32-bit only";
    return "none";
}
}  // namespace

std::string join(const std::vector<std::string>& names, const char* sep) {
    std::string s;
    for (const std::string& n : names) {
        if (!s.empty()) s += sep;
        s += n;
    }
    return s;
}

std::string widthLabel(bool has32, bool has64) {
    if (has32 && has64) return "64-bit and 32-bit";
    if (has64) return "64-bit";
    if (has32) return "32-bit";
    return "none";
}

Compatibility check(const ApkNative& apk, const DeviceAbis& device) {
    Compatibility c;
    c.present = apk.dirs;
    c.codeWidth = codeWidth(apk.has32(), apk.has64());
    if (apk.empty()) {
        c.kind = Compatibility::Kind::NoNativeCode;
        c.summary = "No native libraries: runs on any ABI";
        return c;
    }
    if (!device.known()) {
        c.kind = Compatibility::Kind::Unknown;
        c.summary = "Device ABIs unknown";
        return c;
    }
    for (const std::string& d : apk.dirs) (device.supports(d) ? c.compatible : c.incompatible).push_back(d);
    for (const std::string& a : device.list)
        if (apk.hasDir(a)) {
            c.chosen = a;
            break;
        }
    if (!c.chosen.empty()) {
        c.kind = Compatibility::Kind::Compatible;
        c.summary = "Compatible: the device loads " + c.chosen;
        if (!c.incompatible.empty()) c.summary += "; " + join(c.incompatible) + " not usable here";
    } else {
        c.kind = Compatibility::Kind::Incompatible;
        c.summary = "Incompatible: the APK ships " + join(apk.dirs) + ", the device runs " + join(device.list);
    }
    return c;
}

}  // namespace abi
