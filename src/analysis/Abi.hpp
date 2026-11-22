#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Android ABIs: what a library directory name (lib/<abi>/) or an ELF header says a binary is, what a device
// runs (the ro.product.cpu.* properties) and whether the two fit. Pure data and rules, no I/O.
namespace abi {

enum class Id : uint8_t { Arm64, Arm32, X86_64, X86, ArmLegacy, Mips, Mips64, Riscv64, Unknown };

struct Info {
    Id id = Id::Unknown;
    const char* name = "";    // NDK directory name: "arm64-v8a"
    const char* arch = "";    // "AArch64", "ARM (32-bit)", "x86-64", "x86 (IA-32)"
    int bits = 0;             // 32 or 64, 0 when unknown
    bool ndkTarget = false;   // one of the four ABIs the NDK still builds for
    bool legacy = false;      // armeabi, mips, mips64: older than the NDK targets, still seen in old APKs
    bool disassemblable = false;  // ApkSpy has a disassembler for it
};

// "arm64-v8a" -> Info; an unknown name yields Id::Unknown with the name kept out (Info::name empty).
Info fromName(std::string_view name);
// The ELF header facts that identify an architecture.
struct ElfIdent {
    bool valid = false;
    bool is64 = false;
    bool littleEndian = true;
    uint16_t machine = 0;
    uint16_t type = 0;
    uint32_t flags = 0;
};
// Reads e_ident / e_machine of up to the first 64 bytes. valid = false (no throw) for anything that is not an ELF.
ElfIdent peekElf(const uint8_t* data, size_t size);
Info fromElf(const ElfIdent& e);
// "AArch64", "ARM", "x86", "x86-64", "MIPS", ... for any machine number; "machine N" when unknown.
std::string machineName(uint16_t machine);

// ---------------------------------------------------------------------------------------------------- APK side

struct NativeLib {
    std::string path;      // "lib/arm64-v8a/libfoo.so"
    std::string dirName;   // the ABI directory ("arm64-v8a"), as written
    Info dir;              // what the directory says
    Info elf;              // what the ELF header says (Unknown when the entry is not a readable ELF)
    ElfIdent ident;        // the header facts behind `elf`
    uint64_t size = 0;
    bool validElf = false;
    // The directory and the header disagree (an x86 library in lib/arm64-v8a, ...). ARM32 in armeabi / armeabi-v7a
    // is not a mismatch: both are 32-bit ARM.
    bool mismatch() const;
    // The architecture to analyse: the header when it is readable, else the directory.
    Info effective() const { return validElf ? elf : dir; }
};

struct ApkNative {
    std::vector<NativeLib> libs;
    std::vector<std::string> dirs;  // distinct ABI directories in first-seen order, as written
    bool empty() const { return libs.empty(); }
    bool hasDir(std::string_view name) const;
    bool has32() const;  // a library whose effective architecture is 32-bit
    bool has64() const;
    size_t countIn(std::string_view dirName) const;
};

// Splits "lib/<dir>/<file>.so" entries; non-library entries and nested paths are ignored. `identOf(path)` returns the
// ELF header of an entry (valid = false when it could not be read); `sizeOf(path)` its size.
struct LibEntry {
    std::string path;
    uint64_t size = 0;
    ElfIdent ident;
};
ApkNative inventory(const std::vector<LibEntry>& entries);

// ---------------------------------------------------------------------------------------------------- device side

struct DeviceAbis {
    std::string primary;                  // ro.product.cpu.abi
    std::string secondary;                // ro.product.cpu.abi2
    std::vector<std::string> list;        // ro.product.cpu.abilist, in preference order
    std::vector<std::string> list32;      // ro.product.cpu.abilist32
    std::vector<std::string> list64;      // ro.product.cpu.abilist64
    bool known() const { return !list.empty(); }
    bool supports32() const { return !list32.empty(); }
    bool supports64() const { return !list64.empty(); }
    bool supports(std::string_view name) const;
};
// From the property values (any may be empty). A missing abilist falls back to the primary and secondary ABI; missing
// 32 / 64-bit lists are derived from the list by each ABI's bitness.
DeviceAbis deviceAbis(const std::string& abiProp, const std::string& abi2Prop, const std::string& abilist,
                      const std::string& abilist32, const std::string& abilist64);

// ---------------------------------------------------------------------------------------------------- matching

struct Compatibility {
    enum class Kind : uint8_t { NoNativeCode, Compatible, Incompatible, Unknown };
    Kind kind = Kind::Unknown;
    std::string chosen;                       // the ABI Android loads the app's libraries from
    std::vector<std::string> present;         // ABI directories in the APK
    std::vector<std::string> compatible;      // present ABIs the device can run
    std::vector<std::string> incompatible;    // present ABIs it cannot
    std::string codeWidth;                    // "none", "32-bit only", "64-bit only", "32-bit and 64-bit"
    std::string summary;                      // one line for the UI
};
// Android's rule: the app uses the libraries of the first ABI in the device's list that the APK ships (the primary
// ABI first), never a mix. An APK without native libraries runs anywhere; `device` unknown gives Kind::Unknown but
// still fills the APK side.
Compatibility check(const ApkNative& apk, const DeviceAbis& device);

// "arm64-v8a, armeabi-v7a" style joins, shared by the UI and MCP.
std::string join(const std::vector<std::string>& names, const char* sep = ", ");
// "64-bit" / "32-bit" / "64-bit and 32-bit" / "none".
std::string widthLabel(bool has32, bool has64);

}  // namespace abi
