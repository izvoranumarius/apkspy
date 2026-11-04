#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Read-only ELF parser for native libraries shipped in APKs (lib/<abi>/*.so).
// 32- and 64-bit, little and big endian. Every table is bounds-checked; a
// malformed file yields whatever could be parsed plus a list of warnings.
class ElfFile {
public:
    struct Section {
        std::string name;
        uint32_t type = 0;
        uint64_t flags = 0;
        uint64_t addr = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
        uint32_t link = 0;
        uint64_t entsize = 0;
    };
    struct Segment {
        uint32_t type = 0;
        uint32_t flags = 0;  // PF_R=4, PF_W=2, PF_X=1
        uint64_t offset = 0;
        uint64_t vaddr = 0;
        uint64_t filesz = 0;
        uint64_t memsz = 0;
    };
    struct Symbol {
        std::string name;
        uint64_t value = 0;
        uint64_t size = 0;
        uint8_t type = 0;     // STT_*
        uint8_t binding = 0;  // STB_*
        uint16_t shndx = 0;   // 0 = undefined (import)
        bool dynamic = false;
    };
    // Relocations that name a symbol (imports through the GOT / PLT). RELATIVE
    // relocations carry no name and are skipped to keep large libraries cheap.
    struct Relocation {
        uint64_t offset = 0;  // patched address (the GOT slot for JUMP_SLOT / GLOB_DAT)
        uint32_t type = 0;
        int64_t addend = 0;
        std::string symbol;
    };

    static std::shared_ptr<ElfFile> parse(std::shared_ptr<const std::vector<uint8_t>> bytes, std::string name,
                                          std::string& error);

    const std::string& name() const { return name_; }
    bool is64() const { return is64_; }
    bool littleEndian() const { return little_; }
    uint16_t machine() const { return machine_; }
    uint16_t elfType() const { return type_; }
    uint64_t entry() const { return entry_; }
    std::string machineName() const;
    std::string typeName() const;

    const std::vector<Section>& sections() const { return sections_; }
    const std::vector<Segment>& segments() const { return segments_; }
    const std::vector<Symbol>& symbols() const { return symbols_; }
    const std::vector<Relocation>& relocations() const { return relocations_; }
    const std::vector<std::string>& needed() const { return needed_; }
    const std::string& soname() const { return soname_; }
    const std::vector<std::string>& warnings() const { return warnings_; }

    // Exported functions/objects (defined, global/weak) and imports.
    std::vector<const Symbol*> exports() const;
    std::vector<const Symbol*> imports() const;
    // JNI entry points: Java_* exports plus JNI_OnLoad / JNI_OnUnload.
    std::vector<const Symbol*> jniSymbols() const;

    // Maps a virtual address to a file offset through the PT_LOAD segments.
    bool vaddrToOffset(uint64_t vaddr, uint64_t& offset) const;
    // Raw bytes [offset, offset+len) clipped to the file.
    std::vector<uint8_t> bytesAt(uint64_t offset, size_t len) const;
    const std::vector<uint8_t>& data() const { return *data_; }

    // Printable ASCII runs (>= minLen) inside read-only data sections
    // (.rodata, .data.rel.ro, ...); falls back to the whole file when the
    // section table is missing.
    struct StringHit {
        uint64_t offset;
        std::string value;
    };
    std::vector<StringHit> strings(size_t minLen, size_t limit) const;

    // Demangles the most common Itanium C++ names well enough for display
    // ("_ZN3foo3barEv" -> "foo::bar()"). Returns the input when unknown.
    static std::string demangle(const std::string& name);

private:
    ElfFile() = default;
    uint16_t u16(uint64_t off) const;
    uint32_t u32(uint64_t off) const;
    uint64_t u64(uint64_t off) const;
    uint64_t word(uint64_t off) const { return is64_ ? u64(off) : u32(off); }
    bool inBounds(uint64_t off, uint64_t len) const {
        return off <= data_->size() && len <= data_->size() - off;
    }
    std::string cstr(uint64_t off, uint64_t limitEnd) const;
    void readSymbols(const Section& symtab, bool dynamic);
    void readDynamic();
    void readRelocations(const Section& rel);

    std::shared_ptr<const std::vector<uint8_t>> data_;
    std::string name_;
    bool is64_ = false;
    bool little_ = true;
    uint16_t type_ = 0;
    uint16_t machine_ = 0;
    uint64_t entry_ = 0;
    std::vector<Section> sections_;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
    std::vector<Relocation> relocations_;
    std::vector<std::string> needed_;
    std::string soname_;
    std::vector<std::string> warnings_;
};
