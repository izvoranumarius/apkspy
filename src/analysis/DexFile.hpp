#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Read-only view over one DEX file (classes.dex, classes2.dex, ...).
//
// Memory model: the DexFile shares ownership of the raw bytes and decodes
// lazily. Strings, types and signatures are resolved on demand straight from
// the mapped data (no per-string std::string is ever stored), so a DexFile
// costs little more than the file itself plus one small record per class.
//
// Robustness: every offset and index read from the file is bounds-checked;
// malformed or truncated input yields empty strings / "invalid" results
// instead of reading out of bounds. Lookups by name rely on the sort order
// the DEX format guarantees (strings by content, types by string, methods by
// class/name/proto) and degrade to "not found" when a crafted file breaks it.
class DexFile {
public:
    static constexpr uint32_t kNoIndex = 0xFFFFFFFFu;

    struct ClassDef {
        uint32_t classIdx = kNoIndex;       // type index of the class
        uint32_t accessFlags = 0;
        uint32_t superclassIdx = kNoIndex;  // type index or kNoIndex
        uint32_t interfacesOff = 0;
        uint32_t sourceFileIdx = kNoIndex;  // string index or kNoIndex
        uint32_t classDataOff = 0;
    };

    struct EncodedMethod {
        uint32_t methodIdx = 0;
        uint32_t accessFlags = 0;
        uint32_t codeOff = 0;  // 0 for abstract/native methods
        bool direct = false;
    };

    struct EncodedField {
        uint32_t fieldIdx = 0;
        uint32_t accessFlags = 0;
        bool isStatic = false;
    };

    struct ClassData {
        std::vector<EncodedField> fields;
        std::vector<EncodedMethod> methods;
    };

    struct CodeItem {
        uint16_t registers = 0;
        uint16_t ins = 0;
        uint16_t outs = 0;
        uint16_t tries = 0;
        uint32_t debugInfoOff = 0;
        const uint8_t* insns = nullptr;  // points into the DEX data (little endian units)
        uint32_t insnsSize = 0;          // in 16-bit code units
        uint32_t offset = 0;             // file offset of the code_item
        // Code unit i (bounds are the caller's job: i < insnsSize). Read
        // byte-wise: a crafted file may misalign the code item.
        uint16_t unit(uint32_t i) const { return static_cast<uint16_t>(insns[2 * i] | (insns[2 * i + 1] << 8)); }
    };

    // Parses the header and id tables. `name` is the entry name (classes.dex).
    // Returns nullptr (and sets `error`) for anything that is not a usable DEX.
    static std::shared_ptr<DexFile> parse(std::shared_ptr<const std::vector<uint8_t>> bytes, std::string name,
                                          std::string& error);

    const std::string& name() const { return name_; }
    uint32_t version() const { return version_; }  // 35, 37, 38, 39, 40, ...
    size_t sizeBytes() const { return data_->size(); }
    const uint8_t* data() const { return data_->data(); }

    uint32_t stringCount() const { return stringIdsSize_; }
    uint32_t typeCount() const { return typeIdsSize_; }
    uint32_t protoCount() const { return protoIdsSize_; }
    uint32_t fieldCount() const { return fieldIdsSize_; }
    uint32_t methodCount() const { return methodIdsSize_; }
    const std::vector<ClassDef>& classes() const { return classDefs_; }

    // Raw MUTF-8 bytes of a string (valid while the DexFile lives). Empty for
    // a bad index. Good enough for ASCII identifiers and comparisons.
    std::string_view stringView(uint32_t idx) const;
    // The string converted to standard UTF-8 (MUTF-8 NUL and surrogate pairs
    // re-encoded).
    std::string string(uint32_t idx) const;
    // Type descriptor ("Lcom/foo/Bar;", "I", "[B").
    std::string_view typeDescriptor(uint32_t typeIdx) const;

    // Field / method components.
    uint32_t fieldClass(uint32_t fieldIdx) const;
    uint32_t fieldType(uint32_t fieldIdx) const;
    std::string_view fieldName(uint32_t fieldIdx) const;
    uint32_t methodClass(uint32_t methodIdx) const;
    uint32_t methodProto(uint32_t methodIdx) const;
    std::string_view methodName(uint32_t methodIdx) const;
    // "(ILjava/lang/String;)V"
    std::string protoDescriptor(uint32_t protoIdx) const;
    std::vector<uint32_t> protoParameters(uint32_t protoIdx) const;
    uint32_t protoReturnType(uint32_t protoIdx) const;

    // Smali-style references: "Lcom/foo/Bar;->baz(I)V", "Lcom/foo/Bar;->f:I".
    std::string methodSignature(uint32_t methodIdx) const;
    std::string fieldSignature(uint32_t fieldIdx) const;

    // Interfaces implemented by a class (type indices).
    std::vector<uint32_t> interfaces(const ClassDef& def) const;
    // Decodes class_data_item (fields + methods). Empty for marker classes.
    bool classData(const ClassDef& def, ClassData& out) const;
    bool codeItem(uint32_t codeOff, CodeItem& out) const;

    // Name-based lookups (binary searches over the sorted id tables).
    uint32_t findString(std::string_view s) const;
    uint32_t findType(std::string_view descriptor) const;
    // Index of the class_def defining `descriptor`, or kNoIndex.
    uint32_t findClassDef(std::string_view descriptor) const;
    // Method ids of a given class + name (all overloads); proto filter when
    // `protoDesc` is non-empty ("(I)V").
    std::vector<uint32_t> findMethods(std::string_view classDescriptor, std::string_view name,
                                      std::string_view protoDesc = {}) const;
    std::vector<uint32_t> findFields(std::string_view classDescriptor, std::string_view name) const;

    // Source line of a pc (code-unit offset) via debug_info_item; -1 when
    // the method has no line information.
    int lineForPc(const CodeItem& code, uint32_t pc) const;

    // Java-ish rendering helpers.
    static std::string descriptorToJava(std::string_view descriptor);  // "Lcom/a/B;" -> "com.a.B"
    static std::string javaToDescriptor(std::string_view javaName);    // "com.a.B" -> "Lcom/a/B;"
    static std::string accessFlagsToString(uint32_t flags, bool forMethod);

private:
    DexFile() = default;
    bool readU32(size_t off, uint32_t& v) const;
    bool readU16(size_t off, uint16_t& v) const;
    bool inBounds(size_t off, size_t len) const { return off <= data_->size() && len <= data_->size() - off; }

    std::shared_ptr<const std::vector<uint8_t>> data_;
    std::string name_;
    uint32_t version_ = 0;
    uint32_t stringIdsSize_ = 0, stringIdsOff_ = 0;
    uint32_t typeIdsSize_ = 0, typeIdsOff_ = 0;
    uint32_t protoIdsSize_ = 0, protoIdsOff_ = 0;
    uint32_t fieldIdsSize_ = 0, fieldIdsOff_ = 0;
    uint32_t methodIdsSize_ = 0, methodIdsOff_ = 0;
    std::vector<ClassDef> classDefs_;
};

// LEB128 helpers shared by the DEX code (bounds-checked; false on overflow
// or truncation).
namespace leb {
bool readUleb(const uint8_t* data, size_t size, size_t& pos, uint32_t& out);
bool readSleb(const uint8_t* data, size_t size, size_t& pos, int32_t& out);
}  // namespace leb
