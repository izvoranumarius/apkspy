#pragma once
#include <cstdint>
#include <string>
#include <vector>

class DexFile;

// Reads Kotlin's @Metadata annotation (kotlin.Metadata) on a class and turns
// it into a small model for display: the metadata kind (class / file facade /
// synthetic / multi-file), the metadata version, the d2 string pool, and -
// for classes - the declaration kind and modifiers from the d1 protobuf
// (interface, object, companion object, enum, annotation; data, sealed,
// value, inner).
//
// Only the class-level Class.flags field of d1 is decoded, not the whole
// protobuf (function and property signatures would need the full schema).
// d1 is read in the encoding current kotlinc writes (a '\0' marker, then one
// byte per character); the older 8-to-7-bit encoding is detected and leaves
// the class flags unknown rather than guessed.
namespace kotlinmeta {

// The annotation's k element.
enum class Kind { Unknown = 0, Class = 1, File = 2, SyntheticClass = 3, MultiFileClass = 4, MultiFilePart = 5 };

// Class.flags: CLASS_KIND (bits 6-8).
enum class ClassKind { Class, Interface, EnumClass, EnumEntry, AnnotationClass, Object, CompanionObject };

struct Metadata {
    bool present = false;
    Kind kind = Kind::Unknown;
    int versionMajor = 0, versionMinor = 0, versionPatch = 0;
    std::vector<std::string> names;  // d2 string pool
    // From d1 (kind == Class only); flagsKnown is false when d1 could not be read.
    bool flagsKnown = false;
    uint32_t classFlags = 0;
    ClassKind classKind = ClassKind::Class;
    bool isData = false;
    bool isSealed = false;
    bool isInner = false;
    bool isValue = false;  // value / inline class
    bool isCompanion() const { return classKind == ClassKind::CompanionObject; }
    // Declaration kind for the UI ("data class", "companion object", ...).
    std::string displayKind() const;
};

// Parses the @Metadata annotation of the class with `classDescriptor`
// ("Lcom/a/B;"). False when the class has none or it cannot be read (never
// throws; reads are bounded by the DEX size).
bool read(const DexFile& dex, const std::string& classDescriptor, Metadata& out);

// True when the class has an annotations directory (cheap pre-check; the
// annotation itself may still be something other than @Metadata).
bool has(const DexFile& dex, const std::string& classDescriptor);

// Class.flags from a d1 string array (exposed for tests). False when d1 is not
// in the readable encoding or the protobuf is malformed.
bool classFlagsFromD1(const std::vector<std::string>& d1, uint32_t& flags);

}  // namespace kotlinmeta
