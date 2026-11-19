#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

// .proto schemas for the protobuf / gRPC content views: messages decoded with
// their real field names, nested types, enum names, packed repeated fields
// and maps, instead of bare field numbers.
//
// The parser reads proto2 / proto3 source: package, message (nested), enum,
// oneof, map<K, V>, repeated / optional / required, and skips options,
// imports, services, extensions and reserved ranges. Types are resolved like
// protoc does: from the innermost scope outwards.
namespace protoschema {

struct Field {
    std::string name;
    int number = 0;
    std::string type;      // "int32", "string", ... or a message / enum name as written
    bool repeated = false;
    bool isMap = false;    // map<K, V>: an entry message with key = 1, value = 2
    std::string keyType, valueType;
    std::string scope;     // full name of the message that declares it (for resolution)
};

struct Message {
    std::string fullName;  // "pkg.Outer.Inner"
    std::map<int, Field> fields;
};

struct Enum {
    std::string fullName;
    std::map<int, std::string> values;
};

class Schema {
public:
    // Parses one .proto source; errors name the file and line. Several files
    // can be added to one schema.
    bool addSource(const std::string& text, const std::string& fileName, std::string& error);
    // Every .proto file under a directory (recursively). Returns how many parsed.
    size_t addDirectory(const std::string& dir, std::vector<std::string>& errors);

    std::vector<std::string> messageNames() const;  // sorted full names
    const Message* message(const std::string& fullName) const;
    // Decodes `bytes` as message `fullName` into indented text; false when the
    // bytes are not protobuf. Unknown fields keep their numbers.
    bool decode(const std::string& bytes, const std::string& fullName, std::string& out) const;
    bool empty() const { return messages_.empty(); }

private:
    const Message* resolveMessage(const std::string& type, const std::string& scope) const;
    const Enum* resolveEnum(const std::string& type, const std::string& scope) const;
    bool decodeInto(const std::string& bytes, const Message& m, int depth, std::string& out) const;
    std::map<std::string, Message> messages_;
    std::map<std::string, Enum> enums_;
};

}  // namespace protoschema
