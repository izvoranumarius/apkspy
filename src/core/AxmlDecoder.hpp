#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Decodes Android binary XML (AXML - the compiled format found inside APKs,
// e.g. AndroidManifest.xml and res/**/*.xml) into readable, indented XML
// text so it can be shown and highlighted like any other source file.
//
// The format is a sequence of chunks (ResChunk_header: u16 type, u16
// headerSize, u32 size) wrapped in a RES_XML_TYPE (0x0003) chunk:
//   0x0001 string pool        - all strings referenced below
//   0x0180 resource map       - attribute order -> resource id (unused here)
//   0x0100/0x0101 namespaces  - xmlns declarations
//   0x0102/0x0103 elements    - start/end tags with typed attributes
//   0x0104 CDATA              - text content
class ResourceTable;

class AxmlDecoder {
public:
    // Returns false (with a reason in 'error') if 'bytes' is not valid AXML.
    // On success 'out' receives the XML text.
    // `resources` (optional) resolves app references: "@ref/0x7F0E0023"
    // becomes "@string/app_name".
    static bool decode(const std::vector<uint8_t>& bytes, std::string& out, std::string& error,
                       const ResourceTable* resources = nullptr);

    // True if the buffer starts with the AXML magic (RES_XML_TYPE, LE).
    static bool looksLikeAxml(const std::vector<uint8_t>& bytes);

    // --- Event-based access (additive, M4) ---------------------------------
    // One attribute of a start element. `name` already carries the resolved
    // namespace prefix ("android:name"); xmlns declarations are reported as
    // attributes named "xmlns:prefix". Values are the formatted strings the
    // text decoder would print (typed values already resolved), unescaped.
    struct Attr {
        std::string name;
        std::string value;
    };

    // Consumer of the decoded element tree. All callbacks run inline on the
    // calling thread; default implementations make partial overrides easy.
    struct Visitor {
        virtual ~Visitor() = default;
        virtual void startElement(const std::string& name, const std::vector<Attr>& attrs) {
            (void)name;
            (void)attrs;
        }
        virtual void endElement(const std::string& name) { (void)name; }
        virtual void text(const std::string& text) { (void)text; }
    };

    // Walks the AXML chunk stream and feeds `visitor`. Same validation and
    // error strings as decode(); decode() itself is implemented on top of
    // this walk, so the two can never disagree about the format.
    static bool decodeEvents(const std::vector<uint8_t>& bytes, Visitor& visitor, std::string& error,
                             const ResourceTable* resources = nullptr);
};
