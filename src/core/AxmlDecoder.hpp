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
class AxmlDecoder {
public:
    // Returns false (with a reason in 'error') if 'bytes' is not valid AXML.
    // On success 'out' receives the XML text.
    static bool decode(const std::vector<uint8_t>& bytes, std::string& out, std::string& error);

    // True if the buffer starts with the AXML magic (RES_XML_TYPE, LE).
    static bool looksLikeAxml(const std::vector<uint8_t>& bytes);
};
