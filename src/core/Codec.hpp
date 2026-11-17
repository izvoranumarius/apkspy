#pragma once
#include <string>
#include <string_view>
#include <vector>

// Byte transforms for the Decoder panel (as in CyberChef or Burp's Decoder):
// Base64 / Base32 / hex / URL / HTML / string escapes, XOR, ROT13, zlib and
// gzip, hashes, JWT and text encodings. Every value is a byte string held in
// std::string; text is UTF-8 unless an operation says otherwise.
namespace codec {

enum class Op {
    Base64Decode, Base64Encode, Base64UrlEncode,
    Base32Decode, Base32Encode,
    HexDecode, HexEncode,
    UrlDecode, UrlEncode,
    HtmlDecode, HtmlEncode,
    Unescape, Escape,          // \n \t \xNN \uXXXX (Java, JavaScript, C)
    DecodeText, EncodeText,    // bytes in a charset -> UTF-8, and back (arg: charset)
    Xor, Rot13, Reverse,
    Inflate, ZlibCompress, GzipCompress,
    Md5, Sha1, Sha256,
    JwtDecode,
};

// How an operation's argument is entered.
enum class Arg { None, Text, Charset };

struct OpInfo {
    Op op;
    const char* name;   // "Base64 decode"
    const char* group;  // "Encoding", "Text", "Crypto", "Compression", "Hash", "Other"
    Arg arg;
    const char* hint;   // what the argument is
};
const std::vector<OpInfo>& ops();
const OpInfo& info(Op op);

// Text encodings understood by DecodeText / EncodeText.
const std::vector<const char*>& charsets();  // "UTF-8", "UTF-16LE", ...

struct Result {
    bool ok = true;
    std::string out;
    std::string error;
};
Result apply(Op op, std::string_view in, std::string_view arg = {});

// Building blocks (also used by tests).
std::string base64Encode(std::string_view in, bool url = false);
bool base64Decode(std::string_view in, std::string& out);  // either alphabet, padding optional, whitespace ignored
std::string base32Encode(std::string_view in);
bool base32Decode(std::string_view in, std::string& out);
std::string hexEncode(std::string_view in);
bool hexDecode(std::string_view in, std::string& out);  // spaces, 0x, \x and : allowed
bool decodeText(std::string_view bytes, std::string_view charset, std::string& utf8, std::string& error);
bool encodeText(std::string_view utf8, std::string_view charset, std::string& bytes, std::string& error);
std::string md5Hex(std::string_view in);
std::string sha1Hex(std::string_view in);

// True for valid UTF-8 without control characters (tab and line breaks are fine).
bool isReadableText(std::string_view s);
// What the input most likely is, best first: the operations that decode it.
std::vector<Op> guess(std::string_view in);
// Decodes layer after layer (Base64 inside URL encoding inside hex...) while each
// step gives readable text or a compressed stream; the operations it used.
std::vector<Op> smartDecode(std::string_view in, int maxSteps = 8);
// What an encoded-looking string decodes to (smart decode giving readable text,
// more than escapes alone); false for plain strings. `steps` names the chain.
bool decodePreview(std::string_view s, std::string& decoded, std::string& steps);

// A "..." literal in a line of code: [begin, end) covers the quotes, `text` is
// the content with escapes resolved.
struct Literal {
    size_t begin = 0, end = 0;
    std::string text;
};
std::vector<Literal> stringLiterals(std::string_view line);
// The literal containing byte `col`, or nullptr.
const Literal* literalAt(const std::vector<Literal>& lits, size_t col);

// "00000000  48 65 6c 6c 6f  Hello" lines, at most `maxBytes`.
std::string hexDump(std::string_view in, size_t maxBytes = 64 * 1024);

}  // namespace codec
