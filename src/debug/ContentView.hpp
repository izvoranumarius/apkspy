#pragma once
#include <string>
#include <vector>

namespace protoschema {
class Schema;
}

// Content views for captured bodies (as in mitmproxy): the same bytes shown
// as pretty JSON, indented XML / HTML, URL-encoded or multipart form fields,
// schema-less protobuf, gRPC messages, MessagePack, image facts or a hex dump.
//
// Every view works on the decoded body (chunked framing and gzip / deflate
// already undone, see TrafficProxy::decodeBody) and returns display text; a
// view that cannot read the bytes says why and falls back to a hex dump.
// Output is capped (kMaxOutput) so a huge body never stalls the UI.
namespace contentview {

enum class View { Auto, Text, Json, Xml, Form, Multipart, Protobuf, Grpc, MsgPack, Image, Hex, Jwt, GraphQL, Cbor, Dns };
constexpr int kViewCount = 15;
const char* viewName(View v);

constexpr size_t kMaxOutput = 512 * 1024;

// The view Auto picks for a body: from the content type first, then by sniffing.
View detect(const std::string& body, const std::string& contentType);

struct Rendered {
    View view = View::Text;  // the view actually used (Auto resolved)
    std::string text;
    std::string note;        // "decoded as protobuf (12 fields)", or why the view failed
};
// `schema` / `message` (optional): decode protobuf and gRPC with that .proto message type.
Rendered render(View view, const std::string& body, const std::string& contentType,
                const protoschema::Schema* schema = nullptr, const std::string& message = {});

// The pieces, exposed for tests.
std::string hexDump(const std::string& bytes, size_t maxBytes = 64 * 1024);
bool prettyJson(const std::string& body, std::string& out);
std::string prettyXml(const std::string& body);
bool formFields(const std::string& body, std::string& out);
bool multipart(const std::string& body, const std::string& contentType, std::string& out);
// Schema-less protobuf: field numbers, wire types and values; nested messages
// are decoded when their bytes parse as one. False when the bytes are not protobuf.
bool protobuf(const std::string& body, std::string& out);
// gRPC framing (1-byte compressed flag + 4-byte length per message), each
// message decoded as protobuf.
bool grpc(const std::string& body, std::string& out);
bool msgpack(const std::string& body, std::string& out);
bool imageInfo(const std::string& body, std::string& out);
std::string urlDecode(const std::string& s, bool plusIsSpace = true);
// JSON Web Tokens: every token in `text` with its header and claims
// decoded (exp / iat / nbf shown as dates). False when there is none.
bool jwt(const std::string& text, std::string& out);
std::vector<std::string> findJwts(const std::string& text);
// GraphQL requests (JSON with "query", or application/graphql): the query
// indented, then the variables and operation name.
bool graphql(const std::string& body, std::string& out);
bool cbor(const std::string& body, std::string& out);
// A DNS message (UDP payload, or TCP with its 2-byte length): header,
// questions and answers. dnsSummary() is one line ("A? example.com",
// "example.com A 93.184.216.34") and dnsName() the first question's name.
bool dns(const std::string& msg, std::string& out);
std::string dnsSummary(const std::string& msg);
std::string dnsName(const std::string& msg);

// Cookies, for the cookie tables.
struct Cookie {
    std::string name, value;
    std::string attributes;  // "Path=/; HttpOnly; Secure" (Set-Cookie only)
};
std::vector<Cookie> parseCookieHeader(const std::string& value);  // "a=1; b=2"
Cookie parseSetCookie(const std::string& value);

}  // namespace contentview
