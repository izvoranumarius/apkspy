#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Plain-text HTTP/2 ("h2c", as used by plain-text gRPC channels), read
// passively: the proxy relays the bytes unchanged and this observer decodes
// the frames (HPACK headers, DATA, END_STREAM, RST_STREAM) into one exchange
// per stream for the request list. Nothing is rewritten.
namespace http2 {

using Headers = std::vector<std::pair<std::string, std::string>>;

// The client connection preface (RFC 9113, 3.4).
constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t kPrefaceLen = 24;

bool huffmanDecode(const std::string& in, std::string& out);

// HPACK (RFC 7541) decoder for one direction of a connection.
class HpackDecoder {
public:
    bool decode(const std::string& block, Headers& out, std::string& error);
    void setMaxTableSize(size_t n) { maxAllowed_ = n; }

private:
    bool lookup(uint64_t index, std::pair<std::string, std::string>& out) const;
    void add(std::pair<std::string, std::string> h);
    void evict();
    std::deque<std::pair<std::string, std::string>> dyn_;  // newest first
    size_t size_ = 0;
    size_t max_ = 4096;
    size_t maxAllowed_ = 4096;
};

// One stream's request and response, as decoded so far.
struct Exchange {
    uint32_t stream = 0;
    std::string method, path, authority, scheme;
    Headers requestHeaders;   // without pseudo-headers
    std::string requestBody;
    int status = 0;
    Headers responseHeaders;  // trailers appended
    std::string responseBody;
    bool requestEnded = false, responseEnded = false, reset = false;
};

class Observer {
public:
    // started: the request headers arrived; updated: more of it; finished:
    // the response ended (or the stream was reset / the connection closed).
    struct Callbacks {
        std::function<void(const Exchange&)> started, updated, finished;
    };
    explicit Observer(Callbacks cb, size_t maxBody) : cb_(std::move(cb)), maxBody_(maxBody) {}
    // Bytes of one direction, in order (the client's start with the preface).
    void feed(bool fromClient, const char* data, size_t len);
    // The connection ended: open streams finish as they are.
    void close();
    const std::string& error() const { return error_; }

private:
    void frame(bool fromClient, uint8_t type, uint8_t flags, uint32_t stream, const std::string& payload);
    void headersDone(bool fromClient, uint32_t stream, bool endStream);
    Exchange& ex(uint32_t stream);
    std::mutex mutex_;  // both directions feed from their own threads
    Callbacks cb_;
    size_t maxBody_;
    std::string buf_[2];
    bool prefaceSeen_ = false;
    HpackDecoder hpack_[2];  // [0] server -> client, [1] client -> server
    std::string headerBlock_[2];
    uint32_t headerStream_[2] = {0, 0};
    bool headerEnd_[2] = {false, false};
    std::map<uint32_t, Exchange> streams_;
    std::string error_;
};

}  // namespace http2
