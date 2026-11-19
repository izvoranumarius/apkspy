#include "debug/Http2.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

namespace http2 {

namespace {

// HPACK static table (RFC 7541, Appendix A), entries 1-61. Generated from the RFC text.
constexpr std::pair<const char*, const char*> kStaticTable[61] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};

// HPACK Huffman code (RFC 7541, Appendix B): {code, bit length} per symbol 0-255, then EOS.
// Generated from the RFC text.
constexpr struct { uint32_t code; uint8_t bits; } kHuffman[257] = {
    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},
    {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
    {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28},
    {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},
    {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
    {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10},
    {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
    {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
    {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
    {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6},
    {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
    {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7},
    {0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7},
    {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
    {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
    {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5},
    {0x25, 6}, {0x26, 6}, {0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7},
    {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7},
    {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
    {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14},
    {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20},
    {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23},
    {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
    {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23},
    {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
    {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24}, {0x3fffda, 22}, {0x1fffdd, 21},
    {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
    {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22},
    {0x7fffeb, 23}, {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
    {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20}, {0x3fffe2, 22},
    {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
    {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23},
    {0x3fffe8, 22}, {0x1ffffec, 25}, {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
    {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21},
    {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
    {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27},
    {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21},
    {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22},
    {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27},
    {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
    {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26}, {0x3fffffff, 30},
};

// Code -> symbol, per bit length.
const std::vector<std::unordered_map<uint32_t, int>>& huffmanMaps() {
    static const std::vector<std::unordered_map<uint32_t, int>> maps = [] {
        std::vector<std::unordered_map<uint32_t, int>> m(31);
        for (int s = 0; s < 257; ++s) m[kHuffman[s].bits][kHuffman[s].code] = s;
        return m;
    }();
    return maps;
}

bool readInt(const std::string& b, size_t& pos, int prefixBits, uint64_t& v) {
    if (pos >= b.size()) return false;
    const uint8_t mask = static_cast<uint8_t>((1u << prefixBits) - 1);
    v = static_cast<uint8_t>(b[pos++]) & mask;
    if (v < mask) return true;
    int shift = 0;
    for (;;) {
        if (pos >= b.size() || shift > 56) return false;
        const uint8_t c = static_cast<uint8_t>(b[pos++]);
        v += static_cast<uint64_t>(c & 0x7f) << shift;
        shift += 7;
        if (!(c & 0x80)) return true;
    }
}

bool readString(const std::string& b, size_t& pos, std::string& out) {
    if (pos >= b.size()) return false;
    const bool huffman = (static_cast<uint8_t>(b[pos]) & 0x80) != 0;
    uint64_t len;
    if (!readInt(b, pos, 7, len) || len > b.size() - pos) return false;
    const std::string raw = b.substr(pos, static_cast<size_t>(len));
    pos += static_cast<size_t>(len);
    if (!huffman) return out = raw, true;
    return huffmanDecode(raw, out);
}

}  // namespace

bool huffmanDecode(const std::string& in, std::string& out) {
    const auto& maps = huffmanMaps();
    out.clear();
    uint32_t cur = 0;
    int len = 0;
    for (unsigned char byte : in) {
        for (int bit = 7; bit >= 0; --bit) {
            cur = cur << 1 | ((byte >> bit) & 1);
            if (++len > 30) return false;
            const auto it = maps[static_cast<size_t>(len)].find(cur);
            if (it != maps[static_cast<size_t>(len)].end()) {
                if (it->second == 256) return false;  // EOS inside a string is an error
                out += static_cast<char>(it->second);
                cur = 0;
                len = 0;
            }
        }
    }
    // Padding: fewer than 8 bits, all ones (the start of EOS).
    return len < 8 && cur == (1u << len) - 1;
}

bool HpackDecoder::lookup(uint64_t index, std::pair<std::string, std::string>& out) const {
    if (index == 0) return false;
    if (index <= 61) {
        out = {kStaticTable[index - 1].first, kStaticTable[index - 1].second};
        return true;
    }
    if (index - 62 >= dyn_.size()) return false;
    out = dyn_[static_cast<size_t>(index - 62)];
    return true;
}

void HpackDecoder::evict() {
    while (size_ > max_ && !dyn_.empty()) {
        size_ -= 32 + dyn_.back().first.size() + dyn_.back().second.size();
        dyn_.pop_back();
    }
}

void HpackDecoder::add(std::pair<std::string, std::string> h) {
    const size_t n = 32 + h.first.size() + h.second.size();
    dyn_.push_front(std::move(h));
    size_ += n;
    evict();
}

bool HpackDecoder::decode(const std::string& block, Headers& out, std::string& error) {
    size_t pos = 0;
    while (pos < block.size()) {
        const uint8_t b = static_cast<uint8_t>(block[pos]);
        std::pair<std::string, std::string> h;
        uint64_t idx;
        if (b & 0x80) {  // indexed field
            if (!readInt(block, pos, 7, idx) || !lookup(idx, h)) return error = "HPACK: bad index", false;
            out.push_back(std::move(h));
        } else if ((b & 0xc0) == 0x40 || (b & 0xf0) == 0x00 || (b & 0xf0) == 0x10) {
            // Literal: with incremental indexing (01), without (0000) or never indexed (0001).
            const bool index = (b & 0xc0) == 0x40;
            if (!readInt(block, pos, index ? 6 : 4, idx)) return error = "HPACK: bad literal", false;
            if (idx) {
                std::pair<std::string, std::string> named;
                if (!lookup(idx, named)) return error = "HPACK: bad name index", false;
                h.first = named.first;
            } else if (!readString(block, pos, h.first))
                return error = "HPACK: bad name", false;
            if (!readString(block, pos, h.second)) return error = "HPACK: bad value", false;
            out.push_back(h);
            if (index) add(std::move(h));
        } else if ((b & 0xe0) == 0x20) {  // dynamic table size update
            if (!readInt(block, pos, 5, idx) || idx > maxAllowed_) return error = "HPACK: bad table size", false;
            max_ = static_cast<size_t>(idx);
            evict();
        } else {
            return error = "HPACK: unknown representation", false;
        }
    }
    return true;
}

Exchange& Observer::ex(uint32_t stream) {
    Exchange& e = streams_[stream];
    e.stream = stream;
    return e;
}

void Observer::feed(bool fromClient, const char* data, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!error_.empty()) return;
    std::string& b = buf_[fromClient ? 1 : 0];
    b.append(data, len);
    if (fromClient && !prefaceSeen_) {
        if (b.size() < kPrefaceLen) return;
        if (b.compare(0, kPrefaceLen, kPreface, kPrefaceLen) != 0) {
            error_ = "not an HTTP/2 connection preface";
            return;
        }
        b.erase(0, kPrefaceLen);
        prefaceSeen_ = true;
    }
    size_t pos = 0;
    while (b.size() - pos >= 9) {
        const auto* p = reinterpret_cast<const unsigned char*>(b.data() + pos);
        const size_t flen = static_cast<size_t>(p[0]) << 16 | static_cast<size_t>(p[1]) << 8 | p[2];
        if (flen > (16u << 20)) {
            error_ = "HTTP/2 frame too large";
            return;
        }
        if (b.size() - pos < 9 + flen) break;
        const uint32_t stream = (static_cast<uint32_t>(p[5]) << 24 | static_cast<uint32_t>(p[6]) << 16 | static_cast<uint32_t>(p[7]) << 8 | p[8]) & 0x7fffffff;
        frame(fromClient, p[3], p[4], stream, b.substr(pos + 9, flen));
        pos += 9 + flen;
        if (!error_.empty()) return;
    }
    b.erase(0, pos);
}

void Observer::frame(bool fromClient, uint8_t type, uint8_t flags, uint32_t stream, const std::string& payload) {
    const int dir = fromClient ? 1 : 0;
    std::string body = payload;
    // PADDED (DATA, HEADERS): a pad-length byte, the data, then the padding.
    if ((type == 0 || type == 1) && (flags & 0x8)) {
        if (body.empty() || static_cast<uint8_t>(body[0]) >= body.size()) return;
        const size_t padLen = static_cast<uint8_t>(body[0]);
        body = body.substr(1, body.size() - 1 - padLen);
    }
    switch (type) {
        case 0: {  // DATA
            if (!streams_.count(stream)) return;
            Exchange& e = ex(stream);
            std::string& target = fromClient ? e.requestBody : e.responseBody;
            if (target.size() < maxBody_) target.append(body, 0, std::min(body.size(), maxBody_ - target.size()));
            if (flags & 0x1) (fromClient ? e.requestEnded : e.responseEnded) = true;
            if (!fromClient && (flags & 0x1)) {
                if (cb_.finished) cb_.finished(e);
                streams_.erase(stream);
            } else if (cb_.updated)
                cb_.updated(e);
            return;
        }
        case 1:  // HEADERS
            if (flags & 0x20) body = body.size() >= 5 ? body.substr(5) : std::string();  // PRIORITY
            headerBlock_[dir] = body;
            headerStream_[dir] = stream;
            headerEnd_[dir] = (flags & 0x1) != 0;
            if (flags & 0x4) headersDone(fromClient, stream, headerEnd_[dir]);
            return;
        case 9:  // CONTINUATION
            if (headerStream_[dir] != stream) return;
            headerBlock_[dir] += body;
            if (flags & 0x4) headersDone(fromClient, stream, headerEnd_[dir]);
            return;
        case 3:  // RST_STREAM
            if (streams_.count(stream)) {
                Exchange& e = ex(stream);
                e.reset = true;
                if (cb_.finished) cb_.finished(e);
                streams_.erase(stream);
            }
            return;
        case 4:  // SETTINGS: HEADER_TABLE_SIZE bounds the other side's encoder
            if (flags & 0x1) return;  // ACK
            for (size_t i = 0; i + 6 <= body.size(); i += 6) {
                const int id = static_cast<uint8_t>(body[i]) << 8 | static_cast<uint8_t>(body[i + 1]);
                const uint32_t v = static_cast<uint32_t>(static_cast<uint8_t>(body[i + 2])) << 24 |
                                   static_cast<uint32_t>(static_cast<uint8_t>(body[i + 3])) << 16 |
                                   static_cast<uint32_t>(static_cast<uint8_t>(body[i + 4])) << 8 | static_cast<uint8_t>(body[i + 5]);
                if (id == 1) hpack_[fromClient ? 0 : 1].setMaxTableSize(v);
            }
            return;
        default:
            return;  // PRIORITY, PING, GOAWAY, WINDOW_UPDATE, PUSH_PROMISE...
    }
}

void Observer::headersDone(bool fromClient, uint32_t stream, bool endStream) {
    const int dir = fromClient ? 1 : 0;
    Headers fields;
    std::string err;
    if (!hpack_[dir].decode(headerBlock_[dir], fields, err)) {
        error_ = err;  // the table is out of step: stop decoding this connection
        return;
    }
    headerBlock_[dir].clear();
    headerStream_[dir] = 0;
    if (fromClient) {
        const bool fresh = !streams_.count(stream);
        Exchange& e = ex(stream);
        for (auto& [n, v] : fields) {
            if (n == ":method") e.method = v;
            else if (n == ":path") e.path = v;
            else if (n == ":authority") e.authority = v;
            else if (n == ":scheme") e.scheme = v;
            else e.requestHeaders.emplace_back(n, v);
        }
        if (endStream) e.requestEnded = true;
        if (fresh && cb_.started) cb_.started(e);
        else if (cb_.updated) cb_.updated(e);
        return;
    }
    if (!streams_.count(stream)) return;
    Exchange& e = ex(stream);
    for (auto& [n, v] : fields) {
        if (n == ":status") e.status = std::atoi(v.c_str());
        else e.responseHeaders.emplace_back(n, v);
    }
    if (endStream) {
        e.responseEnded = true;
        if (cb_.finished) cb_.finished(e);
        streams_.erase(stream);
    } else if (cb_.updated)
        cb_.updated(e);
}

void Observer::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, e] : streams_)
        if (cb_.finished) cb_.finished(e);
    streams_.clear();
}

}  // namespace http2
