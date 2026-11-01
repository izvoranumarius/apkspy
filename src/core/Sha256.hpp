#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Self-contained SHA-256 (FIPS 180-4) for certificate fingerprints (M4).
// No new third-party dependency is allowed (ground rule 2), so this is the
// small standard implementation: init/update/finish plus one-shot helpers.
namespace sha256 {

struct Context {
    uint32_t h[8];
    uint64_t bits = 0;  // message bits hashed so far (excluding padding)
    uint8_t buf[64];
    size_t bufLen = 0;
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline void compress(Context& c, const uint8_t* p) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) |
               (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        const uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

inline void init(Context& c) {
    static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (int i = 0; i < 8; ++i) c.h[i] = H0[i];
    c.bits = 0;
    c.bufLen = 0;
}

// Buffers and compresses full blocks; partial bytes stay in c.buf.
inline void update(Context& c, const uint8_t* data, size_t len) {
    c.bits += (uint64_t)len * 8;
    while (len > 0) {
        const size_t take = len < 64 - c.bufLen ? len : 64 - c.bufLen;
        for (size_t i = 0; i < take; ++i) c.buf[c.bufLen + i] = data[i];
        c.bufLen += take;
        data += take;
        len -= take;
        if (c.bufLen == 64) {
            compress(c, c.buf);
            c.bufLen = 0;
        }
    }
}

inline void finish(Context& c, uint8_t out[32]) {
    const uint64_t bits = c.bits;  // message length before padding
    // Padding: 0x80, then zeros so that (bufLen + k) % 64 == 56, then the
    // 64-bit big-endian bit count. k is at least 1 and at most 64.
    size_t k = c.bufLen <= 55 ? 55 - c.bufLen + 1 : 119 - c.bufLen + 1;
    uint8_t pad[72];
    pad[0] = 0x80;
    for (size_t i = 1; i < k; ++i) pad[i] = 0;
    for (int i = 0; i < 8; ++i) pad[k + i] = (uint8_t)(bits >> (56 - 8 * i));
    const size_t padLen = k + 8;
    // Feed the padding WITHOUT counting it into c.bits. (The message is fully
    // buffered or compressed by update(); only this tail remains.)
    const uint8_t* p = pad;
    size_t n = padLen;
    while (n > 0) {
        const size_t take = n < 64 - c.bufLen ? n : 64 - c.bufLen;
        for (size_t i = 0; i < take; ++i) c.buf[c.bufLen + i] = p[i];
        c.bufLen += take;
        p += take;
        n -= take;
        if (c.bufLen == 64) {
            compress(c, c.buf);
            c.bufLen = 0;
        }
    }
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(c.h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c.h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c.h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c.h[i];
    }
}

inline void digest(const uint8_t* data, size_t len, uint8_t out[32]) {
    Context c;
    init(c);
    update(c, data, len);
    finish(c, out);
}

inline std::string hex(const uint8_t d[32]) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; ++i) {
        s += kHex[d[i] >> 4];
        s += kHex[d[i] & 0xF];
    }
    return s;
}

// Lowercase hex SHA-256 of a byte buffer - the certificate fingerprint form.
inline std::string hexOf(const std::vector<uint8_t>& data) {
    uint8_t d[32];
    digest(data.data(), data.size(), d);
    return hex(d);
}

}  // namespace sha256
