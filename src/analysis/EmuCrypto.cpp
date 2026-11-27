#include "analysis/EmuCrypto.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <random>
#include "mbedtls/aes.h"
#include "mbedtls/des.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

namespace emu::crypto {
namespace {

std::string upper(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '/') out.push_back(cur), cur.clear();
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

}  // namespace

Transformation parse(const std::string& transformation) {
    Transformation t;
    const std::vector<std::string> parts = split(transformation);
    if (parts.empty() || parts.size() == 2 || parts.size() > 3) return t;
    const std::string c = upper(parts[0]);
    if (c == "AES") t.cipher = "AES";
    else if (c == "DES") t.cipher = "DES";
    else if (c == "DESEDE" || c == "TRIPLEDES" || c == "3DES") t.cipher = "DESede";
    else if (c == "RSA") t.cipher = "RSA";
    else return t;
    t.mode = parts.size() == 3 ? upper(parts[1]) : "ECB";
    const std::string pad = parts.size() == 3 ? upper(parts[2]) : "PKCS5PADDING";
    if (t.cipher == "RSA") {  // Java's "RSA/ECB/..." and "RSA/None/..." are one block
        if (t.mode != "ECB" && t.mode != "NONE") return t;
        if (parts.size() == 1 || pad == "PKCS1PADDING") t.pkcs5 = true;  // here: PKCS#1 v1.5
        else if (pad == "NOPADDING") t.pkcs5 = false;
        else if (pad == "OAEPPADDING") t.oaep = "SHA-1";
        else if (pad == "OAEPWITHSHA-1ANDMGF1PADDING") t.oaep = "SHA-1";
        else if (pad == "OAEPWITHSHA-256ANDMGF1PADDING") t.oaep = "SHA-256";
        else if (pad == "OAEPWITHSHA-384ANDMGF1PADDING") t.oaep = "SHA-384";
        else if (pad == "OAEPWITHSHA-512ANDMGF1PADDING") t.oaep = "SHA-512";
        else return t;
        t.mode = "ECB";
        t.ok = true;
        return t;
    }
    if (t.mode == "GCM" && t.cipher == "AES" && pad == "NOPADDING") {
        t.ok = true;
        return t;
    }
    if (t.mode != "ECB" && t.mode != "CBC" && !(t.mode == "CTR" && t.cipher == "AES")) return t;
    if (pad == "PKCS5PADDING" || pad == "PKCS7PADDING") t.pkcs5 = true;
    else if (pad == "NOPADDING") t.pkcs5 = false;
    else return t;
    if (t.mode == "CTR") t.pkcs5 = false;
    t.ok = true;
    return t;
}

bool run(const Transformation& t, bool encrypt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivIn, const std::vector<uint8_t>& in,
         std::vector<uint8_t>& out, std::string& error) {
    const size_t block = t.cipher == "AES" ? 16 : 8;
    if (t.cipher == "AES" && key.size() != 16 && key.size() != 24 && key.size() != 32) {
        error = "InvalidKeyException: Invalid AES key length: " + std::to_string(key.size()) + " bytes";
        return false;
    }
    if (t.cipher == "DES" && key.size() != 8) {
        error = "InvalidKeyException: Wrong key size";
        return false;
    }
    if (t.cipher == "DESede" && key.size() != 24 && key.size() != 16) {
        error = "InvalidKeyException: Invalid key length: " + std::to_string(key.size()) + " bytes";
        return false;
    }
    std::vector<uint8_t> iv = ivIn;
    if (t.mode != "ECB" && iv.size() != block) {
        error = iv.empty() ? "InvalidKeyException: this mode needs an IV" : "InvalidAlgorithmParameterException: wrong IV length";
        return false;
    }
    std::vector<uint8_t> data = in;
    if (encrypt && t.pkcs5) {
        const size_t pad = block - data.size() % block;
        data.insert(data.end(), pad, static_cast<uint8_t>(pad));
    }
    if (t.mode != "CTR" && data.size() % block != 0) {
        error = "IllegalBlockSizeException: input length is not a multiple of " + std::to_string(block);
        return false;
    }
    out.assign(data.size(), 0);
    int rc = 0;
    if (t.cipher == "AES") {
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        const bool useEnc = encrypt || t.mode == "CTR";  // CTR runs the block cipher forwards both ways
        rc = useEnc ? mbedtls_aes_setkey_enc(&ctx, key.data(), static_cast<unsigned>(key.size() * 8)) : mbedtls_aes_setkey_dec(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
        if (rc == 0) {
            if (t.mode == "ECB") {
                for (size_t i = 0; i < data.size() && rc == 0; i += 16) rc = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, data.data() + i, out.data() + i);
            } else if (t.mode == "CBC") {
                rc = mbedtls_aes_crypt_cbc(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), out.data());
            } else {
                size_t offset = 0;
                unsigned char stream[16] = {};
                rc = mbedtls_aes_crypt_ctr(&ctx, data.size(), &offset, iv.data(), stream, data.data(), out.data());
            }
        }
        mbedtls_aes_free(&ctx);
    } else if (t.cipher == "DES") {
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        rc = encrypt ? mbedtls_des_setkey_enc(&ctx, key.data()) : mbedtls_des_setkey_dec(&ctx, key.data());
        if (rc == 0) {
            if (t.mode == "ECB") {
                for (size_t i = 0; i < data.size() && rc == 0; i += 8) rc = mbedtls_des_crypt_ecb(&ctx, data.data() + i, out.data() + i);
            } else {
                rc = mbedtls_des_crypt_cbc(&ctx, encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), out.data());
            }
        }
        mbedtls_des_free(&ctx);
    } else {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        const bool three = key.size() == 24;
        if (encrypt) rc = three ? mbedtls_des3_set3key_enc(&ctx, key.data()) : mbedtls_des3_set2key_enc(&ctx, key.data());
        else rc = three ? mbedtls_des3_set3key_dec(&ctx, key.data()) : mbedtls_des3_set2key_dec(&ctx, key.data());
        if (rc == 0) {
            if (t.mode == "ECB") {
                for (size_t i = 0; i < data.size() && rc == 0; i += 8) rc = mbedtls_des3_crypt_ecb(&ctx, data.data() + i, out.data() + i);
            } else {
                rc = mbedtls_des3_crypt_cbc(&ctx, encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), out.data());
            }
        }
        mbedtls_des3_free(&ctx);
    }
    if (rc != 0) {
        error = "the cipher failed (mbedTLS " + std::to_string(rc) + ")";
        return false;
    }
    if (!encrypt && t.pkcs5) {
        if (out.empty()) {
            error = "BadPaddingException";
            return false;
        }
        const uint8_t pad = out.back();
        if (pad == 0 || pad > block || pad > out.size() || !std::all_of(out.end() - pad, out.end(), [&](uint8_t b) { return b == pad; })) {
            error = "BadPaddingException: pad block corrupted (wrong key or IV?)";
            return false;
        }
        out.resize(out.size() - pad);
    }
    return true;
}

bool digest(const std::string& algorithm, const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

bool gcm(bool encrypt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& aad,
         unsigned tagBits, const std::vector<uint8_t>& in, std::vector<uint8_t>& out, std::string& error) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        error = "InvalidKeyException: Invalid AES key length: " + std::to_string(key.size()) + " bytes";
        return false;
    }
    if (iv.empty() || tagBits < 32 || tagBits > 128 || tagBits % 8) {
        error = "InvalidAlgorithmParameterException: bad GCM IV or tag length";
        return false;
    }
    const size_t tag = tagBits / 8;
    if (!encrypt && in.size() < tag) {
        error = "AEADBadTagException: input too short";
        return false;
    }
    const size_t n = encrypt ? in.size() : in.size() - tag;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size() * 8));
    out.assign(n + (encrypt ? tag : 0), 0);
    uint8_t none = 0;
    if (rc == 0) {
        if (encrypt)
            rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, n, iv.data(), iv.size(), aad.data(), aad.size(), in.data(),
                                           n ? out.data() : &none, tag, out.data() + n);
        else
            rc = mbedtls_gcm_auth_decrypt(&ctx, n, iv.data(), iv.size(), aad.data(), aad.size(), in.data() + n, tag, in.data(),
                                          n ? out.data() : &none);
    }
    mbedtls_gcm_free(&ctx);
    if (rc != 0) {
        error = "AEADBadTagException: Tag mismatch (wrong key, IV or additional data?)";
        return false;
    }
    return true;
}

namespace {
// Blinding only: the values never leave the process.
int randomBytes(void*, unsigned char* out, size_t n) {
    static std::mt19937 gen{std::random_device{}()};
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<unsigned char>(gen());
    return 0;
}
}  // namespace

namespace {

// MGF1: data ^= H(seed || 0) || H(seed || 1) || ...
bool mgf1(const std::string& hash, const uint8_t* seed, size_t seedLen, uint8_t* data, size_t len) {
    std::vector<uint8_t> block(seed, seed + seedLen), out;
    block.resize(seedLen + 4);
    size_t done = 0;
    for (uint32_t counter = 0; done < len; ++counter) {
        for (int i = 0; i < 4; ++i) block[seedLen + static_cast<size_t>(i)] = static_cast<uint8_t>(counter >> (24 - 8 * i));
        if (!digest(hash, block, out)) return false;
        for (size_t i = 0; i < out.size() && done < len; ++i, ++done) data[done] ^= out[i];
    }
    return true;
}

// EME-OAEP decoding (RFC 8017). False when the block was not made with these digests and label.
bool oaepDecode(std::vector<uint8_t> em, const std::string& hash, const std::string& mgfHash, const std::vector<uint8_t>& label,
                std::vector<uint8_t>& out) {
    std::vector<uint8_t> labelHash;
    if (!digest(hash, label, labelHash)) return false;
    const size_t h = labelHash.size();
    if (em.size() < 2 * h + 2) return false;
    uint8_t* seed = em.data() + 1;
    uint8_t* db = seed + h;
    const size_t dbLen = em.size() - h - 1;
    if (!mgf1(mgfHash, db, dbLen, seed, h) || !mgf1(mgfHash, seed, h, db, dbLen)) return false;
    if (em[0] != 0 || !std::equal(labelHash.begin(), labelHash.end(), db)) return false;
    size_t i = h;
    while (i < dbLen && db[i] == 0) ++i;
    if (i >= dbLen || db[i] != 1) return false;
    out.assign(db + i + 1, db + dbLen);
    return true;
}

bool oaepEncode(const std::vector<uint8_t>& message, size_t size, const std::string& hash, const std::string& mgfHash,
                const std::vector<uint8_t>& label, std::vector<uint8_t>& em) {
    std::vector<uint8_t> labelHash;
    if (!digest(hash, label, labelHash)) return false;
    const size_t h = labelHash.size();
    if (size < 2 * h + 2 || message.size() > size - 2 * h - 2) return false;
    em.assign(size, 0);
    uint8_t* seed = em.data() + 1;
    uint8_t* db = seed + h;
    const size_t dbLen = size - h - 1;
    randomBytes(nullptr, seed, h);
    std::copy(labelHash.begin(), labelHash.end(), db);
    db[dbLen - message.size() - 1] = 1;
    std::copy(message.begin(), message.end(), db + dbLen - message.size());
    return mgf1(mgfHash, seed, h, db, dbLen) && mgf1(mgfHash, db, dbLen, seed, h);
}

}  // namespace

bool rsa(bool encrypt, bool privateKey, const RsaPadding& padding, const std::vector<uint8_t>& der, const std::vector<uint8_t>& in,
         std::vector<uint8_t>& out, std::string& error) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    struct Free {
        mbedtls_pk_context* p;
        ~Free() { mbedtls_pk_free(p); }
    } guard{&pk};
    const int parsed = privateKey ? mbedtls_pk_parse_key(&pk, der.data(), der.size(), nullptr, 0, randomBytes, nullptr)
                                  : mbedtls_pk_parse_public_key(&pk, der.data(), der.size());
    if (parsed != 0 || mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        error = "InvalidKeySpecException: not an RSA key";
        return false;
    }
    mbedtls_rsa_context* ctx = mbedtls_pk_rsa(pk);
    const size_t size = mbedtls_rsa_get_len(ctx);
    if (size < 64 || size > 1024) {
        error = "InvalidKeyException: unsupported RSA key size";
        return false;
    }
    std::vector<uint8_t> block(size, 0), result(size, 0);
    const auto tooLong = [&] {
        error = "IllegalBlockSizeException: data too long for the key";
        return false;
    };
    if (encrypt && padding.kind == RsaPadding::Pkcs1) {  // 00 02 <random non-zero> 00 data (public) or 00 01 FF.. 00 data
        if (in.size() + 11 > size) return tooLong();
        const size_t fill = size - in.size() - 3;
        block[1] = privateKey ? 1 : 2;
        if (privateKey) {
            std::fill(block.begin() + 2, block.begin() + 2 + static_cast<std::ptrdiff_t>(fill), static_cast<uint8_t>(0xFF));
        } else {
            randomBytes(nullptr, block.data() + 2, fill);
            for (size_t i = 0; i < fill; ++i)
                if (block[2 + i] == 0) block[2 + i] = 0x5A;
        }
        std::copy(in.begin(), in.end(), block.end() - static_cast<std::ptrdiff_t>(in.size()));
    } else if (encrypt && padding.kind == RsaPadding::Oaep) {
        if (!oaepEncode(in, size, padding.hash, padding.mgfHash.empty() ? padding.hash : padding.mgfHash, padding.label, block)) return tooLong();
    } else {
        if (in.size() > size || (!encrypt && in.size() != size)) {
            error = "IllegalBlockSizeException: the data does not match the key size";
            return false;
        }
        std::copy(in.begin(), in.end(), block.end() - static_cast<std::ptrdiff_t>(in.size()));
    }
    const int rc = privateKey ? mbedtls_rsa_private(ctx, randomBytes, nullptr, block.data(), result.data())
                              : mbedtls_rsa_public(ctx, block.data(), result.data());
    if (rc != 0) {
        error = "BadPaddingException: the RSA operation failed";
        return false;
    }
    if (encrypt || padding.kind == RsaPadding::None) {
        out = std::move(result);
        return true;
    }
    if (padding.kind == RsaPadding::Oaep) {
        if (!padding.mgfHash.empty()) {
            if (oaepDecode(result, padding.hash, padding.mgfHash, padding.label, out)) return true;
        } else if (oaepDecode(result, padding.hash, padding.hash, padding.label, out) ||
                   oaepDecode(result, padding.hash, "SHA-1", padding.label, out)) {
            return true;
        }
        error = "BadPaddingException: OAEP decoding failed (wrong key or digests?)";
        return false;
    }
    // Decrypting PKCS#1 v1.5: the private key reads type 2 (random) padding, the public key reads type 1.
    size_t i = 2;
    while (i < size && result[i] != 0) ++i;
    if (result[0] != 0 || result[1] != (privateKey ? 2 : 1) || i < 10 || i >= size) {
        error = "BadPaddingException: Decryption error";
        return false;
    }
    out.assign(result.begin() + static_cast<std::ptrdiff_t>(i) + 1, result.end());
    return true;
}

bool digest(const std::string& algorithm, const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    const std::string a = upper(algorithm);
    if (a == "MD5") {
        out.assign(16, 0);
        return mbedtls_md5(data.data(), data.size(), out.data()) == 0;
    }
    if (a == "SHA-1" || a == "SHA1") {
        out.assign(20, 0);
        return mbedtls_sha1(data.data(), data.size(), out.data()) == 0;
    }
    if (a == "SHA-256" || a == "SHA256") {
        out.assign(32, 0);
        return mbedtls_sha256(data.data(), data.size(), out.data(), 0) == 0;
    }
    if (a == "SHA-384" || a == "SHA384") {
        out.assign(64, 0);
        const bool ok = mbedtls_sha512(data.data(), data.size(), out.data(), 1) == 0;
        out.resize(48);
        return ok;
    }
    if (a == "SHA-512" || a == "SHA512") {
        out.assign(64, 0);
        return mbedtls_sha512(data.data(), data.size(), out.data(), 0) == 0;
    }
    return false;
}

}  // namespace emu::crypto
