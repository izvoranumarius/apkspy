#include "analysis/EmuCrypto.hpp"
#include <algorithm>
#include <cctype>
#include "mbedtls/aes.h"
#include "mbedtls/des.h"
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
    else return t;
    t.mode = parts.size() == 3 ? upper(parts[1]) : "ECB";
    const std::string pad = parts.size() == 3 ? upper(parts[2]) : "PKCS5PADDING";
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
    if (a == "SHA-512" || a == "SHA512") {
        out.assign(64, 0);
        return mbedtls_sha512(data.data(), data.size(), out.data(), 0) == 0;
    }
    return false;
}

}  // namespace emu::crypto
