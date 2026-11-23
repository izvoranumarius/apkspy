#pragma once
#include <cstdint>
#include <string>
#include <vector>

// The few javax.crypto / java.security operations app string decoders use, backed by mbedTLS: AES, DES and DESede in
// ECB / CBC (and AES CTR), PKCS#5 or no padding, and the MD5 / SHA-1 / SHA-256 / SHA-512 digests.
namespace emu::crypto {

struct Transformation {
    bool ok = false;
    std::string cipher;   // "AES", "DES", "DESede"
    std::string mode;     // "ECB", "CBC", "CTR"
    bool pkcs5 = false;
};

// "AES", "AES/CBC/PKCS5Padding", "DESede/ECB/NoPadding", ... (Java's defaults: ECB and PKCS5Padding when omitted).
Transformation parse(const std::string& transformation);

// Encrypts or decrypts `in`. False with a Java-style reason ("BadPaddingException", "InvalidKeyException: ...").
bool run(const Transformation& t, bool encrypt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
         const std::vector<uint8_t>& in, std::vector<uint8_t>& out, std::string& error);

// "MD5", "SHA-1" / "SHA1", "SHA-256" / "SHA256", "SHA-512" / "SHA512".
bool digest(const std::string& algorithm, const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

}  // namespace emu::crypto
