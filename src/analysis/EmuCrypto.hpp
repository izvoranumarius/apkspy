#pragma once
#include <cstdint>
#include <string>
#include <vector>

// The few javax.crypto / java.security operations app string decoders use, backed by mbedTLS: AES, DES and DESede in
// ECB / CBC (and AES CTR and GCM), PKCS#5 or no padding, RSA with PKCS#1 v1.5, OAEP or no padding, and the MD5 / SHA-1 /
// SHA-256 / SHA-384 / SHA-512 digests.
namespace emu::crypto {

struct Transformation {
    bool ok = false;
    std::string cipher;   // "AES", "DES", "DESede", "RSA"
    std::string mode;     // "ECB", "CBC", "CTR", "GCM"
    bool pkcs5 = false;
    std::string oaep;     // RSA OAEP: the digest the name gives ("SHA-256"), else empty
};

// "AES", "AES/CBC/PKCS5Padding", "DESede/ECB/NoPadding", ... (Java's defaults: ECB and PKCS5Padding when omitted).
Transformation parse(const std::string& transformation);

// Encrypts or decrypts `in`. False with a Java-style reason ("BadPaddingException", "InvalidKeyException: ...").
bool run(const Transformation& t, bool encrypt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
         const std::vector<uint8_t>& in, std::vector<uint8_t>& out, std::string& error);

// AES-GCM as Java does it: the tag (`tagBits` long) follows the ciphertext; `aad` is the additional data.
bool gcm(bool encrypt, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& aad,
         unsigned tagBits, const std::vector<uint8_t>& in, std::vector<uint8_t>& out, std::string& error);

struct RsaPadding {
    enum Kind { None, Pkcs1, Oaep } kind = Pkcs1;
    std::string hash = "SHA-1";  // OAEP
    // OAEP's mask digest. Empty: the name did not say, and providers differ (the JDK uses SHA-1, Android's the main
    // digest), so decryption accepts either and encryption uses the main digest.
    std::string mgfHash;
    std::vector<uint8_t> label;
};
// RSA with a DER key (X.509 SubjectPublicKeyInfo, or PKCS#8 / PKCS#1 private).
bool rsa(bool encrypt, bool privateKey, const RsaPadding& padding, const std::vector<uint8_t>& der, const std::vector<uint8_t>& in,
         std::vector<uint8_t>& out, std::string& error);

// "MD5", "SHA-1" / "SHA1", "SHA-256" / "SHA256", "SHA-384", "SHA-512" / "SHA512".
bool digest(const std::string& algorithm, const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

}  // namespace emu::crypto
