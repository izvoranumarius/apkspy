#include "core/ApkInfo.hpp"
#include "core/Workspace.hpp"  // Root definition
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include "core/AxmlDecoder.hpp"
#include "core/Der.hpp"
#include "core/Paths.hpp"
#include "core/Sha256.hpp"
#include "core/TreeNode.hpp"
#include "core/TextUtils.hpp"

namespace {

// --- manifest ---------------------------------------------------------------

const std::string* attrValue(const std::vector<AxmlDecoder::Attr>& attrs, const char* prefixed,
                             const char* bare) {
    for (const AxmlDecoder::Attr& a : attrs) {
        if (a.name == prefixed) return &a.value;
        if (a.name == bare) return &a.value;  // manifests without the android ns mapping
    }
    return nullptr;
}

bool attrBool(const std::vector<AxmlDecoder::Attr>& attrs, const char* prefixed, const char* bare) {
    const std::string* v = attrValue(attrs, prefixed, bare);
    return v && (*v == "true" || *v == "0x1" || *v == "1");
}

bool isComponentType(const std::string& name) {
    return name == "activity" || name == "activity-alias" || name == "service" || name == "receiver" ||
           name == "provider";
}

class ManifestVisitor : public AxmlDecoder::Visitor {
public:
    explicit ManifestVisitor(ApkInfo& info) : info_(info) {}

    void startElement(const std::string& name, const std::vector<AxmlDecoder::Attr>& attrs) override {
        if (name == "manifest") {
            if (const std::string* v = attrValue(attrs, "android:package", "package")) info_.packageName = *v;
            if (const std::string* v = attrValue(attrs, "android:versionName", "versionName"))
                info_.versionName = *v;
            if (const std::string* v = attrValue(attrs, "android:versionCode", "versionCode"))
                info_.versionCode = *v;
        } else if (name == "uses-sdk") {
            if (const std::string* v = attrValue(attrs, "android:minSdkVersion", "minSdkVersion"))
                info_.minSdk = *v;
            if (const std::string* v = attrValue(attrs, "android:targetSdkVersion", "targetSdkVersion"))
                info_.targetSdk = *v;
        } else if (name == "uses-permission" || name == "uses-permission-sdk-23") {
            if (const std::string* v = attrValue(attrs, "android:name", "name"))
                info_.permissions.push_back(*v);
        } else if (name == "application") {
            if (const std::string* v = attrValue(attrs, "android:label", "label")) info_.appLabel = *v;
            if (const std::string* v = attrValue(attrs, "android:icon", "icon")) info_.appIcon = *v;
            info_.debuggable = attrBool(attrs, "android:debuggable", "debuggable");
            info_.allowBackup = attrBool(attrs, "android:allowBackup", "allowBackup");
        } else if (isComponentType(name)) {
            ApkComponent c;
            c.type = name;
            if (const std::string* v = attrValue(attrs, "android:name", "name")) c.name = *v;
            c.exported = attrBool(attrs, "android:exported", "exported");
            info_.components.push_back(std::move(c));
            inFilter_ = false;
            return;
        } else if (name == "intent-filter" && !info_.components.empty()) {
            inFilter_ = true;
            return;
        } else if ((name == "action" || name == "category") && inFilter_) {
            if (const std::string* v = attrValue(attrs, "android:name", "name")) {
                auto& dst = name == "action" ? info_.components.back().actions
                                             : info_.components.back().categories;
                if (std::find(dst.begin(), dst.end(), *v) == dst.end()) dst.push_back(*v);
            }
            return;
        }
    }

    void endElement(const std::string& name) override {
        if (name == "intent-filter" || isComponentType(name)) inFilter_ = false;
    }

private:
    ApkInfo& info_;
    bool inFilter_ = false;
};

// --- certificates -----------------------------------------------------------

// SHA-256 fingerprint + subject/issuer CN of one X.509 certificate.
ApkSigningInfo describeCert(const uint8_t* der, size_t len, const char* scheme) {
    ApkSigningInfo s;
    s.scheme = scheme;
    s.certSha256 = sha256::hexOf(std::vector<uint8_t>(der, der + len));
    size_t pos = 0;
    der::Node cert, tbs;
    if (!der::read(der, len, pos, cert) || !cert.isSequence()) return s;
    pos = 0;
    der::Children certChildren = der::of(cert);
    if (!certChildren.next(pos, tbs) || !tbs.isSequence()) return s;
    // TBSCertificate: [0] version?, INTEGER serial, SEQ signature, SEQ issuer,
    // SEQ validity, SEQ subject - the 2nd and 4th SEQUENCE carry the names.
    size_t tbsPos = 0;
    der::Node child;
    der::Children tbsChildren = der::of(tbs);
    int sequences = 0;
    while (tbsChildren.next(tbsPos, child)) {
        if (child.isContext(0)) continue;  // explicit version
        if (!child.isSequence()) continue;
        ++sequences;
        if (sequences == 2) s.issuer = der::commonName(child);
        if (sequences == 4) {
            s.subject = der::commonName(child);
            break;
        }
    }
    return s;
}

// First certificate of a PKCS#7 SignedData blob (v1/JAR: META-INF/*.RSA).
bool certFromPkcs7(const std::vector<uint8_t>& blob, ApkSigningInfo& out) {
    static const uint8_t kOidSignedData[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    size_t pos = 0;
    der::Node contentInfo;
    if (!der::read(blob.data(), blob.size(), pos, contentInfo) || !contentInfo.isSequence()) return false;
    size_t ciPos = 0;
    der::Node child;
    der::Children ci = der::of(contentInfo);
    if (!ci.next(ciPos, child)) return false;
    if (!der::oidEquals(child, kOidSignedData, sizeof kOidSignedData)) return false;
    if (!ci.next(ciPos, child)) return false;
    if (!child.isContext(0)) return false;  // [0] SignedData
    size_t sdPos = 0;
    der::Node signedData;
    der::Children sd = der::of(child);
    if (!sd.next(sdPos, signedData) || !signedData.isSequence()) return false;
    size_t innerPos = 0;
    der::Node field;
    der::Children fields = der::of(signedData);
    while (fields.next(innerPos, field)) {
        if (!field.isContext(0)) continue;  // [0] IMPLICIT SET OF Certificate
        size_t certPos = 0;
        der::Node cert;
        der::Children certs = der::of(field);
        if (!certs.next(certPos, cert) || !cert.isSequence()) return false;
        // Hash the FULL certificate encoding (header included).
        const size_t header = cert.total - cert.len;
        out = describeCert(cert.content - header, cert.total, "v1 (JAR)");
        return true;
    }
    return false;
}

// --- APK signing block (v2/v3) ----------------------------------------------

uint32_t readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t readU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

constexpr uint32_t kV2BlockId = 0x7109871a;
constexpr uint32_t kV3BlockId = 0xf05368c0;
constexpr uint64_t kMaxSigningBlock = 16ull * 1024 * 1024;

// First certificate of a v2/v3 signer sequence (same layout for both: the
// certificates sequence is the second length-prefixed field of signed data).
bool firstCertOfSigners(const uint8_t* p, size_t len, ApkSigningInfo& out, const char* scheme) {
    auto u32At = [&](size_t at) -> uint32_t { return at + 4 <= len ? readU32(p + at) : 0; };
    size_t pos = 0;
    const uint32_t signersLen = u32At(pos);
    if (signersLen == 0 || static_cast<uint64_t>(pos) + 4 + signersLen > len) return false;
    pos += 4;
    const uint32_t signerLen = u32At(pos);
    if (signerLen == 0 || static_cast<uint64_t>(pos) + 4 + signerLen > len) return false;
    pos += 4;
    const uint32_t signedDataLen = u32At(pos);
    if (signedDataLen == 0 || static_cast<uint64_t>(pos) + 4 + signedDataLen > len) return false;
    pos += 4;
    // signed data: digests (len-prefixed), certificates (len-prefixed), ...
    const uint32_t digestsLen = u32At(pos);
    if (static_cast<uint64_t>(pos) + 4 + digestsLen > len) return false;
    pos += 4 + digestsLen;
    const uint32_t certsLen = u32At(pos);
    if (certsLen == 0 || static_cast<uint64_t>(pos) + 4 + certsLen > len) return false;
    pos += 4;
    const uint32_t certLen = u32At(pos);
    if (certLen == 0 || static_cast<uint64_t>(pos) + 4 + certLen > len) return false;
    out = describeCert(p + pos + 4, certLen, scheme);
    return true;
}

}  // namespace

bool ApkInfo::describeSignatureBlock(const std::vector<uint8_t>& blob, ApkSigningInfo& out) {
    return certFromPkcs7(blob, out);
}

ApkSigningInfo ApkInfo::describeCertificate(const uint8_t* der, size_t len, const char* scheme) {
    return describeCert(der, len, scheme);
}

// `buffer` holds the file bytes starting at absolute offset `bufferOffset`
// (0 = the whole file). All offsets inside the buffer are translated through
// it, so a tail read works as well as a full read.
bool ApkInfo::parseSigningBlock(const std::vector<uint8_t>& buffer, uint64_t bufferOffset,
                                std::vector<ApkSigningInfo>& out) {
    out.clear();
    const size_t size = buffer.size();
    if (size < 22) return false;
    // Locate the End Of Central Directory record (scan back over the comment).
    size_t eocd = 0;
    bool found = false;
    const size_t scanFrom = size >= 0xFFFF + 22 ? size - (0xFFFF + 22) : 0;
    for (size_t i = size - 22 + 1; i-- > scanFrom;) {
        if (buffer[i] == 0x50 && buffer[i + 1] == 0x4b && buffer[i + 2] == 0x05 && buffer[i + 3] == 0x06) {
            eocd = i;
            found = true;
            break;
        }
    }
    if (!found) return false;
    const uint64_t cdOffset = readU32(buffer.data() + eocd + 16);
    if (cdOffset < 24 || cdOffset > bufferOffset + size) return false;
    // The signing block sits right before the central directory and ends with
    // the 16-byte magic; an 8-byte size footer precedes the magic.
    static const char kMagic[16] = {'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
                                    'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};
    if (cdOffset - 16 < bufferOffset) return false;
    if (std::memcmp(buffer.data() + (cdOffset - 16 - bufferOffset), kMagic, 16) != 0) return false;
    if (cdOffset - 24 < bufferOffset) return false;
    const uint64_t sizeFooter = readU64(buffer.data() + (cdOffset - 24 - bufferOffset));
    if (sizeFooter < 24 || sizeFooter > kMaxSigningBlock) return false;
    const uint64_t blockStart = cdOffset - sizeFooter - 8;
    if (blockStart < bufferOffset) return false;  // block not (fully) inside this buffer
    if (readU64(buffer.data() + (blockStart - bufferOffset)) != sizeFooter) return false;

    // Length-prefixed (u64) pairs: u32 id + payload.
    size_t pos = static_cast<size_t>(blockStart - bufferOffset) + 8;
    const size_t pairsEnd = static_cast<size_t>(cdOffset - 24 - bufferOffset);
    while (pos + 12 <= pairsEnd) {
        const uint64_t pairLen = readU64(buffer.data() + pos);
        if (pairLen < 4 || pos + 8 + pairLen > pairsEnd) break;
        const uint32_t id = readU32(buffer.data() + pos + 8);
        const uint8_t* payload = buffer.data() + pos + 12;
        const size_t payloadLen = static_cast<size_t>(pairLen) - 4;
        const char* scheme = id == kV2BlockId ? "v2" : (id == kV3BlockId ? "v3" : nullptr);
        if (scheme) {
            ApkSigningInfo s;
            if (firstCertOfSigners(payload, payloadLen, s, scheme)) out.push_back(std::move(s));
        }
        pos += 8 + static_cast<size_t>(pairLen);
    }
    return !out.empty();
}

ApkInfo ApkInfo::extract(Root& apkRoot) {
    ApkInfo info;
    struct ResolveLabel {
        Root& root;
        ApkInfo& info;
        ~ResolveLabel() {
            // "@string/app_name" -> the default-configuration text.
            if (!root.resources || info.appLabel.empty() || info.appLabel[0] != '@') return;
            const uint32_t id = root.resources->find(info.appLabel);
            const std::string text = id ? root.resources->value(id) : std::string();
            if (!text.empty()) {
                info.appLabelRef = info.appLabel;
                info.appLabel = text;
            }
        }
    } resolveLabel{apkRoot, info};
    // Manifest: decoded on the UI thread through the archive's ContentSource.
    if (apkRoot.tree) {
        if (const TreeNode* manifest = apkRoot.tree->findChild("AndroidManifest.xml")) {
            info.manifestPath = manifest->path();
            std::vector<uint8_t> bytes;
            if (apkRoot.source && apkRoot.source->read(*manifest, bytes)) {
                ManifestVisitor visitor(info);
                std::string error;
                info.ok = AxmlDecoder::decodeEvents(bytes, visitor, error, apkRoot.resources.get());
            }
        }
    }
    // Signing: v2/v3 come from the file tail (independent of the archive
    // handle), v1 from the META-INF entries via the tree.
    {
        std::ifstream in(pathutil::fromUtf8(apkRoot.apkPath), std::ios::binary);
        if (in) {
            in.seekg(0, std::ios::end);
            const std::streamoff fileSize = in.tellg();
            if (fileSize > 0) {
                // EOCD (22) + max zip comment (0xFFFF) + a generous signing
                // block window. If the block were bigger than this window the
                // v2/v3 info is simply not reported - v1 still is.
                const std::streamoff tailLen = std::min<std::streamoff>(fileSize, 0x10000 + 1024 * 1024);
                std::vector<uint8_t> tail(static_cast<size_t>(tailLen));
                in.seekg(-tailLen, std::ios::end);
                in.read(reinterpret_cast<char*>(tail.data()), tailLen);
                if (static_cast<size_t>(in.gcount()) == static_cast<size_t>(tailLen)) {
                    std::vector<ApkSigningInfo> blockSigs;
                    if (parseSigningBlock(tail, static_cast<uint64_t>(fileSize - tailLen), blockSigs))
                        info.signatures.insert(info.signatures.end(), blockSigs.begin(), blockSigs.end());
                }
            }
        }
    }
    if (apkRoot.tree && apkRoot.source) {
        // v1 (JAR) signatures live in top-level META-INF/*.RSA|DSA|EC entries
        // (subfolders under META-INF are not signature files).
        const std::function<void(const TreeNode&)> scan = [&](const TreeNode& node) {
            if (node.isFolder()) {
                for (const auto& c : node.children()) scan(*c);
                return;
            }
            const std::string& path = node.path();
            if (path.rfind("META-INF/", 0) != 0) return;
            const std::string rest = path.substr(9);
            if (rest.find('/') != std::string::npos) return;
            const size_t dot = rest.find_last_of('.');
            if (dot == std::string::npos) return;
            const std::string ext = tex::asciiLower(rest.substr(dot + 1));
            if (ext != "rsa" && ext != "dsa" && ext != "ec") return;
            std::vector<uint8_t> blob;
            if (!apkRoot.source->read(node, blob)) return;
            ApkSigningInfo s;
            if (certFromPkcs7(blob, s)) info.signatures.push_back(std::move(s));
        };
        scan(*apkRoot.tree);
    }
    return info;
}
