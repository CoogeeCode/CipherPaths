// Copyright 2026 Coogee Code Pty. Ltd. Australia
// https://www.coogeecode.com.au/
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// CipherPaths - https://cipherpaths.com/ - for more information.

// CipherPaths Core - Vault lifecycle implementation.
#include "cipherpaths/VaultManager.h"

#include "cipherpaths/Crypto.h"
#include "cipherpaths/Encoding.h"
#include "cipherpaths/Errors.h"
#include "cipherpaths/Json.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>

namespace cipherpaths {

namespace {

constexpr char kKdfName[] = "Argon2id";
constexpr char kWrapAad[] = "cipherpaths:vmk-wrap:v1";
constexpr char kRecoveryInfo[] = "cipherpaths:recovery-kek:v1";
constexpr char kHeaderMacInfo[] = "cipherpaths:header-mac:v1";

// Current UTC time as an ISO-8601 "YYYY-MM-DDThh:mm:ssZ" string.
std::string isoNow() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

// A wrapped key blob: nonce || ciphertext || tag, base64 encoded for JSON.
std::string wrapKey(const SecureBuffer& kek, const SecureBuffer& vmk) {
    uint8_t nonce[crypto::kNonceBytes];
    crypto::randomBytes(nonce, sizeof(nonce));
    auto enc = crypto::aesGcmEncrypt(kek.data(), nonce, vmk.data(), vmk.size(),
                                     reinterpret_cast<const uint8_t*>(kWrapAad),
                                     sizeof(kWrapAad) - 1);
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), nonce, nonce + crypto::kNonceBytes);
    blob.insert(blob.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    blob.insert(blob.end(), enc.tag.begin(), enc.tag.end());
    return encoding::base64Encode(blob);
}

// Returns the VMK on success; throws IncorrectPassword on auth failure.
SecureBuffer unwrapKey(const SecureBuffer& kek, const std::string& blobB64) {
    std::vector<uint8_t> blob = encoding::base64Decode(blobB64);
    const std::size_t minLen = crypto::kNonceBytes + crypto::kTagBytes;
    if (blob.size() < minLen) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "wrapped key too short");
    }
    const uint8_t* nonce = blob.data();
    const uint8_t* ct = blob.data() + crypto::kNonceBytes;
    const std::size_t ctLen = blob.size() - crypto::kNonceBytes - crypto::kTagBytes;
    const uint8_t* tag = blob.data() + crypto::kNonceBytes + ctLen;
    try {
        return crypto::aesGcmDecrypt(kek.data(), nonce, ct, ctLen, tag,
                                     reinterpret_cast<const uint8_t*>(kWrapAad),
                                     sizeof(kWrapAad) - 1);
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::IncorrectPassword);
    }
}

// Format 32 raw bytes as grouped uppercase base32 with dashes for printing.
std::string formatRecoveryKey(const std::vector<uint8_t>& raw) {
    const std::string b32 = encoding::base32Encode(raw);
    std::string out;
    for (std::size_t i = 0; i < b32.size(); ++i) {
        if (i > 0 && i % 4 == 0) out.push_back('-');
        out.push_back(b32[i]);
    }
    return out;
}

// Derive the recovery Key-Encryption-Key from the raw recovery bytes via HKDF,
// giving domain separation from any other use of those bytes.
// A fixed all-zero salt is used; the `info` label provides the separation and
// the recovery bytes are already full-entropy keying material.
SecureBuffer deriveRecoveryKek(const SecureBuffer& recoveryRaw) {
    const std::vector<uint8_t> salt(crypto::kSaltBytes, 0x00);
    return crypto::hkdfSha256(recoveryRaw, salt, kRecoveryInfo, crypto::kKeyBytes);
}

// Decode a printed recovery key (base32, any spacing) into its 32 raw key bytes.
SecureBuffer recoveryKeyToBytes(const std::string& recoveryKey) {
    std::vector<uint8_t> bytes;
    try {
        bytes = encoding::base32Decode(recoveryKey);
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::IncorrectPassword, "recovery key not valid base32");
    }
    if (bytes.size() != crypto::kKeyBytes) {
        secureZero(bytes.data(), bytes.size());
        throw CipherPathsError(ErrorCode::IncorrectPassword, "recovery key wrong length");
    }
    SecureBuffer key(bytes.data(), bytes.size());
    secureZero(bytes.data(), bytes.size());
    return key;
}

} // namespace

struct VaultManager::Header {
    std::string magic;
    int version = kVersion;
    std::string kdf = kKdfName;
    std::vector<uint8_t> salt;            // Argon2id password salt
    uint32_t iterations = 0;              // Argon2id time cost
    uint32_t memoryKiB = 0;               // Argon2id memory cost (KiB)
    uint32_t parallelism = 0;             // Argon2id lanes
    std::vector<uint8_t> hkdfSalt;        // fixed salt for sub-key derivation
    std::string wrappedVaultKey;          // base64
    std::string recoveryWrappedVaultKey;  // base64
    std::string created;
    std::vector<std::string> tags;        // hardcoded tag list
    std::string headerMac;                // base64 HMAC-SHA256 over the header
};

// True if `rootFolder` already contains a vault header file.
bool VaultManager::vaultExists(const std::filesystem::path& rootFolder) {
    std::error_code ec;
    return std::filesystem::exists(rootFolder / kHeaderFileName, ec);
}

// Read, parse and sanity-check the vault header JSON; throws on any inconsistency.
VaultManager::Header VaultManager::readHeader(const std::filesystem::path& rootFolder) {
    std::error_code ec;
    if (!std::filesystem::exists(rootFolder, ec)) {
        throw CipherPathsError(ErrorCode::MissingVaultFolder, rootFolder.string());
    }
    const auto path = rootFolder / kHeaderFileName;
    std::ifstream in(path, std::ios::binary);
    if (!in) throw CipherPathsError(ErrorCode::MissingVaultHeader, path.string());
    std::stringstream ss;
    ss << in.rdbuf();

    JsonValue j;
    try {
        j = JsonValue::parse(ss.str());
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "header JSON parse failed");
    }

    Header h;
    h.magic = j.getString("magic");
    if (h.magic != kMagic) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "bad magic");
    }
    if (!j.contains("kdf") ||
        j.at("version").asNumber() != kVersion ||
        j.getString("kdf") != kKdfName ||
        j.at("iterations").asNumber() < crypto::kArgon2MinIterations ||
        j.at("iterations").asNumber() > crypto::kArgon2MaxIterations ||
        j.at("iterations").asNumber() != static_cast<uint32_t>(j.at("iterations").asNumber()) ||
        !j.contains("memoryKiB") ||
        j.at("memoryKiB").asNumber() != crypto::kArgon2MemoryKiB ||
        !j.contains("parallelism") ||
        j.at("parallelism").asNumber() != crypto::kArgon2Parallelism ||
        !j.contains("hkdfSalt")) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "unsupported KDF parameters");
    }
    h.version = kVersion;
    h.kdf = kKdfName;
    try {
        h.salt = encoding::base64Decode(j.getString("salt"));
        h.hkdfSalt = encoding::base64Decode(j.getString("hkdfSalt"));
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "invalid KDF salt");
    }
    h.iterations = static_cast<uint32_t>(j.at("iterations").asNumber());
    h.memoryKiB = crypto::kArgon2MemoryKiB;
    h.parallelism = crypto::kArgon2Parallelism;
    h.wrappedVaultKey = j.getString("wrappedVaultKey");
    h.recoveryWrappedVaultKey = j.getString("recoveryWrappedVaultKey");
    h.created = j.getString("created");
    if (j.contains("tags")) {
        for (const auto& tag : j.at("tags").items()) {
            h.tags.push_back(tag.asString());
        }
    }
    h.headerMac = j.getString("headerMac", "");
    const std::size_t wrappedKeyBytes = crypto::kNonceBytes + crypto::kKeyBytes + crypto::kTagBytes;
    try {
        if (h.salt.size() != crypto::kSaltBytes ||
            h.hkdfSalt.size() != crypto::kSaltBytes ||
            encoding::base64Decode(h.wrappedVaultKey).size() != wrappedKeyBytes ||
            encoding::base64Decode(h.recoveryWrappedVaultKey).size() != wrappedKeyBytes) {
            throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "invalid key material length");
        }
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "invalid wrapped key");
    }
    return h;
}

// Serialise `h` to JSON and write it to the vault root via a temp-file rename.
void VaultManager::writeHeader(const std::filesystem::path& rootFolder, const Header& h) {
    JsonValue j = JsonValue::makeObject();
    j["magic"] = h.magic;
    j["version"] = h.version;
    j["kdf"] = h.kdf;
    j["salt"] = encoding::base64Encode(h.salt);
    j["iterations"] = static_cast<double>(h.iterations);
    j["memoryKiB"] = static_cast<double>(h.memoryKiB);
    j["parallelism"] = static_cast<double>(h.parallelism);
    j["hkdfSalt"] = encoding::base64Encode(h.hkdfSalt);
    j["wrappedVaultKey"] = h.wrappedVaultKey;
    j["recoveryWrappedVaultKey"] = h.recoveryWrappedVaultKey;
    j["created"] = h.created;

    JsonValue tagsArray = JsonValue::makeArray();
    for (const auto& tag : h.tags) {
        tagsArray.push_back(JsonValue(tag));
    }
    j["tags"] = tagsArray;
    j["headerMac"] = h.headerMac;

    const auto finalPath = rootFolder / kHeaderFileName;
    const auto tmpPath = rootFolder / (std::string(kHeaderFileName) + ".tmp");
    {
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out) throw CipherPathsError(ErrorCode::FailedSave, finalPath.string());
        const std::string text = j.dump(true);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.flush();
        if (!out) throw CipherPathsError(ErrorCode::FailedSave, finalPath.string());
    }
    std::error_code ec;
    std::filesystem::rename(tmpPath, finalPath, ec);
    if (ec) {
        std::filesystem::remove(finalPath, ec);
        std::filesystem::rename(tmpPath, finalPath, ec);
        if (ec) throw CipherPathsError(ErrorCode::FailedSave, finalPath.string());
    }
}

// Build the deterministic, length-prefixed byte string that the header MAC covers.
std::string VaultManager::headerMacInput(const Header& h) {
    // Deterministic serialization of every authenticated field (everything
    // except headerMac itself). Field values are length-prefixed so no
    // combination of contents can be confused for another.
    std::string s;
    auto add = [&s](const std::string& v) {
        s += std::to_string(v.size());
        s += ':';
        s += v;
        s += '|';
    };
    add(h.magic);
    add(std::to_string(h.version));
    add(h.kdf);
    add(encoding::base64Encode(h.salt));
    add(std::to_string(h.iterations));
    add(std::to_string(h.memoryKiB));
    add(std::to_string(h.parallelism));
    add(encoding::base64Encode(h.hkdfSalt));
    add(h.wrappedVaultKey);
    add(h.recoveryWrappedVaultKey);
    add(h.created);
    for (const auto& t : h.tags) add(t);
    return s;
}

// Compute the base64 HMAC-SHA256 of the header under `macKey`.
std::string VaultManager::computeHeaderMac(const Header& h, const SecureBuffer& macKey) {
    const std::string input = headerMacInput(h);
    const auto mac = crypto::hmacSha256(
        macKey.data(), macKey.size(),
        reinterpret_cast<const uint8_t*>(input.data()), input.size());
    return encoding::base64Encode(mac.data(), mac.size());
}

// Recompute the header MAC from the VMK and constant-time compare it; throws on mismatch.
void VaultManager::verifyHeaderMac(const Header& h, const SecureBuffer& vmk) {
    if (h.headerMac.empty()) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "missing header MAC");
    }
    SecureBuffer macKey = crypto::hkdfSha256(vmk, h.hkdfSalt, kHeaderMacInfo,
                                             crypto::kKeyBytes);
    const std::string expected = computeHeaderMac(h, macKey);
    if (expected.size() != h.headerMac.size() ||
        !crypto::constantTimeEquals(
            reinterpret_cast<const uint8_t*>(expected.data()),
            reinterpret_cast<const uint8_t*>(h.headerMac.data()),
            expected.size())) {
        throw CipherPathsError(ErrorCode::CorruptedVaultHeader, "header MAC mismatch");
    }
}

// Create a new vault: generate the VMK, wrap it under the password and a fresh
// recovery key, write the authenticated header, and return the unlocked vault.
CreateVaultResult VaultManager::create(const std::filesystem::path& rootFolder,
                                       std::string_view masterPassword,
                                       uint32_t iterations,
                                       std::size_t namePadMultiple) {
    if (masterPassword.empty()) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "master password cannot be empty");
    }
    if (iterations != 0 &&
        (iterations < crypto::kArgon2MinIterations ||
         iterations > crypto::kArgon2MaxIterations)) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "Argon2id iterations out of range");
    }
    std::error_code ec;
    std::filesystem::create_directories(rootFolder, ec);
    if (ec) throw CipherPathsError(ErrorCode::PermissionDenied, rootFolder.string());
    if (vaultExists(rootFolder)) {
        throw CipherPathsError(ErrorCode::AlreadyExists, "vault already initialised");
    }

    Header h;
    h.magic = kMagic;
    h.version = kVersion;
    h.kdf = kKdfName;
    h.salt = crypto::randomBytes(crypto::kSaltBytes);
    h.iterations = iterations ? iterations : crypto::calibrateIterations();
    h.memoryKiB = crypto::kArgon2MemoryKiB;
    h.parallelism = crypto::kArgon2Parallelism;
    h.hkdfSalt = crypto::randomBytes(crypto::kSaltBytes);
    h.created = isoNow();
    h.tags = {"banking", "gaming", "shopping", "work", "personal", "other"};

    // Generate the Vault Master Key.
    std::vector<uint8_t> vmkRaw = crypto::randomBytes(crypto::kKeyBytes);
    SecureBuffer vmk(vmkRaw.data(), vmkRaw.size());
    secureZero(vmkRaw.data(), vmkRaw.size());

    // Wrap with the password-derived KEK.
    SecureBuffer passwordKek = crypto::argon2idDerive(masterPassword, h.salt,
                                                      h.iterations, h.memoryKiB,
                                                      h.parallelism, crypto::kKeyBytes);
    h.wrappedVaultKey = wrapKey(passwordKek, vmk);
    passwordKek.wipe();

    // Wrap with a fresh recovery key (run through HKDF for domain separation).
    std::vector<uint8_t> recoveryRaw = crypto::randomBytes(crypto::kKeyBytes);
    SecureBuffer recoveryRawKey(recoveryRaw.data(), recoveryRaw.size());
    SecureBuffer recoveryKek = deriveRecoveryKek(recoveryRawKey);
    h.recoveryWrappedVaultKey = wrapKey(recoveryKek, vmk);
    recoveryKek.wipe();
    recoveryRawKey.wipe();
    const std::string recoveryKey = formatRecoveryKey(recoveryRaw);
    secureZero(recoveryRaw.data(), recoveryRaw.size());

    // Authenticate the plaintext header with a VMK-derived MAC key.
    SecureBuffer macKey = crypto::hkdfSha256(vmk, h.hkdfSalt, kHeaderMacInfo,
                                             crypto::kKeyBytes);
    h.headerMac = computeHeaderMac(h, macKey);
    macKey.wipe();

    writeHeader(rootFolder, h);

    CreateVaultResult result;
    result.vault = std::make_shared<Vault>(rootFolder, vmk, h.hkdfSalt, namePadMultiple);
    result.recoveryKey = recoveryKey;
    return result;
}

// Unlock an existing vault with the master password; throws IncorrectPassword on failure.
std::shared_ptr<Vault> VaultManager::unlock(const std::filesystem::path& rootFolder,
                                            std::string_view masterPassword,
                                            std::size_t namePadMultiple) {
    if (masterPassword.empty()) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "master password cannot be empty");
    }
    Header h = readHeader(rootFolder);
    SecureBuffer kek = crypto::argon2idDerive(masterPassword, h.salt, h.iterations,
                                              h.memoryKiB, h.parallelism,
                                              crypto::kKeyBytes);
    SecureBuffer vmk = unwrapKey(kek, h.wrappedVaultKey);
    kek.wipe();
    verifyHeaderMac(h, vmk);
    return std::make_shared<Vault>(rootFolder, vmk, h.hkdfSalt, namePadMultiple);
}

// Unlock an existing vault with the printed recovery key instead of the password.
std::shared_ptr<Vault> VaultManager::unlockWithRecoveryKey(
    const std::filesystem::path& rootFolder, const std::string& recoveryKey,
    std::size_t namePadMultiple) {
    Header h = readHeader(rootFolder);
    if (h.recoveryWrappedVaultKey.empty()) {
        throw CipherPathsError(ErrorCode::IncorrectPassword, "no recovery key configured");
    }
    SecureBuffer recoveryRaw = recoveryKeyToBytes(recoveryKey);
    SecureBuffer kek = deriveRecoveryKek(recoveryRaw);
    SecureBuffer vmk = unwrapKey(kek, h.recoveryWrappedVaultKey);
    kek.wipe();
    recoveryRaw.wipe();
    verifyHeaderMac(h, vmk);
    return std::make_shared<Vault>(rootFolder, vmk, h.hkdfSalt, namePadMultiple);
}

// Change the master password by re-wrapping the VMK; no encrypted file is touched.
void VaultManager::changePassword(const std::filesystem::path& rootFolder,
                                  std::string_view currentPassword,
                                  std::string_view newPassword,
                                  uint32_t iterations) {
    if (newPassword.empty()) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "master password cannot be empty");
    }
    if (iterations != 0 &&
        (iterations < crypto::kArgon2MinIterations ||
         iterations > crypto::kArgon2MaxIterations)) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "Argon2id iterations out of range");
    }
    Header h = readHeader(rootFolder);
    SecureBuffer oldKek = crypto::argon2idDerive(currentPassword, h.salt, h.iterations,
                                                 h.memoryKiB, h.parallelism,
                                                 crypto::kKeyBytes);
    SecureBuffer vmk = unwrapKey(oldKek, h.wrappedVaultKey);
    oldKek.wipe();
    verifyHeaderMac(h, vmk);

    // Re-wrap with a fresh password salt and (re)calibrated iteration count.
    // The hkdfSalt is left UNCHANGED so the VMK-derived sub-keys stay identical
    // and every already-encrypted file/name remains decryptable.
    h.salt = crypto::randomBytes(crypto::kSaltBytes);
    h.iterations = iterations ? iterations : crypto::calibrateIterations();
    h.memoryKiB = crypto::kArgon2MemoryKiB;
    h.parallelism = crypto::kArgon2Parallelism;
    SecureBuffer newKek = crypto::argon2idDerive(newPassword, h.salt, h.iterations,
                                                 h.memoryKiB, h.parallelism,
                                                 crypto::kKeyBytes);
    h.wrappedVaultKey = wrapKey(newKek, vmk);
    newKek.wipe();
    // recoveryWrappedVaultKey is left unchanged (still valid for the same VMK).

    // Re-authenticate the header (VMK, and therefore the MAC key, are unchanged).
    SecureBuffer macKey = crypto::hkdfSha256(vmk, h.hkdfSalt, kHeaderMacInfo,
                                             crypto::kKeyBytes);
    h.headerMac = computeHeaderMac(h, macKey);
    macKey.wipe();
    writeHeader(rootFolder, h);
}

// Return an advisory "Weak"/"Fair"/"Good"/"Strong" label from length and character mix.
std::string VaultManager::passwordStrengthHint(const std::string& password) {
    bool lower = false, upper = false, digit = false, symbol = false;
    for (unsigned char c : password) {
        if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= 'A' && c <= 'Z') upper = true;
        else if (c >= '0' && c <= '9') digit = true;
        else symbol = true;
    }
    const int classes = lower + upper + digit + symbol;
    const std::size_t len = password.size();
    if (len < 8 || classes <= 1) return "Weak";
    if (len < 12 || classes == 2) return "Fair";
    if (len < 16 || classes == 3) return "Good";
    return "Strong";
}

} // namespace cipherpaths