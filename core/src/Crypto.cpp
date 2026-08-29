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

// CipherPaths Core - Cryptography service implementation (OpenSSL backed).
#include "cipherpaths/Crypto.h"

#include "cipherpaths/Errors.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include <chrono>

namespace cipherpaths::crypto {

namespace {

// Raise a CryptoFailure error carrying the name of the failed operation.
[[noreturn]] void cryptoFail(const std::string& what) {
    throw CipherPathsError(ErrorCode::CryptoFailure, what);
}

} // namespace

// Fill `out` with `n` cryptographically secure random bytes.
void randomBytes(uint8_t* out, std::size_t n) {
    if (n == 0) return;
    if (RAND_bytes(out, static_cast<int>(n)) != 1) {
        cryptoFail("RAND_bytes failed");
    }
}

// Return a vector of `n` cryptographically secure random bytes.
std::vector<uint8_t> randomBytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
    randomBytes(buf.data(), n);
    return buf;
}

// Derive `outLen` key bytes from a password and salt with Argon2id (OpenSSL KDF).
SecureBuffer argon2idDerive(std::string_view password,
                            const std::vector<uint8_t>& salt,
                            uint32_t iterations,
                            uint32_t memoryKiB,
                            uint32_t parallelism,
                            std::size_t outLen) {
    SecureBuffer out(outLen);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (!kdf) cryptoFail("Argon2id not available in this OpenSSL build");
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) cryptoFail("Argon2id ctx alloc failed");

    uint32_t threads = parallelism;
    OSSL_PARAM params[7];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD,
        const_cast<char*>(password.data()), password.size());
    params[i++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        const_cast<uint8_t*>(salt.data()), salt.size());
    params[i++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    params[i++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &parallelism);
    params[i++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
    params[i++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memoryKiB);
    params[i++] = OSSL_PARAM_construct_end();

    const int rc = EVP_KDF_derive(kctx, out.data(), outLen, params);
    EVP_KDF_CTX_free(kctx);
    if (rc != 1) cryptoFail("Argon2id derivation failed");
    return out;
}

// Compute the HMAC-SHA256 tag of `data` under `key`.
std::array<uint8_t, 32> hmacSha256(const uint8_t* key, std::size_t keyLen,
                                   const uint8_t* data, std::size_t dataLen) {
    std::array<uint8_t, 32> mac{};
    unsigned int macLen = 0;
    const unsigned char* rc = HMAC(EVP_sha256(), key, static_cast<int>(keyLen),
                                   data, dataLen, mac.data(), &macLen);
    if (!rc || macLen != mac.size()) cryptoFail("HMAC-SHA256 failed");
    return mac;
}

// Derive `outLen` bytes from input keying material with HKDF-SHA256 (`info` separates domains).
SecureBuffer hkdfSha256(const uint8_t* ikm, std::size_t ikmLen,
                        const std::vector<uint8_t>& salt,
                        const std::string& info,
                        std::size_t outLen) {
    SecureBuffer out(outLen);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) cryptoFail("HKDF ctx alloc failed");

    bool ok = EVP_PKEY_derive_init(pctx) == 1
        && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1
        && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) == 1
        && EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikmLen)) == 1
        && EVP_PKEY_CTX_add1_hkdf_info(pctx,
               reinterpret_cast<const unsigned char*>(info.data()),
               static_cast<int>(info.size())) == 1;

    std::size_t len = outLen;
    if (ok) {
        ok = EVP_PKEY_derive(pctx, out.data(), &len) == 1 && len == outLen;
    }
    EVP_PKEY_CTX_free(pctx);
    if (!ok) cryptoFail("HKDF-HMAC-SHA256 derivation failed");
    return out;
}

// Encrypt `plaintext` with AES-256-GCM, returning the ciphertext and auth tag.
GcmCiphertext aesGcmEncrypt(const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* plaintext, std::size_t plaintextLen,
                            const uint8_t* aad, std::size_t aadLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cryptoFail("EVP_CIPHER_CTX_new failed");

    GcmCiphertext result;
    result.ciphertext.resize(plaintextLen);

    int outl = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceBytes, nullptr) == 1
        && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;

    if (ok && aad && aadLen > 0) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aadLen)) == 1;
    }
    if (ok && plaintextLen > 0) {
        ok = EVP_EncryptUpdate(ctx, result.ciphertext.data(), &outl,
                               plaintext, static_cast<int>(plaintextLen)) == 1;
    }
    if (ok) {
        int finalLen = 0;
        ok = EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + outl, &finalLen) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagBytes,
                                 result.tag.data()) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) cryptoFail("AES-256-GCM encryption failed");
    return result;
}

// Decrypt and authenticate an AES-256-GCM ciphertext; throws CorruptedFile if the tag fails.
SecureBuffer aesGcmDecrypt(const uint8_t* key,
                           const uint8_t* nonce,
                           const uint8_t* ciphertext, std::size_t ciphertextLen,
                           const uint8_t* tag,
                           const uint8_t* aad, std::size_t aadLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) cryptoFail("EVP_CIPHER_CTX_new failed");

    SecureBuffer plaintext(ciphertextLen);
    int outl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceBytes, nullptr) == 1
        && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;

    if (ok && aad && aadLen > 0) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aadLen)) == 1;
    }
    if (ok && ciphertextLen > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                               ciphertext, static_cast<int>(ciphertextLen)) == 1;
    }
    // Set the expected tag, then finalise. Final returns <= 0 if authentication fails.
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagBytes,
                                 const_cast<uint8_t*>(tag)) == 1;
    }
    bool authenticated = false;
    if (ok) {
        int finalLen = 0;
        authenticated = EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &finalLen) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) cryptoFail("AES-256-GCM decryption setup failed");
    if (!authenticated) {
        // Wrong key or tampered data: wipe and report.
        plaintext.wipe();
        throw CipherPathsError(ErrorCode::CorruptedFile, "GCM authentication failed");
    }
    return plaintext;
}

// Pick an Argon2id iteration count so one derivation takes roughly `targetMs` on this machine.
uint32_t calibrateIterations(uint32_t targetMs) {
    constexpr uint32_t kMinIterations = kArgon2MinIterations;
    constexpr uint32_t kMaxIterations = kArgon2MaxIterations;

    // Time a single-pass Argon2id derivation at the fixed memory cost, then
    // scale the time cost linearly to hit the target duration.
    const std::vector<uint8_t> salt(kSaltBytes, 0x5A);
    const std::string pw = "calibration-probe";

    const auto start = std::chrono::steady_clock::now();
    (void)argon2idDerive(pw, salt, 1, kArgon2MemoryKiB, kArgon2Parallelism, kKeyBytes);
    const auto end = std::chrono::steady_clock::now();

    const double ms = std::chrono::duration<double, std::milli>(end - start).count();
    if (ms <= 0.0) return kMinIterations;

    double iters = static_cast<double>(targetMs) / ms;
    if (iters < kMinIterations) iters = kMinIterations;
    if (iters > kMaxIterations) iters = kMaxIterations;
    return static_cast<uint32_t>(iters);
}

// Compare two equal-length buffers without leaking timing information.
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, std::size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

// Return the human-readable version string of the linked OpenSSL library.
std::string opensslVersion() {
    return OpenSSL_version(OPENSSL_VERSION);
}

} // namespace cipherpaths::crypto
