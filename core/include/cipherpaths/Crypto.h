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

// CipherPaths Core - Cryptography service
// Portable C++ wrapper around OpenSSL. Provides the only
// primitives the rest of the core needs:
//   * AES-256-GCM authenticated encryption (96-bit nonce, 128-bit tag)
//   * Argon2id password-based key derivation (memory-hard)
//   * HKDF-HMAC-SHA256 key separation
//   * HMAC-SHA256 for authenticating the vault header
//   * Cryptographically secure random bytes
// All functions throw cipherpaths::CipherPathsError on failure.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "SecureBuffer.h"

namespace cipherpaths::crypto {

inline constexpr std::size_t kKeyBytes = 32;   // AES-256 key
inline constexpr std::size_t kNonceBytes = 12; // 96-bit GCM nonce
inline constexpr std::size_t kTagBytes = 16;   // 128-bit GCM tag
inline constexpr std::size_t kSaltBytes = 32;  // Argon2id salt

// Argon2id parameters. Memory cost dominates GPU/ASIC
// resistance; the time cost (iterations) is calibrated at vault creation.
inline constexpr uint32_t kArgon2MemoryKiB     = 65536; // 64 MiB per derivation
inline constexpr uint32_t kArgon2Parallelism   = 1;     // single lane (portable)
inline constexpr uint32_t kArgon2MinIterations = 3;     // floor on the time cost
inline constexpr uint32_t kArgon2MaxIterations = 40;

/// Fill a buffer with cryptographically secure random bytes.
std::vector<uint8_t> randomBytes(std::size_t n);
void randomBytes(uint8_t* out, std::size_t n);

/// Argon2id password hashing. Derives `outLen` bytes from a password and salt
/// using the given time cost (`iterations`), memory cost (KiB) and parallelism.
SecureBuffer argon2idDerive(std::string_view password,
                            const std::vector<uint8_t>& salt,
                            uint32_t iterations,
                            uint32_t memoryKiB,
                            uint32_t parallelism,
                            std::size_t outLen);

/// HMAC-SHA256 over `data` keyed by `key`. Returns the 32-byte tag. Used to
/// authenticate the plaintext vault header.
std::array<uint8_t, 32> hmacSha256(const uint8_t* key, std::size_t keyLen,
                                   const uint8_t* data, std::size_t dataLen);

/// HKDF-HMAC-SHA256 (extract + expand). Derives a sub-key from input keying
/// material using a context string (`info`) for domain separation.
SecureBuffer hkdfSha256(const uint8_t* ikm, std::size_t ikmLen,
                        const std::vector<uint8_t>& salt,
                        const std::string& info,
                        std::size_t outLen);

inline SecureBuffer hkdfSha256(const SecureBuffer& ikm,
                               const std::vector<uint8_t>& salt,
                               const std::string& info,
                               std::size_t outLen) {
    return hkdfSha256(ikm.data(), ikm.size(), salt, info, outLen);
}

/// Result of an AES-256-GCM encryption: ciphertext followed by the 16-byte tag
/// is NOT concatenated here; the tag is returned separately for clarity.
struct GcmCiphertext {
    std::vector<uint8_t> ciphertext;        // same length as the plaintext
    std::array<uint8_t, kTagBytes> tag{};   // authentication tag
};

/// AES-256-GCM encrypt. `key` must be 32 bytes, `nonce` 12 bytes. `aad` is
/// optional additional authenticated data (not encrypted, but integrity bound).
GcmCiphertext aesGcmEncrypt(const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* plaintext, std::size_t plaintextLen,
                            const uint8_t* aad, std::size_t aadLen);

/// AES-256-GCM decrypt. Throws CipherPathsError(CorruptedFile) if the tag does
/// not authenticate (wrong key, tampering, or truncation).
SecureBuffer aesGcmDecrypt(const uint8_t* key,
                           const uint8_t* nonce,
                           const uint8_t* ciphertext, std::size_t ciphertextLen,
                           const uint8_t* tag,
                           const uint8_t* aad, std::size_t aadLen);

/// Calibrate the Argon2id time cost (iteration count) so that one derivation
/// at the fixed memory cost takes roughly `targetMs` milliseconds on this
/// machine, clamped to a minimum (kArgon2MinIterations) and a sensible
/// maximum.
uint32_t calibrateIterations(uint32_t targetMs = 800);

/// Constant-time comparison of two equal-length buffers.
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, std::size_t len);

/// Human-readable version string of the OpenSSL library linked at runtime
/// (e.g. "OpenSSL 3.5.0"). Useful for About/diagnostics screens.
std::string opensslVersion();

} // namespace cipherpaths::crypto