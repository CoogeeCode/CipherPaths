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

// CipherPaths Core - Encrypted name codec implementation.
#include "cipherpaths/NameCodec.h"

#include "cipherpaths/Encoding.h"
#include "cipherpaths/Errors.h"

#include <cstring>
#include <array>

namespace cipherpaths {

namespace {
// AAD binds the ciphertext to the format header AND the record-type tag byte,
// so the tag character cannot be altered on disk without failing decryption.
// Layout: "CP#1" (kHeaderLen bytes) followed by the single record-type char.
std::array<uint8_t, NameCodec::kPrefixLen> makeAad(char recordType) {
    std::array<uint8_t, NameCodec::kPrefixLen> aad{};
    std::memcpy(aad.data(), NameCodec::kHeader, NameCodec::kHeaderLen);
    aad[NameCodec::kHeaderLen] = static_cast<uint8_t>(recordType);
    return aad;
}
} // namespace

// Construct with the 32-byte name key and the Padme padding block size.
NameCodec::NameCodec(const SecureBuffer& nameKey, std::size_t padMultiple)
    : nameKey_(nameKey.data(), nameKey.size()), padMultiple_(padMultiple) {
    if (nameKey_.size() != crypto::kKeyBytes) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "name key must be 32 bytes");
    }
}

// True if `diskName` starts with the "CP#1" header and carries a type tag byte.
bool NameCodec::hasMagic(const std::string& diskName) {
    return diskName.size() > kPrefixLen &&
           std::memcmp(diskName.data(), kHeader, kHeaderLen) == 0;
}

// Return the record-type tag character of an on-disk name without decrypting it.
char NameCodec::recordTypeChar(const std::string& diskName) {
    if (!hasMagic(diskName)) return kRecordTypeNone;
    return diskName[kHeaderLen];
}

// Encrypt a plaintext name into a filesystem-safe "CP#1" on-disk name.
std::string NameCodec::encode(const std::string& plaintextName,
                              char recordType) const {
    if (plaintextName.empty()) {
        throw CipherPathsError(ErrorCode::InvalidArgument, "empty name");
    }
    if (plaintextName.size() > kMaxNameBytes) {
        throw CipherPathsError(ErrorCode::NameTooLong, plaintextName.substr(0, 32));
    }

    // Build the plaintext block: [len][name bytes][random padding], padded with
    // random bytes up to the next multiple of padMultiple_ (a Padme-style
    // length-hiding scheme). Short names stay short on disk; the on-disk length
    // only reveals the true length rounded up to padMultiple_ bytes. A
    // padMultiple_ of 0 (or 1) disables padding: the block is exactly
    // [len][name], with no rounding.
    const std::size_t rawLen = kLenBytes + plaintextName.size();
    const std::size_t blockLen = (padMultiple_ <= 1)
        ? rawLen
        : ((rawLen + padMultiple_ - 1) / padMultiple_) * padMultiple_;

    SecureBuffer block(blockLen);
    block[0] = static_cast<uint8_t>(plaintextName.size());
    std::memcpy(block.data() + kLenBytes, plaintextName.data(), plaintextName.size());
    // Random padding for the unused tail (hides the true length).
    const std::size_t padOffset = kLenBytes + plaintextName.size();
    const std::size_t padLen = blockLen - padOffset;
    if (padLen > 0) {
        crypto::randomBytes(block.data() + padOffset, padLen);
    }

    // Fresh 96-bit nonce per name.
    uint8_t nonce[crypto::kNonceBytes];
    crypto::randomBytes(nonce, sizeof(nonce));

    const auto aad = makeAad(recordType);
    auto enc = crypto::aesGcmEncrypt(nameKey_.data(), nonce,
                                     block.data(), block.size(),
                                     aad.data(), aad.size());

    // Assemble binary payload: nonce || ciphertext || tag.
    std::vector<uint8_t> payload;
    payload.reserve(crypto::kNonceBytes + enc.ciphertext.size() + crypto::kTagBytes);
    payload.insert(payload.end(), nonce, nonce + crypto::kNonceBytes);
    payload.insert(payload.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    payload.insert(payload.end(), enc.tag.begin(), enc.tag.end());

    return std::string(kHeader) + recordType +
           encoding::base64urlEncode(payload);
}

// Decrypt a "CP#1" on-disk name back to its plaintext form.
std::string NameCodec::decode(const std::string& diskName) const {
    if (!hasMagic(diskName)) {
        throw CipherPathsError(ErrorCode::NotCipherPathsEntry, diskName.substr(0, 16));
    }
    const char recordType = diskName[kHeaderLen];
    const std::string encoded = diskName.substr(kPrefixLen);
    std::vector<uint8_t> payload = encoding::base64urlDecode(encoded);

    const std::size_t minLen = crypto::kNonceBytes + crypto::kTagBytes;
    if (payload.size() < minLen + 1) {
        throw CipherPathsError(ErrorCode::CorruptedFile, "name payload too short");
    }

    const uint8_t* nonce = payload.data();
    const uint8_t* ct = payload.data() + crypto::kNonceBytes;
    const std::size_t ctLen = payload.size() - crypto::kNonceBytes - crypto::kTagBytes;
    const uint8_t* tag = payload.data() + crypto::kNonceBytes + ctLen;

    const auto aad = makeAad(recordType);
    SecureBuffer block = crypto::aesGcmDecrypt(nameKey_.data(), nonce,
                                               ct, ctLen, tag,
                                               aad.data(), aad.size());
    if (block.empty()) {
        throw CipherPathsError(ErrorCode::CorruptedFile, "empty name block");
    }
    const std::size_t nameLen = block[0];
    if (nameLen == 0 || nameLen + kLenBytes > block.size()) {
        throw CipherPathsError(ErrorCode::CorruptedFile, "bad name length");
    }
    return std::string(reinterpret_cast<const char*>(block.data() + kLenBytes), nameLen);
}

} // namespace cipherpaths
