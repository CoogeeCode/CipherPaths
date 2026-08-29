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

// CipherPaths Core - Encrypted name codec.
// Encodes a plaintext file/folder name into an on-disk name of the form:
//     CP#1<T><base64url( nonce || AES-256-GCM(name||padding) || tag )>
// where <T> is a single record-type tag character (see kRecordTypeNone). The
// tag lets the UI colour a top-level folder's tile by record type WITHOUT
// decrypting the folder's credential file - the type is read straight from the
// on-disk name. It is authenticated (bound into the AES-GCM AAD) so it cannot
// be silently tampered with.
// The plaintext is padded with random bytes up to the next multiple of a fixed
// block size (a Padme-style length-hiding scheme) before encryption, so the
// on-disk name only reveals the name length rounded up to that block size
// rather than its exact value. Short names therefore stay short on disk (unlike
// a single fixed maximum length), which keeps paths within the tight file-name
// and path-length limits imposed by services such as OneDrive. Folders and
// files use the same scheme; the file system itself records whether an entry is
// a file or a directory.
#pragma once

#include <string>

#include "Crypto.h"

namespace cipherpaths {

class NameCodec {
public:
    /// Four character header "CP#1" = CipherPaths Name format, version 1.
    static constexpr char kHeader[] = "CP#1";
    static constexpr std::size_t kHeaderLen = 4;

    /// A single record-type tag character stored on disk immediately after the
    /// header (offset kHeaderLen). It is an opaque tag from the core's point of
    /// view - the UI layer assigns meaning (e.g. '1'=web, '2'=credit card).
    /// '0' means "no type / not applicable" (files, sub-folders).
    static constexpr char kRecordTypeNone = '0';

    /// Length of the plaintext prefix before the base64url payload
    /// (header + one record-type character).
    static constexpr std::size_t kPrefixLen = kHeaderLen + 1;

    /// Number of leading bytes in the plaintext block that store the true name
    /// length (a single byte, so names are limited to 255 bytes anyway).
    static constexpr std::size_t kLenBytes = 1;

    /// Padme-style block granularity, in bytes. The plaintext block
    /// ([len][name][random padding]) is padded up to the next multiple of this
    /// value, so the smallest block is padMultiple bytes, then 2x, 3x, ...
    /// This hides the exact name length while keeping short names short.
	/// Initially this was 10, but file systems like OneDrive have a 400-character limit
	/// on the full path, so we need to keep the on-disk names as short as possible.
    /// User-configurable (config dialog "Filename padding" setting); a value of
    /// 0 disables padding entirely (the block is exactly [len][name], no
    /// rounding). This only affects newly-encoded names - decode() does not
    /// depend on the padding multiple, so existing on-disk names remain
    /// readable after the setting changes.
    static constexpr std::size_t kDefaultPadMultiple = 3;

    /// Largest permitted plaintext block, in bytes. Chosen so the final
    /// base64url on-disk name (prefix + base64url(nonce ‖ ciphertext ‖ tag))
    /// stays within the 255-character NTFS/exFAT limit.
    static constexpr std::size_t kMaxBlockLen = 150;

    /// Maximum length of an original name, in UTF-8 bytes.
    static constexpr std::size_t kMaxNameBytes = kMaxBlockLen - kLenBytes;

    /// `nameKey` must be 32 bytes (derived from the Vault Master Key via HKDF).
    /// `padMultiple` is the Padme block granularity used by encode() (see
    /// kDefaultPadMultiple above); 0 disables padding.
    explicit NameCodec(const SecureBuffer& nameKey,
                       std::size_t padMultiple = kDefaultPadMultiple);

    /// Encrypt `plaintextName` into a filesystem-safe on-disk name, tagging it
    /// with the single record-type character `recordType` (default: none).
    /// Throws NameTooLong if the name exceeds kMaxNameBytes UTF-8 bytes.
    std::string encode(const std::string& plaintextName,
                       char recordType = kRecordTypeNone) const;

    /// Decrypt an on-disk name back to its plaintext form.
    /// Throws NotCipherPathsEntry if the name lacks the CP#1 prefix,
    /// or CorruptedFile if authentication fails.
    std::string decode(const std::string& diskName) const;

    /// True if `diskName` begins with the CP#1 magic header (and carries the
    /// record-type tag character).
    static bool hasMagic(const std::string& diskName);

    /// The record-type tag character of an on-disk name, WITHOUT decrypting it.
    /// Returns kRecordTypeNone if `diskName` is not a CipherPaths entry.
    static char recordTypeChar(const std::string& diskName);

private:
    SecureBuffer nameKey_;
    std::size_t padMultiple_;
};

} // namespace cipherpaths
