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

// CipherPaths Core - Binary <-> text encodings.
// Portable C++. Three encodings are provided:
//   * Base64url (RFC 4648 §5 URL-safe alphabet) for ON-DISK FILE NAMES. This is
//     standard Base64 with '+' replaced by '-' and '/' replaced by '_', so the
//     result contains none of the characters reserved on NTFS/exFAT
//     (\\ / : * ? " < > | ). The '=' padding character is kept because it is
//     filename-safe and keeps decoding unambiguous. Base64url is more compact
//     than Base32 while still avoiding reserved characters.
//   * Base32 (RFC 4648 alphabet, no padding) retained for the printed recovery
//     key (grouped, case-insensitive, human-transcribable).
//   * Base64 (standard alphabet) for values stored inside the vault header JSON
//     and the exported recovery key file, where case is preserved.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipherpaths::encoding {

/// Encode bytes to an uppercase Base32 string with no padding.
std::string base32Encode(const uint8_t* data, std::size_t len);
inline std::string base32Encode(const std::vector<uint8_t>& v) {
    return base32Encode(v.data(), v.size());
}

/// Decode an uppercase Base32 string (padding optional). Throws on invalid chars.
std::vector<uint8_t> base32Decode(const std::string& text);

/// Base64url encode (URL-safe alphabet: '+' -> '-', '/' -> '_') WITH '='
/// padding. Used for on-disk encrypted file names.
std::string base64urlEncode(const uint8_t* data, std::size_t len);
inline std::string base64urlEncode(const std::vector<uint8_t>& v) {
    return base64urlEncode(v.data(), v.size());
}

/// Decode a Base64url string (accepts '-'/'_' as well as the standard '+'/'/'
/// for robustness; '=' padding optional). Throws on invalid chars.
std::vector<uint8_t> base64urlDecode(const std::string& text);

/// Standard Base64 encode / decode (with '=' padding).
std::string base64Encode(const uint8_t* data, std::size_t len);
inline std::string base64Encode(const std::vector<uint8_t>& v) {
    return base64Encode(v.data(), v.size());
}
std::vector<uint8_t> base64Decode(const std::string& text);

} // namespace cipherpaths::encoding
