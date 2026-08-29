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

// CipherPaths Core - Unlocked vault and derived keys.
// A Vault is produced by VaultManager once a master password (or recovery key)
// has successfully unwrapped the Vault Master Key (VMK). It owns the derived
// sub-keys and a NameCodec, and exposes the vault root path. Keys live only in
// memory and are wiped on destruction (via SecureBuffer).
#pragma once

#include <filesystem>
#include <memory>
#include <string>

#include "Crypto.h"
#include "NameCodec.h"

namespace cipherpaths {

/// Sub-keys derived from the Vault Master Key via HKDF-HMAC-SHA256, using
/// distinct `info` context strings for domain separation.
struct VaultKeys {
    SecureBuffer content;   // file CONTENT encryption key
    SecureBuffer name;      // file/folder NAME encryption key
};

class Vault {
public:
    Vault(std::filesystem::path root, const SecureBuffer& masterKey,
          const std::vector<uint8_t>& salt,
          std::size_t namePadMultiple = NameCodec::kDefaultPadMultiple);

    const std::filesystem::path& root() const { return root_; }
    const NameCodec& nameCodec() const { return *nameCodec_; }
    const SecureBuffer& contentKey() const { return keys_.content; }

    // HKDF context labels (kept public so tools/tests can reason about them).
    static constexpr char kContentInfo[] = "cipherpaths:content-key:v1";
    static constexpr char kNameInfo[]    = "cipherpaths:name-key:v1";

private:
    std::filesystem::path root_;
    VaultKeys keys_;
    std::unique_ptr<NameCodec> nameCodec_;
};

} // namespace cipherpaths
