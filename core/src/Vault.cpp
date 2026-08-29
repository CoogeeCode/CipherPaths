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

// CipherPaths Core - Unlocked vault implementation.
#include "cipherpaths/Vault.h"

namespace cipherpaths {

// Build an unlocked vault: derive the content and name sub-keys from the Vault
// Master Key and create the NameCodec for on-disk names.
Vault::Vault(std::filesystem::path root, const SecureBuffer& masterKey,
             const std::vector<uint8_t>& salt, std::size_t namePadMultiple)
    : root_(std::move(root)) {
    // Derive separate sub-keys from the Vault Master Key.
    keys_.content = crypto::hkdfSha256(masterKey, salt, kContentInfo, crypto::kKeyBytes);
    keys_.name    = crypto::hkdfSha256(masterKey, salt, kNameInfo,    crypto::kKeyBytes);

    nameCodec_ = std::make_unique<NameCodec>(keys_.name, namePadMultiple);
}

} // namespace cipherpaths
