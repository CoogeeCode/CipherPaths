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

// CipherPaths Core - Vault lifecycle.
// Creates new vaults, unlocks existing ones with the master password or the
// recovery key, and changes the master password by re-wrapping the Vault Master
// Key (no bulk re-encryption required).
#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include "Vault.h"

namespace cipherpaths {

/// Result of creating a new vault: the unlocked vault plus the one-time
/// recovery key string that must be shown to (and saved by) the user.
struct CreateVaultResult {
    std::shared_ptr<Vault> vault;
    std::string recoveryKey;   // grouped base32, e.g. "ABCD-EFGH-...".
};

class VaultManager {
public:
    /// On-disk header file name (plaintext) stored in the vault root.
    static constexpr char kHeaderFileName[] = "cipherpaths-vault.json";
    static constexpr char kMagic[] = "CipherPaths Vault";
    static constexpr int kVersion = 1;

    /// True if `rootFolder` already contains a CipherPaths vault header.
    static bool vaultExists(const std::filesystem::path& rootFolder);

    /// Create a brand new vault in `rootFolder` (must be an existing, empty-ish
    /// directory). Generates the VMK, wraps it with the password-derived key and
    /// a fresh recovery key, and writes the header. `iterations` of 0 means
    /// "calibrate automatically". `namePadMultiple` seeds the vault's NameCodec
    /// (see NameCodec::kDefaultPadMultiple); it is a UI/config preference, not
    /// part of the persisted header, so it is passed in fresh on every open.
    static CreateVaultResult create(const std::filesystem::path& rootFolder,
                                    std::string_view masterPassword,
                                    uint32_t iterations = 0,
                                    std::size_t namePadMultiple = NameCodec::kDefaultPadMultiple);

    /// Unlock an existing vault with the master password. Throws
    /// IncorrectPassword if authentication fails.
    static std::shared_ptr<Vault> unlock(const std::filesystem::path& rootFolder,
                                         std::string_view masterPassword,
                                         std::size_t namePadMultiple = NameCodec::kDefaultPadMultiple);

    /// Unlock using the printed recovery key (any spacing/dashes are ignored).
    static std::shared_ptr<Vault> unlockWithRecoveryKey(
        const std::filesystem::path& rootFolder,
        const std::string& recoveryKey,
        std::size_t namePadMultiple = NameCodec::kDefaultPadMultiple);

    /// Change the master password by re-wrapping the VMK. Does not touch any
    /// encrypted file. Returns nothing; throws on wrong current password.
    static void changePassword(const std::filesystem::path& rootFolder,
                               std::string_view currentPassword,
                               std::string_view newPassword,
                               uint32_t iterations = 0);

    /// Estimate a strength label for UI warnings. Purely
    /// advisory; never blocks the user.
    static std::string passwordStrengthHint(const std::string& password);

private:
    struct Header; // defined in the .cpp
    static Header readHeader(const std::filesystem::path& rootFolder);
    static void writeHeader(const std::filesystem::path& rootFolder, const Header& h);

    // Header authentication. The MAC key is derived from the
    // VMK, so the header can only be verified after a successful unwrap.
    static std::string headerMacInput(const Header& h);
    static std::string computeHeaderMac(const Header& h, const SecureBuffer& macKey);
    static void verifyHeaderMac(const Header& h, const SecureBuffer& vmk);
};

} // namespace cipherpaths
