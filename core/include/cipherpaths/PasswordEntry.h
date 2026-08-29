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

// CipherPaths Core - Password entry service.
// Manages the encrypted, hidden ##credentials##.json file that may exist in each
// TOP-LEVEL folder. Sub-folders must not have one (any such file is ignored).
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "EncryptedFileSystem.h"

namespace cipherpaths {

struct WebCredential {
    std::string url;
    std::string username;
    std::string password;
    std::string twoFactorType;
};

struct CreditCardCredential {
    std::string cardholderName;
    std::string cardNumber;
    std::string expiryDate;
    std::string cvv;
    std::string issuer;
};

struct ContactCredential {
    std::string fullName;
    std::string email;
    std::string phoneNumber;
    std::string address;
    std::string city;
    std::string state;
    std::string postalCode;
    std::string country;
    std::string dateOfBirth;
};

using CredentialData = std::variant<WebCredential, CreditCardCredential, ContactCredential>;

struct Credential {
    std::string type;
    std::vector<std::string> tags;
    std::string dateCreated;
    std::string lastUpdated;
    std::string passwordUpdated;
    CredentialData data;
};

struct PasswordEntry {
    std::string folderName;
    Credential credential;
};

class PasswordEntryService {
public:
    static constexpr char kFileName[] = "##credentials##.json";

    explicit PasswordEntryService(EncryptedFileSystem& efs) : efs_(efs) {}

    /// Load the credential for a top-level folder, or nullopt if none exists.
    /// Throws InvalidJson if the file exists but is malformed.
    std::optional<PasswordEntry> load(const std::filesystem::path& topLevelFolder) const;

    /// Create or update the credential for a top-level folder.
    void save(const std::filesystem::path& topLevelFolder, const PasswordEntry& entry);

    /// Mask a password for display.
    static std::string mask(const std::string& password);

    /// Serialise/parse the JSON form (exposed for testing).
    static std::string toJson(const PasswordEntry& entry);
    static PasswordEntry fromJson(const std::string& json);

    /// Check if credential data is a specific type.
    static bool isWebCredential(const Credential& cred) { return cred.type == "web"; }
    static bool isCreditCardCredential(const Credential& cred) { return cred.type == "creditcard"; }
    static bool isContactCredential(const Credential& cred) { return cred.type == "contact"; }

    /// Get the variant value with bounds checking (returns nullptr if type doesn't match).
    static WebCredential* getWebCredential(Credential& cred);
    static const WebCredential* getWebCredential(const Credential& cred);
    static CreditCardCredential* getCreditCardCredential(Credential& cred);
    static const CreditCardCredential* getCreditCardCredential(const Credential& cred);
    static ContactCredential* getContactCredential(Credential& cred);
    static const ContactCredential* getContactCredential(const Credential& cred);

private:
    EncryptedFileSystem& efs_;
};

} // namespace cipherpaths
