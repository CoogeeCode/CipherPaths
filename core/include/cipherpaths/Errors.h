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

// CipherPaths Core - Error handling
// Portable C++ (no platform dependencies). See README for build instructions.
#pragma once

#include <stdexcept>
#include <string>

namespace cipherpaths {

/// Stable error codes for every recoverable failure in the core library.
/// The Windows UI layer maps these to user facing messages.
enum class ErrorCode {
    Ok = 0,
    IncorrectPassword,     // Master password / recovery key did not authenticate
    MissingVaultFolder,    // Vault root folder does not exist
    MissingVaultHeader,    // vault header file not found
    CorruptedFile,         // AES-GCM authentication failed / truncated data
    CorruptedVaultHeader,  // Vault header JSON malformed or fails authentication
    UnsupportedFileType,   // Viewer cannot preview this file
    NotCipherPathsEntry,   // File/folder name lacks the CP#1 magic prefix
    FailedImport,          // Could not read a source file being imported
    FailedSave,            // Could not write encrypted data
    FailedRename,          // Could not rename an entry (not a lock/permission issue)
    PermissionDenied,      // OS denied access
    DiskFull,              // No space left on device
    AlreadyExists,         // Duplicate name in the same folder
    NotFound,              // Logical entry not found in the vault
    InvalidJson,           // password.json or header JSON parse error
    NameTooLong,           // Original name exceeds the encodable limit
    CryptoFailure,         // Unexpected OpenSSL failure
    InvalidArgument        // Programmer / caller error
};

/// Human readable description for an error code.
const char* describe(ErrorCode code) noexcept;

/// Exception type thrown by the core library. Carries a stable ErrorCode plus
/// an optional contextual message (e.g. the offending path).
class CipherPathsError : public std::runtime_error {
public:
    CipherPathsError(ErrorCode code, const std::string& context = {})
        : std::runtime_error(buildMessage(code, context)), code_(code) {}

    ErrorCode code() const noexcept { return code_; }

private:
    static std::string buildMessage(ErrorCode code, const std::string& context) {
        std::string msg = describe(code);
        if (!context.empty()) {
            msg += " (";
            msg += context;
            msg += ")";
        }
        return msg;
    }

    ErrorCode code_;
};

} // namespace cipherpaths
