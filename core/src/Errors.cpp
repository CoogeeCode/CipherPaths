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

// CipherPaths Core - Error descriptions.
#include "cipherpaths/Errors.h"

namespace cipherpaths {

// Return a fixed human-readable description for an error code.
const char* describe(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Ok:                  return "Success";
        case ErrorCode::IncorrectPassword:   return "Incorrect master password or recovery key";
        case ErrorCode::MissingVaultFolder:  return "Vault folder does not exist";
        case ErrorCode::MissingVaultHeader:  return "Vault header file is missing";
        case ErrorCode::CorruptedFile:       return "Encrypted file is corrupted or has been tampered with";
        case ErrorCode::CorruptedVaultHeader:return "Vault header is corrupted or unreadable";
        case ErrorCode::UnsupportedFileType: return "This file type cannot be previewed yet";
        case ErrorCode::NotCipherPathsEntry: return "Entry was not created by CipherPaths (missing magic prefix)";
        case ErrorCode::FailedImport:        return "Failed to import the source file";
        case ErrorCode::FailedSave:          return "Failed to save the encrypted file";
        case ErrorCode::FailedRename:        return "Failed to rename the item";
        case ErrorCode::PermissionDenied:    return "Permission denied";
        case ErrorCode::DiskFull:            return "Not enough disk space";
        case ErrorCode::AlreadyExists:       return "An item with this name already exists in the folder";
        case ErrorCode::NotFound:            return "Item not found in the vault";
        case ErrorCode::InvalidJson:         return "Invalid JSON content";
        case ErrorCode::NameTooLong:         return "Name is too long to encode for this file system";
        case ErrorCode::CryptoFailure:       return "An internal cryptographic operation failed";
        case ErrorCode::InvalidArgument:     return "Invalid argument";
    }
    return "Unknown error";
}

} // namespace cipherpaths
