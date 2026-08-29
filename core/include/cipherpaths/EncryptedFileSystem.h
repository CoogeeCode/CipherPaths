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

// CipherPaths Core - Encrypted file system layer.
// Mirrors a plaintext folder hierarchy onto disk where every file and folder
// name is encrypted (CP#1 format) and every file's CONTENT is encrypted with
// AES-256-GCM. All operations are expressed in terms of plaintext names; this
// layer transparently encrypts/decrypts names and content. Entries written by
// other tools (lacking the CP#1 magic) are ignored.
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "SecureBuffer.h"
#include "Vault.h"
#include "NameCodec.h"

namespace cipherpaths {

/// A decrypted directory entry.
struct Entry {
    std::string name;                 // decrypted plaintext name
    std::filesystem::path diskPath;   // absolute on-disk path (encrypted name)
    bool isDirectory = false;
    std::uintmax_t encryptedSize = 0; // bytes on disk
    // Record-type tag read straight from the on-disk name (no decryption).
    // '0' (kRecordTypeNone) for files and untyped folders.
    char recordTypeCode = NameCodec::kRecordTypeNone;
};

class EncryptedFileSystem {
public:
    /// File content container magic: "CipherPaths File", version 1.
    static constexpr char kContentMagic[] = "CPF1";
    static constexpr std::size_t kContentMagicLen = 4;

    explicit EncryptedFileSystem(std::shared_ptr<Vault> vault);

    /// Top-level folders directly under the vault root (left pane).
    std::vector<Entry> listTopLevelFolders() const;

    /// Contents (files + subfolders) of a directory on disk.
    std::vector<Entry> list(const std::filesystem::path& diskDir) const;

    /// Resolve a logical path (plaintext components from the root) to a disk
    /// path. Returns nullopt if any component does not exist.
    std::optional<Entry> resolve(const std::vector<std::string>& components) const;

    /// Find an immediate child by plaintext name (case-insensitive, NTFS-like).
    std::optional<Entry> findChild(const std::filesystem::path& diskDir,
                                   const std::string& name) const;

    /// Create a new (empty) folder; throws AlreadyExists on duplicate name.
    /// `recordType` tags the on-disk name so the folder's record type can be
    /// determined without decrypting its credential file (default: none).
    Entry createFolder(const std::filesystem::path& parentDir, const std::string& name,
                       char recordType = NameCodec::kRecordTypeNone);

    /// Import a plaintext file from disk, encrypting its contents and name.
    /// The source file is left untouched.
    Entry importFile(const std::filesystem::path& parentDir,
                     const std::filesystem::path& sourceFile,
                     std::optional<std::string> nameOverride = std::nullopt);

    /// Recursively import a folder tree (drag & drop folders).
    Entry importFolder(const std::filesystem::path& parentDir,
                       const std::filesystem::path& sourceFolder,
                       std::optional<std::string> nameOverride = std::nullopt);

    /// Create or overwrite a file from an in-memory buffer (used for
    /// ##password##.json and ##notes##.txt).
    Entry writeNewFile(const std::filesystem::path& parentDir, const std::string& name,
                       const uint8_t* data, std::size_t len, bool overwrite = false);

    /// Decrypt a file's contents into memory.
    SecureBuffer readFile(const std::filesystem::path& diskFile) const;

    /// Overwrite an existing file's contents atomically.
    void writeFile(const std::filesystem::path& diskFile,
                   const uint8_t* data, std::size_t len);

    /// Rename a file or folder by re-encrypting its name.
    Entry rename(const std::filesystem::path& diskPath, const std::string& newName);

    /// Move a file/folder into another directory (optionally renaming).
    Entry move(const std::filesystem::path& diskPath,
               const std::filesystem::path& destDir,
               std::optional<std::string> newName = std::nullopt);

    /// Delete a file or (recursively) a folder. No trash.
    void remove(const std::filesystem::path& diskPath);

    /// Export (decrypt) a file to the regular file system. If a name collision
    /// occurs at the destination, a "(n)" suffix is appended.
    std::filesystem::path exportFile(const std::filesystem::path& diskFile,
                                     const std::filesystem::path& destDir) const;

    /// Export (decrypt) a folder tree to the regular file system.
    std::filesystem::path exportFolder(const std::filesystem::path& diskFolder,
                                       const std::filesystem::path& destDir) const;

    /// Decrypt the plaintext name of an entry.
    std::string decryptName(const std::filesystem::path& diskPath) const;

    Vault& vault() { return *vault_; }

private:
    std::vector<uint8_t> encryptContent(const uint8_t* data, std::size_t len) const;
    SecureBuffer decryptContent(const std::vector<uint8_t>& blob) const;
    void atomicWrite(const std::filesystem::path& target,
                     const uint8_t* data, std::size_t len) const;
    void ensureNoDuplicate(const std::filesystem::path& dir, const std::string& name) const;

    std::shared_ptr<Vault> vault_;
};

} // namespace cipherpaths
