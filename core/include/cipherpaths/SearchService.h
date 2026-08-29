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

// CipherPaths Core - Search service
// Performs an in-memory search over decrypted file/folder names and the URL /
// username fields of ##password##.json entries. No on-disk index is created.
#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "EncryptedFileSystem.h"
#include "PasswordEntry.h"

namespace cipherpaths {

struct SearchHit {
    enum class Kind { FileName, FolderName, CredentialUrl, CredentialUsername, NotesText, FileContent, EncryptedName };
    Kind kind;
    std::string displayName;             // decrypted name of the matching entry
    std::vector<std::string> logicalPath;// plaintext path components from the root
    std::filesystem::path diskPath;      // on-disk location
    std::string context;                 // matched field / snippet
    // Whether diskPath is a folder or a file. Kind alone is not enough to tell:
    // an EncryptedName hit can land on either, since the encrypted-name search
    // walks both files and folders under the same Kind.
    bool isDirectory = false;
};

class SearchService {
public:
    explicit SearchService(EncryptedFileSystem& efs) : efs_(efs) {}

    /// Basic search (MVP): names, credential URLs and usernames.
    std::vector<SearchHit> search(const std::string& query) const;

    /// Advanced search additionally scans notes and text file contents.
    std::vector<SearchHit> searchAdvanced(const std::string& query) const;

private:
    void walk(const std::filesystem::path& dir, std::vector<std::string>& path,
              const std::string& needleLower, bool advanced,
              std::vector<SearchHit>& out) const;

    EncryptedFileSystem& efs_;
};

} // namespace cipherpaths
