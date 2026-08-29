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

// CipherPaths Core - Notes service.
// Manages the encrypted ##notes##.txt file that may exist in any folder.
#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "EncryptedFileSystem.h"

namespace cipherpaths {

class NotesService {
public:
    static constexpr char kFileName[] = "##notes##.txt";

    explicit NotesService(EncryptedFileSystem& efs) : efs_(efs) {}

    /// Decrypt the notes for a folder, or nullopt if there are none.
    std::optional<std::string> load(const std::filesystem::path& folder) const;

    /// Encrypt and save notes for a folder (creates or overwrites the file).
    void save(const std::filesystem::path& folder, const std::string& text);

    /// True if the folder has a notes file.
    bool exists(const std::filesystem::path& folder) const;

private:
    EncryptedFileSystem& efs_;
};

} // namespace cipherpaths
