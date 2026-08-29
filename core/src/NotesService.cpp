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

// CipherPaths Core - Notes service implementation.
#include "cipherpaths/NotesService.h"

namespace cipherpaths {

// True if the folder contains an encrypted notes file.
bool NotesService::exists(const std::filesystem::path& folder) const {
    return efs_.findChild(folder, kFileName).has_value();
}

// Decrypt and return the folder's notes text, or nullopt if there is none.
std::optional<std::string> NotesService::load(const std::filesystem::path& folder) const {
    auto child = efs_.findChild(folder, kFileName);
    if (!child) return std::nullopt;
    SecureBuffer plain = efs_.readFile(child->diskPath);
    return std::string(reinterpret_cast<const char*>(plain.data()), plain.size());
}

// Encrypt and write `text` as the folder's notes file, creating or overwriting it.
void NotesService::save(const std::filesystem::path& folder, const std::string& text) {
    efs_.writeNewFile(folder, kFileName,
                      reinterpret_cast<const uint8_t*>(text.data()), text.size(),
                      /*overwrite=*/true);
}

} // namespace cipherpaths
