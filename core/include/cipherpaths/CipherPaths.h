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

// CipherPaths Core - umbrella header.
// Include this single header to access the whole portable core library
// (CipherPathsCore). The core has NO platform dependencies beyond OpenSSL and
// the C++20 standard library, so it can be reused by the Windows UI layer and a
// future Linux command-line front-end.
#pragma once

#include "Errors.h"
#include "SecureBuffer.h"
#include "Crypto.h"
#include "Encoding.h"
#include "Json.h"
#include "NameCodec.h"
#include "Vault.h"
#include "VaultManager.h"
#include "EncryptedFileSystem.h"
#include "PasswordEntry.h"
#include "NotesService.h"
#include "SearchService.h"
#include "ViewerService.h"

namespace cipherpaths {
inline constexpr int kCoreVersionMajor = 0;
inline constexpr int kCoreVersionMinor = 9;
inline constexpr int kCoreVersionPatch = 4;
inline constexpr const char* kCoreVersion = "0.9.4";
} // namespace cipherpaths
