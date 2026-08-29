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

// CipherPaths Core - Viewer service.
// Classifies a decrypted file so the UI can route it to the correct built-in
// viewer (text editor, JPG/PNG image viewer) or show an "unsupported" message.
// The classification is portable; the actual rendering lives in the UI layer.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipherpaths {

enum class ViewerKind {
    Text,        // built-in text viewer / editor
    Jpeg,        // built-in JPG viewer
    Png,         // built-in PNG viewer
    Pdf,         // built-in PDF viewer (WebView2, streamed from memory)
    Video,       // built-in video player (Media Foundation, streamed from memory)
    Unsupported  // cannot preview yet
};

class ViewerService {
public:
    /// Classify by plaintext name extension and (optionally) content sniffing.
    static ViewerKind classify(const std::string& plaintextName,
                               const uint8_t* content = nullptr,
                               std::size_t len = 0);

    /// True if the bytes look like UTF-8 / ASCII text (heuristic).
    static bool looksLikeText(const uint8_t* data, std::size_t len);

    /// True if the bytes begin with the JPEG SOI marker (FF D8 FF).
    static bool looksLikeJpeg(const uint8_t* data, std::size_t len);

    /// True if the bytes begin with the 8-byte PNG signature.
    static bool looksLikePng(const uint8_t* data, std::size_t len);

    /// True if the bytes begin with the PDF signature ("%PDF-").
    static bool looksLikePdf(const uint8_t* data, std::size_t len);
};

} // namespace cipherpaths
