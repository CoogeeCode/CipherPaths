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

// CipherPaths Core - Viewer service implementation.
#include "cipherpaths/ViewerService.h"

#include <algorithm>
#include <cctype>

namespace cipherpaths {

namespace {
// Return the lowercased file extension of `name` (without the dot), or "".
std::string extLower(const std::string& name) {
    const auto dot = name.find_last_of('.');
    if (dot == std::string::npos) return {};
    std::string ext = name.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char> (std::tolower(c)); });
    return ext;
}
} // namespace

// True if the bytes begin with the JPEG SOI marker (FF D8 FF).
bool ViewerService::looksLikeJpeg(const uint8_t* data, std::size_t len) {
    return len >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
}

// True if the bytes begin with the 8-byte PNG signature.
bool ViewerService::looksLikePng(const uint8_t* data, std::size_t len) {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A ("\x89PNG\r\n\x1a\n").
    static const uint8_t kSig[8] = {0x89, 0x50, 0x4E, 0x47,
                                    0x0D, 0x0A, 0x1A, 0x0A};
    if (len < sizeof(kSig)) return false;
    for (std::size_t i = 0; i < sizeof(kSig); ++i) {
        if (data[i] != kSig[i]) return false;
    }
    return true;
}

// True if the bytes contain the PDF signature ("%PDF-") near the start.
bool ViewerService::looksLikePdf(const uint8_t* data, std::size_t len) {
    // PDF files begin with "%PDF-" (25 50 44 46 2D). Some files carry a few
    // junk bytes before the header, so scan a small prefix window.
    static const uint8_t kSig[5] = {0x25, 0x50, 0x44, 0x46, 0x2D};
    if (len < sizeof(kSig)) return false;
    const std::size_t limit = std::min<std::size_t>(len - sizeof(kSig) + 1, 1024);
    for (std::size_t off = 0; off < limit; ++off) {
        bool match = true;
        for (std::size_t i = 0; i < sizeof(kSig); ++i) {
            if (data[off + i] != kSig[i]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

// Heuristic: true if a sample of the bytes looks like UTF-8 / ASCII text.
bool ViewerService::looksLikeText(const uint8_t* data, std::size_t len) {
    if (len == 0) return true;
    const std::size_t sample = std::min<std::size_t>(len, 4096);
    std::size_t suspicious = 0;
    for (std::size_t i = 0; i < sample; ++i) {
        const uint8_t c = data[i];
        if (c == 0) return false; // NUL byte => binary
        if (c < 0x09 || (c > 0x0D && c < 0x20)) ++suspicious;
    }
    return suspicious * 100 / sample < 5; // <5% control chars
}

// Classify a decrypted file by extension, then by content sniffing, into a ViewerKind.
ViewerKind ViewerService::classify(const std::string& plaintextName,
                                   const uint8_t* content, std::size_t len) {
    const std::string ext = extLower(plaintextName);

    static const char* kTextExts[] = {"txt", "md", "json", "log", "csv", "xml",
                                      "ini", "cfg", "yml", "yaml", "cpp", "h",
                                      "c", "py", "js", "html", "css", "sh", "bat", "bak"};
    for (const char* t : kTextExts) {
        if (ext == t) return ViewerKind::Text;
    }
    if (ext == "jpg" || ext == "jpeg") return ViewerKind::Jpeg;
    if (ext == "png") return ViewerKind::Png;
    if (ext == "pdf") return ViewerKind::Pdf;

    // Common video containers played by the Media Foundation viewer. Actual
    // playback still depends on the codecs installed on the machine (H.264/AAC
    // in an .mp4 always works on Win10/11); classification here just routes the
    // file to the video window rather than the "unsupported" message.
    static const char* kVideoExts[] = {"mp4", "m4v", "mov", "avi",
                                       "wmv", "mkv", "webm"};
    for (const char* v : kVideoExts) {
        if (ext == v) return ViewerKind::Video;
    }

    // Fall back to content sniffing when the extension is unknown.
    if (content && len > 0) {
        if (looksLikeJpeg(content, len)) return ViewerKind::Jpeg;
        if (looksLikePng(content, len)) return ViewerKind::Png;
        if (looksLikePdf(content, len)) return ViewerKind::Pdf;
        if (looksLikeText(content, len)) return ViewerKind::Text;
    }
    return ViewerKind::Unsupported;
}

} // namespace cipherpaths
