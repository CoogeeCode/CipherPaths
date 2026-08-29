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

// CipherPaths Core - Binary <-> text encodings implementation.
#include "cipherpaths/Encoding.h"

#include "cipherpaths/Errors.h"

namespace cipherpaths::encoding {

namespace {
constexpr char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Map one Base32 character to its 5-bit value, or -1 if it is not valid.
int base32Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';   // accept lowercase defensively
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}
} // namespace

// Encode bytes as an unpadded uppercase Base32 string (RFC 4648 alphabet).
std::string base32Encode(const uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t buffer = 0;
    int bits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kBase32Alphabet[(buffer >> bits) & 0x1F]);
        }
    }
    if (bits > 0) {
        out.push_back(kBase32Alphabet[(buffer << (5 - bits)) & 0x1F]);
    }
    return out;
}

// Decode Base32 text back to bytes, skipping '=' padding, spaces and '-'.
std::vector<uint8_t> base32Decode(const std::string& text) {
    std::vector<uint8_t> out;
    out.reserve(text.size() * 5 / 8);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == ' ' || c == '-') continue; // ignore padding/separators
        const int v = base32Value(c);
        if (v < 0) throw CipherPathsError(ErrorCode::InvalidArgument, "bad base32 char");
        buffer = (buffer << 5) | static_cast<uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// Encode bytes as URL-safe (filename-safe) Base64 with '=' padding.
std::string base64urlEncode(const uint8_t* data, std::size_t len) {
    // Standard Base64 followed by the URL-safe character substitution. Keeping
    // '=' padding (it is filename-safe) means the length is always a multiple
    // of four, which makes decoding unambiguous.
    std::string out = base64Encode(data, len);
    for (char& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

// Decode a URL-safe (or standard) Base64 string back to bytes.
std::vector<uint8_t> base64urlDecode(const std::string& text) {
    // Map the URL-safe alphabet back to the standard one, then reuse the
    // standard Base64 decoder. Standard '+'/'/' are accepted too, so a value
    // produced by either encoder round-trips.
    std::string std64;
    std64.reserve(text.size());
    for (char c : text) {
        if (c == '-') std64.push_back('+');
        else if (c == '_') std64.push_back('/');
        else std64.push_back(c);
    }
    return base64Decode(std64);
}

// Encode bytes as a standard Base64 string with '=' padding.
std::string base64Encode(const uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 2 < len; i += 3) {
        const uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kBase64Alphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(n >> 12) & 0x3F]);
        out.push_back(kBase64Alphabet[(n >> 6) & 0x3F]);
        out.push_back(kBase64Alphabet[n & 0x3F]);
    }
    const std::size_t rem = len - i;
    if (rem == 1) {
        const uint32_t n = data[i] << 16;
        out.push_back(kBase64Alphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(n >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(kBase64Alphabet[(n >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(n >> 12) & 0x3F]);
        out.push_back(kBase64Alphabet[(n >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

// Decode a standard Base64 string back to bytes, skipping padding/whitespace.
std::vector<uint8_t> base64Decode(const std::string& text) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(text.size() * 3 / 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        const int v = val(c);
        if (v < 0) throw CipherPathsError(ErrorCode::InvalidArgument, "bad base64 char");
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace cipherpaths::encoding
