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

// CipherPaths Core - Secure memory buffer
// Portable C++. Holds sensitive material (keys, decrypted content) and zeroes
// memory on destruction.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace cipherpaths {

/// Securely wipe a region of memory. Uses a volatile pointer so the compiler
/// cannot optimise the clear away. (OpenSSL_cleanse equivalent, kept dependency
/// free so SecureBuffer can be used in headers without pulling in OpenSSL.)
inline void secureZero(void* data, std::size_t len) noexcept {
    if (data == nullptr || len == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (len--) {
        *p++ = 0;
    }
}

/// A byte buffer whose contents are zeroed on destruction and on reset.
/// Move-only by default semantics are allowed; copies are explicit.
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size) : data_(size, 0) {}
    SecureBuffer(const uint8_t* data, std::size_t size) : data_(data, data + size) {}

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    ~SecureBuffer() { wipe(); }

    uint8_t* data() noexcept { return data_.data(); }
    const uint8_t* data() const noexcept { return data_.data(); }
    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }

    uint8_t& operator[](std::size_t i) noexcept { return data_[i]; }
    const uint8_t& operator[](std::size_t i) const noexcept { return data_[i]; }

    void resize(std::size_t n) { data_.resize(n); }
    void assign(const uint8_t* p, std::size_t n) { wipe(); data_.assign(p, p + n); }

    std::vector<uint8_t>& vec() noexcept { return data_; }
    const std::vector<uint8_t>& vec() const noexcept { return data_; }

    /// Zero the contents but keep capacity.
    void wipe() noexcept {
        if (!data_.empty()) {
            secureZero(data_.data(), data_.size());
        }
    }

private:
    std::vector<uint8_t> data_;
};

} // namespace cipherpaths
