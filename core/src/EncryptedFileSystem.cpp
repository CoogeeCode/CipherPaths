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

// CipherPaths Core - Encrypted file system layer implementation.
#include "cipherpaths/EncryptedFileSystem.h"

#include "cipherpaths/Crypto.h"
#include "cipherpaths/Encoding.h"
#include "cipherpaths/Errors.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cstring>
#include <fstream>

namespace fs = std::filesystem;

namespace cipherpaths {

    namespace {

        // ---------------------------------------------------------------------------
        // Windows long-path (MAX_PATH) support
        // ---------------------------------------------------------------------------
        //
        // The Win32 file APIs that std::filesystem ultimately calls are historically
        // limited to MAX_PATH (260) characters. Because CipherPaths encrypts every
        // path component into a fixed ~200-character "CP#1" Base64url name, even a shallow
        // vault hierarchy can blow past 260 characters and then create_directory /
        // create file calls fail with "path too long", so files and folders cannot be
        // created on Windows.
        //
        // Windows lifts that limit to ~32,767 characters when the path is given in the
        // extended-length form, i.e. prefixed with "\\?\". That form has strict rules:
        //   * the path MUST be absolute (no "." / ".." and no relative paths);
        //   * it MUST use backslashes (the prefix disables the usual '/'->'\' fixup);
        //   * a UNC path "\\server\share\..." must instead be written as
        //     "\\?\UNC\server\share\...".
        //
        // makeWindowsLongPath() converts a path into that form on Windows and is a
        // pure no-op on every other platform (POSIX has no MAX_PATH-style limit), so
        // the existing Linux/macOS behaviour is completely unchanged. It is defined
        // inline in this anonymous namespace so there are no linkage issues and the
        // symbol never escapes this translation unit.
        //
        // Every std::filesystem call and every std::fstream open below passes its path
        // argument through this helper. The helper is idempotent: a path that already
        // starts with "\\?\" is returned unchanged, so wrapping a path twice is safe.

#if defined(_WIN32)

        inline std::filesystem::path makeWindowsLongPath(const std::filesystem::path& p) {
            if (p.empty()) return p;

            // The extended-length prefix requires an absolute path. Convert relative
            // paths against the current working directory; fall back to the original
            // path if that fails for any reason.
            std::error_code ec;
            fs::path abs = p.is_absolute() ? p : fs::absolute(p, ec);
            if (ec) abs = p;

            // Work on the native (wide) representation.
            std::wstring native = abs.native();
            if (native.empty()) return abs;

            // Already in extended-length form -> leave it untouched (idempotent).
            if (native.rfind(L"\\\\?\\", 0) == 0) return abs;

            // The prefix disables automatic separator translation, so normalise any
            // forward slashes to backslashes first.
            std::replace(native.begin(), native.end(), L'/', L'\\');

            std::wstring prefixed;
            if (native.rfind(L"\\\\", 0) == 0) {
                // UNC path "\\server\share\..." -> "\\?\UNC\server\share\..."
                // Strip the leading "\\" and splice in the "\\?\UNC\" prefix.
                prefixed = L"\\\\?\\UNC\\" + native.substr(2);
            }
            else {
                // Drive-letter path "C:\..." -> "\\?\C:\..."
                prefixed = L"\\\\?\\" + native;
            }
            return fs::path(prefixed);
        }

#else // !_WIN32

// POSIX: no MAX_PATH limitation of this kind; return the path unchanged.
        inline std::filesystem::path makeWindowsLongPath(const std::filesystem::path& p) {
            return p;
        }

#endif // _WIN32

        // Convenience alias so the call sites below stay terse and readable.
        inline std::filesystem::path lp(const std::filesystem::path& p) {
            return makeWindowsLongPath(p);
        }

        // True when `ec` (as left by fs::rename / fs::remove / fs::remove_all)
        // indicates the failure was another process having the entry open,
        // rather than something else (disk full, an unexpected OS error, ...).
        // Distinguishing this lets callers say "it's open elsewhere" instead of
        // a generic "failed to save/rename" that gives no hint of the actual,
        // fixable cause.
        //
        // Raw numeric Win32 error codes are used here (rather than pulling in
        // <windows.h>) to keep this file's platform footprint unchanged - same
        // approach as makeWindowsLongPath above.
#if defined(_WIN32)
        bool isFileInUseError(const std::error_code& ec) {
            constexpr int kErrorSharingViolation = 32;
            constexpr int kErrorLockViolation = 33;
            constexpr int kErrorAccessDenied = 5;
            return ec.value() == kErrorSharingViolation ||
                   ec.value() == kErrorLockViolation ||
                   ec.value() == kErrorAccessDenied;
        }
#else
        bool isFileInUseError(const std::error_code&) { return false; }
#endif

        // Case-insensitive ASCII string equality (NTFS-like name comparison).
        bool iequals(const std::string& a, const std::string& b) {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) !=
                    std::tolower(static_cast<unsigned char>(b[i]))) return false;
            }
            return true;
        }

        // Read an entire file into a byte vector; throws FailedImport on error.
        std::vector<uint8_t> readWholeFile(const fs::path& p) {
            // Open through the long-path helper so deep/long source paths work on Windows.
            std::ifstream in(lp(p), std::ios::binary | std::ios::ate);
            if (!in) throw CipherPathsError(ErrorCode::FailedImport, p.string());
            const std::streamsize size = in.tellg();
            in.seekg(0);
            std::vector<uint8_t> buf(static_cast<std::size_t>(size));
            if (size > 0 && !in.read(reinterpret_cast<char*>(buf.data()), size)) {
                throw CipherPathsError(ErrorCode::FailedImport, p.string());
            }
            return buf;
        }

    } // namespace

    // Construct over an unlocked vault (which must not be null).
    EncryptedFileSystem::EncryptedFileSystem(std::shared_ptr<Vault> vault)
        : vault_(std::move(vault)) {
        if (!vault_) throw CipherPathsError(ErrorCode::InvalidArgument, "null vault");
    }

    // Decrypt the plaintext name of a single on-disk entry.
    std::string EncryptedFileSystem::decryptName(const fs::path& diskPath) const {
        return vault_->nameCodec().decode(diskPath.filename().string());
    }

    // List the decrypted entries of an on-disk directory, folders first then by name.
    std::vector<Entry> EncryptedFileSystem::list(const fs::path& diskDir) const {
        std::vector<Entry> entries;
        std::error_code ec;
        // Scan through the long-path form, but keep the natural (un-prefixed)
        // diskDir for building each entry's stored path so the prefix never leaks
        // into comparisons or the UI.
        const fs::path scanDir = lp(diskDir);
        if (!fs::is_directory(scanDir, ec)) {
            throw CipherPathsError(ErrorCode::NotFound, diskDir.string());
        }
        for (const auto& de : fs::directory_iterator(scanDir, ec)) {
            const std::string diskName = de.path().filename().string();
            // Ignore the vault header and any entry not created by CipherPaths.
            if (!NameCodec::hasMagic(diskName)) continue;
            std::string plaintext;
            try {
                plaintext = vault_->nameCodec().decode(diskName);
            }
            catch (const CipherPathsError&) {
                //If we get here the file name was corrupt, or at least we couldn't decrpyted it
                plaintext = "Error - File name corrupt: " + diskName.substr(0, 10) + "...";
            }
            Entry e;
            e.name = std::move(plaintext);
            e.diskPath = diskDir / diskName; // natural path (no \\?\ prefix)
            e.isDirectory = de.is_directory(ec);
            e.recordTypeCode = NameCodec::recordTypeChar(diskName);
            if (!e.isDirectory) e.encryptedSize = de.file_size(ec);
            entries.push_back(std::move(e));
        }
        std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
            if (a.isDirectory != b.isDirectory) return a.isDirectory > b.isDirectory;
            return iequals(a.name, b.name) ? a.name < b.name
                : std::lexicographical_compare(
                    a.name.begin(), a.name.end(),
                    b.name.begin(), b.name.end(),
                    [](char x, char y) {
                        return std::tolower((unsigned char)x) <
                            std::tolower((unsigned char)y);
                    });
            });
        return entries;
    }

    // List only the folders directly under the vault root.
    std::vector<Entry> EncryptedFileSystem::listTopLevelFolders() const {
        std::vector<Entry> all = list(vault_->root());
        std::vector<Entry> folders;
        for (auto& e : all) {
            if (e.isDirectory) folders.push_back(std::move(e));
        }
        return folders;
    }

    // Find an immediate child of `diskDir` by plaintext name (case-insensitive).
    std::optional<Entry> EncryptedFileSystem::findChild(const fs::path& diskDir,
        const std::string& name) const {
        for (auto& e : list(diskDir)) {
            if (iequals(e.name, name)) return e;
        }
        return std::nullopt;
    }

    // Walk a logical (plaintext) path from the root to its on-disk entry, or nullopt.
    std::optional<Entry> EncryptedFileSystem::resolve(
        const std::vector<std::string>& components) const {
        fs::path cur = vault_->root();
        Entry result;
        result.diskPath = cur;
        result.isDirectory = true;
        result.name.clear();
        for (const auto& comp : components) {
            auto child = findChild(cur, comp);
            if (!child) return std::nullopt;
            result = *child;
            cur = child->diskPath;
        }
        return result;
    }

    // Throw AlreadyExists if `dir` already has a child called `name`.
    void EncryptedFileSystem::ensureNoDuplicate(const fs::path& dir,
        const std::string& name) const {
        if (findChild(dir, name)) {
            throw CipherPathsError(ErrorCode::AlreadyExists, name);
        }
    }

    // ---- content encryption --------------------------------------------------

    namespace {
        // Bytes prepended to the plaintext (little-endian real length) so the
        // Padmé padding that follows can be stripped again on read.
        constexpr std::size_t kLenFieldBytes = 8;

        // Minimum on-disk blob size. 4096 == the default NTFS cluster, so every
        // small (and every zero-length) file is padded up to exactly one cluster:
        // they all look identical in size and cost no extra allocated storage.
        constexpr std::size_t kMinBlobBytes = 4096;

        // Padmé length-hiding padding (see Nikitin et al., "PURBs").
        // Rounds L up so that only the top few significant bits can vary, which
        // bounds the multiplicative overhead to ~12% while leaking at most
        // O(log log L) bits about the true size. Values below 2 are returned
        // unchanged (never reached here because of the 4 KiB floor).
        std::size_t padme(std::size_t L) {
            if (L < 2) return L;
            const int e = std::bit_width(L) - 1;                       // floor(log2 L)
            const int s = std::bit_width(static_cast<std::size_t>(e)); // floor(log2 e)+1
            const int lastBits = e - s;
            if (lastBits <= 0) return L;
            const std::size_t mask = (std::size_t{1} << lastBits) - 1;
            return (L + mask) & ~mask;                                 // round up
        }
    } // namespace

    // Encrypt file content into an on-disk blob: magic + nonce + AES-256-GCM
    // ciphertext of (length-prefixed data + Padmé padding) + tag.
    std::vector<uint8_t> EncryptedFileSystem::encryptContent(const uint8_t* data,
        std::size_t len) const {
        // Fixed on-disk overhead around the padded plaintext.
        const std::size_t overhead = kContentMagicLen + crypto::kNonceBytes + crypto::kTagBytes;
        // Minimum bytes actually needed: overhead + length field + the content.
        const std::size_t rawTotal = overhead + kLenFieldBytes + len;
        // Target TOTAL on-disk size: 4 KiB floor, then Padmé-bucketed.
        const std::size_t total = padme(rawTotal < kMinBlobBytes ? kMinBlobBytes : rawTotal);

        // Build the plaintext to encrypt: len(8, little-endian) ‖ data ‖ random pad.
        const std::size_t plainLen = total - overhead;   // >= kLenFieldBytes + len
        SecureBuffer plain(plainLen);
        for (std::size_t i = 0; i < kLenFieldBytes; ++i)
            plain.data()[i] = static_cast<uint8_t>(
                (static_cast<uint64_t>(len) >> (8 * i)) & 0xFF);
        if (len) std::memcpy(plain.data() + kLenFieldBytes, data, len);
        const std::size_t padLen = plainLen - kLenFieldBytes - len;
        if (padLen) {
            std::vector<uint8_t> pad = crypto::randomBytes(padLen);
            std::memcpy(plain.data() + kLenFieldBytes + len, pad.data(), padLen);
        }

        uint8_t nonce[crypto::kNonceBytes];
        crypto::randomBytes(nonce, sizeof(nonce));
        auto enc = crypto::aesGcmEncrypt(
            vault_->contentKey().data(), nonce, plain.data(), plainLen,
            reinterpret_cast<const uint8_t*>(kContentMagic), kContentMagicLen);

        std::vector<uint8_t> blob;
        blob.reserve(total);
        blob.insert(blob.end(), kContentMagic, kContentMagic + kContentMagicLen);
        blob.insert(blob.end(), nonce, nonce + crypto::kNonceBytes);
        blob.insert(blob.end(), enc.ciphertext.begin(), enc.ciphertext.end());
        blob.insert(blob.end(), enc.tag.begin(), enc.tag.end());
        return blob;
    }

    // Reverse encryptContent(): verify the blob, decrypt, and strip length + padding.
    SecureBuffer EncryptedFileSystem::decryptContent(const std::vector<uint8_t>& blob) const {
        const std::size_t headerLen = kContentMagicLen + crypto::kNonceBytes + crypto::kTagBytes;
        if (blob.size() < headerLen ||
            std::memcmp(blob.data(), kContentMagic, kContentMagicLen) != 0) {
            throw CipherPathsError(ErrorCode::CorruptedFile, "bad content header");
        }
        const uint8_t* nonce = blob.data() + kContentMagicLen;
        const uint8_t* ct = nonce + crypto::kNonceBytes;
        const std::size_t ctLen = blob.size() - headerLen;
        const uint8_t* tag = ct + ctLen;
        SecureBuffer padded = crypto::aesGcmDecrypt(
            vault_->contentKey().data(), nonce, ct, ctLen, tag,
            reinterpret_cast<const uint8_t*>(kContentMagic), kContentMagicLen);

        // Strip the authenticated length prefix and the Padmé padding.
        if (padded.size() < kLenFieldBytes)
            throw CipherPathsError(ErrorCode::CorruptedFile, "short content payload");
        uint64_t realLen = 0;
        for (std::size_t i = 0; i < kLenFieldBytes; ++i)
            realLen |= static_cast<uint64_t>(padded.data()[i]) << (8 * i);
        if (realLen > padded.size() - kLenFieldBytes)
            throw CipherPathsError(ErrorCode::CorruptedFile, "bad content length");

        SecureBuffer out(static_cast<std::size_t>(realLen));
        if (realLen)
            std::memcpy(out.data(), padded.data() + kLenFieldBytes,
                        static_cast<std::size_t>(realLen));
        return out;
    }

    // Write `data` to `target` atomically: write a temp file in the same
    // directory, then rename it over the target.
    void EncryptedFileSystem::atomicWrite(const fs::path& target,
        const uint8_t* data, std::size_t len) const {
        // Random temporary file name in the same directory.
        const std::string tmpName = "CPtmp_" +
            encoding::base32Encode(crypto::randomBytes(12));
        const fs::path tmp = target.parent_path() / tmpName;
        {
            std::ofstream out(lp(tmp), std::ios::binary | std::ios::trunc);
            if (!out) throw CipherPathsError(ErrorCode::FailedSave, target.string());
            if (len > 0) out.write(reinterpret_cast<const char*>(data),
                static_cast<std::streamsize>(len));
            out.flush();
            if (!out) {
                std::error_code rmec; fs::remove(lp(tmp), rmec);
                throw CipherPathsError(ErrorCode::DiskFull, target.string());
            }
        }
        std::error_code ec;
        fs::rename(lp(tmp), lp(target), ec);
        if (ec) {
            fs::remove(lp(target), ec);
            fs::rename(lp(tmp), lp(target), ec);
            if (ec) {
                std::error_code rmec; fs::remove(lp(tmp), rmec);
                throw CipherPathsError(ErrorCode::FailedSave, target.string());
            }
        }
    }

    // ---- operations ----------------------------------------------------------

    // Create a new empty folder with an encrypted, record-type-tagged name.
    Entry EncryptedFileSystem::createFolder(const fs::path& parentDir,
        const std::string& name, char recordType) {
        ensureNoDuplicate(parentDir, name);
        const std::string diskName = vault_->nameCodec().encode(name, recordType);
        const fs::path path = parentDir / diskName;
        std::error_code ec;
        if (!fs::create_directory(lp(path), ec) || ec) {
            throw CipherPathsError(ErrorCode::FailedSave, path.string());
        }
        Entry e{ name, path, true, 0, recordType };
        return e;
    }

    // Create (or, with `overwrite`, replace) an encrypted file from a memory buffer.
    Entry EncryptedFileSystem::writeNewFile(const fs::path& parentDir, const std::string& name,
        const uint8_t* data, std::size_t len,
        bool overwrite) {
        auto existing = findChild(parentDir, name);
        if (existing && !overwrite) throw CipherPathsError(ErrorCode::AlreadyExists, name);

        std::vector<uint8_t> blob = encryptContent(data, len);
        fs::path path;
        if (existing) {
            path = existing->diskPath;       // keep the same on-disk name
        }
        else {
            path = parentDir / vault_->nameCodec().encode(name);
        }
        atomicWrite(path, blob.data(), blob.size());
        std::error_code ec;
        return Entry{ name, path, false, fs::file_size(lp(path), ec) };
    }

    // Import a plaintext file from disk, encrypting its contents and name; source untouched.
    Entry EncryptedFileSystem::importFile(const fs::path& parentDir,
        const fs::path& sourceFile,
        std::optional<std::string> nameOverride) {
        const std::string name = nameOverride.value_or(sourceFile.filename().string());
        ensureNoDuplicate(parentDir, name);
        std::vector<uint8_t> plain = readWholeFile(sourceFile);
        Entry e = writeNewFile(parentDir, name, plain.data(), plain.size(), false);
        secureZero(plain.data(), plain.size());
        return e;
    }

    // Recursively import a folder tree from disk into the vault.
    Entry EncryptedFileSystem::importFolder(const fs::path& parentDir,
        const fs::path& sourceFolder,
        std::optional<std::string> nameOverride) {
        const std::string name = nameOverride.value_or(sourceFolder.filename().string());
        Entry folder = createFolder(parentDir, name);
        std::error_code ec;
        for (const auto& de : fs::directory_iterator(lp(sourceFolder), ec)) {
            if (de.is_directory(ec)) {
                importFolder(folder.diskPath, de.path());
            }
            else if (de.is_regular_file(ec)) {
                importFile(folder.diskPath, de.path());
            }
        }
        return folder;
    }

    // Read and decrypt a vault file's contents into memory.
    SecureBuffer EncryptedFileSystem::readFile(const fs::path& diskFile) const {
        std::vector<uint8_t> blob = readWholeFile(diskFile);
        return decryptContent(blob);
    }

    // Re-encrypt and atomically overwrite an existing vault file's contents.
    void EncryptedFileSystem::writeFile(const fs::path& diskFile,
        const uint8_t* data, std::size_t len) {
        std::vector<uint8_t> blob = encryptContent(data, len);
        atomicWrite(diskFile, blob.data(), blob.size());
    }

    // Rename an entry in place by re-encrypting its name, keeping its record-type tag.
    Entry EncryptedFileSystem::rename(const fs::path& diskPath, const std::string& newName) {
        const fs::path parent = diskPath.parent_path();
        auto existing = findChild(parent, newName);
        if (existing && existing->diskPath != diskPath) {
            throw CipherPathsError(ErrorCode::AlreadyExists, newName);
        }
        // Preserve the folder's record-type tag across the rename.
        const char recordType =
            NameCodec::recordTypeChar(diskPath.filename().string());
        const fs::path newPath =
            parent / vault_->nameCodec().encode(newName, recordType);
        std::error_code ec;
        fs::rename(lp(diskPath), lp(newPath), ec);
        if (ec) {
            if (isFileInUseError(ec))
                throw CipherPathsError(ErrorCode::PermissionDenied,
                    diskPath.filename().string() + " is open in another program");
            throw CipherPathsError(ErrorCode::FailedRename, newPath.string());
        }
        Entry e;
        e.name = newName;
        e.diskPath = newPath;
        e.isDirectory = fs::is_directory(lp(newPath), ec);
        e.recordTypeCode = recordType;
        if (!e.isDirectory) e.encryptedSize = fs::file_size(lp(newPath), ec);
        return e;
    }

    // Move an entry into another directory (optionally renaming), with a copy+delete
    // fallback across devices.
    Entry EncryptedFileSystem::move(const fs::path& diskPath, const fs::path& destDir,
        std::optional<std::string> newName) {
        const std::string name = newName.value_or(decryptName(diskPath));
        ensureNoDuplicate(destDir, name);
        // Preserve the entry's record-type tag across the move.
        const char recordType =
            NameCodec::recordTypeChar(diskPath.filename().string());
        const fs::path newPath =
            destDir / vault_->nameCodec().encode(name, recordType);
        std::error_code ec;
        fs::rename(lp(diskPath), lp(newPath), ec);
        if (ec) {
            // Cross-device fallback: copy then remove.
            fs::copy(lp(diskPath), lp(newPath), fs::copy_options::recursive, ec);
            if (ec) throw CipherPathsError(ErrorCode::FailedSave, newPath.string());
            fs::remove_all(lp(diskPath), ec);
        }
        Entry e;
        e.name = name;
        e.diskPath = newPath;
        e.isDirectory = fs::is_directory(lp(newPath), ec);
        e.recordTypeCode = recordType;
        if (!e.isDirectory) e.encryptedSize = fs::file_size(lp(newPath), ec);
        return e;
    }

    // Delete a file, or recursively delete a folder. There is no trash.
    void EncryptedFileSystem::remove(const fs::path& diskPath) {
        std::error_code ec;
        if (fs::is_directory(lp(diskPath), ec)) {
            fs::remove_all(lp(diskPath), ec);
        }
        else {
            fs::remove(lp(diskPath), ec);
        }
        if (ec) {
            if (isFileInUseError(ec))
                throw CipherPathsError(ErrorCode::PermissionDenied,
                    diskPath.filename().string() + " is open in another program");
            throw CipherPathsError(ErrorCode::PermissionDenied, diskPath.string());
        }
    }

    // Decrypt a vault file out to the regular file system, adding a "(n)" suffix
    // on a name collision.
    std::filesystem::path EncryptedFileSystem::exportFile(const fs::path& diskFile,
        const fs::path& destDir) const {
        const std::string name = decryptName(diskFile);
        std::error_code ec;
        fs::create_directories(lp(destDir), ec);

        // Resolve name collisions with a "(n)" suffix.
        fs::path target = destDir / name;
        if (fs::exists(lp(target), ec)) {
            const fs::path stem = fs::path(name).stem();
            const std::string ext = fs::path(name).extension().string();
            for (int i = 1; ; ++i) {
                target = destDir / (stem.string() + " (" + std::to_string(i) + ")" + ext);
                if (!fs::exists(lp(target), ec)) break;
            }
        }
        SecureBuffer plain = readFile(diskFile);
        std::ofstream out(lp(target), std::ios::binary | std::ios::trunc);
        if (!out) throw CipherPathsError(ErrorCode::FailedSave, target.string());
        if (!plain.empty())
            out.write(reinterpret_cast<const char*>(plain.data()),
                static_cast<std::streamsize>(plain.size()));
        if (!out) throw CipherPathsError(ErrorCode::FailedSave, target.string());
        return target;
    }

    // Recursively decrypt a vault folder tree out to the regular file system.
    std::filesystem::path EncryptedFileSystem::exportFolder(const fs::path& diskFolder,
        const fs::path& destDir) const {
        const std::string name = decryptName(diskFolder);
        const fs::path target = destDir / name;
        std::error_code ec;
        fs::create_directories(lp(target), ec);
        for (const auto& child : list(diskFolder)) {
            if (child.isDirectory) exportFolder(child.diskPath, target);
            else exportFile(child.diskPath, target);
        }
        return target;
    }

} // namespace cipherpaths
