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

// CipherPaths Core - integration / unit tests.
// A small dependency-free harness that exercises every part of the portable
// core against a temporary vault on disk. Run via `ctest` or directly.
#include "cipherpaths/CipherPaths.h"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <type_traits>

namespace fs = std::filesystem;
using namespace cipherpaths;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_failures;                                                      \
            std::cerr << "FAIL: " << #cond << " @ " << __FILE__ << ":"         \
                      << __LINE__ << "\n";                                     \
        }                                                                      \
    } while (0)

#define CHECK_THROWS(expr, expectedCode)                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        bool threw = false;                                                    \
        try { expr; } catch (const CipherPathsError& e) {                      \
            threw = (e.code() == (expectedCode));                              \
        }                                                                      \
        if (!threw) {                                                          \
            ++g_failures;                                                      \
            std::cerr << "FAIL: expected throw " << #expectedCode << " @ "     \
                      << __FILE__ << ":" << __LINE__ << "\n";                  \
        }                                                                      \
    } while (0)

// Print a section banner to stdout.
static void section(const char* name) {
    std::cout << "== " << name << " ==\n";
}

// Exercise the crypto primitives: AES-GCM, Argon2id, HKDF and HMAC.
static void testCrypto() {
    CHECK(!std::is_copy_constructible_v<SecureBuffer>);
    CHECK(!std::is_copy_assignable_v<SecureBuffer>);
    section("crypto: AES-256-GCM round trip + tamper detection");
    auto key = crypto::randomBytes(crypto::kKeyBytes);
    auto nonce = crypto::randomBytes(crypto::kNonceBytes);
    std::string msg = "The quick brown fox jumps over the lazy dog.";
    auto enc = crypto::aesGcmEncrypt(key.data(), nonce.data(),
                                     reinterpret_cast<const uint8_t*>(msg.data()),
                                     msg.size(), nullptr, 0);
    auto dec = crypto::aesGcmDecrypt(key.data(), nonce.data(),
                                     enc.ciphertext.data(), enc.ciphertext.size(),
                                     enc.tag.data(), nullptr, 0);
    CHECK(std::string(reinterpret_cast<char*>(dec.data()), dec.size()) == msg);

    // Tamper with the ciphertext -> must fail authentication.
    enc.ciphertext[0] ^= 0x01;
    CHECK_THROWS(crypto::aesGcmDecrypt(key.data(), nonce.data(),
                                       enc.ciphertext.data(), enc.ciphertext.size(),
                                       enc.tag.data(), nullptr, 0),
                 ErrorCode::CorruptedFile);

    section("crypto: Argon2id + HKDF determinism & separation");
    std::vector<uint8_t> salt(crypto::kSaltBytes, 0x11);
    auto k1 = crypto::argon2idDerive("pw", salt, 3, crypto::kArgon2MemoryKiB,
                                     crypto::kArgon2Parallelism, 32);
    auto k2 = crypto::argon2idDerive("pw", salt, 3, crypto::kArgon2MemoryKiB,
                                     crypto::kArgon2Parallelism, 32);
    CHECK(std::equal(k1.data(), k1.data() + 32, k2.data()));
    auto c = crypto::hkdfSha256(k1, salt, "content", 32);
    auto n = crypto::hkdfSha256(k1, salt, "name", 32);
    CHECK(!std::equal(c.data(), c.data() + 32, n.data())); // domain separation

    section("crypto: HMAC-SHA256 determinism & key sensitivity");
    {
        std::vector<uint8_t> hkey = crypto::randomBytes(32);
        const std::string data = "authenticate me";
        auto m1 = crypto::hmacSha256(hkey.data(), hkey.size(),
                                     reinterpret_cast<const uint8_t*>(data.data()), data.size());
        auto m2 = crypto::hmacSha256(hkey.data(), hkey.size(),
                                     reinterpret_cast<const uint8_t*>(data.data()), data.size());
        CHECK(m1 == m2);
        std::vector<uint8_t> hkey2 = crypto::randomBytes(32);
        auto m3 = crypto::hmacSha256(hkey2.data(), hkey2.size(),
                                     reinterpret_cast<const uint8_t*>(data.data()), data.size());
        CHECK(m1 != m3);
    }
}

// Round-trip the base32 / base64 / base64url encoders.
static void testEncoding() {
    section("encoding: base32 / base64 / base64url round trips");
    for (std::size_t len : {0u, 1u, 2u, 5u, 16u, 60u, 141u}) {
        auto data = crypto::randomBytes(len);
        auto b32 = encoding::base32Encode(data);
        CHECK(encoding::base32Decode(b32) == data);
        auto b64 = encoding::base64Encode(data);
        CHECK(encoding::base64Decode(b64) == data);
        auto b64u = encoding::base64urlEncode(data);
        CHECK(encoding::base64urlDecode(b64u) == data);
        // Base64url must never contain characters reserved in file names.
        CHECK(b64u.find('+') == std::string::npos);
        CHECK(b64u.find('/') == std::string::npos);
    }
    // Base64url substitutes '+'->'-' and '/'->'_' versus standard Base64.
    {
        // 0xFB 0xFF 0xBF encodes to "+/+/" in standard Base64.
        std::vector<uint8_t> tricky = {0xFB, 0xFF, 0xBF};
        auto std64 = encoding::base64Encode(tricky);
        auto url64 = encoding::base64urlEncode(tricky);
        CHECK(std64.find('+') != std::string::npos || std64.find('/') != std::string::npos);
        CHECK(url64.find('+') == std::string::npos);
        CHECK(url64.find('/') == std::string::npos);
        CHECK(encoding::base64urlDecode(url64) == tricky);
    }
}

// Round-trip the minimal JSON parser and serialiser.
static void testJson() {
    section("json: parse + dump round trip");
    std::string text = R"({"a":1,"b":"hi \"there\"","c":[1,2,true,null],"d":{"e":3.5}})";
    JsonValue v = JsonValue::parse(text);
    CHECK(v.at("a").asNumber() == 1);
    CHECK(v.at("b").asString() == "hi \"there\"");
    CHECK(v.at("c").items().size() == 4);
    CHECK(v.at("d").at("e").asNumber() == 3.5);
    CHECK_THROWS(JsonValue::parse("{bad json"), ErrorCode::InvalidJson);
}

// Exercise the encrypted name codec: round trip, magic, padding, record-type tag.
static void testNameCodec() {
    section("name codec: encrypt/decrypt, magic, padded length, too-long");
    auto key = crypto::randomBytes(32);
    NameCodec codec(SecureBuffer(key.data(), key.size()));

    std::string a = codec.encode("Banking.txt");
    std::string b = codec.encode("Banking.txt");
    CHECK(NameCodec::hasMagic(a));
    CHECK(a != b);                       // fresh nonce -> different ciphertext
    CHECK(a.size() == b.size());         // same name -> same padded length
    CHECK(codec.decode(a) == "Banking.txt");
    CHECK(codec.decode(b) == "Banking.txt");

    // Padme-style padding: the plaintext block is rounded up to the next
    // multiple of kPadMultiple, so names within the same bucket share an on-disk
    // length, while much longer names occupy a bigger bucket (keeping short
    // names short instead of a single fixed maximum length).
    CHECK(codec.encode("x").size() == codec.encode("abcdefghi").size());   // both in first bucket
    CHECK(codec.encode("x").size() < codec.encode("a-much-longer-name.jpeg").size());

    CHECK_THROWS(codec.decode("not-a-cipherpaths-name"), ErrorCode::NotCipherPathsEntry);
    std::string tooLong(NameCodec::kMaxNameBytes + 1, 'z');
    CHECK_THROWS(codec.encode(tooLong), ErrorCode::NameTooLong);

    // Record-type tag: readable without decrypting, round-trips the name, and
    // is authenticated (tampering with the tag character breaks decryption).
    std::string typed = codec.encode("Banking.txt", '2');
    CHECK(NameCodec::recordTypeChar(typed) == '2');
    CHECK(codec.decode(typed) == "Banking.txt");
    CHECK(codec.encode("Banking.txt").size() == typed.size());  // tag doesn't change length
    CHECK(NameCodec::recordTypeChar(codec.encode("x")) == '0');  // default = none
    std::string tampered = typed;
    tampered[NameCodec::kHeaderLen] = '3';            // flip the tag byte
    CHECK_THROWS(codec.decode(tampered), ErrorCode::CorruptedFile);
    CHECK(NameCodec::recordTypeChar("short") == '0'); // non-CipherPaths name
}

// End-to-end test of vault lifecycle and the encrypted file system against a temp vault.
static void testVaultAndFs(const fs::path& tmp) {
    section("vault: create / unlock / wrong password / recovery / change pw");
    const fs::path root = tmp / "vault";
    CHECK_THROWS(VaultManager::create(tmp / "empty-password-vault", ""),
                 ErrorCode::InvalidArgument);
    CHECK_THROWS(VaultManager::create(tmp / "low-iteration-vault", "password", 1),
                 ErrorCode::InvalidArgument);
    CHECK_THROWS(VaultManager::create(tmp / "high-iteration-vault", "password",
                                      crypto::kArgon2MaxIterations + 1),
                 ErrorCode::InvalidArgument);
    auto created = VaultManager::create(root, "correct horse battery staple");
    CHECK(created.vault != nullptr);
    CHECK(!created.recoveryKey.empty());
    CHECK(VaultManager::vaultExists(root));

    CHECK_THROWS(VaultManager::unlock(root, "wrong-password"),
                 ErrorCode::IncorrectPassword);
    auto vault = VaultManager::unlock(root, "correct horse battery staple");
    CHECK(vault != nullptr);

    // Recovery key unlocks too.
    auto rvault = VaultManager::unlockWithRecoveryKey(root, created.recoveryKey);
    CHECK(rvault != nullptr);

    // Change password; old fails, new works, recovery still works.
    VaultManager::changePassword(root, "correct horse battery staple", "new-master-pw-123");
    CHECK_THROWS(VaultManager::changePassword(root, "new-master-pw-123", ""),
                 ErrorCode::InvalidArgument);
    CHECK_THROWS(VaultManager::changePassword(root, "new-master-pw-123", "next-password", 1),
                 ErrorCode::InvalidArgument);
    CHECK_THROWS(VaultManager::changePassword(root, "new-master-pw-123", "next-password",
                                              crypto::kArgon2MaxIterations + 1),
                 ErrorCode::InvalidArgument);
    CHECK(VaultManager::unlock(root, "new-master-pw-123") != nullptr);
    CHECK_THROWS(VaultManager::unlock(root, "correct horse battery staple"),
                 ErrorCode::IncorrectPassword);
    CHECK(VaultManager::unlock(root, "new-master-pw-123") != nullptr);
    CHECK(VaultManager::unlockWithRecoveryKey(root, created.recoveryKey) != nullptr);

    section("efs: folders, import, read, rename, move, list, delete");
    EncryptedFileSystem efs(vault);

    Entry banking = efs.createFolder(root, "Banking");
    CHECK_THROWS(efs.createFolder(root, "banking"), ErrorCode::AlreadyExists); // case-insensitive dup

    // On-disk name is encrypted (random looking, has magic, no plaintext).
    const std::string diskName = banking.diskPath.filename().string();
    CHECK(NameCodec::hasMagic(diskName));
    CHECK(diskName.find("Banking") == std::string::npos);

    // Create a source file and import it.
    const fs::path src = tmp / "secret.txt";
    { std::ofstream o(src); o << "top secret contents"; }
    Entry imported = efs.importFile(banking.diskPath, src);
    CHECK(imported.name == "secret.txt");
    CHECK(fs::exists(src)); // source untouched

    // Content on disk is encrypted (does not contain plaintext).
    {
        // On Windows the vault's temp path + ~205-char encrypted name can exceed
        // MAX_PATH, so a bare stream cannot open it; use the \\?\ long-path form.
        fs::path rawPath = imported.diskPath;
#ifdef _WIN32
        rawPath = fs::path(LR"(\\?\)" + fs::absolute(imported.diskPath).wstring());
#endif
        std::ifstream in(rawPath, std::ios::binary);
        std::string raw((std::istreambuf_iterator<char>(in)), {});
        CHECK(raw.find("top secret") == std::string::npos);
        CHECK(raw.rfind("CPF1", 0) == 0); // content magic
        // Padmé padding: a tiny file is padded up to one 4 KiB cluster,
        // so its on-disk size does not reveal the true content length.
        CHECK(raw.size() == 4096);
    }

    // Read back decrypts correctly.
    SecureBuffer plain = efs.readFile(imported.diskPath);
    CHECK(std::string(reinterpret_cast<char*>(plain.data()), plain.size()) ==
          "top secret contents");

    // Edit + save (text editor flow).
    std::string edited = "top secret contents (edited)";
    efs.writeFile(imported.diskPath,
                  reinterpret_cast<const uint8_t*>(edited.data()), edited.size());
    SecureBuffer plain2 = efs.readFile(imported.diskPath);
    CHECK(std::string(reinterpret_cast<char*>(plain2.data()), plain2.size()) == edited);

    section("efs: content padding (Padme length hiding)");
    {
        auto rawBytes = [](const fs::path& p) -> std::string {
            fs::path rp = p;
#ifdef _WIN32
            rp = fs::path(LR"(\\?\)" + fs::absolute(p).wstring());
#endif
            std::ifstream in(rp, std::ios::binary);
            return std::string((std::istreambuf_iterator<char>(in)), {});
        };
        Entry pad = efs.createFolder(root, "PadTest");

        // Two DIFFERENT zero-length files: both padded to exactly one 4 KiB
        // cluster (empty is indistinguishable from small), yet their bytes differ
        // (fresh nonce + random padding) so equal plaintext is not detectable.
        const fs::path e1 = tmp / "empty1.bin"; { std::ofstream o(e1); }
        const fs::path e2 = tmp / "empty2.bin"; { std::ofstream o(e2); }
        Entry ie1 = efs.importFile(pad.diskPath, e1);
        Entry ie2 = efs.importFile(pad.diskPath, e2);
        std::string b1 = rawBytes(ie1.diskPath), b2 = rawBytes(ie2.diskPath);
        CHECK(b1.size() == 4096 && b2.size() == 4096);
        CHECK(b1 != b2);                                  // no identical-blob leak
        CHECK(efs.readFile(ie1.diskPath).size() == 0);    // still decrypts to empty
        CHECK(efs.readFile(ie2.diskPath).size() == 0);

        // A 10 KiB file rounds up to a Padme bucket that is a multiple of 256 and
        // hides its exact size, with small (<~12%) overhead.
        std::string big(10000, 'Z');
        const fs::path bf = tmp / "big.bin";
        { std::ofstream o(bf, std::ios::binary); o.write(big.data(), (std::streamsize)big.size()); }
        Entry ibig = efs.importFile(pad.diskPath, bf);
        std::string rb = rawBytes(ibig.diskPath);
        CHECK(rb.size() >= 10000 + 8 + 32);               // holds content+len+overhead
        CHECK(rb.size() % 256 == 0);                      // Padme bucket granularity
        CHECK(rb.size() < (10000 + 32) * 12 / 10);        // overhead well under 20%
        SecureBuffer bigBack = efs.readFile(ibig.diskPath);
        CHECK(bigBack.size() == big.size());
        CHECK(std::string(reinterpret_cast<char*>(bigBack.data()), bigBack.size()) == big);

        efs.remove(pad.diskPath);
    }

    // Rename.
    Entry renamed = efs.rename(imported.diskPath, "notes-secret.txt");
    CHECK(renamed.name == "notes-secret.txt");
    CHECK(!fs::exists(imported.diskPath));

    // Subfolder + move.
    Entry sub = efs.createFolder(banking.diskPath, "Archive");
    Entry moved = efs.move(renamed.diskPath, sub.diskPath);
    CHECK(efs.findChild(sub.diskPath, "notes-secret.txt").has_value());
    CHECK(!efs.findChild(banking.diskPath, "notes-secret.txt").has_value());

    // resolve() by logical path.
    auto resolved = efs.resolve({"Banking", "Archive", "notes-secret.txt"});
    CHECK(resolved.has_value());
    CHECK(resolved->diskPath == moved.diskPath);

    // Top-level listing.
    CHECK(efs.listTopLevelFolders().size() == 1);

    section("efs: export decrypts to plaintext + collision suffix");
    const fs::path outDir = tmp / "export";
    fs::path exported = efs.exportFile(moved.diskPath, outDir);
    {
        std::ifstream in(exported); std::string s((std::istreambuf_iterator<char>(in)), {});
        CHECK(s == edited);
    }
    fs::path exported2 = efs.exportFile(moved.diskPath, outDir); // collision
    CHECK(exported2 != exported);

    section("password.json + notes + viewer classify");
    PasswordEntryService pwd(efs);
    PasswordEntry pe;
    pe.folderName = "Banking";
    pe.credential.type = "web";
    pe.credential.dateCreated = "2026-01-02";
    pe.credential.lastUpdated = "2026-06-08";
    pe.credential.passwordUpdated = "2026-05-01";
    WebCredential peWeb;
    peWeb.url = "https://bank.example.com";
    peWeb.username = "john@example.com";
    peWeb.password = "s3cr3t-pass";
    peWeb.twoFactorType = "Google";
    pe.credential.data = peWeb;
    pwd.save(banking.diskPath, pe);
    auto loaded = pwd.load(banking.diskPath);
    CHECK(loaded.has_value());
    CHECK(loaded->credential.type == "web");
    const WebCredential* loadedWeb =
        PasswordEntryService::getWebCredential(loaded->credential);
    CHECK(loadedWeb != nullptr);
    CHECK(loadedWeb->username == "john@example.com");
    CHECK(loaded->credential.dateCreated == "2026-01-02");
    CHECK(loaded->credential.lastUpdated == "2026-06-08");
    CHECK(loaded->credential.passwordUpdated == "2026-05-01");
    CHECK(loadedWeb->twoFactorType == "Google");
    CHECK(PasswordEntryService::mask("anything") == "********");

    NotesService notes(efs);
    notes.save(banking.diskPath, "Remember to rotate this password quarterly.");
    auto notesText = notes.load(banking.diskPath);
    CHECK(notesText.has_value() && notesText->find("rotate") != std::string::npos);

    CHECK(ViewerService::classify("photo.JPG") == ViewerKind::Jpeg);
    CHECK(ViewerService::classify("diagram.PNG") == ViewerKind::Png);
    CHECK(ViewerService::classify("readme.txt") == ViewerKind::Text);
    CHECK(ViewerService::classify("archive.zip") == ViewerKind::Unsupported);
    const uint8_t jpegMagic[] = {0xFF, 0xD8, 0xFF, 0xE0};
    CHECK(ViewerService::classify("unknown.bin", jpegMagic, 4) == ViewerKind::Jpeg);
    const uint8_t pngMagic[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    CHECK(ViewerService::classify("unknown.bin", pngMagic, 8) == ViewerKind::Png);
    CHECK(ViewerService::looksLikePng(pngMagic, 8));
    CHECK(!ViewerService::looksLikePng(jpegMagic, 4));
    CHECK(ViewerService::classify("document.PDF") == ViewerKind::Pdf);
    const uint8_t pdfMagic[] = {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37};
    CHECK(ViewerService::classify("unknown.bin", pdfMagic, 8) == ViewerKind::Pdf);
    CHECK(ViewerService::looksLikePdf(pdfMagic, 8));
    CHECK(!ViewerService::looksLikePdf(pngMagic, 8));
    CHECK(ViewerService::classify("clip.MP4") == ViewerKind::Video);
    CHECK(ViewerService::classify("home_movie.mov") == ViewerKind::Video);
    CHECK(ViewerService::classify("show.mkv") == ViewerKind::Video);

    section("search: names, url, username");
    SearchService search(efs);
    CHECK(!search.search("Banking").empty());
    CHECK(!search.search("bank.example").empty());     // credential url
    CHECK(!search.search("john@example").empty());      // credential username
    CHECK(!search.search("notes-secret").empty());      // file name
    CHECK(search.search("nonexistent-term-xyz").empty());
    CHECK(!search.searchAdvanced("rotate").empty());    // notes content (advanced)

    section("efs: delete");
    efs.remove(banking.diskPath);
    CHECK(efs.listTopLevelFolders().empty());
}

// Regression test: a master-password change must not break already-encrypted data.
static void testPasswordChangePreservesData(const fs::path& tmp) {
    section("vault: password change preserves existing encrypted data (regression)");
    const fs::path root = tmp / "vault-pwchange";
    auto created = VaultManager::create(root, "first-master-password");

    // Import a file under the ORIGINAL password.
    {
        EncryptedFileSystem efs(created.vault);
        Entry f = efs.createFolder(root, "Docs");
        const fs::path src = tmp / "pwchange-src.txt";
        { std::ofstream o(src); o << "survive the password change"; }
        efs.importFile(f.diskPath, src);
    }

    // Change the master password.
    VaultManager::changePassword(root, "first-master-password", "second-master-password");

    // Re-unlock with the NEW password and confirm the old file still decrypts.
    {
        auto v = VaultManager::unlock(root, "second-master-password");
        CHECK(v != nullptr);
        EncryptedFileSystem efs(v);
        auto resolved = efs.resolve({"Docs", "pwchange-src.txt"});
        CHECK(resolved.has_value());
        SecureBuffer plain = efs.readFile(resolved->diskPath);
        CHECK(std::string(reinterpret_cast<char*>(plain.data()), plain.size()) ==
              "survive the password change");
    }

    // Recovery key still unlocks and yields the same data too.
    {
        auto v = VaultManager::unlockWithRecoveryKey(root, created.recoveryKey);
        CHECK(v != nullptr);
    }

    section("vault: header MAC tamper detection");
    {
        const fs::path hdr = root / VaultManager::kHeaderFileName;
        std::string text;
        { std::ifstream in(hdr, std::ios::binary);
          text.assign((std::istreambuf_iterator<char>(in)), {}); }

        // (a) Corrupting the wrapped key makes the KEK unwrap fail outright.
        std::string tampered = text;
        std::size_t wpos = tampered.find("\"wrappedVaultKey\": \"");
        CHECK(wpos != std::string::npos);
        std::size_t vstart = wpos + std::string("\"wrappedVaultKey\": \"").size();
        tampered[vstart] = (tampered[vstart] == 'A') ? 'B' : 'A';
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(tampered.data(), (std::streamsize)tampered.size()); }
        CHECK_THROWS(VaultManager::unlock(root, "second-master-password"),
                     ErrorCode::IncorrectPassword);

        std::string tampered3 = text;
        std::size_t mpos = tampered3.find("\"memoryKiB\": 65536");
        CHECK(mpos != std::string::npos);
        mpos += std::string("\"memoryKiB\": ").size();
        tampered3[mpos] = '1';
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(tampered3.data(), (std::streamsize)tampered3.size()); }
        CHECK_THROWS(VaultManager::unlock(root, "second-master-password"),
                     ErrorCode::CorruptedVaultHeader);

        std::string tamperedParallelism = text;
        std::size_t ppos = tamperedParallelism.find("\"parallelism\": 1");
        CHECK(ppos != std::string::npos);
        ppos += std::string("\"parallelism\": ").size();
        tamperedParallelism[ppos] = '2';
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(tamperedParallelism.data(), (std::streamsize)tamperedParallelism.size()); }
        CHECK_THROWS(VaultManager::unlock(root, "second-master-password"),
                     ErrorCode::CorruptedVaultHeader);

        std::string tampered4 = text;
        std::size_t kpos = tampered4.find("\"wrappedVaultKey\": \"");
        CHECK(kpos != std::string::npos);
        std::size_t kstart = kpos + std::string("\"wrappedVaultKey\": \"").size();
        tampered4.erase(kstart, 1);
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(tampered4.data(), (std::streamsize)tampered4.size()); }
        CHECK_THROWS(VaultManager::unlock(root, "second-master-password"),
                     ErrorCode::CorruptedVaultHeader);
        std::string tampered2 = text;
        std::size_t cpos = tampered2.find("\"created\": \"");
        CHECK(cpos != std::string::npos);
        std::size_t cstart = cpos + std::string("\"created\": \"").size();
        tampered2[cstart] = (tampered2[cstart] == '2') ? '1' : '2';
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(tampered2.data(), (std::streamsize)tampered2.size()); }
        CHECK_THROWS(VaultManager::unlock(root, "second-master-password"),
                     ErrorCode::CorruptedVaultHeader);

        // Restore the good header.
        { std::ofstream out(hdr, std::ios::binary | std::ios::trunc);
          out.write(text.data(), (std::streamsize)text.size()); }
    }
}

// Run every test group against a fresh temp directory and report the tally.
int main() {
    std::cout << "CipherPathsCore test suite (v" << kCoreVersion << ")\n";
    fs::path tmp = fs::temp_directory_path() / ("cipherpaths-test-" +
                   std::to_string(static_cast<long long>(::time(nullptr))));
    fs::create_directories(tmp);

    try {
        testCrypto();
        testEncoding();
        testJson();
        testNameCodec();
        testVaultAndFs(tmp);
        testPasswordChangePreservesData(tmp);
    } catch (const std::exception& e) {
        std::cerr << "UNCAUGHT EXCEPTION: " << e.what() << "\n";
        ++g_failures;
    }

    std::error_code ec;
    fs::remove_all(tmp, ec);

    std::cout << "\n" << (g_checks - g_failures) << "/" << g_checks
              << " checks passed.\n";
    if (g_failures == 0) {
        std::cout << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cout << g_failures << " CHECK(S) FAILED\n";
    return 1;
}