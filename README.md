<p align="center">
  <img src="https://www.cipherpaths.com/assets/icons/CipherPathsLogo256x256_no_text_transparent.png" alt="CipherPaths logo" width="150">
</p>

<h1 align="center">CipherPaths</h1>

<p align="center"><em>Your passwords <strong>and</strong> your files, locked in one encrypted vault.</em></p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"></a>
  <img alt="Language: C++20" src="https://img.shields.io/badge/C%2B%2B-20-00599C.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg">
  <img alt="Crypto: OpenSSL" src="https://img.shields.io/badge/crypto-OpenSSL%20libcrypto-721412.svg">
</p>

## Project web site
[Cipherpaths web site](https://www.cipherpaths.com/)

## Overview

CipherPaths is a local, offline encrypted vault that combines a **password manager**, an
**encrypted document manager**, and a simple **encrypted file explorer**. Every file and
folder — *names as well as contents* — is encrypted on disk with AES‑256‑GCM. Outside the
application the vault is just a directory of random‑looking names and unreadable blobs.
There is no cloud service, no account, and no subscription.

This repository holds the **open‑source parts** of the project:

| Component | Path | Language | License |
|---|---|---|---|
| Core crypto & storage engine | [`core/`](core) | Portable C++20 | Apache 2.0 |
| Cross‑platform command‑line tool | [`CommandLine/`](CommandLine) | Portable C++20 | Apache 2.0 |

The **Windows GUI application** remains closed source for the moment and is not part of this
repository. Ready‑to‑run GUI builds are available from the website's
[download page](https://www.cipherpaths.com/download.html).

> **Full documentation** is on the website — this README is only a summary:
> [User guide](https://www.cipherpaths.com/guide.html) ·
> [Feature overview](https://www.cipherpaths.com/index.html) ·
> [Command‑line guide](https://www.cipherpaths.com/command-line-guide.html)

![CipherPaths main window](https://www.cipherpaths.com/assets/screenshots/Main-Window-Example1.png)

---

## 1. The Core Crypto Engine (`core/`)

`CipherPathsCore` is a portable, dependency‑light **C++20 static library** that implements the
entire vault: key derivation, authenticated encryption, the on‑disk format, encrypted
file/folder‑name encoding, and a filesystem abstraction expressed entirely in plaintext
names. It depends only on the **C++20 standard library and OpenSSL (libcrypto)** and never
includes a Windows header, so the same sources build for Windows, Linux and macOS and back
both the Windows GUI and the CLI in this repo.

### Features

- **Vault lifecycle** — create, unlock (master password *or* printed recovery key), and
  change the master password by re‑wrapping the Vault Master Key, with no bulk
  re‑encryption of existing data.
- **Authenticated encryption** — AES‑256‑GCM for all file content and names; a fresh random
  96‑bit nonce per operation, a 128‑bit tag, and the format magic bound as additional
  authenticated data.
- **Memory‑hard key derivation** — Argon2id (64 MiB memory cost, calibrated iteration
  count) turns the master password into a Key‑Encryption‑Key that unwraps a random Vault
  Master Key.
- **Key separation** — content, name and header‑MAC sub‑keys are each derived from the
  Vault Master Key with HKDF‑HMAC‑SHA256 using distinct context labels and a per‑vault
  `hkdfSalt` that is independent of the password salt (so a password change never disturbs
  the derived keys).
- **Tamper‑evident header** — the plaintext vault header carries an HMAC‑SHA256 tag over
  every field, verified immediately after the key is recovered.
- **Encrypted names with length hiding** — the `CP#1` name codec encrypts each name and pads
  it Padmé‑style so only the length *bucket* leaks; a one‑character record‑type tag lets a
  UI colour a folder tile without decrypting its credential file.
- **Content length hiding** — files get an authenticated length prefix plus Padmé random
  padding with a 4 KiB floor, so empty and small files are indistinguishable by size and
  identical plaintexts never produce identical blobs.
- **Atomic writes** — every encrypted file is written to a temporary name and renamed into
  place; no partial writes.
- **`SecureBuffer`** — an RAII buffer that wipes its memory on destruction, used for all key
  material and decrypted content.
- **Special files** — per‑folder encrypted `##credentials##.json` (web / credit‑card /
  contact records with tags and timestamps) and `##notes##.txt`.
- **Services** — in‑memory search over names, URLs, usernames, notes and text content (no
  on‑disk index); viewer classification (text / JPEG / PNG / PDF / video) by extension and
  content sniffing.
- **Windows long‑path support** — transparent `\\?\` handling so deep vaults work despite
  `MAX_PATH`.
- **Stable error model** — every recoverable failure is a `CipherPathsError` carrying an
  `ErrorCode`.

### Vault format at a glance

```
<vault root>/
├── cipherpaths-vault.json      plaintext header: KDF params, wrapped keys,
│                               hkdfSalt, HMAC tag, tag list
├── CP#1<type><base64url( nonce ‖ AES-256-GCM(name ‖ padding) ‖ tag )>   ← a folder
│   └── CP#1<...>                                                        ← a file
└── ...

file contents on disk:   "CPF1" ‖ nonce(12) ‖ ciphertext ‖ tag(16)
```

Key hierarchy:

```
Master Password ──Argon2id──▶ Password KEK ─┐
                                            ├─ AES-256-GCM unwrap ─▶ Vault Master Key ──HKDF──┬─▶ Content key
Recovery Key ────HKDF───────▶ Recovery KEK ─┘                                                 ├─▶ Name key
                                                                                             └─▶ Header-MAC key
```

### Public API

Include the umbrella header `cipherpaths/CipherPaths.h`, or the individual headers under
[`core/include/cipherpaths/`](core/include/cipherpaths):

| Header | Purpose |
|---|---|
| `VaultManager.h` | create / unlock / change password |
| `Vault.h` | an unlocked vault and its derived keys |
| `EncryptedFileSystem.h` | list, resolve, import, read, write, rename, move, delete, export |
| `Crypto.h` | AES‑256‑GCM, Argon2id, HKDF, HMAC, CSPRNG |
| `NameCodec.h` | `CP#1` encrypted‑name encode / decode |
| `Encoding.h` | Base32 / Base64 / Base64url |
| `Json.h` | dependency‑free JSON |
| `PasswordEntry.h`, `NotesService.h`, `SearchService.h`, `ViewerService.h` | per‑folder services |
| `SecureBuffer.h` | self‑wiping byte buffer |
| `Errors.h` | `CipherPathsError`, `ErrorCode` |

### Building the core

Requires CMake ≥ 3.20, a C++20 compiler, and **OpenSSL ≥ 3.2** (needed for the Argon2id KDF
provider). On Windows the build reuses the prebuilt static `libcrypto` under
`Static-Libs/OpenSSL/<arch>/`; on Linux/macOS it links the system OpenSSL.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This produces the `CipherPathsCore` static library and the `cipherpaths` CLI (see §2). A
self‑contained integration/unit test harness lives at
[`core/tests/test_main.cpp`](core/tests/test_main.cpp) — compile and link it against the core
to exercise the crypto primitives, encodings, JSON, the name codec, and a full vault
round‑trip.

### Worked example: the command‑line tool

[`CommandLine/main.cpp`](CommandLine/main.cpp) is a single source file that drives the core
end to end — the clearest example of how to consume the library (open a vault, walk it,
import / read / export files, manage credentials and notes, search). It also doubles as a
portable smoke test for the engine.

---

## 2. The CipherPaths Application (GUI + Command Line)

### Windows GUI — closed source, download from the website

A native Windows 10/11 desktop app for x86 and ARM is available on the web site that
presents the vault as a three‑pane explorer: accounts on the left, the credential panel
top‑right, the encrypted file list bottom‑right. It ships as a small portable ZIP or an
installer — get it from **<https://www.cipherpaths.com/download.html>**.

**Password manager**

- Web login, credit‑card and contact record types, each with tags, notes and
  created / updated / password‑updated dates
- Built‑in strong‑password generator (OpenSSL CSPRNG, unbiased sampling, live entropy and
  brute‑force estimates)
- Masked fields with one‑click copy; **clipboard auto‑clear**, and passwords excluded from
  Windows Clipboard History
- Global auto‑type hotkeys (username / password / both), user‑configurable
- Colour‑coded account tiles by record type, with custom icons or fetched site favicons
- Instant local search as you type

**Encrypted files**

- Drag‑and‑drop import of files and whole folders; encrypted names *and* contents
- Sortable file list that also shows the raw on‑disk ciphertext name
- Individual files decrypt on demand — the whole vault is never unlocked at once
- Whole‑vault import / export for backup and migration (round‑trips hidden metadata)

**Built‑in viewers — no plaintext ever written to disk**

- Text editor with save‑back to the vault build in.
- JPEG / PNG image viewer build in.
- PDF viewer build in.
- Video player build in, directly stream the encrypted content.
- "View with external viewer" for other file types, via a monitored, auto‑cleaned temp copy

**Security & storage**

- AES‑256‑GCM + Argon2id with a tamper‑evident header (see §1)
- Fully offline; the vault is an ordinary folder that can live on a USB stick or a cloud drive
- Multiple app instances can share one vault

| | |
|---|---|
| ![The vault in Windows Explorer](https://www.cipherpaths.com/assets/screenshots/On-Disk-Encrypted-File-View.png) | ![In-memory PDF viewer](https://www.cipherpaths.com/assets/screenshots/PDF-viewer-window.png) |
| The vault as Windows Explorer sees it | In‑memory PDF viewer |

Full walkthrough: **<https://www.cipherpaths.com/guide.html>**

### Command‑line tool (`CommandLine/`) — open source, in this repo

`cipherpaths` is a cross‑platform CLI over the same vault format, built from one shared
`main.cpp`. Prebuilt binaries are on the [download page](https://www.cipherpaths.com/download.html)
and are also checked into this repo under `CommandLine/<platform>/<arch>/`.

**Platforms:** Windows (x64, ARM64), Linux x86_64 (statically linked — no runtime
dependencies), Linux ARM64 (cross‑built), macOS (source is portable; build on a Mac).

**Commands**

```
init       <vault-dir>                              create a new vault
open       <vault-dir>                              unlock once, then an interactive prompt
ls         <vault-dir> [/path]                      list a folder
mkdir      <vault-dir> /path [web|creditcard|contact]
add        <vault-dir> /parent <source-file>        import & encrypt a file
cat        <vault-dir> /path/file.txt               print a decrypted file
export     <vault-dir> /path <dest-dir>             decrypt out to the real file system
mv         <vault-dir> /path <new-name>             rename
move       <vault-dir> /path /dest [new-name]       move
rm         <vault-dir> /path                        delete (there is no trash)
setpw / setcc / setcontact                          store a credential record
getpw      <vault-dir> /TopFolder                   show a credential record
note / getnote                                      per-folder notes
search     <vault-dir> <query>                      names, URLs, usernames, notes, contents
changepw   <vault-dir>                              change the master password
version
```

**Interactive mode** (`open`) unlocks the vault once — paying the deliberately expensive
Argon2id cost a single time — then runs the same commands repeatedly without the
`<vault-dir>` argument.

**Password handling:** read from `CIPHERPATHS_PASSWORD` if set, otherwise prompted with
console echo suppressed. `CIPHERPATHS_RECOVERY_KEY` unlocks with the recovery key;
`CIPHERPATHS_NEW_PASSWORD` scripts `changepw`. Pass `-` for any password / card‑number / CVV
argument to be prompted for it instead of exposing it in `argv` or shell history.

```bash
# create a vault and store a login (prompted for the password, not echoed)
cipherpaths init ./myvault
cipherpaths setpw ./myvault /GitHub https://github.com me@example.com -
cipherpaths getpw ./myvault /GitHub

# many operations under a single unlock
cipherpaths open ./myvault
cipherpaths> mkdir /Taxes/2025
cipherpaths> add /Taxes/2025 ./payslip.pdf
cipherpaths> search github
cipherpaths> exit
```

**Building the CLI** — the per‑platform scripts under `CommandLine/scripts/` wrap the CMake
build and drop the binary in `CommandLine/<platform>/<arch>/`:

```bash
CommandLine/scripts/build-windows.ps1     # Windows x64 + ARM64
CommandLine/scripts/build-linux.sh        # Linux x64 (static) + ARM64 (cross)
CommandLine/scripts/build-macos.sh        # macOS x64 + arm64 (run on a Mac)
```

Linux build prerequisites (Debian/Ubuntu):

```bash
sudo apt install -y build-essential cmake libssl-dev pkg-config \
                    zlib1g-dev libzstd-dev libjitterentropy3-dev \
                    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

The Linux x64 binary links OpenSSL, libstdc++ and libgcc **statically** so it runs on any
current distro regardless of the system OpenSSL version; set `CIPHERPATHS_LINUX_DYNAMIC=1`
to opt back into a dynamic build.

---

## Repository layout

```
CipherPaths/
├── core/                     portable crypto & storage engine (Apache 2.0)
│   ├── include/cipherpaths/  public headers (the core API)
│   ├── src/                  implementation
│   ├── tests/test_main.cpp   self-contained test harness
│   └── CMakeLists.txt
├── CommandLine/              cross-platform CLI (Apache 2.0)
│   ├── main.cpp              single shared source, all platforms
│   ├── scripts/              per-platform build scripts
│   ├── cmake/                cross-compilation toolchain files
│   └── <platform>/<arch>/    prebuilt cipherpaths binaries
├── Static-Libs/              prebuilt OpenSSL static libs (Windows)
├── CMakeLists.txt            top-level build (core + CommandLine only)
├── LICENSE                   Apache License 2.0
└── NOTICE
```

The Windows GUI sources are maintained separately and are not included here.

## Security

CipherPaths uses **only OpenSSL (libcrypto)** for cryptography: AES‑256‑GCM, Argon2id,
HKDF‑HMAC‑SHA256 and HMAC‑SHA256. The design, threat model and known limitations are
described in the [user guide](https://www.cipherpaths.com/guide.html) and the
[FAQ](https://www.cipherpaths.com/faq.html). Notably, the scheme does **not** hide the
number of files, the folder structure, or that a very large file is large.

If you believe you have found a security vulnerability, please report it privately to
Coogee Code via <https://www.coogeecode.com.au/> rather than opening a public issue.

## License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).

```
Copyright 2026 Coogee Code Pty. Ltd. Australia
https://www.coogeecode.com.au/
```

## Links

- Website & feature overview — <https://www.cipherpaths.com/index.html>
- User guide — <https://www.cipherpaths.com/guide.html>
- Command‑line guide — <https://www.cipherpaths.com/command-line-guide.html>
- Downloads (Windows GUI + CLI) — <https://www.cipherpaths.com/download.html>
- FAQ — <https://www.cipherpaths.com/faq.html>
- Publisher — Coogee Code Pty. Ltd., Australia — <https://www.coogeecode.com.au/>
