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

// cipherpaths-cli - portable command-line front-end for the CipherPaths core.
//
// This demonstrates that the entire storage/crypto layer is platform
// independent. It is also genuinely useful as a scriptable management tool.
// The SAME source file builds unmodified for Windows, Linux and macOS
// (x86_64 / ARM64) - see CommandLine/CMakeLists.txt.
//
// Usage:
//   cipherpaths init      <vault-dir>
//   cipherpaths open      <vault-dir>
//   cipherpaths ls        <vault-dir> [/logical/path]
//   cipherpaths mkdir     <vault-dir> /logical/path [web|creditcard|contact]
//   cipherpaths add       <vault-dir> /logical/parent <source-file>
//   cipherpaths cat       <vault-dir> /logical/path/file.txt
//   cipherpaths export    <vault-dir> /logical/path/file <dest-dir>
//   cipherpaths mv        <vault-dir> /logical/path <new-name>
//   cipherpaths move      <vault-dir> /logical/path /dest/folder [new-name]
//   cipherpaths rm        <vault-dir> /logical/path
//   cipherpaths setpw     <vault-dir> /TopFolder <url> <user> <password> [2fa]
//   cipherpaths setcc     <vault-dir> /TopFolder <cardholder> <card-no> <expiry> <cvv> <issuer>
//   cipherpaths setcontact <vault-dir> /TopFolder <full-name> <email> <phone> <address> <city> <state> <postal> <country> <dob>
//   cipherpaths getpw     <vault-dir> /TopFolder
//   cipherpaths note      <vault-dir> /Folder "<text>"
//   cipherpaths getnote   <vault-dir> /Folder
//   cipherpaths search    <vault-dir> <query>
//   cipherpaths changepw  <vault-dir>
//   cipherpaths version
//
// The master password is read from the CIPHERPATHS_PASSWORD environment
// variable if set, otherwise prompted on the console with echo suppressed.
// A vault can also be opened read/write via its recovery key instead of the
// master password by setting CIPHERPATHS_RECOVERY_KEY. `changepw` additionally
// honours CIPHERPATHS_NEW_PASSWORD (skipping the interactive prompt/confirm)
// for scripted/CI use.
//
// INTERACTIVE MODE: every command above unlocks the vault from scratch (a
// deliberately expensive Argon2id derivation - see Crypto.h) and exits, which
// is slow when issuing many commands back to back. `cipherpaths open
// <vault-dir>` unlocks the vault ONCE and drops into a prompt where the same
// commands run repeatedly against the already-unlocked vault, with the
// leading <vault-dir> argument omitted (the session is already scoped to
// it). Type "help" for the in-session command list, "exit" or "quit" to
// leave (or Ctrl+D / Ctrl+Z EOF). Arguments containing spaces must be
// "quoted" - there is no shell to do that splitting for you inside the
// prompt.
//
// SECURITY NOTE: passing secrets (passwords, card numbers, CVVs) as command
// line arguments makes them visible to other processes on the same machine
// (e.g. via `ps`) and to shell history. Pass "-" instead of the value for
// any password/card-number/CVV argument to be prompted for it interactively
// with echo suppressed. Likewise, CIPHERPATHS_PASSWORD / CIPHERPATHS_RECOVERY_KEY
// are convenient for scripting but are visible to anything that can read this
// process's environment (e.g. /proc/<pid>/environ on Linux); prefer the
// interactive prompt for anything but automated/CI use. This applies equally
// inside an interactive session - anything typed at the prompt lands in
// shell history exactly like a single-shot command would.
#include "cipherpaths/CipherPaths.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace cipherpaths;
namespace fs = std::filesystem;

namespace {

// Record-type tag characters embedded in a top-level folder's encrypted name
// (see NameCodec.h). These must stay in sync with the id<->code mapping the
// Windows GUI defines in win/RecordTypes.cpp (RecordTypeCodeForId): '1' =
// web, '2' = credit card, '3' = contact. The core treats the tag as opaque;
// only the UI layers (this CLI and the Win32 GUI) assign it meaning.
constexpr char kTypeWeb = '1';
constexpr char kTypeCreditCard = '2';
constexpr char kTypeContact = '3';

// Strips a leading UTF-8 BOM (EF BB BF), if present. Windows PowerShell
// prepends one when a string/here-string is piped into a native process's
// stdin, so the first line of piped interactive input would otherwise silently
// fail to match any command name (the BOM bytes glue onto the first token).
void stripUtf8Bom(std::string& s) {
    if (s.size() >= 3 &&
        static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF) {
        s.erase(0, 3);
    }
}

// Split a logical vault path on '/' or '\' into its non-empty components.
std::vector<std::string> splitLogical(const std::string& path) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : path) {
        if (c == '/' || c == '\\') {
            if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    return parts;
}

// Splits one interactive-mode input line into tokens, honouring "double
// quoted" substrings (which may contain spaces) the same way the shell
// would for a single-shot invocation. There is no backslash-escaping - a
// literal " cannot appear inside a quoted token, same limitation the shell
// itself has for this CLI's arguments (see the SECURITY NOTE / prior "%%"
// escaping discussion for why embedding awkward characters is inherently
// fiddly here).
std::vector<std::string> tokenizeLine(const std::string& line) {
    std::vector<std::string> tokens;
    std::string cur;
    bool inQuotes = false;
    bool haveToken = false;
    for (char c : line) {
        if (inQuotes) {
            if (c == '"') {
                inQuotes = false;
            } else {
                cur.push_back(c);
            }
        } else if (c == '"') {
            inQuotes = true;
            haveToken = true;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            if (haveToken) {
                tokens.push_back(cur);
                cur.clear();
                haveToken = false;
            }
        } else {
            cur.push_back(c);
            haveToken = true;
        }
    }
    if (haveToken) tokens.push_back(cur);
    return tokens;
}

// Current UTC time as an ISO-8601 "YYYY-MM-DDThh:mm:ssZ" string.
std::string isoNow() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

// Reads one line from the console with local echo suppressed, so secrets
// typed interactively never appear on screen or in any terminal scrollback.
// Falls back to plain std::getline when stdin isn't an interactive terminal
// (e.g. piped input in a test harness), since there is no echo to suppress.
std::string readHiddenLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
#if defined(_WIN32)
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    const bool haveConsole = hIn != INVALID_HANDLE_VALUE && hIn != nullptr &&
                              GetConsoleMode(hIn, &oldMode) != 0;
    if (haveConsole) SetConsoleMode(hIn, oldMode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, line);
    if (haveConsole) {
        SetConsoleMode(hIn, oldMode);
        std::cout << "\n";
    }
#else
    const bool haveTty = isatty(fileno(stdin)) != 0;
    termios oldt{};
    if (haveTty) {
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    std::getline(std::cin, line);
    if (haveTty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\n";
    }
#endif
    return line;
}

// Return the master password from CIPHERPATHS_PASSWORD, or prompt for it (no echo).
std::string promptPassword(const char* prompt) {
    if (const char* env = std::getenv("CIPHERPATHS_PASSWORD")) return env;
    return readHiddenLine(prompt);
}

// Lets a sensitive positional argument (password, card number, CVV) be
// supplied as "-" to mean "prompt for it interactively instead" rather than
// exposing it in argv / shell history.
std::string argOrPrompt(const std::string& arg, const char* prompt) {
    if (arg == "-") return readHiddenLine(prompt);
    return arg;
}

// Map a "web"/"creditcard"/"contact" argument to its record-type tag character.
char recordTypeCodeForArg(const std::string& type) {
    if (type == "web") return kTypeWeb;
    if (type == "creditcard") return kTypeCreditCard;
    if (type == "contact") return kTypeContact;
    std::cerr << "Warning: unknown record type '" << type << "', creating untyped folder.\n";
    return NameCodec::kRecordTypeNone;
}

// Unlock the vault at `root` using the recovery key env var if set, else the password.
std::shared_ptr<Vault> openVault(const fs::path& root) {
    if (!VaultManager::vaultExists(root)) {
        throw CipherPathsError(ErrorCode::MissingVaultHeader, root.string());
    }
    if (const char* recoveryKey = std::getenv("CIPHERPATHS_RECOVERY_KEY")) {
        return VaultManager::unlockWithRecoveryKey(root, recoveryKey);
    }
    return VaultManager::unlock(root, promptPassword("Master password: "));
}

// Resolve a logical path to a disk path; "" or "/" means the root.
fs::path resolveDir(EncryptedFileSystem& efs, const fs::path& root,
                    const std::string& logical) {
    auto comps = splitLogical(logical);
    if (comps.empty()) return root;
    auto e = efs.resolve(comps);
    if (!e) throw CipherPathsError(ErrorCode::NotFound, logical);
    return e->diskPath;
}

// Resolves a top-level account folder for a credential command, creating it
// (tagged with `typeCode`) if it doesn't exist yet - mirroring the Windows
// GUI's "New Account" flow, which also creates the folder at credential-save
// time (see MainWindow.cpp). Only single-component (top-level) paths are
// auto-created; a deeper path must already exist, matching mkdir/add.
fs::path resolveOrCreateAccountFolder(EncryptedFileSystem& efs, const fs::path& root,
                                      const std::string& logical, char typeCode) {
    auto comps = splitLogical(logical);
    if (comps.empty()) throw CipherPathsError(ErrorCode::InvalidArgument, "empty folder path");
    if (comps.size() == 1) {
        if (auto existing = efs.findChild(root, comps[0])) return existing->diskPath;
        return efs.createFolder(root, comps[0], typeCode).diskPath;
    }
    auto e = efs.resolve(comps);
    if (!e) throw CipherPathsError(ErrorCode::NotFound, logical);
    return e->diskPath;
}

// Print a credential's fields to stdout, formatted for its type.
void printCredential(const Credential& cred) {
    std::cout << "Type:      " << cred.type << "\n";
    if (const WebCredential* web = PasswordEntryService::getWebCredential(cred)) {
        std::cout << "URL:       " << web->url << "\n"
                  << "Username:  " << web->username << "\n"
                  << "Password:  " << web->password << "\n"
                  << "2FA:       " << web->twoFactorType << "\n";
    } else if (const CreditCardCredential* cc = PasswordEntryService::getCreditCardCredential(cred)) {
        std::cout << "Cardholder: " << cc->cardholderName << "\n"
                  << "Card no:    " << cc->cardNumber << "\n"
                  << "Expiry:     " << cc->expiryDate << "\n"
                  << "CVV:        " << cc->cvv << "\n"
                  << "Issuer:     " << cc->issuer << "\n";
    } else if (const ContactCredential* ct = PasswordEntryService::getContactCredential(cred)) {
        std::cout << "Full name: " << ct->fullName << "\n"
                  << "Email:     " << ct->email << "\n"
                  << "Phone:     " << ct->phoneNumber << "\n"
                  << "Address:   " << ct->address << "\n"
                  << "City:      " << ct->city << "\n"
                  << "State:     " << ct->state << "\n"
                  << "Postcode:  " << ct->postalCode << "\n"
                  << "Country:   " << ct->country << "\n"
                  << "DOB:       " << ct->dateOfBirth << "\n";
    }
    if (!cred.tags.empty()) {
        std::cout << "Tags:      ";
        for (std::size_t i = 0; i < cred.tags.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << cred.tags[i];
        }
        std::cout << "\n";
    }
}

// Print the single-shot command reference; returns 1 as a process exit code.
int usage() {
    std::cout <<
        "CipherPaths CLI v" << kCoreVersion << "\n"
        "Commands:\n"
        "  init      <vault-dir>\n"
        "  open      <vault-dir>\n"
        "  ls        <vault-dir> [/logical/path]\n"
        "  mkdir     <vault-dir> /logical/path [web|creditcard|contact]\n"
        "  add       <vault-dir> /logical/parent <source-file>\n"
        "  cat       <vault-dir> /logical/path/file.txt\n"
        "  export    <vault-dir> /logical/path/file <dest-dir>\n"
        "  mv        <vault-dir> /logical/path <new-name>\n"
        "  move      <vault-dir> /logical/path /dest/folder [new-name]\n"
        "  rm        <vault-dir> /logical/path\n"
        "  setpw     <vault-dir> /TopFolder <url> <user> <password|-> [2fa]\n"
        "  setcc     <vault-dir> /TopFolder <cardholder> <card-no|-> <expiry> <cvv|-> <issuer>\n"
        "  setcontact <vault-dir> /TopFolder <full-name> <email> <phone> <address> <city> <state> <postal> <country> <dob>\n"
        "  getpw     <vault-dir> /TopFolder\n"
        "  note      <vault-dir> /Folder \"<text>\"\n"
        "  getnote   <vault-dir> /Folder\n"
        "  search    <vault-dir> <query>\n"
        "  changepw  <vault-dir>\n"
        "  version\n"
        "\n"
        "A '-' in place of a password/card-number/CVV argument prompts for it\n"
        "interactively instead (echo suppressed) - see the top of main.cpp.\n"
        "\n"
        "'open <vault-dir>' unlocks the vault once and drops into an interactive\n"
        "prompt where the commands above run repeatedly without the <vault-dir>\n"
        "argument and without re-unlocking each time. Type 'help' there for the\n"
        "in-session command list, 'exit' or 'quit' to leave.\n"
        "\n"
        "Run with no command to see this help.\n";
    return 1;
}

// Print the in-session command reference for an already-open vault.
void printInteractiveHelp() {
    std::cout <<
        "Vault commands (vault is already open - omit <vault-dir>):\n"
        "  ls        [/logical/path]\n"
        "  mkdir     /logical/path [web|creditcard|contact]\n"
        "  add       /logical/parent <source-file>\n"
        "  cat       /logical/path/file.txt\n"
        "  export    /logical/path/file <dest-dir>\n"
        "  mv        /logical/path <new-name>\n"
        "  move      /logical/path /dest/folder [new-name]\n"
        "  rm        /logical/path\n"
        "  setpw     /TopFolder <url> <user> <password|-> [2fa]\n"
        "  setcc     /TopFolder <cardholder> <card-no|-> <expiry> <cvv|-> <issuer>\n"
        "  setcontact /TopFolder <full-name> <email> <phone> <address> <city> <state> <postal> <country> <dob>\n"
        "  getpw     /TopFolder\n"
        "  note      /Folder \"<text>\"\n"
        "  getnote   /Folder\n"
        "  search    <query>\n"
        "  changepw\n"
        "  help\n"
        "  exit | quit\n"
        "\n"
        "Wrap any argument containing spaces in \"double quotes\".\n";
}

// The vault command names runVaultCommand() recognizes - used by the
// interactive loop to tell "unknown command" apart from "known command,
// wrong number of arguments" so a typo doesn't dump the whole single-shot
// usage() text (which is written in terms of <vault-dir> that doesn't apply
// inside an open session).
bool isKnownVaultCommand(const std::string& cmd) {
    static const std::vector<std::string> kKnown = {
        "ls", "mkdir", "add", "cat", "export", "mv", "move", "rm",
        "setpw", "setcc", "setcontact", "getpw", "note", "getnote", "search",
    };
    return std::find(kKnown.begin(), kKnown.end(), cmd) != kKnown.end();
}

// Runs one vault command against an already-unlocked vault/filesystem. `args`
// holds the tokens after the command word (equivalent to the single-shot
// CLI's argv[3...], i.e. everything after "<program> <cmd> <vault-dir>").
// Shared by main()'s single-shot dispatch and the interactive session loop
// so the two stay behaviourally identical.
int runVaultCommand(EncryptedFileSystem& efs, const fs::path& root,
                    const std::string& cmd, const std::vector<std::string>& args) {
    if (cmd == "ls") {
        const std::string logical = args.empty() ? "" : args[0];
        const fs::path dir = resolveDir(efs, root, logical);
        for (const auto& e : efs.list(dir)) {
            std::cout << (e.isDirectory ? "[DIR]  " : "       ")
                      << e.name;
            if (!e.isDirectory) std::cout << "  (" << e.encryptedSize << " B enc)";
            std::cout << "\n";
        }
    } else if (cmd == "mkdir") {
        if (args.size() < 1) return usage();
        auto comps = splitLogical(args[0]);
        const std::string name = comps.back();
        comps.pop_back();
        std::ostringstream parent;
        for (auto& c : comps) parent << "/" << c;
        const char typeCode = (args.size() > 1) ? recordTypeCodeForArg(args[1])
                                                  : NameCodec::kRecordTypeNone;
        efs.createFolder(resolveDir(efs, root, parent.str()), name, typeCode);
        std::cout << "Created folder " << name << "\n";
    } else if (cmd == "add") {
        if (args.size() < 2) return usage();
        const fs::path parent = resolveDir(efs, root, args[0]);
        Entry e = efs.importFile(parent, args[1]);
        std::cout << "Imported " << e.name << "\n";
    } else if (cmd == "cat") {
        if (args.size() < 1) return usage();
        auto comps = splitLogical(args[0]);
        auto e = efs.resolve(comps);
        if (!e) throw CipherPathsError(ErrorCode::NotFound, args[0]);
        SecureBuffer plain = efs.readFile(e->diskPath);
        std::cout.write(reinterpret_cast<const char*>(plain.data()),
                        static_cast<std::streamsize>(plain.size()));
        std::cout << "\n";
    } else if (cmd == "export") {
        if (args.size() < 2) return usage();
        auto comps = splitLogical(args[0]);
        auto e = efs.resolve(comps);
        if (!e) throw CipherPathsError(ErrorCode::NotFound, args[0]);
        fs::path out = e->isDirectory ? efs.exportFolder(e->diskPath, args[1])
                                      : efs.exportFile(e->diskPath, args[1]);
        std::cout << "Exported to " << out << "\n";
    } else if (cmd == "mv") {
        if (args.size() < 2) return usage();
        auto comps = splitLogical(args[0]);
        auto e = efs.resolve(comps);
        if (!e) throw CipherPathsError(ErrorCode::NotFound, args[0]);
        Entry renamed = efs.rename(e->diskPath, args[1]);
        std::cout << "Renamed to " << renamed.name << "\n";
    } else if (cmd == "move") {
        if (args.size() < 2) return usage();
        auto comps = splitLogical(args[0]);
        auto e = efs.resolve(comps);
        if (!e) throw CipherPathsError(ErrorCode::NotFound, args[0]);
        fs::path destDir = resolveDir(efs, root, args[1]);
        std::optional<std::string> newName;
        if (args.size() > 2) newName = args[2];
        Entry moved = efs.move(e->diskPath, destDir, newName);
        std::cout << "Moved to " << args[1] << "/" << moved.name << "\n";
    } else if (cmd == "rm") {
        if (args.size() < 1) return usage();
        auto comps = splitLogical(args[0]);
        auto e = efs.resolve(comps);
        if (!e) throw CipherPathsError(ErrorCode::NotFound, args[0]);
        efs.remove(e->diskPath);
        std::cout << "Removed " << args[0] << "\n";
    } else if (cmd == "setpw") {
        if (args.size() < 4) return usage();
        const fs::path folder = resolveOrCreateAccountFolder(efs, root, args[0], kTypeWeb);
        PasswordEntryService pwd(efs);
        PasswordEntry pe;
        pe.folderName = splitLogical(args[0]).back();
        pe.credential.type = "web";
        pe.credential.dateCreated = pe.credential.lastUpdated =
            pe.credential.passwordUpdated = isoNow();
        WebCredential web;
        web.url = args[1];
        web.username = args[2];
        web.password = argOrPrompt(args[3], "Password: ");
        web.twoFactorType = (args.size() > 4) ? args[4] : "";
        pe.credential.data = web;
        pwd.save(folder, pe);
        std::cout << "Saved credential for " << pe.folderName << "\n";
    } else if (cmd == "setcc") {
        if (args.size() < 6) return usage();
        const fs::path folder = resolveOrCreateAccountFolder(efs, root, args[0], kTypeCreditCard);
        PasswordEntryService pwd(efs);
        PasswordEntry pe;
        pe.folderName = splitLogical(args[0]).back();
        pe.credential.type = "creditcard";
        pe.credential.dateCreated = pe.credential.lastUpdated = isoNow();
        CreditCardCredential cc;
        cc.cardholderName = args[1];
        cc.cardNumber = argOrPrompt(args[2], "Card number: ");
        cc.expiryDate = args[3];
        cc.cvv = argOrPrompt(args[4], "CVV: ");
        cc.issuer = args[5];
        pe.credential.data = cc;
        pwd.save(folder, pe);
        std::cout << "Saved credit card credential for " << pe.folderName << "\n";
    } else if (cmd == "setcontact") {
        if (args.size() < 10) return usage();
        const fs::path folder = resolveOrCreateAccountFolder(efs, root, args[0], kTypeContact);
        PasswordEntryService pwd(efs);
        PasswordEntry pe;
        pe.folderName = splitLogical(args[0]).back();
        pe.credential.type = "contact";
        pe.credential.dateCreated = pe.credential.lastUpdated = isoNow();
        ContactCredential ct;
        ct.fullName = args[1];
        ct.email = args[2];
        ct.phoneNumber = args[3];
        ct.address = args[4];
        ct.city = args[5];
        ct.state = args[6];
        ct.postalCode = args[7];
        ct.country = args[8];
        ct.dateOfBirth = args[9];
        pe.credential.data = ct;
        pwd.save(folder, pe);
        std::cout << "Saved contact credential for " << pe.folderName << "\n";
    } else if (cmd == "getpw") {
        if (args.size() < 1) return usage();
        const fs::path folder = resolveDir(efs, root, args[0]);
        PasswordEntryService pwd(efs);
        auto pe = pwd.load(folder);
        if (!pe) { std::cout << "No credential in this folder.\n"; return 0; }
        printCredential(pe->credential);
    } else if (cmd == "note") {
        if (args.size() < 2) return usage();
        const fs::path folder = resolveDir(efs, root, args[0]);
        NotesService(efs).save(folder, args[1]);
        std::cout << "Saved notes.\n";
    } else if (cmd == "getnote") {
        if (args.size() < 1) return usage();
        const fs::path folder = resolveDir(efs, root, args[0]);
        auto text = NotesService(efs).load(folder);
        if (!text) { std::cout << "No notes in this folder.\n"; return 0; }
        std::cout << *text << "\n";
    } else if (cmd == "search") {
        if (args.size() < 1) return usage();
        SearchService search(efs);
        for (const auto& hit : search.searchAdvanced(args[0])) {
            std::string p;
            for (auto& c : hit.logicalPath) p += "/" + c;
            std::cout << p << "  -> " << hit.context << "\n";
        }
    } else {
        return usage();
    }
    return 0;
}

// Shared by the single-shot "changepw" command and the interactive session's
// "changepw". Returns false only on a confirmation mismatch (not an error -
// no exception, just "try again"); real failures throw CipherPathsError.
// Safe to call against a vault that's already open elsewhere in the same
// process: it re-wraps the Vault Master Key under a new password-derived
// key but leaves the key itself (and every subkey derived from it) bit-for-
// bit unchanged, so an already-unlocked Vault/EncryptedFileSystem stays
// valid across it (see VaultManager::changePassword's hkdfSalt comment).
bool runChangePassword(const fs::path& root) {
    if (!VaultManager::vaultExists(root)) {
        throw CipherPathsError(ErrorCode::MissingVaultHeader, root.string());
    }
    std::string oldPw = promptPassword("Current master password: ");
    std::string newPw;
    if (const char* envNew = std::getenv("CIPHERPATHS_NEW_PASSWORD")) {
        newPw = envNew;
    } else {
        newPw = readHiddenLine("New master password: ");
        std::string confirmPw = readHiddenLine("Confirm new master password: ");
        if (newPw != confirmPw) {
            std::cerr << "New passwords do not match.\n";
            return false;
        }
    }
    VaultManager::changePassword(root, oldPw, newPw);
    std::cout << "Master password changed.\n";
    return true;
}

// Unlocks the vault once (paying the Argon2id cost a single time) and runs a
// read-eval-print loop of vault commands until "exit"/"quit" or EOF. This is
// the fast path for issuing many commands: every command below re-unlocks
// from scratch and exits, which is fine for one-off/scripted use but slow
// for a whole session (see the SECURITY NOTE above and the top-of-file
// INTERACTIVE MODE comment).
int runInteractiveSession(const fs::path& root) {
    auto vault = openVault(root);
    EncryptedFileSystem efs(vault);
    std::cout << "Vault opened: " << root.string() << "\n"
              << "Type 'help' for commands, 'exit' or 'quit' to leave.\n";

    std::string line;
    for (;;) {
        std::cout << "cipherpaths> " << std::flush;
        if (!std::getline(std::cin, line)) {
            std::cout << "\n";
            break; // EOF (Ctrl+D / Ctrl+Z)
        }
        stripUtf8Bom(line);
        auto tokens = tokenizeLine(line);
        if (tokens.empty()) continue;

        const std::string cmd = tokens[0];
        const std::vector<std::string> args(tokens.begin() + 1, tokens.end());

        if (cmd == "exit" || cmd == "quit") break;
        if (cmd == "help") { printInteractiveHelp(); continue; }

        try {
            if (cmd == "changepw") {
                runChangePassword(root);
            } else if (cmd == "open" || cmd == "init") {
                std::cerr << "Already in an open session - '" << cmd
                          << "' is not valid here.\n";
            } else if (!isKnownVaultCommand(cmd)) {
                std::cerr << "Unknown command '" << cmd
                          << "'. Type 'help' for the list.\n";
            } else {
                runVaultCommand(efs, root, cmd, args);
            }
        } catch (const CipherPathsError& e) {
            std::cerr << "Error: " << e.what() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Unexpected error: " << e.what() << "\n";
        }
    }
    return 0;
}

} // namespace

// Entry point: dispatch a single-shot command, or drop into an interactive session.
int main(int argc, char** argv) {
    if (argc < 2) return usage();
    const std::string cmd = argv[1];

    if (cmd == "version" || cmd == "--version" || cmd == "-v") {
        std::cout << "cipherpaths-cli " << kCoreVersion
                  << " (" << crypto::opensslVersion() << ")\n";
        return 0;
    }

    if (argc < 3) return usage();
    const fs::path root = argv[2];

    try {
        if (cmd == "init") {
            if (VaultManager::vaultExists(root)) {
                std::cerr << "A vault already exists at " << root << "\n";
                return 1;
            }
            std::string pw = promptPassword("Create master password: ");
            std::cout << "Password strength: "
                      << VaultManager::passwordStrengthHint(pw) << "\n";
            auto created = VaultManager::create(root, pw);
            std::cout << "Vault created at " << root << "\n\n"
                      << "==================== RECOVERY KEY ====================\n"
                      << created.recoveryKey << "\n"
                      << "======================================================\n"
                      << "Print and store this key safely. It is the ONLY way to\n"
                      << "recover the vault if you forget the master password.\n";
            return 0;
        }

        if (cmd == "changepw") {
            return runChangePassword(root) ? 0 : 1;
        }

        if (cmd == "open") {
            return runInteractiveSession(root);
        }

        auto vault = openVault(root);
        EncryptedFileSystem efs(vault);
        const std::vector<std::string> args(argv + 3, argv + argc);
        return runVaultCommand(efs, root, cmd, args);
    } catch (const CipherPathsError& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << "\n";
        return 3;
    }
}
