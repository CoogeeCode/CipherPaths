# Security Policy

## Scope

This policy covers:

- The **CipherPaths core engine** (`core/`) and **command-line tool** (`CommandLine/`) in
  this repository.
- The **CipherPaths Windows GUI application** distributed from
  <https://cipherpaths.com/download.html>.

All cryptography is provided by **OpenSSL (libcrypto)**. Vulnerabilities in OpenSSL itself
should be reported to the OpenSSL project; CipherPaths picks up fixed releases as they land.
If an OpenSSL issue is exploitable *specifically because of how CipherPaths uses it*, we do
want to hear about that.

## Supported versions

CipherPaths is a free project with a single active release line. We only investigate reports
against the **current latest release**:

<https://cipherpaths.com/download.html>

| Version | Supported |
| --- | --- |
| Current latest release | :white_check_mark: |
| Anything older | :x: |

Please confirm the issue reproduces on the latest build before reporting. Run
`cipherpaths version` (CLI) or open **Help → About** (GUI) to check what you are running.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security report.**

Report privately using the contact details on the publisher's website:

**<https://www.coogeecode.com.au/>** — Coogee Code Pty. Ltd., Australia (publisher of CipherPaths)

If your report contains sensitive detail, ask via that contact form for a key so you can
send it encrypted.

### Your report must include a proof of concept

A report **must contain a working proof of concept**. Scanner output, theoretical
descriptions, or "this looks wrong" with no demonstration will be closed without
investigation.

Please provide:

1. **A proof of concept** — the smallest set of steps, inputs, sample files, script, or
   short program that demonstrates the issue. A throwaway vault created for the demo is
   ideal; never send a real vault or real secrets.
2. **The exact version** tested (see *Supported versions*) and your OS and CPU architecture.
3. **Impact** — what an attacker gains, and what they need first (Do they already know the
   master password or recovery key? Do they need local code execution or admin rights? Do
   they need read or write access to the vault files?).
4. **Expected vs. actual behaviour**, and any relevant logs or crash output.

### What to expect

- This is an **unpaid, best-effort project**. **There is no bug bounty and no monetary
  reward.** If you would like credit, we are happy to name you in the release notes and in
  this file.
- We aim to **acknowledge** a valid report within about **7 days**, and to give a first
  assessment (accepted / need more info / declined, with reasoning) within about **21 days**.
- If accepted, we will work on a fix, keep you updated on progress, and agree a disclosure
  date with you. Fixes ship in the next release on the download page.
- If declined, we will explain why — typically out of scope, working as designed, not
  reproducible, or an already-documented limitation (see below).

### Coordinated disclosure

Please give us a reasonable chance to release a fix before going public — normally **90 days**
from acknowledgement, or sooner once a fixed release is out. We will not pursue legal action
against researchers who act in good faith, stay within the scope of this policy, and do not
access, modify, or destroy data that is not their own.

## What we are most interested in

- Any way to recover file **contents or names**, credentials, or notes from a vault
  **without** the master password or recovery key.
- Weaknesses in key derivation, key wrapping, or header authentication — Argon2id
  parameters, HKDF domain separation, the vault-header HMAC, or recovery-key handling.
- Nonce reuse, authentication-tag bypasses, or padding/oracle issues in the `CPF1` file
  content format or the `CP#1` encrypted-name format.
- Memory-safety bugs (buffer over-reads/overflows, use-after-free) reachable from a crafted
  vault or a crafted file added to a vault.
- Plaintext key material or decrypted file content written to disk by the core engine or the
  CLI when it should stay in memory.

## Out of scope

The following are known, accepted properties of the design and are **not** treated as
vulnerabilities unless you can demonstrate impact beyond what is already documented in the
[user guide](https://www.cipherpaths.com/guide.html):

- **Metadata the format deliberately does not hide:** the number of files, the folder/tree
  structure, the approximate size of very large files, and activity timing.
- **Plaintext exposure through the operating system**, outside the application's control:
  the clipboard, pagefile/swap, hibernation image, crash dumps, the memory of an already
  compromised machine, screen capture, or third-party tools inspecting process memory.
- **Attacks that assume the attacker already holds the master password or recovery key**, or
  already has code execution or administrator rights on the unlocked machine.
- **Out-of-band tampering with vault files** using other tools. CipherPaths authenticates the
  *content* of every file and the vault header, but does not keep a signed manifest of the
  whole directory, so deletion or rollback of individual files by an external actor is only
  detected when that entry is next accessed.
- **Source files left on disk after import**, and **exported (decrypted) files** — both are
  outside the vault by design.
- **The theoretical AES-GCM random-nonce birthday bound** — unreachable in practice for a
  single vault (see the specification).
- Missing "defense in depth" hardening with no demonstrated exploit (build flags,
  non-security-relevant static-analysis findings, and similar).
- Reports against any version other than the current latest release.
