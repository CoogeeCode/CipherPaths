#!/usr/bin/env bash
# demo-vault.sh - end-to-end cipherpaths CLI walkthrough (single-shot mode).
#
# Creates a fresh vault, populates it with several web logins (URL +
# username + dummy password) and a note on each, then lists the vault and
# dumps every entry's details. Every command below is its own cipherpaths
# process, so it re-unlocks the vault (a deliberately expensive Argon2id
# derivation - see core/include/cipherpaths/Crypto.h) from scratch each
# time. See demo-vault-interactive.sh for the same walkthrough done as one
# "open" session, which pays that unlock cost once instead of ~20+ times.
#
# Run from anywhere:  CommandLine/linux/x64/demo-vault.sh
#
# SECURITY: this script puts the master password in CIPHERPATHS_PASSWORD and
# the entry passwords on the command line, both of which are visible to any
# process that can read this one's environment (e.g. /proc/<pid>/environ) or
# argv (e.g. `ps -ef`). That is fine for a throwaway demo vault; for real
# data drop the CIPHERPATHS_PASSWORD line (you will be prompted, echo
# suppressed) and pass "-" instead of each password to be prompted for it.
#
# QUOTING: this is plain bash - single-quoting an argument ('...') makes it
# completely literal, no escaping needed even for characters like $, `, !,
# &, *, (, ). Contrast with the cmd.exe version of this demo, where a
# literal % has to be doubled as %% even inside double quotes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP="$SCRIPT_DIR/cipherpaths"
VAULT="/tmp/cipherpaths-demo-cli"

if [ ! -x "$CP" ]; then
    echo "ERROR: cipherpaths not found (or not executable) next to this script ($CP)." >&2
    exit 1
fi

# The CLI reads the master password from here instead of prompting.
export CIPHERPATHS_PASSWORD='Corr3ct-Horse-Batt3ry-Staple'

echo "=== Creating vault at $VAULT ==="
if [ -f "$VAULT/cipherpaths-vault.json" ]; then
    echo "A vault already exists at $VAULT - delete it first to re-run:"
    echo "  rm -rf '$VAULT'"
    exit 1
fi
"$CP" init "$VAULT"
echo

# setpw <vault-dir> /TopFolder <url> <user> <password> [2fa]
# The top-level folder is created automatically (tagged as a "web" record)
# if it doesn't exist yet, so no mkdir is needed first.
echo "=== Adding site credentials ==="
"$CP" setpw "$VAULT" /GitHub          https://github.com/login          dave@example.com   Gh-dummy-pw-001   totp
"$CP" setpw "$VAULT" /Amazon          https://www.amazon.com.au/signin  dave@example.com   Az-dummy-pw-002
"$CP" setpw "$VAULT" /MyBank          https://online.mybank.com.au      dave.smith         Bk-dummy-pw-003   sms
"$CP" setpw "$VAULT" /Reddit          https://www.reddit.com/login      cipherfan          Rd-dummy-pw-004
"$CP" setpw "$VAULT" /WorkVPN         https://vpn.contoso.example       dsmith             Vp-dummy-pw-005   totp
"$CP" setpw "$VAULT" '/Chase bank'    https://www.chase.com             dsmith             'my password'     totp
"$CP" setpw "$VAULT" '/Google - Mary' https://www.google.com            mary@google.com    '!@#$%^&*()'      sms
echo

# note <vault-dir> /Folder "<text>"   (the folder must already exist)
echo "=== Adding notes ==="
"$CP" note "$VAULT" /GitHub  "Personal account. Recovery codes are in the safe. SSH key: id_ed25519."
"$CP" note "$VAULT" /Amazon  "Prime renews every March. Card on file is the Visa ending 4242."
"$CP" note "$VAULT" /MyBank  "Customer number 10293847. Phone banking PIN is stored separately."
"$CP" note "$VAULT" /Reddit  "Throwaway account used for the CipherPaths beta announcement."
"$CP" note "$VAULT" /WorkVPN "Contoso engineering VPN. Rotate every 90 days per IT policy."
echo

echo "=== Vault contents ==="
"$CP" ls "$VAULT"
echo

echo "=== Files inside /GitHub ==="
"$CP" ls "$VAULT" /GitHub
echo

echo "=== Entry details ==="
folders=(GitHub Amazon MyBank Reddit WorkVPN "Chase bank" "Google - Mary")
for f in "${folders[@]}"; do
    echo "--------------------------------------------------"
    echo "[/$f]"
    "$CP" getpw "$VAULT" "/$f"
    echo "Notes:"
    "$CP" getnote "$VAULT" "/$f"
    echo
done

echo "=== Search: \"example.com\" ==="
"$CP" search "$VAULT" example.com
echo

echo "=== Search: \"vpn\" ==="
"$CP" search "$VAULT" vpn
echo

echo "Done. Vault is at $VAULT"
