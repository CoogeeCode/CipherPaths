#!/usr/bin/env bash
# demo-vault-interactive.sh - interactive-mode cipherpaths CLI walkthrough.
#
# Creates a fresh vault, then unlocks it ONCE with `cipherpaths open` and
# drives an entire interactive session - the same site logins, notes,
# listing, full entry details and searches as demo-vault.sh - all against
# that single unlocked session, before exiting. `init` runs single-shot
# first, since it isn't a valid command inside an open session.
#
# This is the interactive-mode counterpart to demo-vault.sh: that script
# pays a fresh Argon2id vault-unlock per command (~20+ times); this one
# pays it exactly once for the whole session - see the timing printed at
# the end.
#
# Run from anywhere:  CommandLine/linux/x64/demo-vault-interactive.sh
#
# SECURITY: see demo-vault.sh's header - the same notes about
# CIPHERPATHS_PASSWORD and argv visibility apply here too.
#
# QUOTING: the command list below is fed through a QUOTED heredoc
# (<<'CMDS'), which disables all bash expansion inside it - $, `, \, ! are
# all completely literal, the same way demo-vault-interactive.ps1 uses a
# single-quoted PowerShell here-string. The double quotes you see inside it
# are not bash's - they are cipherpaths' OWN interactive-mode quoting,
# needed to keep an argument containing spaces (a folder name, a note, a
# password) as one token, exactly as you'd type it by hand at the
# "cipherpaths>" prompt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP="$SCRIPT_DIR/cipherpaths"
VAULT="/tmp/cipherpaths-demo-interactive"

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

echo "=== Opening interactive session (single unlock) ==="
start_ns=$(date +%s%N)
"$CP" open "$VAULT" <<'CMDS'
setpw /GitHub https://github.com/login dave@example.com Gh-dummy-pw-001 totp
setpw /Amazon https://www.amazon.com.au/signin dave@example.com Az-dummy-pw-002
setpw /MyBank https://online.mybank.com.au dave.smith Bk-dummy-pw-003 sms
setpw /Reddit https://www.reddit.com/login cipherfan Rd-dummy-pw-004
setpw /WorkVPN https://vpn.contoso.example dsmith Vp-dummy-pw-005 totp
setpw "/Chase bank" https://www.chase.com dsmith "my password" totp
setpw "/Google - Mary" https://www.google.com mary@google.com "!@#$%^&*()" sms
note /GitHub "Personal account. Recovery codes are in the safe. SSH key: id_ed25519."
note /Amazon "Prime renews every March. Card on file is the Visa ending 4242."
note /MyBank "Customer number 10293847. Phone banking PIN is stored separately."
note /Reddit "Throwaway account used for the CipherPaths beta announcement."
note /WorkVPN "Contoso engineering VPN. Rotate every 90 days per IT policy."
ls
ls /GitHub
getpw /GitHub
getnote /GitHub
getpw /Amazon
getnote /Amazon
getpw /MyBank
getnote /MyBank
getpw /Reddit
getnote /Reddit
getpw /WorkVPN
getnote /WorkVPN
getpw "/Chase bank"
getpw "/Google - Mary"
search example.com
search vpn
exit
CMDS
end_ns=$(date +%s%N)

elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
echo
echo "Interactive session (28 commands) took ${elapsed_ms} ms total."
echo "Compare with demo-vault.sh, which pays a fresh Argon2id unlock per command."
echo "Done. Vault is at $VAULT"
