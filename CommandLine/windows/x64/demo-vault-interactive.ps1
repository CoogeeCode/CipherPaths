<#
.SYNOPSIS
    Interactive-mode walkthrough of the cipherpaths CLI (PowerShell).

.DESCRIPTION
    Creates a fresh vault at c:\temp\mytestvault-interactive, then unlocks it
    ONCE with `cipherpaths open` and drives an entire interactive session -
    several web logins (URL + username + dummy password), a note on each,
    a listing, full details for every entry, and a couple of searches - all
    against that single unlocked session, before exiting.

    This is the interactive-mode counterpart to demo-vault.cmd, which does
    the same walkthrough the single-shot way (one cipherpaths.exe process,
    and one Argon2id vault-unlock, per command). `open` unlocks once and
    pays that cost a single time for the whole session instead - see the
    timing printed at the end of this script for the difference.

    Run from anywhere:  CommandLine\windows\x64\demo-vault-interactive.ps1

.NOTES
    SECURITY: this script puts the master password in $env:CIPHERPATHS_PASSWORD
    and the entry passwords inline in the command list below, both of which
    are visible to any process that can read this one's environment, and the
    command list is visible in this file. That is fine for a throwaway demo
    vault; for real data drop the CIPHERPATHS_PASSWORD line (you will be
    prompted, echo suppressed) and type "-" in place of a password at the
    interactive prompt to be prompted for it instead.

    QUOTING: the command list below is a single-quoted here-string
    (@' ... '@), so PowerShell does none of its own variable expansion or
    escaping on it - $, `, %, ^, &, *, (, ) all pass through completely
    literally (contrast with the cmd.exe version of this demo, where a
    literal % has to be doubled as %% even inside quotes). The double quotes
    you see inside the here-string are not PowerShell's - they are
    cipherpaths' OWN interactive-mode quoting, needed to keep an argument
    that contains spaces (a folder name, a note, a password) as one token,
    exactly as you'd type it by hand at the "cipherpaths>" prompt.
#>

$ErrorActionPreference = 'Stop'

$CP    = Join-Path $PSScriptRoot 'cipherpaths.exe'
$Vault = 'c:\temp\mytestvault-interactive'

if (-not (Test-Path $CP)) {
    Write-Error "cipherpaths.exe not found next to this script ($CP)."
    exit 1
}

if (Test-Path (Join-Path $Vault 'cipherpaths-vault.json')) {
    Write-Host "A vault already exists at $Vault - delete the folder first to re-run." -ForegroundColor Yellow
    exit 1
}

# The CLI reads the master password from here instead of prompting.
$env:CIPHERPATHS_PASSWORD = 'Corr3ct-Horse-Batt3ry-Staple'

try {
    # --------------------------------------------------------------------
    # 1. Create the vault. `init` is a single-shot-only command - it isn't
    #    valid inside an open session, so it runs before `open`.
    # --------------------------------------------------------------------
    Write-Host "=== Creating vault at $Vault ===" -ForegroundColor Cyan
    & $CP init $Vault
    if ($LASTEXITCODE -ne 0) { throw "cipherpaths init failed (exit $LASTEXITCODE)" }
    Write-Host ""

    # --------------------------------------------------------------------
    # 2. Everything else - adding sites, notes, listing, reading every
    #    entry back, searching - happens in ONE interactive session. The
    #    vault is unlocked exactly once, by the "open" call at the bottom;
    #    every line below runs against that single already-unlocked vault.
    # --------------------------------------------------------------------
    $sessionCommands = @'
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
'@

    Write-Host "=== Opening interactive session (single unlock) ===" -ForegroundColor Cyan
    # A manual stopwatch (rather than Measure-Command) so the child process's
    # output keeps streaming straight to the console instead of being
    # captured and discarded by Measure-Command's script-block output rules.
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sessionCommands | & $CP open $Vault
    $stopwatch.Stop()
    if ($LASTEXITCODE -ne 0) { throw "cipherpaths open failed (exit $LASTEXITCODE)" }
    $elapsed = $stopwatch.Elapsed

    Write-Host ""
    Write-Host ("Interactive session ({0} commands) took {1:N2}s total." -f `
        (($sessionCommands -split "`n") | Where-Object { $_.Trim() -and $_.Trim() -ne 'exit' }).Count, `
        $elapsed.TotalSeconds) -ForegroundColor Green
    Write-Host "Compare with demo-vault.cmd, which pays a fresh Argon2id unlock per command." -ForegroundColor Green
    Write-Host "Done. Vault is at $Vault"
}
finally {
    Remove-Item Env:\CIPHERPATHS_PASSWORD -ErrorAction SilentlyContinue
}
