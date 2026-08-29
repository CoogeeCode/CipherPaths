@echo off
setlocal EnableExtensions
REM ===========================================================================
REM  demo-vault.cmd - end-to-end cipherpaths CLI walkthrough.
REM
REM  Creates a fresh vault at c:\temp\mytestvault1, populates it with several
REM  web logins (URL + username + dummy password) and a note on each, then
REM  lists the vault and dumps every entry's details.
REM
REM  Run from anywhere:  CommandLine\demo-vault.cmd
REM
REM  SECURITY: this script puts the master password in CIPHERPATHS_PASSWORD and
REM  the entry passwords in the command line, both of which are visible to any
REM  process that can read this one's environment / argv. That is fine for a
REM  throwaway demo vault; for real data drop the CIPHERPATHS_PASSWORD line
REM  (you will be prompted, echo suppressed) and pass "-" instead of each
REM  password to be prompted for it.
REM
REM  A note on the execution speed. Unlocking the vault for each command can be
REM  slow. Around 0.5sec to 1sec per command. This is by design to prevent brute
REM  force attacks. For faster operation use interactive mode.
REM ===========================================================================

set "CP=%~dp0cipherpaths.exe"
set "VAULT=c:\temp\mytestvault1"

REM The CLI reads the master password from here instead of prompting.
set "CIPHERPATHS_PASSWORD=Corr3ct-Horse-Batt3ry-Staple"

if not exist "%CP%" (
    echo ERROR: cipherpaths.exe not found next to this script ^(%CP%^).
    exit /b 1
)

REM --------------------------------------------------------------------------
REM  1. Create the vault
REM 
REM Use the JSON settings file to check if vault already exists in this folder
REM --------------------------------------------------------------------------
echo === Creating vault at %VAULT% ===
if exist "%VAULT%\cipherpaths-vault.json" (
    echo A vault already exists at %VAULT% - delete the folder first to re-run.
    exit /b 1
)
"%CP%" init "%VAULT%" || exit /b 1
echo.

REM --------------------------------------------------------------------------
REM  2. Add web credentials
REM
REM  setpw <vault-dir> /TopFolder <url> <user> <password> [2fa]
REM  The top-level folder is created automatically (tagged as a "web" record)
REM  if it does not exist yet, so no mkdir is needed first.
REM --------------------------------------------------------------------------
echo === Adding site credentials ===
"%CP%" setpw "%VAULT%" /GitHub           https://github.com/login          dave@example.com   Gh-dummy-pw-001   totp   || exit /b 1
"%CP%" setpw "%VAULT%" /Amazon           https://www.amazon.com.au/signin  dave@example.com   Az-dummy-pw-002          || exit /b 1
"%CP%" setpw "%VAULT%" /MyBank           https://online.mybank.com.au      dave.smith         Bk-dummy-pw-003   sms    || exit /b 1
"%CP%" setpw "%VAULT%" /Reddit           https://www.reddit.com/login      cipherfan          Rd-dummy-pw-004          || exit /b 1
"%CP%" setpw "%VAULT%" /WorkVPN          https://vpn.contoso.example       dsmith             Vp-dummy-pw-005   totp   || exit /b 1

REM  Use quotes if a string has space characters in it.
"%CP%" setpw "%VAULT%" "/Chase bank"     https://www.chase.com             dsmith             "my password"     totp   || exit /b 1

REM A literal % in a CMD batch file must be doubled (%%), even inside quotes.
REM Passwords with quote characters in the password are problmatic in
REM Windows CMD as it is hard to esacepe the quote. 
"%CP%" setpw "%VAULT%" "/Google - Mary"  https://www.google.com            mary@google.com    "!@#$%%^&*()"     sms    || exit /b 1
echo.

REM --------------------------------------------------------------------------
REM  3. Attach a free-text note to each entry
REM
REM  note <vault-dir> /Folder "<text>"   (the folder must already exist)
REM --------------------------------------------------------------------------
echo === Adding notes ===
"%CP%" note "%VAULT%" /GitHub   "Personal account. Recovery codes are in the safe. SSH key: id_ed25519." || exit /b 1
"%CP%" note "%VAULT%" /Amazon   "Prime renews every March. Card on file is the Visa ending 4242."       || exit /b 1
"%CP%" note "%VAULT%" /MyBank   "Customer number 10293847. Phone banking PIN is stored separately."     || exit /b 1
"%CP%" note "%VAULT%" /Reddit   "Throwaway account used for the CipherPaths beta announcement."         || exit /b 1
"%CP%" note "%VAULT%" /WorkVPN  "Contoso engineering VPN. Rotate every 90 days per IT policy."          || exit /b 1
echo.

REM --------------------------------------------------------------------------
REM  4. List the vault
REM --------------------------------------------------------------------------
echo === Vault contents ===
"%CP%" ls "%VAULT%"
echo.

echo === Files inside /GitHub ===
"%CP%" ls "%VAULT%" /GitHub
echo.

REM --------------------------------------------------------------------------
REM  5. Show the details of every entry
REM --------------------------------------------------------------------------
echo === Entry details ===
for %%S in (GitHub Amazon MyBank Reddit WorkVPN "Chase bank" "Google - Mary") do (
    echo --------------------------------------------------
    echo [/%%S]
    "%CP%" getpw   "%VAULT%" /%%S
    echo Notes:
    "%CP%" getnote "%VAULT%" /%%S
    echo.
)

REM --------------------------------------------------------------------------
REM  6. Search across every decrypted field
REM --------------------------------------------------------------------------
echo === Search: "example.com" ===
"%CP%" search "%VAULT%" example.com
echo.

echo === Search: "vpn" ===
"%CP%" search "%VAULT%" vpn
echo.

echo Done. Vault is at %VAULT%
endlocal
