<#
.SYNOPSIS
  Validate the Windows nkCryptoTool P2P shell server (ConPTY) end to end on real
  Windows: generate keys, start the shell server, connect a client to run one
  command (automated smoke), then drop into a live interactive shell.

.DESCRIPTION
  The shell server allocates a Windows pseudo-console (ConPTY) via the Rust shim
  (portable-pty) — the same path the Rust build uses. It REFUSES to run elevated
  (no privilege drop), so run this from a STANDARD (non-Administrator) PowerShell.
  All traffic is one iroh QUIC stream with P-256 + ML-KEM-768 + ML-DSA-65 mutual
  auth; nothing listens on a TCP port.

.PARAMETER Exe
  Path to nkCryptoTool.exe (default: .\nkCryptoTool.exe).

.PARAMETER Cmd
  Command the automated smoke test runs on the remote shell.

.PARAMETER SmokeOnly
  Run only the automated one-command test; skip the interactive session.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File win-p2p-shell-test.ps1 -Exe .\nkCryptoTool.exe
#>
param(
    [string]$Exe = ".\nkCryptoTool.exe",
    [string]$Cmd = "whoami & ver",
    [switch]$SmokeOnly
)

$ErrorActionPreference = "Stop"

function Find-Ticket([string[]]$Files) {
    foreach ($f in $Files) {
        if (Test-Path $f) {
            $m = Select-String -Path $f -Pattern 'nkct1[A-Z2-7]+' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($m) { return $m.Matches[0].Value }
        }
    }
    return $null
}

# --- resolve exe -----------------------------------------------------------
if (-not (Test-Path $Exe)) { throw "nkCryptoTool.exe not found at '$Exe' — pass -Exe <path>." }
$Exe = (Resolve-Path $Exe).Path
Write-Host "exe        : $Exe"

# --- the server refuses to run elevated; warn early ------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This PowerShell is ELEVATED (Administrator). The shell server refuses to run elevated."
    Write-Warning "Open a NORMAL (non-admin) PowerShell and re-run, or the server will exit with 'refusing to serve a shell as root'."
}

# --- workspace + unencrypted demo keys (no passphrase prompt) --------------
$Work = Join-Path $env:TEMP ("nkct-shtest-" + [guid]::NewGuid().ToString("N").Substring(0,8))
$Sdir = Join-Path $Work "s"; $Cdir = Join-Path $Work "c"
New-Item -ItemType Directory -Force -Path $Sdir, $Cdir | Out-Null
$env:NK_PASSPHRASE = ""      # empty => keys are written unencrypted, nothing prompts
Write-Host "workdir    : $Work"

try {
    # --- 1) generate server + client ML-DSA-65 signing keys ----------------
    Write-Host "`n[1/4] generating ML-DSA-65 keys (server + client)..."
    & $Exe --gen-sign-key --mode pqc --key-dir $Sdir | Out-Null
    & $Exe --gen-sign-key --mode pqc --key-dir $Cdir | Out-Null
    $sPriv = Join-Path $Sdir "private_sign_pqc.key"; $sPub = Join-Path $Sdir "public_sign_pqc.key"
    $cPriv = Join-Path $Cdir "private_sign_pqc.key"; $cPub = Join-Path $Cdir "public_sign_pqc.key"
    if (-not (Test-Path $sPriv) -or -not (Test-Path $cPriv)) { throw "key generation failed (see above)." }
    Write-Host "      keys ok."

    # --- 2) start the shell server, pin the client, capture the ticket -----
    Write-Host "`n[2/4] starting the shell server (ConPTY)..."
    $srvOut = Join-Path $Work "srv.out"; $srvErr = Join-Path $Work "srv.err"
    $srv = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $srvOut -RedirectStandardError $srvErr `
        -ArgumentList @("--serve-shell","--mode","pqc",
                        "--signing-privkey",$sPriv,"--signing-pubkey",$cPub)

    $ticket = $null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 300
        if ($srv.HasExited) {
            Write-Host "      server exited early. Log:" -ForegroundColor Red
            Get-Content $srvOut, $srvErr -ErrorAction SilentlyContinue | Write-Host
            throw "server did not stay up (elevated? missing --signing-pubkey?)."
        }
        $ticket = Find-Ticket @($srvOut, $srvErr)
        if ($ticket) { break }
    }
    if (-not $ticket) { throw "no ticket from the server; see $srvOut / $srvErr." }
    Write-Host ("      server up, ticket {0}..." -f $ticket.Substring(0, [Math]::Min(44,$ticket.Length)))

    # --- 3) automated smoke: run one command on the remote shell -----------
    Write-Host "`n[3/4] client smoke test — running '$Cmd' on the remote shell:"
    Write-Host "----------------------------------------------------------------"
    & $Exe --shell --shell-cmd $Cmd --connect $ticket --mode pqc `
        --signing-privkey $cPriv --signing-pubkey $sPub
    $rc = $LASTEXITCODE
    Write-Host "----------------------------------------------------------------"
    Write-Host ("      client exit code: {0}" -f $rc)
    Write-Host "      server log:"
    Get-Content $srvOut, $srvErr -ErrorAction SilentlyContinue |
        Select-String 'authenticated|shell open|ended|error|refus' | ForEach-Object { "        $_" }

    # The single-shot server handled one session; restart it for the interactive run.
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }

    if ($SmokeOnly) { return }

    # --- 4) interactive session -------------------------------------------
    Write-Host "`n[4/4] interactive shell — type commands, then 'exit' to finish."
    $srv2 = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $srvOut -RedirectStandardError $srvErr `
        -ArgumentList @("--serve-shell","--mode","pqc",
                        "--signing-privkey",$sPriv,"--signing-pubkey",$cPub)
    $ticket2 = $null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 300
        if ($srv2.HasExited) { break }
        $ticket2 = Find-Ticket @($srvOut, $srvErr)
        if ($ticket2) { break }
    }
    if (-not $ticket2) { Write-Warning "interactive server did not come up; skipping."; return }
    Write-Host "----------------------------------------------------------------"
    & $Exe --shell --connect $ticket2 --mode pqc `
        --signing-privkey $cPriv --signing-pubkey $sPub
    Write-Host "----------------------------------------------------------------"
    if (-not $srv2.HasExited) { Stop-Process -Id $srv2.Id -Force -ErrorAction SilentlyContinue }
}
finally {
    Get-Process -Name "nkCryptoTool" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
    Write-Host "`ndone. (workspace cleaned)"
}

Write-Host @"

Manual two-terminal interactive run (no script):
  # terminal 1 (server, NON-admin):
  `$env:NK_PASSPHRASE=""
  nkCryptoTool.exe --gen-sign-key --mode pqc --key-dir s
  nkCryptoTool.exe --gen-sign-key --mode pqc --key-dir c
  nkCryptoTool.exe --serve-shell --mode pqc --signing-privkey s\private_sign_pqc.key --signing-pubkey c\public_sign_pqc.key
  # copy the printed nkct1... ticket, then in terminal 2 (client):
  nkCryptoTool.exe --shell --connect <ticket> --mode pqc --signing-privkey c\private_sign_pqc.key --signing-pubkey s\public_sign_pqc.key
"@
