# Installs shelfd + shelf into %USERPROFILE%\.cargo\bin and starts shelfd at
# logon via a Startup folder shortcut (named pipes already provide Windows IPC).
# Run from a clone: powershell -ExecutionPolicy Bypass -File contrib/windows/install-user.ps1
# Do not put SHELF_PASSPHRASE in this script. Prefer platform custody (Windows
# Hello / DPAPI wrap). See docs/INSTALL.md.

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path (Join-Path $RepoRoot 'apps\shelfd'))) {
    Write-Error "Could not find apps/shelfd relative to $PSScriptRoot. Run this script from a Shelf clone."
}

function Install-ShelfCrate {
    param([string]$RelPath)
    $path = Join-Path $RepoRoot $RelPath
    Write-Host "cargo install --path $path --force"
    cargo install --path $path --force
    if ($LASTEXITCODE -ne 0) {
        throw "cargo install failed for $RelPath (exit $LASTEXITCODE)"
    }
}

Install-ShelfCrate 'apps\shelfd'
Install-ShelfCrate 'apps\shelf-cli'

$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$shelfd = Join-Path $cargoHome 'bin\shelfd.exe'
if (-not (Test-Path $shelfd)) {
    throw "shelfd was not installed at $shelfd"
}

$startup = [Environment]::GetFolderPath('Startup')
if (-not $startup) {
    throw 'Could not resolve the current user Startup folder.'
}

$lnkPath = Join-Path $startup 'shelfd.lnk'
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($lnkPath)
    $shortcut.TargetPath = $shelfd
    $shortcut.WorkingDirectory = Split-Path -Parent $shelfd
    $shortcut.WindowStyle = 7
    $shortcut.Description = 'Shelf replica daemon'
    $shortcut.Save()
    Write-Host "Startup shortcut: $lnkPath"
} catch {
    $cmdPath = Join-Path $startup 'shelfd.cmd'
    $line = 'start "" /min "' + $shelfd + '"'
    Set-Content -Path $cmdPath -Value @('@echo off', $line) -Encoding ASCII
    Write-Host "Startup shortcut COM failed; wrote $cmdPath instead."
}

Write-Host "Installed. Log off/on (or start $shelfd) so the user service is running."
Write-Host "Optional GUI: cargo install --path apps/shelf-desktop --force  (or: mise run install)"
