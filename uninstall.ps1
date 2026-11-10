# FaradAiWire Native Uninstaller (Windows PowerShell)
# Usage: irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.ps1 | iex
# Purge data too: $env:FARADAI_WIRE_PURGE = "1"; irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.ps1 | iex

[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$BinaryName = "faradaiwire.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\faradaiwire"
$DataDir = if ($env:FARADAI_WIRE_HOME) { $env:FARADAI_WIRE_HOME } else { Join-Path $env:USERPROFILE ".faradaiwire" }
$ShouldPurge = $Purge.IsPresent -or ($env:FARADAI_WIRE_PURGE -eq "1") -or ($env:FARADAI_WIRE_PURGE -eq "true")

# Guard $DataDir against empty or dangerous system/root paths before any purge operation
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    Write-Error "Refusing empty data directory path."
    exit 1
}
$FullDataDir = [System.IO.Path]::GetFullPath($DataDir).TrimEnd('\')
$DataRoot = [System.IO.Path]::GetPathRoot($FullDataDir).TrimEnd('\')
$ProtectedPaths = @(
    $DataRoot,
    $env:USERPROFILE,
    $env:LOCALAPPDATA,
    $env:APPDATA,
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:SystemRoot,
    $env:TEMP,
    $env:TMP
) | Where-Object { $_ } | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }

if ($ProtectedPaths -contains $FullDataDir) {
    Write-Error "Refusing unsafe data directory path: '$DataDir'"
    exit 1
}

# 1. Restore adopted IDE configurations if backups exist
$BinaryPath = Join-Path $InstallDir $BinaryName
if (!(Test-Path $BinaryPath)) {
    $Cmd = Get-Command "faradaiwire.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $BinaryPath = if ($Cmd) { $Cmd.Source } else { $null }
}

$BackupsDir = Join-Path $FullDataDir "backups"
if ($BinaryPath -and (Test-Path $BinaryPath) -and (Test-Path $BackupsDir)) {
    $BackupFiles = Get-ChildItem -Path $BackupsDir -Filter "*.bak" -ErrorAction SilentlyContinue
    if ($BackupFiles) {
        Write-Host "🔄 Restoring adopted IDE configurations from backups..." -ForegroundColor Cyan
        try {
            & $BinaryPath adopt --rollback --backup-dir $BackupsDir
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Could not restore all client backups automatically (exit code $LASTEXITCODE)."
            }
        } catch {
            Write-Warning "Could not restore all client backups automatically: $_"
        }
    }
}

# 2. Stop any running faradaiwire process and wait up to 10s so binary & DuckDB locks flush cleanly
$Running = Get-Process -Name "faradaiwire" -ErrorAction SilentlyContinue
if ($Running) {
    Write-Host "🛑 Stopping running FaradAiWire process (waiting up to 10s)..." -ForegroundColor Yellow
    Stop-Process -Name "faradaiwire" -ErrorAction SilentlyContinue
    $Exited = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (-not (Get-Process -Name "faradaiwire" -ErrorAction SilentlyContinue)) {
            $Exited = $true
            break
        }
        if ($i -eq 9) {
            Stop-Process -Name "faradaiwire" -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $Exited) {
        Write-Warning "FaradAiWire process did not exit cleanly within 10s."
    }
}

# 3. Remove installed binary directory
if (Test-Path $InstallDir) {
    Write-Host "🗑️  Removing $InstallDir..." -ForegroundColor Cyan
    Remove-Item -Path $InstallDir -Recurse -Force
} else {
    Write-Host "ℹ️  No FaradAiWire binary directory found at $InstallDir." -ForegroundColor DarkGray
}

# 4. Remove FaradAiWire from User PATH while preserving REG_EXPAND_SZ registry value kind
$NormalizedInstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$EnvKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
if ($EnvKey) {
    try {
        $UserPath = $EnvKey.GetValue("Path", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($UserPath) {
            $ValueKind = $EnvKey.GetValueKind("Path")
            $FilteredEntries = $UserPath -split ';' | Where-Object {
                $entry = $_.Trim()
                if (-not $entry) { return $false }
                $expanded = [System.Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\')
                ($entry.TrimEnd('\') -ine $NormalizedInstallDir) -and ($expanded -ine $NormalizedInstallDir)
            }
            $NewUserPath = $FilteredEntries -join ';'
            if ($NewUserPath -ne $UserPath) {
                Write-Host "🔧 Removing FaradAiWire from User PATH..." -ForegroundColor Yellow
                $EnvKey.SetValue("Path", $NewUserPath, $ValueKind)
            }
        }
    } finally {
        $EnvKey.Dispose()
    }
}
if ($env:Path) {
    $env:Path = ($env:Path -split ';' | Where-Object {
        $entry = $_.Trim()
        $entry -and ($entry.TrimEnd('\') -ine $NormalizedInstallDir)
    }) -join ';'
}

# 5. Optionally remove runtime data & analytics
if ($ShouldPurge) {
    if (Test-Path $FullDataDir) {
        Write-Host "🗑️  Removing runtime data & analytics at $FullDataDir..." -ForegroundColor Cyan
        Remove-Item -Path $FullDataDir -Recurse -Force
    }
} elseif (Test-Path $FullDataDir) {
    Write-Host ""
    Write-Host "ℹ️  Runtime configuration & analytics preserved at: $FullDataDir" -ForegroundColor Yellow
    Write-Host "   To remove all data as well, run:" -ForegroundColor White
    Write-Host "     Remove-Item -Path `"$FullDataDir`" -Recurse -Force" -ForegroundColor Cyan
    Write-Host "   Or re-run with purge enabled:" -ForegroundColor White
    Write-Host "     `$env:FARADAI_WIRE_PURGE = `"1`"; irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.ps1 | iex" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "✅ FaradAiWire uninstalled successfully!" -ForegroundColor Green
