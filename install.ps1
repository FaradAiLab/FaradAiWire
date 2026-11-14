# FaradAiWire Native Installer (Windows PowerShell)
# Usage: irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = "FaradAiLab/FaradAiWire"
$BinaryName = "faradaiwire.exe"

# 1. Detect Architecture
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($Arch -ne "amd64") {
    throw "FaradAiWire currently supports 64-bit Windows (x64) only."
}

# 2. Determine Per-User Installation Path
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\faradaiwire"
try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ℹ️  Running elevated as Administrator: installing for current Windows profile ($env:USERNAME) at $InstallDir." -ForegroundColor Yellow
    }
} catch {
    # Best-effort check only
}

if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Ensure TLS 1.2 is enabled on Windows PowerShell 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Ignore if platform defaults already enforce modern TLS
}

# 3. Resolve Latest Version from GitHub API
$Version = $env:FARADAI_WIRE_VERSION
if ([string]::IsNullOrWhiteSpace($Version)) {
    Write-Host "🔍 Discovering latest FaradAiWire release..." -ForegroundColor Cyan
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        if ($Release -and $Release.tag_name) {
            $Version = [string]$Release.tag_name
        }
    } catch {
        $Version = $null
    }
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Could not determine latest FaradAiWire release version from GitHub API. Set `$env:FARADAI_WIRE_VERSION='vX.Y.Z' explicitly or check https://github.com/$Repo/releases"
}

$CleanVersion = $Version.TrimStart("v")
$ZipName = "faradaiwire_${CleanVersion}_windows_${Arch}.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$ZipName"
$ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"
$TempDir = Join-Path $env:TEMP ("faradaiwire-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$TempZip = Join-Path $TempDir $ZipName
$TempChecksums = Join-Path $TempDir "checksums.txt"

try {
    Write-Host "📦 Downloading FaradAiWire $Version ($Arch)..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
    } catch {
        throw "Failed to download FaradAiWire from $DownloadUrl. Check https://github.com/$Repo/releases"
    }

    Write-Host "🔐 Verifying SHA-256 checksum..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempChecksums -UseBasicParsing
    } catch {
        throw "Failed to download $ChecksumsUrl; refusing unverified binary."
    }

    $ExpectedSha = $null
    foreach ($line in (Get-Content -Path $TempChecksums)) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(\./)?(.+?)\s*$') {
            if ($Matches[3] -eq $ZipName) {
                $ExpectedSha = $Matches[1].ToLowerInvariant()
                break
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha)) {
        throw "No checksum entry found for $ZipName in checksums.txt; aborting."
    }

    $ActualSha = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha -ne $ExpectedSha) {
        throw "SHA-256 checksum mismatch for $ZipName! Expected: $ExpectedSha, Actual: $ActualSha"
    }

    # 4. Stop any running faradaiwire process before overwriting locked binary
    $Running = Get-Process -Name "faradaiwire" -ErrorAction SilentlyContinue
    if ($Running) {
        Write-Host "🛑 Stopping running FaradAiWire process before updating (waiting up to 10s)..." -ForegroundColor Yellow
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
            Write-Warning "FaradAiWire process did not exit cleanly within 10s; extraction may fail if the binary is still locked."
        }
    }

    Write-Host "🚀 Extracting FaradAiWire to $InstallDir..." -ForegroundColor Cyan
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
} finally {
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 5. Helper: check whether a PATH entry list already contains $NormalizedInstallDir
$NormalizedInstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')

function Test-PathEntryMatches {
    param(
        [string]$Entry,
        [string]$TargetDir
    )
    $trimmed = $Entry.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $false }
    $unquoted = $trimmed.Trim('"').TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($unquoted)) { return $false }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($unquoted).TrimEnd('\')
    return ($unquoted -ieq $TargetDir) -or ($expanded -ieq $TargetDir)
}

function Send-EnvironmentChangeBroadcast {
    # Best-effort WM_SETTINGCHANGE broadcast so Windows Explorer and newly launched terminals refresh PATH
    try {
        $FullTypeName = "Win32.FaradAiWireNativeEnv"
        if (-not ($FullTypeName -as [type])) {
            Add-Type -Namespace Win32 -Name FaradAiWireNativeEnv -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(
    System.IntPtr hWnd,
    uint Msg,
    System.UIntPtr wParam,
    string lParam,
    uint fuFlags,
    uint uTimeout,
    out System.UIntPtr lpdwResult
);
'@
        }
        $result = [System.UIntPtr]::Zero
        $null = [Win32.FaradAiWireNativeEnv]::SendMessageTimeout(
            [System.IntPtr]0xffff,
            0x001A,
            [System.UIntPtr]::Zero,
            "Environment",
            0x0002,
            1000,
            [ref]$result
        )
    } catch {
        # Ignore in ConstrainedLanguage / headless / restricted environments
    }
}

# 6. Add to User PATH in HKCU\Environment preserving REG_EXPAND_SZ and %VAR% entries
$EnvKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
$RegistryUpdated = $false
if ($EnvKey) {
    try {
        $RawUserPath = $EnvKey.GetValue("Path", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $ValueKind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($null -ne $RawUserPath) {
            try {
                $ExistingKind = $EnvKey.GetValueKind("Path")
                if ($ExistingKind -eq [Microsoft.Win32.RegistryValueKind]::String -or $ExistingKind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                    $ValueKind = $ExistingKind
                }
            } catch {
                $ValueKind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            }
        }

        $ExistingEntries = @()
        if (-not [string]::IsNullOrWhiteSpace([string]$RawUserPath)) {
            $ExistingEntries = @(([string]$RawUserPath) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }

        $AlreadyInUserPath = $false
        foreach ($entry in $ExistingEntries) {
            if (Test-PathEntryMatches -Entry $entry -TargetDir $NormalizedInstallDir) {
                $AlreadyInUserPath = $true
                break
            }
        }

        if (-not $AlreadyInUserPath) {
            Write-Host "🔧 Adding FaradAiWire to User PATH..." -ForegroundColor Yellow
            $NewUserPath = (@($ExistingEntries) + $InstallDir) -join ';'
            $EnvKey.SetValue("Path", $NewUserPath, $ValueKind)
            $RegistryUpdated = $true
        }
    } finally {
        $EnvKey.Dispose()
    }
}

if ($RegistryUpdated) {
    Send-EnvironmentChangeBroadcast
}

# 7. Always ensure the current PowerShell session PATH includes $InstallDir
$SessionEntries = @()
if (-not [string]::IsNullOrWhiteSpace($env:Path)) {
    $SessionEntries = @($env:Path -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$AlreadyInSession = $false
foreach ($entry in $SessionEntries) {
    if (Test-PathEntryMatches -Entry $entry -TargetDir $NormalizedInstallDir) {
        $AlreadyInSession = $true
        break
    }
}
if (-not $AlreadyInSession) {
    $env:Path = (@($SessionEntries) + $InstallDir) -join ';'
}

Write-Host ""
Write-Host "🎉 FaradAiWire $Version installed successfully!" -ForegroundColor Green
Write-Host "Run the gateway with:" -ForegroundColor White
Write-Host "  faradaiwire run" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or open the Admin Console at:" -ForegroundColor White
Write-Host "  http://localhost:8095/admin/dashboard" -ForegroundColor Cyan
Write-Host ""
Write-Host "ℹ️  Note: Already-open VS Code, Cursor, or Windows Terminal apps keep their startup environment — restart them once if 'faradaiwire' is not recognized inside existing windows." -ForegroundColor DarkGray
