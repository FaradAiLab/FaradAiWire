# FaradAiWire Native Installer (Windows PowerShell)
# Usage: irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = "FaradAiLab/FaradAiWire"
$BinaryName = "faradaiwire.exe"

# 1. Detect Architecture
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($Arch -ne "amd64") {
    Write-Error "FaradAiWire currently supports 64-bit Windows (x64) only."
    exit 1
}

# 2. Determine Installation Path
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\faradaiwire"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 3. Resolve Latest Version from GitHub API
Write-Host "🔍 Discovering latest FaradAiWire release..." -ForegroundColor Cyan
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    $Version = $Release.tag_name
} catch {
    $Version = "v1.0.0"
}

$CleanVersion = $Version.TrimStart("v")
$ZipName = "faradaiwire_${CleanVersion}_windows_${Arch}.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$ZipName"
$TempZip = Join-Path $env:TEMP $ZipName

Write-Host "📦 Downloading FaradAiWire $Version ($Arch)..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
} catch {
    Write-Error "Failed to download FaradAiWire from $DownloadUrl. Check https://github.com/$Repo/releases"
    exit 1
}

Write-Host "🚀 Extracting FaradAiWire to $InstallDir..." -ForegroundColor Cyan
Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

# 4. Add to User PATH if not present
$UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "🔧 Adding FaradAiWire to User PATH..." -ForegroundColor Yellow
    [System.Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host ""
Write-Host "🎉 FaradAiWire $Version installed successfully!" -ForegroundColor Green
Write-Host "Run the gateway with:" -ForegroundColor White
Write-Host "  faradaiwire" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or open the Admin Console at:" -ForegroundColor White
Write-Host "  http://localhost:8095/admin/dashboard" -ForegroundColor Cyan
