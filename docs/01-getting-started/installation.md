---
title: "Installation Guide"
description: "Deploy FaradAiWire via Homebrew, POSIX shell installer, PowerShell, or compile from source."
---

# Installation Guide 📦

FaradAiWire is distributed as a single-tenant host-native binary to ensure seamless compatibility with local MCP `stdio` subprocesses (`node`, `python`, `git`) and developer filesystem paths.

---

## System Requirements

- **Supported Operating Systems:**
  - macOS 12+ (Apple Silicon `arm64` & Intel `amd64`)
  - Linux Kernel 5.4+ (Ubuntu, Debian, Fedora, Arch; `x86_64` & `aarch64`)
  - Windows 10 / 11 / Server 2022 (`x64`)
- **Memory & CPU:** $\ge 256\text{ MB}$ RAM, 1 vCPU (static regex engine consumes $<30\text{ MB}$ at idle).
- **Compilation Requirements (Source only):** Go 1.23+ with `CGO_ENABLED=1` (required for embedded DuckDB analytics engine) and a C compiler (`clang` on macOS, `gcc` on Linux).

---

## Installation Channels

### 1. macOS (Homebrew - Recommended)

The easiest method for macOS users. Automatically integrates with macOS `launchd` service management:

```bash
# Add FaradAiWire tap:
brew tap FaradAiLab/tap

# Install latest stable release:
brew install faradaiwire
```

#### Run in Foreground:
```bash
faradaiwire run
```

#### Manage as a Persistent Background Daemon:
```bash
# Start background service (auto-starts on login):
brew services start faradaiwire

# Check service status:
brew services list

# Stop background service:
brew services stop faradaiwire
```

---

### 2. Linux & macOS (Universal Shell Installer)

A zero-dependency POSIX shell script that auto-detects OS architecture and installs the binary to `/usr/local/bin` (or `~/.local/bin` when non-root):

```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
```

---

### 3. Windows (PowerShell)

Run in a PowerShell terminal (requires PowerShell 5.1+):

```powershell
irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.ps1 | iex
```

The script installs `faradaiwire.exe` to `%LOCALAPPDATA%\Programs\faradaiwire` (`$env:LOCALAPPDATA\Programs\faradaiwire`) and appends it to your User `PATH`.

---

### 4. Direct Binary Download (GitHub Releases)

Pre-compiled release archives with standalone executables and cryptographically signed SHA-256 checksums:

1. Visit [GitHub Releases](https://github.com/FaradAiLab/FaradAiWire/releases).
2. Download the archive matching your target architecture (e.g. `faradaiwire_darwin_arm64.tar.gz`).
3. Verify the checksum:
   ```bash
   shasum -a 256 -c checksums.txt
   ```
4. Extract and place in your executable `PATH`:
   ```bash
   tar -xzf faradaiwire_darwin_arm64.tar.gz
   sudo mv faradaiwire /usr/local/bin/
   ```

---

### 5. Build from Source (Go 1.23+)

To develop or compile the latest unreleased features directly from source:

```bash
# 1. Clone the repository:
git clone https://github.com/FaradAiLab/FaradAiWire.git
cd FaradAiWire

# 2. Build the binary and initialize local config:
make build

# 3. Launch the gateway:
make run
```

> [!NOTE]
> FaradAiWire embeds DuckDB for local, zero-egress audit analytics. Ensure `CGO_ENABLED=1` is active in your environment when invoking `go build`:
> ```bash
> CGO_ENABLED=1 go build -o bin/faradaiwire cmd/faradaiwire/main.go
> ```

---

## Verifying the Installation

Verify the installed binary and environment health:

```bash
faradaiwire version
```

Run host diagnostics to confirm port availability and local inference discovery:
```bash
faradaiwire doctor
```

```text
[✓] Configuration discovered at: /Users/username/.faradaiwire/config.yaml
[✓] Ingress port 8090 is available
[✓] Admin port 8095 is available
[✓] Local DuckDB telemetry initialized
[i] SLM Provider: Ollama detected at http://127.0.0.1:11434 (llama-guard3:1b ready)
[✓] Gateway status: ALL CHECKS PASSED
```

---

## Upgrading

### Homebrew:
```bash
brew update && brew upgrade faradaiwire
brew services restart faradaiwire
```

### Shell Installer:
Simply re-run the installer command; it replaces the existing binary while preserving your custom `config.yaml`:
```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
```

---

## Uninstalling

> [!NOTE]
> By default, uninstalling removes the binary (and restores any adopted IDE configs via `faradaiwire adopt --rollback` if backups exist) while preserving `~/.faradaiwire` (`config.yaml`, API keys, and DuckDB analytics). Pass `--purge` to `uninstall.sh` (or `-Purge` to `uninstall.ps1` / set `FARADAI_WIRE_PURGE=1`) to remove runtime data as well.

### Homebrew (macOS & Linux):
```bash
brew services stop faradaiwire
brew uninstall faradaiwire
brew untap FaradAiLab/tap
# Optionally remove runtime data & analytics:
rm -rf ~/.faradaiwire
```

### Shell Uninstaller (macOS & Linux):
```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.sh | sh

# Or also purge runtime data & analytics:
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.sh | sh -s -- --purge
```

### Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.ps1 | iex

# Or also purge runtime data & analytics:
$env:FARADAI_WIRE_PURGE = "1"; irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.ps1 | iex
```

### Manual Removal:
- **macOS & Linux:**
  ```bash
  pkill -x faradaiwire || true
  rm -f /usr/local/bin/faradaiwire ~/.local/bin/faradaiwire
  # Optionally remove runtime data & analytics:
  rm -rf ~/.faradaiwire
  ```
- **Windows (PowerShell):**
  ```powershell
  Stop-Process -Name faradaiwire -Force -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:LOCALAPPDATA\Programs\faradaiwire" -Recurse -Force -ErrorAction SilentlyContinue
  # Optionally remove runtime data & analytics:
  Remove-Item -Path "$env:USERPROFILE\.faradaiwire" -Recurse -Force -ErrorAction SilentlyContinue
  ```

