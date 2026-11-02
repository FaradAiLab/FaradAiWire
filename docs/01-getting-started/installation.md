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
  - Windows 10 / 11 / Server 2022 (`x64` & `arm64`)
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

A zero-dependency POSIX shell script that auto-detects OS architecture, verifies SHA-256 checksums, installs the binary to `~/.local/bin` (or `/usr/local/bin`), and provisions initial configuration in `~/.faradaiwire/config.yaml`:

```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
```

To install into a custom directory:
```bash
INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
```

---

### 3. Windows (PowerShell)

Run in a PowerShell terminal (requires PowerShell 5.1+):

```powershell
irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.ps1 | iex
```

The script installs `faradaiwire.exe` to `$HOME\.faradaiwire\bin` and appends it to your User `PATH`.

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

### Homebrew:
```bash
brew services stop faradaiwire
brew uninstall faradaiwire
brew untap FaradAiLab/tap
```

### Manual Removal:
```bash
rm -f /usr/local/bin/faradaiwire
# Optionally remove runtime data & analytics:
rm -rf ~/.faradaiwire
```

