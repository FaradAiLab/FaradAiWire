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
- **Compilation Requirements (Source only):** Go 1.25+ with `CGO_ENABLED=1` (required for embedded DuckDB analytics engine) and a C compiler (`clang` on macOS, `gcc` on Linux).

---

## Installation Channels

### 1. macOS & Linux (Homebrew - Recommended)

The easiest method for macOS (12+) and Linux users via Homebrew Cask (pre-compiled binary, no Xcode/CLT required):

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

#### Automatic Background Daemon (IDE Integration):
When you run `faradaiwire adopt`, your AI IDEs connect through `faradaiwire connect`, which automatically spawns and detaches the `faradaiwire run` background daemon on demand if it is not already running.

---

### 2. Linux & macOS (Universal Shell Installer)

A zero-dependency POSIX shell script that uses TLS 1.2+, prefers Homebrew on macOS when available, verifies downloads against `checksums.txt` (SHA-256), and installs the binary to `/usr/local/bin` (or `~/.local/bin` when non-root with `PATH` setup):

```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
```

You can pin a specific release with `FARADAI_WIRE_VERSION=v0.1.3`.

---

### 3. Windows (PowerShell)

Run in a PowerShell terminal (requires PowerShell 5.1+):

```powershell
irm https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.ps1 | iex
```

The script enforces TLS 1.2, verifies the downloaded archive against `checksums.txt` (SHA-256), stops any running `faradaiwire` process before replacing the binary, installs `faradaiwire.exe` to `%LOCALAPPDATA%\Programs\faradaiwire` (`$env:LOCALAPPDATA\Programs\faradaiwire`), and appends it to your User `PATH`. Pin a specific release with `$env:FARADAI_WIRE_VERSION = "v0.1.3"`.

---

### 4. Direct Binary Download (GitHub Releases)

Pre-compiled release archives (including `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, and `windows_amd64`) with standalone executables and SHA-256 checksums:

1. Visit [GitHub Releases](https://github.com/FaradAiLab/FaradAiWire/releases).
2. Download the archive matching your target architecture (e.g. `faradaiwire_darwin_arm64.tar.gz` or `faradaiwire_linux_arm64.tar.gz`).
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

### 5. Build from Source (Go 1.25+)

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

### 6. Docker (HTTP/SSE-only)

Run FaradAiWire as a hardened containerized gateway. There is no pre-built registry image yet; Docker Compose builds it from source (`faradaiwire:local`).

> [!IMPORTANT]
> The image sets `FARADAI_WIRE_ALLOW_STDIO=false`. Containers can only front **Remote SSE** and **Streamable HTTP** MCP servers; local `stdio` tools (`npx`, `python`, `git`) are not supported and no Node.js/Python/Git toolchain is shipped. Use a native install (channels 1–5) for stdio tools.

**Requirements:** Docker Engine with Compose v2 and a clone of the repository.

```bash
git clone https://github.com/FaradAiLab/FaradAiWire.git && cd FaradAiWire

# Build and start the gateway
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

1. **Get the admin key and Magic Link.** On first start a `faw_live_...` Admin Bootstrap Key is generated (only its masked prefix appears in logs):

   ```bash
   docker exec -it faradaiwire faradaiwire token
   ```

   Open the printed Magic Link (`http://127.0.0.1:19415/admin/dashboard?token=...`) or paste the key into the Web Console unlock dialog. If you mapped a different host port (e.g. `-p 19425:19415`), add `--port 19425`. Rotate with `faradaiwire token --rotate`.

2. **Register upstreams and connect agents.** In the Web Console (**Tool Sources → Custom Tool Source**) add Remote SSE (`http://mcp-service:8080/sse`) or Streamable HTTP (`http://mcp-service:8080/mcp`) servers. Point agents at `http://127.0.0.1:19410/sse/<profile>` (or `http://faradaiwire:19410/sse/<profile>` from other containers) with `Authorization: Bearer <agent-key>`.

3. **Optional AI Guard.** By default the gateway reaches Ollama on the host (`FARADAI_WIRE_GUARD_OLLAMA_URL=http://host.docker.internal:11434`). To also start the bundled FaradAiGuard sidecar:

   ```bash
   docker compose -f deploy/docker/docker-compose.yml --profile guard up -d --build
   ```

**Details**

| Item | Value |
| :--- | :--- |
| Ports | `19410` (ingress), `19415` (admin); published on `127.0.0.1` only by default |
| Persistent data | Named volume `faradaiwire_data` mounted at `/data` (`FARADAI_WIRE_HOME=/data`: config, keys, agents, DuckDB, logs) |
| User | Non-root UID `10001` |
| Health check | `GET /health` on the ingress port |

**Upgrade:** `git pull && docker compose -f deploy/docker/docker-compose.yml up -d --build` (data persists in the volume).
**Stop:** `docker compose -f deploy/docker/docker-compose.yml down` (add `-v` to also delete the data volume).

> [!WARNING]
> For remote or multi-user exposure, change the port bindings in `docker-compose.yml` only behind TLS termination (Caddy, Nginx, or a cloud load balancer) in front of `:19410` and `:19415`.

For the full reference, see [`deploy/docker/README.md`](https://github.com/FaradAiLab/FaradAiWire/blob/main/deploy/docker/README.md).

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
[✓] Ingress port 19410 is available
[✓] Admin port 19415 is available
[✓] Local DuckDB telemetry initialized
[i] AI Guard Provider: Ollama detected at http://127.0.0.1:11434 (guard-qwen3guard ready)
[✓] Gateway status: ALL CHECKS PASSED
```

---

## Upgrading

### Homebrew:
```bash
brew update && brew upgrade --cask faradaiwire
# If a detached daemon is currently running, restart it so the new binary takes over:
pkill -x faradaiwire || true
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
pkill -x faradaiwire || true
brew uninstall --cask faradaiwire
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

