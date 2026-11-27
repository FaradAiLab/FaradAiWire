---
title: "Environment Variables"
description: "Configuration precedence, CLI overrides, and system environment variables for FaradAiWire."
---

# Environment Variables 🌐

FaradAiWire supports comprehensive configuration through environment variables. Environment variables override values defined in `config.yaml`, enabling seamless deployment in CI/CD, Docker containers, and automated workstation scripts.

---

## Configuration Precedence Hierarchy

Settings are resolved in the following order (highest precedence first):

1. **CLI Flags** (e.g. `--port 9000`, `--host 0.0.0.0`)
2. **Configuration File** (`config.yaml` or `~/.faradaiwire/config.yaml`) for explicit host/port bindings (`listen_host`, `admin_host`, `listen_port`, `admin_port` — leave commented out when using env overrides)
3. **Environment Variables** (also takes precedence over `config.yaml` for `FARADAI_WIRE_ALLOW_STDIO`, `FARADAI_WIRE_ALLOW_LOCAL_TARGETS`, `FARADAI_WIRE_LOG_LEVEL`, and `FARADAI_WIRE_GUARD_*_URL`)
4. **Hardcoded Defaults** (defined in Go package `internal/config`)

---

## Complete Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| **`AGENT_API_KEY`** | *(None)* | Optional client-side MCP Ingress Bearer token override for `faradaiwire connect` (scrubbed from child MCP subprocesses). |
| **`ADMIN_API_KEY`** | *(None)* | Optional client-side Admin Bearer token for remote HTTPS CLI commands (`faradaiwire adopt`, `faradaiwire guard`). Server Admin auth uses `keys/api_keys.json` exclusively (`faradaiwire token [--rotate]`). |
| **`GATEWAY_ID`** | `faradaiwire-gw-local-01` | Unique node identifier recorded in audit telemetry and DuckDB events. |
| **`FARADAI_WIRE_HOST`** | `127.0.0.1` | Network interface address to bind Ingress listeners (`0.0.0.0` for containers). |
| **`FARADAI_WIRE_ADMIN_HOST`** | `127.0.0.1` | Network interface address for the Admin Console listener (`admin_host` / `--admin-host` takes higher precedence). |
| **`FARADAI_WIRE_HOME`** | `~/.faradaiwire` | Data directory for runtime state, DuckDB analytics database, and pinned schemas. |
| **`FARADAI_WIRE_ALLOW_LOCAL_TARGETS`**| `false` | When set to `true`, permits upstream MCP targets on loopback/private IPs (disables SSRF block). |
| **`FARADAI_WIRE_ENV`** | `production` | Set to `development` for verbose debug logs and relaxed local SSRF checks. |
| **`FARADAI_WIRE_DISABLE_PROCESS_LOCK`**| `false` | Set to `true` in CI/test environments to bypass the single-instance flock guard. |
| **`FARADAI_WIRE_LOG_LEVEL`** | `info` | Runtime log level (`debug`, `info`, `warn`, `error`). Overrides `logging.level` in `config.yaml`. |
| **`FARADAI_WIRE_AUDIT_HMAC_KEY`** | *(None)* | Optional key that signs the audit hash chain with HMAC-SHA256 (`v2-hmac`). Must match when running `faradaiwire audit verify` / `GET /admin/audit/verify`. |
| **`FARADAI_WIRE_ALLOW_STDIO`** | `true` | Highest-precedence switch for local stdio MCP subprocesses; `false` disables stdio upstreams (and local-target SSRF relaxation). The official Docker image sets `false`, so containers support **only Remote SSE and Streamable HTTP** upstreams; use a native install for local stdio MCP servers (`npx`, `python`, `git`). |
| **`FARADAI_WIRE_ALLOW_INSECURE_HTTP`** | `false` | Allows `faradaiwire connect` to send a Bearer token over plain `http://` to untrusted non-loopback hosts (not recommended). |
| **`FARADAI_WIRE_GUARDS_DIR`** | *(built-in default)* | Base directory for installed AI Guard model artifacts used by `faradaiwire guard`. |
| **`FARADAI_WIRE_GUARD_OLLAMA_URL`** / **`FARADAI_WIRE_GUARD_DOCKER_URL`** | *(auto-discovery)* | Override AI Guard discovery endpoints for Ollama and the FaradAiGuard Docker sidecar. |
| **`FARADAI_WIRE_NO_BANNER`** | `false` | Set `true` to suppress the terminal startup banner (also suppressed when `CI=true`). |
| **`LISTEN_PORT`** | `19410` | Ingress proxy port for agent traffic. |
| **`ADMIN_PORT`** | `19415` | Admin Console and REST API port. |

---

## Installer & Maintenance Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| **`FARADAI_WIRE_VERSION`** | *(Latest release)* | Pin a specific release tag (e.g. `v0.1.3`) in `install.sh` or `install.ps1` instead of auto-discovering the latest GitHub release. |
| **`FARADAI_WIRE_PURGE`** | `0` | Set to `1` (or `true`) to remove `~/.faradaiwire` runtime data during `uninstall.sh` / `uninstall.ps1`. |

---

## Example `.env` File

Copy the starter template from `.env.example`:

```bash
# Security Credentials
AGENT_API_KEY=
ADMIN_API_KEY=

# Network Binding
FARADAI_WIRE_HOST=127.0.0.1
LISTEN_PORT=19410
ADMIN_PORT=19415

# Runtime Environment
FARADAI_WIRE_ENV=development
FARADAI_WIRE_ALLOW_LOCAL_TARGETS=false
```

Load environment variables automatically:
```bash
export $(grep -v '^#' .env | xargs)
faradaiwire run
```

