---
title: "Environment Variables"
description: "Configuration precedence, CLI overrides, and system environment variables for FaradAiWire."
---

# Environment Variables 🌐

FaradAiWire supports comprehensive configuration through environment variables. Environment variables override values defined in `config.yaml`, enabling seamless deployment in CI/CD, Docker containers, and automated workstation scripts.

---

## Configuration Precedence Hierarchy

Settings are resolved in the following order (highest precedence first):

1. **CLI Flags** (e.g. `--port 9000`, `--standalone`)
2. **Environment Variables** (e.g. `LISTEN_PORT=9000`)
3. **Configuration File** (`config.yaml` or `~/.faradaiwire/config.yaml`)
4. **Hardcoded Defaults** (defined in Go package `internal/config`)

---

## Complete Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| **`API_KEY`** | *(None)* | Master secret for agent Ingress Bearer authentication and Admin API endpoints. |
| **`GATEWAY_ID`** | `faradaiwire-gw-local-01` | Unique node identifier recorded in audit telemetry and DuckDB events. |
| **`FARADAI_WIRE_HOST`** | `127.0.0.1` | Network interface address to bind listeners (`0.0.0.0` for containers). |
| **`FARADAI_WIRE_HOME`** | `~/.faradaiwire` | Data directory for runtime state, DuckDB analytics database, and pinned schemas. |
| **`FARADAI_WIRE_DEFAULT_AGENT`** | `default` | Fallback agent domain name when no `X-Farad-Agent` header is present. |
| **`FARADAI_WIRE_ALLOW_LOCAL_TARGETS`**| `false` | When set to `true`, permits upstream MCP targets on loopback/private IPs (disables SSRF block). |
| **`FARADAI_WIRE_ENV`** | `production` | Set to `development` for verbose debug logs and relaxed local SSRF checks. |
| **`FARADAI_WIRE_DISABLE_PROCESS_LOCK`**| `false` | Set to `true` in CI/test environments to bypass the single-instance flock guard. |
| **`FARADAI_WIRE_HMAC_SECRET`** | *(None)* | 32-byte cryptographic secret used for verifying signed context headers. |
| **`LISTEN_PORT`** | `8090` | Ingress proxy port for agent traffic. |
| **`ADMIN_PORT`** | `8095` | Admin Console and REST API port. |

---

## Example `.env` File

Copy the starter template from `.env.example`:

```bash
# Security Credentials
API_KEY=dev-local-key
FARADAI_WIRE_HMAC_SECRET=0123456789abcdef0123456789abcdef

# Network Binding
FARADAI_WIRE_HOST=127.0.0.1
LISTEN_PORT=8090
ADMIN_PORT=8095

# Runtime Environment
FARADAI_WIRE_ENV=development
FARADAI_WIRE_ALLOW_LOCAL_TARGETS=false
```

Load environment variables automatically:
```bash
export $(grep -v '^#' .env | xargs)
faradaiwire run
```

