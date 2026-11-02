---
title: "faradaiwire run"
description: "Start the FaradAiWire PEP gateway daemon with optional CLI overrides."
---

# `faradaiwire run` 🚀

The `run` command boots the FaradAiWire Policy Enforcement Point daemon, binding the physical Proxy Ingress listener (Port 8090) and Admin Console listener (Port 8095).

---

## Syntax

```bash
faradaiwire run [flags]
```

---

## Command Flags

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **`--config`** | `string` | *(Auto-discovered)* | Explicit path to a YAML configuration file. |
| **`--standalone`**| `bool` | `false` | Force offline-first standalone mode (zero-egress, disables any cloud telemetry). |
| **`--host`** | `string` | `127.0.0.1` | Network interface address to bind HTTP listeners to. Use `0.0.0.0` in containers. |
| **`--port`** | `int` | `8090` | Ingress proxy port for agent tool traffic (`/sse`, `/message`, `/mcp`). |
| **`--admin-port`**| `int` | `8095` | Admin Console port for web UI, metrics, and REST management APIs. |

---

## Single-Instance Guard

To prevent multiple rogue processes from corrupting DuckDB database files or clashing on network ports, FaradAiWire acquires an exclusive advisory file lock on startup ([ADR-0020](../adr/0020-single-tenant-edge-hardening-and-mcp-guardrails.md)):
- Location: `~/.faradaiwire/.faradaiwire.lock` (or local working directory).
- If another instance is already running, the new process exits immediately with an error:
  ```text
  Error: FaradAiWire instance already running (lock held by PID 14201)
  ```
- *To bypass in CI/test runners, set `FARADAI_WIRE_DISABLE_PROCESS_LOCK=true`.*

---

## Graceful Shutdown Lifecycle

FaradAiWire captures `SIGINT` (Ctrl+C) and `SIGTERM` signals ([ADR-0016](../adr/0016-phased-synchronous-teardown-and-telemetry-integrity.md)):
1. Stops accepting new inbound TCP connections on Ports 8090 and 8095.
2. Allows in-flight tool requests up to 10 seconds to complete.
3. Flushes in-memory audit buffers to `logs/faradai_audit.jsonl`.
4. Closes the embedded DuckDB database connection cleanly to prevent database corruption.
5. Releases the process file lock and exits with code `0`.

---

## Examples

### 1. Default Run:
```bash
faradaiwire run
```

### 2. Custom Ingress Port:
```bash
faradaiwire run --port 9090 --admin-port 9095
```

### 3. Container Mode (Bind All Interfaces):
```bash
faradaiwire run --host 0.0.0.0 --standalone
```

