---
title: "Common Issues & Troubleshooting"
description: "Resolving port conflicts, SSE connection drops, SLM timeouts, and SSRF loopback blocking."
---

# Common Issues & Troubleshooting 🩺

This guide provides immediate diagnostic steps and solutions for frequent operational issues.

---

## 1. Port Conflict (`EADDRINUSE` on Port 8090 or 8095)

**Symptom:**
```text
Error: listen tcp 127.0.0.1:8090: bind: address already in use
```

**Diagnosis & Fix:**
Another instance of FaradAiWire or another application is using Port 8090 or 8095.
1. Identify the blocking process:
   - **macOS / Linux:** `lsof -i :8090` or `lsof -i :8095`
   - **Windows:** `netstat -ano | findstr :8090`
2. Terminate the stale process, or start FaradAiWire on alternative ports:
   ```bash
   faradaiwire run --port 9090 --admin-port 9095
   ```

---

## 2. Agent Disconnection / SSE Stream Drops

**Symptom:**
Claude Code or Cursor reports `Connection to faradaiwire-gateway lost` after idling.

**Diagnosis & Fix:**
1. **HTTP Keep-Alives:** Some local firewalls drop idle SSE connections after 60 seconds. FaradAiWire transmits periodic SSE comment pings (`: ping\n\n`) every 15 seconds to prevent intermediate TCP socket teardowns.
2. **Process Lock Collision:** Ensure you are not running two daemon instances against the same configuration directory. Run `faradaiwire doctor` to check socket health.

---

## 3. Upstream Local Tool Blocked by SSRF Protection

**Symptom:**
An agent attempts to connect to an MCP tool on `http://127.0.0.1:5000` or `http://10.0.0.15:8080`, and FaradAiWire returns:
```json
{ "code": -32004, "message": "SSRF violation: target IP belongs to private or loopback subnet" }
```

**Diagnosis & Fix:**
FaradAiWire blocks private IP ranges by default to prevent attackers from targeting internal microservices. If your upstream tool is legitimately hosted on your local machine or LAN:
- Set `FARADAI_WIRE_ALLOW_LOCAL_TARGETS=true` in your `.env` or shell.
- Or update `config.yaml`:
  ```yaml
  security:
    ssrf_protection:
      enabled: true
      block_private_ips: false
  ```

---

## 4. SLM Guard Latency Timeout

**Symptom:**
```text
[WARN] Guard provider Ollama timed out after 1500ms; falling back to fast-path static heuristics
```

**Diagnosis & Fix:**
1. Check whether Ollama is overloaded or swapping model weights to CPU RAM.
2. Verify GPU acceleration is working:
   ```bash
   ollama ps
   ```
3. In `config.yaml`, increase `timeout_ms` under `filters.guard` (e.g. `timeout_ms: 3000`).

---

## 5. DuckDB Process Lock Error

**Symptom:**
```text
Error: failed to open DuckDB: IO Error: Could not set lock on file "~/.faradaiwire/telemetry.duckdb"
```

**Diagnosis & Fix:**
DuckDB requires exclusive single-process access to its file store.
1. Check if a zombie background `faradaiwire` process is running:
   ```bash
   pgrep -fl faradaiwire
   ```
2. Kill any lingering processes: `pkill -9 faradaiwire`
3. Delete stale lock files if the system crashed: `rm -f ~/.faradaiwire/.faradaiwire.lock`

