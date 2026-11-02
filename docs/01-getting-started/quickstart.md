---
title: "5-Minute Quickstart"
description: "Launch FaradAiWire locally and route your first secure MCP tool call in under 5 minutes."
---

# 5-Minute Quickstart ⚡

Get FaradAiWire running on your workstation, verify its security filters, and send your first inspected Model Context Protocol (MCP) tool call.

---

## Step 1: Start FaradAiWire

Choose your preferred installation method (see [Installation Guide](/docs/wire/installation/) for all options):

### Option A: macOS (Homebrew)
```bash
brew tap FaradAiLab/tap
brew install faradaiwire
faradaiwire run
```

### Option B: Linux & macOS (Shell Installer)
```bash
curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
faradaiwire run
```

### Option C: Native Go (Build from Source)
```bash
git clone https://github.com/FaradAiLab/FaradAiWire.git
cd FaradAiWire
make run
```

When started, FaradAiWire prints the startup banner and binds its physical listeners:
```text
┌──────────────────────────────────────────────────────────┐
│ FaradAiWire - Zero-Trust AI Agent Security Gateway       │
│                                                          │
│  Proxy Ingress:  http://127.0.0.1:8090                   │
│  Admin Console:  http://127.0.0.1:8095/admin/dashboard   │
│  Status:         HEALTHY (Offline Standalone Mode)       │
└──────────────────────────────────────────────────────────┘
```

---

## Step 2: Verify Gateway Health

Check that the daemon and its internal subsystems (DLP regex engine, DuckDB audit database, schema cache) are operational:

```bash
faradaiwire doctor
```

Alternatively, query the Admin status endpoint:
```bash
curl -s http://127.0.0.1:8095/admin/status | jq .
```

Expected JSON response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "runtime_mode": "standalone",
  "ingress_port": 8090,
  "admin_port": 8095,
  "uptime_seconds": 12,
  "active_sessions": 0
}
```

---

## Step 3: Send an Inspected MCP Tool Call

AI agents interact with FaradAiWire via JSON-RPC 2.0 frames over HTTP/SSE. Simulate an agent invoking a tool through the Proxy Ingress port (`8090`):

```bash
curl -X POST http://127.0.0.1:8090/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-local-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-001",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "/workspace/README.md"
      }
    }
  }'
```

The request passes through FaradAiWire's Fast-Path pipeline:
1. **Bearer Authentication:** Validates authorization token against configured API keys.
2. **Assistant Prefill Guard:** Confirms no prompt hijack payloads are embedded.
3. **Loop Protection:** Verifies tool call is not part of a runaway recursive loop.
4. **Rate Limiting:** Enforces token-bucket quota.
5. **Schema Validation:** Verifies parameter structure matches tool definition.
6. **Data Loss Prevention (DLP):** Confirms arguments do not contain forbidden credentials.

---

## Step 4: Test DLP Threat Blocking

> [!TIP]
> **Try the Interactive Threat Simulator:**
> Want to see real-time tool sanitization in action before running locally? Try the live interactive **[Wire Inspector](/#demo)** simulator on the homepage.

FaradAiWire's DLP engine inspects outgoing parameters. Test what happens when an agent inadvertently tries to pass an AWS Secret Access Key or read a private key file:

```bash
curl -X POST http://127.0.0.1:8090/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-local-key" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-002",
    "method": "tools/call",
    "params": {
      "name": "fetch_config",
      "arguments": {
        "target": "/etc/shadow"
      }
    }
  }'
```

FaradAiWire immediately aborts the call in **$<0.5\text{ ms}$** without forwarding it to the upstream tool:

```json
{
  "jsonrpc": "2.0",
  "id": "req-002",
  "error": {
    "code": -32004,
    "message": "Security policy violation: sensitive file pattern detected in parameters (sensitive_files)"
  }
}
```

---

## Step 5: Inspect Audit Telemetry

Open the Web Console in your browser:
👉 **[http://localhost:8095/admin/dashboard](http://localhost:8095/admin/dashboard)**

You can view:
- **Verdict breakdown:** Allowed, Masked, Blocked, and HITL counts.
- **Audit stream:** Tamper-evident log entries recording the exact rule triggered (`sensitive_files`), timestamp, client agent, and target tool.
- **Underlying log file:** Inspect entries directly in `logs/faradai_audit.jsonl`:
  ```bash
  tail -f logs/faradai_audit.jsonl | jq .
  ```

---

## Next Steps

- 🤖 **[Configure Your Agent](/docs/wire/agent-setup/):** Connect Claude Code, Cursor, or Windsurf.
- 🛡️ **[Enable Neural SLM Guard](/docs/wire/security-filters/prompt-guard/):** Add local Llama-Guard or Prompt-Guard inference.
- ⚙️ **[Customize DLP Rules](/docs/wire/configuration/config-yaml/):** Add regex patterns for internal tokens or proprietary database identifiers.
