---
title: "MCP Ingress Protocol & Dual Transport"
description: "JSON-RPC 2.0 streaming contracts over HTTP POST, SSE, and Stdio on Port 8090."
---

# MCP Ingress Protocol & Dual Transport 🔌

FaradAiWire's Proxy Ingress listener operates on **Port 8090**, implementing standard Model Context Protocol (MCP) transport specifications.

---

## Ingress Endpoints (Port 8090)

| Endpoint | HTTP Method | Purpose |
| :--- | :--- | :--- |
| **`/sse`** | `GET` | Establishes persistent Server-Sent Events (SSE) session with the AI agent. |
| **`/message`** | `POST` | Ingests JSON-RPC 2.0 frames associated with an SSE session or standalone request. |
| **`/mcp`** | `POST` | Single-shot JSON-RPC 2.0 execution endpoint (convenient for curl/scripts). |

---

## 1. Server-Sent Events (SSE) Handshake

When an agent like Claude Code or Cursor connects to FaradAiWire via SSE:

1. **Client Request:**
   ```http
   GET /sse HTTP/1.1
   Host: 127.0.0.1:8090
   Authorization: Bearer dev-local-key
   Accept: text/event-stream
   ```

2. **FaradAiWire Handshake Response:**
   ```http
   HTTP/1.1 200 OK
   Content-Type: text/event-stream
   Cache-Control: no-cache
   Connection: keep-alive

   event: endpoint
   data: /message?sessionId=sess_8f91c0e3b
   ```

3. **Subsequent Tool Invocations:**
   The agent posts its JSON-RPC frames to `/message?sessionId=sess_8f91c0e3b`.

---

## 2. Direct HTTP JSON-RPC POST (`/message` or `/mcp`)

For automated test runners, bash scripts, or simple agents:

```bash
curl -X POST http://127.0.0.1:8090/message \
  -H "Authorization: Bearer dev-local-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "call-1",
    "method": "tools/call",
    "params": {
      "name": "calculate_hash",
      "arguments": { "algorithm": "sha256", "text": "FaradAi" }
    }
  }'
```

---

## 3. Dual Upstream Transports

FaradAiWire acts as a protocol bridge, supporting two distinct upstream tool transports:

### Local Subprocesses (`stdio`)
- Spawns local tools (e.g. `npx -y @modelcontextprotocol/server-postgres`) directly as OS subprocesses.
- **Process Isolation:** Runs subprocesses in dedicated process groups (`syscall.Setpgid`), preventing rogue tool processes from surviving gateway shutdown.
- **Sanitized Environment:** Passes filtered environment variables to prevent leaking master API keys to subprocesses.

### Remote MCP Servers (`http/sse`)
- Connects to remote MCP microservices over HTTP or persistent SSE streams.
- **SSRF Guard:** Inspects IP targets to block private RFC 1918 subnets and cloud metadata endpoints (`169.254.169.254`).

