---
title: "AI Agent & IDE Integration"
description: "Connect Claude Code, Cursor, Windsurf, Copilot, or custom Python/Node LLM clients to FaradAiWire."
---

# AI Agent & IDE Integration 🤖

FaradAiWire sits as an inline Policy Enforcement Point (PEP) between your AI agent client and upstream Model Context Protocol (MCP) servers.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as AI Agent (Claude / Cursor)
    participant PEP as FaradAiWire PEP (:19410)
    participant Tool as Upstream MCP Server
    
    Agent->>PEP: POST /message (tools/call payload + Bearer Auth)
    Note over PEP: Fast Path: Prefill, RateLimit, Schema, DLP
    alt Policy Violation (e.g. AWS Secret in params)
        PEP-->>Agent: JSON-RPC Error (-32004 DLP Blocked)
    else Clean Payload
        PEP->>Tool: Forward sanitized request (Stdio or SSE)
        Tool-->>PEP: Return raw tool output
        Note over PEP: Deep Path: Response DLP & Injection Scan
        PEP-->>Agent: Return sanitized result
    end
```

---

## Connection Endpoints & Authentication

All agent tool traffic must target FaradAiWire's **Proxy Ingress Port (19410)**:

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| **Ingress Base URL** | `http://127.0.0.1:19410` | Never connect agents to Admin Port `19415` |
| **SSE Endpoint** | `http://127.0.0.1:19410/sse/{profile}` | Aggregated SSE (or `/sse/{profile}/{tool_source}` for Direct mode) |
| **Streamable HTTP Endpoint** | `http://127.0.0.1:19410/mcp/{profile}` | Aggregated HTTP POST (or `/mcp/{profile}/{tool_source}` for Direct mode) |
| **Authorization Header** | `Authorization: Bearer <API_KEY>` | Matches an active Agent key in `keys/api_keys.json` |

---

## 1. Claude Code CLI

Configure Claude Code to route all tool discovery and tool calls through FaradAiWire.

Edit `~/.claude.json` (or project-level `.claude.json`):

```json
{
  "mcpServers": {
    "faradaiwire-gateway": {
      "url": "http://127.0.0.1:19410/sse/claude-code",
      "headers": {
        "Authorization": "Bearer faw_live_your_agent_key"
      }
    }
  }
}
```

Verify in Claude Code:
```bash
claude mcp list
```
*You will see `faradaiwire-gateway` listed as connected.*

---

## 2. Cursor IDE

Cursor supports remote MCP servers over HTTP/SSE.

Open **Cursor Settings** $\to$ **Features** $\to$ **MCP Servers**, or edit `.cursor/mcp.json` in your workspace root:

```json
{
  "mcpServers": {
    "faradaiwire": {
      "url": "http://127.0.0.1:19410/sse/cursor-agent",
      "headers": {
        "Authorization": "Bearer faw_live_your_agent_key"
      }
    }
  }
}
```

Reload Cursor's MCP panel; a green indicator will confirm the connection to port 19410.

---

## 3. Claude Desktop App

Configure the Claude desktop application to use FaradAiWire as its secure proxy.

Open the configuration file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add the gateway entry:

```json
{
  "mcpServers": {
    "faradaiwire-pep": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:19410/sse/claude-desktop",
        "--header",
        "Authorization: Bearer faw_live_your_agent_key"
      ]
    }
  }
}
```

Restart the Claude Desktop application.

---

## 4. Windsurf IDE

In Windsurf, open `~/.codeium/windsurf/mcp_config.json` and configure:

```json
{
  "mcpServers": {
    "faradaiwire": {
      "serverUrl": "http://127.0.0.1:19410/sse/windsurf",
      "headers": {
        "Authorization": "Bearer faw_live_your_agent_key"
      }
    }
  }
}
```

---

## 5. Custom Python Agent (LangChain / LlamaIndex / Requests)

If you are building custom autonomous agents or LLM runners in Python, invoke MCP tools through FaradAiWire via HTTP POST:

```python
import requests

GATEWAY_URL = "http://127.0.0.1:19410/mcp/finance-analyst"
API_KEY = "faw_live_your_agent_key"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}",
}

payload = {
    "jsonrpc": "2.0",
    "id": "py-call-101",
    "method": "tools/call",
    "params": {
        "name": "query_db",
        "arguments": {
            "sql": "SELECT account_id, balance FROM accounts WHERE balance > 10000"
        }
    }
}

response = requests.post(GATEWAY_URL, json=payload, headers=headers)
data = response.json()

if "error" in data:
    print(f"Blocked by Policy: {data['error']['message']} (Code: {data['error']['code']})")
else:
    print("Sanitized Result:", data["result"])
```

---

## 6. Custom TypeScript / Node.js Agent

Using the official `@modelcontextprotocol/sdk`:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

async function runSecureAgent() {
  const transport = new SSEClientTransport(
    new URL("http://127.0.0.1:19410/sse/ts-worker-agent"),
    {
      eventSourceInit: {
        headers: {
          Authorization: "Bearer faw_live_your_agent_key",
        },
      },
      requestInit: {
        headers: {
          Authorization: "Bearer faw_live_your_agent_key",
        },
      },
    }
  );

  const client = new Client({ name: "ts-agent", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);

  // Invoke tool securely through FaradAiWire
  const result = await client.callTool({
    name: "read_file",
    arguments: { path: "package.json" },
  });

  console.log("Verified tool result:", result);
}

runSecureAgent().catch(console.error);
```

---

## Canonical Profile Routing

Target Security Profiles directly in the URL path (with `Authorization: Bearer <agent-key>`):

- **Aggregated Mode:** `/sse/{profile}` or `/mcp/{profile}`
- **Direct Mode:** `/sse/{profile}/{tool_source}` or `/mcp/{profile}/{tool_source}`
- **Scoped Keys:** Profile-scoped API keys also auto-route when hitting root `/sse` or `/mcp`; wildcard (`*`) keys require an explicit `{profile}` segment in the URL path.

---

## Verifying in the Web Console

Once your agent is configured and executes its first tool call:
1. Open **`http://localhost:19415/admin/dashboard`**.
2. Navigate to **Agent Studio** or **Live Audit Stream**.
3. Confirm that the incoming session is identified with the agent name (`claude-code`, `cursor-agent`, etc.), showing active tool schemas and security inspection verdicts in real-time.

