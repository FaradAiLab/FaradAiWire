---
title: "Request Lifecycle & Frame Dispatch"
description: "End-to-end trace of a JSON-RPC 2.0 tool execution frame through FaradAiWire's inspection and transport layers."
---

# Request Lifecycle & Frame Dispatch 🔄

This document traces the complete execution lifecycle of an MCP tool call (`tools/call`) as it travels through FaradAiWire's ingress socket, security filters, upstream transport, and audit engine.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as AI Agent (Client)
    participant Ingress as Ingress Listener (:8090)
    participant Pipeline as Filter Pipeline Engine
    participant Target as Upstream MCP Tool
    participant Telemetry as Telemetry Queue (DuckDB)

    Agent->>Ingress: HTTP POST /message (JSON-RPC Frame)
    Note over Ingress: Phase 1: Bearer Auth & Envelope Sanity Check
    
    Ingress->>Pipeline: Dispatch canonical mcp.Message
    Note over Pipeline: Phase 2: Fast-Path (<1ms)<br/>- Prefill Check<br/>- Rate Limit & Loop Guard<br/>- Schema Drift Check<br/>- DLP Param Scan (Mask/Block)

    alt Security Violation Triggered
        Pipeline-->>Ingress: Return JSON-RPC error (e.g. -32004)
        Ingress-->>Agent: JSON-RPC Error Response
        Pipeline-)Telemetry: Enqueue BLOCKED Audit Event
    else Payload Cleared
        opt High-Risk Tool / Untrusted Input
            Note over Pipeline: Phase 3: Deep-Path (15-40ms)<br/>- Neural SLM Prompt Guard<br/>- Human-in-the-Loop Intercept
        end

        Pipeline->>Target: Phase 4: Upstream Execution<br/>(Stdio Subprocess or SSRF-Safe HTTP)
        Target-->>Pipeline: Raw Tool Output String
        
        Note over Pipeline: Phase 5: Egress Sanitization<br/>- DLP Response Redaction<br/>- Injection Scanning
        
        Pipeline-->>Ingress: Clean Result Frame
        Ingress-->>Agent: JSON-RPC Success Response
        Pipeline-)Telemetry: Enqueue ALLOWED/MASKED Audit Event
    end
```

---

## Phase 1: Ingress Authentication & Envelope Validation

1. **Physical Listener:** The frame is received on Port 8090 via `POST /message`, `POST /mcp`, or streamed over `GET /sse`.
2. **Bearer Token Validation:** The HTTP `Authorization` header is verified against the gateway's authorized keys. If missing or invalid, the connection is rejected immediately with HTTP 401 Unauthorized.
3. **JSON-RPC 2.0 Syntax Validation:** The body is parsed using Go's streaming decoder into a canonical `pkg/mcp.Message`:
   - Validates that `"jsonrpc": "2.0"` is present.
   - Ensures `"id"` is a non-empty string or integer.
   - Validates `"method"` (e.g. `tools/call`, `tools/list`, `initialize`).

---

## Phase 2: Agent Identification & Context Provenance

FaradAiWire extracts identity metadata from incoming HTTP headers:
- `X-Farad-Agent`: Identifies the client persona (e.g., `code-reviewer`, `db-analyst`). If omitted, falls back to `default`.
- `X-User-Role`: Resolves the human or system role (e.g., `Developer`, `Customer`).
- `X-User-ID`: Identifies the human operator for audit trails.
- **Context Anti-Spoofing:** If `FARADAI_WIRE_HMAC_SECRET` is configured, FaradAiWire validates the cryptographic signature of the role header to prevent untrusted agents from forging their own privilege levels.

---

## Phase 3: Fast-Path Filter Pipeline ($<1\text{ ms}$)

The message travels through the ordered in-memory filter chain:

1. **[Assistant Prefill Guard](/docs/wire/03-security-filters/prefill/) (`Order: 5`):** Blocks requests whose message history ends with an `assistant` message (sockpuppeting) with `-32001`.
2. **[Rate Limiting](/docs/wire/03-security-filters/rate-limiting/) (`Order: 10`):** Takes a token from the bucket of the calling agent and user. If the bucket is empty, returns `-32009` (rate limit exceeded). HTTP ingress has a separate per-IP limit that returns HTTP `429`.
3. **[Loop Protection](/docs/wire/03-security-filters/loop-protection/) (`Order: 15`):** Tracks the fingerprint (`tool_name + SHA-256(arguments)`) inside a sliding window. If the same call occurs more than `max_repeat` times within `window_seconds`, returns `-32008` (infinite loop detected).
4. **Policy hook (`Order: 20`):** Optional authorization policy (`-32003` when denied).
5. **[JSON Schema Validation](/docs/wire/03-security-filters/schema-validation/) (`Order: 30`):** Validates arguments against cached tool schemas and rejects violations with `-32002`. Schema changes seen in `tools/list` are logged and the stored baseline is updated.
6. **[DLP Pattern Matching](/docs/wire/03-security-filters/dlp/) (`Order: 50`):** Executes compiled regexes across the call parameters:
   - If a pattern is configured with `action: block`, execution terminates with `-32004`.
   - If configured with `action: mask`, the sensitive substring is replaced with a semantic placeholder (e.g. `[REDACTED:API_KEY]`).

---

## Phase 4: Deep-Path Adaptive Branching (15–40 ms)

If the tool is categorized as high-risk or external input inspection is required:
- **[Neural SLM Prompt Guard](/docs/wire/03-security-filters/prompt-guard/) (`Order: 55`):** Runs regex rules, then sends the tool name and arguments to a local inference engine (for example Ollama or a Docker sidecar) depending on the tool's governance mode. A threat verdict (or a malicious probability at or above the configurable threshold score, default 0.50) blocks the call with `-32004` or escalates it to human approval. If the engine is unavailable, only the regex rules apply.
- **[Human-In-The-Loop (HITL)](/docs/wire/03-security-filters/hitl/) Interceptor (`Order: 70`):** If the tool is listed under `destructive_tools` (e.g. `write_to_db`, `send_email`), FaradAiWire pauses the request and asks an operator for approval (CLI prompt or webhook). If denied or timed out, returns `-32000`.

---

## Phase 5: Upstream Tool Execution

Once cleared, the request is dispatched to the upstream tool provider based on configured session transport:
- **Local Subprocess (`stdio`):** Spawns or pipes to the local process (e.g. `npx -y @modelcontextprotocol/server-postgres`). The process runs with isolated process group credentials (`syscall.Setpgid`) and filtered environment variables to prevent host credential leaks.
- **Remote MCP Server (`http/sse`):** Dials the remote URL using FaradAiWire's SSRF-safe HTTP transport, blocking loopback and private RFC 1918 IPs unless explicitly whitelisted via `FARADAI_WIRE_ALLOW_LOCAL_TARGETS=true`.

---

## Phase 6: Egress Result Sanitization

The upstream tool's output is inspected before reaching the AI agent:
1. **DLP Response Scanning:** Scans tool output (e.g. file contents, database rows) for sensitive credentials and PII. Masks data in-place to prevent leaking secrets into the agent's context window.
2. **Indirect Injection Scan:** The Guard inspects tool responses and blocks hidden prompt injections embedded in scraped web pages or documents with `-32006`.

---

## Phase 7: Non-Blocking Telemetry & Verdict Recording

Before completing the HTTP response:
1. A **Telemetry Verdict** (`ALLOWED`, `MASKED`, `BLOCKED`, `CRITICAL`) is generated.
2. The verdict, duration, rule IDs, and metadata are pushed to an asynchronous ring buffer channel.
3. Dedicated worker goroutines commit the entry to `logs/faradai_audit.jsonl` and the embedded DuckDB database (`~/.faradaiwire/telemetry.duckdb`).
4. The client receives the sanitized JSON-RPC response with zero observable logging latency.

