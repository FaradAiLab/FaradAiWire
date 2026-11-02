---
title: "JSON-RPC Security Error Codes"
description: "Standardized error code catalog (-32000 to -32005) returned by FaradAiWire's Policy Enforcement Point."
---

# JSON-RPC Security Error Codes 🛑

When FaradAiWire's Policy Enforcement Point (PEP) intercepts an adversarial payload, policy violation, or rate limit breach, it returns a standard JSON-RPC 2.0 error response with a deterministic negative integer code (`pkg/mcp/protocol.go`).

```json
{
  "jsonrpc": "2.0",
  "id": "req-004",
  "error": {
    "code": -32004,
    "message": "Security policy violation: AWS secret key detected in arguments (aws_credentials)",
    "data": {
      "filter": "dlp",
      "verdict": "BLOCKED",
      "rule": "aws_credentials"
    }
  }
}
```

---

## Gateway Security Error Catalog

| Code | Constant | Meaning | Typical Trigger |
| :--- | :--- | :--- | :--- |
| **`-32000`** | `ErrGateway` | Gateway internal error or rate limit burst exceeded | Token-bucket rate limit exhausted. |
| **`-32001`** | `ErrPrefillBlocked` | Assistant prefill injection detected | Agent input contains conversational prefill hijack tokens. |
| **`-32002`** | `ErrLoopDetected` | Infinite reasoning loop detected | The exact same tool was called $\ge \text{max\_repeat}$ times with identical arguments. |
| **`-32003`** | `mcp.ErrPolicyDenied` | Policy authorization denied | Tool is blacklisted in `agents/<agent>.yaml` (Standardized in [ADR-0050](../adr/0050-absolute-opa-purge-and-open-core-policy-decoupling.md)). |
| **`-32004`** | `ErrDLPBlocked` | Sensitive data pattern detected | Argument contains private keys, `.env` references, or credentials. |
| **`-32005`** | `ErrHITLRejected` | Operator rejected or approval timed out | Human operator declined execution of a destructive tool or failed to confirm within SLA. |

---

## Standard JSON-RPC 2.0 Protocol Codes

FaradAiWire also enforces standard JSON-RPC 2.0 specification errors:

| Code | Meaning | Reason |
| :--- | :--- | :--- |
| **`-32700`** | `Parse error` | Inbound payload was not valid JSON. |
| **`-32600`** | `Invalid Request` | JSON-RPC frame missing `"jsonrpc": "2.0"` or `"id"`. |
| **`-32601`** | `Method not found` | Requested MCP method (e.g. `unknown/method`) is not implemented. |
| **`-32602`** | `Invalid params` | Arguments fail JSON Schema validation or mandatory fields are missing. |
| **`-32603`** | `Internal error` | Upstream MCP tool crashed or returned malformed output. |

---

## Recommended Agent Client Error Handling

When developing autonomous LLM agents or prompt scaffolding, guide the model's behavior based on error codes:

- **Upon `-32004` (DLP Blocked):** Prompt the LLM: *"Your previous tool call was blocked because it contained credentials. Strip the secret and retry without exposing sensitive data."*
- **Upon `-32002` (Loop Detected):** Prompt the LLM: *"You are repeating the same tool call without progress. Change your approach or ask the user for clarification."*
- **Upon `-32005` (HITL Rejected):** Prompt the LLM: *"The human operator refused authorization for this destructive action. Do not attempt to retry this tool."*

