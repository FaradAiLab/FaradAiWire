---
title: "JSON-RPC Security Error Codes"
description: "Standardized error code catalog (-32000 to -32009) returned by FaradAiWire's Policy Enforcement Point."
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

The codes below are the constants defined in `pkg/mcp/protocol.go`. The detail page of each control describes the exact messages.

| Code | Constant | Meaning | Raised by |
| :--- | :--- | :--- | :--- |
| **`-32000`** | `ErrHITLDenied` | Human approval was denied, timed out, or no approval channel was available | [HITL](/docs/wire/03-security-filters/hitl/), [DLP](/docs/wire/03-security-filters/dlp/) (`hitl` action), [Guard](/docs/wire/03-security-filters/prompt-guard/) |
| **`-32001`** | `ErrPrefillInjection` | Assistant prefill injection (sockpuppeting) detected | [Prefill Guard](/docs/wire/03-security-filters/prefill/) |
| **`-32002`** | `ErrSchemaValidation` | Tool arguments violate the tool's JSON Schema | [Schema Validation](/docs/wire/03-security-filters/schema-validation/) |
| **`-32003`** | `ErrPolicyDenied` | Policy authorization denied ([ADR-0050](../adr/0050-absolute-opa-purge-and-open-core-policy-decoupling.md)) | Policy hook |
| **`-32004`** | `ErrDLPViolation` | Sensitive data pattern or guard rule blocked the call | [DLP](/docs/wire/03-security-filters/dlp/), [Guard](/docs/wire/03-security-filters/prompt-guard/) |
| **`-32006`** | `ErrIndirectInjection` | Indirect prompt injection detected in a tool response | [Guard](/docs/wire/03-security-filters/prompt-guard/) (response path) |
| **`-32007`** | `ErrToolSchemaDrift` | Defined for tool schema poisoning. The Schema Validation filter currently logs drift and does not return this code. | Reserved |
| **`-32008`** | `ErrLoopDetected` | Same tool called with identical arguments more than `max_repeat` times inside the window | [Loop Protection](/docs/wire/03-security-filters/loop-protection/) |
| **`-32009`** | `ErrRateLimitExceeded` | Tool-call token bucket is empty | [Rate Limiting](/docs/wire/03-security-filters/rate-limiting/) |

HTTP ingress rate limiting is separate: it returns HTTP `429` with a JSON body (`RATE_LIMIT_EXCEEDED` or `TOO_MANY_FAILED_ATTEMPTS`), not a JSON-RPC error.

---

## Standard JSON-RPC 2.0 Protocol Codes

FaradAiWire also enforces standard JSON-RPC 2.0 specification errors:

| Code | Meaning | Reason |
| :--- | :--- | :--- |
| **`-32700`** | `Parse error` | Inbound payload was not valid JSON. |
| **`-32600`** | `Invalid Request` | JSON-RPC frame missing `"jsonrpc": "2.0"` or `"id"`. |
| **`-32601`** | `Method not found` | Requested MCP method (e.g. `unknown/method`) is not implemented. |
| **`-32602`** | `Invalid params` | Method parameters could not be parsed or mandatory fields are missing. Schema violations of tool arguments use `-32002`. |
| **`-32603`** | `Internal error` | Upstream MCP tool crashed or returned malformed output. |

---

## Recommended Agent Client Error Handling

When developing autonomous LLM agents or prompt scaffolding, guide the model's behavior based on error codes:

- **Upon `-32004` (DLP Blocked):** Prompt the LLM: *"Your previous tool call was blocked because it contained credentials. Strip the secret and retry without exposing sensitive data."*
- **Upon `-32008` (Loop Detected):** Prompt the LLM: *"You are repeating the same tool call without progress. Change your approach or ask the user for clarification."*
- **Upon `-32000` (HITL denied or timed out):** Prompt the LLM: *"The human operator refused authorization for this destructive action. Do not attempt to retry this tool."*

