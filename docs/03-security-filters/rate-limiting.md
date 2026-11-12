---
title: "Rate Limiting"
description: "Token-bucket limits on HTTP ingress (per client IP) and on tool calls (per agent and user), with configurable rates and bursts."
---

# Rate Limiting

FaradAiWire applies rate limits at **two independent layers**. Both use the token-bucket algorithm, and every number below is configurable.

| Layer | Protects | Keyed by | Config block |
| :--- | :--- | :--- | :--- |
| HTTP ingress | The gateway itself (`/sse`, `/message`, `/mcp`, `/health`) | Client IP | `security.rate_limiting` |
| Tool-call filter | Upstream MCP servers and their API quotas | Agent + user | `filters.rate_limiting` |

## Token-bucket basics

Each key owns a bucket with capacity `burst` tokens. Every request consumes one token. Tokens refill continuously at `rate` tokens per second, never beyond the capacity. If the bucket has less than one token, the request is rejected. A burst up to the capacity is allowed instantly, then the sustained rate applies.

## Layer 1: HTTP ingress

Implemented as HTTP middleware wrapped around the proxy handler.

- **Key:** the client IP taken strictly from the network socket (`RemoteAddr`). `X-Forwarded-For` and `X-Real-IP` are ignored, so the limit cannot be bypassed by spoofing headers.
- **Rejection:** HTTP `429` with `Retry-After: 1` and body `{"error":"RATE_LIMIT_EXCEEDED","message":"Too many requests, please slow down."}`.
- **Memory:** idle buckets are evicted after 5 minutes (sweep every minute).

```yaml
security:
  rate_limiting:
    enabled: true
    rate: 50.0              # sustained requests per second, per IP
    burst: 100              # bucket capacity, per IP
    login_max_attempts: 5   # failed logins before lockout
    login_lockout_sec: 900  # maximum lockout duration in seconds
```

| Field | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` | Turns ingress limiting on or off. |
| `rate` | `50.0` | Refill rate in requests per second. |
| `burst` | `100` | Maximum burst per IP. |
| `login_max_attempts` | `5` | Consecutive failed authentications before lockout. |
| `login_lockout_sec` | `900` | Upper bound for lockout. |

Values that are zero or negative fall back to these defaults.

### Login brute-force lockout

Failed authentications are counted per IP. After `login_max_attempts` failures, the IP is locked with exponential backoff (2s, 4s, 8s, ... capped at `login_lockout_sec`). Locked clients receive `429` with `{"error":"TOO_MANY_FAILED_ATTEMPTS"}` and a `Retry-After` header. A successful login clears the counter.

## Layer 2: Tool-call filter

| Property | Value |
| :--- | :--- |
| Filter name | `rate_limiting` |
| Order constant | `OrderRateLimit = 10` |
| Applies to | `tools/call` only. Other MCP methods pass through. |
| Key | `agent:<agent>:user:<userID>` (`global` and `anonymous` when unknown) |

The key does **not** include the tool name, so all tools of one agent and user share one bucket. A new bucket starts full (`max_burst` tokens).

```yaml
filters:
  rate_limiting:
    enabled: true
    max_burst: 5                  # bucket capacity
    refill_rate: 1.0              # tokens per second
    ttl_seconds: 300              # idle bucket lifetime
    cleanup_interval_seconds: 60  # background sweep period
    max_keys: 10000               # upper bound on tracked buckets
```

| Field | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` in `config.example.yaml` | Adds the filter to the pipeline. |
| `max_burst` | `5` (code fallback) | Bucket capacity. |
| `refill_rate` | `1.0` (code fallback) | Tokens per second. |
| `ttl_seconds` | `300` | Idle buckets are removed after this time. |
| `cleanup_interval_seconds` | `60` | Period of the background eviction sweep. |
| `max_keys` | `10000` | When exceeded, expired buckets are pruned, then the least recently used one is evicted. |

> [!NOTE]
> The default values differ by source. `config.example.yaml` and the code fallback use `5` and `1.0`. The generated starter config and the toggle in the web UI use `max_burst: 50` and `refill_rate: 10.0`. Always set both explicitly for production.

### Per-agent overrides

An agent definition can override the limits for that agent. When `rate_limit.max_burst` or `rate_limit.refill_rate` is set to a value greater than zero, it replaces the global value for requests from that agent. Unset or zero fields keep the global value.

### Error response

Exceeded limits return `-32009` (`ErrRateLimitExceeded`):

```json
{
  "jsonrpc": "2.0",
  "id": "req-77",
  "error": { "code": -32009, "message": "Tool execution rate limit exceeded" }
}
```

If the state store itself fails, the request is rejected with `-32603` (fail-closed).

## Limits and caveats

- **Shared bucket per agent and user.** Heavy and light tools consume the same tokens.
- **IPs behind a shared NAT or reverse proxy share one ingress bucket**, because forwarding headers are not trusted.
- **State is in memory and per process.** Counters reset on restart and are not shared across gateway instances.

## Troubleshooting

- **Legitimate bursts are rejected.** Increase `max_burst` first, then `refill_rate`.
- **One agent needs a different limit.** Use the per-agent `rate_limit` override instead of raising the global values.
- **Clients behind a corporate proxy hit `429`.** Raise `security.rate_limiting.burst` and `rate`, since all of them appear as one IP.
- **Tune related detection.** For repeated identical calls rather than call volume, see [Loop Protection](/docs/wire/03-security-filters/loop-protection/).
