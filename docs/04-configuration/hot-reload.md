---
title: "Runtime Configuration Hot-Reload"
description: "Update DLP patterns, rate limits, and agent profiles at runtime without dropping active SSE connections."
---

# Runtime Configuration Hot-Reload 🔄

In an agentic workflow, dropping long-running Server-Sent Events (SSE) connections to reload a configuration file would break active agent reasoning sessions. FaradAiWire provides **Atomic Runtime Hot-Reloading** ([ADR-0015](../adr/0015-unified-hot-reload-and-multi-agent-domain-isolation.md) & [ADR-0044](../adr/0044-atomic-pipeline-swapping-and-killswitch-hierarchy.md)) powered by Go's `fsnotify` library and atomic pointer swapping.

---

## How It Works

1. **Filesystem Watchers:** When `hot_reload: true` is configured, FaradAiWire registers background watchers on `config.yaml` and the `agents/` directory.
2. **Debouncing:** When you save changes in your editor, FaradAiWire debounces file system events (150ms window) to prevent reading partially written files.
3. **Atomic Pipeline Swap:**
   - The new configuration is parsed and compiled into a fresh in-memory pipeline.
   - If parsing fails (e.g. invalid YAML syntax or invalid regex), an error is logged and the current pipeline remains active.
   - If validation passes, an atomic pointer swap (`atomic.Pointer[FilterPipeline]`) replaces the active pipeline.
4. **Zero Interruption:** In-flight tool executions finish against the pipeline that started them, while subsequent tool calls immediately evaluate against the updated rules. Active SSE streams remain connected.

---

## What Can Be Hot-Reloaded?

| Subsystem | Hot-Reloadable? | Behavior on Save |
| :--- | :--- | :--- |
| **DLP Patterns & Actions** | ✅ Yes | Recompiles regex table and updates mask/block rules. |
| **Agent Profiles (`agents/*.yaml`)** | ✅ Yes | In-memory agent catalog refreshes instantly. |
| **Rate Limiter & Loop Limits** | ✅ Yes | Adjusts token bucket capacity and window without clearing current counts. |
| **HITL Destructive Tools** | ✅ Yes | Updates the list of tools that require operator prompt. |
| **SLM Guard Thresholds** | ✅ Yes | Updates confidence thresholds and provider URLs. |
| **Port Bindings (8090, 8095)** | ❌ No | Requires daemon restart to rebind operating system TCP sockets. |
| **DuckDB Database Path** | ❌ No | Requires restart to cleanly close and reopen DuckDB locks. |

---

## Triggering Reload Programmatically

In addition to automated filesystem monitoring, you can trigger a configuration reload via the Admin REST API:

```bash
curl -X POST http://127.0.0.1:8095/api/reload \
  -H "Authorization: Bearer dev-local-key"
```

Expected response:
```json
{
  "status": "reloaded",
  "timestamp": 1730300400,
  "loaded_filters": [
    "prefill_block",
    "rate_limiting",
    "loop_protection",
    "schema_validation",
    "dlp",
    "guard",
    "hitl"
  ]
}
```

