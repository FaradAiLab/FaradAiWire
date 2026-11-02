# FaradAiWire Codebase Review Guide

This guide outlines the recommended sequence and logical flow for reviewing the **FaradAiWire** codebase. Follow this order to understand the architecture step-by-step.

---

## 1. Entrypoint & Protocol Basics
Start here to understand how the gateway boots up and how messages are formatted.
* **[cmd/faradaiwire/main.go](cmd/faradaiwire/main.go)**
  - The CLI entrypoint. Review the `run` (stdio/sse proxy runner), `audit` (static scanner), and `version` subcommands. Pay attention to how OS signals are handled for graceful shutdown.
* **[pkg/mcp/protocol.go](pkg/mcp/protocol.go)**
  - Defines the core JSON-RPC 2.0 structures and standard security error codes (`-32000` through `-32009`, including `ErrPolicyDenied = -32003`) used to report gateway violations back to the LLM agent.

## 2. Configuration & Filter Pipeline Orchestration
Understand how rules are loaded, hot-reloaded dynamically, and executed sequentially.
* **[internal/config/provider.go](internal/config/provider.go) & [yaml.go](internal/config/yaml.go)**
  - Code abstraction for config loading. Allows easy swapping from file-based config to dynamic configurations.
* **[internal/config/watcher.go](internal/config/watcher.go)**
  - Employs `fsnotify` to monitor the config YAML, automatically hot-reloading changes in memory without gateway downtime.
* **[pkg/filter/filter.go](pkg/filter/filter.go) & [internal/filter/pipeline.go](internal/filter/pipeline.go)**
  - Defines the `SecurityFilter` interface and canonical execution ordering (`OrderPrefill`, `OrderRateLimit`, `OrderLoopProtection`, `OrderPolicy`, `OrderSchemaValidation`, `OrderDLP`, `OrderGuard`, `OrderInjectionScanner`, `OrderHITL`). The `Pipeline` class chains these filters together and executes them sequentially. External filters can be registered dynamically via `pipeline.RegisterFilter(f)`.

## 3. Security Filters (Core Guardrails)
Review the individual security filters. Each implements specific logic for preventing AI/LLM attacks.
* **[prefill.go](internal/filter/prefill/prefill.go)**
  - Prefill / Sockpuppeting block. Inspects the end of message history arrays to ensure they don't terminate with an assistant role block.
* **[ratelimit.go](internal/filter/ratelimit/ratelimit.go)**
  - Token-bucket rate limiting per agent/client to prevent resource exhaustion and denial of service.
* **[loop.go](internal/filter/loop/loop.go)**
  - Autonomous loop protection. Detects recursive or repeating tool invocations within sliding execution windows.
* **[schema.go](internal/filter/schema/schema.go)**
  - Parameter validation and baseline drift defense. Caches tools' JSON Schemas, validates client argument payloads, and pins/warns if schema drift is detected.
* **[injection.go](internal/filter/injection/injection.go)**
  - Response payload scanner. Intercepts tool execution outputs to block indirect prompt injection patterns.
* **[dlp.go](internal/filter/dlp/dlp.go)**
  - Data Loss Prevention. Matches and masks sensitive PII (like credit card patterns) before forwarding them to the LLM agent.
* **[hitl.go](internal/filter/hitl/hitl.go)**
  - Human-in-the-Loop gate. Intercepts destructive tool calls (like sending email) and blocks them unless manual CLI or webhook confirmation is received.

## 4. Communication Proxy Layer
Inspect how client connections are intercepted and mapped to user context headers.
* **[internal/proxy/stdio.go](internal/proxy/stdio.go)**
  - Redirection logic for command-line spawned stdio sub-processes.
* **[internal/proxy/sse.go](internal/proxy/sse.go)**
  - SSE Reverse Proxy. Reads user identification headers (`X-User-ID`, `X-User-Role`), maps asynchronous request-response IDs over HTTP streams, and binds proper user contexts.

## 5. Integration Suite & Testing
Review the automated test suite and benchmarks to see how all the filters interact.
* **Go Unit & Race Tests (`go test -race ./...`)**
  - Runs all unit tests, adaptive routing benchmarks, and pipeline concurrency safety checks.
* **[verify/mock_server/main.go](verify/mock_server/main.go)**
  - Standalone mock MCP server supporting both `stdio` and `sse` transports for end-to-end proxy verification.
