---
title: "CLI Command Reference Overview"
description: "Command-line interface commands, global flags, and exit codes for FaradAiWire."
---

# CLI Command Reference Overview 💻

The `faradaiwire` binary provides a comprehensive command-line interface for daemon execution, environment health diagnostics, static skill security auditing, and local SLM guard management.

---

## Command Summary

```text
Usage: faradaiwire <command> [options]

Commands:
  run       Start the FaradAiWire PEP gateway daemon
  doctor    Diagnose system health, port bindings, and discover local SLM inference engines
  audit     Perform static security analysis on agent skill directories or MCP packages
  guard     Inspect and manage local Small Language Models (list, status, install, uninstall)
  version   Display version, git commit hash, and build architecture
```

---

## Configuration Auto-Discovery

All commands accept an optional `--config <path>` flag. When omitted, FaradAiWire searches standard discovery locations in order:
1. `./config.yaml` (Current working directory)
2. `~/.faradaiwire/config.yaml` (User home directory)
3. `/etc/faradaiwire/config.yaml` (System configuration directory on Linux)

If no configuration file is found, FaradAiWire automatically initializes `~/.faradaiwire/config.yaml` with production-safe offline defaults.

---

## Exit Codes

FaradAiWire conforms to standard UNIX exit code conventions:

| Exit Code | Meaning | Example Scenario |
| :--- | :--- | :--- |
| **`0`** | **Success** | Clean shutdown, health checks passed, or audit reported no threats. |
| **`1`** | **Fatal Error** | Configuration parse error, port conflict, or database permission failure. |
| **`2`** | **Security Violation** | `audit` command detected a high-risk security issue (e.g. reverse shell or token harvesting). |

