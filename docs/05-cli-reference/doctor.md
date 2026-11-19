---
title: "faradaiwire doctor"
description: "Inspect host health, port availability, configuration validity, and discover local AI Guard inference engines."
---

# `faradaiwire doctor` 🩺

The `doctor` command executes an exhaustive diagnostic audit of your local host environment, verifying prerequisite ports, disk permissions, DuckDB database integrity, and discovering local AI Guard inference engines.

---

## Syntax

```bash
faradaiwire doctor [--config <path>]
```

---

## Diagnostic Checks Performed

| Check Category | Validation Logic |
| :--- | :--- |
| **Configuration** | Locates `config.yaml`, parses YAML syntax, and validates regex compilation. |
| **Port Conflicts** | Probes Ports 19410 and 19415 to ensure listeners can bind without `EADDRINUSE`. |
| **Disk Permissions** | Verifies write access to `~/.faradaiwire`, `logs/`, and `./schemas/`. |
| **Telemetry Engine** | Opens and verifies read/write integrity of the embedded DuckDB database file. |
| **AI Guard Discovery** | Probes Ollama (`http://127.0.0.1:11434`) and Docker (`http://127.0.0.1:8088`), testing model readiness and latency. |

---

## Sample Output

```text
FaradAiWire Health & Diagnostic Report
============================================================
[✓] Configuration: Discovered at /Users/username/.faradaiwire/config.yaml (Syntax Valid)
[✓] Ingress Port: 19410 is available for binding
[✓] Admin Port: 19415 is available for binding
[✓] File Permissions: Write access confirmed for logs/ and schemas/
[✓] Telemetry: DuckDB database is clean and accessible
[✓] AI Guard Provider: Ollama reachable at http://127.0.0.1:11434 (latency: 4.2ms)
    ↳ Model 'guard-qwen3guard' is READY for deep-path inspection
============================================================
Status: ALL CHECKS PASSED. Ready to launch.
```

---

## Troubleshooting Common Doctor Warnings

### 1. Ingress Port 19410 in Use:
```text
[✗] Ingress Port 19410 is currently bound by another process (PID: 34102)
```
*Resolution:* Terminate the conflicting process with `kill -9 34102`, or run FaradAiWire with a custom port: `faradaiwire run --port 19420`.

### 2. AI Guard Engine Not Found:
```text
[!] AI Guard Discovery: No local inference engines detected at :11434 (Ollama) or :8088 (Docker)
    ↳ FaradAiWire will operate using sub-millisecond static heuristics & regex only.
```
*Resolution:* This is not a fatal error; FaradAiWire operates securely using fast-path regex and schema validation. To enable AI Guard deep-path inspection, launch Ollama (`ollama run hf.co/faradailab/guard-qwen3guard`).

