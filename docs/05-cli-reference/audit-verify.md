---
title: "faradaiwire audit verify"
description: "Verify tamper-evident integrity of DuckDB audit tables and rotated JSONL audit segments."
---

# `faradaiwire audit verify` 🔐

The `audit verify` command recomputes the hash chain (and optional HMAC) over FaradAiWire's local audit stores and reports whether any record was modified, deleted, or reordered.

> [!NOTE]
> This is **not** the same as `faradaiwire skill-audit` (static skill scanner). See [skill-audit](/docs/wire/05-cli-reference/audit/).

---

## Syntax

```bash
faradaiwire audit verify [--config <path>] [--db <path>] [--jsonl <path>] [--json]
```

| Flag | Description |
| :--- | :--- |
| `--config <path>` | YAML config used to resolve the default DuckDB (`telemetry`) and JSONL (`audit_log.path`) locations. |
| `--db <path>` | Path to the telemetry DuckDB file. |
| `--jsonl <path>` | Path to the active audit JSONL file (rotated segments are discovered automatically). |
| `--json` | Emit a structured JSON report: `{"valid": bool, "duckdb": {...}, "jsonl": {...}}`. |

When neither `--db` nor `--jsonl` is given, paths come from `config.yaml` (when telemetry / `audit_log` are enabled). If nothing can be resolved the command exits with an error.

---

## Hash Chain & HMAC

- JSONL logs use length-prefixed **v2 canonical hashing**. Each rotated segment starts with a **segment header** that anchors the previous segment's tail hash, so deleting or swapping whole segments is detected.
- Set `FARADAI_WIRE_AUDIT_HMAC_KEY` to additionally sign the chain with HMAC-SHA256 (`v2-hmac`). Use the same key when verifying.

---

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Integrity verified (`PASSED`). |
| `1` | Tampering detected, or invalid arguments / unreadable files. |
| `2` | The DuckDB file is locked by a running daemon. |

> [!TIP]
> While the daemon is running, DuckDB is locked. Use the live endpoint `GET http://127.0.0.1:19415/admin/audit/verify` (see [Admin API](/docs/wire/06-api-reference/admin-endpoints/)) or pass only `--jsonl`.
