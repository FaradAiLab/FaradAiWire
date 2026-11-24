---
title: "Runtime Settings"
description: "Live-tunable settings stored in DuckDB and edited from the Web Console or /admin/settings: desktop alerts and maintenance limits."
---

# Runtime Settings ⚙️

Runtime settings overlay `config.yaml` and are persisted in DuckDB. They apply immediately, without restart, via `GET/POST/PUT /admin/settings` or the Web Console **Settings** tab.

## Desktop Alerts (`guard.*`)

Native workstation notifications (clickable deep links on macOS; loopback URLs are normalized) for security events.

| Key | Default | Description |
| :--- | :--- | :--- |
| `guard.desktop_alerts_enabled` | `true` | Master switch for desktop notifications. |
| `guard.alert_on_guard_offline` | `true` | AI Guard disconnects or falls back to L1 regex protection (links to `#guards`). |
| `guard.alert_on_hitl_pending` | `true` | A tool call is paused awaiting human approval. |
| `guard.alert_on_block` | `true` | DLP, AI Guard, rate limit, loop, or schema policy blocks a call. |
| `guard.alert_on_audit` | `false` | Non-blocking `Audit` rule match (opt-in to avoid alert fatigue). |
| `guard.alert_cooldown_sec` | `60` | Per-category cooldown for non-HITL alerts (0–3600, `0` disables throttling). |

## Maintenance (`maintenance.*`)

| Key | Default | Range | Description |
| :--- | :--- | :--- | :--- |
| `maintenance.session_idle_timeout_min` | `30` | 5–1440 | Evict inactive SSE/stdio sessions. |
| `maintenance.correlation_ttl_min` | `60` | 10–1440 | Request correlation retention. |
| `maintenance.audit_retention_days` | `30` | 7–365 | Retention for DuckDB records and rotated JSONL segments. |
| `maintenance.retain_local_payloads` | `true` | — | Store unredacted payloads only in local DuckDB. |
| `maintenance.audit_jsonl_max_size_mb` | `10` | 1–100 | Rotation size per JSONL segment. |
| `maintenance.audit_jsonl_max_files` | `10` | 1–100 | Rotated segments kept on disk. |
| `maintenance.audit_export_max_rows` | `50000` | 1000–200000 | Row cap per CSV/JSONL export. |

See [Telemetry & Audit Logging](/docs/wire/06-api-reference/telemetry/) for how these affect audit storage.
