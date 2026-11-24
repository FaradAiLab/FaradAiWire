# Changelog

All notable changes to FaradAiWire are documented in this file.

## [v0.1.7] - 2026-11-24

### Added
- **Audit Log Viewer & Overview Analytics:** Web Console Overview analytics, Audit Security Events sub-tabs, CSV/JSONL export, Verify Integrity UI, and SSE auto-pause; backend `GET /admin/analytics/summary`, `/admin/audit-logs/export`, `/admin/security-audit-logs`.
- **Containers:** Dockerfile, bootstrap-token authentication, and container port hints for token recovery (`deploy/docker/README.md`).
- **Observability:** zero-dependency `GET /admin/metrics` (OpenMetrics) and `GET /admin/readyz`; configurable `logging.level` / `FARADAI_WIRE_LOG_LEVEL`; query-scrubbed access logs and stdio stderr sink.
- **Audit Integrity:** async bounded JSONL logger with 10 MB rotation, retention, and segment anchors; length-prefixed v2 hashing with optional HMAC (`FARADAI_WIRE_AUDIT_HMAC_KEY`); `faradaiwire audit verify` and `GET /admin/audit/verify`.
- **Attribution & Provenance:** verified admin actor attribution, `security_audit_logs`, 4-channel HITL provenance, ingress auth audit, and 429 aggregation.
- **Runtime maintenance settings** (`maintenance.*`) for JSONL rotation, retention, and export limits.

### Changed
- **Breaking (CLI):** the static scanner command was renamed from `faradaiwire audit` to `faradaiwire skill-audit`; `audit` now hosts `audit verify`.
- **Admin Auth Consolidation:** Legacy server-side admin token env vars (`FARADAI_WIRE_ADMIN_TOKEN`, `ADMIN_API_KEY`) are deprecated for server auth; Admin auth uses the `keys/api_keys.json` keystore only (`faradaiwire token [--rotate]`). `ADMIN_API_KEY` remains a client-side CLI override.

## [v0.1.6] - 2026-11-21

### Added
- **Desktop Alerts:** Native notifications (tiered, clickable on macOS) for guard offline, HITL pending, blocks, and optional audit matches, with per-category cooldowns (`guard.*` runtime settings).
- **Deep Links:** Web Console `#guards` and `#policy-packs` sub-tab deep-linking.
- **Compact Protocol IDs:** Compact protocol ID support with automated legacy ID migration.
- **Agent CRUD** endpoints and audit log management in the OpenAPI spec.

### Changed
- Renamed SLM references and endpoints to **AI Guard**; default ports changed to `19410` (ingress) and `19415` (admin).
- Asynchronous pre-flight capability probing for HTTP providers; Windows compatibility and cross-platform process-guard fixes.

## [v0.1.5] - 2026-11-16

### Added
- Streaming SSE support for MCP protocol probing with real-time stderr logs.

### Changed
- Release pipeline migrated from Homebrew formula to cask; improved daemon spawning; increased stdio probe timeout.

---

## [v0.1.3] - 2026-11-14

### Security
- **Admin Control Plane Hardening:** Enforced explicit `Origin`, `Sec-Fetch-Site`, and JSON `Content-Type` validation across `/admin`, `/api`, and `/ws` routes even when `security.cors_allowed_origins` includes `"*"`.
- **Fail-Closed Admin Bind & Bearer Auth:** Added `--admin-host` / `admin_host` / `FARADAI_WIRE_ADMIN_HOST` (default `127.0.0.1`); binding to a non-loopback address fails closed unless `ADMIN_API_KEY` or `FARADAI_WIRE_ADMIN_TOKEN` is configured.
- **Credential Redaction:** Redacted embedded URL credentials in `/admin/guards/probe` (`configured_url`) and `/admin/guards/configure` (`classifier_url`).
- **CLI HTTP Hardening:** Blocked automatic HTTP redirects on `guard` and `adopt` CLI HTTP clients and restricted Admin Bearer token transmission (including `/progress` polling) to loopback or HTTPS endpoints.

### Fixed
- **Race-Safe AI Guard Reload:** Replaced in-place config mutation in `/admin/guards/configure` with cloned-config atomic reload so concurrent readers and live gateway caches stay consistent.
- **StdioProxy Lifecycle Race:** Fixed a race between `StdioProxy.Dial()` and `Stop()` so newly opened upstream sessions are torn down cleanly if shutdown starts mid-dial.
- **Release Pipeline & Formula:** Cleaned placeholder `linux_arm64` checksum state in `deploy/homebrew/faradaiwire.rb`, hardened version parsing in `.github/workflows/release.yml`, and wired `-ldflags` `config.Version` injection.

### Changed
- Abstracted daemon process detachment into OS-specific build tags, updated admin settings/MCP probing, and added installer checksum/TLS hardening (`install.sh`, `install.ps1`).

---

## [v0.1.2] - 2026-11-10

### Added
- Dynamic runtime settings overlay and persistent configuration backed by DuckDB (`fc980ee`).
- Expanded support for additional AI clients alongside bridge security and reliability improvements (`b8aa2d8`).

---

## [v0.1.1] - 2026-11-09

### Added
- MCP client adoption wizard (`adopt`) and client configuration adapters (`e5966d8`).
