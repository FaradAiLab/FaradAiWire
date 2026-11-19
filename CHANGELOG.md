# Changelog

All notable changes to FaradAiWire are documented in this file.

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
