---
title: "Admin REST API Endpoints"
description: "HTTP endpoints on Port 19415 for gateway status, configuration toggles, schema management, AI Guard, and telemetry."
---

# Admin REST API Endpoints 🛠️

All endpoints documented here are hosted on FaradAiWire's **Admin Console Port (`19415`)** (bound to `127.0.0.1` by default via `--admin-host` / `admin_host`).

### Authentication & CSRF Protections

- **Bearer & Session Authentication:** Server-side Admin authentication uses active `role: "Admin"` keys in `keys/api_keys.json` (`faradaiwire token [--rotate]`) exclusively. On non-loopback interfaces, protected `/admin`, `/api`, and `/ws` endpoints require an `Admin` Bearer token or `faw_admin_session` `HttpOnly` cookie (`/admin/dashboard`, `/admin/assets/*`, `/admin/auth/session`, and `/admin/auth/logout` remain reachable for login). Even on loopback, an explicit `Authorization: Bearer` header carrying an `Agent` (or legacy `Developer`) key is rejected with `403 ADMIN_ROLE_REQUIRED`.
- **Admin Key Lifecycle:** `GET /admin/api-keys` and `GET /admin/api-keys/{id}` redact `raw_key` on `Admin` keys while returning `prefix`; `POST /admin/api-keys` always mints `role: "Agent"` ingress keys; `DELETE /admin/api-keys` rejects `Admin` keys with `403 ADMIN_KEY_CLI_ONLY`.
- **CSRF & Origin Enforcement:** Cross-site browser requests (`Sec-Fetch-Site: cross-site` or disallowed `Origin`) are rejected with `403 Forbidden`. Setting `security.cors_allowed_origins: ["*"]` does not disable Origin validation for CSRF or WebSocket upgrades.
- **JSON Content-Type:** Mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) must use `Content-Type: application/json` (otherwise rejected with `415 Unsupported Media Type`).

---

## 1. Gateway Status

### `GET /admin/status`
Returns real-time health metrics, daemon version, uptime, and active session counts.

**Request:**
```bash
curl -s http://127.0.0.1:19415/admin/status
```

**Response (`200 OK`):**
```json
{
  "status": "Ready",
  "version": "v0.1.5",
  "runtime_mode": "STANDALONE",
  "ingress_port": 19410,
  "ingress_host": "127.0.0.1",
  "ingress_url": "http://127.0.0.1:19410",
  "guard_tier": "neural_active",
  "guard_model": "Qwen3Guard-0.6B",
  "guard_endpoint": "http://127.0.0.1:11434",
  "guard_latency_ms": 16.4
}
```

---

## 2. Configuration & Runtime Toggles

### `GET /admin/settings`
Returns the active in-memory YAML configuration.

### `POST /admin/config/toggle`
Dynamically enables or disables a security filter at runtime without restarting the daemon.

**Request:**
```bash
curl -X POST http://127.0.0.1:19415/admin/config/toggle \
  -H "Content-Type: application/json" \
  -d '{
    "filter": "dlp",
    "enabled": false
  }'
```

**Response (`200 OK`):**
```json
{
  "filter": "dlp",
  "enabled": false,
  "updated_at": 1730300900
}
```

---

## 3. Schema Management

### `POST /admin/schemas/clear`
Clears in-memory and on-disk schema caches in `./schemas/`, allowing tools to re-register baseline schemas on next call.

**Request:**
```bash
curl -X POST http://127.0.0.1:19415/admin/schemas/clear
```

**Response (`200 OK`):**
```json
{
  "status": "cleared",
  "message": "Schema cache purged successfully"
}
```

---

## 4. MCP Tools Catalog

### `GET /admin/mcp/tools`
Returns the list of all tools discovered by the gateway across upstream sessions, along with their schema hash.

**Response (`200 OK`):**
```json
{
  "tools": [
    {
      "name": "read_file",
      "session_id": "sess-default",
      "transport": "stdio",
      "schema_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "pinned": true
    }
  ]
}
```

---

## 5. Live Telemetry Stream

### `GET /api/v1/logs/events`
Establishes a Server-Sent Events (SSE) stream delivering real-time JSON audit events as they occur. Used by the Web Console live dashboard.

**Request:**
```bash
curl -N http://127.0.0.1:19415/api/v1/logs/events
```

**Streamed Event:**
```text
event: audit_verdict
data: {"id":"evt-109","timestamp":"2026-10-30T21:00:00Z","verdict":"BLOCKED","rule":"sensitive_files","tool":"fetch","agent":"claude-code"}
```

---

## 6. AI Guard Probe, Configuration & Model Lifecycle

### `GET /admin/guards/probe`
Probes configured or locally available AI Guard inference backends (Ollama, FaradAiGuard Docker sidecar, or custom URL). Any embedded URL credentials in `configured_url` are redacted before returning the JSON payload.

### `POST /admin/guards/configure`
Updates AI Guard discovery settings and atomically reloads configuration across the admin server and live gateway.

**Request (`Content-Type: application/json`):**
```json
{
  "classifier_url": "http://127.0.0.1:11434",
  "enabled": true,
  "mode": "auto"
}
```
Supported optional fields: `classifier_url`, `enabled`, `mode`, `ollama_url`, `docker_url`, `custom_url`.

**Response (`200 OK`):**
```json
{
  "status": "success",
  "classifier_url": "http://127.0.0.1:11434",
  "mode": "auto",
  "message": "AI Guard configuration successfully updated"
}
```
*(Embedded credentials in `classifier_url` are redacted in the response.)*

### Model Catalog, Lifecycle & HITL Endpoints
- `GET /admin/guards/status`: Runtime status, PID, and health of the active AI Guard process.
- `GET /admin/guards/models`: Lists all curated and installed AI Guard models.
- `POST /admin/guards/models/{id}/install` & `GET /admin/guards/models/{id}/progress`: Trigger and track local model installation.
- `POST /admin/guards/models/{id}/connect`: Verify and bind an external Ollama, Docker, or vLLM AI Guard endpoint.
- `POST /admin/guards/models/{id}/activate` & `POST /admin/guards/models/deactivate`: Zero-downtime hot-swap or return to L1-only mode.
- `POST /admin/guards/models/{id}/policy`: Configure `default_action` (`hitl` / `block`) and `critical_tools`.
- `GET /admin/guards/hitl/pending` & `POST /admin/guards/hitl/respond`: Inspect and resolve pending HITL approvals.

