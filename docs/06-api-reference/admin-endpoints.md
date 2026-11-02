---
title: "Admin REST API Endpoints"
description: "HTTP endpoints on Port 8095 for gateway status, configuration toggles, schema management, and telemetry."
---

# Admin REST API Endpoints 🛠️

All endpoints documented here are hosted on FaradAiWire's **Admin Console Port (`8095`)**.

---

## 1. Gateway Status

### `GET /admin/status`
Returns real-time health metrics, daemon version, uptime, and active session counts.

**Request:**
```bash
curl -s http://127.0.0.1:8095/admin/status
```

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "runtime_mode": "standalone",
  "ingress_port": 8090,
  "admin_port": 8095,
  "uptime_seconds": 1842,
  "active_sessions": 2,
  "duckdb_events_count": 512
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
curl -X POST http://127.0.0.1:8095/admin/config/toggle \
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
curl -X POST http://127.0.0.1:8095/admin/schemas/clear
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
curl -N http://127.0.0.1:8095/api/v1/logs/events
```

**Streamed Event:**
```text
event: audit_verdict
data: {"id":"evt-109","timestamp":"2026-10-30T21:00:00Z","verdict":"BLOCKED","rule":"sensitive_files","tool":"fetch","agent":"claude-code"}
```

