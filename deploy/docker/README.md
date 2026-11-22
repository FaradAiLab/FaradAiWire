# FaradAiWire Docker Deployment (Containerized Security Gateway)

This deployment runs **FaradAiWire** as a hardened, HTTP/SSE-only MCP Security Gateway inside Docker (`FARADAI_WIRE_ALLOW_STDIO=false`).

## Architecture Highlights

- **Minimal Non-Root Image:** Runs as UID `10001` (`faradai`) on `debian:bookworm-slim` with only `ca-certificates` and `libstdc++6` (required by Go DuckDB). No Node.js, npm, Python, `uv`, or Git toolchains are shipped inside the container.
- **Unified Persistent Volume (`/data`):** All runtime state—`config.yaml`, `wire.duckdb`, `keys/api_keys.json`, `agents/`, `protocols/`, `policies/`, `schemas/`, `logs/`, and `.faradaiwire.lock`—is stored under `/data` (`FARADAI_WIRE_HOME=/data`). Recreating the container or upgrading the image preserves all data.
- **Zero-Bleed Bootstrap Auth:** On first startup, FaradAiWire generates an `Admin`-role Bootstrap Master Key (`faw_live_...`) and a `default` Security Profile. Only the masked key prefix is printed to container logs; the full secret never leaks to stdout.

## Quick Start

1. Build and start the gateway:

   ```bash
   docker compose -f deploy/docker/docker-compose.yml up -d --build
   ```

2. Retrieve the **Bootstrap Master Key** & Magic Link URL on demand:

   ```bash
   docker exec -it faradaiwire faradaiwire token
   ```

   Open the printed **Magic Link** (`http://127.0.0.1:19415/admin/dashboard?token=...`) to exchange the token into an `HttpOnly; SameSite=Lax` admin session cookie cleanly stripped from your URL bar (`303 See Other` + `Referrer-Policy: no-referrer`), or paste the `faw_live_...` Admin key into the Web Console unlock dialog.

3. Connect AI agents or upstream HTTP/SSE MCP servers:
   - **Upstream Tool Sources:** In the Admin Console (**Tool Sources -> Custom Tool Source**), register internal **Remote SSE** (`http://mcp-service:8080/sse`) or **Streamable HTTP** (`http://mcp-service:8080/mcp`) endpoints.
   - **Downstream AI Agents:** Generate a scoped `Developer` API key and connect your agent frameworks or containers to `http://faradaiwire:19410/sse/<profile>` (or `http://127.0.0.1:19410/sse/<profile>` from host) with `Authorization: Bearer <token>`.

## AI Guard Discovery inside Docker

- By default, the gateway checks Ollama on your host via `FARADAI_WIRE_GUARD_OLLAMA_URL=http://host.docker.internal:11434`.
- To run the bundled FaradAiGuard sidecar container alongside the gateway:

  ```bash
  docker compose -f deploy/docker/docker-compose.yml --profile guard up -d --build
  ```

## Persistence Verification

Because `/data` is backed by the named volume `faradaiwire_data`, you can destroy and recreate the container without losing configuration, keys, agents, or DuckDB audit telemetry:

```bash
docker compose -f deploy/docker/docker-compose.yml down
docker compose -f deploy/docker/docker-compose.yml up -d
```

For production internet/multi-user exposure, place TLS termination (Caddy, Nginx, or cloud load balancer) in front of `:19410` and `:19415`.
