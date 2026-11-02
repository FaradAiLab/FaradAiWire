---
title: "API & Protocol Reference Overview"
description: "Contract specifications for Admin REST APIs, JSON-RPC 2.0 Ingress endpoints, and OpenAPI 3.1 definitions."
---

# API & Protocol Reference Overview 📋

FaradAiWire exposes two distinct networking interfaces governed by physical port segregation:

1. **Proxy Ingress API (Port 8090):** Streamed JSON-RPC 2.0 interface for AI agents (Claude Code, Cursor, Windsurf, custom SDKs).
2. **Admin REST API (Port 8095):** Administrative control plane for configuration management, schema inspection, live telemetry, and Web Console UI.

---

## Authentication Schemes

```mermaid
graph TD
    subgraph Agent Port [Port 8090: Ingress]
        A["AI Agent Request"] -->|"Header: Authorization: Bearer <API_KEY>"| V1{"Verify Key"}
        V1 -->|"Valid"| Pipeline["Security Pipeline"]
        V1 -->|"Invalid or Missing"| E401["HTTP 401 Unauthorized"]
    end

    subgraph Admin Port [Port 8095: Admin Console]
        Admin["Browser / Admin Client"] -->|"Source: 127.0.0.1 or X-API-Key"| V2{"Loopback / Auth"}
        V2 -->|"Allowed"| AdminAPI["Admin REST Handlers"]
        V2 -->|"Denied"| E403["HTTP 403 Forbidden"]
    end
```

---

## OpenAPI 3.1 Specification

The complete, machine-readable OpenAPI 3.1 definition for all FaradAiWire Admin and Ingress endpoints is maintained in the repository:
👉 **[`api/openapi.yaml`](https://github.com/FaradAiLab/FaradAiWire/blob/main/api/openapi.yaml)**

You can import this contract into Postman, Swagger UI, Insomnia, or code generation tools.

