---
title: "config.yaml Reference"
description: "Full schema reference and field descriptions for FaradAiWire's YAML configuration."
---

# config.yaml Reference ⚙️

FaradAiWire uses YAML for its primary configuration file (`config.yaml`). The file is automatically generated with sensible defaults on first run if missing.

> [!NOTE]
> - **Read-only at runtime:** FaradAiWire treats `config.yaml` as a read-only baseline after startup. Changes made via the Web Console or Admin API (such as filter toggles under `filters.*`, AI Guard discovery under `guard.discovery.*`, and runtime tuning) persist in the local DuckDB `system_settings` overlay rather than rewriting `config.yaml`.
> - **Home-directory (`~/`) expansion:** All path fields (`agents_dir`, `protocols_dir`, `filters.schema_validation.schemas_dir`, `audit_log.path`, `telemetry.db_path`, `security.api_keys_path`, `admin_tls.cert_file`, `admin_tls.key_file`) and `FARADAI_WIRE_HOME` expand leading `~/` automatically.

```yaml
# ==============================================================================
# FaradAiWire Zero-Trust Gateway Configuration
# ==============================================================================

# Network Port Bindings
# listen_host: "127.0.0.1"         # Ingress listener host (default 127.0.0.1; keep commented to allow FARADAI_WIRE_HOST override)
listen_port: 19410                 # Ingress Proxy port (Fail-Closed Bearer Auth)
# admin_host: "127.0.0.1"          # Admin Console host (default 127.0.0.1; non-loopback requires an active Admin key in keys/api_keys.json)
admin_port: 19415                  # Admin Console & REST API port (Loopback by default)
agents_dir: "~/.faradaiwire/agents" # Directory containing per-agent configurations

# Security & Access Guardrails
security:
  # Explicit browser origins allowed for CORS, Admin CSRF checks, and WebSocket upgrades.
  # Note: "*" does NOT bypass CSRF / Sec-Fetch-Site or WebSocket CSWSH origin validation.
  cors_allowed_origins:
    - "http://localhost:19418"
    - "http://localhost:19410"
    - "http://localhost:19415"
  ssrf_protection:
    enabled: true                  # Block requests to private/link-local IP addresses
    block_private_ips: true        # Disallow RFC 1918 and loopback upstream destinations
    allowed_domains: []            # Explicit whitelist of permitted upstream remote domains

# User Identity and Context Provenance
user_context:
  role_header: "X-User-Role"       # Header mapping to user role
  user_header: "X-User-ID"         # Header mapping to unique user identity
  fallback_role: "Customer"        # Default role if header is missing
  fallback_user: "guest-customer"  # Default user identity if header is missing
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  context_hmac_secret: "${FARADAI_WIRE_HMAC_SECRET}" # Secret for anti-spoofing verification

# Security Filter Pipelines
filters:
  # Assistant prefill hijack prevention
  prefill_block:
    enabled: true

  # Runtime JSON Schema validation for tool parameters & drift detection
  schema_validation:
    enabled: true
    schemas_dir: "./schemas/"      # Directory for pinned baseline schemas
    dynamic_capture: true          # Intercept tools/list responses to cache schemas
    baseline_pinning: true         # Track a baseline per tool and log schema changes (changes are not blocked)

  # Sensitive data loss prevention (PII, credentials, and files)
  dlp:
    enabled: true
    exclude_tools: []              # Tool names exempt from DLP inspection
    patterns:
      - name: "private_keys"
        regex: '-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----'
        action: "block"            # "block", "mask", or "audit"
      - name: "sensitive_files"
        regex: '(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|/etc/shadow|/etc/passwd)'
        action: "block"
      - name: "aws_credentials"
        regex: '(?i)["'']?(aws_secret_access_key|aws_access_key_id)["'']?\s*[:=]?\s*["'']?[A-Za-z0-9/+=]{16,}["'']?'
        action: "mask"
      - name: "credit_card"
        regex: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        action: "mask"
      - name: "email"
        regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b'
        action: "mask"
      - name: "tc_kimlik"            # example custom pattern, not a built-in default
        regex: '\b\d{11}\b'
        action: "mask"

  # AI Guard Engine (Qwen3Guard, Mica, Granite Guardian)
  guard:
    enabled: true
    discovery:
      mode: "auto"                 # "auto", "ollama", "docker", or "custom"
      ollama_url: "http://127.0.0.1:11434"
      docker_url: "http://127.0.0.1:8088"
      custom_url: ""               # Custom OpenAI-compatible URL

  # Human-in-the-Loop Interceptor for destructive tool calls
  hitl:
    enabled: true
    destructive_tools:
      - "write_to_db"
      - "delete_record"
      - "send_email"
      - "para_transferi"
    approval_mode: "cli"           # "cli" or "webhook"
    webhook_url: ""                # Webhook URL for remote notifications
    timeout_seconds: 60            # Seconds before approval request times out

  # Infinite loop prevention
  loop_protection:
    enabled: true
    max_repeat: 3                  # Identical calls allowed per window; the next call is blocked
    window_seconds: 10             # Sliding time window in seconds (see loop-protection page)

  # Token-Bucket Rate Limiter
  rate_limiting:
    enabled: true
    max_burst: 5                   # Bucket capacity per agent and user (see rate-limiting page)
    refill_rate: 1.0               # Replenish rate (tokens/sec)

# Audit Telemetry Log File
audit_log:
  enabled: true
  path: "~/.faradaiwire/logs/faradai_audit.jsonl"
  max_size_mb: 10                  # Baseline segment size (1-100 MB, live override via maintenance.audit_jsonl_max_size_mb)
  max_files: 10                    # Baseline rotated files (1-100, live override via maintenance.audit_jsonl_max_files)

# Local DuckDB Telemetry & Analytics
telemetry:
  enabled: true
  retention_days: 30               # Default: 30 days
  max_payload_bytes: 524288        # Default: 512 KB

# Structured Runtime Logging
logging:
  level: "info"                    # debug | info | warn | error (override: FARADAI_WIRE_LOG_LEVEL)

# Runtime Configuration Hot-Reload
hot_reload: true                   # Enable zero-downtime config reloading via fsnotify

# Admin Console TLS (Optional)
admin_tls:
  enabled: false
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
```

