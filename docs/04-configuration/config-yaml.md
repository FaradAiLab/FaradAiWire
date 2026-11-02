---
title: "config.yaml Reference"
description: "Full schema reference and field descriptions for FaradAiWire's YAML configuration."
---

# config.yaml Reference ⚙️

FaradAiWire uses YAML for its primary configuration file (`config.yaml`). The file is automatically generated with sensible defaults on first run if missing.

```yaml
# ==============================================================================
# FaradAiWire Zero-Trust Gateway Configuration
# ==============================================================================

# Network Port Bindings
listen_port: 8090                  # Ingress Proxy port (Fail-Closed Bearer Auth)
admin_port: 8095                   # Admin Console & REST API port (Loopback only)
agents_dir: "./agents"             # Directory containing per-agent configurations

# Security & Access Guardrails
security:
  cors_allowed_origins:
    - "http://localhost:3000"
    - "http://localhost:8090"
    - "http://localhost:8095"
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
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
    baseline_pinning: true         # Alert or block when tools alter schema definitions

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
      - name: "tc_kimlik"
        regex: '\b\d{11}\b'
        action: "mask"

  # Semantic SLM Security Guard Engine
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
    timeout_seconds: 300           # Seconds before approval request times out

  # Infinite loop prevention
  loop_protection:
    enabled: true
    max_repeat: 3                  # Max consecutive identical calls before blocking
    window_seconds: 10             # Sliding time window in seconds

  # Token-Bucket Rate Limiter
  rate_limiting:
    enabled: true
    max_burst: 5                   # Max burst capacity
    refill_rate: 1.0               # Replenish rate (tokens/sec)

# Audit Telemetry Log File
audit_log:
  enabled: true
  path: "./logs/faradai_audit.jsonl"

# Runtime Configuration Hot-Reload
hot_reload: true                   # Enable zero-downtime config reloading via fsnotify

# Admin Console TLS (Optional)
admin_tls:
  enabled: false
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
```

