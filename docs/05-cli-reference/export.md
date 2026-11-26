---
title: "faradaiwire export"
description: "Export a Security Profile's MCP servers to native client JSON without routing through FaradAiWire."
---

# `faradaiwire export` 📤

The `export` command serializes a FaradAiWire **Security Profile**'s attached Tool Sources into a target client's native MCP JSON format so your IDE or CLI can connect directly to upstream MCP servers without routing through FaradAiWire.

Offline mode reads strictly from your local `agents/` and `protocols/` directories and does **not** acquire the daemon single-instance lock—you can run it even while `faradaiwire run` is active.

---

## Syntax

```bash
faradaiwire export --profile <name> --client <target> [flags]
```

---

## Flags

| Flag | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| **`--profile <name>`** | Yes | — | Security Profile name to export. |
| **`--client <id>`** | Yes | — | Target client ID (see matrix below). |
| **`--scope <global\|project>`** | No | Client default | Target configuration scope (`project` or `global`). |
| **`--out <new-file>`** | No | `stdout` | Write primary MCP JSON to a brand-new file (`0600`). Refuses existing files and protected live client config paths. |
| **`--companion-out <new-file>`** | No | *(stderr notice)* | Write optional companion snippet (e.g., Claude Code `.claude/settings.json`) to a brand-new file (`0600`). |
| **`--admin-url <url>`** | No | — | Query a running Admin Console (e.g. Docker). Uses `ADMIN_API_KEY` (or local active `Admin` key on loopback); requires `https://` for non-loopback hosts and blocks HTTP redirects. |
| **`--config <path>`** | No | Auto-discovered | Path to `config.yaml` when running in offline mode. |

---

## Supported Clients Matrix

| Client (`--client`) | Scopes (Default) | Target Config Hint | Remote SSE/HTTP Support | Selected Tools Degradation |
| :--- | :--- | :--- | :--- | :--- |
| **`claude-code`** | `project` (default), `global` | `.mcp.json` / `~/.claude.json` *(merge hazard)* | `url` + `type` (`sse` / `http`) | Companion `permissions.deny` in `.claude/settings.json` (`mcp__<server>__<tool>`) |
| **`claude-desktop`** | `global` (only) | `claude_desktop_config.json` *(merge hazard)* | **Omitted** (`UNSUPPORTED_TRANSPORT_OMITTED`; use Settings → Connectors) | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |
| **`cursor`** | `global` (only) | `~/.cursor/mcp.json` | `url` | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |
| **`cursor-workspace`** | `project` (only) | `.cursor/mcp.json` | `url` | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |
| **`windsurf`** | `global` (only) | `~/.codeium/windsurf/mcp_config.json` | `serverUrl` | `disabledTools` denylist (`DENYLIST_UPSTREAM_DRIFT`) / `disabled: true` if 0 tools enabled |
| **`cline`** | `global` (only) | `cline_mcp_settings.json` | `url` + `type` (`sse` / `streamableHttp`) | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |
| **`roo-code`** | `global` (default), `project` | `mcp_settings.json` / `.roo/mcp.json` | `url` + `type` (`sse` / `streamable-http`) | `disabledTools` denylist (`DENYLIST_UPSTREAM_DRIFT`) / `disabled: true` if 0 tools enabled |
| **`antigravity`** | `global` (default), `project` | `~/.gemini/antigravity/mcp_config.json` / `.agents/mcp_config.json` | `serverUrl` (`type` omitted) | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |
| **`generic`** | `project` (default), `global` | `mcp-servers.json` | `url` + `type` (`sse` / `http`) | Fail-open warning (`SELECTED_TOOLS_UNSUPPORTED`) |

---

## Zero-Leak Secret Placeholders

By design, `faradaiwire export` **never emits raw plaintext secrets** into stdout, downloaded JSON, or `--out` files:

- Literal values in `env`, HTTP `headers`, `Authorization` tokens, `--header`/`-H` CLI flags, and URL credentials or secret query/fragment parameters are replaced with uppercase placeholders such as `[OPENAI_API_KEY]` or `[SERVER_BEARER_TOKEN]`.
- Pure `${ENV_VAR}` references are preserved as-is so your runtime environment can supply them natively.
- Default-value syntax (`${VAR:-default}`) is stripped to `${VAR}` (`ENV_DEFAULT_STRIPPED` warning), and mixed literal+env values redact any embedded literals (`ENV_INTERPOLATION_UNSUPPORTED` warning).

---

## Exporting a Profile & Disabling FaradAiWire

> **Rollback vs. Direct Export:**
> - Use `faradaiwire adopt --rollback` if you only want to restore the original pre-adoption backup files exactly as they existed before running `adopt`.
> - Use `faradaiwire export` (or Studio UI **Security Profiles → Export Native MCP**) when you have added, modified, or curated Tool Sources inside FaradAiWire and want to take that profile with you while bypassing or stopping the gateway.

### Step-by-Step Guide

1. **Generate the native MCP export:**
   - **CLI (local offline):**
     ```bash
     faradaiwire export --profile cursor --client cursor --out ./cursor-mcp-export.json
     ```
   - **CLI (Docker / remote Admin Console):**
     ```bash
     ADMIN_API_KEY="faw_adm_..." faradaiwire export \
       --admin-url http://127.0.0.1:19415 \
       --profile claude-code \
       --client claude-code \
       --scope project \
       --out ./mcp-export.json \
       --companion-out ./claude-settings-deny.json
     ```
   - **Web Studio UI:** Open `http://127.0.0.1:19415/admin/dashboard` → **Security Profiles** → click **Export Native MCP** on your profile card → pick your Target Client and Scope → **Copy JSON** or **Download JSON**.

2. **Review warnings before applying:**
   Check stderr (CLI) or the warnings panel (Studio UI) for:
   - `SECURITY_POLICIES_EXCLUDED`: FaradAiWire runtime policies are not portable to native client JSON.
   - `UNSUPPORTED_TRANSPORT_OMITTED`: Remote SSE/HTTP servers omitted for `claude-desktop` (configure those in Claude Desktop **Settings → Connectors**).
   - `SELECTED_TOOLS_UNSUPPORTED` / `UNCATALOGED_ALLOWLIST_FAIL_OPEN` / `DENYLIST_UPSTREAM_DRIFT`: Per-tool restrictions could not be exported natively or rely on denylists.

3. **Merge into your client's config file and remove `farad-ai-wire`:**
   Open the target client config file shown in the `Target Config Hint` (for example `~/.cursor/mcp.json` or `.mcp.json`):
   - Delete the `"farad-ai-wire"` entry under `"mcpServers"`.
   - Paste or merge the exported `"mcpServers"` entries into `"mcpServers"`.
   - **Merge hazard warning:** Never replace `~/.claude.json` or `claude_desktop_config.json` wholesale—those files hold non-MCP client preferences alongside `mcpServers`. Always merge only the `"mcpServers"` object.

4. **Populate credential placeholders:**
   Replace every `[KEY_NAME]` placeholder in the merged config with your real credential, or export the referenced `${ENV_VAR}` variables in your shell/environment before launching the client.

5. **Apply companion permissions (Claude Code only, if generated):**
   If your profile restricts specific tools, merge `"permissions": { "deny": [...] }` from the companion output into `.claude/settings.json` (project scope) or `~/.claude/settings.json` (global scope). Do not overwrite unrelated settings.

6. **Stop FaradAiWire and restart your client:**
   - **Foreground daemon:** press `Ctrl+C` in the terminal running `faradaiwire run`.
   - **Docker gateway:** `docker stop <container-name>`.
   - Restart Claude Code, Cursor, Windsurf, or your IDE/client so it connects directly to the native MCP servers.

> [!WARNING]
> **Security Notice:** Once traffic bypasses FaradAiWire and connects directly to MCP servers, **DLP & Secrets Redaction**, **AI Guard**, **Runtime JSON Schema Pinning**, **Loop & Rate Protection**, **HITL approvals**, and **tamper-evident audit telemetry** are completely disabled.

---

## Examples

### Print exported JSON to stdout (with warnings on stderr)
```bash
faradaiwire export --profile windsurf --client windsurf
```

### Save primary config and Claude Code companion rules to new files
```bash
faradaiwire export \
  --profile claude-code \
  --client claude-code \
  --scope project \
  --out ./exported.mcp.json \
  --companion-out ./exported.claude-settings.json
```

### Export from a Dockerized FaradAiWire instance
```bash
faradaiwire export \
  --admin-url http://127.0.0.1:19415 \
  --profile default \
  --client cursor-workspace \
  --out ./cursor-project-export.json
```
*(If Admin authentication is required or non-loopback HTTPS is used, set `ADMIN_API_KEY` in your environment.)*
