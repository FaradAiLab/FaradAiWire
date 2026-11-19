---
title: "faradaiwire guard"
description: "Inspect, benchmark, and manage local AI Guard models for semantic prompt inspection."
---

# `faradaiwire guard` 🛡️

The `guard` subcommand manages the local AI Guard models used by FaradAiWire's Deep-Path AI Guard engine.

---

## Syntax

```bash
faradaiwire guard <subcommand> [arguments] [flags]
```

---

## Subcommands

| Subcommand | Arguments | Description |
| :--- | :--- | :--- |
| **`list`** | None | Lists all supported AI Guard models, their parameter sizes, provider engines, and local installation status. |
| **`status`** | None | Displays real-time operational status, active model, provider endpoint, and inference latency. |
| **`install`** | `<model-id>` | Triggers automated local model installation (e.g. invokes Ollama pull or verifies Docker image). |
| **`uninstall`**| `<model-id>` | Removes local model weights to reclaim workstation disk space. |

---

## Examples & Output

### 1. List Supported Models:
```bash
faradaiwire guard list
```

```text
AVAILABLE AI GUARD MODELS:
 ID                   NAME                 PROVIDER    PARADIGM        STATUS
 prompt-guard-docker  FaradAiGuard Docker  docker      Classification  READY (8088)
 qwen3guard           Qwen3Guard-0.6B      ollama      GenerativeLLM   READY (11434)
 granite-guardian     IBM Granite 3.0-2B   ollama      GenerativeLLM   AVAILABLE
 mica-v0.5            Mica v0.5-4B         ollama      DecisionModel   AVAILABLE
```

### 2. Check Guard Status:
```bash
faradaiwire guard status
```

```text
ACTIVE AI GUARD:
 Provider:          Ollama (http://127.0.0.1:11434)
 Active Model:      qwen3guard
 Quantization:      Q4_K_M (4-bit)
 Context Size:      2048 tokens
 Average Latency:   16.4 ms
 Status:            HEALTHY
```

### 3. Install a New Guard Model:
```bash
faradaiwire guard install qwen3guard
```
*FaradAiWire communicates with the local Ollama API (or the running gateway's Admin Console) to pull and verify model weights.*

> [!NOTE]
> When `guard` calls the running gateway's Admin Console endpoints (such as `/admin/guards/models/{id}/install` or `/admin/guards/models/{id}/progress`), CLI HTTP clients disable HTTP redirects (`CheckRedirect`) and attach the `Authorization: Bearer` admin token (`ADMIN_API_KEY` / `FARADAI_WIRE_ADMIN_TOKEN`) only over loopback or HTTPS (`admin_tls.enabled: true`) connections.

