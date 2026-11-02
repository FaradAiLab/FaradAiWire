---
title: "faradaiwire guard"
description: "Inspect, benchmark, and manage local Small Language Models (SLMs) for semantic prompt inspection."
---

# `faradaiwire guard` 🛡️

The `guard` subcommand manages the local Small Language Model (SLM) classifiers used by FaradAiWire's Deep-Path Neural Security Guard.

---

## Syntax

```bash
faradaiwire guard <subcommand> [arguments] [flags]
```

---

## Subcommands

| Subcommand | Arguments | Description |
| :--- | :--- | :--- |
| **`list`** | None | Lists all supported SLM models, their parameter sizes, provider engines, and local installation status. |
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
AVAILABLE SLM MODELS:
 ID                   NAME                 PROVIDER    PARADIGM        STATUS
 prompt-guard-docker  Meta PromptGuard     docker      Classification  READY (8088)
 llama-guard3:1b      Llama Guard 3 1B     ollama      DecisionModel   READY (11434)
 qwen3guard-0.6b      Qwen3 Guard 0.6B     ollama      DecisionModel   AVAILABLE
 granite-guardian     IBM Granite 3.0      ollama      DecisionModel   AVAILABLE
```

### 2. Check Guard Status:
```bash
faradaiwire guard status
```

```text
ACTIVE SLM SECURITY GUARD:
 Provider:          Ollama (http://127.0.0.1:11434)
 Active Model:      llama-guard3:1b
 Quantization:      Q4_K_M (4-bit)
 Context Size:      2048 tokens
 Average Latency:   24.5 ms
 Status:            HEALTHY
```

### 3. Install a New Guard Model:
```bash
faradaiwire guard install qwen3guard-0.6b
```
*FaradAiWire communicates with the local Ollama API to pull and verify model weights.*

