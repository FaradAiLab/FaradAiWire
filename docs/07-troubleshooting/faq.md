---
title: "Frequently Asked Questions (FAQ)"
description: "Answers to common architectural, performance, GPU, and deployment questions."
---

# Frequently Asked Questions (FAQ) ❓

---

### How much latency does FaradAiWire add to tool calls?
For typical tool invocations evaluating fast-path rules (Prefill block, Rate Limiting, Schema Validation, and DLP Regex Masking), FaradAiWire adds **less than 1 millisecond ($<0.5\text{ ms}$)** of P99 latency overhead. When the Deep-Path Neural SLM Guard is engaged for ambiguous or untrusted content, local inference adds approximately **15 to 40 ms**, which is negligible compared to standard LLM network latency ($1000\text{--}3000\text{ ms}$).

---

### Do I need a GPU to run FaradAiWire?
**No.** FaradAiWire's core engine, regex DLP, schema pinning, and loop protectors are written in compiled Go machine code and require minimal CPU and $<30\text{ MB}$ of RAM. If you choose to enable the optional Deep-Path SLM Guard, lightweight models like `prompt-guard` (86M parameters) or `qwen3guard-0.6b` execute with sub-20ms latency on modern CPUs and Apple Silicon (M1/M2/M3/M4) unified memory without requiring dedicated discrete NVIDIA GPUs.

---

### Does FaradAiWire transmit my code or tool data to any third-party cloud?
**Absolutely not.** The open-source FaradAiWire Core binary operates under a strict **Zero-Egress Guarantee**:
- All regex pattern matching is performed in local memory.
- Small Language Model inference runs on your machine via Ollama or local Docker sidecars.
- Audit logs and analytics are stored in local files (`logs/faradai_audit.jsonl` and `~/.faradaiwire/telemetry.duckdb`).
- Zero bytes of prompts, parameters, or metadata are ever transmitted across the internet.

---

### Why is FaradAiWire distributed as a native daemon instead of Docker by default?
As established in [ADR-0051](../adr/0051-developer-first-native-distribution-and-docker-deferral.md), over 95% of developer MCP tools (e.g. filesystem access, git, sqlite, local scripts) run as local `stdio` subprocesses (`npx`, `python`, `git`). Running FaradAiWire in a Docker container severs access to host directories and runtimes without complex bind mounts and virtualization slowdowns. Running as a native binary preserves native OS filesystem speed and seamless tool integration.

---

### Can I run FaradAiWire in containerized environments?
Yes. If you are deploying in headless Linux environments or container clusters, you can build the container from `deploy/docker/` and bind listeners with `faradaiwire run --host 0.0.0.0 --standalone`.

---

### What is the difference between FaradAiWire Core and FaradAiWireEE?
- **FaradAiWire Core (Open Source):** Apache 2.0 single-tenant Policy Enforcement Point (PEP) running on local developer workstations with fast-path deterministic filters.
- **FaradAiWireEE (Enterprise):** Commercial multi-tenant control plane providing centralized Open Policy Agent (OPA) ABAC policy distribution, KMS BYOK crypto-shredding, SSO, and real-time SIEM audit streaming. Learn more in the [FaradAiWireEE Docs](/docs/wire-ee/).

