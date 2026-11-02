# Contributing to FaradAiWire

Thank you for your interest in contributing to **FaradAiWire**! 🛡️

We welcome contributions of all kinds: bug fixes, documentation improvements, new security filter modules, Model Context Protocol (MCP) tool integrations, and test cases.

---

## 📜 Developer Certificate of Origin (DCO)

FaradAiWire is an open-source project licensed under the [Apache License, Version 2.0](../LICENSE).

To ensure that all contributions are legally unencumbered and respect open-source and intellectual property rights, we require all commits to adhere to the **Developer Certificate of Origin (DCO)**.

### Signing Your Commits

Simply add a `Signed-off-by` trailer to every commit message. Git provides a built-in flag (`-s` or `--signoff`) to automate this:

```bash
git commit -s -m "feat(dlp): add Turkish phone number masking rule"
```

This will automatically append your name and email address:
```
Signed-off-by: Jane Doe <jane.doe@example.com>
```

By signing off on a commit, you certify the following statement (DCO v1.1):
```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

---

## 🏗️ Architecture & Core Invariants

Key design invariants that every pull request must respect:
1. **Open Core Purity:** Core must remain 100% offline-first, zero-egress, and free of proprietary licensing or cloud phone-home hooks. Enterprise-specific capabilities (such as centralized multi-tenant sync or corporate fleet policies) belong in separate enterprise extensions, never in Core.
2. **Uniform Plugin Pipeline:** Use `pipeline.RegisterFilter(f SecurityFilter)` for all new filters.
3. **Strict Port Segregation:** Port `8090` is exclusively for client agent ingress (`/sse`, `/message`, `/mcp`), while port `8095` is strictly for administrative endpoints and the web console.
4. **Zero-I/O Hot Path:** Never execute blocking disk I/O (`os.Stat`, `os.ReadFile`) inside the request or DLP evaluation hot path.

---

## 🛠️ Local Development & Testing

Prerequisites: **Go 1.23+** and **Node.js 20+** (for web dashboard changes).

```bash
# Clone the repository
git clone https://github.com/FaradAiLab/FaradAiWire.git
cd FaradAiWire

# Run tests
make test

# Start the local daemon in development mode
make dev
```

---

## 🚀 Pull Request Checklist

Before submitting a PR:
- [ ] Commits are signed off (`git commit -s`).
- [ ] Tests pass locally (`make test` or `go test ./...`).
- [ ] Code follows idiomatic Go style and passes `golangci-lint` if applicable.
- [ ] If you modified public interfaces or contracts, relevant documentation or specs have been updated.
