<![CDATA[<div align="center">

```
   _____ _               _____ _     _      _     _
  / ____| |             / ____| |   (_)    | |   | |
 | |    | | __ ___   __| (___ | |__  _  ___| | __| |
 | |    | |/ _` \ \ /\ / /\___ \| '_ \| |/ _ \ |/ _` |
 | |____| | (_| |\ V  V / ____) | | | | |  __/ | (_| |
  \_____|_|\__,_| \_/\_/ |_____/|_| |_|_|\___|_|\__,_|
```

# ClawShield

### 🛡️ Security Layer for AI Agents

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)]()

**One command to audit, harden, and monitor the security of your AI agent infrastructure.**

[Quick Start](#-quick-start) • [Features](#-features) • [Commands](#-commands) • [Installation](#-installation) • [Contributing](#contributing)

</div>

---

## The Problem

AI agents run with powerful permissions — root access, API keys, network access, tool execution. A misconfigured server or a malicious skill can compromise everything.

**ClawShield** scans your system in seconds and tells you exactly what's wrong and how to fix it.

<!-- TODO: Add terminal recording GIF here
     Shows: clawshield scan running on a fresh VPS,
     finding 5 issues, then clawshield harden --auto fixing them,
     score going from D (45/100) to A (92/100) in 30 seconds -->

---

## ⚡ Quick Start

```bash
# Install (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/openclaw/clawshield/main/scripts/install.sh | bash

# Run your first scan
clawshield scan
```

That's it. You'll get a full security report in under 5 seconds.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔍 | **Security Scanner** | 20+ checks across network, access, system, files, and agent security |
| 🔒 | **Auto-Hardener** | One-command fixes for common vulnerabilities (firewall, SSH, fail2ban) |
| 👁️ | **Live Monitor** | Real-time watching of auth logs, connections, and suspicious processes |
| 🔬 | **Skill Scanner** | Analyze OpenClaw skills for malicious code before installing them |
| 📊 | **Security Score** | A+ through F grading with actionable recommendations |

### What Gets Scanned

- **Network** — Firewall status, exposed database ports, Docker port leaks, public services
- **Access** — SSH config (password auth, root login, port), fail2ban, running as root
- **System** — Kernel updates, automatic security updates, file permissions
- **Agent** — API keys in environment, .env file permissions, OpenClaw config security
- **Docker** — Containers with publicly exposed ports (bypasses UFW!)

---

## 📊 Security Score

ClawShield grades your system from **A+** to **F**:

| Grade | Score | Meaning |
|-------|-------|---------|
| **A+** | 90-100 | Excellent — production ready |
| **A** | 80-89 | Good — minor improvements possible |
| **B** | 70-79 | Fair — some issues to address |
| **C** | 60-69 | Concerning — several vulnerabilities |
| **D** | 50-59 | Poor — significant risks |
| **F** | 0-49 | Critical — immediate action required |

---

## 🔧 Commands

### `clawshield scan`

Run a full security audit of your system.

```
$ clawshield scan

🔍 Running security scan...

══════════════════════════════════════════════════════
  🛡️  ClawShield Security Report
  2026-02-10 15:30:00 | OS: linux
══════════════════════════════════════════════════════

── NETWORK ──
  ✅ PASS  Firewall (UFW)
           Active with 8 rules
  ✅ PASS  Database Ports
           No database ports exposed to the internet
  ℹ️  INFO  Public Services
           3 services listening on all interfaces (excl. SSH)

── ACCESS ──
  ✅ PASS  SSH Password Auth
           Disabled (key-only)
  ✅ PASS  SSH Root Login
           Root login restricted to key-only
  ⚠️  WARN  SSH Port
           Running on default port 22
  ✅ PASS  Fail2Ban
           Active (12 IPs currently banned)

── PROCESS ──
  ⚠️  WARN  Running as Root
           OpenClaw is running as root (required but high-risk)

── SYSTEM ──
  ✅ PASS  Automatic Security Updates
           Enabled
  ✅ PASS  Kernel Version
           6.8.0-90-generic

══════════════════════════════════════════════════════
  Security Score: A 82/100
  ✅ 8 passed  ⚠️  2 warnings  ❌ 0 failed
══════════════════════════════════════════════════════
```

### `clawshield harden`

Interactive hardening — walks you through each fix with risk levels.

```bash
clawshield harden          # Interactive mode
clawshield harden --auto   # Auto-apply low-risk fixes only
```

**What it can fix automatically:**
- Enable UFW firewall with sane defaults
- Install and configure fail2ban
- Enable unattended security updates
- Fix file permissions on sensitive configs
- Set SSH idle timeouts

### `clawshield monitor`

Real-time security monitoring. Watches for:

- 🚨 Failed login attempts
- 🔑 SSH logins
- 🚫 fail2ban bans
- 📡 New network listeners
- 🚨 Suspicious processes (miners, reverse shells, etc.)

```bash
clawshield monitor
# Press Ctrl+C to stop
```

### `clawshield skill-scan <path>`

Scan an OpenClaw skill for malicious code before installing it.

```bash
clawshield skill-scan ./skills/some-community-skill
```

Detects:
- Reverse shells and backdoors
- Data exfiltration patterns
- Cryptocurrency miners
- Credential theft
- Privilege escalation
- Persistence mechanisms
- Obfuscated code execution

Verdicts: **SAFE ✅** · **REVIEW 🔍** · **SUSPICIOUS ⚠️** · **DANGEROUS ❌**

### `clawshield status`

Quick security score without the full report.

### `clawshield version`

Print version info.

---

## 📦 Installation

### Quick Install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw/clawshield/main/scripts/install.sh | bash
```

### Download Binary

Grab the latest from [Releases](https://github.com/openclaw/clawshield/releases):

| Platform | Architecture | Download |
|----------|-------------|----------|
| Linux | amd64 | `clawshield-linux-amd64` |
| macOS | Intel | `clawshield-macos-amd64` |
| macOS | Apple Silicon | `clawshield-macos-arm64` |
| Windows | amd64 | `clawshield-windows-amd64.exe` |

```bash
chmod +x clawshield-*
sudo mv clawshield-* /usr/local/bin/clawshield
```

### Build from Source

```bash
git clone https://github.com/openclaw/clawshield.git
cd clawshield
go build -o clawshield ./cmd/clawshield/
sudo mv clawshield /usr/local/bin/
```

---

## 🤖 Built for OpenClaw

ClawShield is designed as the security layer for [OpenClaw](https://openclaw.com) — the open platform for AI agents.

When AI agents operate autonomously, security isn't optional. ClawShield ensures:

- **The host is hardened** before agents get access
- **Skills are vetted** before installation
- **Runtime behavior** is continuously monitored
- **Security posture** is quantified and tracked

Works standalone on any Linux/macOS system, but shines as part of the OpenClaw stack.

---

## ⚔️ ClawShield vs Manual Hardening

| | ClawShield | Manual |
|---|---|---|
| Time to audit | **5 seconds** | 30-60 minutes |
| Checks performed | **20+** automated | Whatever you remember |
| Consistency | Same every time | Varies by expertise |
| Fix application | One command | Copy-paste from guides |
| Skill vetting | Automated pattern matching | Read every file yourself |
| Monitoring | Continuous real-time | `tail -f` and hope |
| Score tracking | Quantified A+ to F | "Seems fine" |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick links:**
- 🐛 [Report a Bug](https://github.com/openclaw/clawshield/issues/new?template=bug_report.md)
- 💡 [Request a Feature](https://github.com/openclaw/clawshield/issues/new?template=feature_request.md)
- 🔒 [Report a Vulnerability](SECURITY.md)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Built with 🛡️ by the [OpenClaw](https://openclaw.com) team.
]]>