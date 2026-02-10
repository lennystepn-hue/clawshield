# 🛡️ ClawShield

**Security Layer for AI Agents.**

One binary. Zero config. Your AI agent keeps root access — ClawShield keeps everything else locked down.

```bash
curl -sL https://clawshield.io/install | bash
clawshield scan
```

---

## The Problem

AI agents (OpenClaw, Claude Code, etc.) run as **root** on servers. They have access to everything: files, network, credentials, system configs. One malicious skill or misconfiguration and your entire system is compromised.

- **341 malicious skills** discovered on ClawHub
- Most users have **zero security hardening**
- Agents run 24/7 with **unrestricted root access**
- No monitoring, no audit trail, no kill switch

**ClawShield fixes this.**

---

## What It Does

### 🔍 Security Scanner (`clawshield scan`)

Full security audit in seconds. Checks:

| Category | Checks |
|----------|--------|
| **Network** | Firewall status, exposed ports, database ports, Docker port leaks, Tailscale |
| **Access** | SSH config (password auth, root login, port), Fail2Ban, brute force protection |
| **System** | Kernel version, automatic updates, pending patches |
| **Files** | Config permissions, .env files, SSH keys, /etc/shadow |
| **Agent** | OpenClaw process, API keys in environment, secrets exposure |
| **Docker** | Containers bypassing firewall, exposed services |

Outputs a **Security Score** (A+ to F) with actionable fix commands.

```
══════════════════════════════════════════════════════
  Security Score: B 71/100
  ✅ 8 passed  ⚠️  4 warnings  ❌ 2 failed
══════════════════════════════════════════════════════
```

### 🔒 Auto-Hardener (`clawshield harden`)

One command to fix everything:

- **`--auto`** — Applies all low-risk fixes automatically
- **Interactive mode** — Walks you through each fix with risk level

Fixes include:
- Enable/configure UFW firewall
- Disable SSH password authentication
- Install & configure Fail2Ban
- Enable unattended security updates
- Fix file permissions on sensitive configs
- Set SSH idle timeout
- Restrict root login to key-only
- Secure Docker daemon (prevent UFW bypass)

### 👁️ Live Monitor (`clawshield monitor`)

Real-time security monitoring daemon:

- 🚨 Failed login attempts
- 🔑 SSH logins
- 🚫 Fail2Ban bans
- 📡 New listening ports
- 💀 Suspicious processes (crypto miners, reverse shells, data exfiltration)

```
  19:42:03 ALERT    🚨 Failed login attempt: root from 45.33.12.8
  19:42:15 BLOCK    🚫 IP banned by fail2ban: 45.33.12.8
  19:43:01 INFO     🔑 SSH login: publickey for root from 100.76.32.47
```

### 🔬 Skill Scanner (`clawshield skill-scan <path>`)

Static analysis for OpenClaw/ClawHub skills before installation. Detects:

| Severity | Patterns |
|----------|----------|
| 🚨 **Critical** | Reverse shells, crypto miners, data exfiltration, remote code execution, SUID exploits, disk destruction |
| ❌ **High** | Credential theft, base64 obfuscation, firewall tampering, SSH key access, world-writable permissions |
| ⚠️ **Medium** | Crontab modification, systemd persistence, shell profile changes, direct IP URLs |
| 💡 **Low** | Binding to 0.0.0.0, broad network access |

**40+ detection patterns.** Verdicts: `SAFE ✅` / `REVIEW 🔍` / `SUSPICIOUS ⚠️` / `DANGEROUS ❌`

```
  🚨 CRITICAL (2)
    install.sh:14 — Reverse shell pattern detected
    setup.py:89 — Data exfiltration: sending sensitive files to remote server

  ⛔ DO NOT INSTALL THIS SKILL — critical security risks detected
```

---

## Installation

### One-liner (Linux/macOS)
```bash
curl -sL https://clawshield.io/install | bash
```

### Manual Download
```bash
# Linux
wget https://github.com/clawshield/clawshield/releases/latest/download/clawshield-linux-amd64
chmod +x clawshield-linux-amd64
sudo mv clawshield-linux-amd64 /usr/local/bin/clawshield

# macOS (Apple Silicon)
wget https://github.com/clawshield/clawshield/releases/latest/download/clawshield-macos-arm64
chmod +x clawshield-macos-arm64
sudo mv clawshield-macos-arm64 /usr/local/bin/clawshield

# Windows
# Download clawshield-windows-amd64.exe from releases
```

### From Source
```bash
git clone https://github.com/clawshield/clawshield
cd clawshield
go build -o clawshield ./cmd/clawshield/
```

---

## Usage

```bash
# Full security audit
clawshield scan

# Quick score only
clawshield status

# Auto-fix low-risk issues
clawshield harden --auto

# Interactive hardening (choose what to fix)
clawshield harden

# Scan a skill before installing
clawshield skill-scan ./path/to/skill
clawshield skill-scan ~/.openclaw/skills/some-skill

# Start live monitoring
clawshield monitor
```

---

## Platform Support

| Platform | Scanner | Hardener | Monitor | Skill Scan |
|----------|:-------:|:--------:|:-------:|:----------:|
| Linux (Ubuntu/Debian) | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Linux (RHEL/Fedora) | ✅ Most | 🔶 Partial | ✅ Full | ✅ Full |
| macOS | ✅ Core | ✅ Core | 🔶 Basic | ✅ Full |
| Windows | 🔶 Basic | 🔶 Basic | 🔶 Basic | ✅ Full |

---

## Architecture

```
clawshield (single Go binary, ~3MB)
├── cmd/clawshield/     → CLI entry point
├── internal/
│   ├── scanner/        → Security audit engine
│   ├── hardener/       → System hardening actions
│   ├── monitor/        → Live security monitoring
│   └── skills/         → Skill static analysis (40+ patterns)
├── pkg/
│   ├── system/         → OS-level utilities
│   ├── network/        → Port/connection checks
│   └── process/        → Process monitoring
├── configs/            → Default security configs
└── dist/               → Cross-compiled binaries
```

**Zero dependencies.** Single binary. Works offline. No API keys needed.

---

## Roadmap

### v0.2 — Dashboard & Alerts
- [ ] Web dashboard (localhost) with live security status
- [ ] Telegram/Email alerts on critical events
- [ ] Scheduled scans via cron
- [ ] JSON/API output for integration

### v0.3 — Agent Behavior Analysis
- [ ] Track what the AI agent accesses (files, URLs, APIs)
- [ ] Anomaly detection (agent doing something unusual)
- [ ] Audit trail / compliance log
- [ ] Rate limiting for agent actions

### v0.4 — Network & Cloud
- [ ] Multi-host dashboard (manage fleet of servers)
- [ ] ClawHub integration (auto-scan before skill install)
- [ ] Threat intelligence feed (known malicious patterns)
- [ ] API for third-party integrations

### v1.0 — Production
- [ ] SaaS dashboard (clawshield.io)
- [ ] Team management
- [ ] Compliance reports (SOC2, GDPR)
- [ ] Enterprise features

---

## Tech Stack

- **Language:** Go 1.22+
- **Binary Size:** ~3MB per platform
- **Platforms:** Linux, macOS, Windows (amd64 + arm64)
- **Dependencies:** None (pure Go, no CGo)

---

## Contributing

Coming soon. For now, report issues and feature requests.

---

## License

TBD

---

**Built by [Volt ⚡](https://github.com/clawshield) — Security for the AI Agent era.**
