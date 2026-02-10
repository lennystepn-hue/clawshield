---
name: clawshield
description: "Security Layer for AI Agents — run security scans, auto-harden systems, monitor for threats, and audit skills for malicious code."
homepage: https://clawshield.io
metadata: {"clawdbot":{"emoji":"🛡️","requires":{"bins":["clawshield"]}}}
---

# ClawShield — Security Layer for AI Agents

One binary. Zero config. Scan, harden, and protect AI agent environments.

## PURPOSE

Protect AI agent systems by scanning for vulnerabilities, hardening configurations, monitoring for threats in real-time, and auditing installed skills for malicious code.

## WHEN TO USE

- TRIGGERS:
  - "Scan this system for security issues"
  - "Harden this server"
  - "Check if this skill is safe to install"
  - "Monitor for security threats"
  - "What's my security score?"
  - "Run a security audit"
  - "Is my system secure?"
  - "Fix all security issues"
  - "Scan skills for malware"
- DO NOT USE WHEN:
  - User asks about application-level security (use code review instead)
  - User needs network penetration testing (out of scope)

## COMMANDS

### Quick Security Score

```bash
clawshield status
```

Returns: score (0-100), grade (A+ to F), and summary of issues.

### Full Security Scan

```bash
clawshield scan
```

Runs 13 system checks across 5 categories:

| Category | Checks |
|----------|--------|
| **Network** | UFW firewall status, open/dangerous ports |
| **Access** | SSH root login, SSH password auth, Fail2Ban |
| **System** | Automatic updates, kernel version, disk usage |
| **Files** | /etc/shadow permissions, /tmp sticky bit |
| **Agent** | Workspace permissions, .env exposure, Docker socket |

Output: Color-coded terminal report with score, grade, and per-check details.

### Auto-Harden

```bash
# Interactive — asks before each fix
clawshield harden

# Non-interactive — fix everything automatically
clawshield harden --auto
```

Automatically fixes:
- Enables UFW firewall
- Disables SSH root login
- Installs and enables Fail2Ban
- Fixes file permissions (/etc/shadow, /tmp)
- Configures unattended upgrades

### Skill Scanner

```bash
# Scan a single skill directory
clawshield skill-scan /root/workspace/skills/some-skill

# Scan all installed skills
clawshield skill-scan /root/workspace/skills/*
```

Detects 40+ threat patterns including:
- Reverse shells and backdoors
- Cryptocurrency miners
- Data exfiltration (curl/wget to external IPs)
- Environment variable theft
- Persistence mechanisms (cron, systemd)
- Obfuscated/encoded payloads (base64, eval)
- Privilege escalation attempts
- File system tampering

### Live Monitor

```bash
clawshield monitor
```

Watches for real-time security events:
- File changes in sensitive directories
- New network connections
- Authentication attempts
- Process spawning
- Suspicious activity

Logs to `/var/log/clawshield/monitor.log`.

## WORKFLOW

### Routine Security Check
1. Run `clawshield scan` to assess current state
2. Review results — report findings to user
3. If issues found, suggest `clawshield harden --auto`
4. After hardening, run `clawshield scan` again to verify

### Before Installing a New Skill
1. Run `clawshield skill-scan <path-to-skill>` 
2. Review threat report
3. If threats found, warn user with details
4. Only proceed with install if clean or user explicitly approves

### Ongoing Monitoring
1. Start `clawshield monitor` in background
2. Check `/var/log/clawshield/monitor.log` periodically
3. Alert user on critical events

## OUTPUT FORMAT

### Scan Output
```
🛡️  ClawShield Security Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━

[Network]
  ✓ UFW Firewall — active
  ✗ Open Ports — 3 dangerous ports exposed

[Access]
  ✗ SSH Root Login — permitted
  ⚠ SSH Password Auth — enabled
  ✗ Fail2Ban — not active

Score: 62/100 (Grade: D)
```

### Skill Scan Output

The scanner checks for 40+ threat patterns including crypto miners,
data exfiltration, privilege escalation, and persistence mechanisms.
Output shows findings grouped by severity (CRITICAL, WARNING, CLEAN)
with file paths and line numbers. Safe skills show "SAFE" verdict.

## WEB DASHBOARD

ClawShield includes a web dashboard at `http://localhost:9090`:

- **Dashboard**: Real-time security score, check results, auto-fix button
- **Monitor**: Live event feed
- **Scan History**: Timeline of past scans
- **System Info**: Hostname, OS, uptime, IP

The dashboard runs as systemd service `clawshield-web.service`.

```bash
# Check dashboard status
systemctl status clawshield-web

# Restart dashboard
systemctl restart clawshield-web
```

## EXAMPLES

```bash
# Full audit workflow
clawshield scan
clawshield harden --auto
clawshield scan  # verify fixes

# Scan a skill before installing
clawshield skill-scan /root/workspace/skills/suspicious-skill

# Quick check
clawshield status

# Background monitoring
clawshield monitor &
```

## NOTES

- ClawShield requires root/sudo for hardening operations
- Scan is read-only and safe to run anytime
- Monitor writes to `/var/log/clawshield/monitor.log`
- Dashboard available at port 9090
- All checks are Linux-specific (Ubuntu/Debian focused)
