package hardener

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/clawshield/clawshield/internal/scanner"
)

// richDescription holds the Problem/Fix/Risk text for display
type richDescription struct {
	Problem string
	Fix     string
	Risk    string
}

// descriptions maps check Name → rich description for interactive display
var descriptions = map[string]richDescription{
	"UFW Firewall": {
		Problem: "No firewall is active. All ports are exposed to the internet with no filtering.",
		Fix:     "Enables UFW with default deny incoming, allow outgoing, and allows SSH.",
		Risk:    "Existing connections won't be affected. SSH is explicitly allowed.",
	},
	"IPv6 Disabled": {
		Problem: "IPv6 is enabled but likely not used. It increases attack surface with a second network stack.",
		Fix:     "Disables IPv6 via sysctl (persistent across reboots).",
		Risk:    "None if you don't use IPv6. Some apps may complain if they expect IPv6 localhost (::1).",
	},
	"TLS Certificate Expiry": {
		Problem: "TLS certificates are expiring soon. Expired certs cause service outages and security warnings.",
		Fix:     "Runs certbot renew to refresh Let's Encrypt certificates.",
		Risk:    "Certbot may briefly restart your web server during renewal.",
	},
	"SSH Root Login": {
		Problem: "Root can log in directly via SSH with a password. This is the #1 target for brute-force attacks.",
		Fix:     "Sets PermitRootLogin to prohibit-password (key-only) in SSH config.",
		Risk:    "If you don't have SSH keys configured for root, you'll need to use a non-root user + sudo.",
	},
	"SSH Password Auth": {
		Problem: "Password authentication allows brute-force attacks. Bots try thousands of passwords per hour.",
		Fix:     "Sets PasswordAuthentication=no in SSH config. Only key-based login will work.",
		Risk:    "If you don't have SSH keys configured, you'll be locked out! Make sure your key is in ~/.ssh/authorized_keys first.",
	},
	"Fail2Ban": {
		Problem: "No brute-force protection. Attackers can try unlimited passwords against SSH.",
		Fix:     "Installs and enables Fail2Ban with default SSH jail (5 retries, 1h ban).",
		Risk:    "Legitimate users who mistype passwords 5 times get temporarily banned. Usually harmless.",
	},
	"SSH Authorized Keys": {
		Problem: "SSH authorized_keys file has loose permissions. Other users could inject their keys.",
		Fix:     "Sets permissions to 600 (owner read/write only).",
		Risk:    "None. This is the correct permission for authorized_keys.",
	},
	"Password Policy": {
		Problem: "No password complexity requirements. Users can set weak passwords like '123456'.",
		Fix:     "Installs pam_pwquality and enforces minimum 12-character passwords.",
		Risk:    "Existing passwords aren't affected. Only new password changes must meet the policy.",
	},
	"SSH Idle Timeout": {
		Problem: "SSH sessions stay open forever. An unattended terminal is a security risk.",
		Fix:     "Sets ClientAliveInterval=300 (5 min ping) with max 2 retries = 10 min timeout.",
		Risk:    "Long-running SSH commands won't be affected. Only idle sessions get disconnected.",
	},
	"Time Sync (NTP)": {
		Problem: "System clock is not synchronized. This can break TLS, logging, and cron timing.",
		Fix:     "Enables NTP time synchronization via timedatectl.",
		Risk:    "None. Time will gradually adjust (no sudden jumps).",
	},
	"AppArmor": {
		Problem: "AppArmor is not active. Processes run without mandatory access control restrictions.",
		Fix:     "Installs and enables AppArmor with default profiles.",
		Risk:    "Default profiles are permissive. Custom apps are unaffected unless you add profiles.",
	},
	"Pending Updates": {
		Problem: "Package updates are pending, potentially including security patches.",
		Fix:     "Runs apt-get update && apt-get upgrade -y to install all pending updates.",
		Risk:    "Services may restart during upgrade. Kernel updates need a reboot.",
	},
	"Open FD Limit": {
		Problem: "File descriptor limit is low. High-traffic services may run out of connections.",
		Fix:     "Sets soft/hard nofile limit to 65536 in /etc/security/limits.conf.",
		Risk:    "Requires re-login to take effect. No downside to higher limits.",
	},
	"Core Dumps": {
		Problem: "Core dumps write to disk and may contain sensitive data (passwords, keys in memory).",
		Fix:     "Redirects core dumps to /bin/false (effectively disabling them).",
		Risk:    "Debugging crashes becomes harder. Not an issue for production servers.",
	},
	"/etc/shadow Permissions": {
		Problem: "Password hash file is readable by non-root users. Hashes can be cracked offline.",
		Fix:     "Sets /etc/shadow to mode 600 (root-only read/write).",
		Risk:    "None. This is the correct permission.",
	},
	"/tmp Sticky Bit": {
		Problem: "Without sticky bit, any user can delete other users' files in /tmp.",
		Fix:     "Sets the sticky bit on /tmp (chmod +t).",
		Risk:    "None. This is the standard /tmp configuration.",
	},
	"Log Rotation": {
		Problem: "Log files can grow unbounded and fill the disk, causing service outages.",
		Fix:     "Installs logrotate and enables the timer for automatic log rotation.",
		Risk:    "None. Logrotate only compresses and rotates old logs.",
	},
	"Workspace Permissions": {
		Problem: "Agent workspace is world-readable. Other system users can read your files.",
		Fix:     "Sets workspace directory to mode 750 (owner + group only).",
		Risk:    "None if no other users need to read workspace files.",
	},
	"Docker Socket": {
		Problem: "Docker socket is world-accessible. Any user can run containers as root.",
		Fix:     "Restricts Docker socket to root:docker group (mode 660).",
		Risk:    "Non-docker-group users and some tools may lose Docker access. Verify your setup.",
	},
	"OpenClaw Config Perms": {
		Problem: "OpenClaw config file has loose permissions. May contain API keys readable by others.",
		Fix:     "Sets config file to mode 600 (owner read/write only).",
		Risk:    "None. This is the correct permission for config files with secrets.",
	},
	"Zombie Processes": {
		Problem: "Zombie processes waste PID slots and indicate parent processes not cleaning up children.",
		Fix:     "Sends SIGCHLD to parent processes, then SIGKILL if zombies persist.",
		Risk:    "Killing parent processes may restart services. Usually harmless.",
	},
	// macOS checks
	"macOS Firewall": {
		Problem: "The macOS Application Firewall is disabled. Incoming connections are not filtered.",
		Fix:     "Enables the built-in application firewall via socketfilterfw.",
		Risk:    "None. Allows all outgoing; only filters unsigned incoming connections.",
	},
	"Stealth Mode": {
		Problem: "Stealth mode is off. Your Mac responds to network probes (ping, port scans).",
		Fix:     "Enables stealth mode so the system ignores unsolicited probes.",
		Risk:    "None for normal use. Some network diagnostics may not work.",
	},
	"Gatekeeper": {
		Problem: "Gatekeeper is disabled. Unsigned/unnotarized apps can run without warning.",
		Fix:     "Re-enables Gatekeeper to block unsigned applications.",
		Risk:    "None. You can still right-click > Open to run unsigned apps when needed.",
	},
	"Remote Login (SSH)": {
		Problem: "Remote Login (SSH) is enabled. Anyone who knows your IP can attempt to connect.",
		Fix:     "Disables Remote Login via systemsetup.",
		Risk:    "You won't be able to SSH into this Mac remotely. Re-enable if needed.",
	},
	"FileVault Encryption": {
		Problem: "Disk encryption is off. Anyone with physical access can read your data.",
		Fix:     "Enable FileVault in System Settings > Privacy & Security. Requires restart.",
		Risk:    "Slight performance impact. Keep your recovery key safe!",
	},
	"macOS Updates": {
		Problem: "macOS software updates are available, potentially including security patches.",
		Fix:     "Installs all available updates via softwareupdate.",
		Risk:    "May require restart. Large updates can take significant time.",
	},
	// Windows checks
	"Windows Firewall": {
		Problem: "Windows Firewall is partially or fully disabled. Network traffic is unfiltered.",
		Fix:     "Enables all firewall profiles (Domain, Private, Public).",
		Risk:    "None for normal use. Some misconfigured apps may stop working.",
	},
	"Guest Account": {
		Problem: "The Guest account is enabled. Anyone can log in without credentials.",
		Fix:     "Disables the Guest account.",
		Risk:    "None. Guest accounts are a security liability.",
	},
	"UAC Enabled": {
		Problem: "User Account Control is disabled. All programs run with full admin privileges.",
		Fix:     "Enables UAC via registry. Requires restart to take effect.",
		Risk:    "Programs will prompt for elevation. This is normal and expected.",
	},
	"RDP Status": {
		Problem: "Remote Desktop is enabled. Attackers can attempt RDP brute-force attacks.",
		Fix:     "Disables Remote Desktop via registry.",
		Risk:    "You won't be able to RDP into this machine. Re-enable if needed.",
	},
	"Antivirus (Defender)": {
		Problem: "Windows Defender real-time protection is disabled. Malware can execute freely.",
		Fix:     "Re-enables real-time monitoring via PowerShell.",
		Risk:    "None. This is the standard protection every Windows machine should have.",
	},
}

func AutoHarden() {
	fmt.Println("🔒 ClawShield Auto-Hardening")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("📡 Scanning system first...")
	fmt.Println()

	report := scanner.RunFullScan()

	// Filter fixable issues
	var fixable []scanner.CheckResult
	for _, c := range report.Checks {
		if (c.Status == "warn" || c.Status == "fail") && c.FixCmd != "" && c.Risk == "low" {
			fixable = append(fixable, c)
		}
	}

	if len(fixable) == 0 {
		fmt.Println("  ✅ No low-risk fixes needed — system looks good!")
		fmt.Println()
		scanner.PrintScore(report)
		return
	}

	fmt.Printf("  Found %d low-risk issue(s) to fix automatically\n\n", len(fixable))

	applied := 0
	for _, c := range fixable {
		desc := getDescription(c)
		fmt.Printf("  🔧 %s\n", c.Name)
		fmt.Printf("     %s\n", desc.Problem)
		fmt.Printf("     Applying: %s\n", desc.Fix)

		if err := runFix(c.FixCmd); err != nil {
			fmt.Printf("     ❌ Failed: %s\n", err)
		} else {
			fmt.Printf("     ✅ Done\n")
			applied++
		}
		fmt.Println()
	}

	// Count skipped medium/high
	skipped := 0
	for _, c := range report.Checks {
		if (c.Status == "warn" || c.Status == "fail") && c.FixCmd != "" && c.Risk != "low" {
			skipped++
		}
	}

	fmt.Printf("✅ Applied %d/%d automatic fixes\n", applied, len(fixable))
	if skipped > 0 {
		fmt.Printf("💡 %d medium/high-risk fix(es) skipped — run 'clawshield harden' for interactive mode\n", skipped)
	}
	fmt.Println()
	fmt.Println("📊 Re-scanning...")
	fmt.Println()

	report2 := scanner.RunFullScan()
	scanner.PrintScore(report2)
}

func InteractiveHarden() {
	fmt.Println("🔒 ClawShield Interactive Hardening")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("📡 Scanning system first...")
	fmt.Println()

	report := scanner.RunFullScan()

	// Filter fixable issues
	var fixable []scanner.CheckResult
	for _, c := range report.Checks {
		if (c.Status == "warn" || c.Status == "fail") && c.FixCmd != "" {
			fixable = append(fixable, c)
		}
	}

	if len(fixable) == 0 {
		fmt.Println("  ✅ Nothing to fix — all checks pass or have no automated fix!")
		fmt.Println()
		scanner.PrintScore(report)
		return
	}

	fmt.Printf("  Found %d fixable issue(s)\n\n", len(fixable))

	reader := bufio.NewReader(os.Stdin)
	applied := 0

	for i, c := range fixable {
		desc := getDescription(c)

		// Status icon
		statusIcon := "⚠️"
		if c.Status == "fail" {
			statusIcon = "❌"
		}

		// Risk color
		riskColor := "\033[32m" // green
		riskLabel := "LOW"
		if c.Risk == "medium" {
			riskColor = "\033[33m" // yellow
			riskLabel = "MEDIUM"
		} else if c.Risk == "high" {
			riskColor = "\033[31m" // red
			riskLabel = "HIGH"
		}

		fmt.Printf("  ┌─ %s %s [%d/%d]\n", statusIcon, c.Name, i+1, len(fixable))
		fmt.Printf("  │  %sRisk: %s\033[0m\n", riskColor, riskLabel)
		fmt.Printf("  │\n")
		fmt.Printf("  │  \033[1mProblem:\033[0m %s\n", desc.Problem)
		fmt.Printf("  │  \033[1mFix:\033[0m     %s\n", desc.Fix)
		fmt.Printf("  │  \033[1mRisk:\033[0m    %s\n", desc.Risk)
		fmt.Printf("  │\n")
		fmt.Printf("  └─ Apply? [y/N] ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "y" || input == "yes" {
			fmt.Printf("     🔧 Applying... ")
			if err := runFix(c.FixCmd); err != nil {
				fmt.Printf("❌ %s\n", err)
			} else {
				fmt.Printf("✅\n")
				applied++
			}
		} else {
			fmt.Println("     ⏭️  Skipped")
		}
		fmt.Println()
	}

	fmt.Printf("✅ Applied %d/%d fixes\n", applied, len(fixable))
	fmt.Println()
	fmt.Println("📊 Re-scanning...")
	fmt.Println()

	report2 := scanner.RunFullScan()
	scanner.PrintScore(report2)
}

func runFix(cmd string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("sh", "-c", cmd).Run()
	}
	return exec.Command("bash", "-c", cmd).Run()
}

func getDescription(c scanner.CheckResult) richDescription {
	if desc, ok := descriptions[c.Name]; ok {
		return desc
	}
	// Fallback: generate from check data
	return richDescription{
		Problem: c.Detail,
		Fix:     c.Fix,
		Risk:    "Check documentation for potential side effects.",
	}
}
