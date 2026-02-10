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

type HardenAction struct {
	Name        string
	Description string
	Risk        string // "low", "medium", "high"
	Command     func() error
}

func AutoHarden() {
	fmt.Println("🔒 Auto-hardening (low-risk fixes only)...\n")
	
	actions := getActions()
	applied := 0

	for _, action := range actions {
		if action.Risk == "low" {
			fmt.Printf("  🔧 %s... ", action.Name)
			if err := action.Command(); err != nil {
				fmt.Printf("❌ %s\n", err)
			} else {
				fmt.Printf("✅\n")
				applied++
			}
		}
	}

	fmt.Printf("\n✅ Applied %d automatic fixes\n", applied)
	fmt.Println("💡 Run 'clawshield harden' for interactive mode (medium/high-risk fixes)")
	fmt.Println("\n📊 Re-scanning...\n")

	report := scanner.RunFullScan()
	scanner.PrintScore(report)
}

func InteractiveHarden() {
	reader := bufio.NewReader(os.Stdin)
	actions := getActions()
	applied := 0

	for _, action := range actions {
		riskColor := "\033[32m" // green
		if action.Risk == "medium" {
			riskColor = "\033[33m" // yellow
		} else if action.Risk == "high" {
			riskColor = "\033[31m" // red
		}

		fmt.Printf("  %s[%s risk]%s %s\n", riskColor, action.Risk, "\033[0m", action.Name)
		fmt.Printf("  %s\n", action.Description)
		fmt.Print("  Apply? [y/N] ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "y" || input == "yes" {
			fmt.Printf("  🔧 Applying... ")
			if err := action.Command(); err != nil {
				fmt.Printf("❌ %s\n", err)
			} else {
				fmt.Printf("✅\n")
				applied++
			}
		} else {
			fmt.Println("  ⏭️  Skipped")
		}
		fmt.Println()
	}

	fmt.Printf("✅ Applied %d fixes\n", applied)
	fmt.Println("\n📊 Re-scanning...\n")

	report := scanner.RunFullScan()
	scanner.PrintScore(report)
}

func getActions() []HardenAction {
	if runtime.GOOS == "darwin" {
		return getDarwinActions()
	}
	return getLinuxActions()
}

func getLinuxActions() []HardenAction {
	return []HardenAction{
		{
			Name:        "Enable UFW Firewall",
			Description: "Activate the firewall with default deny incoming",
			Risk:        "low",
			Command: func() error {
				exec.Command("ufw", "--force", "enable").Run()
				exec.Command("ufw", "default", "deny", "incoming").Run()
				exec.Command("ufw", "default", "allow", "outgoing").Run()
				return exec.Command("ufw", "allow", "ssh").Run()
			},
		},
		{
			Name:        "Disable SSH Password Authentication",
			Description: "Only allow SSH key-based authentication (make sure you have keys set up!)",
			Risk:        "medium",
			Command: func() error {
				// Write config drop-in
				config := "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
				err := os.WriteFile("/etc/ssh/sshd_config.d/90-clawshield.conf", []byte(config), 0644)
				if err != nil {
					return err
				}
				return exec.Command("systemctl", "reload", "sshd").Run()
			},
		},
		{
			Name:        "Install & Enable Fail2Ban",
			Description: "Protect against brute-force SSH attacks",
			Risk:        "low",
			Command: func() error {
				exec.Command("apt-get", "install", "-y", "fail2ban").Run()
				// Create jail config
				jail := `[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
`
				os.MkdirAll("/etc/fail2ban/jail.d", 0755)
				os.WriteFile("/etc/fail2ban/jail.d/clawshield.conf", []byte(jail), 0644)
				return exec.Command("systemctl", "enable", "--now", "fail2ban").Run()
			},
		},
		{
			Name:        "Enable Unattended Security Updates",
			Description: "Automatically install critical security updates",
			Risk:        "low",
			Command: func() error {
				exec.Command("apt-get", "install", "-y", "unattended-upgrades").Run()
				config := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`
				return os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(config), 0644)
			},
		},
		{
			Name:        "Fix Config File Permissions",
			Description: "Set restrictive permissions on sensitive config files",
			Risk:        "low",
			Command: func() error {
				files := []string{
					"/root/.openclaw/config.yaml",
					"/root/.openclaw/config.yml",
					"/root/.config/openclaw/config.yaml",
					"/root/.env",
					"/root/workspace/.env",
				}
				for _, f := range files {
					if _, err := os.Stat(f); err == nil {
						os.Chmod(f, 0600)
					}
				}
				return nil
			},
		},
		{
			Name:        "Secure Docker Daemon",
			Description: "Disable Docker's iptables manipulation (prevents UFW bypass)",
			Risk:        "high",
			Command: func() error {
				config := `{
  "iptables": false,
  "ip6tables": false
}
`
				if err := os.WriteFile("/etc/docker/daemon.json", []byte(config), 0644); err != nil {
					return err
				}
				return exec.Command("systemctl", "restart", "docker").Run()
			},
		},
		{
			Name:        "Set SSH Idle Timeout",
			Description: "Disconnect idle SSH sessions after 15 minutes",
			Risk:        "low",
			Command: func() error {
				config := "ClientAliveInterval 300\nClientAliveCountMax 3\n"
				return os.WriteFile("/etc/ssh/sshd_config.d/91-clawshield-timeout.conf", []byte(config), 0644)
			},
		},
		{
			Name:        "Disable Root Login via Password",
			Description: "Allow root SSH only with key authentication",
			Risk:        "medium",
			Command: func() error {
				config := "PermitRootLogin prohibit-password\n"
				return os.WriteFile("/etc/ssh/sshd_config.d/92-clawshield-root.conf", []byte(config), 0644)
			},
		},
	}
}

func getDarwinActions() []HardenAction {
	return []HardenAction{
		{
			Name:        "Enable macOS Firewall",
			Description: "Activate the built-in application firewall",
			Risk:        "low",
			Command: func() error {
				return exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on").Run()
			},
		},
		{
			Name:        "Enable Stealth Mode",
			Description: "Don't respond to ping/port scan requests",
			Risk:        "low",
			Command: func() error {
				return exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on").Run()
			},
		},
	}
}
