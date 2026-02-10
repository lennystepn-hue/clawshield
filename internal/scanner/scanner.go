package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"strconv"
	"net"
)

type CheckResult struct {
	Name     string
	Category string
	Status   string // "pass", "warn", "fail", "info"
	Detail   string
	Fix      string
}

type ScanReport struct {
	OS      string
	Checks  []CheckResult
	Score   int
	Grade   string
}

func RunFullScan() ScanReport {
	report := ScanReport{
		OS: runtime.GOOS,
	}

	switch runtime.GOOS {
	case "linux":
		report.Checks = runLinuxChecks()
	case "darwin":
		report.Checks = runDarwinChecks()
	default:
		report.Checks = runGenericChecks()
	}

	report.Score, report.Grade = calculateScore(report.Checks)
	return report
}

func runLinuxChecks() []CheckResult {
	var checks []CheckResult

	// === FIREWALL ===
	checks = append(checks, checkFirewall())

	// === SSH ===
	checks = append(checks, checkSSHConfig()...)

	// === FAIL2BAN ===
	checks = append(checks, checkFail2Ban())

	// === RUNNING AS ROOT ===
	checks = append(checks, checkRootUser())

	// === OPEN PORTS ===
	checks = append(checks, checkOpenPorts()...)

	// === UNATTENDED UPGRADES ===
	checks = append(checks, checkUnattendedUpgrades())

	// === FILE PERMISSIONS ===
	checks = append(checks, checkFilePermissions()...)

	// === OPENCLAW SPECIFIC ===
	checks = append(checks, checkOpenClawSecurity()...)

	// === KERNEL ===
	checks = append(checks, checkKernel())

	// === DOCKER ===
	checks = append(checks, checkDocker()...)

	return checks
}

func checkFirewall() CheckResult {
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return CheckResult{
			Name:     "Firewall (UFW)",
			Category: "Network",
			Status:   "fail",
			Detail:   "UFW not installed or not accessible",
			Fix:      "apt install ufw && ufw enable",
		}
	}
	status := string(out)
	if strings.Contains(status, "Status: active") {
		// Count rules
		lines := strings.Split(status, "\n")
		ruleCount := 0
		for _, l := range lines {
			if strings.Contains(l, "ALLOW") || strings.Contains(l, "DENY") || strings.Contains(l, "REJECT") {
				ruleCount++
			}
		}
		return CheckResult{
			Name:     "Firewall (UFW)",
			Category: "Network",
			Status:   "pass",
			Detail:   fmt.Sprintf("Active with %d rules", ruleCount),
		}
	}
	return CheckResult{
		Name:     "Firewall (UFW)",
		Category: "Network",
		Status:   "fail",
		Detail:   "UFW installed but inactive",
		Fix:      "ufw enable",
	}
}

func checkSSHConfig() []CheckResult {
	var results []CheckResult

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		results = append(results, CheckResult{
			Name:     "SSH Configuration",
			Category: "Access",
			Status:   "info",
			Detail:   "Could not read sshd_config",
		})
		return results
	}
	config := string(data)

	// Also read config.d files
	configDFiles, _ := os.ReadDir("/etc/ssh/sshd_config.d")
	for _, f := range configDFiles {
		if strings.HasSuffix(f.Name(), ".conf") {
			d, err := os.ReadFile("/etc/ssh/sshd_config.d/" + f.Name())
			if err == nil {
				config += "\n" + string(d)
			}
		}
	}

	// Password Authentication
	if strings.Contains(config, "PasswordAuthentication no") {
		results = append(results, CheckResult{
			Name:     "SSH Password Auth",
			Category: "Access",
			Status:   "pass",
			Detail:   "Disabled (key-only)",
		})
	} else {
		results = append(results, CheckResult{
			Name:     "SSH Password Auth",
			Category: "Access",
			Status:   "fail",
			Detail:   "Password authentication is enabled",
			Fix:      "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
		})
	}

	// Root Login
	if strings.Contains(config, "PermitRootLogin prohibit-password") || strings.Contains(config, "PermitRootLogin no") {
		results = append(results, CheckResult{
			Name:     "SSH Root Login",
			Category: "Access",
			Status:   "pass",
			Detail:   "Root login restricted to key-only",
		})
	} else if strings.Contains(config, "PermitRootLogin yes") {
		results = append(results, CheckResult{
			Name:     "SSH Root Login",
			Category: "Access",
			Status:   "warn",
			Detail:   "Root login with password allowed",
			Fix:      "Set 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config",
		})
	} else {
		results = append(results, CheckResult{
			Name:     "SSH Root Login",
			Category: "Access",
			Status:   "pass",
			Detail:   "Using default (key-only with modern SSH)",
		})
	}

	// SSH Port
	defaultPort := true
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Port ") && !strings.HasPrefix(trimmed, "#") {
			port := strings.TrimPrefix(trimmed, "Port ")
			if strings.TrimSpace(port) != "22" {
				defaultPort = false
			}
		}
	}
	if defaultPort {
		results = append(results, CheckResult{
			Name:     "SSH Port",
			Category: "Access",
			Status:   "warn",
			Detail:   "Running on default port 22",
			Fix:      "Consider changing to a non-standard port",
		})
	} else {
		results = append(results, CheckResult{
			Name:     "SSH Port",
			Category: "Access",
			Status:   "pass",
			Detail:   "Running on non-standard port",
		})
	}

	return results
}

func checkFail2Ban() CheckResult {
	out, err := exec.Command("systemctl", "is-active", "fail2ban").Output()
	if err != nil || !strings.Contains(string(out), "active") {
		return CheckResult{
			Name:     "Fail2Ban",
			Category: "Access",
			Status:   "fail",
			Detail:   "Not running - brute force protection disabled",
			Fix:      "apt install fail2ban && systemctl enable --now fail2ban",
		}
	}

	// Count banned IPs
	banned := 0
	jailOut, err := exec.Command("fail2ban-client", "status", "sshd").Output()
	if err == nil {
		for _, line := range strings.Split(string(jailOut), "\n") {
			if strings.Contains(line, "Currently banned") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					n, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					banned = n
				}
			}
		}
	}

	return CheckResult{
		Name:     "Fail2Ban",
		Category: "Access",
		Status:   "pass",
		Detail:   fmt.Sprintf("Active (%d IPs currently banned)", banned),
	}
}

func checkRootUser() CheckResult {
	if os.Getuid() == 0 {
		return CheckResult{
			Name:     "Running as Root",
			Category: "Process",
			Status:   "warn",
			Detail:   "OpenClaw is running as root (required but high-risk)",
			Fix:      "ClawShield monitors root-level operations for anomalies",
		}
	}
	return CheckResult{
		Name:     "Running as Root",
		Category: "Process",
		Status:   "pass",
		Detail:   "Running as non-root user",
	}
}

func checkOpenPorts() []CheckResult {
	var results []CheckResult

	out, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		return results
	}

	dangerousPorts := map[string]string{
		"3306":  "MySQL",
		"5432":  "PostgreSQL",
		"6379":  "Redis",
		"27017": "MongoDB",
		"9200":  "Elasticsearch",
		"6333":  "Qdrant",
		"5984":  "CouchDB",
		"7474":  "Neo4j HTTP",
		"7687":  "Neo4j Bolt",
	}

	lines := strings.Split(string(out), "\n")
	exposedCount := 0

	for _, line := range lines {
		for port, name := range dangerousPorts {
			if strings.Contains(line, ":"+port) && (strings.Contains(line, "0.0.0.0:") || strings.Contains(line, "*:")) {
				// Check if it's actually listening on all interfaces
				if !strings.Contains(line, "127.0.0.1:"+port) {
					exposedCount++
					results = append(results, CheckResult{
						Name:     fmt.Sprintf("Exposed Port: %s (%s)", port, name),
						Category: "Network",
						Status:   "fail",
						Detail:   fmt.Sprintf("%s is accessible from the internet on port %s", name, port),
						Fix:      fmt.Sprintf("Bind %s to 127.0.0.1 or block port %s in firewall", name, port),
					})
				}
			}
		}
	}

	if exposedCount == 0 {
		results = append(results, CheckResult{
			Name:     "Database Ports",
			Category: "Network",
			Status:   "pass",
			Detail:   "No database ports exposed to the internet",
		})
	}

	// Check for any publicly listening services
	publicServices := 0
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0:") || strings.Contains(line, "*:") {
			if !strings.Contains(line, ":22 ") { // Skip SSH
				publicServices++
			}
		}
	}

	results = append(results, CheckResult{
		Name:     "Public Services",
		Category: "Network",
		Status:   "info",
		Detail:   fmt.Sprintf("%d services listening on all interfaces (excl. SSH)", publicServices),
	})

	return results
}

func checkUnattendedUpgrades() CheckResult {
	_, err := os.Stat("/etc/apt/apt.conf.d/20auto-upgrades")
	if err != nil {
		return CheckResult{
			Name:     "Automatic Security Updates",
			Category: "System",
			Status:   "warn",
			Detail:   "Unattended upgrades not configured",
			Fix:      "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
		}
	}

	data, _ := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
	if strings.Contains(string(data), `"1"`) {
		return CheckResult{
			Name:     "Automatic Security Updates",
			Category: "System",
			Status:   "pass",
			Detail:   "Enabled",
		}
	}

	return CheckResult{
		Name:     "Automatic Security Updates",
		Category: "System",
		Status:   "warn",
		Detail:   "Configured but may be disabled",
		Fix:      "dpkg-reconfigure -plow unattended-upgrades",
	}
}

func checkFilePermissions() []CheckResult {
	var results []CheckResult

	sensitiveFiles := map[string]os.FileMode{
		"/etc/shadow":                     0640,
		"/root/.ssh/authorized_keys":      0600,
	}

	// OpenClaw config files
	openclawConfigs := []string{
		"/root/.openclaw/config.yaml",
		"/root/.openclaw/config.yml",
		"/root/.config/openclaw/config.yaml",
	}

	for _, path := range openclawConfigs {
		if _, err := os.Stat(path); err == nil {
			sensitiveFiles[path] = 0600
		}
	}

	for path, maxPerm := range sensitiveFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		perm := info.Mode().Perm()
		if perm > maxPerm {
			results = append(results, CheckResult{
				Name:     fmt.Sprintf("File Permissions: %s", path),
				Category: "Files",
				Status:   "fail",
				Detail:   fmt.Sprintf("Permissions %o (should be %o or stricter)", perm, maxPerm),
				Fix:      fmt.Sprintf("chmod %o %s", maxPerm, path),
			})
		} else {
			results = append(results, CheckResult{
				Name:     fmt.Sprintf("File Permissions: %s", path),
				Category: "Files",
				Status:   "pass",
				Detail:   fmt.Sprintf("Permissions %o ✓", perm),
			})
		}
	}

	return results
}

func checkOpenClawSecurity() []CheckResult {
	var results []CheckResult

	// Check if OpenClaw is running
	out, _ := exec.Command("pgrep", "-f", "openclaw").Output()
	if len(out) > 0 {
		results = append(results, CheckResult{
			Name:     "OpenClaw Process",
			Category: "Agent",
			Status:   "info",
			Detail:   "OpenClaw is running",
		})
	}

	// Check for API keys in environment
	envVars := os.Environ()
	exposedKeys := 0
	for _, env := range envVars {
		lower := strings.ToLower(env)
		if (strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || 
			strings.Contains(lower, "secret") || strings.Contains(lower, "token")) &&
			strings.Contains(env, "=") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && len(parts[1]) > 0 {
				exposedKeys++
			}
		}
	}

	if exposedKeys > 0 {
		results = append(results, CheckResult{
			Name:     "API Keys in Environment",
			Category: "Agent",
			Status:   "warn",
			Detail:   fmt.Sprintf("%d API keys/secrets found in environment variables", exposedKeys),
			Fix:      "Consider using a secrets manager (1Password CLI, Vault, etc.)",
		})
	} else {
		results = append(results, CheckResult{
			Name:     "API Keys in Environment",
			Category: "Agent",
			Status:   "pass",
			Detail:   "No exposed API keys found",
		})
	}

	// Check .env files for world-readable permissions
	envFiles := []string{".env", "/root/.env", "/root/workspace/.env"}
	for _, f := range envFiles {
		info, err := os.Stat(f)
		if err == nil {
			perm := info.Mode().Perm()
			if perm > 0600 {
				results = append(results, CheckResult{
					Name:     fmt.Sprintf("Env File: %s", f),
					Category: "Agent",
					Status:   "fail",
					Detail:   fmt.Sprintf("World-readable (%o) — API keys may be exposed", perm),
					Fix:      fmt.Sprintf("chmod 600 %s", f),
				})
			}
		}
	}

	// Check Tailscale
	_, err := exec.Command("tailscale", "status").Output()
	if err == nil {
		results = append(results, CheckResult{
			Name:     "Tailscale VPN",
			Category: "Network",
			Status:   "pass",
			Detail:   "Active — private network available",
		})
	}

	// Check if services are bound to Tailscale only
	tsIP := getTailscaleIP()
	if tsIP != "" {
		results = append(results, CheckResult{
			Name:     "Tailscale IP",
			Category: "Network",
			Status:   "info",
			Detail:   tsIP,
		})
	}

	return results
}

func getTailscaleIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if strings.HasPrefix(i.Name, "tailscale") || i.Name == "tailscale0" {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

func checkKernel() CheckResult {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return CheckResult{
			Name:     "Kernel Version",
			Category: "System",
			Status:   "info",
			Detail:   "Could not determine kernel version",
		}
	}
	kernel := strings.TrimSpace(string(out))

	// Check for pending kernel updates
	pendingOut, _ := exec.Command("bash", "-c", "ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1").Output()
	pending := strings.TrimSpace(string(pendingOut))

	if pending != "" && !strings.Contains(pending, kernel) {
		return CheckResult{
			Name:     "Kernel Version",
			Category: "System",
			Status:   "warn",
			Detail:   fmt.Sprintf("Running %s (newer kernel available, reboot needed)", kernel),
			Fix:      "Schedule a reboot to apply kernel update",
		}
	}

	return CheckResult{
		Name:     "Kernel Version",
		Category: "System",
		Status:   "pass",
		Detail:   kernel,
	}
}

func checkDocker() []CheckResult {
	var results []CheckResult

	out, err := exec.Command("docker", "ps", "--format", "{{.Names}}:{{.Ports}}").Output()
	if err != nil {
		return results
	}

	containers := strings.TrimSpace(string(out))
	if containers == "" {
		return results
	}

	for _, line := range strings.Split(containers, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "0.0.0.0:") {
			parts := strings.SplitN(line, ":", 2)
			name := parts[0]
			results = append(results, CheckResult{
				Name:     fmt.Sprintf("Docker: %s", name),
				Category: "Network",
				Status:   "warn",
				Detail:   "Container has ports exposed on all interfaces (bypasses UFW!)",
				Fix:      "Bind to 127.0.0.1 or Tailscale IP instead of 0.0.0.0",
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Name:     "Docker Containers",
			Category: "Network",
			Status:   "pass",
			Detail:   "No containers with publicly exposed ports",
		})
	}

	return results
}

func runDarwinChecks() []CheckResult {
	var checks []CheckResult

	// macOS Firewall
	out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
	if err == nil {
		if strings.Contains(string(out), "enabled") {
			checks = append(checks, CheckResult{Name: "macOS Firewall", Category: "Network", Status: "pass", Detail: "Enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "macOS Firewall", Category: "Network", Status: "fail", Detail: "Disabled", Fix: "Enable in System Preferences > Security"})
		}
	}

	// FileVault
	fvOut, err := exec.Command("fdesetup", "status").Output()
	if err == nil {
		if strings.Contains(string(fvOut), "On") {
			checks = append(checks, CheckResult{Name: "FileVault Encryption", Category: "System", Status: "pass", Detail: "Enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "FileVault Encryption", Category: "System", Status: "fail", Detail: "Disk not encrypted", Fix: "Enable FileVault in System Preferences > Security"})
		}
	}

	// SIP
	sipOut, err := exec.Command("csrutil", "status").Output()
	if err == nil {
		if strings.Contains(string(sipOut), "enabled") {
			checks = append(checks, CheckResult{Name: "System Integrity Protection", Category: "System", Status: "pass", Detail: "Enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "System Integrity Protection", Category: "System", Status: "fail", Detail: "Disabled — system is vulnerable"})
		}
	}

	checks = append(checks, checkRootUser())

	return checks
}

func runGenericChecks() []CheckResult {
	return []CheckResult{
		{Name: "OS Support", Category: "System", Status: "info", Detail: fmt.Sprintf("Limited checks for %s", runtime.GOOS)},
		checkRootUser(),
	}
}

func calculateScore(checks []CheckResult) (int, string) {
	if len(checks) == 0 {
		return 0, "?"
	}

	total := 0
	scored := 0

	for _, c := range checks {
		switch c.Status {
		case "pass":
			total += 100
			scored++
		case "warn":
			total += 50
			scored++
		case "fail":
			total += 0
			scored++
		// "info" doesn't count
		}
	}

	if scored == 0 {
		return 0, "?"
	}

	score := total / scored

	var grade string
	switch {
	case score >= 90:
		grade = "A+"
	case score >= 80:
		grade = "A"
	case score >= 70:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 50:
		grade = "D"
	default:
		grade = "F"
	}

	return score, grade
}
