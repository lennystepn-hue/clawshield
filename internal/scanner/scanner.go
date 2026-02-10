package scanner

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type CheckResult struct {
	Name     string
	Category string
	Status   string // "pass", "warn", "fail"
	Detail   string
	Fix      string
	FixCmd   string // actual command(s) to run
	Risk     string // "low", "medium", "high"
}

type ScanReport struct {
	OS     string
	Checks []CheckResult
	Score  int
	Grade  string
}

func RunFullScan() ScanReport {
	report := ScanReport{OS: runtime.GOOS}
	switch runtime.GOOS {
	case "linux":
		report.Checks = runLinuxChecks()
	case "darwin":
		report.Checks = runDarwinChecks()
	case "windows":
		report.Checks = runWindowsChecks()
	default:
		report.Checks = runGenericChecks()
	}
	report.Score, report.Grade = calculateScore(report.Checks)
	return report
}

func run(cmd string) string {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// isTailscaleBind checks if a listening line is bound to a Tailscale IP (100.x.x.x)
func isTailscaleBind(line, port string) bool {
	idx := strings.Index(line, ":"+port)
	if idx < 0 {
		return false
	}
	prefix := strings.TrimSpace(line[:idx])
	parts := strings.Fields(prefix)
	if len(parts) == 0 {
		return false
	}
	ip := parts[len(parts)-1]
	return strings.HasPrefix(ip, "100.") && len(ip) >= 7
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func runLinuxChecks() []CheckResult {
	var checks []CheckResult

	// Read SSH config once
	sshConf := readFile("/etc/ssh/sshd_config")
	// Also read config.d files
	configDFiles, _ := os.ReadDir("/etc/ssh/sshd_config.d")
	for _, f := range configDFiles {
		if strings.HasSuffix(f.Name(), ".conf") {
			sshConf += "\n" + readFile("/etc/ssh/sshd_config.d/"+f.Name())
		}
	}

	// Check fail2ban status once (used by SSH Port check)
	f2bStatus := run("systemctl is-active fail2ban 2>/dev/null")
	f2bActive := f2bStatus == "active"

	// Read ss output once
	ssOut := run("ss -tlnp 2>/dev/null")
	ssLines := []string{}
	for _, l := range strings.Split(ssOut, "\n") {
		if strings.Contains(l, "LISTEN") {
			ssLines = append(ssLines, l)
		}
	}

	// ═══════════════════════════════════════
	// NETWORK (7)
	// ═══════════════════════════════════════

	// 1. UFW Firewall
	ufw := run("ufw status 2>/dev/null")
	if strings.Contains(ufw, "Status: active") {
		checks = append(checks, CheckResult{Name: "UFW Firewall", Category: "Network", Status: "pass", Detail: "UFW is active"})
	} else if strings.Contains(ufw, "Status: inactive") {
		checks = append(checks, CheckResult{Name: "UFW Firewall", Category: "Network", Status: "fail", Detail: "UFW is inactive", Fix: "ufw --force enable", FixCmd: "ufw --force enable && ufw default deny incoming && ufw default allow outgoing && ufw allow ssh", Risk: "low"})
	} else {
		checks = append(checks, CheckResult{Name: "UFW Firewall", Category: "Network", Status: "warn", Detail: "UFW not installed or inaccessible"})
	}

	// 2. Open Ports
	dangerousPortSet := map[int]bool{21: true, 23: true, 25: true, 3306: true, 5432: true, 6379: true, 27017: true}
	dangerousCount := 0
	for _, l := range ssLines {
		re := regexp.MustCompile(`:(\d+)\s`)
		m := re.FindStringSubmatch(l)
		if m != nil {
			p, _ := strconv.Atoi(m[1])
			if dangerousPortSet[p] {
				dangerousCount++
			}
		}
	}
	if dangerousCount == 0 {
		checks = append(checks, CheckResult{Name: "Open Ports", Category: "Network", Status: "pass", Detail: fmt.Sprintf("%d listening ports, no dangerous ones exposed", len(ssLines))})
	} else {
		checks = append(checks, CheckResult{Name: "Open Ports", Category: "Network", Status: "warn", Detail: fmt.Sprintf("%d potentially dangerous port(s) open", dangerousCount)})
	}

	// 3. IPv6 Disabled
	ipv6 := run("sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null")
	if ipv6 == "1" {
		checks = append(checks, CheckResult{Name: "IPv6 Disabled", Category: "Network", Status: "pass", Detail: "IPv6 is disabled"})
	} else if ipv6 == "0" {
		checks = append(checks, CheckResult{Name: "IPv6 Disabled", Category: "Network", Status: "warn", Detail: "IPv6 is enabled — disable if not needed", Fix: "sysctl -w net.ipv6.conf.all.disable_ipv6=1 && echo 'net.ipv6.conf.all.disable_ipv6=1' >> /etc/sysctl.conf", FixCmd: "sysctl -w net.ipv6.conf.all.disable_ipv6=1 && grep -q 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf || echo 'net.ipv6.conf.all.disable_ipv6=1' >> /etc/sysctl.conf", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "IPv6 Disabled", Category: "Network", Status: "warn", Detail: "Could not determine IPv6 status"})
	}

	// 4. DNS Configuration
	resolv := readFile("/etc/resolv.conf")
	if resolv != "" {
		nsCount := 0
		for _, l := range strings.Split(resolv, "\n") {
			if matched, _ := regexp.MatchString(`^\s*nameserver\s`, l); matched {
				nsCount++
			}
		}
		if nsCount > 0 {
			checks = append(checks, CheckResult{Name: "DNS Configuration", Category: "Network", Status: "pass", Detail: fmt.Sprintf("%d nameserver(s) configured", nsCount)})
		} else {
			checks = append(checks, CheckResult{Name: "DNS Configuration", Category: "Network", Status: "fail", Detail: "No nameservers in /etc/resolv.conf"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "DNS Configuration", Category: "Network", Status: "warn", Detail: "Cannot read /etc/resolv.conf"})
	}

	// 5. Binding Audit
	internalServices := []string{"mysqld", "postgres", "redis", "mongod", "memcached", "couchdb"}
	badBindings := 0
	for _, l := range ssLines {
		bindAll := strings.Contains(l, "0.0.0.0:") || strings.Contains(l, "*:")
		if bindAll {
			lower := strings.ToLower(l)
			for _, svc := range internalServices {
				if strings.Contains(lower, svc) {
					badBindings++
					break
				}
			}
		}
	}
	if badBindings == 0 {
		checks = append(checks, CheckResult{Name: "Binding Audit", Category: "Network", Status: "pass", Detail: "No internal services bound to all interfaces"})
	} else {
		checks = append(checks, CheckResult{Name: "Binding Audit", Category: "Network", Status: "warn", Detail: fmt.Sprintf("%d internal service(s) listening on 0.0.0.0", badBindings)})
	}

	// 6. TLS Certificate Expiry
	{
		certPaths := []string{"/etc/letsencrypt/live", "/etc/ssl/certs"}
		expiringSoon := 0
		certsChecked := 0
		for _, cp := range certPaths {
			certs := run(fmt.Sprintf("find %s -maxdepth 3 \\( -name '*.pem' -o -name '*.crt' \\) 2>/dev/null | head -10", cp))
			if certs == "" {
				continue
			}
			for _, cert := range strings.Split(certs, "\n") {
				if cert == "" {
					continue
				}
				endDate := run(fmt.Sprintf("openssl x509 -enddate -noout -in \"%s\" 2>/dev/null", cert))
				if endDate == "" {
					continue
				}
				certsChecked++
				dateStr := strings.TrimPrefix(endDate, "notAfter=")
				expiry, err := time.Parse("Jan  2 15:04:05 2006 MST", dateStr)
				if err != nil {
					expiry, err = time.Parse("Jan 2 15:04:05 2006 MST", dateStr)
				}
				if err == nil {
					daysLeft := int(time.Until(expiry).Hours() / 24)
					if daysLeft < 30 {
						expiringSoon++
					}
				}
			}
		}
		if expiringSoon > 0 {
			checks = append(checks, CheckResult{Name: "TLS Certificate Expiry", Category: "Network", Status: "warn", Detail: fmt.Sprintf("%d certificate(s) expiring within 30 days", expiringSoon), Fix: "certbot renew", FixCmd: "certbot renew --non-interactive", Risk: "low"})
		} else {
			checks = append(checks, CheckResult{Name: "TLS Certificate Expiry", Category: "Network", Status: "pass", Detail: fmt.Sprintf("%d certificate(s) checked, all OK", certsChecked)})
		}
	}

	// 7. Tailscale Status
	tsStatus := run("tailscale status 2>/dev/null | head -1")
	tsOnline := tsStatus != "" && !strings.Contains(strings.ToLower(tsStatus), "stopped")
	if tsOnline {
		checks = append(checks, CheckResult{Name: "Tailscale", Category: "Network", Status: "pass", Detail: "Tailscale is connected"})
	} else {
		checks = append(checks, CheckResult{Name: "Tailscale", Category: "Network", Status: "warn", Detail: "Tailscale is not running or not installed"})
	}

	// ═══════════════════════════════════════
	// ACCESS (11)
	// ═══════════════════════════════════════

	// 8. SSH Root Login
	if sshConf == "" {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "warn", Detail: "SSH config not readable"})
	} else if matched, _ := regexp.MatchString(`(?m)^\s*PermitRootLogin\s+yes`, sshConf); matched {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "fail", Detail: "Root login is permitted", Fix: "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd", FixCmd: "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && systemctl restart sshd", Risk: "medium"})
	} else if matched, _ := regexp.MatchString(`(?m)^\s*PermitRootLogin\s+prohibit-password`, sshConf); matched {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "warn", Detail: "Root login allowed with key only"})
	} else {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "pass", Detail: "Root login disabled"})
	}

	// 9. SSH Password Auth
	if sshConf == "" {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "warn", Detail: "SSH config not readable"})
	} else if matched, _ := regexp.MatchString(`(?m)^\s*PasswordAuthentication\s+yes`, sshConf); matched {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "warn", Detail: "Password authentication enabled", Fix: "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd", FixCmd: "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "pass", Detail: "Password auth disabled"})
	}

	// 10. Fail2Ban
	if f2bActive {
		checks = append(checks, CheckResult{Name: "Fail2Ban", Category: "Access", Status: "pass", Detail: "Fail2Ban is active"})
	} else {
		checks = append(checks, CheckResult{Name: "Fail2Ban", Category: "Access", Status: "fail", Detail: "Fail2Ban is not active", Fix: "apt-get install -y fail2ban && systemctl enable --now fail2ban", FixCmd: "dpkg -s fail2ban >/dev/null 2>&1 || apt-get install -y fail2ban && systemctl enable --now fail2ban", Risk: "low"})
	}

	// 11. SSH Port
	sshPort := 22
	if sshConf != "" {
		re := regexp.MustCompile(`(?m)^\s*Port\s+(\d+)`)
		if m := re.FindStringSubmatch(sshConf); m != nil {
			sshPort, _ = strconv.Atoi(m[1])
		}
	}
	if sshPort != 22 {
		checks = append(checks, CheckResult{Name: "SSH Port", Category: "Access", Status: "pass", Detail: fmt.Sprintf("SSH running on non-default port %d", sshPort)})
	} else if f2bActive {
		checks = append(checks, CheckResult{Name: "SSH Port", Category: "Access", Status: "pass", Detail: "SSH on port 22, protected by Fail2Ban"})
	} else {
		checks = append(checks, CheckResult{Name: "SSH Port", Category: "Access", Status: "warn", Detail: "SSH on default port 22 without Fail2Ban"})
	}

	// 12. SSH Authorized Keys
	akPath := "/root/.ssh/authorized_keys"
	if info, err := os.Stat(akPath); err == nil {
		mode := info.Mode().Perm()
		if mode <= 0o600 {
			checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Access", Status: "pass", Detail: fmt.Sprintf("authorized_keys exists with mode %o", mode)})
		} else {
			checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Access", Status: "warn", Detail: fmt.Sprintf("authorized_keys has loose permissions (%o)", mode), Fix: "chmod 600 /root/.ssh/authorized_keys", FixCmd: "chmod 600 /root/.ssh/authorized_keys", Risk: "low"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Access", Status: "warn", Detail: "No authorized_keys found for root"})
	}

	// 13. Recent Logins — only flag password-based logins
	authLog := run("grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -10")
	if authLog != "" {
		lines := strings.Split(authLog, "\n")
		pwLogins := 0
		keyLogins := 0
		for _, l := range lines {
			if strings.Contains(l, "Accepted password") {
				pwLogins++
			}
			if strings.Contains(l, "Accepted publickey") {
				keyLogins++
			}
		}
		if pwLogins > 0 {
			checks = append(checks, CheckResult{Name: "Recent Logins", Category: "Access", Status: "warn", Detail: fmt.Sprintf("%d password-based login(s) detected — consider key-only auth", pwLogins)})
		} else {
			checks = append(checks, CheckResult{Name: "Recent Logins", Category: "Access", Status: "pass", Detail: fmt.Sprintf("%d recent key-based login(s) — all secure", keyLogins)})
		}
	} else {
		checks = append(checks, CheckResult{Name: "Recent Logins", Category: "Access", Status: "pass", Detail: "No recent login entries found"})
	}

	// 14. Password Policy
	pamContent := readFile("/etc/pam.d/common-password")
	hasPolicy, _ := regexp.MatchString(`pam_pwquality|minlen\s*=\s*\d+|pam_cracklib`, pamContent)
	if hasPolicy {
		checks = append(checks, CheckResult{Name: "Password Policy", Category: "Access", Status: "pass", Detail: "PAM password policy configured"})
	} else {
		checks = append(checks, CheckResult{Name: "Password Policy", Category: "Access", Status: "warn", Detail: "No PAM password policy (pam_pwquality/minlen) found", Fix: "apt-get install -y libpam-pwquality && echo 'password requisite pam_pwquality.so retry=3 minlen=12' >> /etc/pam.d/common-password", FixCmd: "dpkg -s libpam-pwquality >/dev/null 2>&1 || apt-get install -y libpam-pwquality; grep -q pam_pwquality /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3 minlen=12' >> /etc/pam.d/common-password", Risk: "medium"})
	}

	// 15. Inactive Users
	{
		lastlogOut := run("lastlog 2>/dev/null | tail -n +2")
		systemUsers := map[string]bool{
			"daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true,
			"lp": true, "mail": true, "news": true, "uucp": true, "proxy": true, "www-data": true,
			"backup": true, "list": true, "irc": true, "gnats": true, "nobody": true,
			"systemd-network": true, "systemd-resolve": true, "messagebus": true, "syslog": true,
			"_apt": true, "tss": true, "uuidd": true, "systemd-timesync": true, "sshd": true,
			"pollinate": true, "landscape": true,
		}
		var inactiveUsers []string
		now := time.Now()
		for _, line := range strings.Split(lastlogOut, "\n") {
			if line == "" || strings.Contains(line, "**Never logged in**") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 4 {
				continue
			}
			username := parts[0]
			if systemUsers[username] {
				continue
			}
			// Try to parse date from remaining fields
			dateStr := strings.Join(parts[3:], " ")
			for _, layout := range []string{
				"Mon Jan  2 15:04:05 -0700 2006",
				"Mon Jan 2 15:04:05 -0700 2006",
				"Mon Jan  2 15:04:05 2006",
				"Mon Jan 2 15:04:05 2006",
			} {
				if t, err := time.Parse(layout, dateStr); err == nil {
					if now.Sub(t).Hours() > 90*24 {
						inactiveUsers = append(inactiveUsers, username)
					}
					break
				}
			}
		}
		if len(inactiveUsers) > 0 {
			detail := fmt.Sprintf("%d user(s) inactive 90+ days", len(inactiveUsers))
			if len(inactiveUsers) <= 3 {
				detail += ": " + strings.Join(inactiveUsers, ", ")
			} else {
				detail += ": " + strings.Join(inactiveUsers[:3], ", ")
			}
			checks = append(checks, CheckResult{Name: "Inactive Users", Category: "Access", Status: "warn", Detail: detail})
		} else {
			checks = append(checks, CheckResult{Name: "Inactive Users", Category: "Access", Status: "pass", Detail: "No inactive user accounts found"})
		}
	}

	// 16. UID Zero Accounts
	{
		uid0 := run("awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null")
		var uid0Users []string
		for _, u := range strings.Split(uid0, "\n") {
			if u != "" && u != "root" {
				uid0Users = append(uid0Users, u)
			}
		}
		if len(uid0Users) > 0 {
			checks = append(checks, CheckResult{Name: "UID Zero Accounts", Category: "Access", Status: "fail", Detail: "Non-root UID 0 accounts: " + strings.Join(uid0Users, ", ")})
		} else {
			checks = append(checks, CheckResult{Name: "UID Zero Accounts", Category: "Access", Status: "pass", Detail: "Only root has UID 0"})
		}
	}

	// 17. Empty Passwords
	{
		emptyPw := run(`awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null`)
		var emptyUsers []string
		for _, u := range strings.Split(emptyPw, "\n") {
			if u != "" {
				emptyUsers = append(emptyUsers, u)
			}
		}
		if len(emptyUsers) > 0 {
			detail := fmt.Sprintf("%d account(s) with empty passwords", len(emptyUsers))
			if len(emptyUsers) <= 3 {
				detail += ": " + strings.Join(emptyUsers, ", ")
			} else {
				detail += ": " + strings.Join(emptyUsers[:3], ", ")
			}
			checks = append(checks, CheckResult{Name: "Empty Passwords", Category: "Access", Status: "warn", Detail: detail})
		} else {
			checks = append(checks, CheckResult{Name: "Empty Passwords", Category: "Access", Status: "pass", Detail: "No accounts with empty passwords"})
		}
	}

	// 18. SSH Idle Timeout
	{
		re := regexp.MustCompile(`(?m)^\s*ClientAliveInterval\s+(\d+)`)
		m := re.FindStringSubmatch(sshConf)
		interval := 0
		if m != nil {
			interval, _ = strconv.Atoi(m[1])
		}
		timeoutOk := interval > 0 && interval <= 300
		if timeoutOk {
			checks = append(checks, CheckResult{Name: "SSH Idle Timeout", Category: "Access", Status: "pass", Detail: fmt.Sprintf("ClientAliveInterval set to %ds", interval)})
		} else {
			checks = append(checks, CheckResult{Name: "SSH Idle Timeout", Category: "Access", Status: "warn", Detail: "SSH ClientAliveInterval not set or too high", Fix: "echo 'ClientAliveInterval 300\nClientAliveCountMax 2' >> /etc/ssh/sshd_config && systemctl restart sshd", FixCmd: "grep -q ClientAliveInterval /etc/ssh/sshd_config && sed -i 's/^#\\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config; grep -q ClientAliveCountMax /etc/ssh/sshd_config && sed -i 's/^#\\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config; systemctl restart sshd", Risk: "medium"})
		}
	}

	// ═══════════════════════════════════════
	// SYSTEM (13)
	// ═══════════════════════════════════════

	// 19. Automatic Updates
	unattended := run("systemctl is-active unattended-upgrades 2>/dev/null")
	if unattended == "active" {
		checks = append(checks, CheckResult{Name: "Automatic Updates", Category: "System", Status: "pass", Detail: "Unattended upgrades active"})
	} else {
		checks = append(checks, CheckResult{Name: "Automatic Updates", Category: "System", Status: "warn", Detail: "Unattended upgrades not active"})
	}

	// 20. Kernel Version
	kernel := run("uname -r")
	checks = append(checks, CheckResult{Name: "Kernel Version", Category: "System", Status: "pass", Detail: fmt.Sprintf("Running %s", kernel)})

	// 21. Disk Usage
	df := run("df -h / | tail -1")
	diskPct := 0
	if re := regexp.MustCompile(`(\d+)%`); true {
		if m := re.FindStringSubmatch(df); m != nil {
			diskPct, _ = strconv.Atoi(m[1])
		}
	}
	diskStatus := "pass"
	if diskPct > 90 {
		diskStatus = "fail"
	} else if diskPct > 75 {
		diskStatus = "warn"
	}
	checks = append(checks, CheckResult{Name: "Disk Usage", Category: "System", Status: diskStatus, Detail: fmt.Sprintf("Root partition %d%% used", diskPct)})

	// 22. Swap Usage
	{
		freeOut := run("free -m 2>/dev/null")
		swapAdded := false
		for _, line := range strings.Split(freeOut, "\n") {
			if matched, _ := regexp.MatchString(`(?i)^Swap:`, line); matched {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					total, _ := strconv.Atoi(parts[1])
					used, _ := strconv.Atoi(parts[2])
					if total == 0 {
						checks = append(checks, CheckResult{Name: "Swap Usage", Category: "System", Status: "pass", Detail: "No swap configured"})
					} else {
						pct := (used * 100) / total
						st := "pass"
						if pct > 80 {
							st = "warn"
						}
						checks = append(checks, CheckResult{Name: "Swap Usage", Category: "System", Status: st, Detail: fmt.Sprintf("Swap %d%% used (%dMB / %dMB)", pct, used, total)})
					}
					swapAdded = true
				}
				break
			}
		}
		if !swapAdded {
			checks = append(checks, CheckResult{Name: "Swap Usage", Category: "System", Status: "pass", Detail: "Swap info not available"})
		}
	}

	// 23. RAM Usage
	{
		memInfo := run("free -b 2>/dev/null")
		memAdded := false
		for _, line := range strings.Split(memInfo, "\n") {
			if matched, _ := regexp.MatchString(`(?i)^Mem:`, line); matched {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					total, _ := strconv.ParseInt(parts[1], 10, 64)
					used, _ := strconv.ParseInt(parts[2], 10, 64)
					if total > 0 {
						pct := int((used * 100) / total)
						st := "pass"
						if pct > 85 {
							st = "warn"
						}
						checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: st, Detail: fmt.Sprintf("%d%% used (%dMB / %dMB)", pct, used/1024/1024, total/1024/1024)})
						memAdded = true
					}
				}
				break
			}
		}
		if !memAdded {
			checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: "pass", Detail: "Memory info not available"})
		}
	}

	// 24. CPU Load
	{
		loadAvg := run("cat /proc/loadavg 2>/dev/null")
		numCPU := runtime.NumCPU()
		load1m := 0.0
		if parts := strings.Fields(loadAvg); len(parts) > 0 {
			load1m, _ = strconv.ParseFloat(parts[0], 64)
		}
		st := "pass"
		if load1m > float64(numCPU) {
			st = "warn"
		}
		checks = append(checks, CheckResult{Name: "CPU Load", Category: "System", Status: st, Detail: fmt.Sprintf("Load avg %.2f (%d cores)", load1m, numCPU)})
	}

	// 25. Zombie Processes
	{
		zombies := run("ps aux 2>/dev/null | grep -c '[d]efunct'")
		zc, _ := strconv.Atoi(zombies)
		if zc > 0 {
			checks = append(checks, CheckResult{Name: "Zombie Processes", Category: "System", Status: "warn", Detail: fmt.Sprintf("%d zombie process(es) detected", zc)})
		} else {
			checks = append(checks, CheckResult{Name: "Zombie Processes", Category: "System", Status: "pass", Detail: "No zombie processes"})
		}
	}

	// 26. NTP Sync
	{
		timectl := run("timedatectl 2>/dev/null")
		synced, _ := regexp.MatchString(`(?i)(System clock synchronized|NTP synchronized):\s*yes`, timectl)
		if synced {
			checks = append(checks, CheckResult{Name: "Time Sync (NTP)", Category: "System", Status: "pass", Detail: "System clock is synchronized"})
		} else {
			checks = append(checks, CheckResult{Name: "Time Sync (NTP)", Category: "System", Status: "warn", Detail: "System clock not synchronized", Fix: "timedatectl set-ntp true", FixCmd: "timedatectl set-ntp true", Risk: "low"})
		}
	}

	// 27. AppArmor
	{
		aaStatus := run("systemctl is-active apparmor 2>/dev/null")
		if aaStatus != "active" {
			aaStatus = run("aa-status 2>/dev/null | head -1")
		}
		aaActive := aaStatus == "active" || strings.Contains(aaStatus, "profiles are loaded")
		if aaActive {
			checks = append(checks, CheckResult{Name: "AppArmor", Category: "System", Status: "pass", Detail: "AppArmor is active"})
		} else {
			checks = append(checks, CheckResult{Name: "AppArmor", Category: "System", Status: "warn", Detail: "AppArmor is not active or not installed", Fix: "apt-get install -y apparmor && systemctl enable --now apparmor", FixCmd: "dpkg -s apparmor >/dev/null 2>&1 || apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor", Risk: "low"})
		}
	}

	// 28. Pending Updates
	{
		updatesOut := run("apt list --upgradable 2>/dev/null | tail -n +2 | wc -l")
		pendingCount, _ := strconv.Atoi(updatesOut)
		st := "pass"
		if pendingCount > 20 {
			st = "fail"
		} else if pendingCount > 5 {
			st = "warn"
		}
		fix := ""
		fixCmd := ""
		if pendingCount > 0 {
			fix = "apt-get update && apt-get upgrade -y"
			fixCmd = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq"
		}
		checks = append(checks, CheckResult{Name: "Pending Updates", Category: "System", Status: st, Detail: fmt.Sprintf("%d package update(s) pending", pendingCount), Fix: fix, FixCmd: fixCmd, Risk: "low"})
	}

	// 29. Open FD Limit
	{
		fdLimit := run("ulimit -n 2>/dev/null")
		fdVal, _ := strconv.Atoi(fdLimit)
		if fdVal < 1024 {
			checks = append(checks, CheckResult{Name: "Open FD Limit", Category: "System", Status: "warn", Detail: fmt.Sprintf("File descriptor limit: %s", fdLimit), Fix: "echo '* soft nofile 65536\n* hard nofile 65536' >> /etc/security/limits.conf", FixCmd: "grep -q 'soft nofile 65536' /etc/security/limits.conf || echo '* soft nofile 65536\n* hard nofile 65536' >> /etc/security/limits.conf", Risk: "low"})
		} else {
			checks = append(checks, CheckResult{Name: "Open FD Limit", Category: "System", Status: "pass", Detail: fmt.Sprintf("File descriptor limit: %d", fdVal)})
		}
	}

	// 30. Core Dumps
	{
		corePattern := run("cat /proc/sys/kernel/core_pattern 2>/dev/null")
		coreSafe := strings.HasPrefix(corePattern, "|") || corePattern == "" || strings.Contains(corePattern, "/dev/null")
		if coreSafe {
			checks = append(checks, CheckResult{Name: "Core Dumps", Category: "System", Status: "pass", Detail: "Core dumps piped or disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Core Dumps", Category: "System", Status: "warn", Detail: fmt.Sprintf("Core dumps may write to disk: %s", corePattern), Fix: "echo '|/bin/false' > /proc/sys/kernel/core_pattern", FixCmd: "echo '|/bin/false' > /proc/sys/kernel/core_pattern && echo 'kernel.core_pattern=|/bin/false' >> /etc/sysctl.conf && sysctl -p", Risk: "low"})
		}
	}

	// 31. Secure Boot
	{
		sbState := run("mokutil --sb-state 2>/dev/null")
		sbEnabled := strings.Contains(strings.ToLower(sbState), "secureboot enabled")
		detail := "Secure Boot status unavailable (mokutil not found)"
		if sbState != "" {
			if sbEnabled {
				detail = "Secure Boot is enabled"
			} else {
				detail = "Secure Boot is disabled"
			}
		}
		checks = append(checks, CheckResult{Name: "Secure Boot", Category: "System", Status: "pass", Detail: detail})
	}

	// ═══════════════════════════════════════
	// FILES (10)
	// ═══════════════════════════════════════

	// 32. /etc/shadow Permissions
	if info, err := os.Stat("/etc/shadow"); err == nil {
		mode := info.Mode().Perm()
		worldGroup := mode & 0o077
		if worldGroup == 0 {
			checks = append(checks, CheckResult{Name: "/etc/shadow Permissions", Category: "Files", Status: "pass", Detail: fmt.Sprintf("Mode: %o", mode)})
		} else {
			checks = append(checks, CheckResult{Name: "/etc/shadow Permissions", Category: "Files", Status: "fail", Detail: fmt.Sprintf("Mode: %o", mode), Fix: "chmod 600 /etc/shadow", FixCmd: "chmod 600 /etc/shadow", Risk: "low"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "/etc/shadow Permissions", Category: "Files", Status: "warn", Detail: "Cannot stat /etc/shadow"})
	}

	// 33. /tmp Sticky Bit
	if info, err := os.Stat("/tmp"); err == nil {
		sticky := info.Mode()&os.ModeSticky != 0
		if sticky {
			checks = append(checks, CheckResult{Name: "/tmp Sticky Bit", Category: "Files", Status: "pass", Detail: "Sticky bit set"})
		} else {
			checks = append(checks, CheckResult{Name: "/tmp Sticky Bit", Category: "Files", Status: "fail", Detail: "Sticky bit not set", Fix: "chmod +t /tmp", FixCmd: "chmod +t /tmp", Risk: "low"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "/tmp Sticky Bit", Category: "Files", Status: "warn", Detail: "Cannot stat /tmp"})
	}

	// 34. SUID Binaries
	{
		expectedSuid := map[string]bool{
			"/usr/bin/passwd": true, "/usr/bin/sudo": true, "/usr/bin/su": true,
			"/usr/bin/newgrp": true, "/usr/bin/chsh": true, "/usr/bin/chfn": true,
			"/usr/bin/gpasswd": true, "/usr/bin/mount": true, "/usr/bin/umount": true,
			"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,
			"/usr/lib/openssh/ssh-keysign":                true,
			"/usr/bin/fusermount3": true, "/usr/bin/fusermount": true,
			"/usr/sbin/pppd": true, "/usr/bin/at": true,
			"/usr/lib/polkit-1/polkit-agent-helper-1": true,
			"/usr/lib/xorg/Xorg.wrap":                 true,
			"/usr/libexec/polkit-agent-helper-1":       true,
		}
		suidOut := run("find /usr -perm -4000 -type f 2>/dev/null")
		var suidFiles, unexpectedSuid []string
		for _, f := range strings.Split(suidOut, "\n") {
			if f == "" {
				continue
			}
			suidFiles = append(suidFiles, f)
			if !expectedSuid[f] {
				unexpectedSuid = append(unexpectedSuid, f)
			}
		}
		if len(unexpectedSuid) == 0 {
			checks = append(checks, CheckResult{Name: "SUID Binaries", Category: "Files", Status: "pass", Detail: fmt.Sprintf("%d SUID binaries, all expected", len(suidFiles))})
		} else {
			detail := fmt.Sprintf("%d unexpected SUID binary(ies)", len(unexpectedSuid))
			show := unexpectedSuid
			if len(show) > 3 {
				show = show[:3]
			}
			detail += ": " + strings.Join(show, ", ")
			if len(unexpectedSuid) > 3 {
				detail += "..."
			}
			checks = append(checks, CheckResult{Name: "SUID Binaries", Category: "Files", Status: "warn", Detail: detail})
		}
	}

	// 35. World-Writable Dirs
	{
		wwDirs := run("find / -maxdepth 3 -type d -perm -o+w ! -path '/tmp/*' ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null")
		var wwFiltered []string
		for _, d := range strings.Split(wwDirs, "\n") {
			if d != "" && d != "/tmp" && d != "/var/tmp" {
				wwFiltered = append(wwFiltered, d)
			}
		}
		if len(wwFiltered) == 0 {
			checks = append(checks, CheckResult{Name: "World-Writable Dirs", Category: "Files", Status: "pass", Detail: "No unexpected world-writable directories"})
		} else {
			detail := fmt.Sprintf("%d world-writable dir(s)", len(wwFiltered))
			show := wwFiltered
			if len(show) > 3 {
				show = show[:3]
			}
			detail += ": " + strings.Join(show, ", ")
			if len(wwFiltered) > 3 {
				detail += "..."
			}
			checks = append(checks, CheckResult{Name: "World-Writable Dirs", Category: "Files", Status: "warn", Detail: detail})
		}
	}

	// 36. Crontab Audit
	{
		cronEntries := run("crontab -l 2>/dev/null")
		cronDContent := run("cat /etc/cron.d/* 2>/dev/null")
		suspiciousRe := regexp.MustCompile(`(?i)curl|wget|nc\s|ncat|bash\s+-i|python.*-c|perl.*-e|reverse|backdoor`)
		hasSuspicious := suspiciousRe.MatchString(cronEntries) || suspiciousRe.MatchString(cronDContent)
		cronCount := 0
		for _, l := range strings.Split(cronEntries, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				cronCount++
			}
		}
		if hasSuspicious {
			checks = append(checks, CheckResult{Name: "Crontab Audit", Category: "Files", Status: "fail", Detail: "Suspicious patterns found in cron entries"})
		} else {
			checks = append(checks, CheckResult{Name: "Crontab Audit", Category: "Files", Status: "pass", Detail: fmt.Sprintf("%d cron entries, no suspicious patterns", cronCount)})
		}
	}

	// 37. Unowned Files
	{
		unowned := run("find / -maxdepth 3 \\( -nouser -o -nogroup \\) 2>/dev/null | head -5")
		var unownedList []string
		for _, f := range strings.Split(unowned, "\n") {
			if f != "" {
				unownedList = append(unownedList, f)
			}
		}
		if len(unownedList) > 0 {
			detail := fmt.Sprintf("%d file(s) without valid owner", len(unownedList))
			show := unownedList
			if len(show) > 3 {
				show = show[:3]
			}
			detail += ": " + strings.Join(show, ", ")
			checks = append(checks, CheckResult{Name: "Unowned Files", Category: "Files", Status: "warn", Detail: detail})
		} else {
			checks = append(checks, CheckResult{Name: "Unowned Files", Category: "Files", Status: "pass", Detail: "No unowned files found"})
		}
	}

	// 38. Large Files in /tmp
	{
		tmpLarge := run("find /tmp -maxdepth 2 -type f -size +100M 2>/dev/null | head -5")
		var tmpLargeList []string
		for _, f := range strings.Split(tmpLarge, "\n") {
			if f != "" {
				tmpLargeList = append(tmpLargeList, f)
			}
		}
		if len(tmpLargeList) > 0 {
			checks = append(checks, CheckResult{Name: "Large Files in /tmp", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d file(s) >100MB in /tmp (possible data staging)", len(tmpLargeList))})
		} else {
			checks = append(checks, CheckResult{Name: "Large Files in /tmp", Category: "Files", Status: "pass", Detail: "No large files in /tmp"})
		}
	}

	// 39. Log Rotation
	{
		logrotateActive := run("systemctl is-active logrotate.timer 2>/dev/null")
		logrotateConf := fileExists("/etc/logrotate.conf")
		lrOk := logrotateActive == "active" || logrotateConf
		if lrOk {
			checks = append(checks, CheckResult{Name: "Log Rotation", Category: "Files", Status: "pass", Detail: "Logrotate is configured"})
		} else {
			checks = append(checks, CheckResult{Name: "Log Rotation", Category: "Files", Status: "warn", Detail: "Logrotate not found or inactive", Fix: "apt-get install -y logrotate && systemctl enable --now logrotate.timer", FixCmd: "dpkg -s logrotate >/dev/null 2>&1 || apt-get install -y logrotate && systemctl enable --now logrotate.timer", Risk: "low"})
		}
	}

	// 40. Backup Tools
	{
		backupTools := []string{"borg", "restic", "duplicity", "rclone"}
		var found []string
		for _, t := range backupTools {
			if run("which "+t+" 2>/dev/null") != "" {
				found = append(found, t)
			}
		}
		if len(found) > 0 {
			checks = append(checks, CheckResult{Name: "Backup Tools", Category: "Files", Status: "pass", Detail: "Backup tool(s) installed: " + strings.Join(found, ", ")})
		} else {
			checks = append(checks, CheckResult{Name: "Backup Tools", Category: "Files", Status: "warn", Detail: "No backup tools found (borg, restic, duplicity, rclone)"})
		}
	}

	// 41. API Keys in Files
	{
		keyFiles := run("grep -rl 'sk-\\|ghp_\\|Bearer ' /root/workspace --include='*.json' --include='*.ts' --include='*.js' 2>/dev/null | head -5")
		var keyFileList []string
		for _, f := range strings.Split(keyFiles, "\n") {
			if f != "" {
				keyFileList = append(keyFileList, f)
			}
		}
		if len(keyFileList) > 0 {
			show := keyFileList
			if len(show) > 3 {
				show = show[:3]
			}
			displayNames := make([]string, len(show))
			for i, f := range show {
				displayNames[i] = strings.TrimPrefix(f, "/root/workspace/")
			}
			checks = append(checks, CheckResult{Name: "API Keys in Files", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d file(s) contain API keys/tokens: %s", len(keyFileList), strings.Join(displayNames, ", "))})
		} else {
			checks = append(checks, CheckResult{Name: "API Keys in Files", Category: "Files", Status: "pass", Detail: "No API keys found in workspace files"})
		}
	}

	// ═══════════════════════════════════════
	// AGENT (9)
	// ═══════════════════════════════════════

	// 42. Workspace Permissions
	if info, err := os.Stat("/root/workspace"); err == nil {
		worldRead := info.Mode().Perm() & 0o004
		if worldRead != 0 {
			checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "warn", Detail: "Workspace is world-readable", Fix: "chmod 750 /root/workspace", FixCmd: "chmod 750 /root/workspace", Risk: "low"})
		} else {
			checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "pass", Detail: "Workspace not world-readable"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "pass", Detail: "Workspace check OK"})
	}

	// 43. .env File Exposure
	{
		envFiles := run("find /root/workspace -name '.env' -type f 2>/dev/null")
		envCount := 0
		for _, f := range strings.Split(envFiles, "\n") {
			if f != "" {
				envCount++
			}
		}
		if envCount > 0 {
			checks = append(checks, CheckResult{Name: ".env File Exposure", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%d .env file(s) found in workspace", envCount)})
		} else {
			checks = append(checks, CheckResult{Name: ".env File Exposure", Category: "Agent", Status: "pass", Detail: "No .env files found"})
		}
	}

	// 44. Docker Socket
	if info, err := os.Stat("/var/run/docker.sock"); err == nil {
		_ = info
		dStat := run("stat -c '%a' /var/run/docker.sock 2>/dev/null")
		dPerms, _ := strconv.ParseInt(dStat, 8, 64)
		dWorldAccess := (dPerms & 0o006) != 0
		if dWorldAccess {
			checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "warn", Detail: "Docker socket is world-accessible", Fix: "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock", FixCmd: "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "pass", Detail: "Docker socket properly restricted"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "pass", Detail: "Docker socket not exposed"})
	}

	// 45. OpenClaw Config Perms
	{
		ocConfigPaths := []string{"/root/.config/openclaw/config.json", "/root/.openclaw.json", "/etc/openclaw/config.json", "/root/.openclaw/config.yaml", "/root/.openclaw/config.yml", "/root/.config/openclaw/config.yaml"}
		ocFound := false
		for _, p := range ocConfigPaths {
			if info, err := os.Stat(p); err == nil {
				mode := info.Mode().Perm()
				ocFound = true
				if mode <= 0o600 {
					checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%s mode %o", p, mode)})
				} else {
					checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%s has loose permissions (%o)", p, mode), Fix: fmt.Sprintf("chmod 600 %s", p), FixCmd: fmt.Sprintf("chmod 600 %s", p), Risk: "low"})
				}
				break
			}
		}
		if !ocFound {
			checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "pass", Detail: "No OpenClaw config file found at standard paths"})
		}
	}

	// 46. API Keys in Env
	{
		envVars := os.Environ()
		keyRe := regexp.MustCompile(`(?i)(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)`)
		var sensitiveKeys []string
		for _, env := range envVars {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && len(parts[1]) > 0 {
				if keyRe.MatchString(parts[0]) && parts[0] != "TERM" && parts[0] != "SHELL" {
					sensitiveKeys = append(sensitiveKeys, parts[0])
				}
			}
		}
		if len(sensitiveKeys) == 0 {
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "pass", Detail: "No API keys/secrets found in environment"})
		} else {
			show := sensitiveKeys
			if len(show) > 3 {
				show = show[:3]
			}
			detail := fmt.Sprintf("%d sensitive env var(s): %s", len(sensitiveKeys), strings.Join(show, ", "))
			if len(sensitiveKeys) > 3 {
				detail += "..."
			}
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "warn", Detail: detail})
		}
	}

	// 47. Skill Integrity
	{
		skillsDir := "/root/workspace/skills"
		entries, err := os.ReadDir(skillsDir)
		if err != nil {
			checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "Skills directory not found"})
		} else {
			var skills []string
			var unsigned []string
			for _, e := range entries {
				if e.IsDir() {
					skills = append(skills, e.Name())
					if !fileExists(filepath.Join(skillsDir, e.Name(), "SIGNATURE")) {
						unsigned = append(unsigned, e.Name())
					}
				}
			}
			if len(skills) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "No skills installed"})
			} else if len(unsigned) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%d skill(s) installed, all signed", len(skills))})
			} else {
				show := unsigned
				if len(show) > 3 {
					show = show[:3]
				}
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%d/%d skill(s) unsigned: %s", len(unsigned), len(skills), strings.Join(show, ", "))})
			}
		}
	}

	// 48. OpenClaw Version
	{
		ocVersion := run("openclaw --version 2>/dev/null")
		if ocVersion != "" {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("OpenClaw version: %s", ocVersion)})
		} else {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: "OpenClaw version not available"})
		}
	}

	// 49. Agent Memory Limit
	{
		cgroupLimit := run("cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null")
		hasLimit := cgroupLimit != "" && cgroupLimit != "max" && cgroupLimit != "9223372036854771712"
		if hasLimit {
			val, _ := strconv.ParseInt(cgroupLimit, 10, 64)
			checks = append(checks, CheckResult{Name: "Agent Memory Limit", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("Memory limit: %dMB", val/1024/1024)})
		} else {
			checks = append(checks, CheckResult{Name: "Agent Memory Limit", Category: "Agent", Status: "warn", Detail: "No memory limit set for agent processes"})
		}
	}

	// 50. Privileged Containers
	{
		containers := run("docker ps -q 2>/dev/null")
		if containers != "" {
			ids := strings.Split(containers, "\n")
			var privileged []string
			for i, id := range ids {
				if id == "" || i >= 10 {
					continue
				}
				inspect := run(fmt.Sprintf("docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' %s 2>/dev/null", id))
				if strings.Contains(inspect, "true") {
					name := strings.Split(inspect, " ")[0]
					name = strings.TrimPrefix(name, "/")
					privileged = append(privileged, name)
				}
			}
			if len(privileged) > 0 {
				checks = append(checks, CheckResult{Name: "Privileged Containers", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%d privileged container(s): %s", len(privileged), strings.Join(privileged, ", "))})
			} else {
				checks = append(checks, CheckResult{Name: "Privileged Containers", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%d container(s) running, none privileged", len(ids))})
			}
		} else {
			checks = append(checks, CheckResult{Name: "Privileged Containers", Category: "Agent", Status: "pass", Detail: "No Docker containers running"})
		}
	}

	return checks
}

func runDarwinChecks() []CheckResult {
	var checks []CheckResult

	// Read SSH config once
	sshConf := readFile("/etc/ssh/sshd_config")
	configDFiles, _ := os.ReadDir("/etc/ssh/sshd_config.d")
	for _, f := range configDFiles {
		if strings.HasSuffix(f.Name(), ".conf") {
			sshConf += "\n" + readFile("/etc/ssh/sshd_config.d/"+f.Name())
		}
	}

	// ═══════════════════════════════════════
	// NETWORK (2)
	// ═══════════════════════════════════════

	// 1. macOS Firewall
	fwOut := run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null")
	if strings.Contains(fwOut, "enabled") {
		checks = append(checks, CheckResult{Name: "macOS Firewall", Category: "Network", Status: "pass", Detail: "Application firewall is enabled"})
	} else {
		checks = append(checks, CheckResult{Name: "macOS Firewall", Category: "Network", Status: "fail", Detail: "Application firewall is disabled", Fix: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", FixCmd: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", Risk: "low"})
	}

	// 2. Stealth Mode
	stealthOut := run("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null")
	if strings.Contains(stealthOut, "enabled") {
		checks = append(checks, CheckResult{Name: "Stealth Mode", Category: "Network", Status: "pass", Detail: "Stealth mode is enabled"})
	} else {
		checks = append(checks, CheckResult{Name: "Stealth Mode", Category: "Network", Status: "warn", Detail: "Stealth mode is disabled — system responds to probes", Fix: "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on", FixCmd: "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on", Risk: "low"})
	}

	// 3. AirDrop Discovery Mode
	{
		airdrop := run("defaults read com.apple.sharingd DiscoverableMode 2>/dev/null")
		if airdrop == "Off" || airdrop == "Contacts Only" || airdrop == "ContactsOnly" {
			checks = append(checks, CheckResult{Name: "AirDrop Discovery", Category: "Network", Status: "pass", Detail: fmt.Sprintf("AirDrop set to: %s", airdrop)})
		} else if airdrop == "Everyone" {
			checks = append(checks, CheckResult{Name: "AirDrop Discovery", Category: "Network", Status: "warn", Detail: "AirDrop discoverable by Everyone", Fix: "Set AirDrop to Contacts Only in Finder > AirDrop", FixCmd: "defaults write com.apple.sharingd DiscoverableMode -string 'Contacts Only'", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "AirDrop Discovery", Category: "Network", Status: "pass", Detail: "AirDrop discovery mode not determinable (likely default)"})
		}
	}

	// 4. Bluetooth Discoverability
	{
		btDisc := run("defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null")
		if btDisc == "0" {
			checks = append(checks, CheckResult{Name: "Bluetooth", Category: "Network", Status: "pass", Detail: "Bluetooth is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Bluetooth", Category: "Network", Status: "warn", Detail: "Bluetooth is enabled — ensure discoverability is limited", Fix: "Disable Bluetooth if not needed", FixCmd: "defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0 && killall -HUP blued", Risk: "low"})
		}
	}

	// 5. Wi-Fi Auto-Join Open Networks
	{
		autoJoin := run("defaults read /Library/Preferences/com.apple.wifi.known-networks 2>/dev/null")
		// Check for auto-join on open (no security) networks
		if strings.Contains(autoJoin, "SecurityType = Open") || strings.Contains(autoJoin, "AutoLogin = 1") {
			checks = append(checks, CheckResult{Name: "Wi-Fi Auto-Join Open", Category: "Network", Status: "warn", Detail: "Auto-join for open Wi-Fi networks may be enabled", Fix: "Review Wi-Fi settings, remove open networks", FixCmd: "", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "Wi-Fi Auto-Join Open", Category: "Network", Status: "pass", Detail: "No open Wi-Fi auto-join detected"})
		}
	}

	// ═══════════════════════════════════════
	// ACCESS (11)
	// ═══════════════════════════════════════

	// 3. SSH Password Auth
	if sshConf == "" {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "warn", Detail: "SSH config not readable"})
	} else if matched, _ := regexp.MatchString(`(?m)^\s*PasswordAuthentication\s+yes`, sshConf); matched {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "warn", Detail: "Password authentication enabled", Fix: "Set PasswordAuthentication no in /etc/ssh/sshd_config", FixCmd: "sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null; true", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "SSH Password Auth", Category: "Access", Status: "pass", Detail: "Password auth disabled or defaulting to no"})
	}

	// 4. SSH Root Login
	if sshConf == "" {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "warn", Detail: "SSH config not readable"})
	} else if matched, _ := regexp.MatchString(`(?m)^\s*PermitRootLogin\s+yes`, sshConf); matched {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "fail", Detail: "Root login is permitted", Fix: "Set PermitRootLogin no in /etc/ssh/sshd_config", FixCmd: "sed -i '' 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null; true", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "SSH Root Login", Category: "Access", Status: "pass", Detail: "Root login disabled or restricted"})
	}

	// 5. Gatekeeper
	gkOut := run("spctl --status 2>/dev/null")
	if strings.Contains(gkOut, "assessments enabled") {
		checks = append(checks, CheckResult{Name: "Gatekeeper", Category: "Access", Status: "pass", Detail: "Gatekeeper is enabled"})
	} else {
		checks = append(checks, CheckResult{Name: "Gatekeeper", Category: "Access", Status: "fail", Detail: "Gatekeeper is disabled — unsigned apps can run freely", Fix: "sudo spctl --master-enable", FixCmd: "spctl --master-enable", Risk: "low"})
	}

	// Screen Lock
	screenLockDelay := run("defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null")
	askForPw := run("defaults read com.apple.screensaver askForPassword 2>/dev/null")
	if askForPw == "1" {
		checks = append(checks, CheckResult{Name: "Screen Lock", Category: "Access", Status: "pass", Detail: fmt.Sprintf("Screen lock requires password (idle: %ss)", screenLockDelay)})
	} else {
		checks = append(checks, CheckResult{Name: "Screen Lock", Category: "Access", Status: "warn", Detail: "Screen lock does not require password on wake"})
	}

	// Sudo NOPASSWD
	{
		sudoers := run("cat /etc/sudoers 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null")
		if strings.Contains(sudoers, "NOPASSWD") {
			checks = append(checks, CheckResult{Name: "Sudo NOPASSWD", Category: "Access", Status: "warn", Detail: "NOPASSWD entries found in sudoers", Fix: "Review /etc/sudoers and remove NOPASSWD entries", FixCmd: "visudo", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "Sudo NOPASSWD", Category: "Access", Status: "pass", Detail: "No NOPASSWD entries in sudoers"})
		}
	}

	// Login Window Config
	{
		loginWindow := run("defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null")
		if loginWindow == "1" {
			checks = append(checks, CheckResult{Name: "Login Window", Category: "Access", Status: "pass", Detail: "Login window shows name+password fields (not user list)"})
		} else {
			checks = append(checks, CheckResult{Name: "Login Window", Category: "Access", Status: "warn", Detail: "Login window shows user list — should show name+password", Fix: "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true", FixCmd: "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true", Risk: "low"})
		}
	}

	// Auto-Login Disabled
	{
		autoLogin := run("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null")
		if autoLogin == "" {
			checks = append(checks, CheckResult{Name: "Auto-Login", Category: "Access", Status: "pass", Detail: "Auto-login is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Auto-Login", Category: "Access", Status: "fail", Detail: fmt.Sprintf("Auto-login enabled for user: %s", autoLogin), Fix: "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser", FixCmd: "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser", Risk: "high"})
		}
	}

	// Require Password After Sleep
	{
		askPwDelay := run("defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null")
		if askForPw == "1" {
			delay, _ := strconv.Atoi(askPwDelay)
			if delay <= 5 {
				checks = append(checks, CheckResult{Name: "Password After Sleep", Category: "Access", Status: "pass", Detail: fmt.Sprintf("Password required within %ds of sleep", delay)})
			} else {
				checks = append(checks, CheckResult{Name: "Password After Sleep", Category: "Access", Status: "warn", Detail: fmt.Sprintf("Password delay after sleep: %ds (should be ≤5)", delay), Fix: "defaults write com.apple.screensaver askForPasswordDelay -int 0", FixCmd: "defaults write com.apple.screensaver askForPasswordDelay -int 0", Risk: "low"})
			}
		} else {
			checks = append(checks, CheckResult{Name: "Password After Sleep", Category: "Access", Status: "warn", Detail: "Password not required after sleep"})
		}
	}

	// Guest Account Disabled
	{
		guestEnabled := run("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
		if guestEnabled == "0" || guestEnabled == "" {
			checks = append(checks, CheckResult{Name: "Guest Account", Category: "Access", Status: "pass", Detail: "Guest account is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Guest Account", Category: "Access", Status: "fail", Detail: "Guest account is enabled", Fix: "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false", FixCmd: "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false", Risk: "medium"})
		}
	}

	// Remote Apple Events
	{
		rae := run("systemsetup -getremoteappleevents 2>/dev/null")
		if strings.Contains(strings.ToLower(rae), "off") {
			checks = append(checks, CheckResult{Name: "Remote Apple Events", Category: "Access", Status: "pass", Detail: "Remote Apple Events disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Remote Apple Events", Category: "Access", Status: "warn", Detail: "Remote Apple Events enabled", Fix: "sudo systemsetup -setremoteappleevents off", FixCmd: "systemsetup -setremoteappleevents off", Risk: "medium"})
		}
	}

	// Remote Management (ARD)
	{
		ard := run("ps aux 2>/dev/null | grep -c '[A]RDAgent'")
		ardCount, _ := strconv.Atoi(ard)
		if ardCount == 0 {
			checks = append(checks, CheckResult{Name: "Remote Management (ARD)", Category: "Access", Status: "pass", Detail: "ARD agent not running"})
		} else {
			checks = append(checks, CheckResult{Name: "Remote Management (ARD)", Category: "Access", Status: "warn", Detail: "Apple Remote Desktop agent is running", Fix: "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop", FixCmd: "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop", Risk: "medium"})
		}
	}

	// ═══════════════════════════════════════
	// SYSTEM (12)
	// ═══════════════════════════════════════

	// 7. FileVault Encryption
	fvOut := run("fdesetup status 2>/dev/null")
	if strings.Contains(fvOut, "On") {
		checks = append(checks, CheckResult{Name: "FileVault Encryption", Category: "System", Status: "pass", Detail: "FileVault is enabled"})
	} else {
		checks = append(checks, CheckResult{Name: "FileVault Encryption", Category: "System", Status: "fail", Detail: "Disk is not encrypted", Fix: "Enable FileVault in System Settings > Privacy & Security", FixCmd: "", Risk: "high"})
	}

	// 8. System Integrity Protection
	sipOut := run("csrutil status 2>/dev/null")
	if strings.Contains(sipOut, "enabled") {
		checks = append(checks, CheckResult{Name: "System Integrity Protection", Category: "System", Status: "pass", Detail: "SIP is enabled"})
	} else {
		checks = append(checks, CheckResult{Name: "System Integrity Protection", Category: "System", Status: "fail", Detail: "SIP is disabled — system is vulnerable"})
	}

	// 9. macOS Updates
	updOut := run("softwareupdate -l 2>&1")
	if strings.Contains(updOut, "No new software available") {
		checks = append(checks, CheckResult{Name: "macOS Updates", Category: "System", Status: "pass", Detail: "System is up to date"})
	} else if strings.Contains(updOut, "*") {
		lines := strings.Split(updOut, "\n")
		count := 0
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "*") {
				count++
			}
		}
		checks = append(checks, CheckResult{Name: "macOS Updates", Category: "System", Status: "warn", Detail: fmt.Sprintf("%d update(s) available", count), Fix: "softwareupdate -ia", FixCmd: "softwareupdate -ia --verbose", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "macOS Updates", Category: "System", Status: "pass", Detail: "No pending updates"})
	}

	// 10. Disk Usage
	df := run("df -h / | tail -1")
	diskPct := 0
	if re := regexp.MustCompile(`(\d+)%`); true {
		if m := re.FindStringSubmatch(df); m != nil {
			diskPct, _ = strconv.Atoi(m[1])
		}
	}
	diskStatus := "pass"
	if diskPct > 90 {
		diskStatus = "fail"
	} else if diskPct > 75 {
		diskStatus = "warn"
	}
	checks = append(checks, CheckResult{Name: "Disk Usage", Category: "System", Status: diskStatus, Detail: fmt.Sprintf("Root partition %d%% used", diskPct)})

	// 11. RAM Usage
	{
		// macOS: use vm_stat or sysctl
		memTotal := run("sysctl -n hw.memsize 2>/dev/null")
		pageSize := run("sysctl -n hw.pagesize 2>/dev/null")
		vmStat := run("vm_stat 2>/dev/null")
		total, _ := strconv.ParseInt(memTotal, 10, 64)
		pSize, _ := strconv.ParseInt(pageSize, 10, 64)
		if pSize == 0 {
			pSize = 4096
		}
		// Parse active + wired from vm_stat
		var active, wired int64
		for _, line := range strings.Split(vmStat, "\n") {
			if strings.Contains(line, "Pages active") {
				re := regexp.MustCompile(`(\d+)`)
				if m := re.FindString(line); m != "" {
					v, _ := strconv.ParseInt(m, 10, 64)
					active = v * pSize
				}
			}
			if strings.Contains(line, "Pages wired") {
				re := regexp.MustCompile(`(\d+)`)
				if m := re.FindString(line); m != "" {
					v, _ := strconv.ParseInt(m, 10, 64)
					wired = v * pSize
				}
			}
		}
		used := active + wired
		if total > 0 {
			pct := int((used * 100) / total)
			st := "pass"
			if pct > 85 {
				st = "warn"
			}
			checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: st, Detail: fmt.Sprintf("%d%% used (%dMB / %dMB)", pct, used/1024/1024, total/1024/1024)})
		} else {
			checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: "pass", Detail: "Memory info not available"})
		}
	}

	// 12. CPU Load
	{
		loadAvg := run("sysctl -n vm.loadavg 2>/dev/null")
		// Format: { 1.23 4.56 7.89 }
		loadAvg = strings.Trim(loadAvg, "{ }")
		numCPU := runtime.NumCPU()
		load1m := 0.0
		if parts := strings.Fields(loadAvg); len(parts) > 0 {
			load1m, _ = strconv.ParseFloat(parts[0], 64)
		}
		st := "pass"
		if load1m > float64(numCPU) {
			st = "warn"
		}
		checks = append(checks, CheckResult{Name: "CPU Load", Category: "System", Status: st, Detail: fmt.Sprintf("Load avg %.2f (%d cores)", load1m, numCPU)})
	}

	// 13. XProtect / MRT
	{
		xpVersion := run("system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A1 'XProtect' | tail -1")
		mrtExists := fileExists("/Library/Apple/System/Library/CoreServices/MRT.app") || fileExists("/System/Library/CoreServices/MRT.app")
		xpExists := fileExists("/Library/Apple/System/Library/CoreServices/XProtect.app") || fileExists("/System/Library/CoreServices/XProtect.bundle")
		if xpExists && mrtExists {
			detail := "XProtect and MRT present"
			if xpVersion != "" {
				detail += " (" + strings.TrimSpace(xpVersion) + ")"
			}
			checks = append(checks, CheckResult{Name: "XProtect / MRT", Category: "System", Status: "pass", Detail: detail})
		} else if xpExists {
			checks = append(checks, CheckResult{Name: "XProtect / MRT", Category: "System", Status: "warn", Detail: "XProtect found but MRT not detected"})
		} else {
			checks = append(checks, CheckResult{Name: "XProtect / MRT", Category: "System", Status: "warn", Detail: "XProtect/MRT not found — malware protection may be missing"})
		}
	}

	// Time Machine Backup
	{
		tmStatus := run("defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null")
		if tmStatus == "1" {
			checks = append(checks, CheckResult{Name: "Time Machine", Category: "System", Status: "pass", Detail: "Time Machine auto-backup is enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Time Machine", Category: "System", Status: "warn", Detail: "Time Machine auto-backup is not enabled", Fix: "Enable Time Machine in System Settings", FixCmd: "defaults write /Library/Preferences/com.apple.TimeMachine AutoBackup -bool true", Risk: "medium"})
		}
	}

	// Firmware Password / Apple Silicon
	{
		hwModel := run("sysctl -n hw.model 2>/dev/null")
		isAppleSilicon := strings.Contains(run("sysctl -n machdep.cpu.brand_string 2>/dev/null"), "Apple")
		if isAppleSilicon {
			checks = append(checks, CheckResult{Name: "Firmware Security", Category: "System", Status: "pass", Detail: fmt.Sprintf("Apple Silicon (%s) — firmware password N/A, Secure Enclave protects boot", hwModel)})
		} else {
			fwPw := run("firmwarepasswd -check 2>/dev/null")
			if strings.Contains(fwPw, "Yes") {
				checks = append(checks, CheckResult{Name: "Firmware Password", Category: "System", Status: "pass", Detail: "Firmware password is set"})
			} else {
				checks = append(checks, CheckResult{Name: "Firmware Password", Category: "System", Status: "warn", Detail: "Firmware password not set (Intel Mac)", Fix: "Set firmware password via Recovery Mode", FixCmd: "", Risk: "medium"})
			}
		}
	}

	// Automatic Update Check
	{
		autoCheck := run("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null")
		if autoCheck == "1" {
			checks = append(checks, CheckResult{Name: "Auto Update Check", Category: "System", Status: "pass", Detail: "Automatic update check is enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Auto Update Check", Category: "System", Status: "warn", Detail: "Automatic software update check is disabled", Fix: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true", FixCmd: "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true", Risk: "low"})
		}
	}

	// SIP Detailed Check
	{
		sipDetail := run("csrutil status 2>/dev/null")
		if strings.Contains(sipDetail, "enabled") && !strings.Contains(sipDetail, "Custom Configuration") {
			checks = append(checks, CheckResult{Name: "SIP Detailed", Category: "System", Status: "pass", Detail: "SIP fully enabled with default configuration"})
		} else if strings.Contains(sipDetail, "Custom Configuration") {
			checks = append(checks, CheckResult{Name: "SIP Detailed", Category: "System", Status: "warn", Detail: "SIP has custom configuration — some protections may be weakened"})
		} else {
			checks = append(checks, CheckResult{Name: "SIP Detailed", Category: "System", Status: "fail", Detail: "SIP is disabled or has unknown configuration"})
		}
	}

	// Homebrew Audit
	{
		brewPath := run("which brew 2>/dev/null")
		if brewPath != "" {
			outdated := run("brew outdated 2>/dev/null | wc -l")
			count, _ := strconv.Atoi(strings.TrimSpace(outdated))
			if count > 10 {
				checks = append(checks, CheckResult{Name: "Homebrew Audit", Category: "System", Status: "warn", Detail: fmt.Sprintf("%d outdated Homebrew packages", count), Fix: "brew upgrade", FixCmd: "brew upgrade", Risk: "low"})
			} else {
				checks = append(checks, CheckResult{Name: "Homebrew Audit", Category: "System", Status: "pass", Detail: fmt.Sprintf("%d outdated Homebrew packages", count)})
			}
		} else {
			checks = append(checks, CheckResult{Name: "Homebrew Audit", Category: "System", Status: "pass", Detail: "Homebrew not installed"})
		}
	}

	// ═══════════════════════════════════════
	// FILES (7)
	// ═══════════════════════════════════════

	// Library Validation
	{
		libVal := run("defaults read /Library/Preferences/com.apple.security.libraryvalidation Enabled 2>/dev/null")
		if libVal == "0" {
			checks = append(checks, CheckResult{Name: "Library Validation", Category: "Files", Status: "warn", Detail: "Library Validation is disabled", Fix: "defaults write /Library/Preferences/com.apple.security.libraryvalidation Enabled -bool true", FixCmd: "defaults write /Library/Preferences/com.apple.security.libraryvalidation Enabled -bool true", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "Library Validation", Category: "Files", Status: "pass", Detail: "Library Validation enabled (default)"})
		}
	}

	// Crontab Audit
	{
		cronEntries := run("crontab -l 2>/dev/null")
		suspiciousRe := regexp.MustCompile(`(?i)curl|wget|nc\s|ncat|bash\s+-i|python.*-c|perl.*-e|reverse|backdoor`)
		hasSuspicious := suspiciousRe.MatchString(cronEntries)
		cronCount := 0
		for _, l := range strings.Split(cronEntries, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				cronCount++
			}
		}
		if hasSuspicious {
			checks = append(checks, CheckResult{Name: "Crontab Audit", Category: "Files", Status: "fail", Detail: "Suspicious patterns found in cron entries"})
		} else {
			checks = append(checks, CheckResult{Name: "Crontab Audit", Category: "Files", Status: "pass", Detail: fmt.Sprintf("%d cron entries, no suspicious patterns", cronCount)})
		}
	}

	// SSH Authorized Keys Permissions
	{
		home := os.Getenv("HOME")
		akPath := home + "/.ssh/authorized_keys"
		if info, err := os.Stat(akPath); err == nil {
			mode := info.Mode().Perm()
			if mode <= 0o600 {
				checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Files", Status: "pass", Detail: fmt.Sprintf("authorized_keys mode %o", mode)})
			} else {
				checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Files", Status: "warn", Detail: fmt.Sprintf("authorized_keys has loose permissions (%o)", mode), Fix: fmt.Sprintf("chmod 600 %s", akPath), FixCmd: fmt.Sprintf("chmod 600 %s", akPath), Risk: "low"})
			}
		} else {
			checks = append(checks, CheckResult{Name: "SSH Authorized Keys", Category: "Files", Status: "pass", Detail: "No authorized_keys file found"})
		}
	}

	// Home Directory Permissions
	{
		home := os.Getenv("HOME")
		if info, err := os.Stat(home); err == nil {
			mode := info.Mode().Perm()
			worldRead := mode & 0o004
			if worldRead != 0 {
				checks = append(checks, CheckResult{Name: "Home Dir Permissions", Category: "Files", Status: "warn", Detail: fmt.Sprintf("Home directory is world-readable (%o)", mode), Fix: fmt.Sprintf("chmod 750 %s", home), FixCmd: fmt.Sprintf("chmod 750 %s", home), Risk: "low"})
			} else {
				checks = append(checks, CheckResult{Name: "Home Dir Permissions", Category: "Files", Status: "pass", Detail: fmt.Sprintf("Home directory mode %o", mode)})
			}
		} else {
			checks = append(checks, CheckResult{Name: "Home Dir Permissions", Category: "Files", Status: "pass", Detail: "Home directory check OK"})
		}
	}

	// World-Writable Dirs in /tmp
	{
		wwTmp := run("find /tmp -maxdepth 2 -type d -perm -o+w 2>/dev/null")
		var wwFiltered []string
		for _, d := range strings.Split(wwTmp, "\n") {
			if d != "" && d != "/tmp" {
				wwFiltered = append(wwFiltered, d)
			}
		}
		if len(wwFiltered) == 0 {
			checks = append(checks, CheckResult{Name: "World-Writable Dirs (/tmp)", Category: "Files", Status: "pass", Detail: "No unexpected world-writable dirs in /tmp"})
		} else {
			checks = append(checks, CheckResult{Name: "World-Writable Dirs (/tmp)", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d world-writable dir(s) in /tmp", len(wwFiltered))})
		}
	}

	// 15. .env File Exposure
	{
		home := os.Getenv("HOME")
		searchPaths := []string{home, home + "/workspace", "/root/workspace"}
		envCount := 0
		for _, sp := range searchPaths {
			envFiles := run(fmt.Sprintf("find %s -maxdepth 3 -name '.env' -type f 2>/dev/null", sp))
			for _, f := range strings.Split(envFiles, "\n") {
				if f != "" {
					envCount++
				}
			}
		}
		if envCount > 0 {
			checks = append(checks, CheckResult{Name: ".env File Exposure", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d .env file(s) found", envCount)})
		} else {
			checks = append(checks, CheckResult{Name: ".env File Exposure", Category: "Files", Status: "pass", Detail: "No .env files found"})
		}
	}

	// 16. Remote Login (SSH)
	{
		remoteLogin := run("systemsetup -getremotelogin 2>/dev/null")
		if strings.Contains(strings.ToLower(remoteLogin), "off") {
			checks = append(checks, CheckResult{Name: "Remote Login (SSH)", Category: "Access", Status: "pass", Detail: "Remote Login is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Remote Login (SSH)", Category: "Access", Status: "warn", Detail: "Remote Login (SSH) is enabled", Fix: "sudo systemsetup -setremotelogin off", FixCmd: "systemsetup -setremotelogin off", Risk: "medium"})
		}
	}

	// ═══════════════════════════════════════
	// AGENT (4)
	// ═══════════════════════════════════════

	// 17. API Keys in Env
	{
		envVars := os.Environ()
		keyRe := regexp.MustCompile(`(?i)(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)`)
		var sensitiveKeys []string
		for _, env := range envVars {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && len(parts[1]) > 0 {
				if keyRe.MatchString(parts[0]) && parts[0] != "TERM" && parts[0] != "SHELL" {
					sensitiveKeys = append(sensitiveKeys, parts[0])
				}
			}
		}
		if len(sensitiveKeys) == 0 {
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "pass", Detail: "No API keys/secrets found in environment"})
		} else {
			show := sensitiveKeys
			if len(show) > 3 {
				show = show[:3]
			}
			detail := fmt.Sprintf("%d sensitive env var(s): %s", len(sensitiveKeys), strings.Join(show, ", "))
			if len(sensitiveKeys) > 3 {
				detail += "..."
			}
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "warn", Detail: detail})
		}
	}

	// 18. Docker Socket
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		dStat := run("stat -f '%Lp' /var/run/docker.sock 2>/dev/null")
		dPerms, _ := strconv.ParseInt(dStat, 8, 64)
		dWorldAccess := (dPerms & 0o006) != 0
		if dWorldAccess {
			checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "warn", Detail: "Docker socket is world-accessible", Fix: "chmod 660 /var/run/docker.sock", FixCmd: "chmod 660 /var/run/docker.sock", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "pass", Detail: "Docker socket properly restricted"})
		}
	} else {
		checks = append(checks, CheckResult{Name: "Docker Socket", Category: "Agent", Status: "pass", Detail: "Docker socket not present"})
	}

	// 19. OpenClaw Config Perms
	{
		home := os.Getenv("HOME")
		ocConfigPaths := []string{home + "/.config/openclaw/config.json", home + "/.openclaw.json", "/etc/openclaw/config.json", home + "/.openclaw/config.yaml", home + "/.openclaw/config.yml", home + "/.config/openclaw/config.yaml"}
		ocFound := false
		for _, p := range ocConfigPaths {
			if info, err := os.Stat(p); err == nil {
				mode := info.Mode().Perm()
				ocFound = true
				if mode <= 0o600 {
					checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%s mode %o", p, mode)})
				} else {
					checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%s has loose permissions (%o)", p, mode), Fix: fmt.Sprintf("chmod 600 %s", p), FixCmd: fmt.Sprintf("chmod 600 %s", p), Risk: "low"})
				}
				break
			}
		}
		if !ocFound {
			checks = append(checks, CheckResult{Name: "OpenClaw Config Perms", Category: "Agent", Status: "pass", Detail: "No OpenClaw config file found"})
		}
	}

	// Workspace Permissions
	{
		home := os.Getenv("HOME")
		wsPaths := []string{home + "/workspace", "/root/workspace"}
		for _, ws := range wsPaths {
			if info, err := os.Stat(ws); err == nil {
				worldRead := info.Mode().Perm() & 0o004
				if worldRead != 0 {
					checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "warn", Detail: "Workspace is world-readable", Fix: fmt.Sprintf("chmod 750 %s", ws), FixCmd: fmt.Sprintf("chmod 750 %s", ws), Risk: "low"})
				} else {
					checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "pass", Detail: "Workspace not world-readable"})
				}
				break
			}
		}
	}

	// Skill Integrity
	{
		home := os.Getenv("HOME")
		skillsDirs := []string{home + "/workspace/skills", "/root/workspace/skills"}
		checked := false
		for _, skillsDir := range skillsDirs {
			entries, err := os.ReadDir(skillsDir)
			if err != nil {
				continue
			}
			checked = true
			var skills []string
			var unsigned []string
			for _, e := range entries {
				if e.IsDir() {
					skills = append(skills, e.Name())
					if !fileExists(filepath.Join(skillsDir, e.Name(), "SIGNATURE")) {
						unsigned = append(unsigned, e.Name())
					}
				}
			}
			if len(skills) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "No skills installed"})
			} else if len(unsigned) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%d skill(s) installed, all signed", len(skills))})
			} else {
				show := unsigned
				if len(show) > 3 {
					show = show[:3]
				}
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%d/%d skill(s) unsigned: %s", len(unsigned), len(skills), strings.Join(show, ", "))})
			}
			break
		}
		if !checked {
			checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "Skills directory not found"})
		}
	}

	// OpenClaw Version
	{
		ocVersion := run("openclaw --version 2>/dev/null")
		if ocVersion != "" {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("OpenClaw version: %s", ocVersion)})
		} else {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: "OpenClaw version not available"})
		}
	}

	return checks
}

func runWindowsChecks() []CheckResult {
	var checks []CheckResult

	// Helper to run powershell commands
	ps := func(cmd string) string {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}

	// Helper to run cmd commands
	cmd := func(c string) string {
		out, err := exec.Command("cmd", "/C", c).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}

	// ═══════════════════════════════════════
	// NETWORK (2)
	// ═══════════════════════════════════════

	// 1. Windows Firewall
	fwOut := ps("Get-NetFirewallProfile | Select-Object -Property Name,Enabled | Format-List")
	if fwOut == "" {
		fwOut = cmd("netsh advfirewall show allprofiles state")
	}
	allEnabled := true
	if strings.Contains(strings.ToLower(fwOut), "off") || strings.Contains(strings.ToLower(fwOut), "false") {
		allEnabled = false
	}
	if allEnabled && fwOut != "" {
		checks = append(checks, CheckResult{Name: "Windows Firewall", Category: "Network", Status: "pass", Detail: "All firewall profiles enabled"})
	} else if fwOut == "" {
		checks = append(checks, CheckResult{Name: "Windows Firewall", Category: "Network", Status: "warn", Detail: "Could not determine firewall status"})
	} else {
		checks = append(checks, CheckResult{Name: "Windows Firewall", Category: "Network", Status: "fail", Detail: "One or more firewall profiles disabled", Fix: "netsh advfirewall set allprofiles state on", FixCmd: "netsh advfirewall set allprofiles state on", Risk: "low"})
	}

	// 2. Open Ports
	netstatOut := cmd("netstat -an")
	dangerousPortSet := map[int]bool{21: true, 23: true, 25: true, 3306: true, 5432: true, 6379: true, 27017: true}
	dangerousCount := 0
	listenCount := 0
	for _, l := range strings.Split(netstatOut, "\n") {
		if strings.Contains(l, "LISTENING") {
			listenCount++
			re := regexp.MustCompile(`:(\d+)\s`)
			m := re.FindStringSubmatch(l)
			if m != nil {
				p, _ := strconv.Atoi(m[1])
				if dangerousPortSet[p] {
					dangerousCount++
				}
			}
		}
	}
	if dangerousCount == 0 {
		checks = append(checks, CheckResult{Name: "Open Ports", Category: "Network", Status: "pass", Detail: fmt.Sprintf("%d listening ports, no dangerous ones exposed", listenCount)})
	} else {
		checks = append(checks, CheckResult{Name: "Open Ports", Category: "Network", Status: "warn", Detail: fmt.Sprintf("%d potentially dangerous port(s) open", dangerousCount)})
	}

	// SMB v1 Disabled
	{
		smbOut := ps("Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol")
		if strings.ToLower(smbOut) == "false" {
			checks = append(checks, CheckResult{Name: "SMB v1 Disabled", Category: "Network", Status: "pass", Detail: "SMB v1 is disabled"})
		} else if strings.ToLower(smbOut) == "true" {
			checks = append(checks, CheckResult{Name: "SMB v1 Disabled", Category: "Network", Status: "fail", Detail: "SMB v1 is enabled — vulnerable to EternalBlue", Fix: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol", FixCmd: "powershell -Command \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "SMB v1 Disabled", Category: "Network", Status: "pass", Detail: "Could not determine SMB v1 status"})
		}
	}

	// NetBIOS over TCP/IP
	{
		nbOut := ps("Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Select-Object -ExpandProperty TcpipNetbiosOptions")
		if strings.Contains(nbOut, "2") {
			checks = append(checks, CheckResult{Name: "NetBIOS over TCP/IP", Category: "Network", Status: "pass", Detail: "NetBIOS over TCP/IP is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "NetBIOS over TCP/IP", Category: "Network", Status: "warn", Detail: "NetBIOS over TCP/IP may be enabled", Fix: "Disable NetBIOS in network adapter advanced settings", FixCmd: "", Risk: "medium"})
		}
	}

	// Network Discovery
	{
		ndOut := ps("Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq 'True'} | Measure-Object | Select-Object -ExpandProperty Count")
		ndCount, _ := strconv.Atoi(ndOut)
		if ndCount == 0 {
			checks = append(checks, CheckResult{Name: "Network Discovery", Category: "Network", Status: "pass", Detail: "Network Discovery is disabled"})
		} else {
			checks = append(checks, CheckResult{Name: "Network Discovery", Category: "Network", Status: "warn", Detail: fmt.Sprintf("Network Discovery has %d enabled rules", ndCount), Fix: "Disable Network Discovery in Network and Sharing Center", FixCmd: "powershell -Command \"Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Enabled False\"", Risk: "low"})
		}
	}

	// Remote Desktop NLA
	{
		nlaOut := ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication")
		rdpEnabled := ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
		if rdpEnabled == "1" {
			checks = append(checks, CheckResult{Name: "RDP NLA", Category: "Network", Status: "pass", Detail: "RDP disabled — NLA check not applicable"})
		} else if nlaOut == "1" {
			checks = append(checks, CheckResult{Name: "RDP NLA", Category: "Network", Status: "pass", Detail: "Network Level Authentication enabled for RDP"})
		} else {
			checks = append(checks, CheckResult{Name: "RDP NLA", Category: "Network", Status: "warn", Detail: "NLA not enabled for RDP", Fix: "Enable NLA in System Properties > Remote", FixCmd: "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f", Risk: "medium"})
		}
	}

	// ═══════════════════════════════════════
	// ACCESS (12)
	// ═══════════════════════════════════════

	// 3. Password Policy
	netAccounts := cmd("net accounts")
	minLen := 0
	for _, l := range strings.Split(netAccounts, "\n") {
		if strings.Contains(l, "Minimum password length") {
			re := regexp.MustCompile(`(\d+)`)
			if m := re.FindString(l); m != "" {
				minLen, _ = strconv.Atoi(m)
			}
		}
	}
	if minLen >= 8 {
		checks = append(checks, CheckResult{Name: "Password Policy", Category: "Access", Status: "pass", Detail: fmt.Sprintf("Minimum password length: %d", minLen)})
	} else {
		checks = append(checks, CheckResult{Name: "Password Policy", Category: "Access", Status: "warn", Detail: fmt.Sprintf("Minimum password length: %d (recommend 8+)", minLen), Fix: "net accounts /minpwlen:8", FixCmd: "net accounts /minpwlen:8", Risk: "low"})
	}

	// 4. Guest Account
	guestOut := cmd("net user guest")
	guestActive := strings.Contains(strings.ToLower(guestOut), "account active               yes")
	if guestActive {
		checks = append(checks, CheckResult{Name: "Guest Account", Category: "Access", Status: "fail", Detail: "Guest account is enabled", Fix: "net user guest /active:no", FixCmd: "net user guest /active:no", Risk: "low"})
	} else {
		checks = append(checks, CheckResult{Name: "Guest Account", Category: "Access", Status: "pass", Detail: "Guest account is disabled"})
	}

	// 5. UAC Enabled
	uacOut := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
	if uacOut == "1" {
		checks = append(checks, CheckResult{Name: "UAC Enabled", Category: "Access", Status: "pass", Detail: "User Account Control is enabled"})
	} else if uacOut == "0" {
		checks = append(checks, CheckResult{Name: "UAC Enabled", Category: "Access", Status: "fail", Detail: "UAC is disabled — all programs run with full privileges", Fix: "Enable UAC in Control Panel > User Accounts", FixCmd: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "UAC Enabled", Category: "Access", Status: "warn", Detail: "Could not determine UAC status"})
	}

	// RDP Status
	rdpOut := ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
	if rdpOut == "1" {
		checks = append(checks, CheckResult{Name: "RDP Status", Category: "Access", Status: "pass", Detail: "Remote Desktop is disabled"})
	} else if rdpOut == "0" {
		checks = append(checks, CheckResult{Name: "RDP Status", Category: "Access", Status: "warn", Detail: "Remote Desktop is enabled", Fix: "Disable RDP if not needed", FixCmd: "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f", Risk: "medium"})
	} else {
		checks = append(checks, CheckResult{Name: "RDP Status", Category: "Access", Status: "pass", Detail: "RDP status could not be determined (likely disabled)"})
	}

	// Account Lockout Policy
	{
		netAcc := cmd("net accounts")
		lockoutThreshold := 0
		for _, l := range strings.Split(netAcc, "\n") {
			if strings.Contains(l, "Lockout threshold") {
				re := regexp.MustCompile(`(\d+)`)
				if m := re.FindString(l); m != "" {
					lockoutThreshold, _ = strconv.Atoi(m)
				}
			}
		}
		if lockoutThreshold > 0 && lockoutThreshold <= 10 {
			checks = append(checks, CheckResult{Name: "Account Lockout", Category: "Access", Status: "pass", Detail: fmt.Sprintf("Account lockout after %d failed attempts", lockoutThreshold)})
		} else {
			checks = append(checks, CheckResult{Name: "Account Lockout", Category: "Access", Status: "warn", Detail: "Account lockout not configured or threshold too high", Fix: "net accounts /lockoutthreshold:5", FixCmd: "net accounts /lockoutthreshold:5", Risk: "medium"})
		}
	}

	// Admin Shares
	{
		shares := cmd("net share")
		hasAdminShares := strings.Contains(shares, "C$") || strings.Contains(shares, "ADMIN$")
		if !hasAdminShares {
			checks = append(checks, CheckResult{Name: "Admin Shares", Category: "Access", Status: "pass", Detail: "Default admin shares not detected"})
		} else {
			checks = append(checks, CheckResult{Name: "Admin Shares", Category: "Access", Status: "warn", Detail: "Default admin shares (C$, ADMIN$) are enabled", Fix: "Disable via registry AutoShareWks=0", FixCmd: "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareWks /t REG_DWORD /d 0 /f", Risk: "medium"})
		}
	}

	// Auto-Logon
	{
		autoLogon := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon")
		if autoLogon == "1" {
			checks = append(checks, CheckResult{Name: "Auto-Logon", Category: "Access", Status: "fail", Detail: "Auto-logon is enabled", Fix: "Disable auto-logon in registry", FixCmd: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v AutoAdminLogon /t REG_SZ /d 0 /f", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "Auto-Logon", Category: "Access", Status: "pass", Detail: "Auto-logon is disabled"})
		}
	}

	// Screen Lock Timeout
	{
		screenTimeout := ps("(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaveTimeOut")
		screenActive := ps("(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaveActive")
		screenSecure := ps("(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction SilentlyContinue).ScreenSaverIsSecure")
		if screenActive == "1" && screenSecure == "1" {
			checks = append(checks, CheckResult{Name: "Screen Lock", Category: "Access", Status: "pass", Detail: fmt.Sprintf("Screen saver with password, timeout: %ss", screenTimeout)})
		} else {
			checks = append(checks, CheckResult{Name: "Screen Lock", Category: "Access", Status: "warn", Detail: "Screen saver lock not properly configured", Fix: "Enable screen saver with password in Settings > Personalization", FixCmd: "", Risk: "low"})
		}
	}

	// Number of Local Admins
	{
		admins := ps("(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Measure-Object).Count")
		adminCount, _ := strconv.Atoi(admins)
		if adminCount <= 2 {
			checks = append(checks, CheckResult{Name: "Local Admins", Category: "Access", Status: "pass", Detail: fmt.Sprintf("%d local administrator(s)", adminCount)})
		} else {
			checks = append(checks, CheckResult{Name: "Local Admins", Category: "Access", Status: "warn", Detail: fmt.Sprintf("%d local administrators — consider reducing", adminCount), Risk: "medium"})
		}
	}

	// Audit Policy
	{
		auditOut := cmd("auditpol /get /category:* 2>nul")
		noAudit := strings.Count(auditOut, "No Auditing")
		totalLines := 0
		for _, l := range strings.Split(auditOut, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "System") && !strings.HasPrefix(l, "Category") {
				totalLines++
			}
		}
		if totalLines > 0 && noAudit > totalLines/2 {
			checks = append(checks, CheckResult{Name: "Audit Policy", Category: "Access", Status: "warn", Detail: fmt.Sprintf("%d/%d audit categories set to No Auditing", noAudit, totalLines), Fix: "Configure audit policy via Group Policy or auditpol", FixCmd: "auditpol /set /category:* /success:enable /failure:enable", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "Audit Policy", Category: "Access", Status: "pass", Detail: "Audit policy is reasonably configured"})
		}
	}

	// PowerShell Execution Policy
	{
		execPol := ps("Get-ExecutionPolicy")
		if execPol == "Restricted" || execPol == "AllSigned" {
			checks = append(checks, CheckResult{Name: "PS Execution Policy", Category: "Access", Status: "pass", Detail: fmt.Sprintf("PowerShell execution policy: %s", execPol)})
		} else {
			checks = append(checks, CheckResult{Name: "PS Execution Policy", Category: "Access", Status: "warn", Detail: fmt.Sprintf("PowerShell execution policy: %s", execPol), Fix: "Set-ExecutionPolicy AllSigned", FixCmd: "powershell -Command \"Set-ExecutionPolicy AllSigned -Force\"", Risk: "medium"})
		}
	}

	// PowerShell Script Block Logging
	{
		sbl := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging")
		if sbl == "1" {
			checks = append(checks, CheckResult{Name: "PS Script Block Logging", Category: "Access", Status: "pass", Detail: "PowerShell Script Block Logging is enabled"})
		} else {
			checks = append(checks, CheckResult{Name: "PS Script Block Logging", Category: "Access", Status: "warn", Detail: "PowerShell Script Block Logging is not enabled", Fix: "Enable via Group Policy or registry", FixCmd: "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f", Risk: "low"})
		}
	}

	// ═══════════════════════════════════════
	// SYSTEM (10)
	// ═══════════════════════════════════════

	// 7. Windows Updates
	wuOut := ps("(New-Object -ComObject Microsoft.Update.AutoUpdate).Results | Select-Object -ExpandProperty LastInstallationSuccessDate")
	if wuOut != "" {
		checks = append(checks, CheckResult{Name: "Windows Updates", Category: "System", Status: "pass", Detail: "Last update: " + wuOut})
	} else {
		checks = append(checks, CheckResult{Name: "Windows Updates", Category: "System", Status: "warn", Detail: "Could not determine Windows Update status"})
	}

	// 8. Disk Usage
	diskOut := ps("(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100")
	diskPct := 0
	if diskOut != "" {
		val, _ := strconv.ParseFloat(strings.TrimSpace(diskOut), 64)
		diskPct = int(val)
	}
	diskStatus := "pass"
	if diskPct > 90 {
		diskStatus = "fail"
	} else if diskPct > 75 {
		diskStatus = "warn"
	}
	checks = append(checks, CheckResult{Name: "Disk Usage", Category: "System", Status: diskStatus, Detail: fmt.Sprintf("C: drive %d%% used", diskPct)})

	// 9. RAM Usage
	{
		totalMem := ps("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)")
		freeMem := ps("[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)")
		total, _ := strconv.Atoi(totalMem)
		free, _ := strconv.Atoi(freeMem)
		if total > 0 {
			used := total - free
			pct := (used * 100) / total
			st := "pass"
			if pct > 85 {
				st = "warn"
			}
			checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: st, Detail: fmt.Sprintf("%d%% used (%dMB / %dMB)", pct, used, total)})
		} else {
			checks = append(checks, CheckResult{Name: "RAM Usage", Category: "System", Status: "pass", Detail: "Memory info not available"})
		}
	}

	// 10. Antivirus Status
	avOut := ps("Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
	if avOut == "True" {
		checks = append(checks, CheckResult{Name: "Antivirus (Defender)", Category: "System", Status: "pass", Detail: "Windows Defender real-time protection is enabled"})
	} else if avOut == "False" {
		checks = append(checks, CheckResult{Name: "Antivirus (Defender)", Category: "System", Status: "fail", Detail: "Windows Defender real-time protection is disabled", Fix: "Enable in Windows Security > Virus & threat protection", FixCmd: "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $false", Risk: "low"})
	} else {
		checks = append(checks, CheckResult{Name: "Antivirus (Defender)", Category: "System", Status: "warn", Detail: "Could not determine antivirus status"})
	}

	// Secure Boot
	{
		sbOut := ps("try { Confirm-SecureBootUEFI } catch { 'Unknown' }")
		if strings.ToLower(sbOut) == "true" {
			checks = append(checks, CheckResult{Name: "Secure Boot", Category: "System", Status: "pass", Detail: "Secure Boot is enabled"})
		} else if strings.ToLower(sbOut) == "false" {
			checks = append(checks, CheckResult{Name: "Secure Boot", Category: "System", Status: "warn", Detail: "Secure Boot is disabled", Fix: "Enable Secure Boot in UEFI/BIOS settings", FixCmd: "", Risk: "medium"})
		} else {
			checks = append(checks, CheckResult{Name: "Secure Boot", Category: "System", Status: "pass", Detail: "Secure Boot status not determinable"})
		}
	}

	// BitLocker
	{
		blOut := ps("(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue).ProtectionStatus")
		if blOut == "On" || blOut == "1" {
			checks = append(checks, CheckResult{Name: "BitLocker", Category: "System", Status: "pass", Detail: "BitLocker is enabled on C:"})
		} else if blOut == "Off" || blOut == "0" {
			checks = append(checks, CheckResult{Name: "BitLocker", Category: "System", Status: "fail", Detail: "BitLocker is not enabled on C:", Fix: "Enable BitLocker in Control Panel", FixCmd: "manage-bde -on C:", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "BitLocker", Category: "System", Status: "warn", Detail: "Could not determine BitLocker status"})
		}
	}

	// Last Reboot Time
	{
		lastBoot := ps("[Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)")
		if lastBoot != "" {
			checks = append(checks, CheckResult{Name: "Last Reboot", Category: "System", Status: "pass", Detail: fmt.Sprintf("Last boot: %s", lastBoot)})
		} else {
			checks = append(checks, CheckResult{Name: "Last Reboot", Category: "System", Status: "pass", Detail: "Could not determine last reboot time"})
		}
	}

	// Pending Reboot
	{
		pendingReboot := ps("Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'")
		pendingWU := ps("Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'")
		if pendingReboot == "True" || pendingWU == "True" {
			checks = append(checks, CheckResult{Name: "Pending Reboot", Category: "System", Status: "warn", Detail: "System has a pending reboot", Fix: "Restart the computer", FixCmd: "", Risk: "low"})
		} else {
			checks = append(checks, CheckResult{Name: "Pending Reboot", Category: "System", Status: "pass", Detail: "No pending reboot"})
		}
	}

	// Windows Version/Build (EOL check)
	{
		winVer := ps("[System.Environment]::OSVersion.Version.ToString()")
		buildNum := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion")
		detail := fmt.Sprintf("Windows %s (build %s)", buildNum, winVer)
		// Basic EOL check: builds older than 21H2 are EOL
		if strings.HasPrefix(buildNum, "1") && !strings.HasPrefix(buildNum, "10") {
			checks = append(checks, CheckResult{Name: "Windows Version", Category: "System", Status: "warn", Detail: detail + " — may be end of life", Risk: "high"})
		} else {
			checks = append(checks, CheckResult{Name: "Windows Version", Category: "System", Status: "pass", Detail: detail})
		}
	}

	// Exploit Protection
	{
		epOut := ps("(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).DEP.Enable")
		if strings.ToLower(epOut) == "true" || epOut == "ON" {
			checks = append(checks, CheckResult{Name: "Exploit Protection (DEP)", Category: "System", Status: "pass", Detail: "DEP is enabled system-wide"})
		} else {
			checks = append(checks, CheckResult{Name: "Exploit Protection (DEP)", Category: "System", Status: "warn", Detail: "DEP may not be fully enabled", Fix: "Enable DEP in Windows Security > App & browser control", FixCmd: "powershell -Command \"Set-ProcessMitigation -System -Enable DEP\"", Risk: "medium"})
		}
	}

	// ═══════════════════════════════════════
	// FILES (3)
	// ═══════════════════════════════════════

	// World-Writable Dirs in Temp
	{
		tempDir := os.Getenv("TEMP")
		if tempDir == "" {
			tempDir = "C:\\Windows\\Temp"
		}
		wwOut := ps(fmt.Sprintf("(Get-ChildItem '%s' -Directory -ErrorAction SilentlyContinue | Where-Object { (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -eq 'Everyone' -and $_.FileSystemRights -match 'Write' } } | Measure-Object).Count", tempDir))
		wwCount, _ := strconv.Atoi(wwOut)
		if wwCount == 0 {
			checks = append(checks, CheckResult{Name: "World-Writable Temp", Category: "Files", Status: "pass", Detail: "No world-writable directories in temp"})
		} else {
			checks = append(checks, CheckResult{Name: "World-Writable Temp", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d world-writable dir(s) in temp", wwCount)})
		}
	}

	// Unquoted Service Paths
	{
		unquoted := ps("Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -notmatch '\"' -and $_.PathName -match ' ' -and $_.PathName -notmatch 'system32' } | Measure-Object | Select-Object -ExpandProperty Count")
		uqCount, _ := strconv.Atoi(unquoted)
		if uqCount == 0 {
			checks = append(checks, CheckResult{Name: "Unquoted Service Paths", Category: "Files", Status: "pass", Detail: "No unquoted service paths found"})
		} else {
			checks = append(checks, CheckResult{Name: "Unquoted Service Paths", Category: "Files", Status: "warn", Detail: fmt.Sprintf("%d service(s) with unquoted paths", uqCount), Fix: "Quote the paths in service configurations", FixCmd: "", Risk: "medium"})
		}
	}

	// AutoRun Disabled
	{
		autoRun := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun")
		if autoRun == "255" || autoRun == "0xFF" {
			checks = append(checks, CheckResult{Name: "AutoRun Disabled", Category: "Files", Status: "pass", Detail: "AutoRun is disabled for all drives"})
		} else {
			checks = append(checks, CheckResult{Name: "AutoRun Disabled", Category: "Files", Status: "warn", Detail: "AutoRun may not be fully disabled", Fix: "Disable AutoRun via Group Policy", FixCmd: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f", Risk: "low"})
		}
	}

	// ═══════════════════════════════════════
	// AGENT (7)
	// ═══════════════════════════════════════

	// Docker Desktop Socket
	{
		dockerPipe := ps("Test-Path \\\\.\\pipe\\docker_engine")
		if dockerPipe == "True" {
			checks = append(checks, CheckResult{Name: "Docker Desktop Socket", Category: "Agent", Status: "warn", Detail: "Docker named pipe is accessible"})
		} else {
			checks = append(checks, CheckResult{Name: "Docker Desktop Socket", Category: "Agent", Status: "pass", Detail: "Docker named pipe not present"})
		}
	}

	// OpenClaw Config Permissions
	{
		home := os.Getenv("USERPROFILE")
		ocPaths := []string{home + "\\.openclaw\\config.yaml", home + "\\.openclaw\\config.yml", home + "\\.config\\openclaw\\config.json"}
		ocFound := false
		for _, p := range ocPaths {
			if _, err := os.Stat(p); err == nil {
				ocFound = true
				checks = append(checks, CheckResult{Name: "OpenClaw Config", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("Config found at %s", p)})
				break
			}
		}
		if !ocFound {
			checks = append(checks, CheckResult{Name: "OpenClaw Config", Category: "Agent", Status: "pass", Detail: "No OpenClaw config file found"})
		}
	}

	// Workspace Permissions
	{
		home := os.Getenv("USERPROFILE")
		wsPaths := []string{home + "\\workspace", "C:\\workspace"}
		for _, ws := range wsPaths {
			if _, err := os.Stat(ws); err == nil {
				checks = append(checks, CheckResult{Name: "Workspace Permissions", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("Workspace exists at %s", ws)})
				break
			}
		}
	}

	// API Keys in Env
	{
		envVars := os.Environ()
		keyRe := regexp.MustCompile(`(?i)(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)`)
		var sensitiveKeys []string
		for _, env := range envVars {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && len(parts[1]) > 0 {
				if keyRe.MatchString(parts[0]) && parts[0] != "TERM" && parts[0] != "SHELL" {
					sensitiveKeys = append(sensitiveKeys, parts[0])
				}
			}
		}
		if len(sensitiveKeys) == 0 {
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "pass", Detail: "No API keys/secrets found in environment"})
		} else {
			show := sensitiveKeys
			if len(show) > 3 {
				show = show[:3]
			}
			detail := fmt.Sprintf("%d sensitive env var(s): %s", len(sensitiveKeys), strings.Join(show, ", "))
			if len(sensitiveKeys) > 3 {
				detail += "..."
			}
			checks = append(checks, CheckResult{Name: "API Keys in Env", Category: "Agent", Status: "warn", Detail: detail})
		}
	}

	// Skill Integrity
	{
		home := os.Getenv("USERPROFILE")
		skillsDirs := []string{home + "\\workspace\\skills", "C:\\workspace\\skills"}
		checked := false
		for _, skillsDir := range skillsDirs {
			entries, err := os.ReadDir(skillsDir)
			if err != nil {
				continue
			}
			checked = true
			var skills []string
			var unsigned []string
			for _, e := range entries {
				if e.IsDir() {
					skills = append(skills, e.Name())
					if !fileExists(filepath.Join(skillsDir, e.Name(), "SIGNATURE")) {
						unsigned = append(unsigned, e.Name())
					}
				}
			}
			if len(skills) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "No skills installed"})
			} else if len(unsigned) == 0 {
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("%d skill(s) installed, all signed", len(skills))})
			} else {
				show := unsigned
				if len(show) > 3 {
					show = show[:3]
				}
				checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "warn", Detail: fmt.Sprintf("%d/%d skill(s) unsigned: %s", len(unsigned), len(skills), strings.Join(show, ", "))})
			}
			break
		}
		if !checked {
			checks = append(checks, CheckResult{Name: "Skill Integrity", Category: "Agent", Status: "pass", Detail: "Skills directory not found"})
		}
	}

	// OpenClaw Version
	{
		ocVersion := cmd("openclaw --version 2>nul")
		if ocVersion != "" {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: fmt.Sprintf("OpenClaw version: %s", ocVersion)})
		} else {
			checks = append(checks, CheckResult{Name: "OpenClaw Version", Category: "Agent", Status: "pass", Detail: "OpenClaw version not available"})
		}
	}

	return checks
}

func runGenericChecks() []CheckResult {
	return []CheckResult{
		{Name: "OS Support", Category: "System", Status: "warn", Detail: fmt.Sprintf("Limited checks for %s", runtime.GOOS)},
	}
}

func calculateScore(checks []CheckResult) (int, string) {
	if len(checks) == 0 {
		return 0, "?"
	}

	total := 0
	for _, c := range checks {
		switch c.Status {
		case "pass":
			total += 100
		case "warn":
			total += 50
		case "fail":
			total += 0
		}
	}

	score := total / len(checks)

	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return score, grade
}
