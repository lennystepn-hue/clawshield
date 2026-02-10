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
		checks = append(checks, CheckResult{Name: "Fail2Ban", Category: "Access", Status: "fail", Detail: "Fail2Ban is not active", Fix: "apt-get install -y fail2ban && systemctl enable --now fail2ban", FixCmd: "apt-get install -y fail2ban && systemctl enable --now fail2ban", Risk: "low"})
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
		checks = append(checks, CheckResult{Name: "Password Policy", Category: "Access", Status: "warn", Detail: "No PAM password policy (pam_pwquality/minlen) found", Fix: "apt-get install -y libpam-pwquality && echo 'password requisite pam_pwquality.so retry=3 minlen=12' >> /etc/pam.d/common-password", FixCmd: "apt-get install -y libpam-pwquality && grep -q pam_pwquality /etc/pam.d/common-password || echo 'password requisite pam_pwquality.so retry=3 minlen=12' >> /etc/pam.d/common-password", Risk: "medium"})
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
			checks = append(checks, CheckResult{Name: "AppArmor", Category: "System", Status: "warn", Detail: "AppArmor is not active or not installed", Fix: "apt-get install -y apparmor && systemctl enable --now apparmor", FixCmd: "apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor", Risk: "low"})
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
			checks = append(checks, CheckResult{Name: "Log Rotation", Category: "Files", Status: "warn", Detail: "Logrotate not found or inactive", Fix: "apt-get install -y logrotate && systemctl enable --now logrotate.timer", FixCmd: "apt-get install -y logrotate && systemctl enable --now logrotate.timer", Risk: "low"})
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
