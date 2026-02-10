package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

type SkillFinding struct {
	File     string
	Line     int
	Pattern  string
	Severity string // "critical", "high", "medium", "low"
	Detail   string
}

type SkillReport struct {
	Path     string
	Findings []SkillFinding
	Score    string
}

// Patterns that indicate potentially malicious skill code
var dangerousPatterns = []struct {
	Pattern  *regexp.Regexp
	Severity string
	Detail   string
}{
	// Data exfiltration
	{regexp.MustCompile(`curl.*\|.*sh`), "critical", "Remote code execution: downloading and executing scripts"},
	{regexp.MustCompile(`wget.*\|.*sh`), "critical", "Remote code execution: downloading and executing scripts"},
	{regexp.MustCompile(`curl.*-d.*(/etc/shadow|/etc/passwd|\.ssh|\.env|api.key|token|secret)`), "critical", "Data exfiltration: sending sensitive files to remote server"},
	{regexp.MustCompile(`base64.*decode`), "high", "Obfuscated code execution via base64"},
	{regexp.MustCompile(`eval\s*\(`), "high", "Dynamic code execution (eval)"},
	{regexp.MustCompile(`exec\s*\(`), "medium", "Process execution — verify this is intended"},

	// Reverse shells
	{regexp.MustCompile(`/dev/tcp/`), "critical", "Reverse shell pattern detected"},
	{regexp.MustCompile(`nc\s+-[elp]`), "critical", "Netcat listener/reverse shell"},
	{regexp.MustCompile(`ncat.*-[elp]`), "critical", "Ncat listener/reverse shell"},
	{regexp.MustCompile(`mkfifo.*/tmp/`), "critical", "Named pipe reverse shell pattern"},
	{regexp.MustCompile(`python.*socket.*connect`), "critical", "Python reverse shell pattern"},
	{regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/`), "critical", "Bash reverse shell"},

	// Crypto mining
	{regexp.MustCompile(`xmrig|cpuminer|minerd|cryptonight|stratum\+`), "critical", "Cryptocurrency miner detected"},

	// Credential theft
	{regexp.MustCompile(`cat\s+/etc/shadow`), "critical", "Reading password hashes"},
	{regexp.MustCompile(`cat.*\.ssh/(id_rsa|id_ed25519|authorized_keys)`), "critical", "Reading SSH keys"},
	{regexp.MustCompile(`cat.*\.(env|secret|token|key|password|passwd)`), "high", "Reading potential secrets file"},
	{regexp.MustCompile(`(ANTHROPIC_API_KEY|OPENAI_API_KEY|API_SECRET)\s*=\s*["'][a-zA-Z0-9_-]{10,}`), "high", "Hardcoded API key with value"},

	// Persistence
	{regexp.MustCompile(`crontab\s+-[el]`), "medium", "Crontab modification — check for persistence"},
	{regexp.MustCompile(`/etc/systemd/system/.*\.service`), "medium", "Systemd service creation — check for persistence"},
	{regexp.MustCompile(`\.bashrc|\.profile|\.bash_profile`), "medium", "Shell profile modification — check for persistence"},
	{regexp.MustCompile(`authorized_keys`), "high", "SSH authorized_keys modification"},

	// Privilege escalation
	{regexp.MustCompile(`chmod\s+[47]77`), "high", "Setting world-writable permissions"},
	{regexp.MustCompile(`chmod\s+u\+s`), "critical", "Setting SUID bit — privilege escalation"},
	{regexp.MustCompile(`sudo\s+.*NOPASSWD`), "critical", "Adding passwordless sudo access"},

	// File system dangers
	{regexp.MustCompile(`rm\s+-rf\s+/[^.]`), "critical", "Recursive deletion of system directories"},
	{regexp.MustCompile(`dd\s+if=.*of=/dev/`), "critical", "Direct disk write — potential data destruction"},
	{regexp.MustCompile(`mkfs\s+`), "critical", "Filesystem format — data destruction"},

	// Network
	{regexp.MustCompile(`iptables\s+-F`), "high", "Flushing firewall rules"},
	{regexp.MustCompile(`ufw\s+disable`), "high", "Disabling firewall"},
	{regexp.MustCompile(`0\.0\.0\.0`), "low", "Binding to all interfaces — verify this is intended"},

	// Suspicious URLs
	{regexp.MustCompile(`https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`), "medium", "Direct IP address URL (no domain) — may indicate C2 server"},
	{regexp.MustCompile(`pastebin\.com|paste\.ee|transfer\.sh|ngrok\.io`), "high", "Connection to paste/tunnel service — potential data exfiltration"},
}

func ScanSkill(path string) {
	report := SkillReport{Path: path}

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("❌ Cannot access path: %s\n", err)
		return
	}

	if info.IsDir() {
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Skip common non-code directories
				name := info.Name()
				if name == "node_modules" || name == ".git" || name == "__pycache__" || name == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if isCodeFile(p) {
				findings := scanFile(p)
				report.Findings = append(report.Findings, findings...)
			}
			return nil
		})
	} else {
		report.Findings = scanFile(path)
	}

	report.Score = calculateSkillScore(report.Findings)
	printSkillReport(report)
}

func isCodeFile(path string) bool {
	codeExts := []string{
		".sh", ".bash", ".py", ".js", ".ts", ".go", ".rb", ".pl",
		".yaml", ".yml", ".json", ".toml", ".md",
		".dockerfile", ".env", ".conf", ".cfg",
	}

	lower := strings.ToLower(path)
	for _, ext := range codeExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	// Also check files without extension (scripts)
	base := filepath.Base(path)
	scriptNames := []string{"Makefile", "Dockerfile", "Vagrantfile", "SKILL.md"}
	for _, name := range scriptNames {
		if base == name {
			return true
		}
	}

	return false
}

func scanFile(path string) []SkillFinding {
	var findings []SkillFinding

	data, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, pattern := range dangerousPatterns {
			if pattern.Pattern.MatchString(line) {
				findings = append(findings, SkillFinding{
					File:     path,
					Line:     lineNum + 1,
					Pattern:  pattern.Pattern.String(),
					Severity: pattern.Severity,
					Detail:   pattern.Detail,
				})
			}
		}
	}

	return findings
}

func calculateSkillScore(findings []SkillFinding) string {
	if len(findings) == 0 {
		return "SAFE ✅"
	}

	hasCritical := false
	hasHigh := false

	for _, f := range findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
		if f.Severity == "high" {
			hasHigh = true
		}
	}

	if hasCritical {
		return "DANGEROUS ❌"
	}
	if hasHigh {
		return "SUSPICIOUS ⚠️"
	}
	return "REVIEW 🔍"
}

func printSkillReport(report SkillReport) {
	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n", colorBold, "\033[36m", colorReset)
	fmt.Printf("  %s🔬 Skill Security Scan%s\n", colorBold, colorReset)
	fmt.Printf("  %sPath: %s%s\n", colorDim, report.Path, colorReset)
	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n\n", colorBold, "\033[36m", colorReset)

	if len(report.Findings) == 0 {
		fmt.Printf("  %s✅ No security issues found%s\n\n", colorGreen, colorReset)
	} else {
		// Group by severity
		bySeverity := map[string][]SkillFinding{}
		for _, f := range report.Findings {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
		}

		for _, sev := range []string{"critical", "high", "medium", "low"} {
			findings := bySeverity[sev]
			if len(findings) == 0 {
				continue
			}

			sevColor := colorDim
			sevIcon := "ℹ️"
			switch sev {
			case "critical":
				sevColor = colorRed + colorBold
				sevIcon = "🚨"
			case "high":
				sevColor = colorRed
				sevIcon = "❌"
			case "medium":
				sevColor = colorYellow
				sevIcon = "⚠️"
			case "low":
				sevColor = colorDim
				sevIcon = "💡"
			}

			fmt.Printf("  %s%s %s (%d)%s\n", sevColor, sevIcon, strings.ToUpper(sev), len(findings), colorReset)

			for _, f := range findings {
				relPath := f.File
				if strings.HasPrefix(relPath, report.Path) {
					relPath = strings.TrimPrefix(relPath, report.Path)
					relPath = strings.TrimPrefix(relPath, "/")
				}
				fmt.Printf("    %s:%d — %s\n", relPath, f.Line, f.Detail)
			}
			fmt.Println()
		}
	}

	// Overall verdict
	verdictColor := colorGreen
	if strings.Contains(report.Score, "DANGEROUS") {
		verdictColor = colorRed + colorBold
	} else if strings.Contains(report.Score, "SUSPICIOUS") {
		verdictColor = colorYellow + colorBold
	} else if strings.Contains(report.Score, "REVIEW") {
		verdictColor = colorYellow
	}

	fmt.Printf("  %sVerdict: %s%s\n", verdictColor, report.Score, colorReset)
	fmt.Printf("  %sFindings: %d total%s\n\n", colorDim, len(report.Findings), colorReset)

	if strings.Contains(report.Score, "DANGEROUS") {
		fmt.Printf("  %s⛔ DO NOT INSTALL THIS SKILL — critical security risks detected%s\n\n", colorRed+colorBold, colorReset)
	}
}
