package monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

func Start() {
	fmt.Printf("%s🛡️  ClawShield Live Monitor%s\n", colorBold, colorReset)
	fmt.Printf("%sPress Ctrl+C to stop%s\n\n", colorDim, colorReset)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start monitoring goroutines
	go monitorAuthLog()
	go monitorConnections()
	go monitorProcesses()

	// Wait for shutdown
	<-sigChan
	fmt.Printf("\n\n%s🛡️  Monitor stopped.%s\n", colorBold, colorReset)
}

func monitorAuthLog() {
	// Watch auth.log for failed login attempts
	file, err := os.Open("/var/log/auth.log")
	if err != nil {
		logEvent("WARN", "Cannot monitor auth.log: "+err.Error())
		return
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, 2)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		line = strings.TrimSpace(line)

		if strings.Contains(line, "Failed password") || strings.Contains(line, "authentication failure") {
			logEvent("ALERT", "🚨 Failed login attempt: "+extractRelevant(line))
		} else if strings.Contains(line, "Accepted publickey") {
			logEvent("INFO", "🔑 SSH login: "+extractRelevant(line))
		} else if strings.Contains(line, "Ban ") {
			logEvent("BLOCK", "🚫 IP banned by fail2ban: "+extractRelevant(line))
		} else if strings.Contains(line, "Invalid user") {
			logEvent("ALERT", "👤 Invalid user attempt: "+extractRelevant(line))
		}
	}
}

func monitorConnections() {
	knownPorts := map[string]bool{}

	for {
		out, err := exec.Command("ss", "-tlnp").Output()
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}

		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			if strings.Contains(line, "LISTEN") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					addr := fields[3]
					if !knownPorts[addr] {
						knownPorts[addr] = true
						if strings.Contains(addr, "0.0.0.0:") || strings.Contains(addr, "*:") {
							logEvent("WARN", "📡 New public listener: "+addr)
						} else {
							logEvent("INFO", "📡 New listener: "+addr)
						}
					}
				}
			}
		}

		time.Sleep(30 * time.Second)
	}
}

func monitorProcesses() {
	knownProcs := map[string]bool{}

	for {
		out, err := exec.Command("ps", "aux", "--no-headers").Output()
		if err != nil {
			time.Sleep(30 * time.Second)
			continue
		}

		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 11 {
				continue
			}

			cmd := strings.Join(fields[10:], " ")

			// Suspicious patterns
			suspicious := []string{
				"crypto", "miner", "xmrig", "cpuminer",
				"nc -l", "ncat -l", "reverse",
				"/tmp/.", "chmod 777",
				"curl.*|.*sh", "wget.*|.*sh",
				"base64.*decode",
			}

			for _, pattern := range suspicious {
				if strings.Contains(strings.ToLower(cmd), pattern) {
					procKey := pattern + ":" + cmd
					if !knownProcs[procKey] {
						knownProcs[procKey] = true
						logEvent("CRITICAL", fmt.Sprintf("🚨 Suspicious process: %s (user: %s, pid: %s)", cmd, fields[0], fields[1]))
					}
				}
			}
		}

		time.Sleep(15 * time.Second)
	}
}

func extractRelevant(line string) string {
	// Extract the most relevant part from a log line
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	if len(line) > 100 {
		return line[:100] + "..."
	}
	return line
}

func logEvent(level, message string) {
	now := time.Now().Format("15:04:05")

	var levelColor string
	switch level {
	case "CRITICAL":
		levelColor = colorRed + colorBold
	case "ALERT":
		levelColor = colorRed
	case "WARN":
		levelColor = colorYellow
	case "BLOCK":
		levelColor = colorGreen
	case "INFO":
		levelColor = colorCyan
	default:
		levelColor = colorDim
	}

	fmt.Printf("  %s%s%s %s%-8s%s %s\n", colorDim, now, colorReset, levelColor, level, colorReset, message)
}
