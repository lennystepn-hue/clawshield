package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/clawshield/clawshield/internal/hardener"
	"github.com/clawshield/clawshield/internal/scanner"
	"github.com/clawshield/clawshield/internal/monitor"
	"github.com/clawshield/clawshield/internal/skills"
)

const version = "0.1.0"

const banner = `
   _____ _               _____ _     _      _     _ 
  / ____| |             / ____| |   (_)    | |   | |
 | |    | | __ ___   __| (___ | |__  _  ___| | __| |
 | |    | |/ _` + "`" + ` \ \ /\ / /\___ \| '_ \| |/ _ \ |/ _` + "`" + ` |
 | |____| | (_| |\ V  V / ____) | | | | |  __/ | (_| |
  \_____|_|\__,_| \_/\_/ |_____/|_| |_|_|\___|_|\__,_|
                                                v%s
  🛡️  Security Layer for AI Agents
`

func main() {
	fmt.Printf(banner, version)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := strings.ToLower(os.Args[1])

	switch cmd {
	case "scan":
		fmt.Println("\n🔍 Running security scan...\n")
		report := scanner.RunFullScan()
		scanner.PrintReport(report)

	case "harden":
		fmt.Println("\n🔒 Hardening system...\n")
		if len(os.Args) > 2 && os.Args[2] == "--auto" {
			hardener.AutoHarden()
		} else {
			hardener.InteractiveHarden()
		}

	case "monitor":
		fmt.Println("\n👁️  Starting live monitor...\n")
		monitor.Start()

	case "skill-scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: clawshield skill-scan <skill-path-or-name>")
			os.Exit(1)
		}
		fmt.Printf("\n🔬 Scanning skill: %s\n\n", os.Args[2])
		skills.ScanSkill(os.Args[2])

	case "status":
		fmt.Println("\n📊 Security Status\n")
		report := scanner.RunFullScan()
		scanner.PrintScore(report)

	case "version":
		fmt.Printf("ClawShield v%s\n", version)

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`
Usage: clawshield <command> [options]

Commands:
  scan          Run a full security audit
  harden        Harden your system (--auto for non-interactive)
  monitor       Start live security monitoring
  skill-scan    Scan a skill for malicious code
  status        Quick security score
  version       Show version

Examples:
  clawshield scan
  clawshield harden --auto
  clawshield skill-scan ./skills/my-skill
  clawshield monitor
`)
}
