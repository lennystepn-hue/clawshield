package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func statusIcon(status string) string {
	switch status {
	case "pass":
		return colorGreen + "✅ PASS" + colorReset
	case "warn":
		return colorYellow + "⚠️  WARN" + colorReset
	case "fail":
		return colorRed + "❌ FAIL" + colorReset
	case "info":
		return colorBlue + "ℹ️  INFO" + colorReset
	default:
		return "  " + status
	}
}

func PrintReport(report ScanReport) {
	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s  🛡️  ClawShield Security Report%s\n", colorBold, colorReset)
	fmt.Printf("%s  %s | OS: %s%s\n", colorDim, time.Now().Format("2006-01-02 15:04:05"), report.OS, colorReset)
	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n\n", colorBold, colorCyan, colorReset)

	// Group by category
	categories := make(map[string][]CheckResult)
	categoryOrder := []string{}

	for _, c := range report.Checks {
		if _, exists := categories[c.Category]; !exists {
			categoryOrder = append(categoryOrder, c.Category)
		}
		categories[c.Category] = append(categories[c.Category], c)
	}

	for _, cat := range categoryOrder {
		checks := categories[cat]
		fmt.Printf("%s%s── %s ──%s\n", colorBold, colorCyan, strings.ToUpper(cat), colorReset)

		for _, c := range checks {
			fmt.Printf("  %s  %s\n", statusIcon(c.Status), c.Name)
			if c.Detail != "" {
				fmt.Printf("         %s%s%s\n", colorDim, c.Detail, colorReset)
			}
			if c.Fix != "" {
				fmt.Printf("         %s💡 Fix: %s%s\n", colorYellow, c.Fix, colorReset)
			}
		}
		fmt.Println()
	}

	PrintScore(report)
}

func PrintScore(report ScanReport) {
	passes := 0
	warns := 0
	fails := 0

	for _, c := range report.Checks {
		switch c.Status {
		case "pass":
			passes++
		case "warn":
			warns++
		case "fail":
			fails++
		}
	}

	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)

	gradeColor := colorGreen
	switch {
	case report.Score < 50:
		gradeColor = colorRed
	case report.Score < 70:
		gradeColor = colorYellow
	case report.Score < 90:
		gradeColor = colorBlue
	}

	fmt.Printf("  %sSecurity Score: %s%s %d/100%s\n", colorBold, gradeColor, report.Grade, report.Score, colorReset)
	fmt.Printf("  %s✅ %d passed  ⚠️  %d warnings  ❌ %d failed%s\n", colorDim, passes, warns, fails, colorReset)
	fmt.Printf("%s%s══════════════════════════════════════════════════════%s\n", colorBold, colorCyan, colorReset)

	if fails > 0 {
		fmt.Printf("\n  %s🔴 Run 'clawshield harden --auto' to fix critical issues%s\n", colorRed, colorReset)
	} else if warns > 0 {
		fmt.Printf("\n  %s🟡 Run 'clawshield harden' to review warnings%s\n", colorYellow, colorReset)
	} else {
		fmt.Printf("\n  %s🟢 Your system is well secured!%s\n", colorGreen, colorReset)
	}
	fmt.Println()
}

func PrintJSON(report ScanReport) {
	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))
}
