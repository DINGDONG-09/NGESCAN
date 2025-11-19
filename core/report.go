//go:build windows
// +build windows

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// ScanReport adalah laporan lengkap hasil scan
type ScanReport struct {
	Metadata Metadata      `json:"metadata"`
	Summary  Summary       `json:"summary"`
	Findings []CheckResult `json:"findings"`
}

// Metadata informasi scan
type Metadata struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	ScanTime time.Time `json:"scan_time"`
	Duration string    `json:"duration"`
	Hostname string    `json:"hostname,omitempty"`
	Username string    `json:"username,omitempty"`
	OS       string    `json:"os,omitempty"`
	IsAdmin  bool      `json:"is_admin"`
}

// Summary ringkasan hasil scan
type Summary struct {
	TotalChecks      int            `json:"total_checks"`
	Vulnerable       int            `json:"vulnerable"`
	Secure           int            `json:"secure"`
	Errors           int            `json:"errors"`
	Skipped          int            `json:"skipped"`
	BySeverity       map[string]int `json:"by_severity"`
	ByCategory       map[string]int `json:"by_category"`
	HighestRiskScore float64        `json:"highest_risk_score"`
}

// GenerateReport membuat laporan dari hasil scan
func GenerateReport(results []CheckResult, metadata Metadata) ScanReport {
	summary := Summary{
		TotalChecks: len(results),
		BySeverity:  make(map[string]int),
		ByCategory:  make(map[string]int),
	}

	for _, r := range results {
		// Count by status
		switch r.Status {
		case "vulnerable":
			summary.Vulnerable++
		case "ok":
			summary.Secure++
		case "error", "timeout":
			summary.Errors++
		case "skipped":
			summary.Skipped++
		}

		// Count by severity
		if r.Status == "vulnerable" {
			summary.BySeverity[r.Finding.Severity]++
			summary.ByCategory[r.Finding.Category]++

			// Track highest risk
			if r.Finding.RiskScore > summary.HighestRiskScore {
				summary.HighestRiskScore = r.Finding.RiskScore
			}
		}
	}

	// Sort results by CheckID
	sort.Slice(results, func(i, j int) bool {
		return results[i].CheckID < results[j].CheckID
	})

	return ScanReport{
		Metadata: metadata,
		Summary:  summary,
		Findings: results,
	}
}

// WriteJSON menulis report ke JSON
func WriteJSON(w io.Writer, report ScanReport, pretty bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	if pretty {
		enc.SetIndent("", "  ")
	}

	return enc.Encode(report)
}

// PrintSummaryTable mencetak tabel ringkasan ke terminal (user-friendly)
func PrintSummaryTable(report ScanReport, w io.Writer) {
	fmt.Fprintln(w, "\n"+Colorize("═══════════════════════════════════════════════════════════", ColorCyan))
	fmt.Fprintln(w, Colorize("                    SCAN SUMMARY", ColorCyan))
	fmt.Fprintln(w, Colorize("═══════════════════════════════════════════════════════════", ColorCyan))

	fmt.Fprintf(w, "\n%-25s: %s\n", "Scan Time", report.Metadata.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "%-25s: %s\n", "Duration", report.Metadata.Duration)
	fmt.Fprintf(w, "%-25s: %s\n", "Hostname", report.Metadata.Hostname)
	fmt.Fprintf(w, "%-25s: %s\n", "User", report.Metadata.Username)
	fmt.Fprintf(w, "%-25s: %v\n", "Admin Privileges", report.Metadata.IsAdmin)

	fmt.Fprintln(w, "\n"+Colorize("───────────────────────────────────────────────────────────", ColorGray))
	fmt.Fprintln(w, Colorize("  Check Results", ColorCyan))
	fmt.Fprintln(w, Colorize("───────────────────────────────────────────────────────────", ColorGray))

	fmt.Fprintf(w, "  %-20s: %d\n", "Total Checks", report.Summary.TotalChecks)
	fmt.Fprintf(w, "  %-20s: %s\n", "Vulnerable", Colorize(fmt.Sprintf("%d", report.Summary.Vulnerable), ColorRed))
	fmt.Fprintf(w, "  %-20s: %s\n", "Secure", Colorize(fmt.Sprintf("%d", report.Summary.Secure), ColorGreen))
	fmt.Fprintf(w, "  %-20s: %d\n", "Errors", report.Summary.Errors)
	fmt.Fprintf(w, "  %-20s: %d\n", "Skipped", report.Summary.Skipped)

	if len(report.Summary.BySeverity) > 0 {
		fmt.Fprintln(w, "\n"+Colorize("───────────────────────────────────────────────────────────", ColorGray))
		fmt.Fprintln(w, Colorize("  Vulnerabilities by Severity", ColorCyan))
		fmt.Fprintln(w, Colorize("───────────────────────────────────────────────────────────", ColorGray))

		severityOrder := []string{"critical", "high", "medium", "low", "info"}
		for _, sev := range severityOrder {
			if count, ok := report.Summary.BySeverity[sev]; ok && count > 0 {
				color := getSeverityColor(sev)
				fmt.Fprintf(w, "  %-20s: %s\n", sev, Colorize(fmt.Sprintf("%d", count), color))
			}
		}

		fmt.Fprintf(w, "\n  %-20s: %.1f\n", "Highest Risk Score", report.Summary.HighestRiskScore)
	}

	if len(report.Summary.ByCategory) > 0 {
		fmt.Fprintln(w, "\n"+Colorize("───────────────────────────────────────────────────────────", ColorGray))
		fmt.Fprintln(w, Colorize("  Vulnerabilities by Category", ColorCyan))
		fmt.Fprintln(w, Colorize("───────────────────────────────────────────────────────────", ColorGray))

		for cat, count := range report.Summary.ByCategory {
			fmt.Fprintf(w, "  %-30s: %d\n", cat, count)
		}
	}

	fmt.Fprintln(w, "\n"+Colorize("═══════════════════════════════════════════════════════════", ColorCyan))
}

func getSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "\033[91m" // bright red
	case "high":
		return ColorRed
	case "medium":
		return ColorYellow
	case "low":
		return ColorCyan
	default:
		return ColorGray
	}
}
