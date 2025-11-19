//go:build windows
// +build windows

package main

import (
	"bufio" // untuk interactive shell
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec" // jalankan ulang exe sendiri dengan argumen user
	"path/filepath"
	"strings"
	"time"

	"corp/OSagent/core"
)

const (
	VERSION   = "1.0.0"
	TOOL_NAME = "OSAgent"
)

func main() {
	// ===== [Mode interaktif] =====
	if len(os.Args) == 1 {
		startInteractiveShell()
		return
	}

	// ===== Flags =====
	shellFlag := flag.Bool("shell", false, "start interactive shell (banner + prompt)")
	pretty := flag.Bool("pretty", false, "Pretty-print JSON output")
	timeout := flag.Int("timeout", 60, "Global timeout in seconds")
	checksFlag := flag.String("checks", "", "Comma-separated check IDs to run (e.g. W-001,W-003). Empty = all.")
	outputFile := flag.String("output", "", "Output results to JSON file")
	summary := flag.Bool("summary", false, "Show summary table (always shown when writing to file)")
	verbose := flag.Bool("verbose", false, "Show detailed progress")
	flag.Parse()

	if *shellFlag {
		startInteractiveShell()
		return
	}

	// ===== Setup Scanner =====
	cfg := core.Config{
		Timeout:        time.Duration(*timeout) * time.Second,
		ParallelChecks: true,
		MaxWorkers:     5,
		Verbose:        *verbose,
	}

	scanner := core.NewScanner(cfg)

	// ===== Register all checks =====
	registerAllChecks(scanner)

	// ===== Parse filter IDs =====
	var filterIDs []string
	if strings.TrimSpace(*checksFlag) != "" {
		for _, raw := range strings.Split(*checksFlag, ",") {
			id := strings.ToUpper(strings.TrimSpace(raw))
			if id != "" {
				filterIDs = append(filterIDs, id)
			}
		}
	}

	// ===== Run scan =====
	fmt.Fprintln(os.Stderr, core.Colorize("Starting Windows OS Security Scan...", core.ColorCyan))
	if len(filterIDs) > 0 {
		fmt.Fprintf(os.Stderr, "Filter: %v\n", filterIDs)
	}
	fmt.Fprintln(os.Stderr, "")

	startTime := time.Now()
	results := scanner.Run(context.Background(), filterIDs)
	duration := time.Since(startTime)

	// ===== Generate Report =====
	metadata := core.Metadata{
		Tool:     TOOL_NAME,
		Version:  VERSION,
		ScanTime: startTime,
		Duration: duration.Round(time.Second).String(),
		Hostname: getHostname(),
		Username: getUsername(),
		OS:       "Windows",
		IsAdmin:  isAdmin(),
	}

	report := core.GenerateReport(results, metadata)

	// ===== Output =====
	var outputWriter *os.File
	var shouldCloseFile bool
	showSummaryTable := *summary

	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file '%s': %v\n", *outputFile, err)
			os.Exit(1)
		}
		outputWriter = file
		shouldCloseFile = true
		showSummaryTable = true // Always show summary when saving to file

		fmt.Fprintf(os.Stderr, core.Colorize("✓ Saving results to: %s\n", core.ColorGreen), *outputFile)
	} else {
		outputWriter = os.Stdout
		shouldCloseFile = false
	}

	if shouldCloseFile {
		defer func() {
			if err := outputWriter.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
			}
		}()
	}

	// Write JSON
	if err := core.WriteJSON(outputWriter, report, *pretty); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	// Print summary to stderr (so it doesn't mix with JSON stdout)
	if showSummaryTable {
		core.PrintSummaryTable(report, os.Stderr)
	}

	// Exit code based on findings
	if report.Summary.Vulnerable > 0 {
		os.Exit(1) // Found vulnerabilities
	}
}

// registerAllChecks mendaftarkan semua pemeriksaan
func registerAllChecks(s *core.Scanner) {
	checks := []core.Check{
		NewCheckAlwaysInstallElevated(),
		NewCheckUnquotedServicePaths(),
		NewCheckUACSnapshot(),
		NewCheckAutoruns(),
		NewCheckScheduledTasks(),
		NewCheckHotfix(),
		NewCheckUsersGroups(),
		NewCheckTokenPrivileges(),
		NewCheckNetworkSnapshot(),
		NewCheckListeningPorts(),
		NewCheckSystemInfo(),
		NewCheckRdpFirewallProxy(),
		NewCheckPathWritable(),
		NewCheckServiceHijack(),
		NewCheckDefenderExclusions(),
		NewCheckLSA(),
		NewCheckIFEO(),
		NewCheckServiceBinaryACL(),
		NewCheckPowerShellHistory(),
		NewCheckLSASSArtifacts(),
	}

	for _, check := range checks {
		s.RegisterCheck(check)
	}
}

/* ======================= Helper functions ======================= */

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getUsername() string {
	return os.Getenv("USERNAME")
}

/* ======================= Interactive shell helpers ======================= */

// startInteractiveShell menampilkan banner & prompt, lalu menjalankan OSagent.exe
// sebagai subprocess dengan argumen yang diketik user (tanpa refactor flag).
func startInteractiveShell() {
	printBanner()

	exe, _ := os.Executable()
	exe = filepath.Clean(exe)
	rd := bufio.NewScanner(os.Stdin)

	fmt.Println("Type commands below. Examples:")
	fmt.Println("  -checks W-016 -pretty -summary")
	fmt.Println("  -checks W-015,W-017 -output results.json")
	fmt.Println("  -summary  (run all with summary)")
	fmt.Println("Built-ins: help, exit, quit")
	fmt.Println()

	for {
		fmt.Print("\x1b[38;2;0;255;204mOSSCANNER\x1b[0m> ")

		if !rd.Scan() {
			// EOF (Ctrl+Z / Ctrl+D) -> keluar
			fmt.Println()
			return
		}
		line := strings.TrimSpace(rd.Text())
		if line == "" {
			continue
		}

		// Built-in commands
		low := strings.ToLower(line)
		switch low {
		case "exit", "quit":
			return
		case "help", "-h", "--help":
			printHelp()
			continue
		}

		// Izinkan user ketik: "OSagent.exe -checks ..." -> buang token pertama
		args := splitCommandLine(line)
		if len(args) > 0 {
			a0 := strings.ToLower(filepath.Base(args[0]))
			if a0 == "osagent" || a0 == "osagent.exe" {
				args = args[1:]
			}
		}
		if len(args) == 0 {
			continue
		}

		// Jalankan ulang executable sendiri dengan argumen user
		cmd := exec.Command(exe, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		}
		fmt.Println() // spasi antar-run
	}
}

// printBanner menampilkan ASCII logo sederhana (bebas kamu ganti)
func printBanner() {
	const banner = `
   ____  _____   ___                    __  
  / __ \/ ___/  /   | ____ ____  ____  / /_ 
 / / / /\__ \  / /| |/ __  / _ \/ __ \/ __/ 
/ /_/ /___/ / / ___ / /_/ /  __/ / / / /_   
\____//____/ /_/  |_\__, /\___/_/ /_/\__/   
                   /____/                    

`

	fmt.Print(banner)
	fmt.Println(strings.Repeat("*", 70))
	fmt.Printf("  Windows OS Security Scanner v%s\n", VERSION)
	fmt.Println("  Defensive Security Assessment Tool")
	fmt.Println(strings.Repeat("*", 70))
}

// printHelp menjelaskan cara pakai dari dalam shell
func printHelp() {
	fmt.Println("Usage inside shell:")
	fmt.Println("  -checks W-001,W-015 -pretty -summary")
	fmt.Println("  -checks W-016 -output scan.json")
	fmt.Println("  -summary (run all checks with summary)")
	fmt.Println("  -verbose (show detailed progress)")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("  -checks [IDs]     Comma-separated check IDs (W-001 to W-020)")
	fmt.Println("  -output [file]    Save results to JSON file")
	fmt.Println("  -pretty           Format JSON with indentation")
	fmt.Println("  -summary          Show summary table after scan")
	fmt.Println("  -verbose          Show detailed progress information")
	fmt.Println("  -timeout [secs]   Set timeout (default: 60)")
	fmt.Println("")
	fmt.Println("Built-ins: help, exit, quit")
}

// splitCommandLine memecah input menjadi argumen (mendukung kutip "…").
func splitCommandLine(s string) []string {
	args := []string{}
	cur := strings.Builder{}
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			inQuote = !inQuote
		case ' ', '\t':
			if inQuote {
				cur.WriteByte(c)
			} else if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}
