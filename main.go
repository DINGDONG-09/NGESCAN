//go:build windows
// +build windows

package main

import (
	"bufio" // untuk interactive shell
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec" // jalankan ulang exe sendiri dengan argumen user
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// type alias biar ringkas
type checkFn = func() Finding

func main() {
	// ===== [Mode interaktif] =====
	// Jika double-click (tidak ada argumen), buka interactive shell.
	if len(os.Args) == 1 {
		startInteractiveShell()
		return
	}

	// ===== Flags =====
	shellFlag := flag.Bool("shell", false, "start interactive shell (banner + prompt)")
	pretty := flag.Bool("pretty", false, "Pretty-print JSON output")
	timeout := flag.Int("timeout", 45, "Global timeout in seconds")
	checksFlag := flag.String("checks", "", "Comma-separated check IDs to run (e.g. W-001,W-003). Empty = all.")
	outputFile := flag.String("output", "", "Output results to JSON file (e.g. -output results.json)")
	flag.Parse()

	// Jika user minta shell lewat flag
	if *shellFlag {
		startInteractiveShell()
		return
	}

	fmt.Fprintln(os.Stderr, "OSAgent (defensive) - running checks...")

	// ===== Registry cek (ID -> fungsi) =====
	reg := map[string]checkFn{
		"W-001": runCheckAlwaysInstallElevated,
		"W-002": runCheckUnquotedServicePaths,
		"W-003": runCheckUACSnapshot,
		"W-004": runCheckAutoruns,
		"W-005": runCheckScheduledTasks,
		"W-006": runCheckHotfix,
		"W-007": runCheckUsersGroups,
		"W-008": runCheckTokenPrivileges,
		"W-009": runCheckNetworkSnapshot,
		"W-010": runCheckListeningPorts,
		"W-011": runCheckSystemInfo,
		"W-012": runCheckRdpFirewallProxy,
		"W-013": runCheckPathWritable,
		"W-014": runCheckServiceHijack,
		"W-015": runCheckDefenderExclusions,
		"W-016": runCheckLSA,
		"W-017": runCheckIFEO,
		"W-018": runCheckServiceBinaryACL,
		"W-019": runCheckPowerShellHistory,
		"W-020": runCheckLSASSArtifacts,
	}

	// ===== Pilih cek yang akan dijalankan =====
	var selected []string
	if strings.TrimSpace(*checksFlag) == "" {
		// tidak ada filter -> semua
		selected = []string{"W-001", "W-002", "W-003", "W-004", "W-005", "W-006", "W-007", "W-008", "W-009", "W-010", "W-011", "W-012", "W-013", "W-014", "W-015", "W-016", "W-017", "W-018", "W-019", "W-020"}
	} else {
		// parse CSV, normalisasi & validasi ID
		for _, raw := range strings.Split(*checksFlag, ",") {
			id := strings.ToUpper(strings.TrimSpace(raw))
			if _, ok := reg[id]; ok {
				selected = append(selected, id)
			}
		}
		// kalau semua ID invalid, fallback ke semua
		if len(selected) == 0 {
			selected = []string{"W-001", "W-002", "W-003", "W-004", "W-005", "W-006", "W-007", "W-008", "W-009", "W-010", "W-011", "W-012", "W-013", "W-014", "W-015", "W-016", "W-017", "W-018", "W-019", "W-020"}
		}
	}

	// ===== Jalankan paralel dengan timeout global =====
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	resultsCh := make(chan Finding, len(selected))
	eg, _ := errgroup.WithContext(ctx)

	for _, id := range selected {
		id := id
		fn := reg[id]
		eg.Go(func() error {
			resultsCh <- fn()
			return nil
		})
	}

	_ = eg.Wait()
	close(resultsCh)

	// kumpulkan hasil
	out := make([]Finding, 0, len(selected))
	for f := range resultsCh {
		out = append(out, f)
	}

	// ===== Sort results by CheckID =====
	sort.Slice(out, func(i, j int) bool {
		return out[i].CheckID < out[j].CheckID
	})

	// ===== Emit output =====
	var outputWriter *os.File
	var shouldCloseFile bool

	// Determine output destination
	if *outputFile != "" {
		// Write to file
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file '%s': %v\n", *outputFile, err)
			os.Exit(1)
		}
		outputWriter = file
		shouldCloseFile = true
		fmt.Fprintf(os.Stderr, "Writing results to file: %s\n", *outputFile)
	} else {
		// Write to stdout
		outputWriter = os.Stdout
		shouldCloseFile = false
	}

	// Ensure file is closed if we opened it
	if shouldCloseFile {
		defer func() {
			if err := outputWriter.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close output file: %v\n", err)
			}
		}()
	}

	enc := json.NewEncoder(outputWriter)
	enc.SetEscapeHTML(false) // biar & tidak jadi \u0026

	if *pretty {
		enc.SetIndent("", "  ")
	}

	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "failed to emit findings:", err)
		os.Exit(1)
	}

	// Print completion message if writing to file
	if *outputFile != "" {
		fmt.Fprintf(os.Stderr, "Results successfully written to: %s\n", *outputFile)
	}
}

/* ======================= Interactive shell helpers ======================= */

// startInteractiveShell menampilkan banner & prompt, lalu menjalankan OSagent.exe
// sebagai subprocess dengan argumen yang diketik user (tanpa refactor flag).
func startInteractiveShell() {
	printBanner()

	exe, _ := os.Executable()
	exe = filepath.Clean(exe)
	rd := bufio.NewScanner(os.Stdin)

	fmt.Println("Type commands below (same as CLI flags). Examples:")
	fmt.Println("  -checks W-016 -pretty")
	fmt.Println("  -checks W-015,W-017")
	fmt.Println("  -output scan_results.json")
	fmt.Println("  -checks W-001,W-020 -pretty -output full_scan.json")
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
        _   ________  ______   _____    ______   ___       _   __
   / | / /  / ____/  / ____/  / ___/   / ____/  /   |     / | / /
  /  |/ /  / / __   / __/     \__ \   / /      / /| |    /  |/ / 
 / /|  /  / /_/ /  / /___    ___/ /  / /___   / ___ |   / /|  /  
/_/ |_/   \____/  /_____/   /____/   \____/  /_/  |_|  /_/ |_/   
                                                                 
                                                                                                       
                                                                                          

`

	fmt.Print(banner)
	fmt.Println(strings.Repeat("*", 70))
	fmt.Println("  OSSCANNER (defensive)                    Windows OS scanner")
	fmt.Println(strings.Repeat("*", 70))
}

// printHelp menjelaskan cara pakai dari dalam shell
func printHelp() {
	fmt.Println("Usage inside shell:")
	fmt.Println("  -checks W-001,W-015 -pretty")
	fmt.Println("  -checks W-016")
	fmt.Println("  -pretty")
	fmt.Println("  -output results.json")
	fmt.Println("  -checks W-001,W-020 -pretty -output scan_results.json")
	fmt.Println("Built-ins: help, exit, quit")
	fmt.Println("")
	fmt.Println("Output options:")
	fmt.Println("  -output [filename.json]  Save results to JSON file (sorted W-001 to W-020)")
	fmt.Println("  -pretty                  Format JSON with indentation")
	fmt.Println("  (no flags)               Display compact JSON to terminal")
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
