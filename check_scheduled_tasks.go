package main

import (
	"bufio"        // scanner baris demi baris
	"bytes"        // buffer hasil exec
	"encoding/xml" // parser XML (fallback)
	"os"           // baca file, cek error
	"os/exec"      // menjalankan schtasks.exe
	"path/filepath"
	"strconv" // untuk itoa
	"strings"
)

/*
   ==========================================================
   W-005: Scheduled Tasks Snapshot (ala winPEAS)
   - Jalur UTAMA:    `schtasks /query /fo LIST /v`
     * Hasil schtasks mencakup SEMUA task (termasuk subfolder Microsoft)
     * Ekstrak "TaskName", "Task To Run" (versi lama) atau "Actions" (versi baru)
   - Jalur FALLBACK: parse file XML di C:\Windows\System32\Tasks\**
     * Berguna jika schtasks diblokir/ tidak tersedia

   Untuk tiap task:
     - Bangun exe_path dari command (hingga ".exe")
     - Deteksi unquoted (spasi tanpa tanda kutip)
     - Cek ACL writability tiap segmen folder menuju exe (potensi exploit)
   ==========================================================
*/

// Struktur minimal untuk fallback XML
type taskXML struct {
	XMLName xml.Name `xml:"Task"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// runCheckScheduledTasks: entry utama W-005
func runCheckScheduledTasks() Finding {
	// Pertama, coba enumerasi via schtasks (cara winPEAS)
	results, err := enumerateTasksViaSchtasks()
	if err != nil {
		// Kalau schtasks gagal (policy, PATH, dll), jatuh ke fallback XML
		results, _ = enumerateTasksViaXML()
	}

	// Tentukan severity berdasarkan analisis yang lebih cerdas
	sev := SevInfo
	exploitableCount := 0
	suspiciousCount := 0

	for _, r := range results {
		taskName := strings.ToLower(r["task_name"])
		exePath := strings.ToLower(strings.ReplaceAll(r["exe_path"], "/", "\\"))
		command := strings.ToLower(strings.ReplaceAll(r["command"], "/", "\\"))

		// Skip legitimate Windows system tasks and user applications
		isSystemTask := strings.Contains(taskName, "\\microsoft\\") ||
			strings.Contains(taskName, "\\windows\\") ||
			strings.Contains(exePath, "\\windows\\system32\\") ||
			strings.Contains(exePath, "\\windows\\syswow64\\") ||
			strings.Contains(exePath, "\\program files\\") ||
			strings.Contains(exePath, "\\program files (x86)\\") ||
			command == "com handler" // COM handlers are system tasks

		// User applications in AppData are also considered legitimate
		isUserApp := strings.Contains(exePath, "\\users\\") &&
			(strings.Contains(exePath, "\\appdata\\local\\programs\\") ||
				strings.Contains(exePath, "\\appdata\\roaming\\"))

		isLegitimate := isSystemTask || isUserApp

		if r["exploitable"] == "true" {
			if !isLegitimate {
				// Non-legitimate task that's exploitable = suspicious
				suspiciousCount++
			} else {
				// Legitimate task that appears exploitable = likely false positive, just count
				exploitableCount++
			}
		}

		if r["unquoted"] == "true" && !isLegitimate {
			// Unquoted non-legitimate path = suspicious
			suspiciousCount++
		}
	}

	// Set severity based on suspicious findings, not just any exploitable finding
	if suspiciousCount > 0 {
		sev = SevMed
	}

	desc := "Scheduled tasks collected: " + strconv.Itoa(len(results))
	if suspiciousCount > 0 {
		desc += " (" + strconv.Itoa(suspiciousCount) + " suspicious, " + strconv.Itoa(exploitableCount) + " system exploitable)"
	}
	return Finding{
		CheckID:     "W-005",
		Title:       "Scheduled Tasks Snapshot",
		Severity:    sev,
		Description: desc,
		Data:        results,
	}
}

/* ---------------------------------------------------------
   Jalur 1 (Utama): SCHTASKS
   --------------------------------------------------------- */

func enumerateTasksViaSchtasks() ([]map[string]string, error) {
	// Perintah setara winPEAS: LIST + verbose → memunculkan semua task & action
	cmd := exec.Command("schtasks", "/query", "/fo", "LIST", "/v")

	// Jalankan dan ambil stdout
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out // kalau ada warning, tetap kita baca
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Parse output LIST /v:
	// - Setiap task dipisah oleh baris kosong
	// - Field penting:
	//   * "TaskName:"   → nama task (mis: \Microsoft\Windows\Defrag\ScheduledDefrag)
	//   * "Task To Run:" (Windows lama)  atau
	//   * "Actions:"     (Windows baru): biasanya "C:\path\app.exe args"
	type curTask struct {
		name string
		act  string
	}
	cur := curTask{}
	results := make([]map[string]string, 0, 128)

	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			// End of one block → commit jika ada nama/aksi
			if cur.name != "" || cur.act != "" {
				results = append(results, analyzeTask(cur.name, cur.act))
				cur = curTask{}
			}
			continue
		}

		// Normalisasi kunci (case-insensitive)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "taskname:"):
			// Format: "TaskName:   \Foo\Bar"
			cur.name = strings.TrimSpace(line[len("TaskName:"):])
		case strings.HasPrefix(lower, "task to run:"):
			// Format: "Task To Run:  C:\...\app.exe /arg"
			cur.act = strings.TrimSpace(line[len("Task To Run:"):])
		case strings.HasPrefix(lower, "actions:"):
			// Format: "Actions:  C:\...\app.exe /arg"
			cur.act = strings.TrimSpace(line[len("Actions:"):])
		}
	}
	// Commit blok terakhir bila tidak diakhiri blank line
	if cur.name != "" || cur.act != "" {
		results = append(results, analyzeTask(cur.name, cur.act))
	}

	return results, nil
}

// analyzeTask: olah satu task hasil schtasks → map hasil dengan analisa risiko
func analyzeTask(taskName, action string) map[string]string {
	// Bangun "command" gabungan yang ramah baca
	cmd := strings.TrimSpace(action)
	// Ekstrak exe path (hingga ".exe"), expand env, trim kutip
	exe := extractExePath(cmd)
	exe = windowsExpandEnv(exe)
	exe = strings.Trim(exe, `"`)

	// Deteksi unquoted pada string asli action
	unquoted := "false"
	if isUnquotedExecutablePath(cmd) {
		unquoted = "true"
	}

	// Cek folder writable di setiap segmen
	writable := []string{}
	for _, seg := range splitPathSegments(exe) {
		if dirIsWritable(seg) {
			writable = append(writable, toDisplayPath(seg))
		}
	}

	exploitable := "false"
	if len(writable) > 0 {
		exploitable = "true"
	}

	// Determine if this is a legitimate task (system or user app)
	taskNameLower := strings.ToLower(taskName)
	exeLower := strings.ToLower(strings.ReplaceAll(exe, "/", "\\"))
	cmdLower := strings.ToLower(strings.ReplaceAll(cmd, "/", "\\"))
	isSystemTask := strings.Contains(taskNameLower, "\\microsoft\\") ||
		strings.Contains(taskNameLower, "\\windows\\") ||
		strings.Contains(exeLower, "\\windows\\system32\\") ||
		strings.Contains(exeLower, "\\windows\\syswow64\\") ||
		strings.Contains(exeLower, "\\program files\\") ||
		strings.Contains(exeLower, "\\program files (x86)\\") ||
		cmdLower == "com handler" // COM handlers are system tasks

	// User applications in AppData are also considered legitimate
	isUserApp := strings.Contains(exeLower, "\\users\\") &&
		(strings.Contains(exeLower, "\\appdata\\local\\programs\\") ||
			strings.Contains(exeLower, "\\appdata\\roaming\\"))

	isLegitimate := isSystemTask || isUserApp

	return map[string]string{
		"task_name":         toDisplayPath(taskName),          // nama task (bisa berawalan '\')
		"command":           toDisplayPath(cmd),               // string action mentah
		"exe_path":          toDisplayPath(exe),               // path exe yang dianalisis
		"unquoted":          unquoted,                         // apakah unquoted
		"exploitable":       exploitable,                      // ada segmen writable?
		"is_system_task":    strconv.FormatBool(isLegitimate), // legitimate task (system or user app)?
		"writable_segments": strings.Join(writable, "; "),     // daftar segmen writable
		"source":            "schtasks",                       // penanda jalur enumerasi
	}
}

/* ---------------------------------------------------------
   Jalur 2 (Fallback): Scan file XML di folder Tasks
   --------------------------------------------------------- */

func enumerateTasksViaXML() ([]map[string]string, error) {
	// Use WINDIR environment variable instead of hardcoded C:\Windows
	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = os.Getenv("SystemRoot")
		if winDir == "" {
			winDir = `C:\Windows` // fallback only
		}
	}
	tasksRoot := filepath.Join(winDir, "System32", "Tasks")

	results := make([]map[string]string, 0, 64)

	filepath.Walk(tasksRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		// Baca isi file task (XML)
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return nil
		}
		// Parse XML minimal
		var t taskXML
		if xml.Unmarshal(data, &t) != nil {
			return nil
		}

		cmd := strings.TrimSpace(t.Actions.Exec.Command)
		args := strings.TrimSpace(t.Actions.Exec.Arguments)
		if cmd == "" {
			return nil
		}

		exe := extractExePath(strings.TrimSpace(cmd + " " + args))
		exe = windowsExpandEnv(exe)
		exe = strings.Trim(exe, `"`)

		unquoted := "false"
		if isUnquotedExecutablePath(cmd + " " + args) {
			unquoted = "true"
		}

		writable := []string{}
		for _, seg := range splitPathSegments(exe) {
			if dirIsWritable(seg) {
				writable = append(writable, toDisplayPath(seg))
			}
		}
		exploitable := "false"
		if len(writable) > 0 {
			exploitable = "true"
		}

		// Determine if this is a legitimate task (system or user app)
		taskNameLower := strings.ToLower(path)
		exeLower := strings.ToLower(strings.ReplaceAll(exe, "/", "\\"))
		cmdLower := strings.ToLower(strings.ReplaceAll(cmd+" "+args, "/", "\\"))
		isSystemTask := strings.Contains(taskNameLower, "\\microsoft\\") ||
			strings.Contains(taskNameLower, "\\windows\\") ||
			strings.Contains(exeLower, "\\windows\\system32\\") ||
			strings.Contains(exeLower, "\\windows\\syswow64\\") ||
			strings.Contains(exeLower, "\\program files\\") ||
			strings.Contains(exeLower, "\\program files (x86)\\") ||
			cmdLower == "com handler" // COM handlers are system tasks

		// User applications in AppData are also considered legitimate
		isUserApp := strings.Contains(exeLower, "\\users\\") &&
			(strings.Contains(exeLower, "\\appdata\\local\\programs\\") ||
				strings.Contains(exeLower, "\\appdata\\roaming\\"))

		isLegitimate := isSystemTask || isUserApp

		results = append(results, map[string]string{
			"task_file":         toDisplayPath(path),
			"command":           toDisplayPath(cmd + " " + args),
			"exe_path":          toDisplayPath(exe),
			"unquoted":          unquoted,
			"exploitable":       exploitable,
			"is_system_task":    strconv.FormatBool(isLegitimate),
			"writable_segments": strings.Join(writable, "; "),
			"source":            "xml",
		})
		return nil
	})

	return results, nil
}
