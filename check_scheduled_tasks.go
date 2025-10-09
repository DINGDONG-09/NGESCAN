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

	// Tentukan severity ringkas: naikkan ke medium jika ada indikasi resiko
	sev := SevInfo
	for _, r := range results {
		if r["unquoted"] == "true" || r["exploitable"] == "true" {
			sev = SevMed
			break
		}
	}

	desc := "Scheduled tasks collected: " + strconv.Itoa(len(results))
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

	return map[string]string{
		"task_name":         toDisplayPath(taskName),      // nama task (bisa berawalan '\')
		"command":           toDisplayPath(cmd),           // string action mentah
		"exe_path":          toDisplayPath(exe),           // path exe yang dianalisis
		"unquoted":          unquoted,                     // apakah unquoted
		"exploitable":       exploitable,                  // ada segmen writable?
		"writable_segments": strings.Join(writable, "; "), // daftar segmen writable
		"source":            "schtasks",                   // penanda jalur enumerasi
	}
}

/* ---------------------------------------------------------
   Jalur 2 (Fallback): Scan file XML di folder Tasks
   --------------------------------------------------------- */

func enumerateTasksViaXML() ([]map[string]string, error) {
	const tasksRoot = `C:\Windows\System32\Tasks`

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

		results = append(results, map[string]string{
			"task_file":         toDisplayPath(path),
			"command":           toDisplayPath(cmd + " " + args),
			"exe_path":          toDisplayPath(exe),
			"unquoted":          unquoted,
			"exploitable":       exploitable,
			"writable_segments": strings.Join(writable, "; "),
			"source":            "xml",
		})
		return nil
	})

	return results, nil
}
