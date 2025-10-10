//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// W-018: Service Binary Writable Paths (read-only, winPEAS-style)
// -----------------------------------------------------------------------------
// Tujuan:
// - Enumerasi semua service (HKLM\SYSTEM\CurrentControlSet\Services\*)
// - Ambil ImagePath -> expand env, buang quotes, potong argumen
// - Cek apakah file EXE atau folder yang menampungnya writable oleh user saat ini
//   (tanpa menulis apapun; kita hanya membuka handle GENERIC_WRITE).
//
// Severity:
// - "high" jika ada service dengan file/dir writable (potensi hijack/persistence)
// - "info" jika tidak ada temuan
//
// Catatan:
// - Tidak ada write/modify; murni open handle untuk permission check.
// - Slice diinisialisasi agar JSON [] (bukan null).
// -----------------------------------------------------------------------------

func runCheckServiceBinaryACL() Finding {
	type Entry struct {
		Service      string `json:"service"`         // nama service (subkey)
		ImagePathRaw string `json:"image_path_raw"`  // nilai ImagePath asli dari registry
		Path         string `json:"normalized_path"` // hasil normalisasi (tanpa argumen, env expanded)
		FileExists   bool   `json:"file_exists"`
		FileWritable bool   `json:"file_writable"`
		DirWritable  bool   `json:"dir_writable"`
	}
	data := struct {
		Writable []Entry `json:"writable"`
		Sample   []Entry `json:"sample,omitempty"` // contoh non-writable utk kontekstual
	}{
		Writable: make([]Entry, 0),
		Sample:   make([]Entry, 0),
	}

	// Buka registry services
	root, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return Finding{
			CheckID:     "W-018",
			Title:       "Service Binary Writable Paths",
			Severity:    SevInfo,
			Description: "Failed to open Services registry.",
			Data:        data,
		}
	}
	defer root.Close()

	names, _ := root.ReadSubKeyNames(0)
	for _, svc := range names {
		sk, err := registry.OpenKey(root, svc, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		img, _, _ := sk.GetStringValue("ImagePath") // bisa kosong untuk driver/tipo layanan tertentu
		sk.Close()
		if strings.TrimSpace(img) == "" {
			continue
		}

		normalized := normalizeExecutablePath(img)
		if normalized == "" {
			continue
		}

		// Cek keberadaan file dan writability
		st, err := os.Stat(normalized)
		exists := (err == nil && !st.IsDir())
		fileWritable := false
		dirWritable := false
		if exists {
			fileWritable = canWriteFile(normalized)
		}
		dirWritable = canWriteDir(filepath.Dir(normalized))

		e := Entry{
			Service:      svc,
			ImagePathRaw: img,
			Path:         normalized,
			FileExists:   exists,
			FileWritable: fileWritable,
			DirWritable:  dirWritable,
		}
		if fileWritable || dirWritable {
			data.Writable = append(data.Writable, e)
		} else if len(data.Sample) < 10 {
			data.Sample = append(data.Sample, e)
		}
	}

	sev := SevInfo
	desc := "No writable service binaries or directories detected."
	if len(data.Writable) > 0 {
		// Check if any writable services are actually exploitable (non-system services)
		criticalCount := 0
		for _, entry := range data.Writable {
			serviceName := strings.ToLower(entry.Service)
			binaryPath := strings.ToLower(entry.Path)

			// Skip Windows system services that are less likely to be exploitable
			isSystemService := strings.Contains(binaryPath, "\\windows\\system32\\") ||
				strings.Contains(binaryPath, "\\windows\\syswow64\\") ||
				strings.Contains(serviceName, "windows") ||
				strings.Contains(serviceName, "microsoft")

			if !isSystemService {
				criticalCount++
			}
		}

		if criticalCount > 0 {
			sev = SevHigh
			desc = fmt.Sprintf("Writable service binary paths found (%d critical, %d total).", criticalCount, len(data.Writable))
		} else {
			sev = SevMed
			desc = fmt.Sprintf("Writable service binary paths found (%d system services).", len(data.Writable))
		}
	}

	return Finding{
		CheckID:     "W-018",
		Title:       "Service Binary Writable Paths",
		Severity:    sev,
		Description: desc,
		Data:        data,
	}
}

// normalizeExecutablePath:
// - Trim spasi & kutip
// - Hilangkan argumen (ambil token pertama bila itu *.exe)
// - Expand env var (%SystemRoot%, %ProgramFiles%, dll)
var rePctVar = regexp.MustCompile(`%([^%]+)%`)

// expandWindowsEnv mengganti %VAR% (case-insensitive) menjadi nilai env Windows.
func expandWindowsEnv(p string) string {
	return rePctVar.ReplaceAllStringFunc(p, func(m string) string {
		name := m[1 : len(m)-1] // buang % %
		// coba berbagai case
		if v := os.Getenv(name); v != "" {
			return v
		}
		if v := os.Getenv(strings.ToUpper(name)); v != "" {
			return v
		}
		if v := os.Getenv(strings.ToLower(name)); v != "" {
			return v
		}
		return m // kalau ga ketemu, biarkan apa adanya
	})
}

// stripNTNamespace membuang prefix NT seperti \??\
func stripNTNamespace(p string) string {
	lp := strings.ToLower(p)
	if strings.HasPrefix(lp, `\??\`) {
		return p[4:]
	}
	return p
}

// substituteSystemRoot meng-handle path relatif khas Windows (SystemRoot, System32)
func substituteSystemRoot(p string) string {
	lp := strings.ToLower(p)
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	switch {
	case strings.HasPrefix(lp, `\systemroot\`):
		return filepath.Join(sysRoot, p[len(`\SystemRoot\`):])
	case strings.HasPrefix(lp, `system32\`):
		return filepath.Join(sysRoot, `System32`, p[len(`system32\`):])
	}
	return p
}

// normalizeExecutablePath:
// - Trim kutip & spasi
// - Ambil token pertama jika mengandung argumen
// - Expand %ENV% (Windows), handle \SystemRoot, System32 relatif, dan buang \??\
// - Kembalikan path yang dibersihkan
func normalizeExecutablePath(img string) string {
	s := strings.TrimSpace(img)
	s = strings.Trim(s, `"`)
	// Potong argumen jika token pertama .exe
	if i := strings.IndexAny(s, " \t"); i > 0 && strings.HasSuffix(strings.ToLower(s[:i]), ".exe") {
		s = s[:i]
	}
	// Expand urut: %VAR% → \SystemRoot/System32 → buang \??\
	s = expandWindowsEnv(s)
	s = substituteSystemRoot(s)
	s = stripNTNamespace(s)
	// Bersihkan separator/.. dsb
	s = filepath.Clean(s)
	return s
}

// canWriteFile: buka file EXISTING dengan GENERIC_WRITE (tanpa menulis).
func canWriteFile(path string) bool {
	p16, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p16,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0)
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return false
}

// canWriteDir: buka directory handle dengan GENERIC_WRITE (non-destructive).
func canWriteDir(path string) bool {
	p16, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p16,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return false
}
