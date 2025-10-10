package main // tetap di package main agar dipanggil oleh main.go

import (
	"path/filepath" // util path Windows
	"strconv"       // konversi int → string
	"strings"       // util string

	"github.com/yusufpapurcu/wmi"       // jalur utama via WMI
	"golang.org/x/sys/windows"          // akses CreateFileW & flags (uji ACL tulis)
	"golang.org/x/sys/windows/registry" // fallback enumerasi layanan via Registry
)

/*
   =========================
   Model & Util bersama
   =========================
*/

// toDisplayPath mengubah backslash Windows "\" menjadi forward slash "/"
// agar tidak di-escape di output JSON dan lebih nyaman dibaca di terminal.
func toDisplayPath(p string) string {
	// Ubah semua '\' menjadi '/'
	return strings.ReplaceAll(p, `\`, `/`)
}

// win32Service: field yang kita ambil dari WMI (HARUS match nama properti WMI)
type win32Service struct {
	Name     string  // nama service
	PathName *string // path exe (bisa null)
}

// runCheckUnquotedServicePaths:
// 1) Enumerasi service (WMI; fallback Registry).
// 2) Deteksi unquoted path.
// 3) Untuk tiap temuan → cek ACL writable di tiap segmen direktori menuju .exe.
func runCheckUnquotedServicePaths() Finding {
	// --- Enumerasi layanan via WMI dulu ---
	if bad, err := enumerateServicesViaWMI(); err == nil {
		// Perkaya tiap temuan dengan hasil ACL check
		for i := range bad {
			enrichWritableSegments(&bad[i])
		}
		return summarizeUnquotedResults(bad)
	}

	// --- Fallback: enumerasi via Registry bila WMI gagal ---
	if bad, err := enumerateServicesViaRegistry(); err == nil {
		for i := range bad {
			enrichWritableSegments(&bad[i])
		}
		return summarizeUnquotedResults(bad)
	}

	// --- Gagal total: laporkan info, jangan bikin agent crash ---
	return Finding{
		CheckID:     "W-002",
		Title:       "Unquoted service executable paths",
		Severity:    SevInfo,
		Description: "Both WMI and Registry enumeration failed",
		Data:        map[string]any{"services_seen": 0},
	}
}

// summarizeUnquotedResults: susun Finding akhir untuk W-002
func summarizeUnquotedResults(bad []map[string]string) Finding {
	sev := SevInfo                            // default: tidak ada temuan
	desc := "No unquoted service paths found" // deskripsi default

	if len(bad) > 0 { // ada temuan
		// Check if any of the unquoted paths are actually exploitable
		exploitableCount := 0
		for _, item := range bad {
			if item["exploitable"] == "true" {
				exploitableCount++
			}
		}

		if exploitableCount > 0 {
			sev = SevHigh
			desc = "Found unquoted service paths: " + strconv.Itoa(len(bad)) + " (exploitable: " + strconv.Itoa(exploitableCount) + ")"
		} else {
			sev = SevLow
			desc = "Found unquoted service paths: " + strconv.Itoa(len(bad)) + " (not exploitable - no writable segments)"
		}
	}

	return Finding{
		CheckID:     "W-002",
		Title:       "Unquoted service executable paths",
		Severity:    sev,
		Description: desc,
		Data:        bad, // setiap item sudah diperkaya writable segments
	}
}

/*
   =========================
   Jalur 1: Enumerasi via WMI
   =========================
*/

func enumerateServicesViaWMI() ([]map[string]string, error) {
	var services []win32Service                     // wadah hasil
	q := "SELECT Name, PathName FROM Win32_Service" // query WMI
	if err := wmi.QueryNamespace(q, &services, "root\\cimv2"); err != nil {
		return nil, err // biarkan caller lakukan fallback
	}

	out := make([]map[string]string, 0, 16) // hasil temuan
	for _, s := range services {
		if s.PathName == nil { // PathName kosong → skip
			continue
		}
		raw := strings.TrimSpace(*s.PathName) // bersihkan spasi
		if isUnquotedExecutablePath(raw) {    // deteksi unquoted
			out = append(out, map[string]string{
				"name": s.Name, // nama service
				"path": raw,    // path asli (mungkin ada argumen)
			})
		}
	}
	return out, nil
}

/*
   =========================
   Jalur 2: Enumerasi via Registry (fallback)
   =========================
*/

func enumerateServicesViaRegistry() ([]map[string]string, error) {
	const base = `SYSTEM\CurrentControlSet\Services` // lokasi service
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(0) // ambil semua subkey (nama service)
	if err != nil {
		return nil, err
	}

	out := make([]map[string]string, 0, 16) // hasil temuan
	for _, svc := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+svc, registry.QUERY_VALUE)
		if err != nil {
			continue // tidak bisa dibuka → lewati
		}
		val, _, err := sk.GetStringValue("ImagePath") // ambil ImagePath
		sk.Close()
		if err != nil || val == "" {
			continue
		}
		raw := strings.TrimSpace(val)
		if isUnquotedExecutablePath(raw) { // deteksi unquoted
			out = append(out, map[string]string{
				"name": svc, // pakai nama subkey sebagai nama service
				"path": raw, // path asli
			})
		}
	}
	return out, nil
}

/*
   =========================
   Analisis Exploitability (ACL)
   =========================
*/

// enrichWritableSegments:
// - Normalisasi path exe,
// - Bagi jadi segmen folder berurutan,
// - Uji setiap segmen apakah user saat ini bisa FILE_GENERIC_WRITE,
// - Tambahkan ke map: "writable_segments" (csv) dan "exploitable" (true/false).
func enrichWritableSegments(item *map[string]string) {
	raw := (*item)["path"]               // path mentah dari WMI/Registry
	exe := extractExePath(raw)           // ambil hanya sampai ".exe" (tanpa argumen)
	expanded := windowsExpandEnv(exe)    // expand %ENV%
	clean := strings.Trim(expanded, `"`) // buang kutip sisa jika ada

	dir := filepath.Clean(filepath.Dir(clean)) // direktori dari exe
	segments := splitPathSegments(dir)         // C:\ , C:\A , C:\A\B , ...

	writableList := make([]string, 0, len(segments))
	for _, seg := range segments {
		if dirIsWritable(seg) {
			// simpan VERSI DISPLAY (forward slash) agar tidak di-escape backslash
			writableList = append(writableList, toDisplayPath(seg))
		}
	}

	// tandai exploitable bila ada segmen yang writable
	exploitable := "false"
	if len(writableList) > 0 {
		exploitable = "true"
	}

	// simpan juga path versi display agar tidak double backslash di output JSON
	(*item)["exe_path"] = toDisplayPath(clean)                      // path exe yang sudah bersih (display)
	(*item)["path"] = toDisplayPath((*item)["path"])                // path asli tapi versi display
	(*item)["writable_segments"] = strings.Join(writableList, "; ") // list segmen writable (display)
	(*item)["exploitable"] = exploitable
}

// extractExePath: potong string hingga ".exe" pertama (abaikan argumen di belakang)
func extractExePath(p string) string {
	s := strings.TrimSpace(p)      // bersihkan spasi
	if strings.HasPrefix(s, `"`) { // jika diawali kutip, hapus dulu utk proses
		s = strings.Trim(s, `"`)
	}
	low := strings.ToLower(s) // untuk cari ".exe" case-insensitive
	if idx := strings.Index(low, ".exe"); idx != -1 {
		return s[:idx+4] // kembalikan sampai ".exe"
	}
	return s // fallback: kembalikan apa adanya
}

// windowsExpandEnv memanggil ExpandEnvironmentStringsW via x/sys/windows.
func windowsExpandEnv(s string) string {
	ptr, err := windows.UTF16PtrFromString(s) // ubah ke UTF-16
	if err != nil {
		return s
	}
	// Panggil sekali untuk ukuran buffer
	n, _ := windows.ExpandEnvironmentStrings(ptr, nil, 0)
	if n == 0 {
		return s
	}
	buf := make([]uint16, n)
	if _, err := windows.ExpandEnvironmentStrings(ptr, &buf[0], uint32(len(buf))); err != nil {
		return s
	}
	return windows.UTF16ToString(buf) // konversi balik ke string Go
}

// splitPathSegments: hasilkan daftar segmen bertingkat dari root → dir akhir.
func splitPathSegments(dir string) []string {
	segments := []string{}
	if dir == "" {
		return segments
	}
	// filepath.VolumeName("C:\A\B") → "C:"
	vol := filepath.VolumeName(dir)
	rest := strings.TrimPrefix(dir, vol) // sisa setelah drive
	rest = strings.TrimPrefix(rest, `\`) // hilangkan leading backslash

	// mulai dengan root drive (mis. "C:\")
	curr := vol + `\`
	segments = append(segments, curr)

	for _, part := range strings.Split(rest, `\`) {
		if part == "" {
			continue
		}
		// bangun segmen berikutnya (mis. C:\A , C:\A\B , ...)
		curr = filepath.Join(curr, part)
		segments = append(segments, curr)
	}
	return segments
}

// dirIsWritable: coba open handle direktori dengan FILE_GENERIC_WRITE tanpa menulis apa pun.
// Sukses open → writable oleh user saat ini.
func dirIsWritable(path string) bool {
	p16, err := windows.UTF16PtrFromString(path) // konversi ke UTF-16
	if err != nil {
		return false
	}
	// OPEN_EXISTING + FILE_FLAG_BACKUP_SEMANTICS → open directory
	handle, err := windows.CreateFile(
		p16,
		windows.FILE_GENERIC_WRITE, // hak tulis generik
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, // share flags aman
		nil,                                // security attrs default
		windows.OPEN_EXISTING,              // jangan buat baru
		windows.FILE_FLAG_BACKUP_SEMANTICS, // agar bisa open directory
		0,
	)
	if err == nil {
		windows.CloseHandle(handle) // tutup handle segera
		return true
	}
	return false
}

/*
   =========================
   Deteksi Unquoted
   =========================
*/

// isUnquotedExecutablePath: true bila segmen .exe mengandung spasi & tidak diawali kutip.
func isUnquotedExecutablePath(path string) bool {
	// Sudah diawali tanda kutip? → dianggap quoted (aman dari isu unquoted)
	if strings.HasPrefix(strings.TrimSpace(path), `"`) {
		return false
	}
	// Ambil segmen sampai ".exe"
	low := strings.ToLower(strings.TrimSpace(path))
	idx := strings.Index(low, ".exe")
	if idx == -1 {
		return false // tidak menunjuk exe → abaikan
	}
	exePart := strings.TrimSpace(path)[:idx+4] // segmen "...\xxx.exe"
	// Jika segmen exe mengandung spasi → rawan
	return strings.Contains(exePart, " ")
}
