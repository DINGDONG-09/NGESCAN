package main // tetap di package main agar bisa akses util di file lain

import ( // import paket yang dibutuhkan
	"strconv"
	"strings" // util olah string

	"golang.org/x/sys/windows/registry" // akses Registry Windows (read-only)
)

/*
   =========================
   Cek W-004: Autoruns Snapshot
   - Enumerasi entri startup dari:
     * HKLM\Software\Microsoft\Windows\CurrentVersion\Run
     * HKCU\Software\Microsoft\Windows\CurrentVersion\Run
     * HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
     * HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
   - Untuk setiap entri:
     * ambil command (value),
     * ekstrak exe_path (sampai ".exe"),
     * deteksi unquoted,
     * cek writable segments (potensi privesc/persistence).
   - Output: satu Finding berisi daftar entri + atribut penilaian.
   =========================
*/

// runCheckAutoruns menjalankan keseluruhan cek Autoruns
func runCheckAutoruns() Finding {
	// daftar lokasi autoruns yang akan discan
	locations := []struct {
		root registry.Key // hive (HKLM/HKCU)
		path string       // subkey path
		name string       // label lokasi untuk output
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU Run"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU RunOnce"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run (WOW6432Node)"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce (WOW6432Node)"},
	}

	// penampung semua entri hasil enumerasi
	all := make([]map[string]string, 0, 32) // kapasitas awal kecil, ringan

	// iterasi setiap lokasi
	for _, loc := range locations {
		// buka key dengan QUERY_VALUE agar read-only
		k, err := registry.OpenKey(loc.root, loc.path, registry.QUERY_VALUE)
		if err != nil {
			// kalau key tidak ada/deny, lewati saja (common case)
			continue
		}
		// pastikan key ditutup
		func() {
			defer k.Close()

			// ambil semua nama value di key (tiap value = satu autorun item)
			names, err := k.ReadValueNames(0) // 0 = ambil semua
			if err != nil {
				return
			}

			// proses setiap value
			for _, n := range names {
				// baca string value; kalau bukan string, skip
				val, _, err := k.GetStringValue(n)
				if err != nil || val == "" {
					continue
				}

				// normalisasi command (hapus spasi tepi)
				cmd := strings.TrimSpace(val)

				// ekstrak exe path (sampai ".exe"), expand %ENV%
				exe := extractExePath(cmd)   // gunakan util yang sudah ada
				exe = windowsExpandEnv(exe)  // expand %ProgramFiles% dll.
				exe = strings.Trim(exe, `"`) // buang kutip sisa

				// deteksi unquoted (spasi di segmen .exe & tanpa kutip)
				unquoted := "false"
				if isUnquotedExecutablePath(cmd) {
					unquoted = "true"
				}

				// evaluasi writable segments untuk potensi persistence/exploit
				writable := []string{}
				for _, seg := range splitPathSegments(exe) { // segmen bertingkat
					if dirIsWritable(seg) { // apakah segmen dapat ditulis user saat ini?
						writable = append(writable, toDisplayPath(seg))
					}
				}

				// set flag exploitable jika ada segmen writable
				exploitable := "false"
				if len(writable) > 0 {
					exploitable = "true"
				}

				// simpan entri (pakai forward slash untuk tampil rapi)
				all = append(all, map[string]string{
					"location":          loc.name,                     // dari key mana
					"name":              n,                            // nama value autorun
					"command":           toDisplayPath(cmd),           // command mentah (display)
					"exe_path":          toDisplayPath(exe),           // hasil ekstrak exe (display)
					"unquoted":          unquoted,                     // apakah unquoted
					"exploitable":       exploitable,                  // apakah ada segmen writable
					"writable_segments": strings.Join(writable, "; "), // daftar segmen writable (display)
				})
			}
		}()
	}

	// tentukan severity:
	// - default info; kalau ada entri unquoted ATAU exploitable, naikkan ke medium
	sev := SevInfo
	for _, it := range all {
		if it["unquoted"] == "true" || it["exploitable"] == "true" {
			sev = SevMed
			break
		}
	}

	// deskripsi ringkas jumlah entri yang ditemukan
	desc := "Autoruns collected: " + strconv.Itoa(len(all))

	// kembalikan satu Finding berisi snapshot autoruns
	return Finding{
		CheckID:     "W-004",
		Title:       "Autoruns (Run/RunOnce) Snapshot",
		Severity:    sev,
		Description: desc,
		Data:        all,
	}
}
