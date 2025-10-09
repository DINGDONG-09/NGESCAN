package main // berada di package main agar dipanggil dari main.go

import ( // import paket yang diperlukan
	"fmt" // format string untuk deskripsi

	"golang.org/x/sys/windows/registry" // akses Registry Windows (read-only)
)

/*
   =========================
   Cek W-003: UAC Policy Snapshot
   - Membaca nilai kunci UAC dari HKLM\...\Policies\System
   - Menginterpretasi nilai seperti winPEAS (EnableLUA, ConsentPrompt, dll.)
   - Menghasilkan Finding berisi nilai mentah + meaning + overall severity
   =========================
*/

// runCheckUACSnapshot mengeksekusi pembacaan UAC policy dan menyusun Finding.
func runCheckUACSnapshot() Finding {
	const ( // path registry yang kita baca
		pSystem = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	)

	// helper untuk baca DWORD; mengembalikan (nilai, ada/tidak, error)
	readDWORD := func(path, name string) (uint64, bool, error) {
		// buka key HKLM\...\System dengan hak QUERY_VALUE
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil { // jika gagal buka key
			return 0, false, err
		}
		defer k.Close() // pastikan ditutup

		// ambil nilai DWORD
		v, _, err := k.GetIntegerValue(name)
		if err != nil { // value tidak ada atau error lain
			return 0, false, nil
		}
		return v, true, nil // kembalikan nilai + flag ada=true
	}

	// baca semua nilai yang kita butuhkan
	enableLUA, hasEnableLUA, _ := readDWORD(pSystem, "EnableLUA")                              // 0=OFF, 1=ON
	consentAdmin, hasConsentAdmin, _ := readDWORD(pSystem, "ConsentPromptBehaviorAdmin")       // 0..5
	consentUser, hasConsentUser, _ := readDWORD(pSystem, "ConsentPromptBehaviorUser")          // 0..3 (di beberapa OS)
	secureDesktop, hasSecureDesktop, _ := readDWORD(pSystem, "PromptOnSecureDesktop")          // 0/1
	filterAdminToken, hasFilterAdminToken, _ := readDWORD(pSystem, "FilterAdministratorToken") // 0/1 (Admin Approval Mode utk built-in admin)

	// map interpretasi seperti yang lazim dipakai di hardening/winPEAS
	meaningConsentAdmin := map[uint64]string{
		0: "Elevate without prompting (least secure)",
		1: "Prompt for credentials on secure desktop",
		2: "Prompt for consent on secure desktop",
		3: "Prompt for credentials",
		4: "Prompt for consent",
		5: "Prompt for consent for non-Windows binaries (default-ish)",
	}
	meaningConsentUser := map[uint64]string{
		0: "Automatically deny elevation requests",
		1: "Prompt for credentials on secure desktop",
		3: "Prompt for credentials", // 2 kadang dipetakan ke 'Prompt for consent' pada edisi tertentu
	}

	// hitung severity overall (ambil yang terburuk)
	overall := SevInfo // mulai dari info

	// jika UAC OFF → critical (seperti penilaian winPEAS)
	if hasEnableLUA && enableLUA == 0 {
		overall = SevCrit
	}

	// jika UAC ON, tapi prompt terlalu permisif → naikkan severity
	if hasEnableLUA && enableLUA == 1 {
		// Admin: 0 = tanpa prompt → high
		if hasConsentAdmin && consentAdmin == 0 && overall != SevCrit {
			overall = SevHigh
		}
		// Secure Desktop dimatikan → medium (phishing UI lebih mudah)
		if hasSecureDesktop && secureDesktop == 0 && overall == SevInfo {
			overall = SevMed
		}
	}

	// susun data detail untuk output (nilai mentah + meaning agar mudah dipahami)
	detail := map[string]any{
		"EnableLUA": map[string]any{
			"value": valOrNil(hasEnableLUA, enableLUA), // tampilkan angka jika ada
			"meaning": func() string { // jelaskan artinya
				if !hasEnableLUA {
					return "not set"
				}
				if enableLUA == 0 {
					return "UAC is OFF (dangerous)"
				}
				return "UAC is ON"
			}(),
		},
		"ConsentPromptBehaviorAdmin": map[string]any{
			"value": valOrNil(hasConsentAdmin, consentAdmin),
			"meaning": func() string {
				if !hasConsentAdmin {
					return "not set"
				}
				if m, ok := meaningConsentAdmin[consentAdmin]; ok {
					return m
				}
				return fmt.Sprintf("unknown (%d)", consentAdmin)
			}(),
		},
		"ConsentPromptBehaviorUser": map[string]any{
			"value": valOrNil(hasConsentUser, consentUser),
			"meaning": func() string {
				if !hasConsentUser {
					return "not set"
				}
				if m, ok := meaningConsentUser[consentUser]; ok {
					return m
				}
				return fmt.Sprintf("unknown (%d)", consentUser)
			}(),
		},
		"PromptOnSecureDesktop": map[string]any{
			"value": valOrNil(hasSecureDesktop, secureDesktop),
			"meaning": func() string {
				if !hasSecureDesktop {
					return "not set"
				}
				if secureDesktop == 1 {
					return "prompts on secure desktop (recommended)"
				}
				return "prompts on normal desktop (less secure)"
			}(),
		},
		"FilterAdministratorToken": map[string]any{
			"value": valOrNil(hasFilterAdminToken, filterAdminToken),
			"meaning": func() string {
				if !hasFilterAdminToken {
					return "not set"
				}
				if filterAdminToken == 1 {
					return "Admin Approval Mode enabled for built-in Administrator"
				}
				return "Admin Approval Mode disabled for built-in Administrator"
			}(),
		},
	}

	// remediation singkat (hardening tips)
	remediation := "Ensure UAC is enabled (EnableLUA=1); use secure desktop (PromptOnSecureDesktop=1); avoid 'Elevate without prompting' (ConsentPromptBehaviorAdmin!=0)."

	// deskripsi ringkas untuk Finding
	desc := "UAC policy snapshot collected"

	// kembalikan Finding final
	return Finding{
		CheckID:     "W-003",
		Title:       "UAC Policy Snapshot",
		Severity:    overall,
		Description: desc,
		Data: map[string]any{ // bungkus ke dalam 'data'
			"policies":    detail,
			"remediation": remediation,
		},
	}
}

// valOrNil mengembalikan nilai jika ada; bila tidak, nil (supaya JSON rapih).
func valOrNil(has bool, v uint64) any {
	if !has {
		return nil
	}
	return v
}
