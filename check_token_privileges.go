package main

import (
	"fmt"    // format string untuk deskripsi/label
	"unsafe" // parsing buffer TOKEN_PRIVILEGES

	"golang.org/x/sys/windows" // WinAPI: Token, LUID, GetTokenInformation
)

/*
   ============================================
   W-008: Token Privileges Snapshot
   - Baca access token proses saat ini (TOKEN_QUERY)
   - Ambil daftar TOKEN_PRIVILEGES
   - Map LUID -> nama privilege (SeDebugPrivilege, dll)
   - Tandai enabled/disabled (SE_PRIVILEGE_ENABLED)
   - Tentukan severity jika privilege “berbahaya” aktif
   ============================================
*/

// runCheckTokenPrivileges adalah entry utama W-008.
func runCheckTokenPrivileges() Finding {
	// --- 1) Buka token proses saat ini (read-only untuk query) ---
	// Gunakan helper kompatibel di x/sys/windows: tidak butuh GetCurrentProcess
	tok, err := windows.OpenCurrentProcessToken() // (Token, error)
	if err != nil {
		return Finding{
			CheckID:     "W-008",
			Title:       "Token Privileges Snapshot",
			Severity:    SevInfo,
			Description: "Failed to open process token",
			Data:        map[string]any{"error": err.Error()},
		}
	}
	defer tok.Close()

	// --- 2) Ambil TOKEN_PRIVILEGES (2 tahap: panjang -> isi) ---
	var needed uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &needed)

	if needed == 0 {
		return Finding{
			CheckID:     "W-008",
			Title:       "Token Privileges Snapshot",
			Severity:    SevInfo,
			Description: "No privileges found (empty token info).",
			Data:        []any{},
		}
	}

	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed); err != nil {
		return Finding{
			CheckID:     "W-008",
			Title:       "Token Privileges Snapshot",
			Severity:    SevInfo,
			Description: "Failed to query token privileges",
			Data:        map[string]any{"error": err.Error()},
		}
	}

	// --- 3) Parse buffer menjadi slice LUID+Attributes ---
	privs := parseTokenPrivileges(buf) // []windows.LUIDAndAttributes

	// --- 4) Susun hasil per privilege + penilaian risiko ---
	out := make([]map[string]string, 0, len(privs))
	hasHigh := false // privilege sangat berbahaya aktif
	hasMed := false  // privilege menengah aktif

	for _, pa := range privs {
		name := lookupPrivilegeNameCompat(pa.Luid)                     // nama "Se*"
		enabled := (pa.Attributes & windows.SE_PRIVILEGE_ENABLED) != 0 // status aktif?

		out = append(out, map[string]string{
			"name":    name,             // contoh: SeDebugPrivilege
			"enabled": boolStr(enabled), // "true"/"false"
		})

		// Penilaian risiko ala winPEAS
		if enabled {
			switch name {
			// “Potato-class” & debug → privesc kuat
			case "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege":
				hasHigh = true
			// Sensitif/berbahaya tapi sedikit lebih rendah
			case "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
				"SeLoadDriverPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege",
				"SeManageVolumePrivilege":
				hasMed = true
			}
		}
	}

	// --- 5) Tentukan severity & kembalikan hasil ---
	sev := SevInfo
	desc := fmt.Sprintf("Token privileges enumerated: %d", len(out))
	if hasHigh {
		sev = SevHigh
		desc += " (dangerous privilege enabled)"
	} else if hasMed {
		sev = SevMed
		desc += " (sensitive privilege enabled)"
	}

	return Finding{
		CheckID:     "W-008",
		Title:       "Token Privileges Snapshot",
		Severity:    sev,
		Description: desc,
		Data:        out,
	}
}

/* ===== Helpers ringkas & aman ===== */

// parseTokenPrivileges mengubah buffer TOKEN_PRIVILEGES → slice LUID+Attributes.
func parseTokenPrivileges(buf []byte) []windows.LUIDAndAttributes {
	// Header TOKEN_PRIVILEGES: { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY]; }
	type tokenPrivHeader struct{ Count uint32 }
	hdr := (*tokenPrivHeader)(unsafe.Pointer(&buf[0]))
	n := int(hdr.Count)

	out := make([]windows.LUIDAndAttributes, 0, n)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(hdr.Count)
	step := unsafe.Sizeof(windows.LUIDAndAttributes{})

	for i := 0; i < n; i++ {
		ptr := unsafe.Pointer(base + uintptr(i)*step)
		la := *(*windows.LUIDAndAttributes)(ptr)
		out = append(out, la)
	}
	return out
}

// lookupPrivilegeNameCompat: Resolve LUID -> nama privilege "Se*"
// Kompatibel untuk modul x/sys/windows yang tidak mengekspor LookupPrivilegeName.
// Menggunakan advapi32!LookupPrivilegeNameW langsung via LazySystemDLL.
func lookupPrivilegeNameCompat(luid windows.LUID) string {
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	proc := advapi.NewProc("LookupPrivilegeNameW")

	// Panggilan 1: minta panjang nama (cchName)
	var nameLen uint32 = 0
	_, _, _ = proc.Call(
		0, // LPCWSTR lpSystemName = NULL
		uintptr(unsafe.Pointer(&luid)),
		0, // LPWSTR lpName = NULL
		uintptr(unsafe.Pointer(&nameLen)),
	)
	if nameLen == 0 {
		return fmt.Sprintf("LUID(%d,%d)", luid.HighPart, luid.LowPart)
	}

	// Panggilan 2: ambil nama privilege
	buf := make([]uint16, nameLen+1)
	r1, _, _ := proc.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&nameLen)),
	)
	if r1 == 0 {
		return fmt.Sprintf("LUID(%d,%d)", luid.HighPart, luid.LowPart)
	}
	return windows.UTF16ToString(buf)
}

// boolStr mengubah bool → "true"/"false" (konsisten dengan output lain).
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
