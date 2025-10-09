// W-011: System Info Snapshot
// Mengambil info OS, komputer, uptime, arch, domain/workgroup, hostname,
// dan ringkas produk AV/EDR via SecurityCenter2 (kalau tersedia).
//
// Output disusun agar mudah diparse (array bukan string dipisah koma).
// Semua field diberi komentar agar mudah di-maintain.
//
// Build target: windows

package main

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

// --- Integrity Level helpers (RID & struct) ---

// RID untuk Mandatory Label SIDs (S-1-16-xxxx)
const (
	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x0000
	SECURITY_MANDATORY_LOW_RID               = 0x1000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x2000
	SECURITY_MANDATORY_HIGH_RID              = 0x3000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x4000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000
)

// Struktur TOKEN_MANDATORY_LABEL dari WinAPI
type tokenMandatoryLabel struct {
	Label windows.SIDAndAttributes
}

// wmi class: Win32_OperatingSystem
type wmiOS struct {
	Caption        *string // mis. "Microsoft Windows 11 Home"
	Version        *string // mis. "10.0.26100"
	BuildNumber    *string // mis. "26100"
	OSArchitecture *string // mis. "64-bit"
	InstallDate    *string // WMI datetime yyyymmddHHMMSS.mmmmmmsUUU
	LastBootUpTime *string // WMI datetime
	CSName         *string // Hostname
	RegisteredUser *string
	SerialNumber   *string
	Organization   *string
	ProductType    *uint32 // 1=Workstation, 2=Domain Controller, 3=Server
}

// wmi class: Win32_ComputerSystem
type wmiCS struct {
	Manufacturer              *string
	Model                     *string
	Domain                    *string // jika Workgroup biasanya "WORKGROUP"
	PartOfDomain              *bool
	TotalPhysicalMemory       *uint64 // bytes
	NumberOfLogicalProcessors *uint32
}

// SecurityCenter2\AntiVirusProduct (kadang butuh elevation di OS lama)
type wmiAV struct {
	DisplayName            *string
	PathToSignedProductExe *string
	ProductState           *uint32 // bitmask keadaan (enabled/uptodate dsb) — kita sajikan mentah
}

// convert WMI datetime ke time.Time (best effort)
func wmiTime(s *string) (time.Time, bool) {
	if s == nil || len(*s) < 14 {
		return time.Time{}, false
	}
	// format dasar: yyyymmddHHMMSS.mmmmmmsUUU
	str := *s
	layout := "20060102150405"
	t, err := time.Parse(layout, str[:14])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// apakah proses saat ini admin (member Administrators) — ala winPEAS
func isAdmin() bool {
	// Buka token proses
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()

	// SID Builtin\Administrators
	var sid *windows.SID
	_ = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if sid == nil {
		return false
	}
	member, err := tok.IsMember(sid)
	return err == nil && member
}
func integrityLevel() string {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return "unknown"
	}
	defer tok.Close()

	var needed uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &needed)
	if needed == 0 {
		return "unknown"
	}

	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &needed); err != nil {
		return "unknown"
	}

	tml := (*tokenMandatoryLabel)(unsafe.Pointer(&buf[0]))
	if tml == nil || tml.Label.Sid == nil {
		return "unknown"
	}

	// ⬇️ FIX: SubAuthority sekarang return 1 nilai saja
	rid := tml.Label.Sid.SubAuthority(0)

	switch rid {
	case SECURITY_MANDATORY_UNTRUSTED_RID:
		return "Untrusted"
	case SECURITY_MANDATORY_LOW_RID:
		return "Low"
	case SECURITY_MANDATORY_MEDIUM_RID:
		return "Medium"
	case SECURITY_MANDATORY_HIGH_RID:
		return "High"
	case SECURITY_MANDATORY_SYSTEM_RID:
		return "System"
	case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
		return "ProtectedProcess"
	default:
		return fmt.Sprintf("0x%x", rid)
	}
}

// runCheckSystemInfo mengumpulkan snapshot dan mengemas ke Finding
func runCheckSystemInfo() Finding {
	// --- Query WMI: OS ---
	var osRows []wmiOS
	_ = wmi.QueryNamespace(
		`SELECT Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime,CSName,RegisteredUser,SerialNumber,Organization,ProductType FROM Win32_OperatingSystem`,
		&osRows, `root\cimv2`,
	)

	// --- Query WMI: ComputerSystem ---
	var csRows []wmiCS
	_ = wmi.QueryNamespace(
		`SELECT Manufacturer,Model,Domain,PartOfDomain,TotalPhysicalMemory,NumberOfLogicalProcessors FROM Win32_ComputerSystem`,
		&csRows, `root\cimv2`,
	)

	// --- Query AV products (best-effort; bisa kosong) ---
	var avRows []wmiAV
	_ = wmi.QueryNamespace(
		`SELECT DisplayName,PathToSignedProductExe,ProductState FROM AntiVirusProduct`,
		&avRows, `root\SecurityCenter2`,
	)

	os0 := firstOS(osRows)
	cs0 := firstCS(csRows)

	data := map[string]any{
		"os": map[string]any{
			"caption":        safeS(os0.Caption),        // “Windows 11 …”
			"version":        safeS(os0.Version),        // “10.0.26100”
			"build":          safeS(os0.BuildNumber),    // “26100”
			"arch":           safeS(os0.OSArchitecture), // “64-bit”
			"product_type":   safeU32(os0.ProductType),  // 1=Workstation, 2=DC, 3=Server
			"install_time":   formatWmiTime(os0.InstallDate),
			"last_boot_time": formatWmiTime(os0.LastBootUpTime),

			// --- tambahan agar 1:1 dengan winPEAS ---
			"registered_user": safeS(os0.RegisteredUser),
			"serial_number":   safeS(os0.SerialNumber),
			"organization":    safeS(os0.Organization),
		},
		"computer": map[string]any{
			"hostname":        safeS(os0.CSName),
			"domain":          safeS(cs0.Domain),
			"part_of_domain":  safeB(cs0.PartOfDomain),
			"workgroup_mode":  !safeB(cs0.PartOfDomain),
			"manufacturer":    safeS(cs0.Manufacturer),
			"model":           safeS(cs0.Model),
			"total_mem_bytes": safeU64(cs0.TotalPhysicalMemory),
			"logical_cores":   safeU32(cs0.NumberOfLogicalProcessors),
			"go_arch":         runtime.GOARCH,
		},
		"session": map[string]any{
			"is_admin":        isAdmin(),
			"integrity_level": integrityLevel(),
		},
		"av_products": toAVList(avRows),
	}

	return Finding{
		CheckID:     "W-011",
		Title:       "System Info Snapshot",
		Severity:    SevInfo,
		Description: "Operating system and host metadata collected",
		Data:        data,
	}
}

// helpers untuk memilih elemen pertama dengan aman
func firstOS(rows []wmiOS) wmiOS {
	if len(rows) > 0 {
		return rows[0]
	}
	return wmiOS{}
}
func firstCS(rows []wmiCS) wmiCS {
	if len(rows) > 0 {
		return rows[0]
	}
	return wmiCS{}
}

// format WMI time -> RFC3339 string (atau "")
func formatWmiTime(s *string) string {
	if t, ok := wmiTime(s); ok {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}

// util konversi pointer ke nilai dengan default aman
func safeU32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}
func safeU64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// AV list jadi array map
func toAVList(rows []wmiAV) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"name":      safeS(r.DisplayName),
			"exe":       safeS(r.PathToSignedProductExe),
			"raw_state": fmt.Sprintf("0x%08x", safeU32(r.ProductState)), // kita tampilkan hex mentah
		})
	}
	return out
}
