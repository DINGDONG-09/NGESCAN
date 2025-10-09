//go:build windows
// +build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// W-017: IFEO & SilentProcessExit (read-only, winPEAS-style)
// ----------------------------------------------------------------------------
// Cek dua area persistence/abuse yang klasik:
// 1) IFEO (Image File Execution Options) -> value "Debugger" per image
//    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>\Debugger
// 2) SilentProcessExit -> "ReportingMode" (DWORD) & "MonitorProcess" (string)
//    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image>\
//
// Heuristik severity:
// - high  : ada IFEO Debugger terpasang
// - medium: tidak ada IFEO, tetapi ada SilentProcessExit entry
// - info  : tidak ada apa-apa / normal
//
// Catatan:
// - Hanya registry read; tidak menyentuh isi file/menulis registry.
// - Slice diinisialisasi agar JSON menghasilkan [] bukan null.
// ----------------------------------------------------------------------------

func runCheckIFEO() Finding {
	type IFEOEntry struct {
		Image    string `json:"image"`
		Debugger string `json:"debugger,omitempty"`
	}
	type SPEEntry struct {
		Image          string `json:"image"`
		ReportingMode  int    `json:"reporting_mode,omitempty"`  // 0/1/2...
		MonitorProcess string `json:"monitor_process,omitempty"` // executable yang dipanggil
	}

	data := struct {
		IFEO []IFEOEntry `json:"ifeo"`
		SPE  []SPEEntry  `json:"silent_process_exit"`
	}{
		IFEO: make([]IFEOEntry, 0),
		SPE:  make([]SPEEntry, 0),
	}

	// ---------- (1) Enumerate IFEO Debugger ----------
	ifeoRoot := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeoRoot, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE); err == nil {
		defer k.Close()
		names, _ := k.ReadSubKeyNames(0)
		for _, sub := range names {
			if sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE); err == nil {
				dbg, _, _ := sk.GetStringValue("Debugger")
				sk.Close()
				dbg = strings.TrimSpace(dbg)
				if dbg != "" {
					data.IFEO = append(data.IFEO, IFEOEntry{Image: sub, Debugger: dbg})
				}
			}
		}
	}

	// ---------- (2) Enumerate SilentProcessExit ----------
	speRoot := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	if k2, err := registry.OpenKey(registry.LOCAL_MACHINE, speRoot, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE); err == nil {
		defer k2.Close()
		names, _ := k2.ReadSubKeyNames(0)
		for _, sub := range names {
			if sk, err := registry.OpenKey(k2, sub, registry.QUERY_VALUE); err == nil {
				var modeVal uint64
				if v, _, err := sk.GetIntegerValue("ReportingMode"); err == nil {
					modeVal = v
				}
				mon, _, _ := sk.GetStringValue("MonitorProcess")
				sk.Close()

				entry := SPEEntry{Image: sub}
				if modeVal != 0 {
					entry.ReportingMode = int(modeVal)
				}
				mon = strings.TrimSpace(mon)
				if mon != "" {
					entry.MonitorProcess = mon
				}
				// Hanya tambahkan bila ada data menarik
				if entry.ReportingMode != 0 || entry.MonitorProcess != "" {
					data.SPE = append(data.SPE, entry)
				}
			}
		}
	}

	// ---------- Severity & description ----------
	sev := SevInfo
	desc := "No risky IFEO/SilentProcessExit entries found."

	if len(data.IFEO) > 0 {
		sev = SevHigh
		desc = "IFEO Debugger detected."
	} else if len(data.SPE) > 0 {
		sev = SevMed
		desc = "SilentProcessExit entries present."
	}

	return Finding{
		CheckID:     "W-017",
		Title:       "IFEO / SilentProcessExit",
		Severity:    sev,
		Description: desc,
		Data:        data,
	}
}
