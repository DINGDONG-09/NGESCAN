package main

import (
	"sort" // urut tanggal
	"time" // parse tanggal hotfix

	"github.com/yusufpapurcu/wmi" // WMI client
)

/*
   =========================
   Cek W-006: Hotfix / Patch Snapshot
   - Enumerasi WMI Win32_QuickFixEngineering
   - Keluarkan jumlah hotfix, KB terbaru, dan tanggal terakhir
   =========================
*/

type qfe struct {
	HotFixID    *string // mis. "KB5030219"
	InstalledOn *string // tanggal (string, format bervariasi)
}

func runCheckHotfix() Finding {
	var items []qfe
	q := "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"
	_ = wmi.QueryNamespace(q, &items, "root\\cimv2") // bila gagal, items kosong (anggap host offline)

	type entry struct {
		ID  string
		TS  time.Time
		Raw string
	}
	list := make([]entry, 0, len(items))

	// parse tanggal sebisanya (format Windows bisa berbeda-beda)
	parseDate := func(s string) time.Time {
		// coba beberapa pola umum
		layouts := []string{
			"1/2/2006", "01/02/2006", "2006-01-02",
			"02 Jan 2006", "Jan 02, 2006",
		}
		for _, L := range layouts {
			if t, err := time.Parse(L, s); err == nil {
				return t
			}
		}
		return time.Time{} // unknown
	}

	for _, it := range items {
		id := ""
		if it.HotFixID != nil {
			id = *it.HotFixID
		}
		raw := ""
		if it.InstalledOn != nil {
			raw = *it.InstalledOn
		}
		list = append(list, entry{ID: id, TS: parseDate(raw), Raw: raw})
	}

	// sort by TS desc
	sort.Slice(list, func(i, j int) bool { return list[i].TS.After(list[j].TS) })

	latestID, latestOn := "", ""
	if len(list) > 0 {
		latestID = list[0].ID
		if !list[0].TS.IsZero() {
			latestOn = list[0].TS.Format("2006-01-02")
		} else {
			latestOn = list[0].Raw
		}
	}

	data := map[string]any{
		"hotfix_count": len(list),
		"latest_kb":    latestID,
		"latest_date":  latestOn,
	}

	sev := SevInfo
	if len(list) == 0 {
		// tidak ada hotfix terdeteksi → beri sinyal hygiene buruk
		sev = SevMed
	}

	return Finding{
		CheckID:     "W-006",
		Title:       "Hotfix / Patch Snapshot",
		Severity:    sev,
		Description: "Quick summary of installed hotfixes",
		Data:        data,
	}
}
