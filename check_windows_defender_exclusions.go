//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func runCheckDefenderExclusions() Finding {
	type Excl struct {
		Kind  string `json:"kind"`  // "Path" | "Process" | "Extension"
		Value string `json:"value"` // value name berisi isi exclusion
	}
	// pre-initialize agar tidak null saat di-JSON
	data := struct {
		Exclusions []Excl   `json:"exclusions"`
		Hints      []string `json:"hints,omitempty"`
	}{
		Exclusions: make([]Excl, 0),
		Hints:      make([]string, 0),
	}

	// Helper untuk baca values di subkey Exclusions\<sub>
	readExcl := func(root registry.Key, path, sub, kind string) {
		k, err := registry.OpenKey(root, path+`\`+sub, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return // tidak fatal
		}
		defer k.Close()
		names, _ := k.ReadValueNames(0)
		for _, name := range names {
			data.Exclusions = append(data.Exclusions, Excl{Kind: kind, Value: name})
		}
	}

	// Sumber 1: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\*
	base := `SOFTWARE\Microsoft\Windows Defender\Exclusions`
	readExcl(registry.LOCAL_MACHINE, base, "Paths", "Path")
	readExcl(registry.LOCAL_MACHINE, base, "Processes", "Process")
	readExcl(registry.LOCAL_MACHINE, base, "Extensions", "Extension")

	// Sumber 2 (policy): HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\*
	pol := `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`
	readExcl(registry.LOCAL_MACHINE, pol, "Paths", "Path")
	readExcl(registry.LOCAL_MACHINE, pol, "Processes", "Process")
	readExcl(registry.LOCAL_MACHINE, pol, "Extensions", "Extension")

	sev := SevInfo
	desc := "No Defender exclusions found."
	if len(data.Exclusions) > 0 {
		sev = SevMed
		desc = fmt.Sprintf("Found %d Defender exclusions.", len(data.Exclusions))
		// eskalasi heuristik
		for _, e := range data.Exclusions {
			v := strings.ToLower(e.Value)
			if v == "*" || v == `c:\` || v == `c:\*` || strings.Contains(v, `\windows\`) {
				sev = SevCrit
				data.Hints = append(data.Hints, "Wildcard or OS root excluded")
				break
			}
			if strings.Contains(v, `\program files`) || strings.Contains(v, `\programdata`) ||
				strings.Contains(v, `\windows\system32\drivers`) {
				if sev != SevCrit {
					sev = SevHigh
				}
			}
		}
	}

	return Finding{
		CheckID:     "W-015",
		Title:       "Windows Defender Exclusions",
		Severity:    sev,
		Description: desc,
		Data:        data, // sekarang exclusions selalu [] (bukan null) ketika kosong
	}
}
