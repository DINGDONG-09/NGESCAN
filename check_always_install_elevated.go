package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func runCheckAlwaysInstallElevated() Finding {
	const (
		hklmPath = `SOFTWARE\Policies\Microsoft\Windows\Installer`
		hkcuPath = `SOFTWARE\Policies\Microsoft\Windows\Installer`
		value    = "AlwaysInstallElevated"
	)

	readDWORD := func(root registry.Key, path, name string) (uint64, error) {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return 0, err
		}
		defer k.Close()
		v, _, err := k.GetIntegerValue(name)
		return v, err
	}

	hklm, _ := readDWORD(registry.LOCAL_MACHINE, hklmPath, value)
	hkcu, _ := readDWORD(registry.CURRENT_USER, hkcuPath, value)

	sev := SevInfo
	desc := fmt.Sprintf("HKLM=%d, HKCU=%d", hklm, hkcu)

	if hklm == 1 && hkcu == 1 {
		sev = SevCrit
		desc = "Both HKLM and HKCU AlwaysInstallElevated are 1 (CRITICAL risk)"
	} else if hklm == 1 || hkcu == 1 {
		sev = SevHigh
		desc = "One of AlwaysInstallElevated is 1 (HIGH risk)"
	}

	return Finding{
		CheckID:     "W-001",
		Title:       "AlwaysInstallElevated policy",
		Severity:    sev,
		Description: desc,
		Data: map[string]uint64{
			"HKLM": hklm,
			"HKCU": hkcu,
		},
	}
}
