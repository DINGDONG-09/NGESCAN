//go:build windows
// +build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// W-016: LSA / SSP Configuration (read-only)
func runCheckLSA() Finding {
	type LSAInfo struct {
		RunAsPPLEnabled        bool     `json:"run_as_ppl_enabled"`
		SecurityPackages       []string `json:"security_packages"`
		AuthenticationPackages []string `json:"authentication_packages"`
		NotificationPackages   []string `json:"notification_packages"`
		SuspiciousPackages     []string `json:"suspicious_packages"`
		WDigestKeyPresent      bool     `json:"wdigest_key_present"`
		WDigestUseLogonCred    int      `json:"wdigest_use_logon_credential"`
		Hints                  []string `json:"hints,omitempty"`
	}

	info := LSAInfo{
		SecurityPackages:       make([]string, 0),
		AuthenticationPackages: make([]string, 0),
		NotificationPackages:   make([]string, 0),
		SuspiciousPackages:     make([]string, 0),
		Hints:                  make([]string, 0),
		WDigestUseLogonCred:    0,
	}

	readMultiSZ := func(root registry.Key, path, name string) []string {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return []string{}
		}
		defer k.Close()
		vals, _, err := k.GetStringsValue(name)
		if err != nil {
			return []string{}
		}
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			v = strings.TrimSpace(v)
			// bersihkan kutip ganda/single yang mungkin tersisa
			v = strings.Trim(v, `"'`)
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}

	// (1) RunAsPPL  -> open key then k.GetIntegerValue(...)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("RunAsPPL"); err == nil {
			info.RunAsPPLEnabled = (v == 1)
		}
	}

	// (2) Paket LSA
	info.SecurityPackages = readMultiSZ(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Security Packages")
	info.AuthenticationPackages = readMultiSZ(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Authentication Packages")
	info.NotificationPackages = readMultiSZ(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "Notification Packages")

	// Heuristik sederhana
	suspKeywords := []string{"mimilib", "wdigest", "ssp", "inject", "hook"}
	for _, arr := range [][]string{info.SecurityPackages, info.AuthenticationPackages, info.NotificationPackages} {
		for _, p := range arr {
			l := strings.ToLower(p)
			for _, kw := range suspKeywords {
				if strings.Contains(l, kw) {
					info.SuspiciousPackages = append(info.SuspiciousPackages, p)
					break
				}
			}
		}
	}

	// (3) WDigest::UseLogonCredential
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, registry.QUERY_VALUE); err == nil {
		info.WDigestKeyPresent = true
		defer k.Close()
		if v, _, err := k.GetIntegerValue("UseLogonCredential"); err == nil {
			info.WDigestUseLogonCred = int(v) // 1 = berisiko
		}
	}

	sev := SevInfo
	desc := "LSA settings look normal."
	if !info.RunAsPPLEnabled {
		sev = SevHigh
		desc = "LSA RunAsPPL is disabled."
		info.Hints = append(info.Hints, "Enable RunAsPPL to harden LSASS")
	}
	if len(info.SuspiciousPackages) > 0 {
		sev = SevHigh
		if desc == "LSA settings look normal." {
			desc = "Potentially risky LSA packages present."
		} else {
			info.Hints = append(info.Hints, "Review non-default LSA packages")
		}
	}
	if info.WDigestKeyPresent && info.WDigestUseLogonCred == 1 {
		sev = SevHigh
		if desc == "LSA settings look normal." {
			desc = "WDigest UseLogonCredential is enabled."
		} else {
			info.Hints = append(info.Hints, "Disable WDigest::UseLogonCredential")
		}
	}

	return Finding{
		CheckID:     "W-016",
		Title:       "LSA / SSP Configuration",
		Severity:    sev,
		Description: desc,
		Data:        info,
	}
}
