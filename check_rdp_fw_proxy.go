// check_rdp_fw_proxy.go
// W-012: RDP / Firewall / Proxy Snapshot (winPEAS-style, defensive)
// Semua read-only via registry; aman & cepat.

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

/* ===================== Registry helpers ===================== */

// readDWORD: baca REG_DWORD, return (val, err)
func readDWORD(k registry.Key, name string) (uint32, error) {
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// expandEnvStrings: bungkus WinAPI ExpandEnvironmentStrings (UTF-16) → string Go
func expandEnvStrings(raw string) (string, error) {
	inPtr, err := windows.UTF16PtrFromString(raw)
	if err != nil {
		return "", err
	}

	// Langkah 1: coba dengan buffer default 32K (batas Windows: 32767 chars)
	const maxChars = 32767
	buf := make([]uint16, maxChars)
	n, err := windows.ExpandEnvironmentStrings(inPtr, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("ExpandEnvironmentStrings returned 0")
	}

	// Jika n > len(buf), alokasikan buffer pas dan panggil lagi (skenario jarang)
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		n2, err := windows.ExpandEnvironmentStrings(inPtr, &buf[0], uint32(len(buf)))
		if err != nil {
			return "", err
		}
		n = n2
	}

	// n termasuk null-terminator; UTF16ToString akan berhenti di null
	return windows.UTF16ToString(buf[:n]), nil
}

/* --- perbaiki readSZ: cek tipe; expand hanya bila EXPAND_SZ --- */

// readSZ: baca REG_SZ / REG_EXPAND_SZ; auto-expand bila EXPAND_SZ
func readSZ(k registry.Key, name string) (string, error) {
	s, typ, err := k.GetStringValue(name)
	if err != nil {
		return "", err
	}
	if typ == registry.EXPAND_SZ {
		if expanded, err := expandEnvStrings(s); err == nil {
			return expanded, nil
		}
		// fallback: kalau expand gagal, kembalikan raw
	}
	return s, nil
}

// readBINExists: cek REG_BINARY; return true jika ada & length > 0
func readBINExists(k registry.Key, name string) bool {
	b, _, err := k.GetBinaryValue(name)
	return err == nil && len(b) > 0
}

// safeOpenKey: buka key read-only; return *Key atau nil
func safeOpenKey(root registry.Key, path string) *registry.Key {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	return &k
}

/* ===================== RDP snapshot ===================== */

// mapSecurityLayer: 0=RDP, 1=Negotiate, 2=TLS
func mapSecurityLayer(v uint32) string {
	switch v {
	case 0:
		return "RDP"
	case 1:
		return "Negotiate"
	case 2:
		return "TLS"
	default:
		return fmt.Sprintf("%d", v)
	}
}

// mapMinEnc: 1=Low, 2=ClientCompatible, 3=High, 4=FIPS
func mapMinEnc(v uint32) string {
	switch v {
	case 1:
		return "Low(56-bit)"
	case 2:
		return "ClientCompatible"
	case 3:
		return "High(128-bit)"
	case 4:
		return "FIPS"
	default:
		return fmt.Sprintf("%d", v)
	}
}

// rdpLocalSnapshot: kumpulkan konfigurasi RDP dari local config
func rdpLocalSnapshot() map[string]any {
	out := map[string]any{
		"enabled":                 false, // true jika fDenyTSConnections == 0
		"nla_required":            false, // UserAuthentication == 1
		"port":                    3389,  // default port
		"allow_remote_rpc":        nil,   // opsional
		"security_layer":          map[string]any{"value": nil, "meaning": ""},
		"min_encryption_level":    map[string]any{"value": nil, "meaning": ""},
		"single_session_per_user": nil, // true/false jika ada
	}

	// HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server
	if k := safeOpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "fDenyTSConnections"); err == nil {
			out["enabled"] = (v == 0)
		}
		if v, err := readDWORD(*k, "AllowRemoteRPC"); err == nil {
			out["allow_remote_rpc"] = (v != 0)
		}
		if v, err := readDWORD(*k, "UserAuthentication"); err == nil {
			out["nla_required"] = (v == 1)
		}
		// fSingleSessionPerUser (1=single session enforced)
		if v, err := readDWORD(*k, "fSingleSessionPerUser"); err == nil {
			out["single_session_per_user"] = (v != 0)
		}
	}

	// HKLM\...\WinStations\RDP-Tcp
	if k := safeOpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "PortNumber"); err == nil && v != 0 {
			out["port"] = int(v)
		}
		if v, err := readDWORD(*k, "SecurityLayer"); err == nil {
			out["security_layer"] = map[string]any{
				"value":   v,
				"meaning": mapSecurityLayer(v),
			}
		}
		if v, err := readDWORD(*k, "MinEncryptionLevel"); err == nil {
			out["min_encryption_level"] = map[string]any{
				"value":   v,
				"meaning": mapMinEnc(v),
			}
		}
	}

	return out
}

// rdpPolicySnapshot: baca kemungkinan override via GPO (machine policy)
func rdpPolicySnapshot() map[string]any {
	out := map[string]any{}

	// Base policy key
	base := `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	if k := safeOpenKey(registry.LOCAL_MACHINE, base); k != nil {
		defer k.Close()
		// fDenyTSConnections (0=allow RDP, 1=deny)
		if v, err := readDWORD(*k, "fDenyTSConnections"); err == nil {
			out["fDenyTSConnections"] = v
			out["enabled_effective_hint"] = (v == 0) // hint: jika ter-set oleh policy
		}
		// NLA
		if v, err := readDWORD(*k, "UserAuthentication"); err == nil {
			out["UserAuthentication"] = v
		}
		// Single session
		if v, err := readDWORD(*k, "fSingleSessionPerUser"); err == nil {
			out["fSingleSessionPerUser"] = v
		}
	}

	// Policy untuk WinStations\RDP-Tcp (Port/Security)
	ws := `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\WinStations\RDP-Tcp`
	if k := safeOpenKey(registry.LOCAL_MACHINE, ws); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "PortNumber"); err == nil {
			out["PortNumber"] = v
		}
		if v, err := readDWORD(*k, "SecurityLayer"); err == nil {
			out["SecurityLayer"] = map[string]any{"value": v, "meaning": mapSecurityLayer(v)}
		}
		if v, err := readDWORD(*k, "MinEncryptionLevel"); err == nil {
			out["MinEncryptionLevel"] = map[string]any{"value": v, "meaning": mapMinEnc(v)}
		}
	}

	return out
}

/* ===================== CredSSP (AllowEncryptionOracle) ===================== */

func mapAllowEncryptionOracle(v uint32) string {
	// 0 = MitM blocked (paling aman), 1 = Fallback (mitigate), 2 = Vulnerable
	switch v {
	case 0:
		return "MitM blocked (Strict)"
	case 1:
		return "Fallback allowed (Mitigated)"
	case 2:
		return "Vulnerable (Insecure)"
	default:
		return fmt.Sprintf("%d", v)
	}
}

func credsspSnapshot() map[string]any {
	out := map[string]any{}

	// Policy path (lebih prioritas kalau ada)
	pol := `SOFTWARE\Policies\Microsoft\Windows\CredSSP\Parameters`
	if k := safeOpenKey(registry.LOCAL_MACHINE, pol); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "AllowEncryptionOracle"); err == nil {
			out["policy"] = map[string]any{
				"value":   v,
				"meaning": mapAllowEncryptionOracle(v),
			}
		}
	}

	// System path (fallback jika policy tidak ada)
	sys := `SYSTEM\CurrentControlSet\Control\SecurityProviders\CredSSP\Parameters`
	if k := safeOpenKey(registry.LOCAL_MACHINE, sys); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "AllowEncryptionOracle"); err == nil {
			out["system"] = map[string]any{
				"value":   v,
				"meaning": mapAllowEncryptionOracle(v),
			}
		}
	}

	return out
}

/* ===================== Firewall snapshot ===================== */

// countFirewallRules: jumlah value di FirewallRules key (indikasi jumlah aturan terdefinisi)
func countFirewallRules() int {
	const rulesPath = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`
	if k := safeOpenKey(registry.LOCAL_MACHINE, rulesPath); k != nil {
		defer k.Close()
		names, err := k.ReadValueNames(0) // 0 = all
		if err == nil {
			return len(names)
		}
	}
	return 0
}

// fwProfileSnapshot: status per-profile + policy override (+ ringkasan rules_count)
func fwProfileSnapshot() map[string]any {
	// Profile modern: DomainProfile, StandardProfile (Private), PublicProfile
	profiles := []string{"DomainProfile", "StandardProfile", "PublicProfile"}
	out := map[string]any{}
	base := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

	// Per-profile (local policy)
	if k := safeOpenKey(registry.LOCAL_MACHINE, base); k != nil {
		defer k.Close()
		for _, p := range profiles {
			sub := safeOpenKey(registry.LOCAL_MACHINE, base+`\`+p)
			if sub == nil {
				continue
			}
			func() {
				defer sub.Close()
				enabled := false
				if v, err := readDWORD(*sub, "EnableFirewall"); err == nil {
					enabled = (v != 0)
				}
				// DefaultInboundAction: 0=Allow, 1=Block
				inbound := ""
				if v, err := readDWORD(*sub, "DefaultInboundAction"); err == nil {
					switch v {
					case 0:
						inbound = "Allow"
					case 1:
						inbound = "Block"
					default:
						inbound = fmt.Sprintf("%d", v)
					}
				}
				out[strings.ToLower(p)] = map[string]any{
					"enabled":                enabled,
					"default_inbound_action": inbound,
				}
			}() // end sub close scope
		}
	}

	// Policy override via GPO (machine policy)
	if k := safeOpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\WindowsFirewall`); k != nil {
		defer k.Close()
		mapPol := map[string]string{
			"domain":  "DomainProfile",
			"private": "PrivateProfile",
			"public":  "PublicProfile",
		}
		for label, sub := range mapPol {
			if sk := safeOpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\WindowsFirewall\`+sub); sk != nil {
				func() {
					defer sk.Close()
					if v, err := readDWORD(*sk, "EnableFirewall"); err == nil {
						out[label+"_policy"] = map[string]any{"enable_firewall": (v != 0)}
					}
				}()
			}
		}
	}

	// Ringkasan jumlah aturan (ringan)
	out["rules_count"] = countFirewallRules()
	return out
}

/* ===================== Proxy snapshot ===================== */

// proxyPolicySnapshot: mirror kebijakan proxy di HKCU & HKLM (jika ada)
func proxyPolicySnapshot() map[string]any {
	out := map[string]any{}

	// HKCU policy
	if k := safeOpenKey(registry.CURRENT_USER, `Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`); k != nil {
		defer k.Close()
		up := map[string]any{}
		if v, err := readDWORD(*k, "ProxyEnable"); err == nil {
			up["ProxyEnable"] = (v != 0)
		}
		if s, err := readSZ(*k, "ProxyServer"); err == nil {
			up["ProxyServer"] = s
		}
		if s, err := readSZ(*k, "ProxyOverride"); err == nil {
			up["ProxyOverride"] = s
		}
		if s, err := readSZ(*k, "AutoConfigURL"); err == nil {
			up["AutoConfigURL"] = s
		}
		if v, err := readDWORD(*k, "AutoDetect"); err == nil {
			up["AutoDetect"] = (v != 0)
		}
		if len(up) > 0 {
			out["user"] = up
		}
	}

	// HKLM policy (machine-wide)
	if k := safeOpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`); k != nil {
		defer k.Close()
		mp := map[string]any{}
		if v, err := readDWORD(*k, "ProxyEnable"); err == nil {
			mp["ProxyEnable"] = (v != 0)
		}
		if s, err := readSZ(*k, "ProxyServer"); err == nil {
			mp["ProxyServer"] = s
		}
		if s, err := readSZ(*k, "ProxyOverride"); err == nil {
			mp["ProxyOverride"] = s
		}
		if s, err := readSZ(*k, "AutoConfigURL"); err == nil {
			mp["AutoConfigURL"] = s
		}
		if v, err := readDWORD(*k, "AutoDetect"); err == nil {
			mp["AutoDetect"] = (v != 0)
		}
		if len(mp) > 0 {
			out["machine"] = mp
		}
	}

	return out
}

// proxySnapshot: HKCU WinINet + policy override + WinHTTP flag
func proxySnapshot() map[string]any {
	out := map[string]any{
		"enabled":            false,
		"server":             "",
		"override":           "",
		"auto_config_url":    "",
		"auto_detect":        nil,              // bool jika ada
		"winhttp_configured": false,            // machine-level WinHTTP proxy set?
		"policy_override":    map[string]any{}, // user/machine GPO mirror
	}

	// HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings (user proxy)
	if k := safeOpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`); k != nil {
		defer k.Close()
		if v, err := readDWORD(*k, "ProxyEnable"); err == nil {
			out["enabled"] = (v != 0)
		}
		if s, err := readSZ(*k, "ProxyServer"); err == nil {
			out["server"] = s
		}
		if s, err := readSZ(*k, "ProxyOverride"); err == nil {
			out["override"] = s
		}
		if s, err := readSZ(*k, "AutoConfigURL"); err == nil {
			out["auto_config_url"] = s
		}
		// "AutoDetect" tidak selalu ada
		if v, err := readDWORD(*k, "AutoDetect"); err == nil {
			out["auto_detect"] = (v != 0)
		}
	}

	// Policy override mirror (HKCU & HKLM)
	out["policy_override"] = proxyPolicySnapshot()

	// WinHTTP proxy (system level) — indikator konfigurasi saja (ringan)
	// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings (REG_BINARY)
	if k := safeOpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`); k != nil {
		defer k.Close()
		if readBINExists(*k, "WinHttpSettings") {
			out["winhttp_configured"] = true
		}
	}

	return out
}

/* ===================== Public entry (Finding) ===================== */

func runCheckRdpFirewallProxy() Finding {
	data := map[string]any{
		"rdp_local":  rdpLocalSnapshot(),  // detail RDP (local)
		"rdp_policy": rdpPolicySnapshot(), // override via GPO jika ada
		"credssp":    credsspSnapshot(),   // AllowEncryptionOracle (policy/system)
		"firewall":   fwProfileSnapshot(), // per-profile + policy override + rules_count
		"proxy":      proxySnapshot(),     // proxy user + policy mirror + winhttp flag
	}
	return Finding{
		CheckID:     "W-012",
		Title:       "RDP / Firewall / Proxy Snapshot",
		Severity:    SevInfo,
		Description: "Collected key remote access and network policy settings (local + policy + hardening hints)",
		Data:        data,
	}
}
