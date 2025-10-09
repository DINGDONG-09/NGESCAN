package main

import (
	"fmt"     // format string
	"strings" // parsing CIM path

	"github.com/yusufpapurcu/wmi" // WMI client
)

/*
   =========================
   W-007: Users & Local Groups Snapshot
   - Enumerasi anggota local groups: Administrators, Remote Desktop Users, Users
   - Enumerasi seluruh local user: Name, Disabled (quick hygiene)
   - Severity naik ke "medium" bila built-in Administrator aktif (not disabled)
   =========================
*/

// model untuk Win32_GroupUser (association)
type win32GroupUser struct {
	GroupComponent string // CIM path string
	PartComponent  string // CIM path string
}

// model untuk Win32_UserAccount (local users)
type win32UserAccount struct {
	Name         *string
	Domain       *string
	Disabled     *bool
	LocalAccount *bool
	SID          *string
}

// runCheckUsersGroups adalah entry utama W-007
func runCheckUsersGroups() Finding {
	// --- 1) Kumpulkan anggota grup lokal lewat Win32_GroupUser ---
	membersByGroup := map[string][]string{
		"Administrators":       {},
		"Remote Desktop Users": {},
		"Users":                {},
	}
	var links []win32GroupUser
	errGU := wmi.QueryNamespace(`SELECT GroupComponent, PartComponent FROM Win32_GroupUser`, &links, "root\\cimv2")

	if errGU == nil {
		for _, l := range links {
			// contoh GroupComponent:
			// \\HOST\root\cimv2:Win32_Group.Domain="HOST",Name="Administrators"
			_, gName := parseCIMGroup(l.GroupComponent)
			// contoh PartComponent:
			// \\HOST\root\cimv2:Win32_UserAccount.Domain="HOST",Name="Bob"
			uDomain, uName := parseCIMUser(l.PartComponent)

			// hanya local groups (Domain sama dengan hostname—kita treat sebagai local)
			// WMI sering menulis Domain uppercase; kita bandingkan case-insensitive dengan gDomain saja.
			switch gName {
			case "Administrators", "Remote Desktop Users", "Users":
				if uName != "" { // tambahkan "DOMAIN\Name" agar jelas
					display := uName
					if uDomain != "" {
						display = fmt.Sprintf("%s\\%s", uDomain, uName)
					}
					membersByGroup[gName] = append(membersByGroup[gName], display)
				}
			}
		}
	}

	// --- 2) Snapshot semua local users (Name + Disabled) ---
	localUsers := make([]map[string]any, 0, 16)
	var users []win32UserAccount
	errUA := wmi.QueryNamespace(`SELECT Name,Domain,Disabled,LocalAccount,SID FROM Win32_UserAccount WHERE LocalAccount = TRUE`, &users, "root\\cimv2")

	adminEnabled := false
	if errUA == nil {
		for _, u := range users {
			name := safeS(u.Name)
			domain := safeS(u.Domain)
			disabled := safeB(u.Disabled)

			// flag bila built-in Administrator aktif (nama bisa dilokalisasi, tapi default "Administrator")
			if strings.EqualFold(name, "Administrator") && !disabled {
				adminEnabled = true
			}
			localUsers = append(localUsers, map[string]any{
				"user":     name,
				"domain":   domain,
				"disabled": disabled,
				"sid":      safeS(u.SID),
			})
		}
	}

	// --- 3) Tentukan severity ringkas ---
	sev := SevInfo
	desc := "Local groups & users snapshot collected"
	if adminEnabled {
		// built-in Administrator aktif → medium risk (sesuai praktik hardening)
		sev = SevMed
		desc += " (built-in Administrator is enabled)"
	}

	// --- 4) Bungkus hasil ---
	data := map[string]any{
		"groups": map[string]any{
			"Administrators":     membersByGroup["Administrators"],
			"RemoteDesktopUsers": membersByGroup["Remote Desktop Users"],
			"Users":              membersByGroup["Users"],
		},
		"local_users": localUsers,
	}

	// kalau terjadi error WMI, tetap emit informasi itu agar terlihat jelas
	if errGU != nil {
		data["group_query_error"] = errGU.Error()
	}
	if errUA != nil {
		data["user_query_error"] = errUA.Error()
	}

	return Finding{
		CheckID:     "W-007",
		Title:       "Users & Local Groups Snapshot",
		Severity:    sev,
		Description: desc,
		Data:        data,
	}
}

/* ---------- helpers ---------- */

// parseCIMGroup mengurai CIM path Win32_Group untuk dapatkan Domain & Name
func parseCIMGroup(s string) (domain, name string) {
	// contoh: ...Win32_Group.Domain="HOST",Name="Administrators"
	domain = between(s, `Domain="`, `"`)
	name = between(s, `Name="`, `"`)
	return
}

// parseCIMUser mengurai CIM path Win32_UserAccount untuk dapatkan Domain & Name
func parseCIMUser(s string) (domain, name string) {
	// contoh: ...Win32_UserAccount.Domain="HOST",Name="Bob"
	domain = between(s, `Domain="`, `"`)
	name = between(s, `Name="`, `"`)
	return
}

// between mengambil substring di antara prefix dan suffix pertama yang ditemukan
func between(s, prefix, suffix string) string {
	start := strings.Index(s, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)
	end := strings.Index(s[start:], suffix)
	if end == -1 {
		return ""
	}
	return s[start : start+end]
}
