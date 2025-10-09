package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

/*
   W-009: Network Snapshot (enhanced)
   - Adapter aktif (IPEnabled=TRUE)
   - IPv4/IPv6 per-IP dalam CIDR (x.x.x.x/nn, ::/nn)
   - DNS servers & gateways sebagai array
   - DHCP detail: DHCPServer, LeaseObtained, LeaseExpires
   - ConnectionStatus (Win32_NetworkAdapter) + primary_nic (default route)
*/

// Win32_NetworkAdapterConfiguration subset
type win32NAC struct {
	Description          *string
	SettingID            *string // GUID
	IPEnabled            *bool
	IPAddress            *[]string
	IPSubnet             *[]string // selaras dengan IPAddress
	DefaultIPGateway     *[]string
	DNSServerSearchOrder *[]string
	DHCPEnabled          *bool
	DHCPServer           *string
	DHCPLeaseObtained    *time.Time `wmi:"DHCPLeaseObtained"`
	DHCPLeaseExpires     *time.Time `wmi:"DHCPLeaseExpires"`
}

// Win32_ComputerSystem subset
type win32ComputerSystem struct {
	DNSHostName *string
	Domain      *string
	Workgroup   *string
}

// Win32_NetworkAdapter subset (untuk ConnectionStatus)
type win32NA struct {
	GUID                *string
	NetConnectionStatus *uint16
}

func runCheckNetworkSnapshot() Finding {
	// ---- 1) Info sistem (hostname/domain/workgroup)
	sysInfo := map[string]string{"hostname": "", "domain": "", "workgroup": ""}
	var cs []win32ComputerSystem
	_ = wmi.QueryNamespace(`SELECT DNSHostName,Domain,Workgroup FROM Win32_ComputerSystem`, &cs, "root\\cimv2")
	if len(cs) > 0 {
		sysInfo["hostname"] = safeS(cs[0].DNSHostName)
		sysInfo["domain"] = safeS(cs[0].Domain)
		sysInfo["workgroup"] = safeS(cs[0].Workgroup)
	}

	// ---- 2) Adapter IPEnabled=TRUE
	var rows []win32NAC
	_ = wmi.QueryNamespace(
		`SELECT Description,SettingID,IPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,
		        DHCPEnabled,DHCPServer,DHCPLeaseObtained,DHCPLeaseExpires
		 FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE`,
		&rows, "root\\cimv2",
	)

	// ---- 3) Ambil ConnectionStatus per GUID
	guidList := make([]string, 0, len(rows))
	for _, r := range rows {
		if g := safeS(r.SettingID); g != "" {
			guidList = append(guidList, g)
		}
	}
	statusMap := map[string]string{}
	if len(guidList) > 0 {
		var na []win32NA
		// Query all and map by GUID (beberapa WMI tidak mendukung IN (...), jadi baca semua dan map manual)
		_ = wmi.QueryNamespace(`SELECT GUID,NetConnectionStatus FROM Win32_NetworkAdapter`, &na, "root\\cimv2")
		for _, n := range na {
			statusMap[safeS(n.GUID)] = mapNetConnStatus(n.NetConnectionStatus)
		}
	}

	// ---- 4) Bangun output adapter
	adapters := make([]map[string]any, 0, len(rows))

	// Penentu primary_nic: tandai NIC pertama yang punya default gateway
	primaryMarked := false

	for _, r := range rows {
		guid := safeS(r.SettingID)

		ips := joinS(r.IPAddress)
		snets := joinS(r.IPSubnet)
		dnss := joinS(r.DNSServerSearchOrder)
		gws := joinS(r.DefaultIPGateway)

		// Konversi IP + subnet → CIDR
		ipv4CIDR, ipv6CIDR := pairIPwithSubnet(ips, snets)

		// Primary NIC: pertama yang memiliki default gateway
		isPrimary := false
		if !primaryMarked && len(gws) > 0 {
			isPrimary = true
			primaryMarked = true
		}

		adapters = append(adapters, map[string]any{
			"description":    safeS(r.Description),
			"guid":           guid,
			"connection":     statusMap[guid],
			"primary_nic":    isPrimary,
			"dhcp_enabled":   safeB(r.DHCPEnabled),
			"dhcp_server":    safeS(r.DHCPServer),
			"lease_obtained": formatTimePtr(r.DHCPLeaseObtained),
			"lease_expires":  formatTimePtr(r.DHCPLeaseExpires),
			"ipv4":           ipv4CIDR, // []string
			"ipv6":           ipv6CIDR, // []string
			"subnets":        snets,    // []string original (opsional untuk transparansi)
			"gateways":       gws,      // []string
			"dns_servers":    dnss,     // []string
		})
	}

	sev := SevInfo
	desc := "Network adapters collected: " + strconv.Itoa(len(adapters))
	data := map[string]any{"system": sysInfo, "adapters": adapters}

	return Finding{
		CheckID:     "W-009",
		Title:       "Network Snapshot",
		Severity:    sev,
		Description: desc,
		Data:        data,
	}
}

/* ---------- helpers khusus modul ---------- */

// mapNetConnStatus: konversi NetConnectionStatus ke label
func mapNetConnStatus(p *uint16) string {
	if p == nil {
		return ""
	}
	switch *p {
	case 0:
		return "Disconnected"
	case 1:
		return "Connecting"
	case 2:
		return "Connected"
	case 3:
		return "Disconnecting"
	case 4:
		return "Hardware not present"
	case 5:
		return "Hardware disabled"
	case 6:
		return "Hardware malfunction"
	case 7:
		return "Media disconnected"
	case 8:
		return "Authenticating"
	case 9:
		return "Authentication succeeded"
	case 10:
		return "Authentication failed"
	case 11:
		return "Invalid address"
	case 12:
		return "Credentials required"
	default:
		return "Unknown(" + strconv.Itoa(int(*p)) + ")"
	}
}

// pairIPwithSubnet: pasangkan IP+Subnet, hasilkan slice IPv4 CIDR & IPv6 CIDR
func pairIPwithSubnet(ips, subnets []string) (ipv4CIDR []string, ipv6CIDR []string) {
	ipv4CIDR = []string{}
	ipv6CIDR = []string{}

	// Subnet list biasanya sejajar dengan IPAddress
	for i, ip := range ips {
		var mask string
		if i < len(subnets) {
			mask = subnets[i]
		}
		if strings.Contains(ip, ":") { // IPv6
			prefix := "64"
			if mask != "" {
				// WMI untuk IPv6 biasanya sudah "64"
				prefix = mask
			}
			ipv6CIDR = append(ipv6CIDR, ip+"/"+prefix)
			continue
		}

		// IPv4
		prefix := "32"
		if mask != "" {
			if p, err := ipv4MaskToPrefix(mask); err == nil {
				prefix = strconv.Itoa(p)
			}
		}
		ipv4CIDR = append(ipv4CIDR, ip+"/"+prefix)
	}
	return
}

// ipv4MaskToPrefix: "255.255.255.0" -> 24
func ipv4MaskToPrefix(mask string) (int, error) {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0, ErrInvalidMask
	}
	ip = ip.To4()
	if ip == nil {
		return 0, ErrInvalidMask
	}
	ones := 0
	for _, b := range ip {
		switch b {
		case 255:
			ones += 8
		case 254:
			ones += 7
		case 252:
			ones += 6
		case 248:
			ones += 5
		case 240:
			ones += 4
		case 224:
			ones += 3
		case 192:
			ones += 2
		case 128:
			ones += 1
		case 0:
			// nothing
		default:
			return 0, ErrInvalidMask
		}
	}
	return ones, nil
}

var ErrInvalidMask = &net.ParseError{Type: "IP mask", Text: "invalid IPv4 mask"}
