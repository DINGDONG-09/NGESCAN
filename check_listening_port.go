// check_listening_port.go
// W-010: Listening & Active Ports (TCP/UDP) via Win32 IP Helper API
// Switch output: RAW (default) vs AGGREGATE via flag -aggregate

package main

import (
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

/* ===================== Win32 bindings ===================== */

var (
	modIphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procGetExtendedTcpTable        = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable        = modIphlpapi.NewProc("GetExtendedUdpTable")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	AF_INET  = 2
	AF_INET6 = 23

	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1

	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	tcpStateClosed      uint32 = 1
	tcpStateListen      uint32 = 2
	tcpStateSynSent     uint32 = 3
	tcpStateSynReceived uint32 = 4
	tcpStateEstablished uint32 = 5
	tcpStateFinWait1    uint32 = 6
	tcpStateFinWait2    uint32 = 7
	tcpStateCloseWait   uint32 = 8
	tcpStateClosing     uint32 = 9
	tcpStateLastAck     uint32 = 10
	tcpStateTimeWait    uint32 = 11
	tcpStateDeleteTCB   uint32 = 12
)

/* ===================== Flags ===================== */

var aggregateW010 bool

func init() {
	flag.BoolVar(&aggregateW010, "aggregate", false, "Aggregate socket entries for W-010")
}

/* ===================== MSDN structs ===================== */

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}
type mibTCPTableOwnerPID struct{ NumEntries uint32 }

type in6Addr struct{ Bytes [16]byte }

type mibTCP6RowOwnerPID struct {
	LocalAddr   in6Addr
	LocalScope  uint32
	LocalPort   uint32
	RemoteAddr  in6Addr
	RemoteScope uint32
	RemotePort  uint32
	State       uint32
	OwningPID   uint32
}
type mibTCP6TableOwnerPID struct{ NumEntries uint32 }

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}
type mibUDP6RowOwnerPID struct {
	LocalAddr  in6Addr
	LocalScope uint32
	LocalPort  uint32
	OwningPID  uint32
}
type mibUDPTableOwnerPID struct{ NumEntries uint32 }
type mibUDP6TableOwnerPID struct{ NumEntries uint32 }

/* ===================== Helpers ===================== */

func ntohs16(u32 uint32) uint16 {
	v := uint16(u32)
	return (v<<8)&0xff00 | (v >> 8)
}
func ip4FromUint32(u32 uint32) net.IP {
	b := (*[4]byte)(unsafe.Pointer(&u32))
	return net.IPv4(b[0], b[1], b[2], b[3])
}
func ip6FromIn6(a in6Addr) net.IP { return net.IP(a.Bytes[:]) }

func tcpStateToString(s uint32) string {
	switch s {
	case tcpStateClosed:
		return "CLOSED"
	case tcpStateListen:
		return "LISTEN"
	case tcpStateSynSent:
		return "SYN_SENT"
	case tcpStateSynReceived:
		return "SYN_RECEIVED"
	case tcpStateEstablished:
		return "ESTABLISHED"
	case tcpStateFinWait1:
		return "FIN_WAIT_1"
	case tcpStateFinWait2:
		return "FIN_WAIT_2"
	case tcpStateCloseWait:
		return "CLOSE_WAIT"
	case tcpStateClosing:
		return "CLOSING"
	case tcpStateLastAck:
		return "LAST_ACK"
	case tcpStateTimeWait:
		return "TIME_WAIT"
	case tcpStateDeleteTCB:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE_%d", s)
	}
}

func resolvePIDToImage(pid uint32) string {
	if pid == 4 {
		return "System"
	}
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == nil {
		defer windows.CloseHandle(h)
		var size uint32 = windows.MAX_PATH
		buf := make([]uint16, size)
		r1, _, _ := procQueryFullProcessImageNameW.Call(
			uintptr(h), 0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if r1 != 0 {
			name := windows.UTF16ToString(buf[:size])
			if name != "" {
				return filepath.Base(name)
			}
		}
	}
	// Fallback WMI
	if name := resolvePIDToImageFallbackWMI(pid); name != "" {
		return name
	}
	return "-"
}

func resolvePIDToImageFallbackWMI(pid uint32) string {
	var rows []struct {
		Name      *string
		ProcessId *uint32
	}
	q := fmt.Sprintf(`SELECT Name,ProcessId FROM Win32_Process WHERE ProcessId=%d`, pid)
	if err := wmi.QueryNamespace(q, &rows, `root\cimv2`); err == nil && len(rows) > 0 {
		return safeS(rows[0].Name)
	}
	return ""
}

/* ===================== IP Helper wrappers ===================== */

func getExtendedTcpTable(family, tableClass int) ([]mibTCPRowOwnerPID, []mibTCP6RowOwnerPID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(uint32(family)), uintptr(uint32(tableClass)), 0)
	if size == 0 {
		return nil, nil, nil
	}
	buf := make([]byte, size)
	r1, _, e1 := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(uint32(family)),
		uintptr(uint32(tableClass)), 0,
	)
	if r1 != 0 {
		if e1 != syscall.Errno(0) {
			return nil, nil, e1
		}
		return nil, nil, syscall.Errno(r1)
	}

	if family == AF_INET {
		t := (*mibTCPTableOwnerPID)(unsafe.Pointer(&buf[0]))
		n := int(t.NumEntries)
		rows := make([]mibTCPRowOwnerPID, 0, n)
		base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(*t)
		for i := 0; i < n; i++ {
			row := *(*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(mibTCPRowOwnerPID{})))
			rows = append(rows, row)
		}
		return rows, nil, nil
	}

	t6 := (*mibTCP6TableOwnerPID)(unsafe.Pointer(&buf[0]))
	n6 := int(t6.NumEntries)
	rows6 := make([]mibTCP6RowOwnerPID, 0, n6)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(*t6)
	for i := 0; i < n6; i++ {
		row := *(*mibTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(mibTCP6RowOwnerPID{})))
		rows6 = append(rows6, row)
	}
	return nil, rows6, nil
}

func getExtendedUdpTable(family, tableClass int) ([]mibUDPRowOwnerPID, []mibUDP6RowOwnerPID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(uint32(family)), uintptr(uint32(tableClass)), 0)
	if size == 0 {
		return nil, nil, nil
	}
	buf := make([]byte, size)
	r1, _, e1 := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, uintptr(uint32(family)),
		uintptr(uint32(tableClass)), 0,
	)
	if r1 != 0 {
		if e1 != syscall.Errno(0) {
			return nil, nil, e1
		}
		return nil, nil, syscall.Errno(r1)
	}

	if family == AF_INET {
		t := (*mibUDPTableOwnerPID)(unsafe.Pointer(&buf[0]))
		n := int(t.NumEntries)
		rows := make([]mibUDPRowOwnerPID, 0, n)
		base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(*t)
		for i := 0; i < n; i++ {
			row := *(*mibUDPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(mibUDPRowOwnerPID{})))
			rows = append(rows, row)
		}
		return rows, nil, nil
	}

	t6 := (*mibUDP6TableOwnerPID)(unsafe.Pointer(&buf[0]))
	n6 := int(t6.NumEntries)
	rows6 := make([]mibUDP6RowOwnerPID, 0, n6)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(*t6)
	for i := 0; i < n6; i++ {
		row := *(*mibUDP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(mibUDP6RowOwnerPID{})))
		rows6 = append(rows6, row)
	}
	return nil, rows6, nil
}

/* ===================== Collectors (append ke []map[string]any) ===================== */

func collectTCPv4(out *[]map[string]any) {
	rows, _, err := getExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.State != tcpStateListen {
			continue
		}
		*out = append(*out, map[string]any{
			"Protocol":     "TCP",
			"LocalAddress": ip4FromUint32(r.LocalAddr).String(),
			"LocalPort":    fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"PID":          fmt.Sprintf("%d", r.OwningPID),
			"Process":      resolvePIDToImage(r.OwningPID),
			"State":        "LISTEN",
		})
	}
}
func collectTCPv6(out *[]map[string]any) {
	_, rows6, err := getExtendedTcpTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL)
	if err != nil {
		return
	}
	for _, r := range rows6 {
		if r.State != tcpStateListen {
			continue
		}
		*out = append(*out, map[string]any{
			"Protocol":     "TCP",
			"LocalAddress": "[" + ip6FromIn6(r.LocalAddr).String() + "]",
			"LocalPort":    fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"PID":          fmt.Sprintf("%d", r.OwningPID),
			"Process":      resolvePIDToImage(r.OwningPID),
			"State":        "LISTEN",
		})
	}
}
func collectUDPv4(out *[]map[string]any) {
	rows, _, err := getExtendedUdpTable(AF_INET, UDP_TABLE_OWNER_PID)
	if err != nil {
		return
	}
	for _, r := range rows {
		*out = append(*out, map[string]any{
			"Protocol":     "UDP",
			"LocalAddress": ip4FromUint32(r.LocalAddr).String(),
			"LocalPort":    fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"PID":          fmt.Sprintf("%d", r.OwningPID),
			"Process":      resolvePIDToImage(r.OwningPID),
			"State":        "-",
		})
	}
}
func collectUDPv6(out *[]map[string]any) {
	_, rows6, err := getExtendedUdpTable(AF_INET6, UDP_TABLE_OWNER_PID)
	if err != nil {
		return
	}
	for _, r := range rows6 {
		*out = append(*out, map[string]any{
			"Protocol":     "UDP",
			"LocalAddress": "[" + ip6FromIn6(r.LocalAddr).String() + "]",
			"LocalPort":    fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"PID":          fmt.Sprintf("%d", r.OwningPID),
			"Process":      resolvePIDToImage(r.OwningPID),
			"State":        "-",
		})
	}
}

// Active TCP
func collectTCPv4Active(out *[]map[string]any) {
	rows, _, err := getExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.State == tcpStateListen {
			continue
		}
		*out = append(*out, map[string]any{
			"Protocol":      "TCP",
			"LocalAddress":  ip4FromUint32(r.LocalAddr).String(),
			"LocalPort":     fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"RemoteAddress": ip4FromUint32(r.RemoteAddr).String(),
			"RemotePort":    fmt.Sprintf("%d", ntohs16(r.RemotePort)),
			"PID":           fmt.Sprintf("%d", r.OwningPID),
			"Process":       resolvePIDToImage(r.OwningPID),
			"State":         tcpStateToString(r.State),
		})
	}
}
func collectTCPv6Active(out *[]map[string]any) {
	_, rows6, err := getExtendedTcpTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL)
	if err != nil {
		return
	}
	for _, r := range rows6 {
		if r.State == tcpStateListen {
			continue
		}
		*out = append(*out, map[string]any{
			"Protocol":      "TCP",
			"LocalAddress":  "[" + ip6FromIn6(r.LocalAddr).String() + "]",
			"LocalPort":     fmt.Sprintf("%d", ntohs16(r.LocalPort)),
			"RemoteAddress": "[" + ip6FromIn6(r.RemoteAddr).String() + "]",
			"RemotePort":    fmt.Sprintf("%d", ntohs16(r.RemotePort)),
			"PID":           fmt.Sprintf("%d", r.OwningPID),
			"Process":       resolvePIDToImage(r.OwningPID),
			"State":         tcpStateToString(r.State),
		})
	}
}

/* ===================== Public entry ===================== */

func runCheckListeningPorts() Finding {
	items := make([]map[string]any, 0, 256)

	collectTCPv4(&items)
	collectTCPv6(&items)
	collectUDPv4(&items)
	collectUDPv6(&items)
	collectTCPv4Active(&items)
	collectTCPv6Active(&items)

	if aggregateW010 {
		items = aggregateSocketEntries(items)
	}

	return Finding{
		CheckID:     "W-010",
		Title:       "Listening Ports (TCP/UDP) Snapshot",
		Severity:    SevInfo,
		Description: fmt.Sprintf("Entries: %d", len(items)),
		Data:        items,
	}
}

/* ===================== Aggregator: produce LocalAddresses []string ===================== */

func aggregateSocketEntries(in []map[string]any) []map[string]any {
	type key struct {
		Proto, Port, PID, Proc, State string
	}
	type agg struct {
		set   map[string]struct{}
		order []string
	}
	b := map[key]*agg{}
	var keys []key

	for _, it := range in {
		k := key{
			Proto: toS(it["Protocol"]),
			Port:  toS(it["LocalPort"]),
			PID:   toS(it["PID"]),
			Proc:  toS(it["Process"]),
			State: toS(it["State"]),
		}
		if _, ok := b[k]; !ok {
			b[k] = &agg{set: map[string]struct{}{}, order: []string{}}
			keys = append(keys, k)
		}
		addr := toS(it["LocalAddress"])
		if _, ok := b[k].set[addr]; !ok {
			b[k].set[addr] = struct{}{}
			b[k].order = append(b[k].order, addr)
		}
	}

	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		first := ""
		if len(b[k].order) > 0 {
			first = b[k].order[0]
		}
		// array asli:
		addrs := make([]string, len(b[k].order))
		copy(addrs, b[k].order)

		out = append(out, map[string]any{
			"Protocol":           k.Proto,
			"LocalAddress":       first, // back-compat
			"ListoflocalAddress": addrs, // ARRAY JSON
			"LocalPort":          k.Port,
			"PID":                k.PID,
			"Process":            k.Proc,
			"State":              k.State,
		})
	}
	return out
}

// toS: interface{} -> string untuk aggregator
func toS(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}
