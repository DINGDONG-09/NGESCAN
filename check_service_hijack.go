// check_service_hijack.go
// W-014: Service / Driver Hijackability (winPEAS-style, defensive, no touch)

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

/* =========================
   Win32: SCM & Security
   ========================= */

// ⚠️ JANGAN redeclare modAdvapi32 / procAccessCheck / genericMapping di sini
// karena sudah ada di check_path_writable.go (satu package main).
// Kita hanya butuh tambahan proc SCM/Service.

var (
	procOpenSCManagerW             = modAdvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW               = modAdvapi32.NewProc("OpenServiceW")
	procCloseServiceHandle         = modAdvapi32.NewProc("CloseServiceHandle")
	procQueryServiceObjectSecurity = modAdvapi32.NewProc("QueryServiceObjectSecurity")
)

// SC_MANAGER access rights
const (
	SC_MANAGER_CONNECT = 0x0001
)

// SERVICE access rights (subset)
const (
	SERVICE_QUERY_CONFIG         = 0x0001
	SERVICE_CHANGE_CONFIG        = 0x0002
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	SERVICE_START                = 0x0010
	SERVICE_STOP                 = 0x0020
	SERVICE_PAUSE_CONTINUE       = 0x0040
	SERVICE_INTERROGATE          = 0x0080
	SERVICE_USER_DEFINED_CONTROL = 0x0100
)

// mapping generik → specific untuk SERVICE object (sesuai MSDN)
func serviceGenericMapping() genericMapping {
	return genericMapping{
		GenericRead:    uint32(windows.READ_CONTROL | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS),
		GenericWrite:   uint32(windows.READ_CONTROL | SERVICE_CHANGE_CONFIG),
		GenericExecute: uint32(windows.READ_CONTROL | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL),
		GenericAll: uint32(windows.STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS |
			SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL),
	}
}

// openSCM: buka Service Control Manager (read-only)
func openSCM() (windows.Handle, error) {
	h, _, e := procOpenSCManagerW.Call(
		0, // local
		0, // ServicesActive
		uintptr(SC_MANAGER_CONNECT),
	)
	if h == 0 {
		if e != syscall.Errno(0) {
			return 0, e
		}
		return 0, syscall.EINVAL
	}
	return windows.Handle(h), nil
}

// openServiceRO: buka handle service untuk READ_CONTROL
func openServiceRO(scm windows.Handle, name string) (windows.Handle, error) {
	pName, _ := windows.UTF16PtrFromString(name)
	h, _, e := procOpenServiceW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(pName)),
		uintptr(windows.READ_CONTROL),
	)
	if h == 0 {
		if e != syscall.Errno(0) {
			return 0, e
		}
		return 0, syscall.EINVAL
	}
	return windows.Handle(h), nil
}

// closeServiceHandle: tutup handle
func closeServiceHandle(h windows.Handle) {
	if h != 0 {
		procCloseServiceHandle.Call(uintptr(h))
	}
}

// queryServiceSD: ambil SD (DACL) service ke buffer Go
func queryServiceSD(svc windows.Handle) (*byte, error) {
	var needed uint32
	// fase 1: ukur
	r0, _, _ := procQueryServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		0, 0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if r0 != 0 && needed == 0 {
		return nil, syscall.EINVAL
	}
	// fase 2: ambil data
	buf := make([]byte, needed)
	r1, _, e1 := procQueryServiceObjectSecurity.Call(
		uintptr(svc),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(uint32(len(buf))),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}
	return &buf[0], nil
}

// accessCheckService: cek apakah token punya desiredAccess pada SD service
func accessCheckService(pSD *byte, desiredAccess uint32) (bool, error) {
	tok, err := getImpersonationToken()
	if err != nil {
		return false, err
	}
	defer tok.Close()

	mapping := serviceGenericMapping()

	priv := make([]byte, 1024)
	privLen := uint32(len(priv))
	var granted uint32
	var status uint32

	r1, _, e1 := procAccessCheck.Call(
		uintptr(unsafe.Pointer(pSD)),
		uintptr(tok),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&priv[0])),
		uintptr(unsafe.Pointer(&privLen)),
		uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&status)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return false, e1
		}
		return false, syscall.EINVAL
	}
	return status != 0, nil
}

/* =========================
   WMI: Services & Drivers
   ========================= */

type wmiService struct {
	Name        *string
	DisplayName *string
	State       *string
	StartMode   *string
	PathName    *string
}

type wmiDriver struct {
	Name        *string
	DisplayName *string
	State       *string
	StartMode   *string
	PathName    *string
}

func getAllServices() []wmiService {
	var rows []wmiService
	_ = wmi.QueryNamespace(
		`SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_Service`,
		&rows, `root\cimv2`,
	)
	return rows
}

func getAllDrivers() []wmiDriver {
	var rows []wmiDriver
	_ = wmi.QueryNamespace(
		`SELECT Name,DisplayName,State,StartMode,PathName FROM Win32_SystemDriver`,
		&rows, `root\cimv2`,
	)
	return rows
}

/* =========================
   Path parsing / checks
   ========================= */

func parseServiceBinary(pathRaw string) (exePath string, exeDir string, unquoted bool) {
	// expand env vars pakai helper dari W-013
	if expanded := expandEnvWin(pathRaw); expanded != "" {
		pathRaw = expanded
	}
	s := strings.TrimSpace(pathRaw)

	// quoted path
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end >= 0 {
			exePath = s[1 : 1+end]
		} else {
			exePath = s
		}
		unquoted = false
	} else {
		fields := strings.Fields(s)
		if len(fields) > 0 {
			exePath = fields[0]
		} else {
			exePath = s
		}
		unquoted = strings.Contains(exePath, " ")
	}

	// normalisasi \SystemRoot\
	l := strings.ToLower(exePath)
	if strings.HasPrefix(l, `\systemroot\`) {
		sysRoot := expandEnvWin(`%SystemRoot%`)
		exePath = filepath.Join(sysRoot, exePath[len(`\SystemRoot\`):])
	} else if !filepath.IsAbs(exePath) && !strings.Contains(exePath, "://") {
		sysRoot := expandEnvWin(`%SystemRoot%`)
		exePath = filepath.Join(sysRoot, exePath)
	}

	exePath = filepath.Clean(exePath)
	exeDir = filepath.Dir(exePath)
	return
}

/* =========================
   Main collection logic
   ========================= */

func runCheckServiceHijack() Finding {
	scm, err := openSCM()
	if err != nil {
		return Finding{
			CheckID:     "W-014",
			Title:       "Service/Driver Hijackability",
			Severity:    SevMed,
			Description: "Failed to open SCM; returning WMI-only analysis",
			Data:        analyzeServicesAndDrivers(0, false),
		}
	}
	defer closeServiceHandle(scm)

	data := analyzeServicesAndDrivers(scm, true)

	high := false
	for _, anyEntry := range data { // data sudah bertipe []map[string]any
		if toBool(anyEntry["binary_dir_writable"]) || toBool(anyEntry["can_change_config"]) ||
			toBool(anyEntry["can_write_dac"]) || toBool(anyEntry["unquoted_path"]) {
			high = true
			break
		}
	}

	sev := SevInfo
	desc := "No hijackable services/drivers found"
	if high {
		sev = SevHigh
		desc = "Potentially hijackable services/drivers detected"
	}

	return Finding{
		CheckID:     "W-014",
		Title:       "Service/Driver Hijackability",
		Severity:    sev,
		Description: desc,
		Data:        data,
	}
}

func analyzeServicesAndDrivers(scm windows.Handle, withSD bool) []map[string]any {
	results := make([]map[string]any, 0, 512)

	for _, s := range getAllServices() {
		name := safeS(s.Name)
		entry := analyzeOne(safeS(s.PathName), name, safeS(s.DisplayName), "service", safeS(s.State), safeS(s.StartMode), scm, withSD)
		results = append(results, entry)
	}
	for _, d := range getAllDrivers() {
		name := safeS(d.Name)
		entry := analyzeOne(safeS(d.PathName), name, safeS(d.DisplayName), "driver", safeS(d.State), safeS(d.StartMode), scm, withSD)
		results = append(results, entry)
	}
	return results
}

func analyzeOne(pathName, name, display, typ, state, startMode string, scm windows.Handle, withSD bool) map[string]any {
	entry := map[string]any{
		"name":       name,
		"display":    display,
		"type":       typ,
		"state":      state,
		"start_mode": startMode,
		"image_path": pathName,
	}

	exe, dir, unquoted := parseServiceBinary(pathName)
	entry["exe_path"] = exe
	entry["exe_dir"] = dir
	entry["unquoted_path"] = unquoted

	if dir != "" {
		if ok, err := hasDirGenericWrite(dir); err == nil {
			entry["binary_dir_writable"] = ok
			if ok {
				entry["reason_binary_dir"] = "current user has GENERIC_WRITE on service binary directory"
			}
		} else {
			entry["binary_dir_writable"] = false
			entry["error_dir_check"] = err.Error()
		}
	} else {
		entry["binary_dir_writable"] = false
	}

	if withSD && name != "" && scm != 0 {
		if h, err := openServiceRO(scm, name); err == nil && h != 0 {
			defer closeServiceHandle(h)
			if pSD, err := queryServiceSD(h); err == nil && pSD != nil {
				if ok, err := accessCheckService(pSD, SERVICE_CHANGE_CONFIG); err == nil {
					entry["can_change_config"] = ok
				} else {
					entry["can_change_config"] = false
					entry["error_change_config"] = err.Error()
				}
				if ok, err := accessCheckService(pSD, windows.WRITE_DAC); err == nil {
					entry["can_write_dac"] = ok
				} else {
					entry["can_write_dac"] = false
					entry["error_write_dac"] = err.Error()
				}
			} else if err != nil {
				entry["error_query_sd"] = err.Error()
			}
		} else if err != nil {
			entry["error_open_service"] = err.Error()
		}
	}

	return entry
}

/* =========================
   Small helpers
   ========================= */

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	default:
		return false
	}
}
