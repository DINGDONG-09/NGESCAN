// check_path_writable.go
// W-013: Writeable Directories in PATH (winPEAS-style, defensive, no file touch)

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

/* =========================
   Low-level Win32 bindings
   ========================= */

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procGetNamedSecurityInfoW = modAdvapi32.NewProc("GetNamedSecurityInfoW")
	procAccessCheck           = modAdvapi32.NewProc("AccessCheck")
	procMapGenericMask        = modAdvapi32.NewProc("MapGenericMask")
	// ⚠️ JANGAN deklarasi modKernel32 di sini (sudah ada di file lain)
)

// SE_OBJECT_TYPE
const (
	SE_FILE_OBJECT = 1
)

// SECURITY_INFORMATION
const (
	DACL_SECURITY_INFORMATION = 0x00000004
)

// Directory rights (subset) & generic mapping components
const (
	FILE_LIST_DIRECTORY   = 0x00000001
	FILE_ADD_FILE         = 0x00000002
	FILE_ADD_SUBDIRECTORY = 0x00000004
	FILE_READ_EA          = 0x00000008
	FILE_WRITE_EA         = 0x00000010
	FILE_DELETE_CHILD     = 0x00000040
	FILE_READ_ATTRIBUTES  = 0x00000080
	FILE_WRITE_ATTRIBUTES = 0x00000100

	DELETE       = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC    = 0x00040000
	WRITE_OWNER  = 0x00080000
	SYNCHRONIZE  = 0x00100000

	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000
)

// genericMapping merepresentasikan GENERIC_MAPPING WinAPI
type genericMapping struct {
	GenericRead    uint32
	GenericWrite   uint32
	GenericExecute uint32
	GenericAll     uint32
}

/* ===================================
   Helpers: ExpandEnv, token, AccessCheck
   =================================== */

// expandEnvWin: expand %VAR% via WinAPI (akurasi sama Windows)
func expandEnvWin(raw string) string {
	inPtr, err := windows.UTF16PtrFromString(raw)
	if err != nil {
		return raw
	}
	const maxChars = 32767
	buf := make([]uint16, maxChars)
	n, err := windows.ExpandEnvironmentStrings(inPtr, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return raw
	}
	if int(n) > len(buf) {
		// Rare: realokasi pas ukuran
		buf = make([]uint16, n)
		n2, err2 := windows.ExpandEnvironmentStrings(inPtr, &buf[0], uint32(len(buf)))
		if err2 != nil || n2 == 0 {
			return raw
		}
		n = n2
	}
	// n termasuk null-terminator; konversi aman
	return windows.UTF16ToString(buf[:n])
}

// getImpersonationToken: duplikasi primary token → impersonation (dibutuhkan AccessCheck)
func getImpersonationToken() (windows.Token, error) {
	var primary windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &primary); err != nil {
		return 0, err
	}
	defer primary.Close()

	var imp windows.Token
	err := windows.DuplicateTokenEx(
		primary,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&imp,
	)
	if err != nil {
		return 0, err
	}
	return imp, nil
}

func hasDirGenericWrite(dir string) (bool, error) {
	// --- Ambil SD via GetNamedSecurityInfoW (by name) ---
	var pSD *byte
	var pOwner, pGroup, pDacl, pSacl uintptr
	r0, _, e0 := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(dir))), // pObjectName
		uintptr(SE_FILE_OBJECT),                                // ObjectType
		uintptr(DACL_SECURITY_INFORMATION),                     // SecurityInfo
		uintptr(unsafe.Pointer(&pOwner)),                       // ppsidOwner
		uintptr(unsafe.Pointer(&pGroup)),                       // ppsidGroup
		uintptr(unsafe.Pointer(&pDacl)),                        // ppDacl
		uintptr(unsafe.Pointer(&pSacl)),                        // ppSacl
		uintptr(unsafe.Pointer(&pSD)),                          // ppSecurityDescriptor (out)
	)

	if r0 != 0 || pSD == nil {
		// Jika struktur SD invalid (1338), coba fallback by handle
		if errno, ok := e0.(syscall.Errno); ok && errno == syscall.Errno(1338) {
			if alt, altErr := getDirSDByHandle(dir); altErr == nil && alt != nil {
				pSD = alt // pakai SD hasil fallback
			} else {
				// bersihkan alt kalau sempat teralokasi tetapi error lain terjadi
				if alt != nil {
					windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(alt))))
				}
				// gagal total
				if altErr != nil {
					return false, altErr
				}
				return false, e0
			}
		} else {
			// error lain dari GetNamedSecurityInfoW
			if e0 != syscall.Errno(0) {
				return false, e0
			}
			return false, syscall.EINVAL
		}
	}

	// >>>> Defer harus di dalam fungsi & setelah pSD valid
	defer freeSD(pSD)

	// --- Ambil impersonation token ---
	tok, err := getImpersonationToken()
	if err != nil {
		return false, err
	}
	defer tok.Close()

	// --- Specific rights utk directory
	dirGenericWrite := uint32(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)
	dirGenericRead := uint32(FILE_LIST_DIRECTORY | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)
	dirGenericExec := uint32(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)

	// --- Mapping generic
	mapping := genericMapping{
		GenericRead:    dirGenericRead,
		GenericWrite:   dirGenericWrite,
		GenericExecute: dirGenericExec,
		GenericAll:     dirGenericRead | dirGenericWrite | dirGenericExec | WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD,
	}
	desired := uint32(GENERIC_WRITE)
	procMapGenericMask.Call(
		uintptr(unsafe.Pointer(&desired)),
		uintptr(unsafe.Pointer(&mapping)),
	)

	// --- AccessCheck ---
	priv := make([]byte, 1024)
	privLen := uint32(len(priv))
	var granted, accessStatus uint32

	r1, _, e1 := procAccessCheck.Call(
		uintptr(unsafe.Pointer(pSD)),
		uintptr(tok),
		uintptr(desired),
		uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&priv[0])),
		uintptr(unsafe.Pointer(&privLen)),
		uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&accessStatus)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return false, e1
		}
		return false, syscall.EINVAL
	}
	return accessStatus != 0, nil
}

/* ==================================
   PATH collectors (HKLM/HKCU/env)
   ================================== */

// getPathFromReg: ambil PATH (HKLM/HKCU)
// Catatan: registry package tidak punya GetExpandStringValue;
// kita baca via GetStringValue, cek typ, lalu expand manual jika EXPAND_SZ.
// Untuk REG_SZ yang berisi %VAR%, tetap kita expand agar efektif sama Windows.
func getPathFromReg(root registry.Key, subkey, value string) string {
	k, err := registry.OpenKey(root, subkey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, typ, err := k.GetStringValue(value)
	if err != nil {
		return ""
	}
	if typ == registry.EXPAND_SZ {
		return expandEnvWin(s)
	}
	// REG_SZ juga bisa berisi %VAR%
	return expandEnvWin(s)
}

// splitPath: pecah PATH jadi slice, trim, expand, & cleanup
func splitPath(s string) []string {
	parts := strings.Split(s, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.Trim(p, `"`))
		if p == "" {
			continue
		}
		p = expandEnvWin(p)
		// normalisasi (hapus trailing \, resolve .\ ..\)
		p = filepath.Clean(p)
		out = append(out, p)
	}
	return out
}

// collectPathDirs: gabungkan PATH dari process, HKLM, HKCU → unique & existing dirs
func collectPathDirs() []string {
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		lp := strings.ToLower(p)
		if _, ok := seen[lp]; ok {
			return
		}
		// hanya directory yang eksis
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			seen[lp] = struct{}{}
		}
	}

	// Process PATH
	for _, p := range splitPath(os.Getenv("PATH")) {
		add(p)
	}
	// System PATH (HKLM)
	sysPath := getPathFromReg(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "Path")
	for _, p := range splitPath(sysPath) {
		add(p)
	}
	// User PATH (HKCU)
	usrPath := getPathFromReg(registry.CURRENT_USER, `Environment`, "Path")
	for _, p := range splitPath(usrPath) {
		add(p)
	}

	// finalize list
	out := make([]string, 0, len(seen))
	for lp := range seen {
		out = append(out, lp)
	}
	sort.Strings(out)
	return out
}

// import tambahan di atas file:
// "golang.org/x/sys/windows"
// "syscall"
// "unsafe"

var (
	procGetSecurityInfo = windows.NewLazySystemDLL("advapi32.dll").
		NewProc("GetSecurityInfo")
)

// getDirSDByHandle: fallback ambil SD dari HANDLE (bukan by-name)
func getDirSDByHandle(dir string) (*byte, error) {
	pathp, _ := windows.UTF16PtrFromString(dir)
	// Buka handle dir dengan flag backup semantics (tidak menulis apa-apa)
	h, err := windows.CreateFile(pathp,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var pSD *byte
	var pOwner, pGroup, pDacl, pSacl uintptr
	r0, _, e0 := procGetSecurityInfo.Call(
		uintptr(h),
		uintptr(SE_FILE_OBJECT),
		uintptr(DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&pOwner)),
		uintptr(unsafe.Pointer(&pGroup)),
		uintptr(unsafe.Pointer(&pDacl)),
		uintptr(unsafe.Pointer(&pSacl)),
		uintptr(unsafe.Pointer(&pSD)),
	)
	if r0 != 0 || pSD == nil {
		if e0 != syscall.Errno(0) {
			return nil, e0
		}
		return nil, syscall.EINVAL
	}
	return pSD, nil
}

/* ===========================
   Main check implementation
   =========================== */

func runCheckPathWritable() Finding {
	dirs := collectPathDirs()

	type row struct {
		Path     string `json:"path"`     // absolute dir path
		Writable bool   `json:"writable"` // hasil AccessCheck
		Error    string `json:"error"`    // jika gagal evaluasi
	}

	results := make([]row, 0, len(dirs))
	writableCount := 0

	for _, d := range dirs {
		ok, err := hasDirGenericWrite(d)
		r := row{Path: d, Writable: ok}
		if err != nil {
			r.Error = err.Error()
		}
		if ok {
			writableCount++
		}
		results = append(results, r)
	}

	severity := SevInfo
	desc := "No writeable directories in PATH found"
	if writableCount > 0 {
		severity = SevHigh
		desc = "Writeable directories in PATH found: " + strconv.Itoa(writableCount)
	}

	data := map[string]any{
		"total_dirs":    len(dirs),
		"writable_dirs": writableCount,
		"entries":       results, // array berisi setiap path & status writability
	}

	return Finding{
		CheckID:     "W-013",
		Title:       "Writeable Directories in PATH",
		Severity:    severity,
		Description: desc,
		Data:        data,
	}
}
