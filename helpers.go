package main

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// safeS: deref *string -> "" jika nil
func safeS(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// safeB: deref *bool -> false jika nil
func safeB(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// joinS: deref *[]string -> []string; trim spasi dan buang elemen kosong
func joinS(p *[]string) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(*p))
	for _, s := range *p {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// formatTimePtr: *time.Time -> string RFC3339 ("" jika nil/zero)
func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func freeSD(pSD *byte) {
	if pSD != nil {
		// LocalFree expects HLOCAL (alias HANDLE). Cast via uintptr → Handle.
		windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(pSD))))
	}
}
