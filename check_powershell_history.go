//go:build windows
// +build windows

package main

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

// W-019: PowerShell History & Transcription (read-only, privacy-friendly)
// ---------------------------------------------------------------------
// - Mendeteksi file PSReadLine history untuk user saat ini (tanpa membaca isi):
//     %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
//     %USERPROFILE%\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt
// - Membaca kebijakan Transcription (machine & user) jika ada:
//     HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting
//     HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting
// - Selalu INFO; ini observasi untuk defensive posture.

func runCheckPowerShellHistory() Finding {
	type Hist struct {
		UserProfile string `json:"user_profile"`
		Path        string `json:"path"`
		Exists      bool   `json:"exists"`
		SizeBytes   int64  `json:"size_bytes,omitempty"`
		ModifiedUTC string `json:"modified_utc,omitempty"`
	}
	data := struct {
		Histories                []Hist `json:"histories"`
		TranscriptionEnabledHKLM bool   `json:"transcription_enabled_hklm"`
		TranscriptionEnabledHKCU bool   `json:"transcription_enabled_hkcu"`
	}{
		Histories: make([]Hist, 0),
	}

	up := os.Getenv("USERPROFILE")
	if up == "" {
		up = `C:\Users\Default`
	}
	paths := []string{
		filepath.Join(up, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`),
		filepath.Join(up, `AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt`), // PowerShell 7+
	}

	for _, p := range paths {
		h := Hist{UserProfile: up, Path: p}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			h.Exists = true
			h.SizeBytes = st.Size()
			h.ModifiedUTC = st.ModTime().UTC().Format(time.RFC3339)
		}
		data.Histories = append(data.Histories, h)
	}

	// HKLM policy
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("EnableTranscripting"); err == nil && v == 1 {
			data.TranscriptionEnabledHKLM = true
		}
	}
	// HKCU policy (user)
	if k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("EnableTranscripting"); err == nil && v == 1 {
			data.TranscriptionEnabledHKCU = true
		}
	}

	return Finding{
		CheckID:     "W-019",
		Title:       "PowerShell History and Transcription",
		Severity:    SevInfo,
		Description: "PowerShell history metadata collected.",
		Data:        data,
	}
}
