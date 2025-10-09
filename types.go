package main

import (
	"encoding/json"
	"os"
)

type Severity string

const (
	SevInfo Severity = "info"     // informasi
	SevLow  Severity = "low"      // risiko rendah
	SevMed  Severity = "medium"   // risiko sedang
	SevHigh Severity = "high"     // risiko tinggi
	SevCrit Severity = "critical" // kritikal
)

type Finding struct {
	CheckID     string      `json:"check_id"`
	Title       string      `json:"title"`
	Severity    Severity    `json:"severity"`
	Description string      `json:"description"`
	Data        interface{} `json:"data,omitempty"`
}

func emitFindings(findings []Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(findings)
}
