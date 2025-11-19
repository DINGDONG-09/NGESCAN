//go:build windows
// +build windows

package core

import "time"

// Finding adalah hasil dari satu pemeriksaan (enhanced)
type Finding struct {
	CheckID       string                 `json:"check_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Severity      string                 `json:"severity"`   // critical, high, medium, low, info
	Confidence    string                 `json:"confidence"` // high, medium, low
	Status        string                 `json:"status"`     // vulnerable, secure, not_applicable
	Category      string                 `json:"category"`   // privilege_escalation, persistence, etc
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Evidence      map[string]interface{} `json:"evidence,omitempty"`
	Remediation   string                 `json:"remediation,omitempty"`
	References    []string               `json:"references,omitempty"`
	RiskScore     float64                `json:"risk_score"` // 0-10
	AffectedAsset string                 `json:"affected_asset,omitempty"`
	MITRE         string                 `json:"mitre_attack,omitempty"` // MITRE ATT&CK technique ID
}

// NewFinding membuat finding baru dengan defaults
func NewFinding(checkID, title, description string) Finding {
	return Finding{
		CheckID:     checkID,
		Timestamp:   time.Now(),
		Title:       title,
		Description: description,
		Evidence:    make(map[string]interface{}),
		Status:      "secure",
		Severity:    "info",
		Confidence:  "high",
		RiskScore:   0.0,
	}
}

// SetVulnerable menandai finding sebagai vulnerable
func (f *Finding) SetVulnerable(severity string, riskScore float64) {
	f.Status = "vulnerable"
	f.Severity = severity
	f.RiskScore = riskScore
}

// AddEvidence menambahkan bukti ke finding
func (f *Finding) AddEvidence(key string, value interface{}) {
	if f.Evidence == nil {
		f.Evidence = make(map[string]interface{})
	}
	f.Evidence[key] = value
}

// AddReference menambahkan referensi
func (f *Finding) AddReference(ref string) {
	f.References = append(f.References, ref)
}
