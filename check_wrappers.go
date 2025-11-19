//go:build windows
// +build windows

package main

import (
	"context"

	"corp/OSagent/core"
)

// CheckWrapper mem-wrap fungsi check lama ke interface baru
type CheckWrapper struct {
	id       string
	name     string
	category string
	fn       func() Finding
}

func (c *CheckWrapper) ID() string       { return c.id }
func (c *CheckWrapper) Name() string     { return c.name }
func (c *CheckWrapper) Category() string { return c.category }

func (c *CheckWrapper) Run(ctx context.Context) core.Finding {
	// Konversi Finding lama ke core.Finding baru
	oldFinding := c.fn()

	newFinding := core.NewFinding(c.id, c.name, oldFinding.Description)
	newFinding.Category = c.category
	newFinding.Title = oldFinding.Title

	// Copy data as evidence
	if oldFinding.Data != nil {
		newFinding.AddEvidence("data", oldFinding.Data)
	}

	// Map severity ke core.Finding
	severity := string(oldFinding.Severity)
	newFinding.Severity = severity

	// Determine if vulnerable based on severity
	if severity != "info" && oldFinding.Data != nil {
		// Ada data = ada temuan = vulnerable
		riskScore := getRiskScoreFromSeverity(severity)
		newFinding.SetVulnerable(severity, riskScore)
	} else {
		newFinding.Status = "secure"
	}

	return newFinding
}

// getRiskScoreFromSeverity converts severity to risk score
func getRiskScoreFromSeverity(severity string) float64 {
	switch severity {
	case "critical":
		return 9.5
	case "high":
		return 8.0
	case "medium":
		return 6.0
	case "low":
		return 4.0
	default:
		return 2.0
	}
}

// Factory functions untuk setiap check
func NewCheckAlwaysInstallElevated() core.Check {
	return &CheckWrapper{
		id:       "W-001",
		name:     "AlwaysInstallElevated",
		category: "privilege_escalation",
		fn:       runCheckAlwaysInstallElevated,
	}
}

func NewCheckUnquotedServicePaths() core.Check {
	return &CheckWrapper{
		id:       "W-002",
		name:     "Unquoted Service Paths",
		category: "privilege_escalation",
		fn:       runCheckUnquotedServicePaths,
	}
}

func NewCheckUACSnapshot() core.Check {
	return &CheckWrapper{
		id:       "W-003",
		name:     "UAC Configuration",
		category: "defense_evasion",
		fn:       runCheckUACSnapshot,
	}
}

func NewCheckAutoruns() core.Check {
	return &CheckWrapper{
		id:       "W-004",
		name:     "Autorun Entries",
		category: "persistence",
		fn:       runCheckAutoruns,
	}
}

func NewCheckScheduledTasks() core.Check {
	return &CheckWrapper{
		id:       "W-005",
		name:     "Scheduled Tasks",
		category: "persistence",
		fn:       runCheckScheduledTasks,
	}
}

func NewCheckHotfix() core.Check {
	return &CheckWrapper{
		id:       "W-006",
		name:     "Installed Hotfixes",
		category: "configuration",
		fn:       runCheckHotfix,
	}
}

func NewCheckUsersGroups() core.Check {
	return &CheckWrapper{
		id:       "W-007",
		name:     "Users and Groups",
		category: "discovery",
		fn:       runCheckUsersGroups,
	}
}

func NewCheckTokenPrivileges() core.Check {
	return &CheckWrapper{
		id:       "W-008",
		name:     "Token Privileges",
		category: "privilege_escalation",
		fn:       runCheckTokenPrivileges,
	}
}

func NewCheckNetworkSnapshot() core.Check {
	return &CheckWrapper{
		id:       "W-009",
		name:     "Network Configuration",
		category: "discovery",
		fn:       runCheckNetworkSnapshot,
	}
}

func NewCheckListeningPorts() core.Check {
	return &CheckWrapper{
		id:       "W-010",
		name:     "Listening Ports",
		category: "discovery",
		fn:       runCheckListeningPorts,
	}
}

func NewCheckSystemInfo() core.Check {
	return &CheckWrapper{
		id:       "W-011",
		name:     "System Information",
		category: "discovery",
		fn:       runCheckSystemInfo,
	}
}

func NewCheckRdpFirewallProxy() core.Check {
	return &CheckWrapper{
		id:       "W-012",
		name:     "RDP & Firewall Config",
		category: "configuration",
		fn:       runCheckRdpFirewallProxy,
	}
}

func NewCheckPathWritable() core.Check {
	return &CheckWrapper{
		id:       "W-013",
		name:     "Writable PATH Directories",
		category: "privilege_escalation",
		fn:       runCheckPathWritable,
	}
}

func NewCheckServiceHijack() core.Check {
	return &CheckWrapper{
		id:       "W-014",
		name:     "Service Hijacking",
		category: "privilege_escalation",
		fn:       runCheckServiceHijack,
	}
}

func NewCheckDefenderExclusions() core.Check {
	return &CheckWrapper{
		id:       "W-015",
		name:     "Windows Defender Exclusions",
		category: "defense_evasion",
		fn:       runCheckDefenderExclusions,
	}
}

func NewCheckLSA() core.Check {
	return &CheckWrapper{
		id:       "W-016",
		name:     "LSA Protection",
		category: "credential_access",
		fn:       runCheckLSA,
	}
}

func NewCheckIFEO() core.Check {
	return &CheckWrapper{
		id:       "W-017",
		name:     "Image File Execution Options",
		category: "persistence",
		fn:       runCheckIFEO,
	}
}

func NewCheckServiceBinaryACL() core.Check {
	return &CheckWrapper{
		id:       "W-018",
		name:     "Service Binary Permissions",
		category: "privilege_escalation",
		fn:       runCheckServiceBinaryACL,
	}
}

func NewCheckPowerShellHistory() core.Check {
	return &CheckWrapper{
		id:       "W-019",
		name:     "PowerShell History",
		category: "credential_access",
		fn:       runCheckPowerShellHistory,
	}
}

func NewCheckLSASSArtifacts() core.Check {
	return &CheckWrapper{
		id:       "W-020",
		name:     "LSASS Dump Artifacts",
		category: "credential_access",
		fn:       runCheckLSASSArtifacts,
	}
}
