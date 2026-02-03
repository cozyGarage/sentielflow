// Package api defines the public API types for SentinelFlow
package api

import (
	"time"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingType represents the category of a security finding
type FindingType string

const (
	FindingTypeSecret           FindingType = "secret"
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypePolicyViolation  FindingType = "policy_violation"
	FindingTypeInsecureCode     FindingType = "insecure_code"
)

// Location represents where a finding was discovered
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Finding represents a single security issue discovered during scanning
type Finding struct {
	ID          string         `json:"id"`
	Type        FindingType    `json:"type"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Location    Location       `json:"location"`
	Remediation string         `json:"remediation,omitempty"`
	References  []string       `json:"references,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	RuleID      string         `json:"rule_id,omitempty"`
	Scanner     string         `json:"scanner"`
	Confidence  float64        `json:"confidence,omitempty"`
	CVE         string         `json:"cve,omitempty"`
	CVSS        float64        `json:"cvss,omitempty"`
	CWE         []string       `json:"cwe,omitempty"`
}

// ScanResult contains the complete results of a security scan
type ScanResult struct {
	Findings    []Finding     `json:"findings"`
	ScannerRuns []ScannerRun  `json:"scanner_runs"`
	Metadata    ScanMetadata  `json:"metadata"`
	Duration    time.Duration `json:"duration"`
}

// ScannerRun contains information about an individual scanner execution
type ScannerRun struct {
	Scanner       string        `json:"scanner"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	Duration      time.Duration `json:"duration"`
	FilesCount    int           `json:"files_count"`
	FindingsCount int           `json:"findings_count"`
	Error         string        `json:"error,omitempty"`
}

// ScanMetadata contains information about the scan environment
type ScanMetadata struct {
	TargetPath          string    `json:"target_path"`
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
	SentinelFlowVersion string    `json:"sentinelflow_version"`
	GitCommit           string    `json:"git_commit,omitempty"`
	GitBranch           string    `json:"git_branch,omitempty"`
	GitRepository       string    `json:"git_repository,omitempty"`
}

// CountBySeverity returns a map of severity to count
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// CountByType returns a map of finding type to count
func (r *ScanResult) CountByType() map[FindingType]int {
	counts := make(map[FindingType]int)
	for _, f := range r.Findings {
		counts[f.Type]++
	}
	return counts
}

// HasCritical returns true if there are any critical findings
func (r *ScanResult) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHigh returns true if there are any high severity findings
func (r *ScanResult) HasHigh() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// FilterBySeverity returns findings matching the given severity
func (r *ScanResult) FilterBySeverity(severity Severity) []Finding {
	var filtered []Finding
	for _, f := range r.Findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// FilterByScanner returns findings from the specified scanner
func (r *ScanResult) FilterByScanner(scanner string) []Finding {
	var filtered []Finding
	for _, f := range r.Findings {
		if f.Scanner == scanner {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
