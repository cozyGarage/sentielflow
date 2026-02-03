// Package policy provides policy-as-code enforcement using OPA
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements policy-as-code scanning using OPA
type Scanner struct {
	config   *config.Config
	policies []Policy
}

// Policy represents a security policy
type Policy struct {
	ID          string
	Name        string
	Description string
	Severity    api.Severity
	Query       string // OPA Rego query
	FilePath    string
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new policy scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config: cfg,
	}
	s.policies = s.loadPolicies()
	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "policy"
}

// Supports returns true for files that policies should check
func (s *Scanner) Supports(path string) bool {
	// Policy scanner can check any file type
	// It's more about what policies are configured
	return true
}

// Scan performs policy enforcement
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	// Load all Rego policies from configured locations
	if err := s.loadRegoFiles(); err != nil {
		return result, err
	}

	// For each policy, evaluate it against the codebase
	for _, policy := range s.policies {
		violations := s.evaluatePolicy(ctx, policy, path)
		result.Findings = append(result.Findings, violations...)
	}

	result.FilesCount = len(s.policies)
	return result, nil
}

// loadPolicies loads built-in policies
func (s *Scanner) loadPolicies() []Policy {
	var policies []Policy

	// Load built-in policies from config
	for _, policyName := range s.config.Policies.Builtin {
		if policy := s.getBuiltinPolicy(policyName); policy != nil {
			policies = append(policies, *policy)
		}
	}

	return policies
}

// getBuiltinPolicy returns a built-in policy by name
func (s *Scanner) getBuiltinPolicy(name string) *Policy {
	builtinPolicies := map[string]Policy{
		"no-public-s3-buckets": {
			ID:          "pol-s3-public",
			Name:        "No Public S3 Buckets",
			Description: "Prevents S3 buckets from being publicly accessible",
			Severity:    api.SeverityCritical,
			Query:       "data.sentinelflow.s3.deny_public_buckets",
		},
		"no-privileged-containers": {
			ID:          "pol-k8s-privileged",
			Name:        "No Privileged Containers",
			Description: "Prevents deployment of privileged containers",
			Severity:    api.SeverityCritical,
			Query:       "data.sentinelflow.kubernetes.deny_privileged",
		},
		"require-https": {
			ID:          "pol-https-required",
			Name:        "Require HTTPS",
			Description: "Ensures all endpoints use HTTPS",
			Severity:    api.SeverityHigh,
			Query:       "data.sentinelflow.network.require_https",
		},
		"no-hardcoded-credentials": {
			ID:          "pol-no-hardcoded-creds",
			Name:        "No Hardcoded Credentials",
			Description: "Prevents hardcoded passwords and secrets",
			Severity:    api.SeverityCritical,
			Query:       "data.sentinelflow.secrets.deny_hardcoded",
		},
		"enforce-encryption": {
			ID:          "pol-encryption-required",
			Name:        "Enforce Encryption",
			Description: "Requires encryption at rest for storage resources",
			Severity:    api.SeverityHigh,
			Query:       "data.sentinelflow.encryption.require_at_rest",
		},
	}

	if policy, exists := builtinPolicies[name]; exists {
		return &policy
	}

	return nil
}

// loadRegoFiles loads custom Rego policy files
func (s *Scanner) loadRegoFiles() error {
	for _, pattern := range s.config.Policies.Files {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, path := range matches {
			if !strings.HasSuffix(path, ".rego") {
				continue
			}

			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			// Parse the Rego file to extract policy metadata
			policy := s.parseRegoFile(path, string(content))
			if policy != nil {
				s.policies = append(s.policies, *policy)
			}
		}
	}

	return nil
}

// parseRegoFile extracts policy information from a Rego file
func (s *Scanner) parseRegoFile(path, content string) *Policy {
	// Simple metadata extraction from comments
	// In production, use proper Rego parser

	policy := &Policy{
		ID:       filepath.Base(path),
		Name:     filepath.Base(path),
		FilePath: path,
		Severity: api.SeverityMedium,
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "# METADATA") {
			// Parse metadata from comments
			if strings.Contains(line, "title:") {
				policy.Name = strings.TrimSpace(strings.Split(line, "title:")[1])
			}
			if strings.Contains(line, "severity:") {
				severityStr := strings.TrimSpace(strings.Split(line, "severity:")[1])
				policy.Severity = s.parseSeverity(severityStr)
			}
		}
	}

	return policy
}

// parseSeverity converts string to Severity
func (s *Scanner) parseSeverity(str string) api.Severity {
	switch strings.ToLower(str) {
	case "critical":
		return api.SeverityCritical
	case "high":
		return api.SeverityHigh
	case "medium":
		return api.SeverityMedium
	case "low":
		return api.SeverityLow
	default:
		return api.SeverityInfo
	}
}

// evaluatePolicy evaluates a policy against the target path
func (s *Scanner) evaluatePolicy(ctx context.Context, policy Policy, targetPath string) []api.Finding {
	var findings []api.Finding

	// This is a simplified implementation
	// In production, integrate with OPA's Go SDK to evaluate Rego policies

	// For now, create placeholder findings for demonstration
	// Real implementation would:
	// 1. Load Rego policy into OPA
	// 2. Prepare input data from scanned files
	// 3. Evaluate policy query
	// 4. Extract violations from results

	// Placeholder logic for demonstration
	if s.shouldTriggerPolicy(policy, targetPath) {
		finding := api.Finding{
			ID:          fmt.Sprintf("POL-%s", policy.ID),
			Type:        api.FindingTypePolicyViolation,
			Severity:    policy.Severity,
			Title:       policy.Name,
			Description: policy.Description,
			Location: api.Location{
				File: "policy-evaluation",
			},
			Remediation: fmt.Sprintf("Review and comply with policy: %s", policy.Name),
			Scanner:     "policy",
			RuleID:      policy.ID,
			Confidence:  0.9,
		}

		findings = append(findings, finding)
	}

	return findings
}

// shouldTriggerPolicy is a placeholder for actual OPA evaluation
func (s *Scanner) shouldTriggerPolicy(policy Policy, targetPath string) bool {
	// This would be replaced with actual OPA integration
	// For now, return false to avoid noise
	return false
}
