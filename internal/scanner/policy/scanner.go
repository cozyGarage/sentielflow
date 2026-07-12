// Package policy provides policy-as-code enforcement using OPA
package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements policy-as-code scanning using OPA
type Scanner struct {
	config     *config.Config
	severities map[string]api.Severity
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new policy scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		config:     cfg,
		severities: make(map[string]api.Severity),
	}
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "policy"
}

// Supports returns true for files that policies should check
func (s *Scanner) Supports(path string) bool {
	return true
}

// Scan performs policy enforcement
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	if !s.config.Policies.Enabled {
		return result, nil
	}

	engine := NewOPAEngine()
	if err := s.loadPolicyFiles(engine, path); err != nil {
		return result, err
	}

	policyNames := engine.ListPolicies()
	if len(policyNames) == 0 {
		return result, nil
	}

	inputs, err := collectPolicyInputs(path)
	if err != nil {
		return result, err
	}

	result.FilesCount = len(inputs)

	for _, input := range inputs {
		for _, name := range policyNames {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			policyResult, err := engine.EvaluatePolicy(name, input.Data)
			if err != nil {
				continue
			}

			severity := s.severityFor(name)
			findings := ConvertToFindings(policyResult, severity)
			for i := range findings {
				if findings[i].Location.File == "" {
					findings[i].Location.File = input.FilePath
				}
			}
			result.Findings = append(result.Findings, findings...)
		}
	}

	return result, nil
}

func (s *Scanner) loadPolicyFiles(engine *OPAEngine, scanRoot string) error {
	seen := make(map[string]bool)

	loadDir := func(dir string) {
		if dir == "" {
			return
		}
		if _, err := os.Stat(dir); err != nil {
			return
		}
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".rego") {
				return err
			}
			if seen[path] {
				return nil
			}
			seen[path] = true

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			name := strings.TrimSuffix(filepath.Base(path), ".rego")
			if err := engine.LoadPolicy(name, string(content)); err != nil {
				return nil
			}
			s.severities[name] = parseSeverityFromRego(string(content))
			return nil
		})
	}

	loadDir(filepath.Join(scanRoot, "policies"))
	loadDir("policies")

	for _, pattern := range s.config.Policies.Files {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			if !strings.HasSuffix(path, ".rego") || seen[path] {
				continue
			}
			seen[path] = true

			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			name := strings.TrimSuffix(filepath.Base(path), ".rego")
			if err := engine.LoadPolicy(name, string(content)); err != nil {
				continue
			}
			s.severities[name] = parseSeverityFromRego(string(content))
		}
	}

	return nil
}

func parseSeverityFromRego(content string) api.Severity {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "# severity:") {
			parts := strings.SplitN(line, "severity:", 2)
			if len(parts) == 2 {
				return parseSeverity(strings.TrimSpace(parts[1]))
			}
		}
	}
	return api.SeverityMedium
}

func parseSeverity(str string) api.Severity {
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

func (s *Scanner) severityFor(name string) api.Severity {
	if sev, ok := s.severities[name]; ok {
		return sev
	}
	return api.SeverityMedium
}
