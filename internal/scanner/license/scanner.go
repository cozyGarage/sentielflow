// Package license provides license policy scanning
package license

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner checks dependency licenses against policy
type Scanner struct {
	config *config.Config
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new license scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{config: cfg}
}

func (s *Scanner) Name() string { return "license" }

func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)
	return base == "package.json" || base == "go.mod" || base == "Cargo.toml"
}

// Scan performs license policy checking
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}

	denied := s.config.Scanners.License.Denied
	if len(denied) == 0 {
		denied = []string{"GPL-3.0", "AGPL-3.0", "SSPL-1.0"}
	}

	if findings, err := s.checkPackageJSON(path, denied); err == nil {
		result.Findings = append(result.Findings, findings...)
		result.FilesCount++
	}
	if findings, err := s.checkGoMod(path, denied); err == nil {
		result.Findings = append(result.Findings, findings...)
		result.FilesCount++
	}

	return result, nil
}

func (s *Scanner) checkPackageJSON(path string, denied []string) ([]api.Finding, error) {
	pkgPath := filepath.Join(path, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Name         string `json:"name"`
		License      string `json:"license"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var findings []api.Finding
	if pkg.License != "" {
		if f := s.checkLicense(pkg.Name, pkg.License, denied, pkgPath); f != nil {
			findings = append(findings, *f)
		}
	}

	// Check known problematic packages
	knownLicenses := s.getKnownLicenses()
	for dep := range pkg.Dependencies {
		if lic, ok := knownLicenses[dep]; ok {
			if f := s.checkLicense(dep, lic, denied, pkgPath); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

func (s *Scanner) checkGoMod(path string, denied []string) ([]api.Finding, error) {
	goModPath := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	knownLicenses := s.getKnownLicenses()
	var findings []api.Finding

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || !strings.Contains(trimmed, " ") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 && !strings.HasPrefix(parts[0], "require") && parts[0] != ")" {
			mod := parts[0]
			if lic, ok := knownLicenses[mod]; ok {
				if f := s.checkLicense(mod, lic, denied, goModPath); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}

	return findings, nil
}

func (s *Scanner) checkLicense(name, license string, denied []string, filePath string) *api.Finding {
	for _, d := range denied {
		if strings.EqualFold(license, d) || strings.Contains(strings.ToUpper(license), strings.ToUpper(d)) {
			return &api.Finding{
				ID:          fmt.Sprintf("LICENSE-%s", name),
				Type:        api.FindingTypePolicyViolation,
				Severity:    api.SeverityHigh,
				Title:       fmt.Sprintf("Denied license: %s", license),
				Description: fmt.Sprintf("Package %s uses license %s which is not allowed by policy", name, license),
				Location:    api.Location{File: filePath, Snippet: fmt.Sprintf("%s (%s)", name, license)},
				Remediation: fmt.Sprintf("Replace %s with an alternative using an approved license", name),
				Scanner:     "license",
				RuleID:      "denied-license",
				Confidence:  0.9,
				Metadata:    map[string]any{"license": license, "package": name},
			}
		}
	}
	return nil
}

// getKnownLicenses returns a minimal known-license database for common packages
func (s *Scanner) getKnownLicenses() map[string]string {
	return map[string]string{
		"readline":                    "GPL-3.0",
		"github.com/hashicorp/go-plugin": "MPL-2.0",
		"webpack":                     "MIT",
		"lodash":                      "MIT",
	}
}
