// Package dependencies provides dependency vulnerability scanning
package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements dependency vulnerability scanning
type Scanner struct {
	config     *config.Config
	ecosystems map[string]EcosystemScanner
}

// EcosystemScanner defines interface for package ecosystem scanners
type EcosystemScanner interface {
	Name() string
	Detect(path string) bool
	Scan(ctx context.Context, path string) ([]Dependency, error)
}

// Dependency represents a project dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	FilePath  string
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	ID          string
	CVE         string
	Severity    api.Severity
	CVSS        float64
	Description string
	FixedIn     string
	References  []string
}

// ScannerResult contains scan results (matching scanner.ScannerResult interface)
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new dependency scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config:     cfg,
		ecosystems: make(map[string]EcosystemScanner),
	}

	// Register ecosystem scanners
	s.ecosystems["go"] = &GoModScanner{}
	s.ecosystems["npm"] = &NpmScanner{}
	s.ecosystems["pip"] = &PipScanner{}
	s.ecosystems["maven"] = &MavenScanner{}
	s.ecosystems["cargo"] = &CargoScanner{}

	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "dependencies"
}

// Supports returns true for dependency files
func (s *Scanner) Supports(path string) bool {
	base := filepath.Base(path)

	supportedFiles := []string{
		"go.mod", "go.sum",
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
		"pom.xml", "build.gradle",
		"Cargo.toml", "Cargo.lock",
		"Gemfile", "Gemfile.lock",
	}

	for _, f := range supportedFiles {
		if base == f {
			return true
		}
	}

	return false
}

// Scan performs dependency vulnerability scanning
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	// Detect ecosystems in the project
	ecosystemsFound := s.detectEcosystems(path)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, ecosys := range ecosystemsFound {
		wg.Add(1)
		go func(ecoName string, eco EcosystemScanner) {
			defer wg.Done()

			deps, err := eco.Scan(ctx, path)
			if err != nil {
				return
			}

			// Check each dependency for vulnerabilities
			for _, dep := range deps {
				vulns := s.checkVulnerabilities(dep)

				for _, vuln := range vulns {
					finding := s.createFinding(dep, vuln, path)

					mu.Lock()
					result.Findings = append(result.Findings, finding)
					mu.Unlock()
				}
			}
		}(name, ecosys)
	}

	wg.Wait()

	result.FilesCount = len(ecosystemsFound)
	return result, nil
}

// detectEcosystems detects which package ecosystems are used
func (s *Scanner) detectEcosystems(path string) map[string]EcosystemScanner {
	detected := make(map[string]EcosystemScanner)

	for name, ecosys := range s.ecosystems {
		if ecosys.Detect(path) {
			detected[name] = ecosys
		}
	}

	return detected
}

// checkVulnerabilities checks if a dependency has known vulnerabilities
func (s *Scanner) checkVulnerabilities(dep Dependency) []Vulnerability {
	// This is a simplified implementation
	// In production, this would query vulnerability databases (NVD, OSV, etc.)

	// For demonstration, return known vulnerable versions
	vulnDB := s.getKnownVulnerabilities()

	var vulnerabilities []Vulnerability

	key := fmt.Sprintf("%s/%s@%s", dep.Ecosystem, dep.Name, dep.Version)
	if vulns, exists := vulnDB[key]; exists {
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities
}

// getKnownVulnerabilities returns a sample vulnerability database
func (s *Scanner) getKnownVulnerabilities() map[string][]Vulnerability {
	// This is a minimal example. In production, integrate with:
	// - National Vulnerability Database (NVD)
	// - OSV (Open Source Vulnerabilities)
	// - GitHub Advisory Database
	// - Snyk vulnerability DB

	return map[string][]Vulnerability{
		// Example vulnerable packages
		"npm/lodash@4.17.20": {
			{
				ID:          "GHSA-29mw-wpgm-hmr9",
				CVE:         "CVE-2020-8203",
				Severity:    api.SeverityHigh,
				CVSS:        7.4,
				Description: "Prototype pollution in lodash",
				FixedIn:     "4.17.21",
				References: []string{
					"https://github.com/lodash/lodash/issues/4874",
					"https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
				},
			},
		},
	}
}

// createFinding creates a finding from a vulnerability
func (s *Scanner) createFinding(dep Dependency, vuln Vulnerability, basePath string) api.Finding {
	relPath, _ := filepath.Rel(basePath, dep.FilePath)

	return api.Finding{
		ID:          fmt.Sprintf("DEP-%s-%s", dep.Ecosystem, vuln.ID),
		Type:        api.FindingTypeVulnerability,
		Severity:    vuln.Severity,
		Title:       fmt.Sprintf("Vulnerable dependency: %s", dep.Name),
		Description: fmt.Sprintf("%s version %s has known vulnerability: %s", dep.Name, dep.Version, vuln.Description),
		Location: api.Location{
			File:    relPath,
			Snippet: fmt.Sprintf("%s@%s", dep.Name, dep.Version),
		},
		Remediation: fmt.Sprintf("Update %s to version %s or later", dep.Name, vuln.FixedIn),
		References:  vuln.References,
		Scanner:     "dependencies",
		RuleID:      vuln.ID,
		CVE:         vuln.CVE,
		CVSS:        vuln.CVSS,
		Confidence:  0.95,
	}
}

// GoModScanner scans Go modules
type GoModScanner struct{}

func (g *GoModScanner) Name() string { return "go" }

func (g *GoModScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil
}

func (g *GoModScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	goModPath := filepath.Join(path, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	lines := strings.Split(string(content), "\n")

	inRequire := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "require") {
			inRequire = true
			continue
		}

		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}

		if inRequire || strings.HasPrefix(trimmed, "require ") {
			// Parse: module version
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "go",
					FilePath:  goModPath,
				})
			}
		}
	}

	return deps, nil
}

// NpmScanner scans npm packages
type NpmScanner struct{}

func (n *NpmScanner) Name() string { return "npm" }

func (n *NpmScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "package.json"))
	return err == nil
}

func (n *NpmScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	pkgPath := filepath.Join(path, "package.json")
	content, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency

	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   strings.TrimPrefix(version, "^"),
			Ecosystem: "npm",
			FilePath:  pkgPath,
		})
	}

	return deps, nil
}

// PipScanner scans Python packages
type PipScanner struct{}

func (p *PipScanner) Name() string { return "pip" }

func (p *PipScanner) Detect(path string) bool {
	files := []string{"requirements.txt", "Pipfile", "pyproject.toml"}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			return true
		}
	}
	return false
}

func (p *PipScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	reqPath := filepath.Join(path, "requirements.txt")
	content, err := os.ReadFile(reqPath)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Parse: package==version or package>=version
		parts := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == '=' || r == '>' || r == '<'
		})

		if len(parts) >= 2 {
			deps = append(deps, Dependency{
				Name:      parts[0],
				Version:   parts[1],
				Ecosystem: "pip",
				FilePath:  reqPath,
			})
		}
	}

	return deps, nil
}

// MavenScanner scans Maven projects
type MavenScanner struct{}

func (m *MavenScanner) Name() string { return "maven" }

func (m *MavenScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "pom.xml"))
	return err == nil
}

func (m *MavenScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	// Simplified Maven scanning
	// In production, parse pom.xml properly
	return []Dependency{}, nil
}

// CargoScanner scans Rust packages
type CargoScanner struct{}

func (c *CargoScanner) Name() string { return "cargo" }

func (c *CargoScanner) Detect(path string) bool {
	_, err := os.Stat(filepath.Join(path, "Cargo.toml"))
	return err == nil
}

func (c *CargoScanner) Scan(ctx context.Context, path string) ([]Dependency, error) {
	// Simplified Cargo scanning
	// In production, parse Cargo.toml properly
	return []Dependency{}, nil
}
