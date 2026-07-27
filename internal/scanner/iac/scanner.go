package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements IaC security scanning
type Scanner struct {
	config    *config.Config
	terraform *TerraformScanner
	k8s       *KubernetesScanner
	docker    *DockerfileScanner
}

// ScannerResult contains scan results (compatible with scanner.ScannerResult)
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new IaC scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		config:    cfg,
		terraform: NewTerraformScanner(cfg),
		k8s:       NewKubernetesScanner(cfg),
		docker:    NewDockerfileScanner(cfg),
	}
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "iac"
}

// Supports returns true for IaC files
func (s *Scanner) Supports(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	if ext == ".tf" || ext == ".tfvars" {
		return s.frameworkEnabled("terraform")
	}

	if ext == ".yaml" || ext == ".yml" {
		return s.frameworkEnabled("kubernetes")
	}

	if ext != ".go" && (base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")) {
		return s.frameworkEnabled("dockerfile")
	}

	if ext == ".json" && strings.Contains(strings.ToLower(path), "cloudformation") {
		return s.frameworkEnabled("cloudformation")
	}

	return false
}

func (s *Scanner) frameworkEnabled(name string) bool {
	frameworks := s.config.Scanners.IaC.Frameworks
	if len(frameworks) == 0 {
		return true
	}
	for _, f := range frameworks {
		if strings.EqualFold(strings.TrimSpace(f), name) {
			return true
		}
	}
	return false
}

// Scan performs IaC security scanning
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		files, err = s.collectIaCFiles(path)
		if err != nil {
			return nil, err
		}
	} else if s.Supports(path) {
		files = []string{path}
	}

	result.FilesCount = len(files)

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 5)

	for _, file := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			findings := s.scanFile(ctx, filePath, path)
			findings = s.filterFindings(findings)

			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	return result, nil
}

func (s *Scanner) filterFindings(findings []api.Finding) []api.Finding {
	if len(findings) == 0 {
		return findings
	}

	skip := map[string]bool{}
	for _, rule := range s.config.Scanners.IaC.SkipRules {
		skip[strings.TrimSpace(rule)] = true
	}

	minSeverity := s.config.Scanners.IaC.Severity
	var out []api.Finding
	for _, f := range findings {
		if skip[f.RuleID] || skip[f.ID] {
			continue
		}
		if minSeverity != "" && !api.MeetsMinimum(f.Severity, minSeverity) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// scanFile determines file type and delegates to appropriate scanner
func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	ext := strings.ToLower(filepath.Ext(filePath))
	base := strings.ToLower(filepath.Base(filePath))

	if (ext == ".tf" || ext == ".tfvars") && s.frameworkEnabled("terraform") {
		return s.terraform.ScanFile(ctx, filePath, basePath)
	}

	if ext != ".go" && (base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")) && s.frameworkEnabled("dockerfile") {
		return s.docker.ScanFile(ctx, filePath, basePath)
	}

	if (ext == ".yaml" || ext == ".yml") && s.frameworkEnabled("kubernetes") {
		if s.k8s.IsKubernetesManifest(filePath) {
			return s.k8s.ScanFile(ctx, filePath, basePath)
		}
	}

	return []api.Finding{}
}

// collectIaCFiles recursively collects IaC files
func (s *Scanner) collectIaCFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" ||
				name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		if s.Supports(path) {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}
