// Package iac provides Infrastructure-as-Code security scanning
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

	// Terraform files
	if ext == ".tf" || ext == ".tfvars" {
		return true
	}

	// Kubernetes manifests
	if ext == ".yaml" || ext == ".yml" {
		return true
	}

	// Dockerfile (exclude Go source files named dockerfile.go)
	if ext != ".go" && (base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")) {
		return true
	}

	// CloudFormation
	if ext == ".json" && strings.Contains(strings.ToLower(path), "cloudformation") {
		return true
	}

	return false
}

// Scan performs IaC security scanning
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	var files []string

	// Check if path is a file or directory
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

	// Scan files concurrently
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

// scanFile determines file type and delegates to appropriate scanner
func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	ext := strings.ToLower(filepath.Ext(filePath))
	base := strings.ToLower(filepath.Base(filePath))

	// Terraform
	if ext == ".tf" || ext == ".tfvars" {
		return s.terraform.ScanFile(ctx, filePath, basePath)
	}

	// Dockerfile
	if ext != ".go" && (base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")) {
		return s.docker.ScanFile(ctx, filePath, basePath)
	}

	// Kubernetes (YAML/YML files)
	if ext == ".yaml" || ext == ".yml" {
		// Check if it's a Kubernetes manifest
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

		// Skip common directories
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" {
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
