package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestEngineInitialization(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
		Policies: config.PoliciesConfig{
			Enabled: true,
		},
	}

	engine := NewEngine(cfg)

	if engine == nil {
		t.Fatal("Failed to create engine")
	}

	scanners := engine.GetScanners()

	// Should have 4 scanners (secrets, iac, dependencies, policy)
	if len(scanners) != 4 {
		t.Errorf("Expected 4 scanners, got %d", len(scanners))
	}
}

func TestScanNonExistentPath(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	_, err := engine.Scan(context.Background(), "/nonexistent/path")

	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	// Create temporary empty directory
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Should have metadata
	if result.Metadata.TargetPath != tmpDir {
		t.Errorf("Expected target path %s, got %s", tmpDir, result.Metadata.TargetPath)
	}
}

func TestCollectFilesSkipsHidden(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".hidden"), []byte("secret"), 0644)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	os.Mkdir(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "config"), []byte("git config"), 0644)

	cfg := &config.Config{}
	engine := NewEngine(cfg)

	files, err := engine.collectFiles(tmpDir)
	if err != nil {
		t.Fatalf("Failed to collect files: %v", err)
	}

	// Should include test.go and .hidden but not .git/config
	foundGitFile := false
	foundTestFile := false

	for _, f := range files {
		if filepath.Base(f) == "config" {
			foundGitFile = true
		}
		if filepath.Base(f) == "test.go" {
			foundTestFile = true
		}
	}

	if foundGitFile {
		t.Error("Should not collect files from .git directory")
	}

	if !foundTestFile {
		t.Error("Should collect test.go")
	}
}

func TestAllowlistFiltering(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main"), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{
				Enabled:   true,
				Allowlist: []string{"*_test.go"},
			},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check that test files were skipped
	for _, finding := range result.Findings {
		if filepath.Base(finding.Location.File) == "main_test.go" {
			t.Error("Should not scan files matching allowlist pattern")
		}
	}
}
