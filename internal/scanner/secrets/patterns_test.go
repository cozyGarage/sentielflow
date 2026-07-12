package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestLoadCustomPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	patternsDir := filepath.Join(tmpDir, ".sentinelflow")
	os.MkdirAll(patternsDir, 0755)

	patternsYAML := `patterns:
  - id: custom-api-token
    name: Custom API Token
    regex: "CUST_[A-Za-z0-9]{32}"
    severity: critical
    description: Custom API token pattern
`
	os.WriteFile(filepath.Join(patternsDir, "patterns.yaml"), []byte(patternsYAML), 0644)

	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg := &config.Config{}
	scanner := NewScanner(cfg)

	found := false
	for _, p := range scanner.patterns {
		if p.ID == "custom-api-token" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom pattern to be loaded")
	}
}

func TestCustomPatternDetection(t *testing.T) {
	tmpDir := t.TempDir()
	patternsDir := filepath.Join(tmpDir, ".sentinelflow")
	os.MkdirAll(patternsDir, 0755)

	patternsYAML := `patterns:
  - id: custom-token
    name: Custom Token
    regex: "CUST_[A-Za-z0-9]{20}"
    severity: high
    description: Custom token
`
	os.WriteFile(filepath.Join(patternsDir, "patterns.yaml"), []byte(patternsYAML), 0644)

	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg := &config.Config{}
	scanner := NewScanner(cfg)
	findings := scanner.scanContent("api_key=CUST_AbCdEfGhIjKlMnOpQrSt", "test.env", 0)

	if len(findings) == 0 {
		t.Error("expected custom pattern to detect token")
	}
}
