package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestGenerateFromGoMod(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/test

go 1.24

require (
	github.com/spf13/cobra v1.10.2
	github.com/fatih/color v1.16.0
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)

	s := NewScanner(&config.Config{})
	result, err := s.Generate(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if len(result.Document.Components) < 2 {
		t.Errorf("expected at least 2 components, got %d", len(result.Document.Components))
	}
	if result.Document.BOMFormat != "CycloneDX" {
		t.Error("expected CycloneDX format")
	}
}

func TestWriteJSON(t *testing.T) {
	tmpDir := t.TempDir()
	s := NewScanner(&config.Config{})
	doc := &CycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  []Component{{Type: "library", Name: "test", Version: "1.0.0"}},
	}
	outPath := filepath.Join(tmpDir, "sbom.json")
	if err := s.WriteJSON(doc, outPath); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Error("output file not created")
	}
}
