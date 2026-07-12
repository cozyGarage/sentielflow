package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestDetectSQLInjection(t *testing.T) {
	s := NewScanner(&config.Config{})
	tmpDir := t.TempDir()
	content := `query := "SELECT * FROM users WHERE id = " + request.Params["id"]`
	path := filepath.Join(tmpDir, "handler.go")
	os.WriteFile(path, []byte(content), 0644)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected SQL injection finding")
	}
}

func TestDetectPathTraversal(t *testing.T) {
	s := NewScanner(&config.Config{})
	tmpDir := t.TempDir()
	content := `path := baseDir + "/../etc/passwd"`
	path := filepath.Join(tmpDir, "file.go")
	os.WriteFile(path, []byte(content), 0644)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "path-traversal" {
			found = true
		}
	}
	if !found {
		t.Error("expected path traversal finding")
	}
}

func TestSupportsExtensions(t *testing.T) {
	s := NewScanner(&config.Config{})
	if !s.Supports("main.go") {
		t.Error("should support .go files")
	}
	if s.Supports("image.png") {
		t.Error("should not support .png files")
	}
}
