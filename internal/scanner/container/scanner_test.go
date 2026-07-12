package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestDetectImageFromDockerfile(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfile := `FROM nginx:1.25-alpine
RUN apk add --no-cache curl
COPY . /app
`
	os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0644)

	s := NewScanner(&config.Config{})
	image := s.detectImage(tmpDir)
	if image != "nginx:1.25-alpine" {
		t.Errorf("expected nginx:1.25-alpine, got %s", image)
	}
}

func TestScanSkipsWithoutTrivy(t *testing.T) {
	if IsTrivyAvailable() {
		t.Skip("trivy is installed, skipping skip test")
	}

	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			Container: config.ContainerConfig{Image: "alpine:latest"},
		},
	})
	result, err := s.Scan(context.Background(), ".", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Skipped {
		t.Error("expected scan to be skipped when trivy unavailable")
	}
}

func TestSupportsDockerfile(t *testing.T) {
	s := NewScanner(&config.Config{})
	if !s.Supports("Dockerfile") {
		t.Error("should support Dockerfile")
	}
}

func TestParseSeverity(t *testing.T) {
	if parseSeverity("CRITICAL") != "critical" {
		t.Error("expected critical")
	}
	if parseSeverity("unknown") != "info" {
		t.Error("expected info for unknown")
	}
}
