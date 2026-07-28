package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
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

func TestValidateImageRef(t *testing.T) {
	if err := validateImageRef("-o /tmp/out"); err == nil {
		t.Fatal("expected option-like image refs to be rejected")
	}
	if err := validateImageRef("nginx:1.25"); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestParseSeverityViaAPI(t *testing.T) {
	if api.ParseSeverity("CRITICAL") != api.SeverityCritical {
		t.Fatal("expected CRITICAL -> critical")
	}
	if api.ParseSeverity("unknown") != api.SeverityInfo {
		t.Fatal("expected unknown -> info")
	}
}

func TestScanErrorsWithoutTrivy(t *testing.T) {
	if IsTrivyAvailable() {
		t.Skip("trivy is installed, skipping missing-trivy test")
	}

	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			Container: config.ContainerConfig{Image: "alpine:latest"},
		},
	})
	result, err := s.Scan(context.Background(), ".", nil)
	if err == nil {
		t.Fatal("expected error when trivy is unavailable")
	}
	if result == nil {
		t.Fatal("expected non-nil result alongside error")
	}
}

func TestScanErrorsWithoutImage(t *testing.T) {
	s := NewScanner(&config.Config{
		Scanners: config.ScannersConfig{
			Container: config.ContainerConfig{Image: ""},
		},
	})
	result, err := s.Scan(context.Background(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error when no image is configured")
	}
	if result == nil {
		t.Fatal("expected non-nil result alongside error")
	}
}

func TestSupportsDockerfile(t *testing.T) {
	s := NewScanner(&config.Config{})
	if !s.Supports("Dockerfile") {
		t.Error("should support Dockerfile")
	}
}
