package adapter

import (
	"context"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestContainerAdapterPreservesResultOnError(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners.Container.Enabled = true
	cfg.Scanners.Container.Image = ""

	a := NewContainerAdapter(cfg)
	res, err := a.Scan(context.Background(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error when container enabled without image")
	}
	if res == nil {
		t.Fatal("expected non-nil result alongside error so engine can record FilesCount/Findings")
	}
}
