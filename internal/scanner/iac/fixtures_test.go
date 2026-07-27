package iac

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/testutil"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestIaCFixtures(t *testing.T) {
	cfg := config.Default()
	scanner := NewScanner(cfg)
	root := testutil.RepoRoot(t)
	fixtures := filepath.Join(root, "test", "fixtures", "iac")

	result, err := scanner.Scan(context.Background(), fixtures, nil)
	if err != nil {
		t.Fatalf("scan fixtures: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected IaC findings from test/fixtures/iac")
	}

	want := map[string]bool{
		"aws-s3-public-acl": false,
		"k8s-privileged":    false,
		"user-root":         false,
	}
	for _, f := range result.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("expected rule %s from fixtures", rule)
		}
	}

	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == api.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical IaC finding from fixtures")
	}
}
