package baseline

import (
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestFilterBaselinedFindings(t *testing.T) {
	findings := []api.Finding{
		{ID: "SEC-1", RuleID: "aws-access-key", Title: "AWS Key", Location: api.Location{File: "config.go", StartLine: 1}},
		{ID: "SEC-2", RuleID: "github-token", Title: "GitHub Token", Location: api.Location{File: "app.go", StartLine: 5}},
	}

	bl := Generate(findings[:1])

	filtered := Filter(findings, bl)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered))
	}
	if filtered[0].ID != "SEC-2" {
		t.Errorf("expected SEC-2, got %s", filtered[0].ID)
	}
}

func TestHashFindingStable(t *testing.T) {
	f := api.Finding{
		RuleID:   "test-rule",
		Title:    "Test",
		Location: api.Location{File: "foo.go", StartLine: 10},
	}
	h1 := HashFinding(f)
	h2 := HashFinding(f)
	if h1 != h2 {
		t.Error("hash should be stable")
	}
}
