package cli

import (
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestShouldFailChecksAllGates(t *testing.T) {
	cfg := &config.Config{
		FailOn: config.FailOnConfig{
			Severity:         "high",
			Secrets:          true,
			PolicyViolations: true,
		},
	}

	mediumOnly := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypeMisconfiguration, Severity: api.SeverityMedium},
		},
	}
	if shouldFail(mediumOnly, cfg) {
		t.Error("medium-only findings should not fail on high severity threshold")
	}

	withSecret := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypeSecret, Severity: api.SeverityLow},
		},
	}
	if !shouldFail(withSecret, cfg) {
		t.Error("expected fail when secrets gate is enabled")
	}

	withPolicy := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypePolicyViolation, Severity: api.SeverityLow},
		},
	}
	if !shouldFail(withPolicy, cfg) {
		t.Error("expected fail when policy_violations gate is enabled")
	}
}
