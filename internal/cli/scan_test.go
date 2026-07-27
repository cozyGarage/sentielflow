package cli

import (
	"strings"
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

func TestApplyScanFlagsAllPreservesOverrides(t *testing.T) {
	prevAll := scanAll
	prevFailOn := failOnSeverity
	prevBaseline := useBaseline
	prevImage := containerImage
	prevAI := scanAI
	t.Cleanup(func() {
		scanAll = prevAll
		failOnSeverity = prevFailOn
		useBaseline = prevBaseline
		containerImage = prevImage
		scanAI = prevAI
	})

	scanAll = true
	failOnSeverity = "low"
	useBaseline = true
	containerImage = "alpine:3.19"
	scanAI = false

	cfg := config.Default()
	cfg.Scanners.Secrets.Enabled = false
	cfg.Baseline.Enabled = false
	cfg.FailOn.Severity = "high"

	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}

	if !cfg.Scanners.Secrets.Enabled || !cfg.Scanners.SAST.Enabled || !cfg.Scanners.Container.Enabled {
		t.Fatal("expected --all to enable implemented scanners")
	}
	if cfg.FailOn.Severity != "low" {
		t.Fatalf("expected --fail-on to apply with --all, got %q", cfg.FailOn.Severity)
	}
	if !cfg.Baseline.Enabled {
		t.Fatal("expected --baseline to apply with --all")
	}
	if cfg.Scanners.Container.Image != "alpine:3.19" {
		t.Fatalf("expected container image override, got %q", cfg.Scanners.Container.Image)
	}
}

func TestApplyScanFlagsRejectsAI(t *testing.T) {
	prevAI := scanAI
	prevAll := scanAll
	t.Cleanup(func() {
		scanAI = prevAI
		scanAll = prevAll
	})

	scanAI = true
	scanAll = false
	err := applyScanFlags(config.Default())
	if err == nil || !strings.Contains(err.Error(), config.AINotAvailableMessage) {
		t.Fatalf("expected --ai rejection with shared message, got %v", err)
	}
}

func TestScannerErrorsFailsCI(t *testing.T) {
	result := &api.ScanResult{
		ScannerRuns: []api.ScannerRun{
			{Scanner: "dependencies", Error: "osv unavailable"},
		},
	}
	err := scannerErrors(result)
	if err == nil {
		t.Fatal("expected scanner error to fail the scan")
	}
}

func TestValidatePolicyNameRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../evil", "foo/bar", `foo\bar`, "bad name"} {
		if err := validatePolicyName(name); err == nil {
			t.Fatalf("expected rejection for %q", name)
		}
	}
	if err := validatePolicyName("require-https"); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestRemoveHookBlockPreservesOtherHooks(t *testing.T) {
	content := "#!/bin/sh\necho existing\n\n# >>> sentinelflow-pre-commit-hook\n# sentinelflow-pre-commit-hook\nexec sentinelflow scan\n# <<< sentinelflow-pre-commit-hook\n"
	updated, removed := removeHookBlock(content)
	if !removed {
		t.Fatal("expected block removal")
	}
	if !strings.Contains(updated, "echo existing") {
		t.Fatal("expected existing hook content to remain")
	}
	if strings.Contains(updated, "sentinelflow") {
		t.Fatal("expected SentinelFlow block to be removed")
	}
}
