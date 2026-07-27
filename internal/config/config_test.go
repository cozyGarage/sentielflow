package config

import "testing"

func TestValidateRejectsInvalidSeverity(t *testing.T) {
	cfg := Default()
	cfg.FailOn.Severity = "urgent"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid severity to fail validation")
	}
}

func TestValidateRejectsAIEnabled(t *testing.T) {
	cfg := Default()
	cfg.Scanners.AI.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected AI enabled config to fail validation in v1.0")
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults should be valid: %v", err)
	}
}
