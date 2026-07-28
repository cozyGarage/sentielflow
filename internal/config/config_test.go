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
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected AI enabled config to fail validation")
	}
	if err.Error() != AINotAvailableMessage {
		t.Fatalf("expected shared AI rejection message, got %v", err)
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults should be valid: %v", err)
	}
}

func TestValidateNormalizesFailOnSeverity(t *testing.T) {
	cfg := Default()
	cfg.FailOn.Severity = "HIGH"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected HIGH to validate: %v", err)
	}
	if cfg.FailOn.Severity != "high" {
		t.Fatalf("expected normalized severity high, got %q", cfg.FailOn.Severity)
	}
}
