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
