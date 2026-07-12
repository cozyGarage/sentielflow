package policy

import (
	"testing"
)

func TestValidatePolicy(t *testing.T) {
	engine := NewOPAEngine()
	validPolicy := `package test

allow {
    input.secure == true
}
`
	if err := engine.ValidatePolicy(validPolicy); err != nil {
		t.Fatalf("expected valid policy, got error: %v", err)
	}
}

func TestValidatePolicyInvalid(t *testing.T) {
	engine := NewOPAEngine()
	invalidPolicy := `package test

allow {
    input.secure ====
}
`
	if err := engine.ValidatePolicy(invalidPolicy); err == nil {
		t.Error("expected validation error for invalid policy")
	}
}

func TestEvaluatePolicy(t *testing.T) {
	engine := NewOPAEngine()
	policy := `package sentinelflow.test

violation[msg] {
    input.insecure == true
    msg := "Resource is insecure"
}
`
	if err := engine.LoadPolicy("test", policy); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	result, err := engine.EvaluatePolicy("test", map[string]interface{}{"insecure": true})
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestEvaluatePolicyNoViolations(t *testing.T) {
	engine := NewOPAEngine()
	policy := `package sentinelflow.test

violation[msg] {
    input.insecure == true
    msg := "Resource is insecure"
}
`
	engine.LoadPolicy("test", policy)

	result, err := engine.EvaluatePolicy("test", map[string]interface{}{"insecure": false})
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations, got %d", len(result.Violations))
	}
}
