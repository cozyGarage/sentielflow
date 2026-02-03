package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// OPAEngine wraps the OPA policy engine
type OPAEngine struct {
	policies map[string]*rego.PreparedEvalQuery
	modules  map[string]string
}

// NewOPAEngine creates a new OPA engine
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{
		policies: make(map[string]*rego.PreparedEvalQuery),
		modules:  make(map[string]string),
	}
}

// LoadPolicy loads a single Rego policy
func (e *OPAEngine) LoadPolicy(name, content string) error {
	// Parse and compile the policy
	query, err := rego.New(
		rego.Query("data.sentinelflow."+name+".violation"),
		rego.Module(name+".rego", content),
	).PrepareForEval(context.Background())

	if err != nil {
		return fmt.Errorf("failed to compile policy %s: %w", name, err)
	}

	e.policies[name] = &query
	e.modules[name] = content

	return nil
}

// LoadPoliciesFromDir loads all .rego files from a directory
func (e *OPAEngine) LoadPoliciesFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read policy %s: %w", path, err)
		}

		name := strings.TrimSuffix(filepath.Base(path), ".rego")
		return e.LoadPolicy(name, string(content))
	})
}

// EvaluatePolicy evaluates a policy against input data
func (e *OPAEngine) EvaluatePolicy(policyName string, input interface{}) (*PolicyResult, error) {
	query, ok := e.policies[policyName]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", policyName)
	}

	// Evaluate the policy
	results, err := query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	result := &PolicyResult{
		PolicyName: policyName,
		Violations: []PolicyViolation{},
	}

	// Process results
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		// Check if there are violations
		violations, ok := results[0].Expressions[0].Value.([]interface{})
		if ok {
			for _, v := range violations {
				if vMap, ok := v.(map[string]interface{}); ok {
					violation := PolicyViolation{
						Message:  getString(vMap, "msg"),
						Resource: getString(vMap, "resource"),
					}
					result.Violations = append(result.Violations, violation)
				}
			}
		}
	}

	return result, nil
}

// ValidatePolicy validates policy syntax without evaluating
func (e *OPAEngine) ValidatePolicy(content string) error {
	_, err := rego.New(
		rego.Query("data"),
		rego.Module("test.rego", content),
	).PrepareForEval(context.Background())

	return err
}

// ListPolicies returns all loaded policy names
func (e *OPAEngine) ListPolicies() []string {
	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// PolicyResult contains the result of policy evaluation
type PolicyResult struct {
	PolicyName string
	Violations []PolicyViolation
}

// PolicyViolation represents a single policy violation
type PolicyViolation struct {
	Message  string
	Resource string
}

// helper to extract string from map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ConvertToFindings converts policy violations to API findings
func ConvertToFindings(result *PolicyResult, severity api.Severity) []api.Finding {
	var findings []api.Finding

	for _, violation := range result.Violations {
		finding := api.Finding{
			ID:          fmt.Sprintf("POLICY-%s", result.PolicyName),
			Type:        api.FindingTypePolicyViolation,
			Severity:    severity,
			Title:       fmt.Sprintf("Policy Violation: %s", result.PolicyName),
			Description: violation.Message,
			Scanner:     "policy",
			RuleID:      result.PolicyName,
			Confidence:  1.0,
		}

		if violation.Resource != "" {
			finding.Location.File = violation.Resource
		}

		findings = append(findings, finding)
	}

	return findings
}
