package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func createTestResult() *api.ScanResult {
	return &api.ScanResult{
		Findings: []api.Finding{
			{
				ID:          "SEC-001",
				Type:        api.FindingTypeSecret,
				Severity:    api.SeverityCritical,
				Title:       "Hardcoded AWS Access Key",
				Description: "Found AWS access key in source code",
				Location:    api.Location{File: "config.go", StartLine: 10, EndLine: 10},
				Remediation: "Remove hardcoded credentials and use environment variables",
				Scanner:     "secrets",
				RuleID:      "aws-access-key",
				Confidence:  0.95,
			},
			{
				ID:          "IAC-001",
				Type:        api.FindingTypeMisconfiguration,
				Severity:    api.SeverityHigh,
				Title:       "Public S3 Bucket",
				Description: "S3 bucket has public read ACL",
				Location:    api.Location{File: "main.tf", StartLine: 15, EndLine: 18},
				Remediation: "Set ACL to 'private'",
				Scanner:     "iac",
				RuleID:      "aws-s3-public-acl",
				Confidence:  1.0,
			},
		},
		ScannerRuns: []api.ScannerRun{
			{
				Scanner:       "secrets",
				StartTime:     time.Now().Add(-2 * time.Minute),
				EndTime:       time.Now().Add(-1 * time.Minute),
				Duration:      time.Minute,
				FilesCount:    10,
				FindingsCount: 1,
			},
			{
				Scanner:       "iac",
				StartTime:     time.Now().Add(-1 * time.Minute),
				EndTime:       time.Now(),
				Duration:      time.Minute,
				FilesCount:    5,
				FindingsCount: 1,
			},
		},
		Metadata: api.ScanMetadata{
			TargetPath:          "/path/to/project",
			StartTime:           time.Now().Add(-2 * time.Minute),
			EndTime:             time.Now(),
			SentinelFlowVersion: "1.0.0",
		},
		Duration: 2 * time.Minute,
	}
}

func TestMarkdownFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &MarkdownFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for key sections
	if !strings.Contains(output, "# 🛡️ SentinelFlow Security Scan Report") {
		t.Error("Missing header")
	}

	if !strings.Contains(output, "## 📊 Summary") {
		t.Error("Missing summary section")
	}

	if !strings.Contains(output, "🔴 **Critical**: 1") {
		t.Error("Missing critical findings count")
	}

	if !strings.Contains(output, "🟠 **High**: 1") {
		t.Error("Missing high findings count")
	}

	// Check for findings
	if !strings.Contains(output, "Hardcoded AWS Access Key") {
		t.Error("Missing finding title")
	}

	if !strings.Contains(output, "Public S3 Bucket") {
		t.Error("Missing second finding")
	}
}

func TestJSONFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &JSONFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Should be valid JSON
	if !strings.HasPrefix(output, "{") {
		t.Error("Output is not JSON")
	}

	if !strings.Contains(output, `"findings"`) {
		t.Error("Missing findings field")
	}

	if !strings.Contains(output, `"SEC-001"`) {
		t.Error("Missing finding ID")
	}
}

func TestHTMLFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &HTMLFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for HTML structure
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE")
	}

	if !strings.Contains(output, "<html") {
		t.Error("Missing HTML tag")
	}

	if !strings.Contains(output, "SentinelFlow Security Report") {
		t.Error("Missing title")
	}

	// Check for findings
	if !strings.Contains(output, "Hardcoded AWS Access Key") {
		t.Error("Missing finding in HTML")
	}

	// Check for CSS
	if !strings.Contains(output, "<style>") {
		t.Error("Missing embedded CSS")
	}
}

func TestTextFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &TextFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Check for key sections
	if !strings.Contains(output, "SentinelFlow Security Scan Report") {
		t.Error("Missing header")
	}

	if !strings.Contains(output, "Total Findings: 2") {
		t.Error("Missing total findings count")
	}

	if !strings.Contains(output, "Critical: 1") {
		t.Error("Missing critical count")
	}

	if !strings.Contains(output, "High:     1") {
		t.Error("Missing high count")
	}
}

func TestSARIFFormatter(t *testing.T) {
	result := createTestResult()
	formatter := &SARIFFormatter{}

	output, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Should be valid JSON
	if !strings.HasPrefix(output, "{") {
		t.Error("Output is not JSON")
	}

	// Check for SARIF structure
	if !strings.Contains(output, `"version"`) {
		t.Error("Missing SARIF version")
	}

	if !strings.Contains(output, `"runs"`) {
		t.Error("Missing runs array")
	}

	if !strings.Contains(output, `"results"`) {
		t.Error("Missing results array")
	}

	if !strings.Contains(output, "SentinelFlow") {
		t.Error("Missing tool name")
	}
}

func TestEmptyResults(t *testing.T) {
	result := &api.ScanResult{
		Findings:    []api.Finding{},
		ScannerRuns: []api.ScannerRun{},
		Metadata: api.ScanMetadata{
			TargetPath:          "/path/to/project",
			StartTime:           time.Now(),
			EndTime:             time.Now(),
			SentinelFlowVersion: "1.0.0",
		},
	}

	formatters := []Formatter{
		&TextFormatter{},
		&MarkdownFormatter{},
		&JSONFormatter{},
		&HTMLFormatter{},
		&SARIFFormatter{},
	}

	for _, formatter := range formatters {
		_, err := formatter.Format(result)
		if err != nil {
			t.Errorf("Formatter %T failed on empty result: %v", formatter, err)
		}
	}
}
