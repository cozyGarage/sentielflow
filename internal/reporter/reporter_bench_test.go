package reporter

import (
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// createLargeResult creates a scan result with many findings for benchmarking
func createLargeResult(count int) *api.ScanResult {
	findings := make([]api.Finding, count)
	for i := 0; i < count; i++ {
		findings[i] = api.Finding{
			ID:          "TEST-" + string(rune(i+1000)),
			Type:        api.FindingTypeSecret,
			Severity:    api.SeverityHigh,
			Title:       "Test Finding " + string(rune(i+48)),
			Description: "This is a test finding for benchmarking purposes",
			Location: api.Location{
				File:      "test.go",
				StartLine: i + 1,
				EndLine:   i + 1,
			},
			Remediation: "Fix the issue",
			Scanner:     "test",
			RuleID:      "test-rule",
			Confidence:  0.95,
		}
	}

	return &api.ScanResult{
		Findings: findings,
		ScannerRuns: []api.ScannerRun{
			{
				Scanner:       "test",
				StartTime:     time.Now(),
				EndTime:       time.Now().Add(time.Second),
				Duration:      api.DurationMS(time.Second),
				FilesCount:    100,
				FindingsCount: count,
			},
		},
		Metadata: api.ScanMetadata{
			TargetPath:          "/test/path",
			StartTime:           time.Now(),
			EndTime:             time.Now().Add(time.Second),
			SentinelFlowVersion: "1.0.0",
		},
		Duration: api.DurationMS(time.Second),
	}
}

// BenchmarkMarkdownFormatter benchmarks markdown report generation
func BenchmarkMarkdownFormatter(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run("Findings_"+string(rune(size+48)), func(b *testing.B) {
			result := createLargeResult(size)
			formatter := &MarkdownFormatter{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}

// BenchmarkTextFormatter benchmarks text report generation
func BenchmarkTextFormatter(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run("Findings_"+string(rune(size+48)), func(b *testing.B) {
			result := createLargeResult(size)
			formatter := &TextFormatter{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}

// BenchmarkJSONFormatter benchmarks JSON report generation
func BenchmarkJSONFormatter(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run("Findings_"+string(rune(size+48)), func(b *testing.B) {
			result := createLargeResult(size)
			formatter := &JSONFormatter{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}

// BenchmarkSARIFFormatter benchmarks SARIF report generation
func BenchmarkSARIFFormatter(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run("Findings_"+string(rune(size+48)), func(b *testing.B) {
			result := createLargeResult(size)
			formatter := &SARIFFormatter{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}

// BenchmarkHTMLFormatter benchmarks HTML report generation
func BenchmarkHTMLFormatter(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run("Findings_"+string(rune(size+48)), func(b *testing.B) {
			result := createLargeResult(size)
			formatter := &HTMLFormatter{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}

// BenchmarkAllFormats benchmarks all formatters with a typical result
func BenchmarkAllFormats(b *testing.B) {
	result := createLargeResult(50)

	formatters := map[string]Formatter{
		"text":     &TextFormatter{},
		"markdown": &MarkdownFormatter{},
		"json":     &JSONFormatter{},
		"sarif":    &SARIFFormatter{},
		"html":     &HTMLFormatter{},
	}

	for name, formatter := range formatters {
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = formatter.Format(result)
			}
		})
	}
}
