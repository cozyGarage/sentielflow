package filter

import "testing"

func TestShouldSkipTestFiles(t *testing.T) {
	if !ShouldSkip("internal/scanner/sast/scanner_test.go", nil) {
		t.Error("expected _test.go to be skipped")
	}
}

func TestShouldSkipAllowlistPath(t *testing.T) {
	allowlist := []string{"internal/scanner/sast/scanner.go"}
	if !ShouldSkip("internal/scanner/sast/scanner.go", allowlist) {
		t.Error("expected allowlisted path to be skipped")
	}
}

func TestShouldSkipGlobSuffix(t *testing.T) {
	allowlist := []string{"**/*_test.go"}
	if !ShouldSkip("internal/scanner/sast/scanner_test.go", allowlist) {
		t.Error("expected glob suffix match")
	}
}
