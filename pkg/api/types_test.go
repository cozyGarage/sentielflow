package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseSeverityAndRank(t *testing.T) {
	if ParseSeverity("CRITICAL") != SeverityCritical {
		t.Fatal("CRITICAL")
	}
	if ParseSeverity("moderate") != SeverityMedium {
		t.Fatal("moderate")
	}
	if !MeetsMinimum(SeverityHigh, "medium") {
		t.Fatal("high should meet medium")
	}
	if MeetsMinimum(SeverityLow, "high") {
		t.Fatal("low should not meet high")
	}
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Fatal("critical should outrank high")
	}
}

func TestDurationMSJSON(t *testing.T) {
	result := ScanResult{
		Findings: []Finding{},
		Duration: DurationMS(1500 * time.Millisecond),
		ScannerRuns: []ScannerRun{
			{Scanner: "secrets", Duration: DurationMS(250 * time.Millisecond)},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["duration_ms"]) != "1500" {
		t.Fatalf("expected duration_ms=1500, got %s", string(raw["duration_ms"]))
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Duration.Std() != 1500*time.Millisecond {
		t.Fatalf("round-trip duration = %v", decoded.Duration.Std())
	}
}
