package dependencies

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestSeverityFromVulnDB(t *testing.T) {
	tests := []struct {
		in   string
		want api.Severity
	}{
		{"CRITICAL", api.SeverityCritical},
		{"HIGH", api.SeverityHigh},
		{"MODERATE", api.SeverityMedium},
		{"LOW", api.SeverityLow},
		{"", api.SeverityMedium},
	}

	for _, tc := range tests {
		if got := severityFromVulnDB(tc.in, 0); got != tc.want {
			t.Errorf("severityFromVulnDB(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestCheckVulnerabilitiesUsesOSV(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"OSV-TEST-1","summary":"test vuln","aliases":["CVE-2024-0001"]}]}`))
	}))
	defer server.Close()

	source := vulndb.NewOSVSource(server.Client())
	source.SetBaseURL(server.URL)

	client, err := vulndb.NewClient(vulndb.WithSources(source))
	if err != nil {
		t.Fatal(err)
	}

	scanner := &Scanner{
		config: &config.Config{},
		client: client,
	}

	vulns, err := scanner.checkVulnerabilities(context.Background(), Dependency{
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: "npm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "OSV-TEST-1" {
		t.Fatalf("unexpected vuln id %s", vulns[0].ID)
	}
}

func TestGoModScannerParsesSingleLineRequire(t *testing.T) {
	tmp := t.TempDir()
	content := "module example.com/demo\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n"
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&GoModScanner{}).Scan(context.Background(), tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}
	if deps[0].Name != "github.com/foo/bar" || deps[0].Version != "v1.2.3" {
		t.Fatalf("unexpected dependency: %+v", deps[0])
	}
}
