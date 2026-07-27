package policies

import (
	"strings"
	"testing"
)

func TestBuiltinCatalogComplete(t *testing.T) {
	names := Names()
	if len(names) != 4 {
		t.Fatalf("expected 4 built-ins, got %d: %v", len(names), names)
	}

	selected, err := LoadSelected(names)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 4 {
		t.Fatalf("expected 4 loaded policies, got %d", len(selected))
	}

	for _, name := range names {
		b, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		if b.Content == "" || !strings.Contains(b.Content, "package sentinelflow") {
			t.Fatalf("built-in %s has invalid content", name)
		}
		if b.Severity == "" || b.Description == "" {
			t.Fatalf("built-in %s missing metadata", name)
		}
	}
}

func TestLoadSelectedRejectsUnknown(t *testing.T) {
	_, err := LoadSelected([]string{"no-public-s3-buckets", "does-not-exist"})
	if err == nil {
		t.Fatal("expected error for unknown built-in")
	}
}
