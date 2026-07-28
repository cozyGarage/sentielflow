package redact

import (
	"strings"
	"testing"
)

func TestLineMasksAssignments(t *testing.T) {
	in := `api_key = "sk-abcdefghijklmnopqrstuvwxyz"`
	out := Line(in)
	if strings.Contains(out, "sk-abc") {
		t.Fatalf("expected secret masked, got %q", out)
	}
	if !strings.Contains(out, mask) {
		t.Fatalf("expected mask in output, got %q", out)
	}
}

func TestSnippetTruncatesAndMasks(t *testing.T) {
	long := `password="` + strings.Repeat("x", 200) + `"`
	out := Snippet(long)
	if strings.Contains(out, strings.Repeat("x", 50)) {
		t.Fatalf("expected password value masked, got %q", out)
	}
	if !strings.Contains(out, mask) {
		t.Fatalf("expected mask, got %q", out)
	}
}

func TestSubstringMasksRange(t *testing.T) {
	in := "token=supersecrettokenvalue"
	out := Substring(in, 6, len(in))
	if strings.Contains(out, "supersecret") {
		t.Fatalf("expected substring masked, got %q", out)
	}
}
