// Package testutil provides shared helpers for SentinelFlow tests.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// RepoRoot returns the repository root (directory containing go.mod).
func RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

// FixturePath returns an absolute path under test/fixtures/.
func FixturePath(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join(RepoRoot(t), "test", "fixtures", filepath.FromSlash(rel))
}

// ReadFixture reads a file under test/fixtures/.
func ReadFixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(FixturePath(t, rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return data
}
