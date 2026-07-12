// Package filter provides shared file skip logic for scanners.
package filter

import (
	"path/filepath"
	"strings"
)

// ShouldSkip returns true if a file should be excluded from scanning.
func ShouldSkip(path string, allowlist []string) bool {
	normalized := filepath.ToSlash(path)
	base := filepath.Base(normalized)

	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_bench_test.go") {
		return true
	}
	if strings.Contains(normalized, "/testdata/") {
		return true
	}

	for _, pattern := range allowlist {
		if matchPattern(normalized, base, filepath.ToSlash(pattern)) {
			return true
		}
	}
	return false
}

func matchPattern(path, base, pattern string) bool {
	if path == pattern {
		return true
	}
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	if strings.Contains(pattern, "**") {
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], "/")
			suffix := strings.TrimPrefix(parts[1], "/")

			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false
			}
			if suffix == "" {
				return true
			}
			if strings.HasSuffix(path, suffix) || strings.Contains(path, "/"+suffix) {
				return true
			}
		}
	}

	return false
}
