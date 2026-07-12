// Package redact provides safe redaction for sensitive content in reports.
package redact

import (
	"regexp"
	"strings"
)

var (
	assignPattern = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|credential|auth)[\s]*[=:][\s]*["']?([^"'\s]{4,})["']?`)
	valuePattern  = regexp.MustCompile(`["']([A-Za-z0-9+/=_\-]{16,})["']`)
)

const mask = "***REDACTED***"

// Line masks likely secret values in a source line for safe display.
func Line(line string) string {
	if line == "" {
		return line
	}

	out := assignPattern.ReplaceAllStringFunc(line, func(match string) string {
		parts := assignPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return mask
		}
		return parts[1] + "=" + mask
	})

	return valuePattern.ReplaceAllString(out, `"`+mask+`"`)
}

// Substring masks a specific substring within a line.
func Substring(line string, start, end int) string {
	if start < 0 || end > len(line) || start >= end {
		return Line(line)
	}
	return line[:start] + mask + line[end:]
}

// Snippet returns a safely redacted snippet for reports.
func Snippet(snippet string) string {
	trimmed := strings.TrimSpace(snippet)
	if trimmed == "" {
		return snippet
	}
	if len(trimmed) > 120 {
		trimmed = trimmed[:120] + "..."
	}
	return Line(trimmed)
}
