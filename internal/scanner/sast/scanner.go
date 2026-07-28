// Package sast provides static application security testing
package sast

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements SAST rule scanning
type Scanner struct {
	config *config.Config
	rules  []Rule
}

// Rule defines a SAST detection rule
type Rule struct {
	ID          string
	Name        string
	Category    string
	Pattern     *regexp.Regexp
	Severity    api.Severity
	Description string
	CWE         string
}

// ScannerResult contains scan results
type ScannerResult = types.ScannerResult

// NewScanner creates a new SAST scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		config: cfg,
		rules:  loadRules(),
	}
}

func (s *Scanner) Name() string { return "sast" }

func (s *Scanner) Supports(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	supported := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".py": true, ".java": true, ".php": true, ".rb": true, ".cs": true,
		".rs": true, ".kt": true, ".scala": true,
	}
	return supported[ext]
}

func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}

	files, err := types.ResolveFiles(path, opts, s.collectFiles)
	if err != nil {
		return nil, err
	}

	var scanFiles []string
	for _, file := range files {
		if !s.Supports(file) {
			continue
		}
		if info, err := os.Stat(file); err == nil && info.Size() > 1*1024*1024 {
			continue
		}
		scanFiles = append(scanFiles, file)
	}
	result.FilesCount = len(scanFiles)

	concurrency := types.EffectiveConcurrency(opts, s.config.Scanners.SAST.Concurrency, 8)
	var mu sync.Mutex
	var scanErrs []string
	types.RunWorkers(ctx, concurrency, scanFiles, func(fp string) {
		findings, err := s.scanFile(ctx, fp, path)
		if err != nil {
			mu.Lock()
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", fp, err))
			mu.Unlock()
			return
		}
		if len(findings) == 0 {
			return
		}
		mu.Lock()
		result.Findings = append(result.Findings, findings...)
		mu.Unlock()
	})

	if len(scanErrs) > 0 {
		return result, fmt.Errorf("sast scan errors (%d): %s", len(scanErrs), strings.Join(scanErrs, "; "))
	}
	return result, nil
}

func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) ([]api.Finding, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []api.Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		if s.isComment(line) {
			continue
		}

		for _, rule := range s.rules {
			if locs := rule.Pattern.FindAllStringIndex(line, -1); len(locs) > 0 {
				relPath := filePath
				if rel, err := filepath.Rel(basePath, filePath); err == nil {
					relPath = rel
				}

				for _, loc := range locs {
					findings = append(findings, api.Finding{
						ID:          fmt.Sprintf("SAST-%s-%d", rule.ID, lineNum),
						Type:        api.FindingTypeInsecureCode,
						Severity:    rule.Severity,
						Title:       rule.Name,
						Description: rule.Description,
						Location: api.Location{
							File:      relPath,
							StartLine: lineNum,
							EndLine:   lineNum,
							StartCol:  loc[0] + 1,
							EndCol:    loc[1] + 1,
							Snippet:   redact.Snippet(line),
						},
						Remediation: remediationFor(rule.Category),
						Scanner:     "sast",
						RuleID:      rule.ID,
						CWE:         []string{rule.CWE},
						Confidence:  0.8,
					})
				}
			}
		}
	}

	return findings, scanner.Err()
}

func (s *Scanner) collectFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 1024*1024 {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		if filter.ShouldSkip(rel, s.config.Scanners.Exclude) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func (s *Scanner) isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func remediationFor(category string) string {
	remediations := map[string]string{
		"sqli":       "Use parameterized queries or prepared statements instead of string concatenation.",
		"xss":        "Sanitize user input and use context-appropriate output encoding.",
		"path":       "Validate and canonicalize file paths; reject traversal sequences.",
		"ssrf":       "Validate URLs against an allowlist; block internal/private IP ranges.",
		"cmd-inject": "Avoid shell execution with user input; use safe APIs with argument lists.",
	}
	if r, ok := remediations[category]; ok {
		return r
	}
	return "Review and remediate this security issue."
}

func loadRules() []Rule {
	return []Rule{
		{
			ID: "sqli-concat", Name: "SQL Injection via String Concatenation", Category: "sqli",
			Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*.*(request|param|input|user|req\.|params\.|query)`),
			Severity: api.SeverityHigh, Description: "SQL query built with string concatenation from user input", CWE: "CWE-89",
		},
		{
			ID: "sqli-format", Name: "SQL Injection via Format String", Category: "sqli",
			Pattern: regexp.MustCompile(`(?i)(fmt\.Sprintf|sprintf|String\.format)\s*\(\s*["'].*(SELECT|INSERT|UPDATE|DELETE)`),
			Severity: api.SeverityHigh, Description: "SQL query constructed with format string", CWE: "CWE-89",
		},
		{
			ID: "xss-innerhtml", Name: "DOM-based XSS via innerHTML", Category: "xss",
			Pattern: regexp.MustCompile(`(?i)\.innerHTML\s*=\s*.*(request|param|input|user|location|document\.URL)`),
			Severity: api.SeverityHigh, Description: "User-controlled data assigned to innerHTML", CWE: "CWE-79",
		},
		{
			ID: "xss-eval", Name: "XSS via eval()", Category: "xss",
			Pattern: regexp.MustCompile(`(?i)\beval\s*\(`),
			Severity: api.SeverityHigh, Description: "Use of eval() can lead to code injection", CWE: "CWE-95",
		},
		{
			ID: "xss-dangerously", Name: "React dangerouslySetInnerHTML", Category: "xss",
			Pattern: regexp.MustCompile(`dangerouslySetInnerHTML`),
			Severity: api.SeverityMedium, Description: "dangerouslySetInnerHTML bypasses XSS protections", CWE: "CWE-79",
		},
		{
			ID: "path-traversal", Name: "Path Traversal", Category: "path",
			Pattern: regexp.MustCompile(`(?i)(\.\./|\.\.\\)`),
			Severity: api.SeverityHigh, Description: "Path traversal sequence detected", CWE: "CWE-22",
		},
		{
			ID: "path-join-user", Name: "Unsafe Path Join with User Input", Category: "path",
			Pattern: regexp.MustCompile(`(?i)(filepath\.Join|path\.join|os\.path\.join)\s*\([^)]*(request|param|input|user|req\.|params\.)`),
			Severity: api.SeverityMedium, Description: "File path constructed from user input without validation", CWE: "CWE-22",
		},
		{
			ID: "ssrf-http", Name: "Potential SSRF", Category: "ssrf",
			Pattern: regexp.MustCompile(`(?i)(http\.Get|http\.Post|fetch|urllib\.request|requests\.(get|post))\s*\([^)]*(request|param|input|user|req\.|params\.|query)`),
			Severity: api.SeverityHigh, Description: "HTTP request URL may be controlled by user input", CWE: "CWE-918",
		},
		{
			ID: "cmd-inject-exec", Name: "Command Injection via exec", Category: "cmd-inject",
			Pattern: regexp.MustCompile(`(?i)(exec\.Command|os\.system|subprocess\.(call|run|Popen)|Runtime\.getRuntime\(\)\.exec)\s*\([^)]*\+`),
			Severity: api.SeverityCritical, Description: "Shell command built with string concatenation", CWE: "CWE-78",
		},
		{
			ID: "cmd-inject-shell", Name: "Shell Command Execution", Category: "cmd-inject",
			Pattern: regexp.MustCompile(`(?i)(exec\.Command|subprocess)\s*\(\s*["']sh["']|["']bash["']|["']cmd["']`),
			Severity: api.SeverityHigh, Description: "Shell invocation detected; prefer direct execution", CWE: "CWE-78",
		},
	}
}
