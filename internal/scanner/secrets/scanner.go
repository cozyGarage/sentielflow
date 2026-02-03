// Package secrets provides secret detection scanning
package secrets

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner implements secret detection
type Scanner struct {
	config   *config.Config
	patterns []*SecretPattern
}

// SecretPattern defines a secret detection pattern
type SecretPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    api.Severity
	Description string
	Keywords    []string
}

// NewScanner creates a new secret scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config: cfg,
	}
	s.patterns = s.loadPatterns()
	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "secrets"
}

// Supports returns true for files that should be scanned for secrets
func (s *Scanner) Supports(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	// Skip binary and image files
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".svg": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".pdf": true, ".zip": true,
		".tar": true, ".gz": true, ".rar": true, ".7z": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	}
	return !binaryExts[ext]
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// Scan performs secret detection on the target path
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	var files []string

	// Check if path is a file or directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		files, err = s.collectFiles(path)
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}

	result.FilesCount = len(files)

	// Scan files concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 10) // Limit concurrency

	for _, file := range files {
		if !s.Supports(file) {
			continue
		}

		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			findings, err := s.scanFile(ctx, filePath, path)
			if err != nil {
				return // Skip files that can't be read
			}

			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	return result, nil
}

// scanFile scans a single file for secrets
func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) ([]api.Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return s.scanReader(ctx, file, filePath, basePath)
}

// scanReader scans content from a reader for secrets
func (s *Scanner) scanReader(ctx context.Context, r io.Reader, filePath, basePath string) ([]api.Finding, error) {
	var findings []api.Finding
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		// Check each pattern
		for _, pattern := range s.patterns {
			matches := pattern.Pattern.FindAllStringIndex(line, -1)
			for _, match := range matches {
				secret := line[match[0]:match[1]]

				// Skip if it looks like a placeholder
				if s.isPlaceholder(secret) {
					continue
				}

				// Additional entropy check for generic patterns
				if pattern.ID == "generic-secret" && s.calculateEntropy(secret) < s.config.Scanners.Secrets.EntropyThreshold {
					continue
				}

				relPath := filePath
				if basePath != "" {
					rel, err := filepath.Rel(basePath, filePath)
					if err == nil {
						relPath = rel
					}
				}

				finding := api.Finding{
					ID:          fmt.Sprintf("SEC-%s-%d", pattern.ID, lineNum),
					Type:        api.FindingTypeSecret,
					Severity:    pattern.Severity,
					Title:       fmt.Sprintf("Potential %s detected", pattern.Name),
					Description: pattern.Description,
					Location: api.Location{
						File:      relPath,
						StartLine: lineNum,
						EndLine:   lineNum,
						StartCol:  match[0] + 1,
						EndCol:    match[1] + 1,
						Snippet:   s.maskSecret(line, match[0], match[1]),
					},
					Remediation: s.getRemediation(pattern),
					Scanner:     "secrets",
					RuleID:      pattern.ID,
					Confidence:  0.9,
				}

				findings = append(findings, finding)
			}
		}

		// Check for high-entropy strings
		if entropyFindings := s.checkHighEntropy(line, lineNum, filePath, basePath); len(entropyFindings) > 0 {
			findings = append(findings, entropyFindings...)
		}
	}

	return findings, scanner.Err()
}

// loadPatterns loads all secret detection patterns
func (s *Scanner) loadPatterns() []*SecretPattern {
	return []*SecretPattern{
		// AWS
		{
			ID:          "aws-access-key",
			Name:        "AWS Access Key ID",
			Pattern:     regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
			Severity:    api.SeverityCritical,
			Description: "AWS Access Key ID found in code",
			Keywords:    []string{"aws", "access", "key"},
		},
		{
			ID:          "aws-secret-key",
			Name:        "AWS Secret Access Key",
			Pattern:     regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]["']?([A-Za-z0-9/+=]{40})["']?`),
			Severity:    api.SeverityCritical,
			Description: "AWS Secret Access Key found in code",
			Keywords:    []string{"aws", "secret"},
		},
		// GCP
		{
			ID:          "gcp-api-key",
			Name:        "Google Cloud API Key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity:    api.SeverityCritical,
			Description: "Google Cloud API Key found in code",
			Keywords:    []string{"google", "gcp", "api"},
		},
		{
			ID:          "gcp-service-account",
			Name:        "GCP Service Account",
			Pattern:     regexp.MustCompile(`"type"\s*:\s*"service_account"`),
			Severity:    api.SeverityHigh,
			Description: "GCP Service Account credentials file detected",
			Keywords:    []string{"google", "service_account"},
		},
		// Azure
		{
			ID:          "azure-storage-key",
			Name:        "Azure Storage Account Key",
			Pattern:     regexp.MustCompile(`(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{88})`),
			Severity:    api.SeverityCritical,
			Description: "Azure Storage Account Key found in code",
			Keywords:    []string{"azure", "storage", "account"},
		},
		// GitHub
		{
			ID:          "github-token",
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`),
			Severity:    api.SeverityCritical,
			Description: "GitHub personal access token or OAuth token found",
			Keywords:    []string{"github", "token"},
		},
		{
			ID:          "github-app-token",
			Name:        "GitHub App Token",
			Pattern:     regexp.MustCompile(`(ghu|ghs)_[A-Za-z0-9_]{36}`),
			Severity:    api.SeverityHigh,
			Description: "GitHub App token found in code",
			Keywords:    []string{"github", "app"},
		},
		// GitLab
		{
			ID:          "gitlab-token",
			Name:        "GitLab Token",
			Pattern:     regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`),
			Severity:    api.SeverityCritical,
			Description: "GitLab personal access token found",
			Keywords:    []string{"gitlab", "token"},
		},
		// Slack
		{
			ID:          "slack-token",
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			Severity:    api.SeverityHigh,
			Description: "Slack API token found in code",
			Keywords:    []string{"slack", "token"},
		},
		{
			ID:          "slack-webhook",
			Name:        "Slack Webhook URL",
			Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
			Severity:    api.SeverityMedium,
			Description: "Slack webhook URL found in code",
			Keywords:    []string{"slack", "webhook"},
		},
		// Stripe
		{
			ID:          "stripe-secret-key",
			Name:        "Stripe Secret Key",
			Pattern:     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			Severity:    api.SeverityCritical,
			Description: "Stripe live secret key found in code",
			Keywords:    []string{"stripe", "key"},
		},
		{
			ID:          "stripe-publishable-key",
			Name:        "Stripe Publishable Key",
			Pattern:     regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
			Severity:    api.SeverityMedium,
			Description: "Stripe live publishable key found in code",
			Keywords:    []string{"stripe", "key"},
		},
		// Twilio
		{
			ID:          "twilio-api-key",
			Name:        "Twilio API Key",
			Pattern:     regexp.MustCompile(`SK[a-fA-F0-9]{32}`),
			Severity:    api.SeverityHigh,
			Description: "Twilio API Key found in code",
			Keywords:    []string{"twilio"},
		},
		// SendGrid
		{
			ID:          "sendgrid-api-key",
			Name:        "SendGrid API Key",
			Pattern:     regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
			Severity:    api.SeverityHigh,
			Description: "SendGrid API Key found in code",
			Keywords:    []string{"sendgrid"},
		},
		// Private Keys
		{
			ID:          "private-key",
			Name:        "Private Key",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`),
			Severity:    api.SeverityCritical,
			Description: "Private key file content detected",
			Keywords:    []string{"private", "key", "rsa", "ssh"},
		},
		// JWT
		{
			ID:          "jwt-token",
			Name:        "JWT Token",
			Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`),
			Severity:    api.SeverityMedium,
			Description: "JWT token found in code (may contain sensitive claims)",
			Keywords:    []string{"jwt", "token", "bearer"},
		},
		// Generic
		{
			ID:          "generic-api-key",
			Name:        "Generic API Key",
			Pattern:     regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api_secret)[\s]*[=:][\s]*["']?([A-Za-z0-9_\-]{20,})["']?`),
			Severity:    api.SeverityHigh,
			Description: "Generic API key pattern detected",
			Keywords:    []string{"api", "key"},
		},
		{
			ID:          "generic-secret",
			Name:        "Generic Secret",
			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|auth)[\s]*[=:][\s]*["']([^"']{8,})["']`),
			Severity:    api.SeverityHigh,
			Description: "Hardcoded secret detected",
			Keywords:    []string{"password", "secret", "token"},
		},
		// Database connection strings
		{
			ID:          "database-url",
			Name:        "Database Connection String",
			Pattern:     regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|mongodb\+srv):\/\/[^:]+:[^@]+@[^\/]+`),
			Severity:    api.SeverityHigh,
			Description: "Database connection string with credentials found",
			Keywords:    []string{"database", "connection", "url"},
		},
		// Heroku
		{
			ID:          "heroku-api-key",
			Name:        "Heroku API Key",
			Pattern:     regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key[\s]*[=:][\s]*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`),
			Severity:    api.SeverityHigh,
			Description: "Heroku API Key found in code",
			Keywords:    []string{"heroku"},
		},
		// npm
		{
			ID:          "npm-token",
			Name:        "NPM Token",
			Pattern:     regexp.MustCompile(`(?i)//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]+)`),
			Severity:    api.SeverityHigh,
			Description: "NPM authentication token found",
			Keywords:    []string{"npm", "token"},
		},
		// Discord
		{
			ID:          "discord-token",
			Name:        "Discord Bot Token",
			Pattern:     regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`),
			Severity:    api.SeverityHigh,
			Description: "Discord bot token found in code",
			Keywords:    []string{"discord", "bot"},
		},
		// Telegram
		{
			ID:          "telegram-bot-token",
			Name:        "Telegram Bot Token",
			Pattern:     regexp.MustCompile(`[0-9]+:AA[A-Za-z0-9_-]{33}`),
			Severity:    api.SeverityHigh,
			Description: "Telegram bot token found in code",
			Keywords:    []string{"telegram", "bot"},
		},
	}
}

// collectFiles recursively collects files from a directory
func (s *Scanner) collectFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories we shouldn't scan
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip large files
		if info.Size() > 1024*1024 { // 1MB
			return nil
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// isPlaceholder checks if a secret looks like a placeholder value
func (s *Scanner) isPlaceholder(secret string) bool {
	placeholders := []string{
		"xxx", "XXX", "your-", "YOUR_", "<your", "REPLACE",
		"example", "EXAMPLE", "dummy", "DUMMY", "test", "TEST",
		"changeme", "CHANGEME", "placeholder", "PLACEHOLDER",
		"insert", "INSERT", "todo", "TODO", "fixme", "FIXME",
		"secret", "SECRET", "password", "PASSWORD", "token", "TOKEN",
	}

	lower := strings.ToLower(secret)
	for _, p := range placeholders {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}

	// Check for repetitive characters (e.g., "aaaaaaa", "1234567")
	if len(secret) >= 8 && s.calculateEntropy(secret) < 2.0 {
		return true
	}

	return false
}

// calculateEntropy calculates the Shannon entropy of a string
func (s *Scanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, c := range str {
		charCount[c]++
	}

	entropy := 0.0
	strLen := float64(len(str))

	for _, count := range charCount {
		freq := float64(count) / strLen
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// checkHighEntropy looks for high-entropy strings that might be secrets
func (s *Scanner) checkHighEntropy(line string, lineNum int, filePath, basePath string) []api.Finding {
	var findings []api.Finding

	// Look for potential base64 or hex encoded secrets
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`[=:]["']([A-Za-z0-9+/]{40,}={0,2})["']`), // Base64
		regexp.MustCompile(`[=:]["']([a-fA-F0-9]{32,})["']`),         // Hex
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				secret := match[1]
				entropy := s.calculateEntropy(secret)

				if entropy >= s.config.Scanners.Secrets.EntropyThreshold && !s.isPlaceholder(secret) {
					relPath, _ := filepath.Rel(basePath, filePath)

					finding := api.Finding{
						ID:          fmt.Sprintf("SEC-entropy-%d", lineNum),
						Type:        api.FindingTypeSecret,
						Severity:    api.SeverityMedium,
						Title:       "High-entropy string detected",
						Description: fmt.Sprintf("High-entropy string (%.2f bits) may be a secret", entropy),
						Location: api.Location{
							File:      relPath,
							StartLine: lineNum,
							EndLine:   lineNum,
							Snippet:   s.maskSecret(line, 0, len(line)),
						},
						Remediation: "Review this string and move to environment variables if it's a secret",
						Scanner:     "secrets",
						RuleID:      "high-entropy",
						Confidence:  0.7,
						Metadata: map[string]any{
							"entropy": entropy,
						},
					}

					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// maskSecret masks the secret in the line for safe display
func (s *Scanner) maskSecret(line string, start, end int) string {
	if start < 0 || end > len(line) || start >= end {
		return line
	}

	secretLen := end - start
	maskedLen := secretLen
	if maskedLen > 8 {
		maskedLen = 8
	}

	masked := line[:start] + strings.Repeat("*", maskedLen) + line[end:]
	return masked
}

// getRemediation returns remediation advice for a secret type
func (s *Scanner) getRemediation(pattern *SecretPattern) string {
	remediations := map[string]string{
		"aws-access-key": "Remove the AWS access key from code. Use IAM roles or environment variables instead. Rotate the exposed key immediately.",
		"aws-secret-key": "Remove the AWS secret key from code. Use IAM roles, AWS Secrets Manager, or environment variables. Rotate the key immediately.",
		"gcp-api-key":    "Remove the GCP API key from code. Use service accounts or restrict the API key. Rotate if exposed.",
		"github-token":   "Remove the GitHub token from code. Use GitHub Actions secrets or environment variables. Revoke and regenerate the token.",
		"private-key":    "Never commit private keys to source control. Use secret management solutions or environment variables.",
		"generic-secret": "Move hardcoded secrets to environment variables or a secret management solution like HashiCorp Vault.",
		"database-url":   "Use environment variables for database connection strings. Never commit credentials to source control.",
	}

	if remediation, ok := remediations[pattern.ID]; ok {
		return remediation
	}

	return "Remove hardcoded secrets from code. Use environment variables or a secret management solution."
}
