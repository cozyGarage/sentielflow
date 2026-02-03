package iac

import (
"bufio"
"context"
"fmt"
"os"
"path/filepath"
"regexp"
"strings"

"github.com/cozygarage/sentinelflow/internal/config"
"github.com/cozygarage/sentinelflow/pkg/api"
)

// DockerfileScanner scans Dockerfiles for security issues
type DockerfileScanner struct {
config *config.Config
rules  []*DockerfileRule
}

// DockerfileRule defines a Dockerfile security rule
type DockerfileRule struct {
ID          string
Name        string
Description string
Severity    api.Severity
Pattern     *regexp.Regexp
Check       func(lines []string, lineNum int, line string) bool
Remediation string
}

// NewDockerfileScanner creates a new Dockerfile scanner
func NewDockerfileScanner(cfg *config.Config) *DockerfileScanner {
s := &DockerfileScanner{
config: cfg,
}
s.rules = s.loadRules()
return s
}

// ScanFile scans a Dockerfile
func (s *DockerfileScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
file, err := os.Open(filePath)
if err != nil {
return []api.Finding{}
}
defer file.Close()

var findings []api.Finding
var lines []string
relPath, _ := filepath.Rel(basePath, filePath)

scanner := bufio.NewScanner(file)
lineNum := 0

// Read all lines first for multi-line checks
for scanner.Scan() {
lines = append(lines, scanner.Text())
}

// Scan each line
for i, line := range lines {
select {
case <-ctx.Done():
return findings
default:
}

lineNum = i + 1
trimmed := strings.TrimSpace(line)

// Skip comments and empty lines
if trimmed == "" || strings.HasPrefix(trimmed, "#") {
continue
}

// Check rules
for _, rule := range s.rules {
var matches bool
if rule.Pattern != nil {
matches = rule.Pattern.MatchString(line)
}
if rule.Check != nil {
matches = rule.Check(lines, lineNum, line)
}

if matches {
finding := api.Finding{
ID:          fmt.Sprintf("IAC-DOCKER-%s-%d", rule.ID, lineNum),
Type:        api.FindingTypeMisconfiguration,
Severity:    rule.Severity,
Title:       rule.Name,
Description: rule.Description,
Location: api.Location{
File:      relPath,
StartLine: lineNum,
EndLine:   lineNum,
Snippet:   line,
},
Remediation: rule.Remediation,
Scanner:     "iac",
RuleID:      rule.ID,
Confidence:  0.9,
}

findings = append(findings, finding)
}
}
}

return findings
}

// loadRules loads Dockerfile security rules
func (s *DockerfileScanner) loadRules() []*DockerfileRule {
return []*DockerfileRule{
// Base image issues
{
ID:          "latest-tag",
Name:        "Using 'latest' Tag",
Description: "Dockerfile uses 'latest' tag which can lead to unpredictable builds",
Severity:    api.SeverityMedium,
Pattern:     regexp.MustCompile(`^FROM\s+[^\s:]+:latest`),
Remediation: "Use specific version tags instead of 'latest'",
},
{
ID:          "no-tag",
Name:        "No Image Tag Specified",
Description: "Dockerfile base image has no tag (defaults to 'latest')",
Severity:    api.SeverityMedium,
Pattern:     regexp.MustCompile(`^FROM\s+[^\s:]+\s*$`),
Remediation: "Specify a version tag for the base image",
},

// User and permissions
{
ID:          "missing-user",
Name:        "Missing USER Instruction",
Description: "Dockerfile does not switch to non-root user",
Severity:    api.SeverityHigh,
Check: func(lines []string, lineNum int, line string) bool {
// Check if this is the last instruction and no USER was set
if lineNum == len(lines) {
hasUser := false
for _, l := range lines {
if strings.HasPrefix(strings.TrimSpace(l), "USER"+" ") {
hasUser = true
break
}
}
return !hasUser
}
return false
},
Remediation: "Add USER instruction to run container as non-root user",
},
{
ID:          "user-root",
Name:        "Explicit Root User",
Description: "Dockerfile explicitly sets USER to root",
Severity:    api.SeverityHigh,
Pattern:     regexp.MustCompile(`^USER\s+` + `(root|0)\s*$`),
Remediation: "Use a non-root user instead",
},

// Secrets and credentials
{
ID:          "hardcoded-secret",
Name:        "Hardcoded Secret in ENV",
Description: "Environment variable appears to contain hardcoded secret",
Severity:    api.SeverityCritical,
Pattern:     regexp.MustCompile(`^ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY)=["']?[^$\{]`),
Remediation: "Use build arguments or runtime secrets instead of hardcoding",
},
{
ID:          "exposed-port-22",
Name:        "SSH Port Exposed",
Description: "Dockerfile exposes SSH port 22",
Severity:    api.SeverityMedium,
Pattern:     regexp.MustCompile(`^EXPOSE\s+22\s*$`),
Remediation: "Avoid exposing SSH in containers, use exec instead",
},

// Package management
{
ID:          "apt-no-cleanup",
Name:        "APT Cache Not Cleaned",
Description: "apt-get install without cleanup increases image size",
Severity:    api.SeverityLow,
Check: func(lines []string, lineNum int, line string) bool {
if strings.Contains(line, "apt-get "+"install") || strings.Contains(line, "apt "+"install") {
// Check if there's a cleanup in the same RUN
return !strings.Contains(line, "rm -rf "+" /var/lib/apt/lists")
}
return false
},
Remediation: "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install",
},
{
ID:          "sudo-usage",
Name:        "Using sudo in Container",
Description: "Dockerfile uses sudo which is unnecessary in containers",
Severity:    api.SeverityLow,
Pattern:     regexp.MustCompile(`\bsudo\b`),
Remediation: "Remove sudo usage; run commands directly or use USER",
},

// Build practices
{
ID:          "curl-to-bash",
Name:        "Piping curl to bash",
Description: "Downloading and executing scripts directly is dangerous",
Severity:    api.SeverityHigh,
Pattern:     regexp.MustCompile(`curl.*\|\s*(ba)?sh`),
Remediation: "Download scripts, verify them, then execute",
},
{
ID:          "wget-to-bash",
Name:        "Piping wget to bash",
Description: "Downloading and executing scripts directly is dangerous",
Severity:    api.SeverityHigh,
Pattern:     regexp.MustCompile(`wget.*\|\s*(ba)?sh`),
Remediation: "Download scripts, verify them, then execute",
},

// COPY/ADD security
{
ID:          "add-archive-extraction",
Name:        "Using ADD for Remote Files",
Description: "ADD automatically extracts archives which can be dangerous",
Severity:    api.SeverityMedium,
Pattern:     regexp.MustCompile(`^ADD\s+https?://`),
Remediation: "Use COPY instead of ADD, or RUN curl/wget for remote files",
},

// Health and monitoring
{
ID:          "no-healthcheck",
Name:        "Missing HEALTHCHECK",
Description: "Dockerfile does not define a HEALTHCHECK",
Severity:    api.SeverityLow,
Check: func(lines []string, lineNum int, line string) bool {
// Check at the end if no HEALTHCHECK was defined
if lineNum == len(lines) {
for _, l := range lines {
if strings.HasPrefix(strings.TrimSpace(l), "HEALTH"+"CHECK ") {
return false
}
}
return true
}
return false
},
Remediation: "Add HEALTHCHECK instruction for container health monitoring",
},

// Privileged operations
{
ID:          "update-alone",
Name:        "apt-get update Alone",
Description: "apt-get update should be combined with install to avoid cache issues",
Severity:    api.SeverityLow,
Check: func(lines []string, lineNum int, line string) bool {
if strings.Contains(line, "apt-get "+"update") || strings.Contains(line, "apt "+"update") {
// Check if install is in the same RUN command
return !strings.Contains(line, "install")
}
return false
},
Remediation: "Combine apt-get update && apt-get install in single RUN",
},
}
}
