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
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// TerraformScanner scans Terraform files for security issues
type TerraformScanner struct {
	config *config.Config
	rules  []*TerraformRule
}

// TerraformRule defines a Terraform security rule
type TerraformRule struct {
	ID          string
	Name        string
	Description string
	Severity    api.Severity
	Pattern     *regexp.Regexp
	Check       func(content string) bool
	Remediation string
}

// NewTerraformScanner creates a new Terraform scanner
func NewTerraformScanner(cfg *config.Config) *TerraformScanner {
	s := &TerraformScanner{
		config: cfg,
	}
	s.rules = s.loadRules()
	return s
}

// ScanFile scans a Terraform file
func (s *TerraformScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return []api.Finding{}
	}

	var findings []api.Finding
	fileContent := string(content)
	relPath, _ := filepath.Rel(basePath, filePath)

	// Scan line by line for pattern-based rules
	scanner := bufio.NewScanner(strings.NewReader(fileContent))
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		lineNum++
		line := scanner.Text()

		for _, rule := range s.rules {
			if rule.Pattern != nil && rule.Pattern.MatchString(line) {
				// Additional check if provided
				if rule.Check != nil && !rule.Check(fileContent) {
					continue
				}

				finding := api.Finding{
					ID:          fmt.Sprintf("IAC-TF-%s-%d", rule.ID, lineNum),
					Type:        api.FindingTypeMisconfiguration,
					Severity:    rule.Severity,
					Title:       rule.Name,
					Description: rule.Description,
					Location: api.Location{
						File:      relPath,
						StartLine: lineNum,
						EndLine:   lineNum,
						Snippet:   redact.Snippet(line),
					},
					Remediation: rule.Remediation,
					Scanner:     "iac",
					RuleID:      rule.ID,
					Confidence:  0.85,
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// loadRules loads Terraform security rules
func (s *TerraformScanner) loadRules() []*TerraformRule {
	return []*TerraformRule{
		// AWS S3 Public Access
		{
			ID:          "aws-s3-public-acl",
			Name:        "S3 Bucket with Public ACL",
			Description: "S3 bucket has public read or write ACL which exposes data",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`acl\s*=\s*"(public-read|public-read-write)"`),
			Remediation: "Set ACL to 'private' and use bucket policies for controlled access",
		},
		{
			ID:          "aws-s3-no-encryption",
			Name:        "S3 Bucket Without Encryption",
			Description: "S3 bucket does not have server-side encryption enabled",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`resource\s+"aws_s3_bucket"`),
			Check: func(content string) bool {
				// Check if encryption block is missing
				return !strings.Contains(content, "server_side_encryption_configuration")
			},
			Remediation: "Enable server-side encryption with KMS or AES256",
		},
		{
			ID:          "aws-s3-public-block-disabled",
			Name:        "S3 Public Access Block Disabled",
			Description: "S3 bucket public access block settings are not configured",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`resource\s+"aws_s3_bucket"`),
			Check: func(content string) bool {
				return !strings.Contains(content, "aws_s3_bucket_public_access_block")
			},
			Remediation: "Add aws_s3_bucket_public_access_block resource to prevent public access",
		},

		// AWS EC2 Security Groups
		{
			ID:          "aws-sg-open-to-world",
			Name:        "Security Group Open to Internet",
			Description: "Security group allows ingress from 0.0.0.0/0",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0".*\]`),
			Remediation: "Restrict ingress to specific IP ranges or security groups",
		},
		{
			ID:          "aws-sg-ssh-open",
			Name:        "SSH Port Open to Internet",
			Description: "Security group allows SSH (port 22) from 0.0.0.0/0",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`from_port\s*=\s*22.*cidr_blocks.*0\.0\.0\.0/0`),
			Remediation: "Restrict SSH access to specific IP addresses or use bastion hosts",
		},
		{
			ID:          "aws-sg-rdp-open",
			Name:        "RDP Port Open to Internet",
			Description: "Security group allows RDP (port 3389) from 0.0.0.0/0",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`from_port\s*=\s*3389.*cidr_blocks.*0\.0\.0\.0/0`),
			Remediation: "Restrict RDP access to specific IP addresses",
		},

		// AWS RDS
		{
			ID:          "aws-rds-public",
			Name:        "RDS Instance Publicly Accessible",
			Description: "RDS database instance is publicly accessible",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`publicly_accessible\s*=\s*true`),
			Remediation: "Set publicly_accessible to false",
		},
		{
			ID:          "aws-rds-no-encryption",
			Name:        "RDS Instance Without Encryption",
			Description: "RDS instance does not have encryption at rest enabled",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`storage_encrypted\s*=\s*false`),
			Remediation: "Enable storage_encrypted and specify kms_key_id",
		},

		// AWS IAM
		{
			ID:          "aws-iam-wildcard-resource",
			Name:        "IAM Policy with Wildcard Resource",
			Description: "IAM policy allows actions on all resources (*)",
			Severity:    api.SeverityMedium,
			Pattern:     regexp.MustCompile(`"Resource":\s*"\*"`),
			Remediation: "Specify exact resource ARNs instead of using wildcards",
		},

		// AWS EBS
		{
			ID:          "aws-ebs-no-encryption",
			Name:        "EBS Volume Without Encryption",
			Description: "EBS volume does not have encryption enabled",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`encrypted\s*=\s*false`),
			Remediation: "Enable encryption for EBS volumes",
		},

		// GCP
		{
			ID:          "gcp-storage-public",
			Name:        "GCP Storage Bucket Public Access",
			Description: "GCP storage bucket allows public access",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`member\s*=\s*"allUsers"`),
			Remediation: "Remove allUsers from IAM bindings",
		},

		// Azure
		{
			ID:          "azure-storage-public",
			Name:        "Azure Storage Account Public Access",
			Description: "Azure storage account allows public blob access",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`allow_blob_public_access\s*=\s*true`),
			Remediation: "Set allow_blob_public_access to false",
		},

		// General
		{
			ID:          "hardcoded-password",
			Name:        "Hardcoded Password in Terraform",
			Description: "Password appears to be hardcoded in configuration",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`(?i)password\s*=\s*"[^$\{]`),
			Remediation: "Use variables or secrets manager instead of hardcoding passwords",
		},
		{
			ID:          "http-endpoint",
			Name:        "HTTP Endpoint (Insecure)",
			Description: "HTTP endpoint detected, should use HTTPS",
			Severity:    api.SeverityMedium,
			Pattern:     regexp.MustCompile(`"http://`),
			Remediation: "Use HTTPS instead of HTTP for secure communication",
		},
	}
}
