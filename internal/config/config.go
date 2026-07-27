// Package config handles SentinelFlow configuration management
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the SentinelFlow configuration
type Config struct {
	Version   string         `yaml:"version" mapstructure:"version"`
	Scanners  ScannersConfig `yaml:"scanners" mapstructure:"scanners"`
	Policies  PoliciesConfig `yaml:"policies" mapstructure:"policies"`
	Reporting ReportConfig   `yaml:"reporting" mapstructure:"reporting"`
	FailOn    FailOnConfig   `yaml:"fail_on" mapstructure:"fail_on"`
	Git       GitConfig      `yaml:"git" mapstructure:"git"`
	Baseline  BaselineConfig `yaml:"baseline" mapstructure:"baseline"`
}

// ScannersConfig contains settings for all scanners
type ScannersConfig struct {
	Secrets      SecretsConfig      `yaml:"secrets" mapstructure:"secrets"`
	IaC          IaCConfig          `yaml:"iac" mapstructure:"iac"`
	Dependencies DependenciesConfig `yaml:"dependencies" mapstructure:"dependencies"`
	SAST         SASTConfig         `yaml:"sast" mapstructure:"sast"`
	Container    ContainerConfig    `yaml:"container" mapstructure:"container"`
	License      LicenseConfig      `yaml:"license" mapstructure:"license"`
	AI           AIConfig           `yaml:"ai" mapstructure:"ai"`
}

// SecretsConfig configures the secret scanner
type SecretsConfig struct {
	Enabled          bool     `yaml:"enabled" mapstructure:"enabled"`
	Allowlist        []string `yaml:"allowlist" mapstructure:"allowlist"`
	Patterns         []string `yaml:"patterns" mapstructure:"patterns"`
	EntropyThreshold float64  `yaml:"entropy_threshold" mapstructure:"entropy_threshold"`
	ScanGitHistory   bool     `yaml:"scan_git_history" mapstructure:"scan_git_history"`
	MaxHistoryDepth  int      `yaml:"max_history_depth" mapstructure:"max_history_depth"`
}

// IaCConfig configures the Infrastructure-as-Code scanner
type IaCConfig struct {
	Enabled    bool     `yaml:"enabled" mapstructure:"enabled"`
	Frameworks []string `yaml:"frameworks" mapstructure:"frameworks"`
	Severity   string   `yaml:"severity" mapstructure:"severity"`
	SkipRules  []string `yaml:"skip_rules" mapstructure:"skip_rules"`
}

// DependenciesConfig configures the dependency vulnerability scanner
type DependenciesConfig struct {
	Enabled    bool     `yaml:"enabled" mapstructure:"enabled"`
	Ecosystems []string `yaml:"ecosystems" mapstructure:"ecosystems"`
	Severity   string   `yaml:"severity" mapstructure:"severity"`
	IgnoreDev  bool     `yaml:"ignore_dev" mapstructure:"ignore_dev"`
	IgnoreCVEs []string `yaml:"ignore_cves" mapstructure:"ignore_cves"`
}

// SASTConfig configures static application security testing
type SASTConfig struct {
	Enabled   bool     `yaml:"enabled" mapstructure:"enabled"`
	Severity  string   `yaml:"severity" mapstructure:"severity"`
	SkipRules []string `yaml:"skip_rules" mapstructure:"skip_rules"`
}

// ContainerConfig configures container image scanning
type ContainerConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	Image    string `yaml:"image" mapstructure:"image"`
	Severity string `yaml:"severity" mapstructure:"severity"`
}

// LicenseConfig configures license policy scanning
type LicenseConfig struct {
	Enabled bool     `yaml:"enabled" mapstructure:"enabled"`
	Denied  []string `yaml:"denied" mapstructure:"denied"`
	Allowed []string `yaml:"allowed" mapstructure:"allowed"`
}

// BaselineConfig configures finding baselines
type BaselineConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	File    string `yaml:"file" mapstructure:"file"`
}

// AIConfig configures the AI-powered code review
type AIConfig struct {
	Enabled     bool     `yaml:"enabled" mapstructure:"enabled"`
	Provider    string   `yaml:"provider" mapstructure:"provider"`
	Model       string   `yaml:"model" mapstructure:"model"`
	APIKey      string   `yaml:"api_key" mapstructure:"api_key"`
	BaseURL     string   `yaml:"base_url" mapstructure:"base_url"`
	Focus       []string `yaml:"focus" mapstructure:"focus"`
	MaxFileSize int      `yaml:"max_file_size" mapstructure:"max_file_size"`
	Concurrency int      `yaml:"concurrency" mapstructure:"concurrency"`
}

// PoliciesConfig configures policy-as-code
type PoliciesConfig struct {
	Enabled bool     `yaml:"enabled" mapstructure:"enabled"`
	Files   []string `yaml:"files" mapstructure:"files"`
	Builtin []string `yaml:"builtin" mapstructure:"builtin"`
}

// ReportConfig configures report generation
type ReportConfig struct {
	Format             string `yaml:"format" mapstructure:"format"`
	IncludeRemediation bool   `yaml:"include_remediation" mapstructure:"include_remediation"`
	GitHubAnnotations  bool   `yaml:"github_annotations" mapstructure:"github_annotations"`
	SARIFUpload        bool   `yaml:"sarif_upload" mapstructure:"sarif_upload"`
	OutputDir          string `yaml:"output_dir" mapstructure:"output_dir"`
}

// FailOnConfig configures when the scan should fail
type FailOnConfig struct {
	Severity         string `yaml:"severity" mapstructure:"severity"`
	Secrets          bool   `yaml:"secrets" mapstructure:"secrets"`
	PolicyViolations bool   `yaml:"policy_violations" mapstructure:"policy_violations"`
}

// GitConfig configures git-related settings
type GitConfig struct {
	ScanHistory    bool `yaml:"scan_history" mapstructure:"scan_history"`
	HistoryDepth   int  `yaml:"history_depth" mapstructure:"history_depth"`
	ScanStagedOnly bool `yaml:"scan_staged_only" mapstructure:"scan_staged_only"`
}

// Load reads configuration from file and environment
func Load() (*Config, error) {
	cfg := Default()

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Load AI API key from environment if not set
	if cfg.Scanners.AI.APIKey == "" {
		cfg.Scanners.AI.APIKey = os.Getenv("SENTINELFLOW_AI_API_KEY")
		if cfg.Scanners.AI.APIKey == "" {
			cfg.Scanners.AI.APIKey = os.Getenv("OPENAI_API_KEY")
		}
	}

	return cfg, nil
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Version: "1.0",
		Scanners: ScannersConfig{
			Secrets: SecretsConfig{
				Enabled:          true,
				EntropyThreshold: 4.5,
				MaxHistoryDepth:  50,
				Allowlist: []string{
					"test/**",
					"**/*_test.go",
					"**/testdata/**",
					"**/*.test.js",
					"**/*.spec.ts",
				},
			},
			IaC: IaCConfig{
				Enabled:    true,
				Severity:   "medium",
				Frameworks: []string{"terraform", "kubernetes", "dockerfile", "cloudformation"},
			},
			Dependencies: DependenciesConfig{
				Enabled:    true,
				Ecosystems: []string{"auto"},
				Severity:   "medium",
				IgnoreDev:  false,
			},
			SAST: SASTConfig{
				Enabled:  false,
				Severity: "medium",
			},
			Container: ContainerConfig{
				Enabled:  false,
				Severity: "high",
			},
			License: LicenseConfig{
				Enabled: false,
				Denied:  []string{"GPL-3.0", "AGPL-3.0", "SSPL-1.0"},
			},
			AI: AIConfig{
				Enabled:     false,
				Provider:    "openai",
				Model:       "gpt-4",
				MaxFileSize: 100000,
				Concurrency: 3,
				Focus:       []string{"injection", "authentication", "authorization", "cryptography"},
			},
		},
		Policies: PoliciesConfig{
			Enabled: true,
			Files:   []string{"policies/*.rego", ".sentinelflow/policies/*.rego"},
			Builtin: []string{
				"no-public-s3-buckets",
				"no-privileged-containers",
				"require-https",
				"enforce-encryption",
			},
		},
		Reporting: ReportConfig{
			Format:             "text",
			IncludeRemediation: true,
			GitHubAnnotations:  true,
			SARIFUpload:        false,
		},
		FailOn: FailOnConfig{
			Severity:         "high",
			Secrets:          true,
			PolicyViolations: true,
		},
		Git: GitConfig{
			ScanHistory:    false,
			HistoryDepth:   50,
			ScanStagedOnly: false,
		},
		Baseline: BaselineConfig{
			Enabled: false,
			File:    ".sentinelflow/baseline.yaml",
		},
	}
}

// Save writes configuration to a file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	validSeverities := map[string]bool{
		"": true, "critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	validFormats := map[string]bool{
		"": true, "text": true, "json": true, "sarif": true, "markdown": true, "html": true,
	}

	if !validSeverities[strings.ToLower(c.FailOn.Severity)] {
		return fmt.Errorf("invalid fail_on.severity %q (expected critical, high, medium, low, or info)", c.FailOn.Severity)
	}
	if !validSeverities[strings.ToLower(c.Scanners.IaC.Severity)] {
		return fmt.Errorf("invalid scanners.iac.severity %q", c.Scanners.IaC.Severity)
	}
	if !validSeverities[strings.ToLower(c.Scanners.Dependencies.Severity)] {
		return fmt.Errorf("invalid scanners.dependencies.severity %q", c.Scanners.Dependencies.Severity)
	}
	if !validSeverities[strings.ToLower(c.Scanners.SAST.Severity)] {
		return fmt.Errorf("invalid scanners.sast.severity %q", c.Scanners.SAST.Severity)
	}
	if !validSeverities[strings.ToLower(c.Scanners.Container.Severity)] {
		return fmt.Errorf("invalid scanners.container.severity %q", c.Scanners.Container.Severity)
	}
	if !validFormats[strings.ToLower(c.Reporting.Format)] {
		return fmt.Errorf("invalid reporting.format %q (expected text, json, sarif, markdown, or html)", c.Reporting.Format)
	}
	if c.Scanners.Secrets.EntropyThreshold < 0 {
		return fmt.Errorf("scanners.secrets.entropy_threshold must be >= 0")
	}
	if c.Scanners.Secrets.MaxHistoryDepth < 0 {
		return fmt.Errorf("scanners.secrets.max_history_depth must be >= 0")
	}
	if c.Git.HistoryDepth < 0 {
		return fmt.Errorf("git.history_depth must be >= 0")
	}
	if c.Scanners.AI.Enabled {
		return fmt.Errorf("scanners.ai.enabled is not supported in v1.0")
	}

	return nil
}
