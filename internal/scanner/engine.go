// Package scanner provides the scanning engine and scanner implementations
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cozygarage/sentinelflow/internal/adapter"
	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner defines the interface for all security scanners
// Note: This is an alias to the adapter.Scanner interface
type Scanner = adapter.Scanner

// ScanOptions contains options for a scan operation
type ScanOptions struct {
	Config      *config.Config
	Files       []string
	Concurrency int
	Verbose     bool
}

// ScannerResult contains results from a single scanner
// Note: This is an alias to the adapter.ScannerResult type
type ScannerResult = adapter.ScannerResult

// Engine orchestrates all security scanners
type Engine struct {
	config   *config.Config
	scanners []Scanner
}

// NewEngine creates a new scanning engine with configured scanners
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		config:   cfg,
		scanners: []Scanner{},
	}

	// Add enabled scanners using adapters
	if cfg.Scanners.Secrets.Enabled {
		e.scanners = append(e.scanners, adapter.NewSecretsAdapter(cfg))
	}
	if cfg.Scanners.IaC.Enabled {
		e.scanners = append(e.scanners, adapter.NewIaCAdapter(cfg))
	}
	if cfg.Scanners.Dependencies.Enabled {
		e.scanners = append(e.scanners, adapter.NewDependenciesAdapter(cfg))
	}
	if cfg.Policies.Enabled {
		e.scanners = append(e.scanners, adapter.NewPolicyAdapter(cfg))
	}
	if cfg.Scanners.SAST.Enabled {
		e.scanners = append(e.scanners, adapter.NewSASTAdapter(cfg))
	}
	if cfg.Scanners.Container.Enabled {
		e.scanners = append(e.scanners, adapter.NewContainerAdapter(cfg))
	}
	if cfg.Scanners.License.Enabled {
		e.scanners = append(e.scanners, adapter.NewLicenseAdapter(cfg))
	}

	return e
}

// Scan runs all enabled scanners on the target path
func (e *Engine) Scan(ctx context.Context, targetPath string) (*api.ScanResult, error) {
	startTime := time.Now()

	// Verify path exists
	if _, err := os.Stat(targetPath); err != nil {
		return nil, fmt.Errorf("target path does not exist: %s", targetPath)
	}

	// Collect files to scan
	files, err := e.collectFiles(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	result := &api.ScanResult{
		Findings:    []api.Finding{},
		ScannerRuns: []api.ScannerRun{},
		Metadata: api.ScanMetadata{
			TargetPath:          targetPath,
			StartTime:           startTime,
			SentinelFlowVersion: "1.0.0",
		},
	}

	// Collect git metadata if available
	e.collectGitMetadata(targetPath, &result.Metadata)

	// Run scanners concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	opts := ScanOptions{
		Config:      e.config,
		Files:       files,
		Concurrency: 4,
	}

	for _, scanner := range e.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			scanStart := time.Now()
			scanResult, err := s.Scan(ctx, targetPath, opts)
			scanDuration := time.Since(scanStart)

			run := api.ScannerRun{
				Scanner:   s.Name(),
				StartTime: scanStart,
				EndTime:   time.Now(),
				Duration:  api.DurationMS(scanDuration),
			}

			if err != nil {
				run.Error = err.Error()
			} else if scanResult != nil {
				run.FilesCount = scanResult.FilesCount
				run.FindingsCount = len(scanResult.Findings)

				mu.Lock()
				result.Findings = append(result.Findings, scanResult.Findings...)
				mu.Unlock()
			}

			mu.Lock()
			result.ScannerRuns = append(result.ScannerRuns, run)
			mu.Unlock()
		}(scanner)
	}

	wg.Wait()

	// Apply baseline filtering if enabled
	if e.config.Baseline.Enabled {
		blPath := e.config.Baseline.File
		if blPath == "" {
			blPath = baseline.DefaultPath
		}
		bl, err := baseline.Load(blPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load baseline %s: %w", blPath, err)
		}
		result.Findings = baseline.Filter(result.Findings, bl)
	}

	result.Metadata.EndTime = time.Now()
	result.Duration = api.DurationMS(time.Since(startTime))

	return result, nil
}

// collectFiles recursively collects files from the target path
func (e *Engine) collectFiles(targetPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories and common non-code directories
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" ||
				name == "dist" || name == "build" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip binary and large files
		if info.Size() > 5*1024*1024 { // 5MB limit
			return nil
		}

		// Get relative path for filtering
		relPath, _ := filepath.Rel(targetPath, path)

		// Check allowlist patterns
		if e.shouldSkip(relPath) {
			return nil
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// shouldSkip checks if a file should be skipped based on allowlist patterns
func (e *Engine) shouldSkip(path string) bool {
	return filter.ShouldSkip(path, e.config.Scanners.Secrets.Allowlist)
}

// collectGitMetadata extracts git information if available
func (e *Engine) collectGitMetadata(path string, meta *api.ScanMetadata) {
	// Check for .git directory
	gitDir := filepath.Join(path, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return
	}

	// Try to read HEAD for branch
	headFile := filepath.Join(gitDir, "HEAD")
	if data, err := os.ReadFile(headFile); err == nil {
		content := string(data)
		if len(content) > 16 && content[:16] == "ref: refs/heads/" {
			meta.GitBranch = content[16 : len(content)-1]
		}
	}

	// Try to read commit
	if meta.GitBranch != "" {
		refFile := filepath.Join(gitDir, "refs", "heads", meta.GitBranch)
		if data, err := os.ReadFile(refFile); err == nil {
			commit := strings.TrimSpace(string(data))
			if len(commit) >= 40 {
				meta.GitCommit = commit[:40]
			} else if commit != "" {
				meta.GitCommit = commit
			}
		}
	}
}

// AddScanner adds a custom scanner to the engine
func (e *Engine) AddScanner(s Scanner) {
	e.scanners = append(e.scanners, s)
}

// GetScanners returns the list of enabled scanners
func (e *Engine) GetScanners() []Scanner {
	return e.scanners
}
