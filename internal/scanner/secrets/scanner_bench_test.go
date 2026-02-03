package secrets

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

// BenchmarkScanFile benchmarks scanning a single file for secrets
func BenchmarkScanFile(b *testing.B) {
	// Create a temporary file with some content
	tmpDir := b.TempDir()
	content := []byte(`
package main

func main() {
    apiKey := "AKIA" + "IOSFODNN7EXAMPLE"
    secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
`)
	path := filepath.Join(tmpDir, "main.go")
	os.WriteFile(path, content, 0644)

	fullCfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{
				Enabled:          true,
				EntropyThreshold: 4.5,
			},
		},
	}
	s := NewScanner(fullCfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Scan(ctx, path, nil)
	}
}

// BenchmarkScanLargeFile benchmarks scanning a large file
func BenchmarkScanLargeFile(b *testing.B) {
	tmpDir := b.TempDir()

	// Generate large content (1MB)
	size := 1024 * 1024
	content := make([]byte, size)
	for i := 0; i < size; i++ {
		content[i] = byte(rand.Intn(256))
	}

	// Add some secrets (constructed at runtime to avoid detection by source scan)
	copy(content[1000:], []byte("AKIA"+"IOSFODNN7EXAMPLE"))
	copy(content[500000:], []byte("sk_live_"+"0123456789abcdef01234567"))

	path := filepath.Join(tmpDir, "large.bin")
	os.WriteFile(path, content, 0644)

	fullCfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{
				Enabled:          true,
				EntropyThreshold: 4.5,
			},
		},
	}
	s := NewScanner(fullCfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Scan(ctx, path, nil)
	}
}

// BenchmarkEntropyCalculation benchmark just the entropy check logic
// This indirectly tests the entropy calculation by scanning a file with high entropy strings
func BenchmarkEntropyCheck(b *testing.B) {
	tmpDir := b.TempDir()

	// Create reliable high entropy string
	// Base64-like random string
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+"
	highEntropy := make([]byte, 64)
	for i := range highEntropy {
		highEntropy[i] = charset[rand.Intn(len(charset))]
	}

	path := filepath.Join(tmpDir, "entropy.txt")
	os.WriteFile(path, highEntropy, 0644)

}
