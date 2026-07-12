package iac

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestTerraformPublicS3(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewTerraformScanner(cfg)

	dir := t.TempDir()
	content := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`
	filePath := writeTempFile(t, dir, "test.tf", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	if len(findings) == 0 {
		t.Fatal("Expected to find public S3 bucket violation")
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-s3-public-acl" {
			found = true
			if f.Severity != api.SeverityCritical {
				t.Errorf("Expected critical severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect public S3 ACL")
	}
}

func TestTerraformUnencryptedRDS(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewTerraformScanner(cfg)

	dir := t.TempDir()
	content := `
resource "aws_db_instance" "default" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               ="mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  storage_encrypted    = false
}
`
	filePath := writeTempFile(t, dir, "test.tf", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-rds-no-encryption" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect unencrypted RDS instance")
	}
}

func TestKubernetesPrivilegedContainer(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewKubernetesScanner(cfg)

	dir := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
`
	filePath := writeTempFile(t, dir, "test.yaml", manifest)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	if len(findings) == 0 {
		t.Fatal("Expected to find privileged container")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Privileged Container Detected" {
			found = true
			if f.Severity != api.SeverityCritical {
				t.Errorf("Expected critical severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect privileged container")
	}
}

func TestKubernetesRunAsRoot(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewKubernetesScanner(cfg)

	dir := t.TempDir()
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          runAsUser: 0
`
	filePath := writeTempFile(t, dir, "deployment.yaml", manifest)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.Title == "Container Running as Root" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect container running as root")
	}
}

func TestDockerfileLatestTag(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:latest
RUN apt-get update
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "latest-tag" {
			found = true
			if f.Severity != api.SeverityMedium {
				t.Errorf("Expected medium severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Error("Did not detect 'latest' tag usage")
	}
}

func TestDockerfileMissingUser(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:1.21
RUN apt-get update
COPY . /app
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "missing-user" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect missing USER instruction")
	}
}

func TestDockerfileExposedPort(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewDockerfileScanner(cfg)

	dir := t.TempDir()
	content := `FROM nginx:1.21
EXPOSE 22
`
	filePath := writeTempFile(t, dir, "Dockerfile", content)
	findings := scanner.ScanFile(context.Background(), filePath, dir)

	found := false
	for _, f := range findings {
		if f.RuleID == "exposed-port-22" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect exposed sensitive port (SSH)")
	}
}
