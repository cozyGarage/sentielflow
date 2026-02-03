package iac

import (
	"context"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestTerraformPublicS3(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewTerraformScanner(cfg)

	content := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`

	findings := scanner.Scan(context.Background(), content, "test.tf")

	if len(findings) == 0 {
		t.Fatal("Expected to find public S3 bucket violation")
	}

	// Should detect public ACL
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

	findings := scanner.Scan(context.Background(), content, "test.tf")

	found := false
	for _, f := range findings {
		if f.RuleID == "aws-rds-unencrypted" {
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

	findings := scanner.ScanManifest([]byte(manifest), "test.yaml")

	if len(findings) == 0 {
		t.Fatal("Expected to find privileged container")
	}

	found := false
	for _, f := range findings {
		if f.Title == "Privileged Container" {
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
`

	findings := scanner.ScanManifest([]byte(manifest), "deployment.yaml")

	// Should detect missing runAsNonRoot
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

	content := `FROM nginx:latest
RUN apt-get update
`

	findings := scanner.Scan(context.Background(), content, "Dockerfile")

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

	content := `FROM nginx:1.21
RUN apt-get update
COPY . /app
`

	findings := scanner.Scan(context.Background(), content, "Dockerfile")

	found := false
	for _, f := range findings {
		if f.RuleID == "no-user" {
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

	content := `FROM nginx:1.21
EXPOSE 22
`

	findings := scanner.Scan(context.Background(), content, "Dockerfile")

	found := false
	for _, f := range findings {
		if f.RuleID == "exposed-port" {
			found = true
		}
	}

	if !found {
		t.Error("Did not detect exposed sensitive port (SSH)")
	}
}
