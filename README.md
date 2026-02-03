# SentinelFlow 🛡️

![SentinelFlow Banner](docs/assets/banner.png)

<p align="center">
  <img src="docs/assets/logo.png" alt="SentinelFlow Logo" width="200"/>
</p>

**AI-Driven CI/CD Security Gatekeeper**

SentinelFlow is a comprehensive security scanning tool that integrates with CI/CD pipelines to automatically detect security vulnerabilities, leaked secrets, insecure configurations, and more.

## ✨ Features

- **🔐 Secret Scanning**: Detect leaked API keys, tokens, passwords, and credentials
- **🏗️ Infrastructure-as-Code**: Scan Terraform, Kubernetes, Dockerfile, CloudFormation
- **📦 Dependency Analysis**: Check for vulnerable dependencies across multiple ecosystems
- **🤖 AI Code Review**: LLM-powered security pattern detection (optional)
- **📜 Policy Enforcement**: OPA-based policy-as-code validation
- **📊 Multiple Report Formats**: Markdown, SARIF, JSON, HTML output

## 🚀 Quick Start

### Installation

```bash
# Using Go install
go install github.com/cozygarage/sentinelflow/cmd/sentinelflow@latest

# Or build from source
git clone https://github.com/cozygarage/sentinelflow
cd sentinelflow
go build -o sentinelflow ./cmd/sentinelflow
```

### Basic Usage

```bash
# Initialize configuration
sentinelflow init

# Run all scanners
sentinelflow scan --all

# Scan specific types
sentinelflow scan --secrets --iac

# Generate SARIF report for GitHub
sentinelflow scan --all --format sarif -o report.sarif

# Generate Markdown report for PR comments
sentinelflow scan --all --format markdown -o report.md
```

## 📋 Configuration

Create a `.sentinelflow.yaml` file in your project root:

```yaml
version: "1.0"

scanners:
  secrets:
    enabled: true
    allowlist:
      - "test/**"
      - "**/*_test.go"
    entropy_threshold: 4.5

  iac:
    enabled: true
    frameworks:
      - terraform
      - kubernetes
      - dockerfile

  dependencies:
    enabled: true
    ecosystems:
      - auto
    severity: medium

  ai:
    enabled: false
    provider: openai
    model: gpt-4

policies:
  enabled: true
  builtin:
    - no-public-s3-buckets
    - no-privileged-containers
    - require-https

fail_on:
  severity: high
  secrets: true
```

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run SentinelFlow
        uses: sentinelflow/action@v1
        with:
          scan-secrets: true
          scan-iac: true
          scan-dependencies: true
          fail-on: high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: report.sarif
```

### GitLab CI

```yaml
sentinelflow:
  image: sentinelflow/scanner:latest
  script:
    - sentinelflow scan --all --format sarif -o gl-security-report.sarif
  artifacts:
    reports:
      sast: gl-security-report.sarif
```

## 🔍 Scanners

### Secret Scanner

- Over 100+ secret patterns (AWS, GCP, Azure, GitHub, etc.)
- Entropy-based detection
- Git history scanning
- Customizable patterns

### IaC Scanner

- **Terraform**: Security misconfigurations, hardcoded secrets, public resources
- **Kubernetes**: Privileged containers, RBAC issues, security contexts
- **Dockerfile**: Base image vulnerabilities, user permissions, secrets
- **CloudFormation**: AWS security best practices

### Dependency Scanner

- Multi-ecosystem support: Go, npm, pip, Maven, Cargo
- NVD/CVE database integration
- SBOM generation
- Version comparison and fix recommendations

### AI Code Review (Optional)

- LLM-powered security analysis
- OWASP Top 10 detection
- Context-aware suggestions
- Multi-language support

### Policy Engine

- OPA (Open Policy Agent) integration
- Built-in security policies
- Custom Rego policies
- Compliance mapping

## 📖 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Scanner Documentation](docs/scanners.md)
- [CI/CD Integration](docs/cicd-integration.md)
- [Writing Custom Policies](docs/policies.md)

## 🛠️ Development

```bash
# Run tests
go test ./...

# Build
go build -o sentinelflow ./cmd/sentinelflow

# Run locally
./sentinelflow scan --all --verbose
```

## 🔒 Security

SentinelFlow takes security seriously:

- **No secret storage**: Never stores or transmits discovered secrets
- **Local processing**: All scanning happens locally by default
- **Minimal permissions**: CI integration requires only read access
- **Audit logging**: All scans are logged with timestamps

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🌟 Acknowledgments

Built with:

- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration management
- [OPA](https://www.openpolicyagent.org/) - Policy engine
- [go-sarif](https://github.com/owenrumney/go-sarif) - SARIF support

---

**Made with ❤️ by the SentinelFlow team**
