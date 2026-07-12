# SentinelFlow

**CI/CD Security Gatekeeper**

SentinelFlow is a security scanning tool that integrates with CI/CD pipelines to detect leaked secrets, insecure infrastructure configurations, vulnerable dependencies, and policy violations.

## Features

- **Secret Scanning**: Detect leaked API keys, tokens, passwords, and credentials
- **Infrastructure-as-Code**: Scan Terraform, Kubernetes, and Dockerfile configurations
- **Dependency Analysis**: Check for vulnerable dependencies via the OSV API
- **Policy Enforcement**: OPA-based policy-as-code validation
- **Multiple Report Formats**: Text, Markdown, SARIF, JSON, and HTML output

> **Note:** AI-powered code review is configured in `.sentinelflow.yaml` but not yet implemented in the scanner engine.

## Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/cozygarage/sentinelflow
cd sentinelflow
go build -o sentinelflow ./cmd/sentinelflow

# Or use Make (Windows: sentinelflow.exe)
make build
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

## Configuration

Create a `.sentinelflow.yaml` file in your project root (or run `sentinelflow init`):

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
    enabled: false  # Not yet implemented

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

See [Configuration Reference](docs/configuration.md) for all options.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: cozyGarage/sentielflow/.github/actions/sentinelflow@main
        with:
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: report.sarif
```

### GitLab CI

```yaml
sentinelflow:
  image: golang:1.24
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format sarif -o gl-security-report.sarif
  artifacts:
    reports:
      sast: gl-security-report.sarif
```

See [CI/CD Integration](docs/cicd-integration.md) for more examples.

## Scanners

| Scanner | Description |
| --- | --- |
| **Secrets** | Regex patterns, entropy analysis, and keyword heuristics |
| **IaC** | Terraform, Kubernetes manifests, and Dockerfiles |
| **Dependencies** | Lockfile parsing with OSV vulnerability lookup |
| **Policy** | Built-in and custom OPA/Rego policies |

## CLI Commands

| Command | Description |
| --- | --- |
| `sentinelflow scan` | Run security scanners |
| `sentinelflow init` | Create default configuration |
| `sentinelflow policy list` | List built-in policies |
| `sentinelflow policy generate` | Create a new policy template |
| `sentinelflow version` | Print version information |

## Documentation

- [Usage Guide](docs/usage.md)
- [Configuration Reference](docs/configuration.md)
- [Scanner Documentation](docs/scanners.md)
- [CI/CD Integration](docs/cicd-integration.md)
- [Writing Custom Policies](docs/policies.md)
- [Architecture](docs/architecture.md)

## Development

```bash
# Run tests
go test ./...

# Run integration tests
go test -tags=integration ./test/...

# Build
go build -o sentinelflow ./cmd/sentinelflow

# Run locally
./sentinelflow scan --all --verbose
```

## Security

- **No secret storage**: Never stores or transmits discovered secrets
- **Local processing**: All scanning happens locally by default
- **Minimal permissions**: CI integration requires only read access to code

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

Built with:

- [Cobra](https://github.com/spf13/cobra) — CLI framework
- [Viper](https://github.com/spf13/viper) — Configuration management
- [OPA](https://www.openpolicyagent.org/) — Policy engine
- [go-sarif](https://github.com/owenrumney/go-sarif) — SARIF support
