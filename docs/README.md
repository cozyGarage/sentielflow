# SentinelFlow Documentation

Welcome to the SentinelFlow v1.0 documentation.

## Documentation Index

| Document | Description |
| --- | --- |
| [Usage Guide](usage.md) | CLI commands, flags, and common workflows |
| [Configuration Reference](configuration.md) | `.sentinelflow.yaml` options |
| [Scanner Details](scanners.md) | How each scanner works |
| [Policy Authoring](policies.md) | Writing and testing OPA/Rego policies |
| [CI/CD Integration](cicd-integration.md) | GitHub Actions, GitLab CI, Docker |
| [Architecture](architecture.md) | Engine design and scan pipeline |

## Quick Links

- [GitHub Repository](https://github.com/cozyGarage/sentielflow)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Changelog](../CHANGELOG.md)
- [Architecture Overview](../ARCHITECTURE.md)

## Requirements

- Go 1.25+ (toolchain pinned in `go.mod`)
- Optional: [Trivy](https://github.com/aquasecurity/trivy) for container scanning
