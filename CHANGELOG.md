# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Multi-scanner security analysis (Secrets, IaC, Dependencies, Policy)
- Support for Terraform, Kubernetes, Dockerfile scanning
- OPA policy engine integration
- Multiple output formats (Text, Markdown, JSON, SARIF, HTML)
- GitHub Actions and GitLab CI integration examples
- Vulnerability database integration (OSV API)
- Docker image with multi-stage build
- Automated release workflow with GoReleaser
- Comprehensive benchmark suite
- Full test coverage for core components

### Security

- Entropy-based secret detection
- CVSS scoring for vulnerabilities
- Policy-as-code enforcement
- Non-root Docker container execution

## [1.0.0] - TBD

### Added

- Initial release
- Core scanning engine
- 75+ security rules across all scanners
- CI/CD integration support
- Comprehensive documentation

[Unreleased]: https://github.com/cozygarage/sentinelflow/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cozygarage/sentinelflow/releases/tag/v1.0.0
