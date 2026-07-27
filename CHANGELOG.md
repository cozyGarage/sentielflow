# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Python dependency parsing for `pyproject.toml`, `poetry.lock`, and `Pipfile.lock` (in addition to `requirements.txt`)
- Maven `pom.xml` dependency parsing with basic property resolution
- Cargo `Cargo.lock` / `Cargo.toml` dependency parsing

### Fixed

- `--all` now also applies `--fail-on`, `--baseline`, and `--container-image` (no early return)
- `--ai` fails clearly instead of silently enabling a non-existent scanner
- Scanner runtime errors fail the scan instead of producing a false clean pass
- Vulnerability DB no longer caches empty results when all sources fail
- Single-line `go.mod` `require` statements are parsed for dependency and SBOM scans
- Config validation rejects invalid severities/formats; malformed config files fail startup
- `reporting.format` is honored when `--format` is not explicitly set
- Policy `generate` rejects path traversal; hook install appends instead of overwriting
- Markdown reports escape untrusted finding content for safer PR comments
- Trivy image refs are validated; APT cleanup Dockerfile check no longer requires a double space
- Built-in Rego policies are embedded and loaded via `policies.builtin`
- Policy input supports multi-document Kubernetes YAML and richer Terraform attributes/refs
- JSON reports encode durations as `duration_ms` (milliseconds) with shared severity helpers

## [1.0.0] - 2026-07-12

### Added

- Multi-scanner security analysis: secrets, IaC, dependencies, SAST, container, license, and policy
- Terraform, Kubernetes, and Dockerfile misconfiguration rules
- OPA policy-as-code engine with built-in Rego policies
- OSV-backed dependency vulnerability scanning
- Report formats: text, Markdown, JSON, SARIF, and HTML
- GitHub Actions composite action and CI workflow (security scan, SBOM, policy validation)
- Pre-commit hook installer (`sentinelflow hook install`)
- Baseline filtering for incremental adoption
- MIT license

### Fixed

- Policy scanner now evaluates Rego policies at scan time (no stub)
- Dependency scanner queries OSV instead of hardcoded demo data
- `fail_on.secrets` and `fail_on.policy_violations` gates work alongside severity thresholds
- Secret and code snippets are redacted in reports
- Docker HEALTHCHECK uses `sentinelflow version`
- Git metadata collection no longer panics on trailing newlines

### Security

- Entropy-based secret detection with allowlists
- Git history secret scanning with allowlist support
- `govulncheck` in CI pipeline
- Non-root Docker container execution

[Unreleased]: https://github.com/cozyGarage/sentielflow/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/cozyGarage/sentielflow/releases/tag/v1.0.0
