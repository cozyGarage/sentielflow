# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Python dependency parsing for `pyproject.toml`, `poetry.lock`, and `Pipfile.lock` (in addition to `requirements.txt`)
- Maven `pom.xml` dependency parsing with basic property resolution
- Cargo `Cargo.lock` / `Cargo.toml` dependency parsing
- Configurable scanner concurrency (`scanners.concurrency` and per-scanner overrides)

### Changed

- Engine shares collected files with secrets/SAST/IaC scanners (avoid re-walking trees)
- File scanners use fixed worker pools instead of unbounded goroutine-per-file fanout
- Shared `internal/scanner/types` contracts reduce adapter boilerplate
- Secrets keyword prefilter for keyword-embedded patterns; git history scans patch hunks with dedupe

### Fixed

- Secrets placeholder filtering checks the captured value (not keyword-bearing full matches) and avoids over-matching on words like "password"/"secret"
- IaC scanner honors `frameworks`, `skip_rules`, and minimum `severity`
- Terraform S3/SG checks are per-resource and detect multi-line security group ingress
- Kubernetes scanning supports multi-doc YAML, init/ephemeral containers, and pod securityContext merge
- Dockerfile checks are stage-aware (final-stage USER/HEALTHCHECK) and handle continuations/case

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
