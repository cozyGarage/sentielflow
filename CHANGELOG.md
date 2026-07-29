# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Action `timeout` input (maps to `--timeout`)
- Release workflow publishes GitHub binaries even when Docker Hub secrets are absent (`--skip=docker`)

## [1.1.0] - 2026-07-29

### Added

- `scanners.exclude` global path skip list; secrets `allowlist` is secrets-only
- `scripts/count-findings.sh` and install checksum verification against `checksums.txt`
- Release runbook, post-audit residual risks, and product roadmap (R0–R3)
- License `allowed` list; redact unit tests + reporter defense-in-depth
- CI unit-test workflow + `make test-scripts`
- Configurable scan deadline (`scan_timeout` / `--timeout`)
- Visual demo README, `examples/demo-project`, `make demo`
- GitHub Action `delivery: docker` / `delivery: build`
- Restyled HTML reports; shared `test/fixtures/` corpus
- Python / Maven / Cargo dependency parsers
- Configurable scanner concurrency

### Changed

- Release workflow pins GoReleaser action `v6.3.0` + CLI `v2.9.0`
- Action inputs bound via `env` (no shell interpolation)
- `--all` does not enable container (Trivy opt-in via `--container`)
- Docs clarify `go install` unsupported until module path matches the GitHub repo
- Engine shares file walks; scanners use worker pools
- Default IaC frameworks: terraform, kubernetes, dockerfile only

### Fixed

- Findings preserved when scanners return `(result, err)`; container skips are visible errors
- `fail_on` / `--fail-on` case-normalized; worker/policy errors surface on `ScannerRun.Error`
- Path-scoped sample skips; K8s bool-ish YAML; policy privileged init/ephemeral alignment
- License/deps Supports honesty (no false Gemfile/Cargo claims)
- Self-scan excludes intentional scanner pattern sources

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

[Unreleased]: https://github.com/cozyGarage/sentielflow/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/cozyGarage/sentielflow/releases/tag/v1.1.0
[1.0.0]: https://github.com/cozyGarage/sentielflow/releases/tag/v1.0.0
