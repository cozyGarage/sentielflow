# Changelog

All notable changes to SentinelFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scanners.exclude` global path skip list (engine walk); secrets `allowlist` is secrets-only again
- `scripts/count-findings.sh` for Action findings-count under `pipefail` (zero matches OK)
- Visual demo README with screenshots, `examples/demo-project`, and `make demo` / `scripts/demo.sh`
- `scripts/install.sh` one-liner installer for GitHub Release binaries
- GitHub Action `delivery: docker` (default) and `delivery: build` (same-repo dogfood)
- Restyled HTML security reports (teal/slate product look; no purple gradient)
- Shared `test/fixtures/` corpus for secrets, IaC, dependencies, and policy inputs (wired into unit tests)
- Python dependency parsing for `pyproject.toml`, `poetry.lock`, and `Pipfile.lock` (in addition to `requirements.txt`)
- Maven `pom.xml` dependency parsing with basic property resolution
- Cargo `Cargo.lock` / `Cargo.toml` dependency parsing
- Configurable scanner concurrency (`scanners.concurrency` and per-scanner overrides)

### Changed

- Primary install story is clone/`make build` until the first `v*` release publishes binaries and Docker Hub tags
- GoReleaser `project_name: sentinelflow` + lowercase `main.version` ldflags aligned with the CLI
- Dockerfile accepts `ARG VERSION/COMMIT/DATE` and embeds them correctly
- Repo CI dogfoods `./.github/actions/sentinelflow` with `delivery: build`
- README assets compressed; CLI screenshot matches real demo output
- `scan` suppresses cobra Usage on gate failures (`SilenceUsage`)
- Makefile binary name is `sentinelflow` on Unix
- `--format` help includes `html`
- Unified AI rejection messaging for `--ai` / `scanners.ai.enabled`; CLI branding no longer advertises AI as shipped
- Default IaC frameworks are terraform, kubernetes, and dockerfile only (CloudFormation documented as planned)
- Engine shares collected files with secrets/SAST/IaC scanners (avoid re-walking trees)
- File scanners use fixed worker pools instead of unbounded goroutine-per-file fanout
- Shared `internal/scanner/types` contracts reduce adapter boilerplate
- Secrets keyword prefilter for keyword-embedded patterns; git history scans patch hunks with dedupe

### Fixed

- Engine/adapters preserve findings when scanners return `(result, err)` (partial deps/OSV, etc.)
- Enabled container scans fail visibly when Trivy/image is missing (no silent 0 findings)
- `fail_on.severity` / `--fail-on` normalized case-insensitively after CLI flags
- Secrets/SAST/policy per-file and eval errors surface on `ScannerRun.Error`
- Action findings-count no longer fails the job on clean (0-finding) JSON/SARIF reports
- Repo self-scan skips `test/fixtures` samples; ignore OPA-indirect OTEL advisory until upstream bumps
- Policy CLI docs use positional `policy test [policy] [input-file]` (not `--input`)
- Action baseline description points at `.sentinelflow/baseline.yaml`
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
