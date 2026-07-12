# CI/CD Integration

SentinelFlow integrates with GitHub Actions, GitLab CI, and Docker-based pipelines.

## GitHub Actions

### Using the composite action (recommended)

The repo includes a composite action at `.github/actions/sentinelflow` (also published as root `action.yml`):

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
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
          category: sentinelflow
```

For the same repository, use a local path:

```yaml
      - uses: ./.github/actions/sentinelflow
        with:
          scan-all: 'true'
          fail-on: high
          format: sarif
          output: report.sarif
```

### Action inputs

| Input | Default | Description |
| --- | --- | --- |
| `scan-all` | `true` | Enable secrets, IaC, deps, SAST, license |
| `scan-secrets` | `true` | Secret scanning |
| `scan-iac` | `true` | IaC scanning |
| `scan-deps` | `true` | Dependency scanning |
| `scan-sast` | `true` | OWASP SAST rules |
| `scan-license` | `true` | License policy checks |
| `scan-container` | `false` | Container scan (installs Trivy) |
| `container-image` | — | Image to scan when container enabled |
| `use-baseline` | `false` | Skip baselined findings |
| `fail-on` | `high` | Pipeline failure threshold |
| `format` | `sarif` | Report format |
| `output` | `report.sarif` | Output file path |
| `go-version` | `1.25` | Go version for building |

### Container scanning in CI

```yaml
      - uses: ./.github/actions/sentinelflow
        with:
          scan-all: 'false'
          scan-secrets: 'true'
          scan-container: 'true'
          container-image: myapp:${{ github.sha }}
          fail-on: high
          format: sarif
          output: report.sarif
```

### SBOM and policy validation

This repository's workflow runs three jobs:

1. **security-scan** — Full scan, SARIF upload, PR comments
2. **supply-chain** — SBOM generation (`sentinelflow sbom`)
3. **policy-check** — Validates all `.rego` policies

See [.github/workflows/security-scan.yml](../.github/workflows/security-scan.yml) for the full pipeline.

### PR comments

The workflow generates a Markdown report and updates an existing bot comment when possible. The report step uses `continue-on-error: true` so PR feedback is posted even when the security gate fails.

## GitLab CI

```yaml
stages:
  - security

sentinelflow:
  stage: security
  image: golang:1.24
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format sarif -o gl-sast-report.sarif --fail-on high
    - ./sentinelflow sbom -o sbom.json
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - sbom.json
```

See [examples/.gitlab-ci.yml](../examples/.gitlab-ci.yml) for a complete example with policy validation.

## Docker

```bash
docker build -t sentinelflow .
docker run --rm -v $(pwd):/workspace -w /workspace sentinelflow scan --all
```

## Exit codes

SentinelFlow exits with code `1` when findings exceed the `--fail-on` threshold. Use this to gate merges.

## Recommended settings

| Setting | CI recommendation |
| --- | --- |
| `--fail-on` | `high` or `critical` |
| `--format` | `sarif` for GitHub/GitLab security tabs |
| `--all` | Enable all implemented scanners |
| `fetch-depth: 0` | Required for git history secret scanning |
| Config file | Commit `.sentinelflow.yaml` to the repo |
