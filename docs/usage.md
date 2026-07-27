# Usage Guide

SentinelFlow is designed to be simple yet powerful. This guide covers the most common commands and use cases for v1.0.

## Basic Scan

Scan the current directory with all implemented scanners:

```bash
sentinelflow scan --all .
```

`--all` enables secrets, IaC, dependencies, SAST, container (when configured), and license scanning. It does **not** enable AI review — `--ai` / `scanners.ai.enabled` are rejected in this release (planned feature).

## Selecting Scanners

Enable specific scanners instead of running everything:

```bash
sentinelflow scan --secrets .          # Secret detection
sentinelflow scan --iac .              # Terraform, Kubernetes, Dockerfile
sentinelflow scan --deps .             # Dependency vulnerabilities (OSV)
sentinelflow scan --sast .             # OWASP-oriented static patterns
sentinelflow scan --license .          # License policy checks
sentinelflow scan --container .        # Container image scan (requires Trivy)
sentinelflow scan --container --container-image myapp:latest
```

Combine flags as needed:

```bash
sentinelflow scan --secrets --iac --deps --fail-on high
```

## Output Formats

| Format | Description | Use case |
| --- | --- | --- |
| `text` (default) | Human-readable console output | Local development |
| `json` | Machine-readable findings | Automation, dashboards |
| `sarif` | Static Analysis Results Format | GitHub/GitLab Security tab |
| `markdown` | Styled report | PR comments, wikis |
| `html` | Browser-friendly report | Sharing with stakeholders |

```bash
sentinelflow scan --all -f sarif -o report.sarif
sentinelflow scan --all -f markdown -o report.md
```

## Failure Thresholds

Control when the process exits with code `1` (for CI gates):

```bash
# Fail on critical or high severity findings
sentinelflow scan --all --fail-on high

# Fail only on critical
sentinelflow scan --all --fail-on critical
```

Accepted `--fail-on` values: `critical`, `high`, `medium`, `low`. Each level includes all severities above it.

Additional gates are configured in `.sentinelflow.yaml`:

```yaml
fail_on:
  severity: high
  secrets: true              # Fail on any secret finding
  policy_violations: true    # Fail on any OPA policy violation
```

All configured gates are evaluated independently — a single secret or policy violation fails the scan even if severity is below the threshold.

## Policy Commands

```bash
sentinelflow policy list                    # List built-in policies
sentinelflow policy validate policies/*.rego
sentinelflow policy test policies/my.rego test/fixtures/policy/k8s-privileged-pod.json
sentinelflow policy generate my-custom-rule
```

## Supply Chain

Generate a CycloneDX SBOM:

```bash
sentinelflow sbom -o sbom.json
```

## Git Hooks

Install a pre-commit hook for local shift-left scanning:

```bash
sentinelflow hook install
sentinelflow hook uninstall
```

## Baselines

Suppress known accepted findings during incremental adoption:

```bash
sentinelflow scan --all --baseline
```

Configure in `.sentinelflow.yaml`:

```yaml
baseline:
  enabled: true
  file: .sentinelflow/baseline.yaml
```

## Git History Secret Scanning

Enable in configuration (requires `fetch-depth: 0` in CI checkout):

```yaml
scanners:
  secrets:
    scan_git_history: true
    max_history_depth: 50

git:
  scan_history: true
  history_depth: 50
```

## Verbose Mode

```bash
sentinelflow scan --all --verbose
```

Shows target path, enabled scanners, and per-scanner timing in the summary.
