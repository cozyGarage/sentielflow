# SentinelFlow Architecture

SentinelFlow is a Go-based security scanner for CI/CD pipelines. For detailed diagrams and pipeline flow, see [docs/architecture.md](docs/architecture.md).

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        SentinelFlow                           │
├─────────────────────────────────────────────────────────────┤
│  CLI (Cobra)  →  Config (Viper)  →  Scanner Engine          │
│                          ↓                                    │
│              ┌───────────┼───────────┐                       │
│              │           │           │                       │
│         Secrets       IaC      Dependencies                  │
│         Scanner     Scanner      Scanner                     │
│              │           │           │                       │
│              └───────────┼───────────┘                       │
│                          ↓                                    │
│                   Policy Engine (OPA)                         │
│                          ↓                                    │
│              Reporter (SARIF, JSON, Markdown, HTML)           │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
| --- | --- |
| CLI | Cobra + Viper |
| Secret Scanner | Regex patterns, Shannon entropy |
| IaC Scanner | Line-based parsing for Terraform, YAML for K8s, Dockerfile rules |
| Dependency Scanner | Lockfile parsing + OSV API |
| Policy Engine | Open Policy Agent (Rego) |
| Reports | Text, JSON, SARIF, Markdown, HTML |

## Directory Structure

```
sentinelflow/
├── cmd/sentinelflow/       # CLI entry point
├── internal/
│   ├── adapter/            # Scanner adapters for the engine
│   ├── cli/                # Cobra commands
│   ├── config/             # Configuration management
│   ├── reporter/           # Report formatters
│   ├── scanner/            # Scanner implementations
│   │   ├── secrets/
│   │   ├── iac/
│   │   ├── dependencies/
│   │   └── policy/
│   └── vulndb/             # OSV vulnerability database client
├── pkg/api/                # Public types
├── policies/               # Built-in Rego policies
├── docs/                   # Documentation
├── test/                   # Integration tests
├── Dockerfile
├── Makefile
└── go.mod
```

## Scanner Engine

The engine (`internal/scanner/engine.go`) orchestrates enabled scanners concurrently:

1. Collect files from the target path (skipping `.git`, `node_modules`, etc.)
2. Run each enabled scanner in parallel via goroutines
3. Aggregate findings into a single `ScanResult`
4. Pass results to the reporter

Scanners are registered based on configuration:

- `scanners.secrets.enabled` → Secret adapter
- `scanners.iac.enabled` → IaC adapter
- `scanners.dependencies.enabled` → Dependencies adapter
- `policies.enabled` → Policy adapter

## Planned Features

The following are configured but not yet implemented:

- **AI code review** — LLM-powered security analysis (`scanners.ai`)
- **Git history scanning** — Full commit history secret scanning
- **Policy validate/test CLI** — OPA policy testing commands

## CI/CD Integration

SentinelFlow runs as a standalone binary in CI pipelines. See [docs/cicd-integration.md](docs/cicd-integration.md) for GitHub Actions and GitLab CI examples.

## Security Principles

1. **No secret storage** — Findings are masked; secrets are never persisted
2. **Local first** — Scanning runs locally; only package names/versions are sent to OSV
3. **Static analysis** — Code is analyzed without execution
4. **Non-root container** — Docker image runs as unprivileged user
