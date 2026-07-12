# CI/CD Integration

SentinelFlow runs as a CLI binary in your pipeline. Build it from source or use the Docker image.

## GitHub Actions

### Basic scan with SARIF upload

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

      - uses: actions/setup-go@v5
        with:
          go-version: "1.24"

      - name: Build SentinelFlow
        run: go build -o sentinelflow ./cmd/sentinelflow

      - name: Run security scan
        run: ./sentinelflow scan --all --format sarif -o report.sarif --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: report.sarif
          category: sentinelflow
```

### PR comment with Markdown report

```yaml
      - name: Generate Markdown report
        if: github.event_name == 'pull_request'
        run: ./sentinelflow scan --all --format markdown -o report.md

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('report.md', 'utf8');
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: report
            });
```

## GitLab CI

```yaml
stages:
  - security

sentinelflow:
  stage: security
  image: golang:1.24
  script:
    - go build -o sentinelflow ./cmd/sentinelflow
    - ./sentinelflow scan --all --format sarif -o gl-security-report.sarif --fail-on high
  artifacts:
    reports:
      sast: gl-security-report.sarif
```

See [examples/.gitlab-ci.yml](../examples/.gitlab-ci.yml) for a complete example.

## Docker

Build and run using the included Dockerfile:

```bash
docker build -t sentinelflow .
docker run --rm -v $(pwd):/workspace -w /workspace sentinelflow scan --all
```

## Exit Codes

SentinelFlow exits with code `1` when findings exceed the configured `--fail-on` threshold or when a scan error occurs. Use this to gate merges in your pipeline.

## Recommended Settings

| Setting | CI recommendation |
| --- | --- |
| `--fail-on` | `high` or `critical` |
| `--format` | `sarif` for GitHub/GitLab security tabs |
| `--all` | Enable all implemented scanners |
| Config file | Commit `.sentinelflow.yaml` to the repo |
