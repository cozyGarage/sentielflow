# Usage Guide

SentinelFlow is designed to be simple yet powerful. This guide covers the most common commands and use cases.

## Basic Scan

To scan the current directory with all default scanners:

```bash
sentinelflow scan --all .
```

## Selecting Scanners

You can enable specific scanners if you don't want to run everything:

```bash
sentinelflow scan --secrets .     # Just secrets
sentinelflow scan --iac .         # Just Infrastructure-as-Code
sentinelflow scan --deps .        # Just dependency vulnerabilities
```

## Output Formats

SentinelFlow supports multiple output formats for different needs:

| Format           | Description                     | Use Case                     |
| ---------------- | ------------------------------- | ---------------------------- |
| `text` (default) | Human-readable console output   | Local development            |
| `json`           | Machine-readable data           | Integration with other tools |
| `sarif`          | Standard Static Analysis format | GitHub Security Tab          |
| `markdown`       | Styled documentation format     | PR Comments / CI summaries   |

Usage example:

```bash
sentinelflow scan --all -f sarif -o report.sarif
```

## Failure Thresholds

In CI/CD, you often want the build to fail if high-severity issues are found:

```bash
# Fail on critical or high findings (threshold is inclusive)
sentinelflow scan --all --fail-on high

# Fail only on critical findings
sentinelflow scan --all --fail-on critical
```

Accepted values: `critical`, `high`, `medium`, `low`. Each level includes all severities above it.
