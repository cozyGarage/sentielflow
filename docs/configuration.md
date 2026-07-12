# Configuration Reference

SentinelFlow reads settings from `.sentinelflow.yaml` in the project root. Environment variables prefixed with `SENTINELFLOW_` can override file values.

Run `sentinelflow init` to generate a starter configuration.

## Top-Level Options

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `version` | string | `"1.0"` | Configuration schema version |

## Scanners

### Secrets (`scanners.secrets`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable secret scanning |
| `allowlist` | []string | test paths | Glob patterns to skip |
| `patterns` | []string | — | Custom pattern names to include |
| `entropy_threshold` | float | `4.5` | Minimum Shannon entropy to flag |
| `scan_git_history` | bool | `false` | Scan git history for secrets |
| `max_history_depth` | int | `50` | Max commits to scan in history |

### IaC (`scanners.iac`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable IaC scanning |
| `frameworks` | []string | terraform, kubernetes, dockerfile, cloudformation | Frameworks to scan |
| `severity` | string | `medium` | Minimum severity to report |
| `skip_rules` | []string | — | Rule IDs to ignore |

### Dependencies (`scanners.dependencies`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable dependency scanning |
| `ecosystems` | []string | `["auto"]` | Package ecosystems to scan |
| `severity` | string | `medium` | Minimum severity to report |
| `ignore_dev` | bool | `false` | Skip dev dependencies |
| `ignore_cves` | []string | — | CVE IDs to ignore |

### AI (`scanners.ai`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Enable AI review (not yet implemented) |
| `provider` | string | `openai` | LLM provider |
| `model` | string | `gpt-4` | Model name |
| `api_key` | string | env | Set via `SENTINELFLOW_AI_API_KEY` or `OPENAI_API_KEY` |
| `focus` | []string | injection, auth, crypto | Security focus areas |

## Policies (`policies`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable policy scanning |
| `files` | []string | `.sentinelflow/policies/*.rego` | Custom policy file globs |
| `builtin` | []string | see defaults | Built-in policy names |

Built-in policies:

- `no-public-s3-buckets`
- `no-privileged-containers`
- `require-https`
- `no-hardcoded-credentials`
- `enforce-encryption`

## Reporting (`reporting`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `format` | string | `text` | Default output format |
| `include_remediation` | bool | `true` | Include fix suggestions |
| `github_annotations` | bool | `true` | Emit GitHub annotation hints |
| `sarif_upload` | bool | `false` | Enable SARIF upload hints |
| `output_dir` | string | — | Directory for report files |

Supported formats: `text`, `json`, `sarif`, `markdown`, `html`.

## Fail Conditions (`fail_on`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `severity` | string | `high` | Fail threshold: `critical`, `high`, `medium`, or `low` |
| `secrets` | bool | `true` | Fail on any secret finding |
| `policy_violations` | bool | `true` | Fail on policy violations |

CLI override: `--fail-on high`

## Git (`git`)

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `scan_history` | bool | `false` | Scan git commit history |
| `history_depth` | int | `50` | Number of commits to scan |
| `scan_staged_only` | bool | `false` | Only scan staged changes |

## Example

```yaml
version: "1.0"

scanners:
  secrets:
    enabled: true
    entropy_threshold: 4.5
    allowlist:
      - "test/**"
      - "**/*_test.go"

  iac:
    enabled: true
    frameworks:
      - terraform
      - kubernetes
      - dockerfile

  dependencies:
    enabled: true
    ecosystems:
      - auto
    severity: medium

policies:
  enabled: true
  builtin:
    - no-public-s3-buckets
    - no-privileged-containers

fail_on:
  severity: high
  secrets: true
  policy_violations: true
```
