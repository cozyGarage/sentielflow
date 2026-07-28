# Audit residual risks (post Waves 1–3)

Re-audit after correctness, delivery, and scanner-quality waves. Unit tests green; `make demo` fails the gate as expected on intentional findings.

## Residual risks

| Area | Risk | Notes |
| --- | --- | --- |
| Release cut | First `v*` tag not published from this cycle | Needs Waves merged to `main` + `DOCKER_USERNAME` / `DOCKER_PASSWORD`. See [releasing.md](releasing.md). |
| Module path | `go install` unsupported | Module `github.com/cozygarage/sentinelflow` ≠ repo `cozyGarage/sentielflow`. Rename deferred. |
| License scanner | High FN rate by design | Hardcoded license map; no SBOM. Documented; not a full license gate. |
| Dependencies | No Ruby/Gemfile parsing | `Supports` honest; Ruby still unsupported. |
| CloudFormation | Not implemented | IaC frameworks default excludes it; planned. |
| AI scanner | Rejected at config/CLI | Planned; keep `enabled: false`. |
| OSV / network | Partial dependency failures | Findings preserved + `ScannerRun.Error` fails CI — flaky network can red CI. |
| Secrets git history | Requires local `git` | Errors surface; history depth still fixed/configurable via config only. |
| Container delivery | Action `scan-container` needs `delivery: build` | Docker delivery path cannot run host Trivy. `--all` does not enable container (CI dogfood stays Trivy-free). |
| Policy vs IaC | Remaining Rego gaps | e.g. some workload kinds / stringly YAML edge cases may still diverge. |
| Redaction | Heuristic, not cryptographic | Reporter + secrets redact patterns; novel secret formats may still leak in snippets. |

## Optional follow-ups (not blockers)

- CloudFormation rule engine
- AI code review
- Configurable scan timeout / OSV worker pool
- Full Go module + GitHub repo rename
- Expand license DB or integrate SBOM license check
