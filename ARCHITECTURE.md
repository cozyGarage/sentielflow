# SentinelFlow Architecture

## Overview

SentinelFlow is an AI-driven CI/CD security gatekeeper that integrates with GitHub Actions, GitLab CI, and other CI/CD pipelines to automatically perform comprehensive security analysis on every pull request.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SentinelFlow                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   CLI       │  │   Config    │  │   Report    │  │   CI/CD             │ │
│  │   (Go)      │  │   Manager   │  │   Generator │  │   Integrations      │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                     │           │
│         └────────────────┴────────────────┴─────────────────────┘           │
│                                   │                                         │
│                          ┌────────┴────────┐                                │
│                          │  Scanner Engine │                                │
│                          └────────┬────────┘                                │
│                                   │                                         │
│    ┌──────────────────────────────┼─────────────────────────────┐           │
│    │              │               │              │              │           │
│ ┌──┴───┐    ┌─────┴────┐   ┌──────┴─────┐  ┌─────┴────┐  ┌──────┴──────┐    │
│ │Secret│    │   IaC    │   │ Dependency │  │  Policy  │  │  AI Code    │    │
│ │Scan  │    │  Scanner │   │  Scanner   │  │  Engine  │  │  Review     │    │
│ │(Go)  │    │  (Go)    │   │  (Go)      │  │  (Go)    │  │  (Python)   │    │
│ └──────┘    └──────────┘   └────────────┘  └──────────┘  └─────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

### Go Components (Core CLI & Scanners)
- **CLI Framework**: Cobra for command-line interface
- **Secret Scanner**: Pattern matching with regex, entropy analysis
- **IaC Scanner**: AST parsing for Terraform, YAML parsing for K8s/Docker
- **Dependency Scanner**: Parse package files, check against vulnerability DBs
- **Policy Engine**: OPA (Open Policy Agent) integration

### Python Components (AI/ML)
- **AI Code Review**: LLM-based security pattern detection
- **Model Integration**: OpenAI/Anthropic/local models support
- **Security Pattern Database**: ML-trained insecure code patterns

## Directory Structure

```
sentinelflow/
├── cmd/                          # Go CLI commands
│   └── sentinelflow/
│       └── main.go
├── internal/                     # Internal Go packages
│   ├── config/                   # Configuration management
│   ├── scanner/                  # Scanner implementations
│   │   ├── secrets/              # Secret scanning
│   │   ├── iac/                  # Infrastructure-as-Code scanning
│   │   ├── dependencies/         # Dependency vulnerability scanning
│   │   └── policy/               # Policy-as-code engine
│   ├── reporter/                 # Report generation
│   └── integrations/             # CI/CD integrations
├── pkg/                          # Public Go packages
│   └── api/                      # Public API types
├── ai/                           # Python AI components
│   ├── code_review/              # AI code review engine
│   ├── models/                   # ML models and patterns
│   └── api/                      # Python API server
├── policies/                     # Default policy definitions
├── rules/                        # Scanning rules
├── .github/                      # GitHub Actions integration
├── examples/                     # Example configurations
├── docs/                         # Documentation
├── go.mod
├── go.sum
├── pyproject.toml
└── README.md
```

## Core Features

### 1. Secret Scanning
- Git history analysis for leaked secrets
- Support for 100+ secret patterns (AWS, GCP, Azure, generic API keys)
- Entropy-based detection for unknown secret types
- Allowlist/denylist configuration
- Pre-commit hook support

### 2. IaC Scanning
- **Terraform**: Security misconfigurations, hardcoded secrets
- **Dockerfile**: Base image vulnerabilities, privilege escalation
- **Kubernetes**: RBAC issues, privileged containers, network policies
- **CloudFormation**: AWS security best practices
- **Helm Charts**: Template security analysis

### 3. Dependency Vulnerability Scanning
- Multi-ecosystem support: npm, pip, go, maven, cargo, gems
- NVD/CVE database integration
- SBOM generation (CycloneDX, SPDX)
- Severity-based filtering
- Fix recommendations

### 4. AI-Based Code Review
- LLM-powered insecure pattern detection
- OWASP Top 10 vulnerability identification
- Business logic flaw detection
- Context-aware security suggestions
- Multi-language support

### 5. Policy-as-Code
- OPA Rego policy support
- Built-in policy library
- Custom policy definitions
- Policy violation severity levels
- Auto-remediation suggestions

### 6. Security Reports
- Markdown reports for PR comments
- SARIF format for GitHub Security tab
- JSON/HTML/PDF export options
- Trend analysis and metrics
- Compliance mapping (SOC2, PCI-DSS, HIPAA)

## CI/CD Integrations

### GitHub Actions
```yaml
- uses: sentinelflow/action@v1
  with:
    scan-secrets: true
    scan-iac: true
    scan-dependencies: true
    ai-review: true
    policy-file: .sentinelflow/policies.yaml
    fail-on: high
```

### GitLab CI
```yaml
sentinelflow:
  image: sentinelflow/scanner:latest
  script:
    - sentinelflow scan --all
  artifacts:
    reports:
      security: gl-security-report.json
```

### Generic CI
```bash
sentinelflow scan --format sarif --output report.sarif
```

## Configuration

### .sentinelflow.yaml
```yaml
version: "1.0"

scanners:
  secrets:
    enabled: true
    allowlist:
      - "test/**"
      - "**/*_test.go"
    patterns:
      - custom-api-key
  
  iac:
    enabled: true
    frameworks:
      - terraform
      - kubernetes
      - dockerfile
  
  dependencies:
    enabled: true
    ecosystems:
      - go
      - npm
      - pip
    severity: medium
  
  ai:
    enabled: true
    provider: openai
    model: gpt-4
    focus:
      - injection
      - authentication
      - authorization

policies:
  - no-public-s3-buckets
  - no-privileged-containers
  - require-https
  - enforce-encryption-at-rest

reporting:
  format: markdown
  include-remediation: true
  github-annotations: true

fail-on:
  severity: high
  policy-violations: true
```

## API Design

### Scanner Interface (Go)
```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error)
    Supported(path string) bool
}

type ScanResult struct {
    Scanner   string
    Findings  []Finding
    Metadata  map[string]any
    Duration  time.Duration
}

type Finding struct {
    ID          string
    Type        FindingType
    Severity    Severity
    Title       string
    Description string
    Location    Location
    Remediation string
    References  []string
}
```

### AI Review API (Python)
```python
class AICodeReviewer:
    async def review(
        self,
        code: str,
        language: str,
        context: dict
    ) -> ReviewResult:
        """Perform AI-powered security review"""
        pass

class ReviewResult:
    findings: list[SecurityFinding]
    suggestions: list[Suggestion]
    risk_score: float
    confidence: float
```

## Security Considerations

1. **No Secret Storage**: SentinelFlow never stores or transmits discovered secrets
2. **Local Processing**: All scanning happens locally by default
3. **API Key Security**: AI provider keys handled via environment variables
4. **Minimal Permissions**: CI integration requires only read access to code
5. **Audit Logging**: All scans are logged with timestamps and results
