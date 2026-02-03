# Scanner Implementation Details

This guide explains the technical implementation of each scanner in SentinelFlow.

## 1. Secret Scanner (`internal/scanner/secrets`)

### Detection Mechanism

The secret scanner uses a three-tier detection approach:

1.  **Regex Matching**: Predefined patterns for known keys (AWS, GCP, GitHub).
2.  **Entropy Analysis**: Shannon entropy calculation to detect high-randomness strings that don't match known patterns.
3.  **Keyword Heuristics**: Filtering based on context (e.g., assignment to variables like `password` or `token`).

### Obfuscation

SentinelFlow automatically masks secrets in reports using a standard masking algorithm to prevent the report itself from becoming a security risk.

---

## 2. IaC Scanner (`internal/scanner/iac`)

### Supported Frameworks

- **Terraform**: Parses `.tf` files to identify insecure resource configurations.
- **Kubernetes**: Scans manifests for privileged pods, insecure RBAC, and missing resource limits.
- **Dockerfile**: Checks for root usage, missing healthchecks, and insecure package management.

### Technical Implementation

We use custom parsers and AST (Abstract Syntax Tree) traversal to understand the structure of the configuration rather than just doing simple string searches.

---

## 3. Dependency Scanner (`internal/scanner/dependencies`)

### Data Sourcing

SentinelFlow integrates with **OSV (Open Source Vulnerabilities)**, which aggregates data from:

- GitHub Advisory Database
- PyPa (Python)
- Go Vulnerability Database
- Global CVE feed

### Efficient Scanning

We scan lockfiles (e.g., `go.sum`, `package-lock.json`) rather than the entire `node_modules` or `vendor` folders. This is significantly faster and more accurate as it captures the exact versions resolved by your package manager.

---

## 4. Policy Engine (`internal/scanner/policy`)

### OPA Integration

The engine embeds Open Policy Agent as a library. This allows us to compile and execute Rego policies with minimal overhead.

### Built-in Policies

- `no-public-s3-buckets`: Prevents public access to S3.
- `no-privileged-containers`: Blocks containers running in privileged mode.
- `require-https`: Ensures all ingress and endpoints use TLS.
- `enforce-encryption`: Checks for `encrypted: true` on storage resources.
