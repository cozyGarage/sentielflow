# 🛡️ SentinelFlow Security Scan Report

## 📊 Summary

| Metric | Value |
|--------|-------|
| **Target** | `/workspace/examples/demo-project` |
| **Scan Duration** | 4ms |
| **Scanners Run** | 4 |
| **Total Findings** | **23** |

### Findings by Severity

🔴 **Critical**: 17  
🟠 **High**: 4  
🟡 **Medium**: 2  

## 🔍 Scanner Results

| Scanner | Status | Findings | Duration |
|---------|--------|----------|----------|
| sast | ✅ | 0 | 0s |
| iac | ✅ | 8 | 0s |
| secrets | ✅ | 1 | 2ms |
| policy | ✅ | 14 | 3ms |

## 📋 Detailed Findings

### 🔴 Critical Severity (17)

<details>
<summary><strong>k8s-privileged</strong> - Privileged Container Detected</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Container "app" is running in privileged mode, which grants all capabilities

**Remediation:** Remove privileged flag or use specific capabilities instead

**Code Snippet:**
```
privileged: true
```

</details>

<details>
<summary><strong>aws-s3-public-acl</strong> - S3 Bucket with Public ACL</summary>

**File:** `iac/terraform/bad-s3.tf:1`

**Description:** S3 bucket "public_assets" has public ACL "public-read"

**Remediation:** Set ACL to 'private' and use bucket policies for controlled access

**Code Snippet:**
```
resource "aws_s3_bucket" "public_assets"
```

</details>

<details>
<summary><strong>github-token</strong> - Potential GitHub Token detected</summary>

**File:** `secrets/leaked_tokens.env:3`

**Description:** GitHub personal access token or OAuth token found

**Remediation:** Remove the GitHub token from code. Use GitHub Actions secrets or environment variables. Revoke and regenerate the token.

**Code Snippet:**
```
GITHUB_TOKEN=***REDACTED***
```

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Container 'app' is running in privileged mode

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Container 'app' is not enforcing runAsNonRoot

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** CronJob

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** DaemonSet

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Deployment

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Job

</details>

<details>
<summary><strong>no-privileged-containers</strong> - Policy Violation: no-privileged-containers</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** StatefulSet

</details>


*...and 7 more critical findings*

### 🟠 High Severity (4)

<details>
<summary><strong>aws-s3-no-encryption</strong> - S3 Bucket Without Encryption</summary>

**File:** `iac/terraform/bad-s3.tf:1`

**Description:** S3 bucket "public_assets" does not have server-side encryption enabled

**Remediation:** Enable server-side encryption with KMS or AES256

**Code Snippet:**
```
resource "aws_s3_bucket" "public_assets"
```

</details>

<details>
<summary><strong>aws-s3-public-block-disabled</strong> - S3 Public Access Block Disabled</summary>

**File:** `iac/terraform/bad-s3.tf:1`

**Description:** S3 bucket "public_assets" is missing public access block configuration

**Remediation:** Add aws_s3_bucket_public_access_block resource to prevent public access

**Code Snippet:**
```
resource "aws_s3_bucket" "public_assets"
```

</details>

<details>
<summary><strong>user-root</strong> - Explicit Root User</summary>

**File:** `iac/docker/Dockerfile.bad:3`

**Description:** Dockerfile explicitly sets USER to root

**Remediation:** Use a non-root user instead

**Code Snippet:**
```
USER root
```

</details>

<details>
<summary><strong>missing-user</strong> - Missing USER Instruction</summary>

**File:** `iac/docker/Dockerfile.bad:4`

**Description:** Final image stage does not switch to a non-root user

**Remediation:** Add USER instruction to run container as non-root user in the final stage

</details>

### 🟡 Medium Severity (2)

<details>
<summary><strong>k8s-run-as-non-root</strong> - runAsNonRoot Not Enforced</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Container "app" does not enforce running as non-root user

**Remediation:** Set runAsNonRoot: true in pod or container securityContext

**Code Snippet:**
```
securityContext
```

</details>

<details>
<summary><strong>k8s-latest-tag</strong> - Using &#39;latest&#39; Image Tag</summary>

**File:** `iac/k8s/privileged-pod.yaml:0`

**Description:** Container uses 'latest' or no tag, which can lead to unpredictable deployments

**Remediation:** Use specific image tags or digests

**Code Snippet:**
```
image: nginx:latest
```

</details>

---
*Generated by SentinelFlow 1.0.0 at 2026-07-28 00:50:53*
