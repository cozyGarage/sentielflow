# Policy-as-Code with Rego

SentinelFlow empowers you to define custom security requirements using the **Rego** policy language.

## What is OPA/Rego?

Open Policy Agent (OPA) is an open-source, general-purpose policy engine. Rego is its declarative language which allows you to write rules like "Is this resource allowed?".

## Anatomy of a Policy

A typical SentinelFlow policy looks like this:

```rego
package sentinelflow.iac.terraform

# Deny if an S3 bucket has ACL set to public-read
deny[msg] {
    resource := input.resources[_]
    resource.type == "aws_s3_bucket"
    resource.properties.acl == "public-read"
    msg := sprintf("S3 bucket '%v' is publicly accessible", [resource.name])
}
```

## How to Author Policies

1.  **Create a Rego file**: Save it in the `policies/` directory.
2.  **Define the package**: Use the standard `sentinelflow` namespace.
3.  **Define a `deny` rule**: SentinelFlow looks for any `deny` findings.
4.  **Test your policy**:
    ```bash
    sentinelflow policy validate my-rule.rego
    ```

## Best Practices

- **Granular Rules**: Write one rule per security requirement.
- **Helper Functions**: Use functions for repetitive logic (e.g., checking if a port is in a range).
- **Severity Mapping**: Use metadata to assign severity scores to your custom rules.
